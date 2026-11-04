#!/usr/bin/env python3
"""KL-2 discriminator — GitHub Actions build (repo: o-yutaka/moka-harness).

Same experiment as the local harness (kl2_discriminator.py, see README.md in
this directory): a Klaviyo Private API Key whose DECLARED scopes are read-only
— does it stay read-only when writes are attempted through the official MCP
server (klaviyo-mcp-server 0.4.2, stdio), or does the MCP path pass the write
through to execution?

Why this file exists: the local VM's egress to a.klaviyo.com is dead (shim up,
example.com 200, a.klaviyo.com times out on GET and POST — measured
2026-11-05), so the discriminator is re-hosted on GitHub Actions, whose egress
reaches Klaviyo. It is fully self-contained: stdlib only, MCP over raw
JSON-RPC stdio, the MCP server is installed at runtime into a throwaway venv.

Differences from the local build (deliberate, task-specified):
  * Keys arrive UNORDERED as env KLAVIYO_KEY_X / KLAVIYO_KEY_Y. Step 0
    discriminates them by REST behaviour: GET /api/accounts/ must be 200 for
    both; a probe POST /api/profiles/ (unique marker email, our own +kl2probe
    namespace) returning 201 => FULL, 403 => RO. The run aborts unless
    exactly one FULL and one RO are found. Step 0 IS the local build's S2
    (raw-REST negative control): filing-grade BROKEN requires the step-0 RO
    REST write to be 403, which the abort rule structurally guarantees.
  * REST revision defaults to 2024-10-15 (task spec; KL2_REVISION overrides).
    The local build defaulted to the vendor SDK's pinned 2026-07-15. The MCP
    server internally still pins 2026-07-15 via klaviyo_api 24.0.0, so exact
    revision parity between the REST control and the MCP path is NOT
    achievable in this build — noted, not hidden.
  * The optional remote-MCP path (local S7 / KLAVIYO_MCP_URL) is not ported:
    no hosted session exists for the Actions lane.
  * Evidence goes to outputs/kl2/<run_id>/ (the workflow uploads outputs/ as
    an artifact). Before EVERY exit, every file under outputs/ is scrubbed of
    key material ('pk_' tokens and the exact key values).
  * stdout is a PUBLIC log: step names, HTTP statuses, field names, counts
    and verdicts only. Never key values, never full bodies, never marker
    emails, never profile ids.

Steps (verdicts mirror the local README):
  S1 shape capture   tools/list + get_account_details per key
  S3 control write   MCP klaviyo_create_profile with FULL key -> must land
  S4 test W1         MCP klaviyo_create_profile with RO key
  S5 test W2         MCP klaviyo_create_event (FULL control on the S3 marker;
                     RO on a FRESH marker — events:write implicitly creates
                     the profile, Seam B)
  S6 cleanup         data-privacy deletion jobs (REST, FULL key) for every
                     marker profile that exists, step-0 probes included
A write counts as LANDED only via independent REST read-back with the FULL
key (targeted equals(email, ...) lookup — never list enumeration, never
/api/v1/people).

Exit codes mirror the local build: 2 = refused (missing keys / binary),
3 = control failure (run cannot discriminate), 0 = completed.
--selftest: fake stdio server + guard/abort paths, ZERO network.
"""
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API_BASE = "https://a.klaviyo.com"
REVISION = os.environ.get("KL2_REVISION", "2024-10-15")
CALL_TIMEOUT = 90
MCP_PACKAGE = "klaviyo-mcp-server==0.4.2"
OUTPUTS_ROOT = Path(os.environ.get("KL2_OUTPUTS_ROOT", "outputs"))
OUT_DIR = OUTPUTS_ROOT / "kl2"
VENV_DIR = Path(os.environ.get("KL2_VENV_DIR", ".kl2-mcp-venv"))

# ---------------------------------------------------------------- keys ------

def get_env_keys():
    return (os.environ.get("KLAVIYO_KEY_X", "").strip(),
            os.environ.get("KLAVIYO_KEY_Y", "").strip())

def keys_ready(key_x, key_y):
    return bool(key_x) and bool(key_y) and key_x != key_y

# ------------------------------------------------------------- REST raw -----

def rest(method, path, key, body=None, timeout=60):
    url = API_BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Klaviyo-API-Key {key}")
    req.add_header("revision", REVISION)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, _try_json(raw), raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return e.code, _try_json(raw), raw
    except Exception as e:  # network etc.
        return None, None, f"TRANSPORT_ERROR: {e!r}"

def _try_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None

def rest_find_profile_id(email, key):
    q = urllib.parse.urlencode({"filter": f'equals(email,"{email}")', "page[size]": 1})
    status, js, raw = rest("GET", f"/api/profiles/?{q}", key)
    pid = None
    if js and isinstance(js.get("data"), list) and js["data"]:
        pid = js["data"][0].get("id")
    return status, pid, raw

def rest_count_events(metric_name, key):
    q = urllib.parse.urlencode({"filter": f'equals(metric_name,"{metric_name}")', "page[size]": 5})
    status, js, raw = rest("GET", f"/api/events/?{q}", key)
    n = len(js["data"]) if js and isinstance(js.get("data"), list) else None
    return status, n, raw

# ------------------------------------------------------- step 0: key sort ---

class AbortRun(Exception):
    """Run cannot proceed (mirrors local exit-2/exit-3 refusals)."""
    def __init__(self, message, exit_code=2):
        super().__init__(message)
        self.exit_code = exit_code

def classify_write_status(status):
    if status in (200, 201):
        return "FULL"
    if status == 403:
        return "RO"
    return "UNKNOWN"

def discriminate(label, key, probe_email, run_id, rest_fn):
    """One key: GET /api/accounts/ (expect 200) + probe profile-create.
    Returns a record dict (raw bodies included; saved to outputs, never
    printed). Classification is by the probe POST status only."""
    st_get, _js, raw_get = rest_fn("GET", "/api/accounts/", key)
    st_post, _js2, raw_post = rest_fn("POST", "/api/profiles/", key, {"data": {
        "type": "profile", "attributes": {
            "email": probe_email, "first_name": "KL2",
            "last_name": f"PROBE-{label}-{run_id}",
            "properties": {"kl2_marker": run_id}}}})
    return {"label": label, "probe_email": probe_email,
            "get_accounts_status": st_get, "probe_post_status": st_post,
            "class": classify_write_status(st_post),
            "get_raw": raw_get, "probe_raw": raw_post}

def resolve_keys(key_x, key_y, marker_for, run_id, rest_fn, log):
    """Discriminate X and Y; return (ro_key, full_key, records).
    Aborts unless both keys read accounts (200) and exactly one classifies
    FULL and the other RO."""
    records = []
    for label, key in (("X", key_x), ("Y", key_y)):
        rec = discriminate(label, key, marker_for(f"probe{label.lower()}"),
                           run_id, rest_fn)
        records.append(rec)
        log(f"[STEP0-{label}] GET /api/accounts/ -> {rec['get_accounts_status']} "
            f"| POST /api/profiles/ (probe) -> {rec['probe_post_status']} "
            f"| class={rec['class']}")
    bad_get = [r["label"] for r in records if r["get_accounts_status"] != 200]
    if bad_get:
        raise AbortRun(f"STEP0 abort: GET /api/accounts/ not 200 for key(s) "
                       f"{bad_get} — cannot discriminate", 2)
    classes = sorted(r["class"] for r in records)
    if classes != ["FULL", "RO"]:
        raise AbortRun(f"STEP0 abort: expected exactly one FULL and one RO, "
                       f"got {[r['class'] for r in records]}", 2)
    by_class = {r["class"]: r for r in records}
    ro_key = key_x if by_class["RO"]["label"] == "X" else key_y
    full_key = key_x if by_class["FULL"]["label"] == "X" else key_y
    log(f"[STEP0] mapping: RO=key {by_class['RO']['label']}, "
        f"FULL=key {by_class['FULL']['label']} "
        f"(RO REST write rejected 403 = local S2-equivalent, held)")
    return ro_key, full_key, records

# ------------------------------------------------------------ MCP stdio -----

class McpStdio:
    """Raw JSON-RPC over stdio — same wire behaviour as the local build."""
    def __init__(self, argv, api_key):
        env = dict(os.environ)
        env["PRIVATE_API_KEY"] = api_key
        env["READ_ONLY"] = "false"  # operator gate OFF: the key alone must bind
        env.pop("ALLOW_USER_GENERATED_CONTENT", None)
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, text=True, bufsize=1)
        self.q = queue.Queue()
        self._id = 0
        self.stderr_lines = []
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                try:
                    self.q.put(json.loads(line))
                except Exception:
                    pass

    def _pump_err(self):
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip())

    def request(self, method, params=None, timeout=CALL_TIMEOUT):
        self._id += 1
        rid = self._id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self.q.get(timeout=max(1, deadline - time.time()))
            except queue.Empty:
                break
            if resp.get("id") == rid:
                return resp
        raise TimeoutError(f"no response for {method} within {timeout}s")

    def notify(self, method):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def handshake(self):
        r = self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "kl2-discriminator-actions", "version": "1.0"},
        })
        self.notify("notifications/initialized")
        return r

    def list_tools(self):
        return self.request("tools/list", {})

    def call_tool(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

# -------------------------------------------------------------- helpers -----

def is_error_response(resp):
    if not isinstance(resp, dict):
        return True
    if "error" in resp or "exception" in resp:
        return True
    result = resp.get("result")
    if isinstance(result, dict) and result.get("isError"):
        return True
    return False

def result_text(resp):
    try:
        parts = resp["result"]["content"]
        return "\n".join(p.get("text", "") for p in parts if isinstance(p, dict))
    except Exception:
        return ""

def shape_field_names(resp):
    """Top-level field names of the JSON document inside an MCP text result —
    the only response content stdout is allowed to show."""
    js = _try_json(result_text(resp))
    if isinstance(js, dict):
        return sorted(str(k) for k in js.keys())[:16]
    if isinstance(js, list) and js and isinstance(js[0], dict):
        return sorted(str(k) for k in js[0].keys())[:16]
    return []

def count_write_tools(tools):
    return sum(1 for t in tools
               if not (t.get("annotations") or {}).get("readOnlyHint", False))

def event_landed(pid, n_before, n_after):
    """Local S5 rule: the RO event landed iff its fresh implicit profile
    exists AND the metric's event count grew past the FULL control's."""
    return bool(pid) and (n_after or 0) > (n_before or 0)

class Run:
    def __init__(self, run_id):
        self.run_id = run_id
        self.dir = OUT_DIR / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.verdicts = {}

    def save(self, name, obj):
        p = self.dir / name
        if isinstance(obj, (dict, list)):
            p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            p.write_text(str(obj), encoding="utf-8")
        return p

    def verdict(self, step, value, detail=""):
        self.verdicts[step] = {"verdict": value, "detail": detail}
        print(f"[{step}] {value} {detail}", flush=True)

def scrub_tree(root, secret_values):
    """Remove key material from every file under root: exact key values,
    any pk_... token, and any residual 'pk_' substring. Artifact-bound
    evidence must never carry a key, even if a server echoed one back."""
    root = Path(root)
    if not root.is_dir():
        return 0
    changed = 0
    token_re = re.compile(r"pk_[A-Za-z0-9_\-\.]+")
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_bytes().decode("utf-8", "replace")
        except Exception:
            continue
        new = text
        for v in secret_values:
            if v:
                new = new.replace(v, "REDACTED")
        new = token_re.sub("REDACTED", new)
        new = new.replace("pk_", "REDACTED")
        if new != text:
            p.write_text(new, encoding="utf-8")
            changed += 1
    return changed

def install_mcp_server():
    """pip install uv -> uv venv --python 3.13 -> uv pip install the server.
    Live path only (needs network). Returns the server binary path."""
    def find_uv():
        w = shutil.which("uv")
        if w:
            return w
        for cand in (Path(sys.executable).parent / "uv",
                     Path.home() / ".local" / "bin" / "uv"):
            if cand.is_file():
                return str(cand)
        return None
    uv = find_uv()
    if not uv:
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "uv"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise AbortRun(f"SETUP abort: pip install uv failed (rc={r.returncode})", 2)
        uv = find_uv()
    if not uv:
        raise AbortRun("SETUP abort: uv binary not found after install", 2)
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    r = subprocess.run([uv, "venv", "--python", "3.13", str(VENV_DIR)],
                       capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise AbortRun(f"SETUP abort: uv venv failed (rc={r.returncode})", 2)
    venv_py = VENV_DIR / "bin" / "python"
    r = subprocess.run([uv, "pip", "install", "--python", str(venv_py), MCP_PACKAGE],
                       capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise AbortRun(f"SETUP abort: uv pip install {MCP_PACKAGE} failed "
                       f"(rc={r.returncode})", 2)
    server_bin = VENV_DIR / "bin" / "klaviyo-mcp-server"
    if not server_bin.is_file():
        raise AbortRun(f"SETUP abort: server binary missing at {server_bin}", 2)
    print(f"[SETUP] MCP server installed: {MCP_PACKAGE} (venv python 3.13)", flush=True)
    return str(server_bin)

# ----------------------------------------------------------------- main -----

def main_live():
    key_x, key_y = get_env_keys()
    if not keys_ready(key_x, key_y):
        print("REFUSED: KLAVIYO_KEY_X and KLAVIYO_KEY_Y must both be set "
              "(and different). No traffic sent.")
        return 2
    secrets_to_scrub = [key_x, key_y]
    try:
        return _run_live(key_x, key_y)
    finally:
        n = scrub_tree(OUTPUTS_ROOT, secrets_to_scrub)
        print(f"[SCRUB] key material scrubbed from {n} file(s) under {OUTPUTS_ROOT}")

def _run_live(key_x, key_y):
    run_id = time.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    run = Run(run_id)
    base_email = os.environ.get("KL2_MARKER_BASE_EMAIL", "mitsudayoooooon@gmail.com")
    user, _, domain = base_email.partition("@")
    def marker(tag):
        return f"{user}+kl2{tag}-{run_id}@{domain}"
    em_full = marker("f")      # control profile (FULL key, MCP)
    em_ro = marker("r")        # test profile (RO key, MCP)
    em_evt_ro = marker("e")    # RO event probe profile (fresh)
    em_probe_x = marker("probex")
    em_probe_y = marker("probey")
    metric_name = f"KL2MARK-{run_id}"
    markers = {"full": em_full, "ro": em_ro, "evt_ro": em_evt_ro,
               "probe_x": em_probe_x, "probe_y": em_probe_y}
    for em in markers.values():
        assert "+kl2" in em, "marker namespace assertion failed"
    run.save("00_run.json", {"run_id": run_id, "revision": REVISION,
                             "markers": markers, "metric": metric_name,
                             "lane": "github-actions"})
    print(f"run_id={run_id} revision={REVISION} out={run.dir}", flush=True)

    # ---- STEP 0: discriminate the unordered keys (== local S2) ------------
    try:
        ro_key, full_key, records = resolve_keys(
            key_x, key_y, marker, run_id, rest, print)
    except AbortRun as e:
        run.save("00_step0_abort.json", {"reason": str(e)})
        print(f"ABORT: {e}")
        return e.exit_code
    run.save("00_step0.json", [
        {k: v for k, v in r.items() if k not in ("get_raw", "probe_raw")}
        | {"get_body": r["get_raw"], "probe_body": r["probe_raw"]}
        for r in records])
    run.verdict("S2-rest-control(step0)", "HELD",
                "RO key's raw-REST profile-create rejected 403 in step 0; "
                "FULL key's probe create accepted (cleaned up in S6)")

    # ---- SETUP: install the MCP server ------------------------------------
    try:
        server_bin = install_mcp_server()
    except AbortRun as e:
        print(f"ABORT: {e}")
        return e.exit_code

    sessions = {}
    def session(label, key):
        c = McpStdio([server_bin], key)
        hs = c.handshake()
        run.save(f"01_handshake_{label}.json", hs)
        if c.stderr_lines:
            run.save(f"01_stderr_{label}.txt", "\n".join(c.stderr_lines[-50:]))
        sessions[label] = c
        return c

    def safe_call(client, name, args, fname):
        try:
            resp = client.call_tool(name, args)
        except Exception as e:  # timeout / transport — record, don't crash
            resp = {"exception": repr(e)}
        run.save(fname, resp)
        return resp

    try:
        # ---- S1: shape capture -------------------------------------------
        listed = {}
        for label, key in (("full", full_key), ("ro", ro_key)):
            c = session(label, key)
            tl = c.list_tools()
            run.save(f"02_tools_list_{label}.json", tl)
            tools = []
            try:
                tools = tl["result"]["tools"]
            except Exception:
                pass
            listed[label] = [t.get("name", "") for t in tools]
            rd = safe_call(c, "klaviyo_get_account_details", {"model": "other"},
                           f"03_shape_read_{label}.json")
            fields = shape_field_names(rd)
            run.verdict(f"S1-{label}", "ERROR" if is_error_response(rd) else "OK",
                        f"tools={len(tools)} write_tools_listed={count_write_tools(tools)} "
                        f"account_fields={','.join(fields) if fields else '-'}")
        run.save("02b_tools_list_diff.json",
                 {"only_full": sorted(set(listed.get('full', [])) - set(listed.get('ro', []))),
                  "only_ro": sorted(set(listed.get('ro', [])) - set(listed.get('full', [])))})

        # ---- S3: control write via MCP (FULL key) -------------------------
        c_full = sessions["full"]
        safe_call(c_full, "klaviyo_create_profile", {
            "model": "other",
            "profile_data": {"email": em_full, "first_name": "KL2",
                             "last_name": f"FULL-{run_id}"}},
            "05_mcp_write_full.json")
        _, pid_full, rawf = rest_find_profile_id(em_full, full_key)
        run.save("05b_verify_full.txt", rawf)
        if pid_full:
            run.verdict("S3-control", "OK", "control write landed (read-back found)")
        else:
            run.verdict("S3-control", "ERROR",
                        "FULL-key MCP write did not land — run cannot "
                        "discriminate; inspect 05_mcp_write_full.json")
            run.save("verdict.json", run.verdicts)
            print("ABORT: control failure")
            return 3

        # ---- S4: test write W1 via MCP (RO key) ---------------------------
        c_ro = sessions["ro"]
        w_ro = safe_call(c_ro, "klaviyo_create_profile", {
            "model": "other",
            "profile_data": {"email": em_ro, "first_name": "KL2",
                             "last_name": f"RO-{run_id}"}},
            "06_mcp_write_ro.json")
        _, pid_ro, rawr = rest_find_profile_id(em_ro, full_key)
        run.save("06b_verify_ro.txt", rawr)
        if pid_ro:
            run.verdict("S4-W1-profile", "BROKEN",
                        f"RO key's MCP create_profile LANDED (read-back found); "
                        f"mcp_error={is_error_response(w_ro)}")
        else:
            run.verdict("S4-W1-profile", "HELD",
                        f"no profile after RO MCP write; "
                        f"mcp_error={is_error_response(w_ro)}")

        # ---- S5: event probe W2 -------------------------------------------
        ev_args = lambda em: {
            "model": "other",
            "event": {"properties": {"kl2_marker": run_id},
                      "unique_id": f"kl2-{run_id}-{em}"},
            "profile": {"type": "profile", "attributes": {"email": em}},
            "metric": {"type": "metric", "attributes": {"name": metric_name}}}
        safe_call(c_full, "klaviyo_create_event", ev_args(em_full),
                  "07_mcp_event_full.json")
        _, n_ev_full, rawef = rest_count_events(metric_name, full_key)
        run.save("07b_verify_event_full.txt", rawef)
        ev_ro = safe_call(c_ro, "klaviyo_create_event", ev_args(em_evt_ro),
                          "08_mcp_event_ro.json")
        _, pid_evt_ro, rawer = rest_find_profile_id(em_evt_ro, full_key)
        _, n_ev_after, rawer2 = rest_count_events(metric_name, full_key)
        run.save("08b_verify_event_ro.txt", rawer + "\n---\n" + rawer2)
        if event_landed(pid_evt_ro, n_ev_full, n_ev_after):
            run.verdict("S5-W2-event", "BROKEN",
                        f"RO key's MCP create_event landed (implicit profile "
                        f"found, events {n_ev_full} -> {n_ev_after})")
        elif is_error_response(ev_ro) and not pid_evt_ro:
            run.verdict("S5-W2-event", "HELD",
                        f"RO event rejected and no implicit profile created; "
                        f"control_events={n_ev_full}")
        else:
            run.verdict("S5-W2-event", "ERROR",
                        f"inconclusive: profile_found={bool(pid_evt_ro)} "
                        f"events {n_ev_full} -> {n_ev_after}; inspect raw evidence")

        # ---- S6: cleanup (every marker email, step-0 probes included) -----
        pid_by_marker = {}
        for tag, em in markers.items():
            _, pid, _raw = rest_find_profile_id(em, full_key)
            if pid:
                pid_by_marker[tag] = pid
        results = []
        for tag, pid in sorted(pid_by_marker.items()):
            st, js, raw = rest("POST", "/api/data-privacy-deletion-jobs", full_key,
                               {"data": {
                                   "type": "data-privacy-deletion-job",
                                   "attributes": {"profile": {
                                       "data": {"type": "profile", "id": pid}}}}})
            results.append({"marker": tag, "profile": pid, "status": st,
                            "body": js or raw})
        run.save("10_cleanup.json", results)
        run.verdict("S6-cleanup", "OK",
                    f"deletion jobs for {len(results)} marker profile(s) "
                    f"(statuses: {[r['status'] for r in results]})")
    finally:
        for c in sessions.values():
            c.close()

    run.save("verdict.json", run.verdicts)
    broken = [k for k, v in run.verdicts.items()
              if v["verdict"] == "BROKEN"]
    print("\n=== KL-2 VERDICT ===")
    for k, v in run.verdicts.items():
        print(f"{k}: {v['verdict']} — {v['detail']}")
    if broken:
        print("KL2 RESULT: BROKEN — step-0 RO REST write was 403, yet "
              f"{', '.join(broken)} landed via MCP (filing-grade shape; "
              "a second consecutive run is still required before filing)")
    else:
        print("KL2 RESULT: HELD — no RO-key MCP write landed")
    print(f"evidence: {run.dir}")
    return 0

# -------------------------------------------------------------- selftest ----

FAKE_SERVER = r'''
import json, sys
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()
TOOLS = [
  {"name": "klaviyo_get_account_details", "description": "read",
   "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}},
  {"name": "klaviyo_create_profile", "description": "write",
   "annotations": {"readOnlyHint": False}, "inputSchema": {"type": "object"}},
]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if "id" not in msg:
        continue  # notification
    m = msg.get("method")
    if m == "initialize":
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "serverInfo": {"name": "fake", "version": "0"}}})
    elif m == "tools/list":
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}})
    elif m == "tools/call":
        name = (msg.get("params") or {}).get("name")
        if name == "klaviyo_get_account_details":
            payload = {"data": [], "links": {"self": "x"}}
        else:
            payload = {"created": True}
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "isError": False}})
    else:
        send({"jsonrpc": "2.0", "id": msg["id"],
              "error": {"code": -32601, "message": "unknown method"}})
'''

def selftest():
    failures = []
    def check(name, fn):
        try:
            fn()
            print(f"SELFTEST PASS: {name}")
        except Exception as e:
            failures.append(name)
            print(f"SELFTEST FAIL: {name}: {e!r}")

    # -- guard: keys missing / identical -> not ready, zero network ---------
    def t_guard():
        saved = {k: os.environ.pop(k, None) for k in ("KLAVIYO_KEY_X", "KLAVIYO_KEY_Y")}
        try:
            x, y = get_env_keys()
            assert not keys_ready(x, y), "empty env must not be ready"
            os.environ["KLAVIYO_KEY_X"] = "SAME"
            os.environ["KLAVIYO_KEY_Y"] = "SAME"
            x, y = get_env_keys()
            assert not keys_ready(x, y), "identical keys must not be ready"
            os.environ["KLAVIYO_KEY_Y"] = "DIFFERENT"
            x, y = get_env_keys()
            assert keys_ready(x, y), "two distinct keys must be ready"
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    check("guard: env key readiness", t_guard)

    def t_guard_main_refuses():
        saved = {k: os.environ.pop(k, None) for k in ("KLAVIYO_KEY_X", "KLAVIYO_KEY_Y")}
        try:
            rc = main_live()
            assert rc == 2, f"main_live with no keys must return 2, got {rc}"
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    check("guard: main_live refuses without keys (exit 2, no traffic)", t_guard_main_refuses)

    # -- classification ------------------------------------------------------
    def t_classify():
        assert classify_write_status(201) == "FULL"
        assert classify_write_status(200) == "FULL"
        assert classify_write_status(403) == "RO"
        assert classify_write_status(401) == "UNKNOWN"
        assert classify_write_status(None) == "UNKNOWN"
    check("classify_write_status", t_classify)

    # -- step 0 with a fake REST layer ---------------------------------------
    def fake_rest_factory(behaviour):
        def fake_rest(method, path, key, body=None, timeout=60):
            if path == "/api/accounts/":
                st = behaviour.get("get", {}).get(key, 200)
                return st, {"data": []} if st == 200 else None, "{}"
            if path == "/api/profiles/":
                st = behaviour.get("post", {}).get(key, 403)
                return st, {"data": {}} if st in (200, 201) else None, "{}"
            return 404, None, "{}"
        return fake_rest

    def marker_stub(tag):
        return f"probe+kl2{tag}@example.invalid"

    def t_step0_ok():
        rest_fn = fake_rest_factory({"post": {"KX": 201, "KY": 403}})
        ro, full, recs = resolve_keys("KX", "KY", marker_stub, "selftest",
                                      rest_fn, lambda *a: None)
        assert full == "KX" and ro == "KY", f"mapping wrong: ro={ro} full={full}"
        assert [r["class"] for r in recs] == ["FULL", "RO"]
    check("step0: one FULL + one RO resolves (X=FULL)", t_step0_ok)

    def t_step0_swapped():
        rest_fn = fake_rest_factory({"post": {"KX": 403, "KY": 201}})
        ro, full, _ = resolve_keys("KX", "KY", marker_stub, "selftest",
                                   rest_fn, lambda *a: None)
        assert ro == "KX" and full == "KY"
    check("step0: swapped mapping resolves (X=RO)", t_step0_swapped)

    def t_step0_both_full_aborts():
        rest_fn = fake_rest_factory({"post": {"KX": 201, "KY": 201}})
        try:
            resolve_keys("KX", "KY", marker_stub, "selftest", rest_fn, lambda *a: None)
        except AbortRun as e:
            assert e.exit_code == 2
            return
        raise AssertionError("both-FULL must abort")
    check("step0: both FULL aborts", t_step0_both_full_aborts)

    def t_step0_both_ro_aborts():
        rest_fn = fake_rest_factory({"post": {"KX": 403, "KY": 403}})
        try:
            resolve_keys("KX", "KY", marker_stub, "selftest", rest_fn, lambda *a: None)
        except AbortRun:
            return
        raise AssertionError("both-RO must abort")
    check("step0: both RO aborts", t_step0_both_ro_aborts)

    def t_step0_get_fail_aborts():
        rest_fn = fake_rest_factory({"get": {"KY": 401}, "post": {"KX": 201, "KY": 403}})
        try:
            resolve_keys("KX", "KY", marker_stub, "selftest", rest_fn, lambda *a: None)
        except AbortRun:
            return
        raise AssertionError("GET /api/accounts/ != 200 must abort")
    check("step0: accounts GET failure aborts", t_step0_get_fail_aborts)

    # -- verdict helper --------------------------------------------------------
    def t_event_landed():
        assert event_landed("prof_1", 1, 2) is True
        assert event_landed("prof_1", 1, 1) is False
        assert event_landed(None, 0, 5) is False
        assert event_landed("prof_1", None, None) is False
    check("event_landed (local S5 rule)", t_event_landed)

    # -- scrub -----------------------------------------------------------------
    def t_scrub():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "evidence.json"
            p.write_text('{"key": "pk_AbC-123_x", "other": "pk_ tail"}', encoding="utf-8")
            scrub_tree(td, ["pk_AbC-123_x"])
            out = p.read_text(encoding="utf-8")
            assert "pk_" not in out, f"pk_ survived scrub: {out}"
            assert "REDACTED" in out
    check("scrub_tree removes pk_ material", t_scrub)

    # -- JSON-RPC framing against a fake stdio server ---------------------------
    def t_mcp_framing():
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "fake_server.py"
            fake.write_text(FAKE_SERVER, encoding="utf-8")
            shim = Path(td) / "fake_server.sh"
            shim.write_text(f'#!/bin/sh\nexec {sys.executable} {fake}\n', encoding="utf-8")
            shim.chmod(0o755)
            c = McpStdio([str(shim)], "SELFTEST-NOT-A-REAL-KEY")
            try:
                hs = c.handshake()
                assert hs.get("result", {}).get("serverInfo", {}).get("name") == "fake", hs
                tl = c.list_tools()
                tools = tl["result"]["tools"]
                assert len(tools) == 2 and count_write_tools(tools) == 1, tools
                rd = c.call_tool("klaviyo_get_account_details", {"model": "other"})
                assert not is_error_response(rd), rd
                assert shape_field_names(rd) == ["data", "links"], shape_field_names(rd)
                wr = c.call_tool("klaviyo_create_profile",
                                 {"model": "other", "profile_data": {"email": "x@y.z"}})
                assert not is_error_response(wr), wr
                err = c.request("no/such_method", {})
                assert is_error_response(err), err
            finally:
                c.close()
    check("mcp stdio framing (initialize/list/call/error)", t_mcp_framing)

    print(f"\nSELFTEST {'FAILED: ' + ', '.join(failures) if failures else 'ALL PASS'}")
    return 1 if failures else 0

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main_live())
