#!/usr/bin/env python3
"""KL-6 battery — GitHub Actions build (repo: o-yutaka/moka-harness).

KL-6 = Private API Key stored in a Flow Webhook definition: which
READ paths hand the stored key back, and to whom
(notes/candidates.md KL-6; authz-model.md Seam C).

Refined hypothesis (attacker pass first):
  * Who takes what: the holder of a RESTRICTED credential for the
    merchant's account — the sharpest persona is a READ-ONLY key,
    the kind of credential handed to agents/integrations precisely
    because it "cannot do anything". Klaviyo's own Solution Recipes
    instruct merchants to paste a real Private API Key into a Flow
    Webhook's Authorization header (self-loop recipes). The key thus
    becomes stored configuration data inside a flow. If any flow READ
    path returns the header value verbatim, a flows:read-only reader
    extracts a live private key and escalates to whatever scope that
    key carries (recipes encourage broad keys). Chain: RO key ->
    GET flow definition -> stored key -> full API access.
  * Strongest benign story (triage-null, from the card): "Header
    values are encrypted at rest and only ever returned masked on
    every surface — UI, API, clone, export. No read path returns the
    real value." The developer guide's "all information for webhook
    headers are partially hashed" describes DISPLAY; what the
    definition API returns is undocumented — that gap is the test.
  * Intent vs implementation (seams): lifecycle seam (create accepts
    plaintext -> storage -> read-back: where does masking attach?),
    surface seam (UI display masked vs definition API built for
    programmatic copying), scope seam (flows:read is a low scope
    guarding a credential store).
  * Relation to KL-2: KL-2 measured scope binding on the MCP tool
    surface and was REFUTED there. KL-6 is a different surface (flow
    definition storage) and a different mechanism (stored-credential
    read-back, not tool-call binding) — triage treats them apart.
  * Non-claims (from the card): "flow webhooks can POST to arbitrary
    destinations" is the feature itself and is NOT claimed. The
    recipes' existence is public documentation, not a finding. The
    claim is only: a stored key comes back in usable form on a read
    path available to a lower-privilege reader.

Canary discipline (the safety core): masking is a property of the
READ PATH, not of the value's validity, so phase 1 never endangers a
real key. The script plants a generated string `pk_kl6probe_<hex>`
(canary-string mode, default). If a path returns it verbatim or as a
long fragment, phase 2 repeats with a REAL disposable narrow-scope
key supplied via env KL6_CANARY_KEY (created in the UI by the parent
solely for this test, deleted in the UI afterwards) to prove the
stored value is a working credential. The canary/key value itself is
NEVER printed; verdicts record only its classification per path.

Setup is response_shape_first: flow creation via POST /api/flows/
tries webhook settings shapes W1/W2/W3 in order and records which
the API accepts; if creation fails in every shape, the battery falls
back to a flow the parent created in the UI (recipe) whose id is
passed via --flow-id (an id is not a secret). The flow stays DRAFT
with a metric trigger that never fires and an example.com
destination — nothing is ever sent.

Keys: env KLAVIYO_KEY_X / KLAVIYO_KEY_Y (unordered; GitHub Secrets),
tenant B only. Step 0 discriminates exactly like kl1/kl2/kl5:
GET /api/accounts/ 200 for both; probe POST /api/profiles/ 201 =>
FULL, 403 => RO.

Safety rails:
  * Tenant B only; the flow and probe profiles are our own.
  * No /api/v1/people, no profile enumeration. Verification reads are
    by-id or equals(name) on OUR flow only.
  * stdout is a PUBLIC log: step names, statuses, classifications,
    counts. Never key values, never the canary value, never bodies.
  * Full bodies go to outputs/kl6/<run_id>/, scrubbed of key AND
    canary material before exit.
  * Cleanup: the created flow is archived (PATCH status). A real key
    used in phase 2 must be deleted in the UI (keys are UI-managed);
    the script prints that obligation as a verdict line.

Exit codes mirror kl1/kl2/kl5: 2 = refused (missing keys),
3 = control failure / incomplete, 0 = completed.
--selftest: in-memory fake transport, behaviour modes masked / open
/ ro-open / fragment / setup-fail, ZERO network. Asserts exposure
classification, RO-asymmetry detection, setup fallback, the 429
throttle retry, and output scrubbing.
"""
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API_BASE = "https://a.klaviyo.com"
REVISION = os.environ.get("KL6_REVISION", "2024-10-15")
OUTPUTS_ROOT = Path(os.environ.get("KL6_OUTPUTS_ROOT", "outputs"))
OUT_DIR = OUTPUTS_ROOT / "kl6"
MARKER_DOMAIN = "gmail.com"
MARKER_LOCAL = "mitsudayoooooon"
DEST_URL = "https://example.com/kl6-probe"
FRAGMENT_MIN = 16  # prefix match must reach into the random part

# ---------------------------------------------------------------- keys ------

def get_env_keys():
    return (os.environ.get("KLAVIYO_KEY_X", "").strip(),
            os.environ.get("KLAVIYO_KEY_Y", "").strip())

def keys_ready(key_x, key_y):
    return bool(key_x) and bool(key_y) and key_x != key_y

def get_canary():
    """(value, mode) — real disposable key from env, else a generated
    canary string. The value is used in-memory only."""
    v = os.environ.get("KL6_CANARY_KEY", "").strip()
    if v:
        return v, "REAL-KEY"
    return "pk_kl6probe_" + secrets.token_hex(12), "CANARY-STRING"

# ------------------------------------------------------------- transport ----

def _with_throttle_retry(once_fn):
    """Klaviyo burst-throttles (429 with a server-stated wait,
    measured live 2026-11-09). Retry up to 4 times (kl5 shape)."""
    attempt = 0
    while True:
        status, js, raw = once_fn()
        if status != 429 or attempt >= 4:
            return status, js, raw
        wait = 2.0 * (attempt + 1)
        m = re.search(r"available in (\d+(?:\.\d+)?) second", raw or "")
        if m:
            wait = min(float(m.group(1)) + 0.5, 20.0)
        time.sleep(wait)
        attempt += 1


def _rest_once(method, path, key, body=None, revision=None, timeout=60):
    url = API_BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Klaviyo-API-Key {key}")
    req.add_header("revision", revision or REVISION)
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


def rest(method, path, key, body=None, revision=None, timeout=60):
    """Server API (private key) with 429 retry — kl1/kl5 rest() shape."""
    return _with_throttle_retry(
        lambda: _rest_once(method, path, key, body, revision, timeout))


def _try_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None

# ------------------------------------------------------------ run state -----

class Run:
    def __init__(self, run_id):
        self.run_id = run_id
        self.dir = OUT_DIR / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.verdicts = {}

    def save(self, name, obj):
        p = self.dir / name
        if isinstance(obj, (dict, list)):
            p.write_text(json.dumps(obj, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        else:
            p.write_text(str(obj), encoding="utf-8")
        return p

    def verdict(self, step, value, detail=""):
        self.verdicts[step] = {"verdict": value, "detail": detail}
        print(f"[{step}] {value} {detail}", flush=True)

def scrub_tree(root, secret_values):
    """Remove key/canary material from every file under root (kl1/kl2/
    kl5 discipline)."""
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

# --------------------------------------------------------- shape helpers ----

def marker_email(role, run_id):
    return f"{MARKER_LOCAL}+kl6{role}{run_id[-4:]}@{MARKER_DOMAIN}"

def classify_write_status(status):
    if status in (200, 201):
        return "FULL"
    if status == 403:
        return "RO"
    return f"OTHER({status})"

# ---------------------------------------------------------- step 0 ----------

def resolve_keys(rest_fn, key_x, key_y, run_id, run):
    """Discriminate X/Y by REST behaviour (kl1/kl2/kl5 step 0).
    Returns (ro_key, full_key) or (None, None)."""
    records = {}
    classes = {}
    for label, key in (("X", key_x), ("Y", key_y)):
        st_get, _js, raw_get = rest_fn("GET", "/api/accounts/", key)
        probe_email = marker_email(f"x0{label.lower()}", run_id)
        body = {"data": {"type": "profile", "attributes": {
            "email": probe_email, "first_name": "KL6",
            "last_name": f"PROBE-{label}-{run_id}",
            "properties": {"kl6_marker": run_id}}}}
        st_post, _js2, raw_post = rest_fn("POST", "/api/profiles/",
                                          key, body)
        cls = classify_write_status(st_post) if st_get == 200 else "NOREAD"
        classes[label] = cls
        records[label] = {"get_accounts_status": st_get,
                          "probe_post_status": st_post, "class": cls}
        run.save(f"step0_{label}.txt", (raw_get or "") + "\n---\n" +
                 (raw_post or ""))
        print(f"[STEP0] key {label}: accounts={st_get} probe_post="
              f"{st_post} -> {cls}", flush=True)
    run.save("step0.json", records)
    if sorted(classes.values()) != ["FULL", "RO"]:
        return None, None
    full_label = [k for k, v in classes.items() if v == "FULL"][0]
    ro_label = [k for k, v in classes.items() if v == "RO"][0]
    return (key_x if ro_label == "X" else key_y,
            key_x if full_label == "X" else key_y)

# --------------------------------------------------- exposure classifier ----

def longest_prefix_in(text, value):
    """Longest prefix of value appearing verbatim in text (0 if even
    the first 8 chars are absent)."""
    if not text or not value:
        return 0
    best = 0
    for n in range(8, len(value) + 1):
        if value[:n] in text:
            best = n
        else:
            break
    return best

def classify_exposure(raw, canary, probe):
    """Classify one read-path response body. Returns a dict:
    class: VERBATIM | FRAGMENT | MASKED | ABSENT
      VERBATIM — the full planted value is in the body.
      FRAGMENT — a prefix of >= FRAGMENT_MIN chars is in the body
                 (reaches into the random part of the value).
      MASKED   — an Authorization header is present in the body but
                 its value is transformed (no usable prefix).
      ABSENT   — no Authorization header and no value fragment: this
                 path does not expose the header block at all.
    probe_present: the innocuous probe header value was found, i.e.
    the header block itself is part of this read path's output."""
    text = raw or ""
    low = text.lower()
    n = longest_prefix_in(text, canary)
    probe_present = bool(probe) and probe in text
    if n >= len(canary):
        cls = "VERBATIM"
    elif n >= FRAGMENT_MIN:
        cls = "FRAGMENT"
    elif "authorization" in low:
        cls = "MASKED"
    else:
        cls = "ABSENT"
    return {"class": cls, "prefix_len": n,
            "probe_present": probe_present}

# ------------------------------------------------------------ flow setup ----

def webhook_settings(shape, canary, probe):
    auth = f"Klaviyo-API-Key {canary}"
    body = {"kl6_probe": probe}
    if shape == "W1":
        return {"url": DEST_URL,
                "headers": [{"key": "Authorization", "value": auth},
                            {"key": "X-KL6-Probe", "value": probe}],
                "body": body}
    if shape == "W2":
        return {"url": DEST_URL,
                "headers": [{"name": "Authorization", "value": auth},
                            {"name": "X-KL6-Probe", "value": probe}],
                "body": body}
    # W3
    return {"destination_url": DEST_URL,
            "headers": {"Authorization": auth, "X-KL6-Probe": probe},
            "body": body}

def create_flow(rest_fn, full_key, name, canary, probe, run):
    """Try definition shapes in order (response_shape_first). Returns
    (flow_id, shape_used, create_raw) or (None, None, last_raw)."""
    tid = "kl6act1"
    for shape in ("W1", "W2", "W3"):
        definition = {
            "trigger_type": "metric",
            "entry_action_id": tid,
            "actions": [{
                "temporary_id": tid,
                "type": "send-webhook",
                "settings": webhook_settings(shape, canary, probe),
                "next_action_id": None}],
        }
        body = {"data": {"type": "flow", "attributes": {
            "name": name, "definition": definition}}}
        st, js, raw = rest_fn("POST", "/api/flows/", full_key, body)
        run.save(f"setup_create_{shape}.txt", raw or "")
        print(f"[SETUP] shape {shape}: POST /api/flows/ -> {st}",
              flush=True)
        fid = None
        if isinstance(js, dict):
            d = js.get("data") or {}
            if isinstance(d, dict):
                fid = d.get("id")
        if st in (200, 201) and fid:
            return fid, shape, raw
    return None, None, None

# ------------------------------------------------------------ read paths ----

def find_action_ids(raw):
    """Candidate flow-action ids from a flow-actions list response:
    ids of entries whose type mentions webhook, else all ids."""
    ids = []
    try:
        js = json.loads(raw)
    except Exception:
        return ids
    data = js.get("data") if isinstance(js, dict) else None
    if isinstance(data, list):
        webhook_ids, other_ids = [], []
        for item in data:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            blob = json.dumps(item).lower()
            (webhook_ids if "webhook" in blob else other_ids).append(
                item["id"])
        ids = webhook_ids + other_ids
    return ids[:3]

def read_paths(rest_fn, key, key_label, fid, flow_name, canary, probe,
               run):
    """Run R1..R5 for one key; returns {path_label: classification}."""
    enc = urllib.parse.quote
    paths = [
        ("R1", f"/api/flows/{fid}/"),
        ("R2", f"/api/flows/{fid}/?additional-fields%5Bflow%5D=definition"),
        ("R3", f"/api/flows/{fid}/flow-actions/"),
        ("R5", "/api/flows/?additional-fields%5Bflow%5D=definition"
               "&filter=" + enc(f'equals(name,"{flow_name}")', safe="")),
    ]
    results = {}
    action_ids = []
    for label, path in paths:
        st, _js, raw = rest_fn("GET", path, key)
        run.save(f"read_{key_label}_{label}.txt", raw or "")
        c = classify_exposure(raw, canary, probe)
        c["status"] = st
        results[label] = c
        run.verdict(f"KL6-READ-{key_label}-{label}", c["class"],
                    f"status={st} prefix_len={c['prefix_len']} "
                    f"probe_present={c['probe_present']}")
        if label == "R3":
            action_ids = find_action_ids(raw or "")
    for aid in action_ids:
        label = "R4"
        st, _js, raw = rest_fn("GET", f"/api/flow-actions/{aid}/", key)
        run.save(f"read_{key_label}_{label}.txt", raw or "")
        c = classify_exposure(raw, canary, probe)
        c["status"] = st
        results[label] = c
        run.verdict(f"KL6-READ-{key_label}-{label}", c["class"],
                    f"status={st} prefix_len={c['prefix_len']} "
                    f"probe_present={c['probe_present']}")
        break  # one action read is enough for the classification
    return results

# -------------------------------------------------------------- battery -----

def overall_verdict(full_res, ro_res):
    """Combine per-key classifications into the KL-6 overall."""
    def classes(res):
        return [c["class"] for c in res.values()]
    if "VERBATIM" in classes(ro_res):
        return ("EXPOSED-VERBATIM-RO",
                "a read-only key read back the full stored value — "
                "restricted credential escalates to the stored key")
    if "VERBATIM" in classes(full_res):
        return ("EXPOSED-VERBATIM",
                "the full stored value comes back on a flow read "
                "path (FULL key); the RO paths did not expose it")
    for res in (ro_res, full_res):
        for c in res.values():
            if c["class"] == "FRAGMENT":
                return ("EXPOSED-FRAGMENT",
                        f"a prefix of {c['prefix_len']} chars of the "
                        "stored value is returned on a read path")
    allc = classes(full_res) + classes(ro_res)
    if allc and all(c in ("MASKED", "ABSENT") for c in allc) and \
            "MASKED" in allc:
        return ("HELD",
                "every definition-bearing read path returns the "
                "header transformed (masked); triage-null stands on "
                "the API surface")
    if allc and all(c == "ABSENT" for c in allc):
        return ("NO-HEADER-IN-API",
                "no API read path returns the webhook header block "
                "at all; only UI legs (low-privilege view, clone) "
                "remain")
    return ("INCOMPLETE", "read paths returned mixed/empty evidence")

def run_battery(rest_fn, key_x, key_y, flow_id_arg, run):
    """Returns process exit code. All verdicts go through run."""
    if not keys_ready(key_x, key_y):
        run.verdict("KL6-GUARD", "REFUSED",
                    "KLAVIYO_KEY_X / KLAVIYO_KEY_Y missing or identical")
        return 2
    canary, canary_mode = get_canary()
    probe = "kl6probe-" + run.run_id[-6:]
    ro_key, full_key = resolve_keys(rest_fn, key_x, key_y,
                                    run.run_id, run)
    if not full_key:
        run.verdict("KL6-STEP0", "ABORT",
                    "key discrimination failed (need exactly one FULL "
                    "and one RO, both reading /api/accounts/ at 200)")
        return 3
    run.verdict("KL6-TENANT", "NOTE",
                f"tenant B only; canary mode {canary_mode}; server "
                f"revision {REVISION} recorded (Seam J hygiene)")
    flow_name = f"KL6 Probe {run.run_id}"
    fid = flow_id_arg
    created = False
    if fid:
        run.verdict("KL6-SETUP", "EXTERNAL-FLOW",
                    "using parent-supplied flow id (UI-created); "
                    "creation shapes skipped")
    else:
        fid, shape, create_raw = create_flow(rest_fn, full_key,
                                             flow_name, canary, probe,
                                             run)
        if fid:
            created = True
            run.verdict("KL6-SETUP", f"CREATED-{shape}",
                        "flow created via POST /api/flows/ in draft; "
                        "webhook never fires (metric trigger unused, "
                        "destination is example.com)")
            c0 = classify_exposure(create_raw, canary, probe)
            run.verdict("KL6-READ-FULL-R0", c0["class"],
                        f"creation response; prefix_len="
                        f"{c0['prefix_len']} probe_present="
                        f"{c0['probe_present']}")
        else:
            run.verdict("KL6-SETUP", "NEEDS-UI",
                        "POST /api/flows/ rejected every candidate "
                        "webhook settings shape; parent creates the "
                        "flow in the UI (official recipe) and re-runs "
                        "with --flow-id")
            run.verdict("KL6-OVERALL", "INCOMPLETE",
                        "no flow to read; setup is the blocker")
            return 3
    full_res = read_paths(rest_fn, full_key, "FULL", fid, flow_name,
                          canary, probe, run)
    ro_res = read_paths(rest_fn, ro_key, "RO", fid, flow_name,
                        canary, probe, run)
    if created:
        # fold the creation-response classification into FULL results
        pass
    value, detail = overall_verdict(full_res, ro_res)
    run.verdict("KL6-OVERALL", value, detail +
                f" (canary mode {canary_mode})")
    # Cleanup: archive our flow (shape candidates; non-fatal).
    if created:
        body = {"data": {"type": "flow", "id": fid,
                         "attributes": {"status": "archived"}}}
        st, _js, raw = rest_fn("PATCH", f"/api/flows/{fid}/",
                               full_key, body)
        run.save("cleanup_archive.txt", raw or "")
        run.verdict("KL6-CLEANUP", "ARCHIVE-ATTEMPTED",
                    f"PATCH flow status -> {st}")
    if canary_mode == "REAL-KEY":
        run.verdict("KL6-CLEANUP", "KEY-DELETION-OWED",
                    "the disposable key planted for phase 2 must be "
                    "deleted in Settings > API Keys (UI only)")
    return 0

# --------------------------------------------------------------- main -------

def _finish(run, keys, code):
    run.save("verdict.json", run.verdicts)
    scrub_tree(OUT_DIR, [k for k in keys if k])
    print(f"[DONE] verdicts in outputs/kl6/{run.run_id}/verdict.json",
          flush=True)
    return code

def main_live(argv):
    key_x, key_y = get_env_keys()
    run_id = time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + \
        secrets.token_hex(2)
    run = Run(run_id)
    flow_id = None
    if "--flow-id" in argv:
        i = argv.index("--flow-id")
        if i + 1 < len(argv):
            flow_id = argv[i + 1]
    canary, _mode = get_canary()
    code = run_battery(rest, key_x, key_y, flow_id, run)
    return _finish(run, (key_x, key_y, canary), code)

# ------------------------------------------------------------ selftest ------

class FakeFlows:
    """In-memory transport for kl6 selftest. Stores whatever value the
    battery plants (like the real server would) and renders it back
    per mode:
      masked    — header present, value transformed on every path
      open      — value verbatim on definition paths for both keys
      ro-open   — value verbatim ONLY for the RO key (asymmetry)
      fragment  — first 18 chars of the value + ellipsis
      setup-fail— POST /api/flows/ always 400 (UI fallback path)
    """

    FULL = "pk_FAKE_FULL_KEY_0001"
    RO = "pk_FAKE_RO_KEY_0002"

    def __init__(self, mode):
        self.mode = mode
        self.planted = None
        self.probe = None

    def _render_value(self, key):
        v = self.planted or ""
        if self.mode == "open":
            return f"Klaviyo-API-Key {v}"
        if self.mode == "ro-open":
            if key == self.RO:
                return f"Klaviyo-API-Key {v}"
            return "Klaviyo-API-Key ••••••••••••"
        if self.mode == "fragment":
            return f"Klaviyo-API-Key {v[:18]}…"
        return "Klaviyo-API-Key ••••••••••••"

    def _definition_raw(self, key):
        js = {"data": {"id": "FLOW1", "type": "flow", "attributes": {
            "name": "KL6 Probe x",
            "definition": {"trigger_type": "metric", "actions": [{
                "type": "send-webhook",
                "settings": {"url": DEST_URL, "headers": [
                    {"key": "Authorization",
                     "value": self._render_value(key)},
                    {"key": "X-KL6-Probe",
                     "value": self.probe or ""}]}}]}}}}
        return json.dumps(js)

    def __call__(self, method, path, key, body=None, revision=None,
                 timeout=None):
        clean = path.split("?")[0]
        if clean == "/api/accounts/" and method == "GET":
            return 200, {"data": []}, '{"data": []}'
        if clean == "/api/profiles/" and method == "POST":
            if key == self.RO:
                return 403, {"errors": []}, '{"errors": []}'
            js = {"data": {"id": "prof-x", "type": "profile"}}
            return 201, js, json.dumps(js)
        if clean == "/api/flows/" and method == "POST":
            if self.mode == "setup-fail":
                err = {"errors": [{"detail": "bad definition"}]}
                return 400, err, json.dumps(err)
            blob = json.dumps(body)
            m = re.search(r"Klaviyo-API-Key (pk_[A-Za-z0-9_\-]+)", blob)
            self.planted = m.group(1) if m else None
            m2 = re.search(r"(kl6probe-[A-Za-z0-9\-]+)", blob)
            self.probe = m2.group(1) if m2 else None
            js = {"data": {"id": "FLOW1", "type": "flow",
                           "attributes": {"name": "KL6 Probe x"}}}
            return 201, js, json.dumps(js)
        if clean == "/api/flows/FLOW1/" and method == "GET":
            if "additional-fields" in path:
                raw = self._definition_raw(key)
                return 200, json.loads(raw), raw
            js = {"data": {"id": "FLOW1", "type": "flow",
                           "attributes": {"name": "KL6 Probe x"}}}
            return 200, js, json.dumps(js)
        if clean == "/api/flows/FLOW1/flow-actions/" and method == "GET":
            js = {"data": [{"id": "ACT1", "type": "flow-action",
                            "attributes": {"type": "send-webhook"}}]}
            return 200, js, json.dumps(js)
        if clean == "/api/flow-actions/ACT1/" and method == "GET":
            js = {"data": {"id": "ACT1", "type": "flow-action",
                           "attributes": {"settings": {
                               "url": DEST_URL, "headers": [
                                   {"key": "Authorization",
                                    "value": self._render_value(key)},
                                   {"key": "X-KL6-Probe",
                                    "value": self.probe or ""}]}}}}
            raw = json.dumps(js)
            return 200, js, raw
        if clean == "/api/flows/" and method == "GET":
            raw = self._definition_raw(key)
            return 200, json.loads(raw), raw
        if clean == "/api/flows/FLOW1/" and method == "PATCH":
            return 200, {"data": {}}, '{"data": {}}'
        return 404, None, "not found"


def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))
        print(f"[SELFTEST] {'ok' if cond else 'FAIL'}: {name}",
              flush=True)

    def run_mode(mode, flow_id=None):
        srv = FakeFlows(mode)
        run = Run("selftest-" + mode + "-" + secrets.token_hex(2))
        code = run_battery(srv, srv.RO, srv.FULL, flow_id, run)
        return srv, run, code

    # classifier unit checks
    canary = "pk_kl6probe_0123456789abcdef01234567"
    c = classify_exposure('{"v": "Klaviyo-API-Key ' + canary + '"}',
                          canary, "kl6probe-x")
    check("classifier verbatim", c["class"] == "VERBATIM")
    c = classify_exposure('{"v": "Klaviyo-API-Key ' + canary[:18] +
                          '…"}', canary, "kl6probe-x")
    check("classifier fragment", c["class"] == "FRAGMENT")
    c = classify_exposure('{"k": "Authorization", "v": "••••"}',
                          canary, "kl6probe-x")
    check("classifier masked", c["class"] == "MASKED")
    c = classify_exposure('{"name": "flow"}', canary, "kl6probe-x")
    check("classifier absent", c["class"] == "ABSENT")

    _s, run, code = run_mode("masked")
    check("masked mode completes", code == 0)
    check("masked mode overall HELD",
          run.verdicts["KL6-OVERALL"]["verdict"] == "HELD")

    _s, run, code = run_mode("open")
    check("open mode overall EXPOSED-VERBATIM-RO",
          run.verdicts["KL6-OVERALL"]["verdict"] ==
          "EXPOSED-VERBATIM-RO")

    _s, run, code = run_mode("ro-open")
    check("ro-open overall EXPOSED-VERBATIM-RO",
          run.verdicts["KL6-OVERALL"]["verdict"] ==
          "EXPOSED-VERBATIM-RO")
    check("ro-open FULL R2 stays MASKED",
          run.verdicts["KL6-READ-FULL-R2"]["verdict"] == "MASKED")

    _s, run, code = run_mode("fragment")
    check("fragment overall EXPOSED-FRAGMENT",
          run.verdicts["KL6-OVERALL"]["verdict"] == "EXPOSED-FRAGMENT")

    _s, run, code = run_mode("setup-fail")
    check("setup-fail returns 3", code == 3)
    check("setup-fail overall INCOMPLETE",
          run.verdicts["KL6-OVERALL"]["verdict"] == "INCOMPLETE")

    _s, run, code = run_mode("setup-fail", flow_id="FLOW1")
    check("setup-fail + external flow id still measures",
          code == 0 and
          run.verdicts["KL6-SETUP"]["verdict"] == "EXTERNAL-FLOW")

    # both keys FULL must abort discrimination
    srv = FakeFlows("masked")
    run = Run("selftest-bothfull-" + secrets.token_hex(2))
    code = run_battery(srv, srv.FULL, srv.FULL, None, run)
    check("identical keys refused", code == 2)

    # 429 throttle retry recovers
    state = {"n": 0}

    def flaky():
        state["n"] += 1
        if state["n"] == 1:
            return 429, None, "Request was throttled. Expected " \
                              "available in 0 second"
        return 200, {}, "ok"

    st, _js, _raw = _with_throttle_retry(flaky)
    check("throttle retry recovers", st == 200 and state["n"] == 2)

    # scrub removes planted canary + key material from artifacts
    victim = OUT_DIR / "scrub-test.txt"
    victim.parent.mkdir(parents=True, exist_ok=True)
    victim.write_text("leak pk_kl6probe_deadbeefcafe and " +
                      FakeFlows.FULL, encoding="utf-8")
    scrub_tree(OUT_DIR, [FakeFlows.FULL])
    text = victim.read_text(encoding="utf-8")
    check("scrub removes pk_ material",
          "pk_" not in text and FakeFlows.FULL not in text)
    victim.unlink()

    failed = [n for n, ok in checks if not ok]
    print(f"[SELFTEST] {len(checks) - len(failed)}/{len(checks)} "
          f"checks passed", flush=True)
    if failed:
        print("[SELFTEST] FAILED: " + ", ".join(failed), flush=True)
        return 1
    print("[SELFTEST] ALL OK", flush=True)
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main_live(sys.argv[1:]))
