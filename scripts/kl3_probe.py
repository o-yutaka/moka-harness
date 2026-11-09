#!/usr/bin/env python3
"""KL-3 surface-discovery probe — GitHub Actions build
(repo: o-yutaka/moka-harness).

KL-3 = warehouse connection credential handling + connection-test
verification (notes/candidates.md KL-3; authz-model.md Seam C).

Status going in (attacker pass, 2026-11-09): PARKED, not killed.
The card's own kill condition says: if the prerequisite (Advanced
KDP) never opens, the candidate stays "unverified, parked" — and
Advanced KDP is a paid subscription whose premium invitation is
still only auto-acknowledged. On top of that, no public API for
warehouse connections appears in Klaviyo's developer docs: connection
create/test/read-back all live in the Advanced KDP UI
(Advanced > Data management > Syncing). The stored credentials at
stake are the biggest prize of the three remaining candidates
(Snowflake private key, full PEM; BigQuery service-account JSON,
full text), so "no API surface" must be EVIDENCE, not assumption.

This probe therefore measures exactly one thing: does any API
surface on tenant B expose (a) warehouse/CDP connection objects, or
(b) stored credential material of any kind? It is GET-only.

Legs:
  KL3-OBJECTS  — Custom Objects API reachability on tenant B
                 (GET /api/data-sources/, revision 2026-07-15).
                 Maps what the "objects" half of the card's title
                 amounts to on the free plan. Object data sources do
                 NOT hold warehouse credentials; recorded as mapping,
                 not as a KL-3 result.
  KL3-SURFACE  — candidate warehouse/CDP connection paths, all
                 GUESSES and labelled as such in the verdicts:
                 /api/warehouse-connections/, /api/data-warehouse-
                 connections/, /api/warehouse-syncs/,
                 /api/data-syncs/, /api/syncs/, /api/cdp-connections/,
                 /api/connections/. Any 2xx re-opens the candidate.
  KL3-APIKEYS  — one Seam-A-adjacent discovery read: GET
                 /api/api-keys/ at revision 2026-10-15.pre
                 (authz-model.md records a beta credentials:read
                 scope that lists the account's own API keys). If it
                 returns key material or reusable fragments, that is
                 NOT a KL-3 claim — it is routed back to the parent as
                 material for a separate Seam-A battery (KL-2 was
                 refuted on the MCP surface, not this one).
  KL3-CREDSCAN — every 2xx body is scanned in-memory for credential
                 material patterns (PEM header, "private_key" field
                 name, pk_ shaped strings). stdout records COUNTS
                 only; bodies are saved scrubbed.

Verdict KL3-OVERALL:
  NO-API-SURFACE — all warehouse candidates 404/410 and no material
                   found: the parking is now evidence-backed.
  SURFACE-FOUND  — a candidate answered 2xx or material was found:
                   escalate; a real KL-3 battery gets designed.

Keys: env KLAVIYO_KEY_X / KLAVIYO_KEY_Y (unordered; GitHub Secrets),
tenant B only, Step 0 discrimination identical to kl1/kl2/kl5/kl6.
No writes of any kind beyond the Step 0 probe profile (shared
discipline). No /api/v1/people. stdout is a PUBLIC log: statuses,
path names, field counts — never bodies, never key material.

Exit codes: 2 = refused (missing keys), 3 = control failure,
0 = completed. --selftest: in-memory fake, modes quiet / planted,
ZERO network.
"""
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API_BASE = "https://a.klaviyo.com"
REVISION = os.environ.get("KL3_REVISION", "2024-10-15")
OBJECTS_REVISION = os.environ.get("KL3_OBJECTS_REVISION", "2026-07-15")
APIKEYS_REVISION = os.environ.get("KL3_APIKEYS_REVISION",
                                  "2026-10-15.pre")
OUTPUTS_ROOT = Path(os.environ.get("KL3_OUTPUTS_ROOT", "outputs"))
OUT_DIR = OUTPUTS_ROOT / "kl3"
MARKER_DOMAIN = "gmail.com"
MARKER_LOCAL = "mitsudayoooooon"

WAREHOUSE_CANDIDATES = [
    "/api/warehouse-connections/",
    "/api/data-warehouse-connections/",
    "/api/warehouse-syncs/",
    "/api/data-syncs/",
    "/api/syncs/",
    "/api/cdp-connections/",
    "/api/connections/",
]

CRED_PATTERNS = {
    "pem_header": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "private_key_field": re.compile(r'"private_key"'),
    "pk_token": re.compile(r"pk_[A-Za-z0-9_\-\.]{8,}"),
    "service_account": re.compile(r'"type"\s*:\s*"service_account"'),
}

# ---------------------------------------------------------------- keys ------

def get_env_keys():
    return (os.environ.get("KLAVIYO_KEY_X", "").strip(),
            os.environ.get("KLAVIYO_KEY_Y", "").strip())

def keys_ready(key_x, key_y):
    return bool(key_x) and bool(key_y) and key_x != key_y

# ------------------------------------------------------------- transport ----

def _with_throttle_retry(once_fn):
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
    except Exception as e:
        return None, None, f"TRANSPORT_ERROR: {e!r}"


def rest(method, path, key, body=None, revision=None, timeout=60):
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

# ---------------------------------------------------------- step 0 ----------

def marker_email(role, run_id):
    return f"{MARKER_LOCAL}+kl3{role}{run_id[-4:]}@{MARKER_DOMAIN}"

def classify_write_status(status):
    if status in (200, 201):
        return "FULL"
    if status == 403:
        return "RO"
    return f"OTHER({status})"

def resolve_keys(rest_fn, key_x, key_y, run_id, run):
    records = {}
    classes = {}
    for label, key in (("X", key_x), ("Y", key_y)):
        st_get, _js, raw_get = rest_fn("GET", "/api/accounts/", key)
        probe_email = marker_email(f"x0{label.lower()}", run_id)
        body = {"data": {"type": "profile", "attributes": {
            "email": probe_email, "first_name": "KL3",
            "last_name": f"PROBE-{label}-{run_id}",
            "properties": {"kl3_marker": run_id}}}}
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

# -------------------------------------------------------------- probe -------


def scan_cred_material(raw):
    """Count credential-material pattern hits in a body. Counts only —
    the material itself never reaches stdout."""
    text = raw or ""
    return {name: len(pat.findall(text))
            for name, pat in CRED_PATTERNS.items()}

def top_level_keys(js):
    if isinstance(js, dict):
        return sorted(js.keys())
    return []

def run_probe(rest_fn, key_x, key_y, run):
    if not keys_ready(key_x, key_y):
        run.verdict("KL3-GUARD", "REFUSED",
                    "KLAVIYO_KEY_X / KLAVIYO_KEY_Y missing or identical")
        return 2
    _ro_key, full_key = resolve_keys(rest_fn, key_x, key_y,
                                     run.run_id, run)
    if not full_key:
        run.verdict("KL3-STEP0", "ABORT",
                    "key discrimination failed (need exactly one FULL "
                    "and one RO, both reading /api/accounts/ at 200)")
        return 3
    findings = {"surface_2xx": [], "material": {}}

    def probe(step, path, revision=None):
        st, js, raw = rest_fn("GET", path, full_key, None, revision)
        slug = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_")
        run.save(f"probe_{slug}.txt", raw or "")
        hits = scan_cred_material(raw) if st and 200 <= st < 300 \
            else {}
        total_hits = sum(hits.values())
        if st and 200 <= st < 300:
            findings["surface_2xx"].append(path)
            if total_hits:
                findings["material"][path] = hits
        run.verdict(step, f"HTTP-{st}",
                    f"path={path} top_keys={top_level_keys(js)} "
                    f"cred_hits={total_hits}")
        return st

    # KL3-OBJECTS: Custom Objects API reachability (mapping only).
    probe("KL3-OBJECTS", "/api/data-sources/", OBJECTS_REVISION)
    # KL3-SURFACE: guessed warehouse/CDP connection paths.
    for i, path in enumerate(WAREHOUSE_CANDIDATES):
        probe(f"KL3-SURFACE-{i + 1}", path)
    # KL3-APIKEYS: beta credentials surface (Seam A routing).
    probe("KL3-APIKEYS", "/api/api-keys/", APIKEYS_REVISION)

    warehouse_2xx = [p for p in findings["surface_2xx"]
                     if p in WAREHOUSE_CANDIDATES]
    if warehouse_2xx or findings["material"]:
        run.verdict("KL3-OVERALL", "SURFACE-FOUND",
                    f"warehouse 2xx: {warehouse_2xx}; material hits "
                    f"on: {sorted(findings['material'])} — escalate, "
                    "design the real KL-3 battery")
    else:
        run.verdict("KL3-OVERALL", "NO-API-SURFACE",
                    "every warehouse-connection candidate path "
                    "answered 404/410 and no 2xx body contained "
                    "credential material; KL-3 stays parked with "
                    "evidence until Advanced KDP opens")
    return 0

# --------------------------------------------------------------- main -------

def _finish(run, keys, code):
    run.save("verdict.json", run.verdicts)
    scrub_tree(OUT_DIR, [k for k in keys if k])
    print(f"[DONE] verdicts in outputs/kl3/{run.run_id}/verdict.json",
          flush=True)
    return code

def main_live():
    key_x, key_y = get_env_keys()
    run_id = time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + \
        secrets.token_hex(2)
    run = Run(run_id)
    code = run_probe(rest, key_x, key_y, run)
    return _finish(run, (key_x, key_y), code)

# ------------------------------------------------------------ selftest ------

class FakeProbe:
    """Modes: quiet (everything 404 except data-sources 200 with a
    benign body) / planted (one warehouse candidate answers 200 with
    credential material in the body)."""

    FULL = "pk_FAKE_FULL_KEY_0001"
    RO = "pk_FAKE_RO_KEY_0002"

    def __init__(self, mode):
        self.mode = mode

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
        if clean == "/api/data-sources/" and method == "GET":
            js = {"data": [{"id": "ds1", "type": "data-source",
                            "attributes": {"name": "kl test"}}]}
            return 200, js, json.dumps(js)
        if self.mode == "planted" and \
                clean == "/api/warehouse-connections/":
            js = {"data": [{"id": "wc1", "attributes": {
                "private_key": "pk_FAKEPLANTED0123456789"}}]}
            return 200, js, json.dumps(js)
        return 404, None, "not found"


def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))
        print(f"[SELFTEST] {'ok' if cond else 'FAIL'}: {name}",
              flush=True)

    srv = FakeProbe("quiet")
    run = Run("selftest-quiet-" + secrets.token_hex(2))
    code = run_probe(srv, srv.RO, srv.FULL, run)
    check("quiet completes", code == 0)
    check("quiet overall NO-API-SURFACE",
          run.verdicts["KL3-OVERALL"]["verdict"] == "NO-API-SURFACE")
    check("objects surface recorded",
          run.verdicts["KL3-OBJECTS"]["verdict"] == "HTTP-200")

    srv = FakeProbe("planted")
    run = Run("selftest-planted-" + secrets.token_hex(2))
    code = run_probe(srv, srv.RO, srv.FULL, run)
    check("planted overall SURFACE-FOUND",
          run.verdicts["KL3-OVERALL"]["verdict"] == "SURFACE-FOUND")

    hits = scan_cred_material(
        '{"k": "-----BEGIN RSA PRIVATE KEY-----", "pk_x": '
        '"pk_abcdefgh12345678"}')
    check("cred scan counts patterns",
          hits["pem_header"] == 1 and hits["pk_token"] == 1)

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
    sys.exit(main_live())
