#!/usr/bin/env python3
"""KL-4 fixture placement — GitHub Actions build
(repo: o-yutaka/moka-harness).

KL-4 = cross-tenant contamination of generated output
(notes/candidates.md KL-4; authz-model.md Seam E/F).

Why this script is FIXTURES ONLY (attacker pass, 2026-11-09):
KL-4 was DOWNGRADED to the UI lane, not killed. The generation
surfaces (Composer, Customer Agent, Social Insights) have no public
generation API, tenant A's credentials are not in this lane, and
A's Customer Agent is not set up — a script on GitHub Actions cannot
drive a single generation. The card's kill condition ("no marker
appears under diverse elicitation") has never been run, so the
candidate is NOT refuted either. What the API lane CAN do is place
the victim-side markers in tenant B now, so a later UI lane
(elicitation in tenant A's Composer / Customer Agent) can fire
immediately. Placement is preparation, not evidence: this script
produces NO contamination verdict.

Markers (all invented, high-entropy, non-secret):
  token    KL4MARK-<10 hex>          — the search needle
  brand    "KL4 Brand <6 hex>"       — a fake unique proper noun
  sentence "The <brand> quarterly ledger reference is <token>."
Fixtures (tenant B, FULL key):
  F1 profile   custom properties kl4_marker / kl4_brand + the
               token in last_name; email in the kl4 Gmail-tag
               namespace (our own profile, nobody else's)
  F2 event     "KL4 Marker Event" on the F1 profile, properties
               carry token + sentence
  F3 list      name contains the token
  F4 tag       name is the token
  F5 template  name is the token; body carries the sentence
               (shape candidates T1/T2, response_shape_first)
  F6 segment   name contains the token; definition conditions on
               kl4_marker (shape risk — record-only leg)
fixtures.json in outputs/kl4/<run_id>/ records the full marker
strings and created ids for the UI lane. Fixtures are deliberately
NOT deleted — elicitation comes later; ids are recorded so cleanup
is possible whenever the parent decides.

Keys: env KLAVIYO_KEY_X / KLAVIYO_KEY_Y (unordered; GitHub Secrets),
tenant B only, Step 0 discrimination identical to kl1/kl2/kl5/kl6.
No /api/v1/people; reads are by-id only. stdout is a PUBLIC log:
statuses and counts; full marker strings live only in the artifact.

Exit codes: 2 = refused, 3 = control failure (Step 0 or the core
F1 fixture), 0 = completed (partial placement still completes).
--selftest: in-memory fake, modes full / template-fails, ZERO
network.
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
REVISION = os.environ.get("KL4_REVISION", "2024-10-15")
OUTPUTS_ROOT = Path(os.environ.get("KL4_OUTPUTS_ROOT", "outputs"))
OUT_DIR = OUTPUTS_ROOT / "kl4"
MARKER_DOMAIN = "gmail.com"
MARKER_LOCAL = "mitsudayoooooon"

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
    return f"{MARKER_LOCAL}+kl4{role}{run_id[-4:]}@{MARKER_DOMAIN}"

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
            "email": probe_email, "first_name": "KL4",
            "last_name": f"PROBE-{label}-{run_id}",
            "properties": {"kl4_marker": "step0-probe"}}}}
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

# ------------------------------------------------------------- fixtures -----

def _created_id(js):
    if isinstance(js, dict):
        d = js.get("data") or {}
        if isinstance(d, dict):
            return d.get("id")
    return None

def place_fixtures(rest_fn, full_key, run):
    token = "KL4MARK-" + secrets.token_hex(5)
    brand = "KL4 Brand " + secrets.token_hex(3)
    sentence = (f"The {brand} quarterly ledger reference is "
                f"{token}.")
    email = marker_email("victim", run.run_id)
    fx = {"token": token, "brand": brand, "sentence": sentence,
          "email": email, "legs": {}}

    def leg(name, method, path, body=None):
        st, js, raw = rest_fn(method, path, full_key, body)
        run.save(f"fixture_{name}.txt", raw or "")
        fx["legs"][name] = {"status": st, "id": _created_id(js)}
        run.verdict(f"KL4-{name}", f"HTTP-{st}",
                    f"created_id_present={bool(_created_id(js))}")
        return st, js

    # F1 profile (core fixture)
    st, js = leg("F1", "POST", "/api/profiles/", {"data": {
        "type": "profile", "attributes": {
            "email": email, "first_name": "KL4MARK",
            "last_name": token,
            "properties": {"kl4_marker": token, "kl4_brand": brand}}}})
    if st not in (200, 201):
        run.save("fixtures.json", fx)
        return fx, False
    pid = _created_id(js)
    if pid:  # by-id confirmation read (targeted, allowed)
        st_g, _js, raw_g = rest_fn("GET", f"/api/profiles/{pid}/",
                                   full_key)
        run.save("fixture_F1_readback.txt", raw_g or "")
        fx["legs"]["F1"]["readback_status"] = st_g

    # F2 event carrying token + sentence on the F1 profile
    leg("F2", "POST", "/api/events/", {"data": {
        "type": "event", "attributes": {
            "properties": {"kl4_marker": token,
                           "kl4_note": sentence},
            "metric": {"data": {"type": "metric", "attributes": {
                "name": "KL4 Marker Event"}}},
            "profile": {"data": {"type": "profile", "attributes": {
                "email": email}}}}}})

    # F3 list / F4 tag named with the token
    leg("F3", "POST", "/api/lists/", {"data": {
        "type": "list", "attributes": {"name": f"{token} list"}}})
    leg("F4", "POST", "/api/tags/", {"data": {
        "type": "tag", "attributes": {"name": token}}})

    # F5 template: body carries the sentence (shape candidates)
    placed_t = False
    for shape in ("T1", "T2"):
        attrs = {"name": token,
                 "html": f"<html><body><p>{sentence}</p></body></html>",
                 "text": sentence}
        if shape == "T1":
            attrs["editor_type"] = "CODE"
        st, js = leg(f"F5{shape}", "POST", "/api/templates/",
                     {"data": {"type": "template",
                               "attributes": attrs}})
        if st in (200, 201):
            fx["legs"]["F5"] = fx["legs"].pop(f"F5{shape}")
            placed_t = True
            break
    if not placed_t:
        fx["legs"]["F5"] = {"status": None, "id": None}

    # F6 segment named with the token (definition shape risk;
    # record-only leg — failure does not fail the run)
    leg("F6", "POST", "/api/segments/", {"data": {
        "type": "segment", "attributes": {
            "name": f"{token} segment",
            "definition": {"condition_groups": [{"conditions": [{
                "type": "profile-property", "property": "kl4_marker",
                "filter": {"type": "string", "operator": "equals",
                           "value": token}}]}]}}}})

    run.save("fixtures.json", fx)
    return fx, True

def run_fixtures(rest_fn, key_x, key_y, run):
    if not keys_ready(key_x, key_y):
        run.verdict("KL4-GUARD", "REFUSED",
                    "KLAVIYO_KEY_X / KLAVIYO_KEY_Y missing or identical")
        return 2
    _ro, full_key = resolve_keys(rest_fn, key_x, key_y,
                                 run.run_id, run)
    if not full_key:
        run.verdict("KL4-STEP0", "ABORT",
                    "key discrimination failed (need exactly one FULL "
                    "and one RO, both reading /api/accounts/ at 200)")
        return 3
    fx, core_ok = place_fixtures(rest_fn, full_key, run)
    if not core_ok:
        run.verdict("KL4-FIXTURES", "CONTROL-FAILURE",
                    "core fixture F1 (profile) could not be placed")
        return 3
    placed = sum(1 for k, v in fx["legs"].items()
                 if not k.startswith("F5T") and
                 v.get("status") in (200, 201, 202))
    run.verdict("KL4-FIXTURES", f"PLACED-{placed}",
                "marker fixtures placed in tenant B; full marker "
                "strings + ids in fixtures.json. NOT deleted — they "
                "are the victim-side setup for the future UI-lane "
                "elicitation (KL-4 verdict unchanged: unverified)")
    return 0

# --------------------------------------------------------------- main -------

def _finish(run, keys, code):
    run.save("verdict.json", run.verdicts)
    scrub_tree(OUT_DIR, [k for k in keys if k])
    print(f"[DONE] verdicts in outputs/kl4/{run.run_id}/verdict.json",
          flush=True)
    return code

def main_live():
    key_x, key_y = get_env_keys()
    run_id = time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + \
        secrets.token_hex(2)
    run = Run(run_id)
    code = run_fixtures(rest, key_x, key_y, run)
    return _finish(run, (key_x, key_y), code)

# ------------------------------------------------------------ selftest ------

class FakeFixtures:
    """Modes: full (every leg 201) / template-fails (templates 400 in
    both shapes; the run still completes with PLACED-5)."""

    FULL = "pk_FAKE_FULL_KEY_0001"
    RO = "pk_FAKE_RO_KEY_0002"

    def __init__(self, mode):
        self.mode = mode
        self._n = 0

    def __call__(self, method, path, key, body=None, revision=None,
                 timeout=None):
        clean = path.split("?")[0]
        if clean == "/api/accounts/" and method == "GET":
            return 200, {"data": []}, '{"data": []}'
        if method == "POST" and key == self.RO:
            return 403, {"errors": []}, '{"errors": []}'
        if method == "POST" and clean in (
                "/api/profiles/", "/api/events/", "/api/lists/",
                "/api/tags/", "/api/segments/"):
            self._n += 1
            js = {"data": {"id": f"fx-{self._n}", "type": "x"}}
            return 201, js, json.dumps(js)
        if method == "POST" and clean == "/api/templates/":
            if self.mode == "template-fails":
                return 400, {"errors": []}, '{"errors": []}'
            self._n += 1
            js = {"data": {"id": f"fx-{self._n}", "type": "template"}}
            return 201, js, json.dumps(js)
        if method == "GET" and clean.startswith("/api/profiles/"):
            js = {"data": {"id": "fx-1", "type": "profile"}}
            return 200, js, json.dumps(js)
        return 404, None, "not found"


def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))
        print(f"[SELFTEST] {'ok' if cond else 'FAIL'}: {name}",
              flush=True)

    srv = FakeFixtures("full")
    run = Run("selftest-full-" + secrets.token_hex(2))
    code = run_fixtures(srv, srv.RO, srv.FULL, run)
    check("full mode completes", code == 0)
    check("full mode PLACED-6",
          run.verdicts["KL4-FIXTURES"]["verdict"] == "PLACED-6")
    fx = json.loads((run.dir / "fixtures.json").read_text(
        encoding="utf-8"))
    check("fixtures carry token + sentence",
          fx["token"].startswith("KL4MARK-") and
          fx["token"] in fx["sentence"])

    srv = FakeFixtures("template-fails")
    run = Run("selftest-tplfail-" + secrets.token_hex(2))
    code = run_fixtures(srv, srv.RO, srv.FULL, run)
    check("template failure still completes", code == 0)
    check("template failure PLACED-5",
          run.verdicts["KL4-FIXTURES"]["verdict"] == "PLACED-5")

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
