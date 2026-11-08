#!/usr/bin/env python3
"""KL-5 battery — GitHub Actions build (repo: o-yutaka/moka-harness).

KL-5 = Client API unauthenticated writes + identifier collision
(notes/candidates.md KL-5; authz-model.md Seam B + Seam D).

Refined hypothesis (attacker pass first):
  * Who takes what: an unauthenticated store VISITOR whose only
    credential is the merchant's company_id (Site ID) — a PUBLIC value
    printed in every page of the merchant's storefront. The Client API
    accepts profile create/update, event creation and subscription
    writes with nothing but ?company_id=. If those writes resolve onto
    EXISTING profiles by bare identifier (email / phone / external_id),
    the visitor can pollute or flip state on a victim's profile inside
    the merchant's account: arbitrary properties (which feed segments,
    flow branching and recovery flows) and — the sharpest leg — the
    email-marketing CONSENT state (subscribe a victim for harassment /
    spam exposure, or unsubscribe them to suppress legitimate mail).
  * Strongest benign story (triage-null, from the card): "Client API
    writes are limited to NEW profiles and non-sensitive attributes;
    changing an existing profile's consent state or important
    attributes requires a server-side key or the person's own
    confirmation. The public key writing at all is by design; impact
    is confined to self-data inside one's own tenant."
  * Intent vs implementation: the DOCUMENTED identifier precedence is
    Profile ID > External ID > Email > Phone > Anonymous, and
    external-ID-only profiles are documented to NEVER auto-merge.
    KL-1's ID legs measure this resolution machinery on the SERVER API
    surface (merchant key). KL-5 measures the SAME machinery on the
    CLIENT API surface (no key at all) — a precedence violation or an
    existing-profile mutation here is reachable by anyone who can view
    the merchant's storefront.
  * Non-claims (from the card): "a profile can be CREATED with only a
    company_id" is documented design and is NOT claimed. Rate limiting
    is not claimed either way.

Surfaces (per the 2026-11-05 card amendment): own-site klaviyo.js
installation is OUT of scope (brief: testing on your own website is
out of scope), so this battery calls the Client API directly against
a.klaviyo.com — the direct-call shape is itself the experiment. The
hosted-forms surface (*.myklpages.com) is a UI lane, not this script.

Async reality: Client API writes are ingested asynchronously (202
Accepted, queued). Every landing verdict therefore comes from a
POLLED Server-API read-back with the account's Full key — never from
the client response status alone. Poll budget: KL5_POLL_TIMEOUT
seconds at KL5_POLL_INTERVAL seconds (defaults 150 / 10).

Keys: env KLAVIYO_KEY_X / KLAVIYO_KEY_Y (unordered; GitHub Secrets).
Step 0 discriminates them exactly like kl1_run.py / kl2_run.py:
GET /api/accounts/ must be 200 for both; a probe POST /api/profiles/
returning 201 => FULL, 403 => RO. The battery needs the FULL key for
seeding, read-backs and cleanup (tenant B). company_id is tenant B's
Site ID — a public value by design; overridable via KL5_COMPANY_ID.

Safety rails:
  * All writes target run-scoped marker profiles in OUR OWN account
    (emails in the mitsudayoooooon+kl5* Gmail tag namespace, one
    fictional NANPA phone in the 555-010-01xx range). No third-party
    data; the "victim" profiles are our own controls.
  * Verification reads are targeted equals(...) lookups only. Never
    list enumeration of profiles, never /api/v1/people (outside the
    brief's safe harbor).
  * stdout is a PUBLIC log: step names, HTTP statuses, field names,
    counts, verdicts. Never private key values, never full bodies,
    never marker emails or profile ids (run-id suffix only). The
    company_id is public by design and may appear.
  * Full response bodies go to outputs/kl5/<run_id>/ and are scrubbed
    of key material before exit (same discipline as kl1/kl2).
  * Cleanup: data-privacy deletion jobs for every profile created.
  * Marker namespace is kl5-* throughout — KL-1's battery runs in the
    same tenant with kl1-* markers; no shared profiles.

Exit codes mirror kl1/kl2: 2 = refused (missing keys), 3 = control
failure (the run cannot discriminate), 0 = completed.
--selftest: in-memory fake transports (server + client), several
behaviour modes, ZERO network. Asserts verdict logic incl.
existing-profile mutation detection, precedence inversion / fan-out
detection, consent flip, event mutation, the 429 throttle retry, and
output scrubbing.
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
REVISION = os.environ.get("KL5_REVISION", "2024-10-15")
OUTPUTS_ROOT = Path(os.environ.get("KL5_OUTPUTS_ROOT", "outputs"))
OUT_DIR = OUTPUTS_ROOT / "kl5"
MARKER_DOMAIN = "gmail.com"
MARKER_LOCAL = "mitsudayoooooon"
COMPANY_ID = os.environ.get("KL5_COMPANY_ID", "WkzxsA").strip()
BOGUS_COMPANY_ID = "ZZZZZZ"
POLL_TIMEOUT = float(os.environ.get("KL5_POLL_TIMEOUT", "150"))
POLL_INTERVAL = float(os.environ.get("KL5_POLL_INTERVAL", "10"))

# ---------------------------------------------------------------- keys ------

def get_env_keys():
    return (os.environ.get("KLAVIYO_KEY_X", "").strip(),
            os.environ.get("KLAVIYO_KEY_Y", "").strip())

def keys_ready(key_x, key_y):
    return bool(key_x) and bool(key_y) and key_x != key_y

# ------------------------------------------------------------- transport ----

def _with_throttle_retry(once_fn):
    """Klaviyo burst-throttles (429, body: "Request was throttled.
    Expected available in N second", measured live 2026-11-09 in the
    KL-1 run #606 — a 1s throttle aborted Step 0). Retry with the
    server-stated wait, up to 4 times."""
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
    """Server API (private key) with 429 retry — kl1 rest() shape."""
    return _with_throttle_retry(
        lambda: _rest_once(method, path, key, body, revision, timeout))


def _client_once(path, company_id, body=None, revision=None, timeout=60):
    url = f"{API_BASE}{path}?company_id={urllib.parse.quote(company_id)}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST")
    # NO Authorization header — the entire point of the surface is that
    # the public company_id is the only credential presented.
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


def client_post(path, company_id, body=None, revision=None, timeout=60):
    """Client API (company_id only, unauthenticated) with 429 retry."""
    return _with_throttle_retry(
        lambda: _client_once(path, company_id, body, revision, timeout))


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
    """Remove key material from every file under root (kl1/kl2
    discipline). The company_id is public by design and is NOT
    scrubbed; private keys are."""
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

def find_prop(obj, key):
    """Recursively find a property value anywhere in a JSON structure.
    Response-shape-first: verdicts key off the marker property's
    presence wherever the API actually puts it."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_prop(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_prop(v, key)
            if r is not None:
                return r
    return None

def shape_of(js):
    """Field-name skeleton of a JSON body (names only, no values)."""
    if isinstance(js, dict):
        return {k: shape_of(v) for k, v in list(js.items())[:20]}
    if isinstance(js, list):
        return [shape_of(js[0])] if js else []
    return type(js).__name__

def contains_id(obj, needle):
    """True if the exact id string appears anywhere in the structure."""
    if not needle:
        return False
    if isinstance(obj, dict):
        return any(contains_id(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(contains_id(v, needle) for v in obj)
    return obj == needle

# ------------------------------------------------------ profile helpers -----

def marker_email(role, run_id):
    return f"{MARKER_LOCAL}+kl5{role}-{run_id}@{MARKER_DOMAIN}"

def find_profile(rest_fn, key, filter_expr):
    q = urllib.parse.urlencode({"filter": filter_expr, "page[size]": 1})
    status, js, raw = rest_fn("GET", f"/api/profiles/?{q}", key)
    prof = None
    if js and isinstance(js.get("data"), list) and js["data"]:
        prof = js["data"][0]
    return status, prof, raw

def find_by_email(rest_fn, key, email):
    return find_profile(rest_fn, key, f'equals(email,"{email}")')

def find_by_external_id(rest_fn, key, ext):
    return find_profile(rest_fn, key, f'equals(external_id,"{ext}")')

def find_by_phone(rest_fn, key, phone):
    return find_profile(rest_fn, key, f'equals(phone_number,"{phone}")')

def create_profile(rest_fn, key, attributes):
    body = {"data": {"type": "profile", "attributes": attributes}}
    return rest_fn("POST", "/api/profiles/", key, body)

def classify_write_status(status):
    if status in (200, 201):
        return "FULL"
    if status == 403:
        return "RO"
    return f"OTHER({status})"

def poll_until(check_fn, timeout=None, interval=None):
    """Run check_fn until it returns a truthy value or the budget is
    spent. Client-API ingestion is asynchronous, so landing verdicts
    poll instead of reading once. With interval<=0 (selftest), a fixed
    small attempt count is used so fake runs stay fast."""
    timeout = POLL_TIMEOUT if timeout is None else timeout
    interval = POLL_INTERVAL if interval is None else interval
    if interval and interval > 0:
        attempts = max(1, int(timeout / interval))
    else:
        attempts = 3
    for i in range(attempts):
        r = check_fn()
        if r:
            return r
        if i < attempts - 1 and interval and interval > 0:
            time.sleep(interval)
    return None

# ---------------------------------------------------------- step 0 ----------

def resolve_keys(rest_fn, key_x, key_y, run_id, run):
    """Discriminate X/Y by REST behaviour (kl1/kl2 step 0). Returns
    (ro_key, full_key) or (None, None) when the run cannot proceed."""
    records = {}
    classes = {}
    for label, key in (("X", key_x), ("Y", key_y)):
        st_get, _js, raw_get = rest_fn("GET", "/api/accounts/", key)
        # Valid address required (same defect as kl1 runs #606/#608:
        # appending ".x" after the full address yields "...@gmail.com.x",
        # which the real API rejects 400 even for a FULL key).
        probe_email = marker_email(f"x0{label.lower()}", run_id)
        st_post, _js2, raw_post = create_profile(rest_fn, key, {
            "email": probe_email, "first_name": "KL5",
            "last_name": f"PROBE-{label}-{run_id}",
            "properties": {"kl5_marker": run_id}})
        cls = classify_write_status(st_post) if st_get == 200 else "NOREAD"
        classes[label] = cls
        records[label] = {"get_accounts_status": st_get,
                          "probe_post_status": st_post, "class": cls,
                          "probe_email_tag": f"x0{label.lower()}"}
        run.save(f"step0_{label}.txt", raw_get + "\n---\n" + raw_post)
        print(f"[STEP0] key {label}: accounts={st_get} probe_post="
              f"{st_post} -> {cls}", flush=True)
    run.save("step0.json", records)
    vals = sorted(classes.values())
    if vals != ["FULL", "RO"]:
        return None, None
    full_label = [k for k, v in classes.items() if v == "FULL"][0]
    ro_label = [k for k, v in classes.items() if v == "RO"][0]
    return (key_x if ro_label == "X" else key_y,
            key_x if full_label == "X" else key_y)

# ------------------------------------------------------------- seeding ------

def seed_profiles(rest_fn, full_key, run_id, run):
    """Create control profiles V (email+phone) and E (external-id
    only) in our own account via the Server API. Returns dict with
    ids + identifiers, or None on control failure."""
    digits = "".join(c for c in run_id if c.isdigit())
    n = int(digits[-4:]) if digits else 0
    # Fictional NANPA range 555-010-0100..0199; KL-5 parks in
    # 0150..0169 so a concurrent KL-1 run (different derivation)
    # does not share the victim phone.
    phone_v = f"+1555010" + f"01{50 + (n % 20):02d}"
    ext_e = f"kl5ext-{run_id}"
    seeds = {
        "V": {"email": marker_email("v", run_id), "phone_number": phone_v,
              "first_name": "KL5",
              "properties": {"kl5_sentinel": f"V-{run_id}",
                             "kl5_role": "victim",
                             "kl5_attr": f"ORIGINAL-{run_id}"}},
        "E": {"external_id": ext_e, "first_name": "KL5",
              "properties": {"kl5_sentinel": f"E-{run_id}",
                             "kl5_role": "extonly"}},
    }
    out = {"phone_v": phone_v, "ext_e": ext_e, "profiles": {}}
    for role, attrs in seeds.items():
        st, js, raw = create_profile(rest_fn, full_key, attrs)
        run.save(f"seed_{role}.txt", raw)
        pid = (js or {}).get("data", {}).get("id") if isinstance(js, dict) \
            else None
        print(f"[SEED] {role}: create -> {st} id={'yes' if pid else 'no'}",
              flush=True)
        if st not in (200, 201) or not pid:
            return None
        out["profiles"][role] = {"id": pid, "status": st,
                                 "email": attrs.get("email")}
    # Read-back control: sentinels must be intact on the right profiles.
    for role, lookup in (("V", ("email", seeds["V"]["email"])),
                         ("E", ("ext", ext_e))):
        if lookup[0] == "email":
            _st, prof, _raw = find_by_email(rest_fn, full_key, lookup[1])
        else:
            _st, prof, _raw = find_by_external_id(rest_fn, full_key,
                                                  lookup[1])
        got = find_prop(prof, "kl5_sentinel") if prof else None
        want = f"{role}-{run_id}"
        print(f"[SEED] {role}: read-back sentinel "
              f"{'OK' if got == want else 'MISMATCH'}", flush=True)
        if got != want:
            return None
    return out

# ------------------------------------------------- client body builders -----

def profile_body_p1(attrs):
    """Create Client Profile, documented wrapper shape."""
    return {"data": {"type": "client-profile",
                     "attributes": {"profile": dict(attrs)}}}

def profile_body_p2(attrs):
    """Fallback flat shape."""
    return {"data": {"type": "profile", "attributes": dict(attrs)}}

PROFILE_BUILDERS = (("P1", profile_body_p1), ("P2", profile_body_p2))

def event_body_e1(profile_attrs, metric_name, properties):
    """Create Client Event, $-prefixed identifier shape."""
    prof = {}
    if profile_attrs.get("email"):
        prof["$email"] = profile_attrs["email"]
    if profile_attrs.get("phone_number"):
        prof["$phone_number"] = profile_attrs["phone_number"]
    if profile_attrs.get("external_id"):
        prof["$external_id"] = profile_attrs["external_id"]
    for k, v in profile_attrs.get("extra_profile_props", {}).items():
        prof[k] = v
    return {"data": {"type": "event", "attributes": {
        "profile": prof,
        "metric": {"data": {"type": "metric",
                            "attributes": {"name": metric_name}}},
        "properties": dict(properties)}}}

def event_body_e2(profile_attrs, metric_name, properties):
    """Fallback: plain identifier keys in the event profile object."""
    prof = {}
    for k in ("email", "phone_number", "external_id"):
        if profile_attrs.get(k):
            prof[k] = profile_attrs[k]
    for k, v in profile_attrs.get("extra_profile_props", {}).items():
        prof[k] = v
    return {"data": {"type": "event", "attributes": {
        "profile": prof,
        "metric": {"data": {"type": "metric",
                            "attributes": {"name": metric_name}}},
        "properties": dict(properties)}}}

EVENT_BUILDERS = (("E1", event_body_e1), ("E2", event_body_e2))

def sub_body_a(email, consent):
    """Create Client Subscription, bulk-style nested profile shape."""
    return {"data": {"type": "client-subscription", "attributes": {
        "profile": {"data": {"type": "profile", "attributes": {
            "email": email,
            "subscriptions": {"email": {"marketing": {
                "consent": consent}}}}}}}}}

def sub_body_b(email, consent):
    """Fallback: profile attributes directly under attributes."""
    return {"data": {"type": "client-subscription", "attributes": {
        "profile": {"email": email,
                    "subscriptions": {"email": {"marketing": {
                        "consent": consent}}}}}}}

SUB_BUILDERS = (("A", sub_body_a), ("B", sub_body_b))

# ------------------------------------------------------- consent reading ----

def get_consent(rest_fn, key, profile_id):
    """Read a profile's email-marketing consent state via the Server
    API (single-profile GET with the subscriptions additional field).
    Returns (consent_value_or_None, profile_json). Shape-first: dig
    the documented subscriptions path, fall back to a recursive
    'consent' search, and let the caller record the raw body."""
    q = urllib.parse.urlencode(
        {"additional-fields[profile]": "subscriptions"})
    status, js, raw = rest_fn("GET", f"/api/profiles/{profile_id}/?{q}",
                              key)
    consent = None
    if isinstance(js, dict):
        attrs = (js.get("data") or {}).get("attributes") or {}
        subs = attrs.get("subscriptions") or {}
        try:
            consent = subs["email"]["marketing"]["consent"]
        except (KeyError, TypeError):
            consent = find_prop(js, "consent")
    return status, consent, js, raw

# ------------------------------------------------------------- CL legs ------

def _landed_on(rest_fn, key, lookup, want_id, marker_key, marker_val):
    """One poll attempt: resolve lookup -> (profile, landed_bool).
    Returns the profile dict when the marker value is observed on the
    profile with id == want_id, else None."""
    kind, val = lookup
    if kind == "email":
        _st, prof, _raw = find_by_email(rest_fn, key, val)
    elif kind == "ext":
        _st, prof, _raw = find_by_external_id(rest_fn, key, val)
    else:
        _st, prof, _raw = find_by_phone(rest_fn, key, val)
    if not prof:
        return None
    if prof.get("id") == want_id and \
            find_prop(prof, marker_key) == marker_val:
        return prof
    return None


def cl_legs(srv, cli, full_key, run_id, run, seed):
    """Client API legs. srv = Server transport (keyed), cli = Client
    transport (company_id only). All landing verdicts come from polled
    Server read-backs."""
    ev = seed["profiles"]["V"]["email"]
    vid = seed["profiles"]["V"]["id"]
    eid = seed["profiles"]["E"]["id"]
    ext_e = seed["ext_e"]
    phone_v = seed["phone_v"]
    extra_ids = []
    outcomes = {"existing_mutation": [], "consent": [], "precedence": []}

    # ---- CL-0a: profile shape discovery on a FRESH marker profile.
    p0_email = marker_email("p0", run_id)
    p0_val = f"CL0-{run_id}"
    builder = None
    for name, b in PROFILE_BUILDERS:
        st, _js, raw = cli("/client/profiles/", COMPANY_ID,
                           b({"email": p0_email,
                              "properties": {"kl5_probe": p0_val}}))
        run.save(f"cl0_profile_{name}.txt", raw)
        print(f"[CL-0] profile shape {name} -> {st}", flush=True)
        if st in (200, 202):
            builder = (name, b)
            break
    if builder is None:
        run.verdict("KL5-CLIENT-PROFILE-SHAPE", "NONE-ACCEPTED",
                    "no candidate profile shape accepted; statuses in "
                    "cl0_profile_*.txt — client profile legs cannot run")
        return {"fatal": True, "extra_profile_ids": extra_ids,
                "outcomes": outcomes}
    run.verdict("KL5-CLIENT-PROFILE-SHAPE", builder[0],
                "first accepted Create Client Profile body shape")
    build_profile = builder[1]
    prof0 = poll_until(lambda: _landed_on(srv, full_key, ("email", p0_email),
                                          None, "kl5_probe", p0_val)
                       or _found_any(srv, full_key, ("email", p0_email)))
    if prof0:
        extra_ids.append(prof0["id"])
        print(f"[CL-0] fresh profile via client API confirmed "
              f"(documented design; not claimed)", flush=True)

    # ---- CL-0b: negative control — same write, BOGUS company_id.
    # If this lands in tenant B, the company_id is not even the gate.
    bogus_email = marker_email("bogus", run_id)
    bogus_val = f"BOGUS-{run_id}"
    st, _js, raw = cli("/client/profiles/", BOGUS_COMPANY_ID,
                       build_profile({"email": bogus_email,
                                      "properties": {"kl5_probe": bogus_val}}))
    run.save("cl0_bogus.txt", raw)
    print(f"[CL-0] bogus company_id write -> {st}", flush=True)
    bogus_prof = poll_until(
        lambda: _found_any(srv, full_key, ("email", bogus_email)),
        timeout=min(POLL_TIMEOUT, 60.0))
    if bogus_prof:
        extra_ids.append(bogus_prof["id"])
        outcomes["existing_mutation"].append("CL0-BOGUS")
        run.verdict("KL5-CL0-NEGCTRL", "VIOLATED",
                    "a write with a WRONG company_id landed in tenant "
                    "B — the public id is not functioning as the gate")
    else:
        run.verdict("KL5-CL0-NEGCTRL", "HELD",
                    "wrong-company_id write did not land in tenant B")

    # ---- CL-1: existing-profile write by bare EMAIL.
    val = f"CL1-{run_id}"
    st, _js, raw = cli("/client/profiles/", COMPANY_ID,
                       build_profile({"email": ev,
                                      "properties": {"kl5_probe": val}}))
    run.save("cl1_write.txt", raw)
    hit = poll_until(lambda: _landed_on(srv, full_key, ("email", ev),
                                        vid, "kl5_probe", val))
    _st2, prof_v, _r = find_by_email(srv, full_key, ev)
    dup = bool(prof_v) and prof_v.get("id") != vid and \
        find_prop(prof_v, "kl5_probe") == val
    print(f"[CL-1] email-only client write -> {st}; landed on V: "
          f"{bool(hit)}, duplicate-with-probe: {dup}", flush=True)
    if hit:
        outcomes["existing_mutation"].append("CL1")
        run.verdict("KL5-CL1-EMAIL-WRITE", "LANDS-EXISTING",
                    "company_id + victim email alone mutated the "
                    "existing profile's properties")
    elif dup:
        extra_ids.append(prof_v["id"])
        run.verdict("KL5-CL1-EMAIL-WRITE", "DUPLICATE-CREATED",
                    "write created a SECOND profile carrying the "
                    "victim email instead of touching V (identity "
                    "discipline issue; recorded)")
    else:
        run.verdict("KL5-CL1-EMAIL-WRITE", "NO-LAND",
                    "write accepted at the edge but never observed on "
                    "V — consistent with create-only / ignored-for-"
                    "existing behaviour")

    # ---- CL-2: existing-profile write by bare PHONE.
    val = f"CL2-{run_id}"
    st, _js, raw = cli("/client/profiles/", COMPANY_ID,
                       build_profile({"phone_number": phone_v,
                                      "properties": {"kl5_probe": val}}))
    run.save("cl2_write.txt", raw)
    hit = poll_until(lambda: _landed_on(srv, full_key, ("phone", phone_v),
                                        vid, "kl5_probe", val))
    print(f"[CL-2] phone-only client write -> {st}; landed on V: "
          f"{bool(hit)}", flush=True)
    if hit:
        outcomes["existing_mutation"].append("CL2")
        run.verdict("KL5-CL2-PHONE-WRITE", "LANDS-EXISTING",
                    "company_id + victim phone alone mutated the "
                    "existing profile")
    else:
        run.verdict("KL5-CL2-PHONE-WRITE", "NO-LAND",
                    "phone-keyed write never observed on V")

    # ---- CL-3: existing-profile write by bare EXTERNAL_ID (E is
    # external-ID-only; docs say such profiles never auto-merge — the
    # question here is whether the client surface can still WRITE to
    # one by presenting the id).
    val = f"CL3-{run_id}"
    st, _js, raw = cli("/client/profiles/", COMPANY_ID,
                       build_profile({"external_id": ext_e,
                                      "properties": {"kl5_probe": val}}))
    run.save("cl3_write.txt", raw)
    hit = poll_until(lambda: _landed_on(srv, full_key, ("ext", ext_e),
                                        eid, "kl5_probe", val))
    print(f"[CL-3] external-id-only client write -> {st}; landed on "
          f"E: {bool(hit)}", flush=True)
    if hit:
        outcomes["existing_mutation"].append("CL3")
        run.verdict("KL5-CL3-EXT-WRITE", "LANDS-EXISTING",
                    "company_id + external_id alone mutated the "
                    "external-ID-only profile")
    else:
        run.verdict("KL5-CL3-EXT-WRITE", "NO-LAND",
                    "external-id-keyed write never observed on E")

    # ---- CL-4a: collision — V's email + E's external_id in ONE
    # client write. Documented: External ID > Email -> must land on
    # E only (same discriminator as KL-1 ID-2, client surface).
    val = f"CL4-{run_id}"
    st, _js, raw = cli("/client/profiles/", COMPANY_ID,
                       build_profile({"email": ev, "external_id": ext_e,
                                      "properties": {"kl5_probe": val}}))
    run.save("cl4a_write.txt", raw)
    on_v = poll_until(lambda: _on_profile_id(srv, full_key, vid,
                                             "kl5_probe", val),
                      timeout=min(POLL_TIMEOUT, 60.0))
    on_e = poll_until(lambda: _on_profile_id(srv, full_key, eid,
                                             "kl5_probe", val),
                      timeout=min(POLL_TIMEOUT, 60.0))
    print(f"[CL-4a] ext+email client write -> {st}; on V: {bool(on_v)}"
          f", on E: {bool(on_e)}", flush=True)
    if on_e and not on_v:
        run.verdict("KL5-CL4A-PRECEDENCE", "AS-DOCUMENTED",
                    "external_id beat email on the client surface too")
    elif on_v and not on_e:
        outcomes["precedence"].append("CL4A")
        run.verdict("KL5-CL4A-PRECEDENCE", "VIOLATED",
                    "email beat external_id — documented precedence "
                    "(External ID > Email) inverted on the client "
                    "surface")
    elif on_v and on_e:
        outcomes["precedence"].append("CL4A-FANOUT")
        run.verdict("KL5-CL4A-PRECEDENCE", "VIOLATED",
                    "write landed on BOTH profiles (fan-out across "
                    "identifiers the docs keep separate)")
    else:
        run.verdict("KL5-CL4A-PRECEDENCE", "NO-LAND",
                    "collision write landed on neither profile "
                    "(consistent with held/existing-suppressed writes; "
                    "see CL-1..3)")

    # ---- CL-4b: collision — FRESH email + V's phone. Two readings
    # exist (anchoring vs matching; see KL-1 ID-3 note). Descriptive
    # unless it fans out.
    en = marker_email("n", run_id)
    val = f"CL4B-{run_id}"
    st, _js, raw = cli("/client/profiles/", COMPANY_ID,
                       build_profile({"email": en, "phone_number": phone_v,
                                      "properties": {"kl5_probe": val}}))
    run.save("cl4b_write.txt", raw)
    on_v = poll_until(lambda: _on_profile_id(srv, full_key, vid,
                                             "kl5_probe", val),
                      timeout=min(POLL_TIMEOUT, 60.0))
    _s, prof_en, _r = find_by_email(srv, full_key, en)
    en_is_v = bool(prof_en) and prof_en.get("id") == vid
    n_hit = bool(prof_en) and not en_is_v and \
        find_prop(prof_en, "kl5_probe") == val
    if n_hit:
        extra_ids.append(prof_en["id"])
    print(f"[CL-4b] fresh-email+V-phone client write -> {st}; on V: "
          f"{bool(on_v)}, on distinct new profile: {n_hit}, V "
          f"absorbed fresh email: {en_is_v}", flush=True)
    if n_hit and not on_v:
        run.verdict("KL5-CL4B-PRECEDENCE", "AS-DOCUMENTED",
                    "email anchored identity; fresh profile created, "
                    "V untouched")
    elif on_v and not n_hit:
        run.verdict("KL5-CL4B-PRECEDENCE", "PHONE-ANCHORED",
                    "the phone match pulled a write carrying a FRESH "
                    "email onto the existing profile"
                    + (" (which also absorbed the fresh email)"
                       if en_is_v else "")
                    + " — matching-based resolution on the client "
                    "surface (observation, two readings; see NOTE)")
    elif on_v and n_hit:
        outcomes["precedence"].append("CL4B-FANOUT")
        run.verdict("KL5-CL4B-PRECEDENCE", "VIOLATED",
                    "write landed on BOTH the phone owner and a "
                    "distinct fresh-email profile (fan-out)")
    else:
        run.verdict("KL5-CL4B-PRECEDENCE", "NO-LAND",
                    "write landed nowhere observable")

    # ---- CL-5: events. (a) attribution: an event carrying only
    # $email must appear on V's timeline; (b) mutation: non-identifier
    # keys inside the event's profile object must NOT rewrite V's
    # profile properties (identifiers-only per docs; Seam B asks what
    # the implementation actually does).
    # Re-resolve V's CURRENT email first: CL-4b may have re-anchored
    # it (V absorbing the fresh email is itself the PHONE-ANCHORED
    # observation). Later email-keyed legs must address the profile
    # as it NOW is, or they would silently test a different identity.
    _stv, js_v, _rv = srv("GET", f"/api/profiles/{vid}/", full_key)
    ev_now = ev
    if isinstance(js_v, dict):
        cur = (js_v.get("data") or {}).get("attributes") or {}
        if cur.get("email"):
            ev_now = cur["email"]
    if ev_now != ev:
        print(f"[CL-5] note: V's email was re-anchored by an earlier "
              f"leg; later legs use the current email", flush=True)
    run.save("cl5_v_email.json", {"reanchored": ev_now != ev})
    metric = f"KL5 Probe {run_id}"
    ev_val = f"EVT-{run_id}"
    mut_val = f"EVMUT-{run_id}"
    ev_builder = None
    for name, b in EVENT_BUILDERS:
        st, _js, raw = cli("/client/events/", COMPANY_ID, b(
            {"email": ev_now,
             "extra_profile_props": {"kl5_evprobe": mut_val}},
            metric, {"kl5_ev": ev_val}))
        run.save(f"cl5_event_{name}.txt", raw)
        print(f"[CL-5] event shape {name} -> {st}", flush=True)
        if st in (200, 202):
            ev_builder = (name, b)
            break
    if ev_builder is None:
        run.verdict("KL5-CL5-EVENT", "NO-SHAPE-ACCEPTED",
                    "no candidate event shape accepted; statuses in "
                    "cl5_event_*.txt")
    else:
        run.verdict("KL5-CLIENT-EVENT-SHAPE", ev_builder[0],
                    "first accepted Create Client Event body shape")
        build_event = ev_builder[1]
        seen = poll_until(lambda: _event_on_profile(srv, full_key, vid,
                                                    "kl5_ev", ev_val))
        print(f"[CL-5] event attributed to V: {bool(seen)}", flush=True)
        run.verdict("KL5-CL5-EVENT-ATTRIB",
                    "ATTRIBUTED" if seen else "NOT-OBSERVED",
                    "an event bearing only the victim email identifier "
                    "was ingested onto the existing profile's timeline"
                    if seen else "event never observed on V's timeline")
        mut = poll_until(lambda: _on_profile_id(srv, full_key, vid,
                                                "kl5_evprobe", mut_val),
                         timeout=min(POLL_TIMEOUT, 60.0))
        print(f"[CL-5] event profile-object mutation on V: {bool(mut)}",
              flush=True)
        if mut:
            outcomes["existing_mutation"].append("CL5-EVENT")
            run.verdict("KL5-CL5-EVENT-MUTATE", "MUTATES",
                        "non-identifier keys in an event's profile "
                        "object rewrote the existing profile's "
                        "properties — event ingestion is a profile-"
                        "mutation channel on the client surface too")
        else:
            run.verdict("KL5-CL5-EVENT-MUTATE", "NO-MUTATE",
                        "event profile object stayed identifiers-only "
                        "in effect; no property rewrite observed")
        # CL-5b: phone-keyed event attribution.
        ev2_val = f"EVT2-{run_id}"
        st, _js, raw = cli("/client/events/", COMPANY_ID, build_event(
            {"phone_number": phone_v}, metric, {"kl5_ev": ev2_val}))
        run.save("cl5b_event.txt", raw)
        seen2 = poll_until(lambda: _event_on_profile(srv, full_key, vid,
                                                     "kl5_ev", ev2_val))
        print(f"[CL-5b] phone-keyed event -> {st}; attributed to V: "
              f"{bool(seen2)}", flush=True)
        run.verdict("KL5-CL5B-EVENT-PHONE-ATTRIB",
                    "ATTRIBUTED" if seen2 else "NOT-OBSERVED",
                    "an event bearing only the victim phone identifier "
                    "was ingested onto the existing profile's timeline"
                    if seen2 else "phone-keyed event never observed on "
                    "V's timeline")

    # ---- CL-6/7: consent. Baseline first (recorded, not assumed).
    _stc, consent0, _js0, raw0 = get_consent(srv, full_key, vid)
    run.save("cl6_baseline.txt", raw0)
    print(f"[CL-6] V baseline email-marketing consent: {consent0}",
          flush=True)
    sub_builder = None
    for name, b in SUB_BUILDERS:
        st, _js, raw = cli("/client/subscriptions/", COMPANY_ID,
                           b(ev_now, "SUBSCRIBED"))
        run.save(f"cl6_sub_{name}.txt", raw)
        print(f"[CL-6] subscription shape {name} -> {st}", flush=True)
        if st in (200, 202):
            sub_builder = (name, b)
            break
    if sub_builder is None:
        run.verdict("KL5-CL6-CONSENT-SUB", "NO-SHAPE-ACCEPTED",
                    "no candidate subscription shape accepted; "
                    "statuses in cl6_sub_*.txt")
        run.verdict("KL5-CL7-CONSENT-UNSUB", "SKIPPED",
                    "no accepted subscription shape")
    else:
        run.verdict("KL5-CLIENT-SUB-SHAPE", sub_builder[0],
                    "first accepted Create Client Subscription shape")
        build_sub = sub_builder[1]
        got = poll_until(lambda: _consent_is(srv, full_key, vid,
                                             "SUBSCRIBED"))
        print(f"[CL-6] V consent after client subscribe: "
              f"{got or 'unchanged'}", flush=True)
        if got:
            outcomes["consent"].append("CL6-SUB")
            run.verdict("KL5-CL6-CONSENT-SUB", "ACCEPTED",
                        "company_id + victim email alone set the "
                        "existing profile's email-marketing consent to "
                        "SUBSCRIBED — unauthenticated consent write")
            # CL-7: flip it back off, same surface.
            st, _js, raw = cli("/client/subscriptions/", COMPANY_ID,
                               build_sub(ev_now, "UNSUBSCRIBED"))
            run.save("cl7_unsub.txt", raw)
            got2 = poll_until(lambda: _consent_is(srv, full_key, vid,
                                                  "UNSUBSCRIBED"))
            print(f"[CL-7] unsubscribe flip -> {st}; V consent now: "
                  f"{got2 or 'unchanged'}", flush=True)
            if got2:
                outcomes["consent"].append("CL7-UNSUB")
                run.verdict("KL5-CL7-CONSENT-UNSUB", "ACCEPTED",
                            "the same unauthenticated surface flipped "
                            "the existing profile's consent to "
                            "UNSUBSCRIBED — subscribe AND suppress are "
                            "both writable with only the public id")
            else:
                run.verdict("KL5-CL7-CONSENT-UNSUB", "NO-FLIP",
                            "unsubscribe write did not change the "
                            "observed consent state")
        else:
            run.verdict("KL5-CL6-CONSENT-SUB", "IGNORED",
                        "subscription write accepted at the edge (2xx) "
                        "but the existing profile's consent never "
                        "became SUBSCRIBED")
            run.verdict("KL5-CL7-CONSENT-UNSUB", "SKIPPED",
                        "no SUBSCRIBED state was reached to flip")

    return {"fatal": False, "extra_profile_ids": extra_ids,
            "outcomes": outcomes}


def _on_profile_id(rest_fn, key, profile_id, marker_key, marker_val):
    """Poll attempt by immutable profile id (single-profile GET):
    True when the marker property is observed on exactly this
    profile. Immune to identifier re-anchoring by earlier legs."""
    _st, js, _raw = rest_fn("GET", f"/api/profiles/{profile_id}/", key)
    if not isinstance(js, dict):
        return None
    prof = js.get("data")
    if prof and find_prop(prof, marker_key) == marker_val:
        return prof
    return None


def _found_any(rest_fn, key, lookup):
    kind, val = lookup
    if kind == "email":
        _st, prof, _raw = find_by_email(rest_fn, key, val)
    elif kind == "ext":
        _st, prof, _raw = find_by_external_id(rest_fn, key, val)
    else:
        _st, prof, _raw = find_by_phone(rest_fn, key, val)
    return prof


def _event_on_profile(rest_fn, key, profile_id, marker_key, marker_val):
    q = urllib.parse.urlencode(
        {"filter": f'equals(profile_id,"{profile_id}")',
         "page[size]": 25})
    _st, js, _raw = rest_fn("GET", f"/api/events/?{q}", key)
    if not js or not isinstance(js.get("data"), list):
        return None
    for item in js["data"]:
        if find_prop(item, marker_key) == marker_val:
            return item
    return None


def _consent_is(rest_fn, key, profile_id, want):
    _st, consent, _js, _raw = get_consent(rest_fn, key, profile_id)
    return consent if consent == want else None

# ------------------------------------------------------------ cleanup -------

def cleanup(rest_fn, full_key, run, profile_ids):
    results = []
    for pid in sorted(set(pid for pid in profile_ids if pid)):
        body = {"data": {"type": "data-privacy-deletion-job",
                         "attributes": {"profile": {
                             "data": {"type": "profile", "id": pid}}}}}
        st, js, raw = rest_fn("POST", "/api/data-privacy-deletion-jobs/",
                              full_key, body)
        results.append({"profile_tag": pid[:8], "status": st})
        run.save(f"cleanup_{pid[:8]}.txt", raw)
    print(f"[CLEANUP] deletion jobs: "
          f"{[r['status'] for r in results]}", flush=True)
    run.verdict("KL5-CLEANUP", "OK",
                f"{len(results)} deletion job(s) submitted")
    return results

# --------------------------------------------------------------- main -------

def _finish(run, keys, code):
    run.save("verdict.json", run.verdicts)
    scrub_tree(OUT_DIR, [k for k in keys if k])
    print(f"[DONE] verdicts in outputs/kl5/{run.run_id}/verdict.json",
          flush=True)
    return code

def main_live():
    key_x, key_y = get_env_keys()
    run_id = time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + \
        secrets.token_hex(2)
    run = Run(run_id)
    if not keys_ready(key_x, key_y):
        run.verdict("KL5-GUARD", "REFUSED",
                    "KLAVIYO_KEY_X / KLAVIYO_KEY_Y missing or identical")
        return _finish(run, (key_x, key_y), 2)
    if not COMPANY_ID:
        run.verdict("KL5-GUARD", "REFUSED", "KL5_COMPANY_ID is empty")
        return _finish(run, (key_x, key_y), 2)
    _ro_key, full_key = resolve_keys(rest, key_x, key_y, run_id, run)
    if not full_key:
        run.verdict("KL5-STEP0", "ABORT",
                    "key discrimination failed (need exactly one FULL "
                    "and one RO, both reading /api/accounts/ at 200)")
        return _finish(run, (key_x, key_y), 3)
    run.verdict("KL5-TENANT", "NOTE",
                "keys and company_id both belong to tenant B; battery "
                f"is tenant-relative. Server revision {REVISION} "
                "recorded for every Server-API call (Seam J hygiene)")
    seed = seed_profiles(rest, full_key, run_id, run)
    if seed is None:
        run.verdict("KL5-SEED", "CONTROL-FAILURE",
                    "control profiles could not be created/verified")
        return _finish(run, (key_x, key_y), 3)
    res = cl_legs(rest, client_post, full_key, run_id, run, seed)
    oc = res["outcomes"]
    if res.get("fatal"):
        run.verdict("KL5-OVERALL", "INCOMPLETE",
                    "client profile surface unreachable in every "
                    "candidate shape; see KL5-CLIENT-PROFILE-SHAPE")
        code = 3
    elif oc["existing_mutation"] or oc["consent"]:
        parts = []
        if oc["existing_mutation"]:
            parts.append("existing-profile mutation legs: " +
                         ", ".join(oc["existing_mutation"]))
        if oc["consent"]:
            parts.append("consent legs: " + ", ".join(oc["consent"]))
        if oc["precedence"]:
            parts.append("precedence violations: " +
                         ", ".join(oc["precedence"]))
        run.verdict("KL5-OVERALL", "SURFACE-CONFIRMED",
                    "unauthenticated (company_id-only) writes reached "
                    "existing-profile state — " + "; ".join(parts))
        code = 0
    elif oc["precedence"]:
        run.verdict("KL5-OVERALL", "PRECEDENCE-ONLY",
                    "no existing-profile mutation and no consent "
                    "write, but identifier precedence deviated: " +
                    ", ".join(oc["precedence"]))
        code = 0
    else:
        run.verdict("KL5-OVERALL", "HELD",
                    "client writes never mutated an existing profile, "
                    "never wrote consent, and collisions resolved per "
                    "the documented precedence — triage-null stands "
                    "on this surface")
        code = 0
    # Cleanup: seeds + everything the legs resolved + step-0 probes.
    all_ids = [p["id"] for p in seed["profiles"].values()]
    all_ids += res.get("extra_profile_ids", [])
    for role in ("p0", "n", "bogus", "v", "s"):
        _st, prof, _raw = find_by_email(rest, full_key,
                                        marker_email(role, run_id))
        if prof:
            all_ids.append(prof["id"])
    for label in ("x", "y"):
        em = marker_email(f"x0{label}", run_id)
        _st, prof, _raw = find_by_email(rest, full_key, em)
        if prof:
            all_ids.append(prof["id"])
    cleanup(rest, full_key, run, all_ids)
    return _finish(run, (key_x, key_y), code)

# ------------------------------------------------------------ selftest ------

class FakeServer:
    """In-memory Server-API transport (kl1 FakeKlaviyo discipline).
    Server-side create-or-update uses anchoring semantics (strongest
    PRESENT identifier decides identity) — the merchant-key surface
    KL-1 characterises; KL-5's subject is the CLIENT transport."""

    FULL = "pk_FAKE_FULL_KEY_0001"
    RO = "pk_FAKE_RO_KEY_0002"

    def __init__(self):
        self.profiles = {}   # id -> attributes dict
        self.events = []     # {"profile_id": pid, "properties": {...}}
        self._n = 0

    def new_id(self):
        self._n += 1
        return f"prof-{self._n}"

    def by(self, field, val):
        for pid, attrs in self.profiles.items():
            if attrs.get(field) == val:
                return pid
        return None

    def profile_json(self, pid):
        return {"id": pid, "type": "profile",
                "attributes": dict(self.profiles[pid])}

    def create_or_update(self, attrs):
        ext = attrs.get("external_id")
        email = attrs.get("email")
        phone = attrs.get("phone_number")
        target = None
        if ext:
            target = self.by("external_id", ext)
        elif email:
            target = self.by("email", email)
        elif phone:
            target = self.by("phone_number", phone)
        if target is None:
            target = self.new_id()
            self.profiles[target] = {}
        merged = dict(self.profiles[target])
        for k, v in attrs.items():
            if k == "properties":
                props = dict(merged.get("properties", {}))
                props.update(v)
                merged["properties"] = props
            else:
                merged[k] = v
        self.profiles[target] = merged
        return target

    def __call__(self, method, path, key, body=None, revision=None,
                 timeout=None):
        clean = path.split("?")[0]
        if clean == "/api/accounts/" and method == "GET":
            return 200, {"data": []}, '{"data": []}'
        if clean == "/api/profiles/" and method == "GET":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            filt = (q.get("filter") or [""])[0]
            m = re.match(r'equals\((\w+),"(.*)"\)', filt)
            pid = self.by(m.group(1), m.group(2)) if m else None
            data = [self.profile_json(pid)] if pid else []
            js = {"data": data}
            return 200, js, json.dumps(js)
        if clean == "/api/profiles/" and method == "POST":
            if key == self.RO:
                return 403, {"errors": []}, '{"errors": []}'
            attrs = body["data"]["attributes"]
            # Model real-API validation (authz first, then validation):
            # malformed email -> 400 even for FULL. Without this the
            # Step 0 probe-email defect is invisible to the selftest.
            em = attrs.get("email")
            if em and not re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", em):
                err = {"errors": [{"status": 400, "code": "invalid",
                                   "detail": "Invalid email address"}]}
                return 400, err, json.dumps(err)
            pid = self.create_or_update(attrs)
            js = {"data": self.profile_json(pid)}
            return 201, js, json.dumps(js)
        m = re.match(r"^/api/profiles/([^/]+)/$", clean)
        if m and method == "GET":
            pid = m.group(1)
            if pid not in self.profiles:
                return 404, None, "not found"
            js = {"data": self.profile_json(pid)}
            return 200, js, json.dumps(js)
        if clean == "/api/events/" and method == "GET":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            filt = (q.get("filter") or [""])[0]
            m = re.match(r'equals\(profile_id,"(.*)"\)', filt)
            want = m.group(1) if m else None
            data = [{"id": f"ev-{i}", "type": "event",
                     "attributes": {"event_properties": dict(e["properties"])}}
                    for i, e in enumerate(self.events)
                    if e["profile_id"] == want]
            js = {"data": data}
            return 200, js, json.dumps(js)
        if clean == "/api/data-privacy-deletion-jobs/" and method == "POST":
            return 201, {"data": {}}, '{"data": {}}'
        return 404, None, "not found"


class FakeClient:
    """In-memory Client-API transport over a shared FakeServer store.
    Modes:
      held     — client writes accepted (202) but NEVER mutate an
                 existing profile and never write consent; creates
                 happen only when no identifier matches. Events still
                 attribute to the resolved profile's timeline
                 (documented ingestion), but event profile-object
                 extras never rewrite profile properties.
      open     — client writes resolve by matching (documented
                 precedence order) and mutate the target; consent
                 writes land; event profile-object extras mutate.
      inverted — like open, but email beats external_id.
      fanout   — like open, but a collision write lands on EVERY
                 matching profile.
    Only the primary body shapes (P1 / E1 / A) are accepted, so the
    battery's shape discovery exercises its fallback logic."""

    def __init__(self, server, mode):
        self.srv = server
        self.mode = mode

    # -- resolution --------------------------------------------------
    def _matches(self, idents):
        """idents: dict with email/phone_number/external_id (any
        subset). Returns ordered list of matching profile ids."""
        found = {}
        if idents.get("external_id"):
            p = self.srv.by("external_id", idents["external_id"])
            if p:
                found["ext"] = p
        if idents.get("email"):
            p = self.srv.by("email", idents["email"])
            if p:
                found["email"] = p
        if idents.get("phone_number"):
            p = self.srv.by("phone_number", idents["phone_number"])
            if p:
                found["phone"] = p
        if self.mode == "fanout":
            return list(dict.fromkeys(found.values()))
        order = ("email", "ext", "phone") if self.mode == "inverted" \
            else ("ext", "email", "phone")
        for k in order:
            if k in found:
                return [found[k]]
        return []

    def _apply_profile_write(self, attrs):
        idents = {k: attrs.get(k)
                  for k in ("email", "phone_number", "external_id")}
        targets = self._matches(idents)
        if not targets:
            self.srv.create_or_update(attrs)
            return
        if self.mode == "held":
            return  # accepted at the edge, ignored for existing
        for pid in targets:
            merged = dict(self.srv.profiles[pid])
            for k, v in attrs.items():
                if k == "properties":
                    props = dict(merged.get("properties", {}))
                    props.update(v)
                    merged["properties"] = props
                else:
                    merged[k] = v
            self.srv.profiles[pid] = merged

    # -- transport ----------------------------------------------------
    def __call__(self, path, company_id, body=None, revision=None,
                 timeout=None):
        if company_id != COMPANY_ID:
            return 404, None, "unknown company"
        data = (body or {}).get("data") or {}
        attrs = data.get("attributes") or {}
        if path == "/client/profiles/":
            if data.get("type") != "client-profile" or \
                    not isinstance(attrs.get("profile"), dict):
                return 400, {"errors": []}, '{"errors": []}'
            self._apply_profile_write(attrs["profile"])
            return 202, None, ""
        if path == "/client/events/":
            prof = attrs.get("profile") or {}
            if not any(k.startswith("$") for k in prof):
                return 400, {"errors": []}, '{"errors": []}'
            idents = {}
            if prof.get("$email"):
                idents["email"] = prof["$email"]
            if prof.get("$phone_number"):
                idents["phone_number"] = prof["$phone_number"]
            if prof.get("$external_id"):
                idents["external_id"] = prof["$external_id"]
            targets = self._matches(idents)
            if not targets:
                pid = self.srv.create_or_update(
                    {k: v for k, v in idents.items() if v})
                targets = [pid]
            extras = {k: v for k, v in prof.items()
                      if not k.startswith("$")}
            for pid in targets:
                self.srv.events.append(
                    {"profile_id": pid,
                     "properties": dict(attrs.get("properties") or {})})
                if self.mode != "held" and extras:
                    merged = dict(self.srv.profiles[pid])
                    props = dict(merged.get("properties", {}))
                    props.update(extras)
                    merged["properties"] = props
                    self.srv.profiles[pid] = merged
            return 202, None, ""
        if path == "/client/subscriptions/":
            prof = ((attrs.get("profile") or {}).get("data") or {}) \
                .get("attributes") or {}
            if not prof:
                return 400, {"errors": []}, '{"errors": []}'
            consent = None
            try:
                consent = prof["subscriptions"]["email"]["marketing"][
                    "consent"]
            except (KeyError, TypeError):
                pass
            pid = self.srv.by("email", prof.get("email")) \
                if prof.get("email") else None
            if pid and consent and self.mode != "held":
                merged = dict(self.srv.profiles[pid])
                subs = {"email": {"marketing": {"consent": consent}}}
                merged["subscriptions"] = subs
                self.srv.profiles[pid] = merged
            return 202, None, ""
        return 404, None, "not found"


def selftest():
    import tempfile
    global OUT_DIR, POLL_INTERVAL, POLL_TIMEOUT
    OUT_DIR = Path(tempfile.mkdtemp(prefix="kl5-selftest-")) / "kl5"
    POLL_INTERVAL = 0
    POLL_TIMEOUT = 0
    failures = []

    def check(name, cond):
        print(f"[SELFTEST] {name}: {'ok' if cond else 'FAIL'}", flush=True)
        if not cond:
            failures.append(name)

    # guard paths
    check("guard rejects empty keys", not keys_ready("", ""))
    check("guard rejects identical keys", not keys_ready("a", "a"))

    # 429 throttle retry: first attempt throttled ("available in 0
    # second" -> 0.5s wait), second succeeds.
    calls = {"n": 0}

    def flaky_once():
        calls["n"] += 1
        if calls["n"] == 1:
            raw = ('{"errors": [{"detail": "Request was throttled. '
                   'Expected available in 0 second."}]}')
            return 429, _try_json(raw), raw
        return 202, None, ""

    st, _js, _raw = _with_throttle_retry(flaky_once)
    check("throttle retry recovers", st == 202 and calls["n"] == 2)

    def run_mode(mode):
        srv = FakeServer()
        cli = FakeClient(srv, mode)
        run = Run(f"selftest-{mode}")
        rid = f"st{mode[:4]}01"
        ro, full = resolve_keys(srv, FakeServer.RO, FakeServer.FULL,
                                rid, run)
        return srv, cli, run, rid, ro, full

    # both-full keys must abort discrimination (kl1 discipline)
    srv = FakeServer()

    class BothFull(FakeServer):
        def __call__(self, method, path, key, body=None, revision=None,
                     timeout=None):
            if path.split("?")[0] == "/api/profiles/" and method == "POST":
                attrs = body["data"]["attributes"]
                pid = self.create_or_update(attrs)
                js = {"data": self.profile_json(pid)}
                return 201, js, json.dumps(js)
            return super().__call__(method, path, key, body, revision,
                                   timeout)

    bf = BothFull()
    run = Run("selftest-bothfull")
    _ro, full = resolve_keys(bf, FakeServer.RO, FakeServer.FULL,
                             "stbf01", run)
    check("both-full keys abort discrimination", full is None)

    # held mode: the triage-null stands on every leg
    srv, cli, run, rid, ro, full = run_mode("held")
    check("held: keys resolved", bool(full))
    seed = seed_profiles(srv, full, rid, run)
    check("held: seed ok", seed is not None)
    res = cl_legs(srv, cli, full, rid, run, seed)
    v = run.verdicts
    check("held: profile shape P1",
          v["KL5-CLIENT-PROFILE-SHAPE"]["verdict"] == "P1")
    check("held: bogus company held",
          v["KL5-CL0-NEGCTRL"]["verdict"] == "HELD")
    check("held: CL1 no-land",
          v["KL5-CL1-EMAIL-WRITE"]["verdict"] == "NO-LAND")
    check("held: CL2 no-land",
          v["KL5-CL2-PHONE-WRITE"]["verdict"] == "NO-LAND")
    check("held: CL3 no-land",
          v["KL5-CL3-EXT-WRITE"]["verdict"] == "NO-LAND")
    check("held: CL4a no-land",
          v["KL5-CL4A-PRECEDENCE"]["verdict"] == "NO-LAND")
    check("held: event attributed",
          v["KL5-CL5-EVENT-ATTRIB"]["verdict"] == "ATTRIBUTED")
    check("held: event no-mutate",
          v["KL5-CL5-EVENT-MUTATE"]["verdict"] == "NO-MUTATE")
    check("held: phone event attributed",
          v["KL5-CL5B-EVENT-PHONE-ATTRIB"]["verdict"] == "ATTRIBUTED")
    check("held: consent ignored",
          v["KL5-CL6-CONSENT-SUB"]["verdict"] == "IGNORED")
    check("held: unsub skipped",
          v["KL5-CL7-CONSENT-UNSUB"]["verdict"] == "SKIPPED")
    check("held: no outcomes recorded",
          res["outcomes"] == {"existing_mutation": [], "consent": [],
                              "precedence": []})

    # open mode: the full surface confirms
    srv, cli, run, rid, ro, full = run_mode("open")
    seed = seed_profiles(srv, full, rid, run)
    res = cl_legs(srv, cli, full, rid, run, seed)
    v = run.verdicts
    check("open: CL1 lands",
          v["KL5-CL1-EMAIL-WRITE"]["verdict"] == "LANDS-EXISTING")
    check("open: CL2 lands",
          v["KL5-CL2-PHONE-WRITE"]["verdict"] == "LANDS-EXISTING")
    check("open: CL3 lands",
          v["KL5-CL3-EXT-WRITE"]["verdict"] == "LANDS-EXISTING")
    check("open: CL4a as-documented",
          v["KL5-CL4A-PRECEDENCE"]["verdict"] == "AS-DOCUMENTED")
    check("open: CL4b phone-anchored",
          v["KL5-CL4B-PRECEDENCE"]["verdict"] == "PHONE-ANCHORED")
    check("open: event mutates",
          v["KL5-CL5-EVENT-MUTATE"]["verdict"] == "MUTATES")
    check("open: consent sub accepted",
          v["KL5-CL6-CONSENT-SUB"]["verdict"] == "ACCEPTED")
    check("open: consent unsub accepted",
          v["KL5-CL7-CONSENT-UNSUB"]["verdict"] == "ACCEPTED")
    check("open: outcomes recorded",
          "CL1" in res["outcomes"]["existing_mutation"] and
          "CL6-SUB" in res["outcomes"]["consent"])

    # inverted mode: email beats external_id -> violation detected
    srv, cli, run, rid, ro, full = run_mode("inverted")
    seed = seed_profiles(srv, full, rid, run)
    cl_legs(srv, cli, full, rid, run, seed)
    check("inverted: CL4a violated",
          run.verdicts["KL5-CL4A-PRECEDENCE"]["verdict"] == "VIOLATED")

    # fanout mode: collision lands on both -> violation detected
    srv, cli, run, rid, ro, full = run_mode("fanout")
    seed = seed_profiles(srv, full, rid, run)
    cl_legs(srv, cli, full, rid, run, seed)
    check("fanout: CL4a violated",
          run.verdicts["KL5-CL4A-PRECEDENCE"]["verdict"] == "VIOLATED")

    # scrub: planted key material must vanish; company_id stays (public)
    victim = OUT_DIR / "scrub-probe.txt"
    victim.parent.mkdir(parents=True, exist_ok=True)
    victim.write_text(f"leak {FakeServer.FULL} and pk_deadbeef, "
                      f"company {COMPANY_ID} here", encoding="utf-8")
    scrub_tree(OUT_DIR, [FakeServer.FULL, FakeServer.RO])
    text = victim.read_text(encoding="utf-8")
    check("scrub removes key material",
          FakeServer.FULL not in text and "pk_" not in text)
    check("scrub keeps public company_id", COMPANY_ID in text)

    print(f"[SELFTEST] {'ALL OK' if not failures else 'FAILURES: ' + str(failures)}",
          flush=True)
    return 0 if not failures else 1

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main_live())
