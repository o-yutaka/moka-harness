#!/usr/bin/env python3
"""KL-1 battery — GitHub Actions build (repo: o-yutaka/moka-harness).

KL-1 = Customer Agent profile-write authorization / identifier collision
(notes/candidates.md KL-1; authz-model.md Seam D + Seam F).

Refined hypothesis (attacker pass first):
  * Who takes what: an unauthenticated store VISITOR (no merchant account)
    whose only power is talking to a merchant's Customer Agent. Profile
    Enrichment writes conversation-derived preferences/intent into profile
    properties in real time. If the conversation->profile binding trusts a
    self-declared identifier (email/phone), the visitor's answers land on
    the VICTIM's existing profile in the merchant's account — property
    pollution that feeds segments / flow branching / recovery flows.
  * Strongest benign story (triage-null): binding requires an authenticated
    shopper session or a verification code sent to the declared email/phone;
    enrichment only ever writes to a conversation-scoped fresh profile that
    never merges into an existing one. Kill condition on the card.
  * Intent vs implementation: the DOCUMENTED identifier precedence is
    Profile ID > External ID > Email > Phone > Anonymous, external-ID-only
    profiles are documented to NEVER auto-merge, and the conversation
    `profile` binding is documented add-once (Update Conversation,
    scope agents:write, beta revision 2026-10-15.pre). Every leg below
    measures implementation against exactly those documented invariants.

What an API-only battery can and cannot reach (measured, not assumed):
  The conversation itself is born on a channel (web/SMS/WhatsApp chat).
  The official MCP tool surface has NO create-conversation tool
  (create_customer_agent_response posts INTO an existing conversation).
  So this battery:
    AG-*  probes the Customer Agent conversation API surface for
          reachability (list/create/update), the Free-plan gate on
          conversation creation ("0 conversations"), the add-once
          binding invariant, and the agents:write scope binding of the
          read-only key. A 404/405 create outcome is EVIDENCE that the
          conversation leg belongs to the UI/channel lane — it is
          recorded as NOT-API-REACHABLE, never guessed.
    ID-*  measures the identifier-resolution machinery the binding relies
          on, via the Server API: email-only writes onto an existing
          profile (baseline), and precedence collisions
          (external_id x email, email x phone, PATCH email rebind).
          These are the same resolution rules enrichment writes pass
          through; a precedence violation here is the seam, measured.
  The channel-side conversation experiment itself (visitor chat ->
  enrichment write-back) remains a UI-lane item; this script does not
  claim to run it. Cross-tenant legs need tenant-A keys, which do not
  exist yet (only tenant B's keys are issued) — the battery is
  tenant-relative and prints that limitation in its verdict file.

Keys: env KLAVIYO_KEY_X / KLAVIYO_KEY_Y (unordered; GitHub Secrets).
Step 0 discriminates them by REST behaviour exactly like kl2_run.py:
GET /api/accounts/ must be 200 for both; a probe POST /api/profiles/
returning 201 => FULL, 403 => RO. Abort unless exactly one of each.

Safety rails:
  * All writes target run-scoped marker profiles in OUR OWN account
    (emails in the mitsudayoooooon+kl1* Gmail tag namespace, one
    fictional NANPA phone +1 555-010-xxxx). No third-party data.
  * Verification reads are targeted equals(...) lookups only. Never
    list enumeration of profiles, never /api/v1/people (outside the
    brief's safe harbor).
  * stdout is a PUBLIC log: step names, HTTP statuses, field names,
    counts, verdicts. Never key values, never full bodies, never
    marker emails or profile ids (run-id suffix only).
  * Full response bodies go to outputs/kl1/<run_id>/ and are scrubbed
    of key material before exit (same discipline as kl2_run.py).
  * Cleanup: data-privacy deletion jobs for every profile created.

Exit codes mirror kl2: 2 = refused (missing keys), 3 = control failure
(the run cannot discriminate), 0 = completed.
--selftest: in-memory fake transport, several behaviour modes, ZERO
network. Asserts verdict logic incl. precedence-violation detection,
plan-gate detection, rebind acceptance, and output scrubbing.
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
REVISION = os.environ.get("KL1_REVISION", "2024-10-15")
BETA_REVISION = os.environ.get("KL1_BETA_REVISION", "2026-10-15.pre")
OUTPUTS_ROOT = Path(os.environ.get("KL1_OUTPUTS_ROOT", "outputs"))
OUT_DIR = OUTPUTS_ROOT / "kl1"
MARKER_DOMAIN = "gmail.com"
MARKER_LOCAL = "mitsudayoooooon"

# Candidate list paths for the Customer Agent conversation API. The
# reference name is update_customer_agent_conversation_beta; the exact
# REST path is NOT in our notes, so reachability is probed, not assumed.
AGENT_PATHS = [
    ("/api/customer-agent-conversations/", BETA_REVISION),
    ("/api/customer-agent/conversations/", BETA_REVISION),
    ("/api/conversations/", REVISION),
]

# ---------------------------------------------------------------- keys ------

def get_env_keys():
    return (os.environ.get("KLAVIYO_KEY_X", "").strip(),
            os.environ.get("KLAVIYO_KEY_Y", "").strip())

def keys_ready(key_x, key_y):
    return bool(key_x) and bool(key_y) and key_x != key_y

# ------------------------------------------------------------- REST raw -----

def rest(method, path, key, body=None, revision=None, timeout=60):
    # Klaviyo burst-throttles (429 "Expected available in N second",
    # measured 2026-11-09 run #606: a 1s throttle aborted Step 0 key
    # discrimination). Retry 429s with the server-stated wait.
    attempt = 0
    while True:
        status, js, raw = _rest_once(method, path, key, body, revision,
                                     timeout)
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
    """Remove key material from every file under root (kl2 discipline)."""
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
    Response-shape-first: verdicts key off the marker property's presence
    wherever the API actually puts it, not off an assumed field path."""
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

PLAN_WORDS = ("plan", "upgrade", "subscription", "not included",
              "limit", "trial", "billing", "entitlement")

def looks_plan_gated(status, raw):
    if status != 403:
        return False
    low = (raw or "").lower()
    return any(w in low for w in PLAN_WORDS)

# ------------------------------------------------------ profile helpers -----

def marker_email(role, run_id):
    return f"{MARKER_LOCAL}+kl1{role}-{run_id}@{MARKER_DOMAIN}"

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

# ---------------------------------------------------------- step 0 ----------

def resolve_keys(rest_fn, key_x, key_y, run_id, run):
    """Discriminate X/Y by REST behaviour (kl2 step 0). Returns
    (ro_key, full_key) or (None, None) when the run cannot proceed."""
    records = {}
    classes = {}
    for label, key in (("X", key_x), ("Y", key_y)):
        st_get, _js, raw_get = rest_fn("GET", "/api/accounts/", key)
        probe_email = marker_email("x0", run_id) + f".{label.lower()}"
        st_post, _js2, raw_post = create_profile(rest_fn, key, {
            "email": probe_email, "first_name": "KL1",
            "last_name": f"PROBE-{label}-{run_id}",
            "properties": {"kl1_marker": run_id}})
        cls = classify_write_status(st_post) if st_get == 200 else "NOREAD"
        classes[label] = cls
        records[label] = {"get_accounts_status": st_get,
                          "probe_post_status": st_post, "class": cls,
                          "probe_email_tag": f"x0.{label.lower()}"}
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
    """Create control profiles V / E / S in our own account.
    Returns dict with ids + observed shapes, or None on control failure."""
    digits = "".join(c for c in run_id if c.isdigit())[-4:].rjust(4, "0")
    phone_v = f"+1555010{digits}"
    ext_e = f"kl1ext-{run_id}"
    seeds = {
        "V": {"email": marker_email("v", run_id), "phone_number": phone_v,
              "properties": {"kl1_sentinel": f"V-{run_id}",
                             "kl1_role": "victim"}},
        "E": {"external_id": ext_e,
              "properties": {"kl1_sentinel": f"E-{run_id}",
                             "kl1_role": "extonly"}},
        "S": {"email": marker_email("s", run_id),
              "properties": {"kl1_sentinel": f"S-{run_id}",
                             "kl1_role": "self"}},
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
                         ("E", ("ext", ext_e)),
                         ("S", ("email", seeds["S"]["email"]))):
        if lookup[0] == "email":
            _st, prof, _raw = find_by_email(rest_fn, full_key, lookup[1])
        else:
            _st, prof, _raw = find_by_external_id(rest_fn, full_key,
                                                  lookup[1])
        got = find_prop(prof, "kl1_sentinel") if prof else None
        want = f"{role}-{run_id}"
        print(f"[SEED] {role}: read-back sentinel "
              f"{'OK' if got == want else 'MISMATCH'}", flush=True)
        if got != want:
            return None
    return out

# ------------------------------------------------------------- AG legs ------

def ag_legs(rest_fn, ro_key, full_key, run, seed):
    """Customer Agent conversation API surface: reachability, Free-plan
    creation gate, add-once binding, RO scope binding."""
    # AG-1 reachability probe table (reads only).
    table = []
    working = None  # (path, revision)
    for path, rev in AGENT_PATHS:
        for label, key in (("FULL", full_key), ("RO", ro_key)):
            q = urllib.parse.urlencode({"page[size]": 1})
            st, js, raw = rest_fn("GET", f"{path}?{q}", key, revision=rev)
            tag = path.strip("/").replace("/", "_") + f"_{label}"
            run.save(f"ag1_{tag}.txt", raw)
            n = None
            if js and isinstance(js.get("data"), list):
                n = len(js["data"])
            table.append({"path": path, "revision": rev, "key": label,
                          "status": st, "data_count": n})
            print(f"[AG-1] GET {path} rev={rev} key={label} -> {st} "
                  f"count={n}", flush=True)
            if st == 200 and label == "FULL" and working is None:
                working = (path, rev)
    run.save("ag1_table.json", table)
    if working is None:
        run.verdict("KL1-AGENT-REACH", "NOT-API-REACHABLE",
                    "no candidate list path returned 200 for the FULL key; "
                    "statuses in ag1_table.json")
    else:
        run.verdict("KL1-AGENT-REACH", "REACHABLE",
                    f"list path {working[0]} rev {working[1]}")

    # AG-2 conversation inventory on the working path.
    conv_id_existing = None
    conv_existing = None
    if working:
        path, rev = working
        q = urllib.parse.urlencode({"page[size]": 5})
        st, js, raw = rest_fn("GET", f"{path}?{q}", full_key, revision=rev)
        run.save("ag2_list.txt", raw)
        items = (js or {}).get("data") if isinstance(js, dict) else None
        count = len(items) if isinstance(items, list) else None
        print(f"[AG-2] conversations visible: {count}", flush=True)
        if isinstance(items, list) and items:
            conv_existing = items[0]
            conv_id_existing = items[0].get("id")
            run.save("ag2_first_shape.json", shape_of(items[0]))

    # AG-3 creation probe (FULL key). This is the Free-plan gate test.
    create_path, create_rev = working if working else AGENT_PATHS[0]
    body = {"data": {"type": "customer-agent-conversation",
                     "attributes": {}}}
    st, js, raw = rest_fn("POST", create_path, full_key, body,
                          revision=create_rev)
    run.save("ag3_create.txt", raw)
    conv_id_new = None
    if isinstance(js, dict):
        conv_id_new = (js.get("data") or {}).get("id")
    print(f"[AG-3] POST {create_path} -> {st} id="
          f"{'yes' if conv_id_new else 'no'}", flush=True)
    if st in (200, 201) and conv_id_new:
        run.verdict("KL1-AGENT-CREATE", "REACHABLE",
                    "conversation creation accepted via API")
    elif looks_plan_gated(st, raw):
        run.verdict("KL1-AGENT-CREATE", "PLAN-GATED",
                    "403 with plan/subscription wording on Free plan")
    elif st in (404, 405):
        run.verdict("KL1-AGENT-CREATE", "NOT-API-REACHABLE",
                    f"create -> {st}; conversations originate on channels, "
                    "consistent with the official tool surface having no "
                    "create-conversation tool")
    else:
        run.verdict("KL1-AGENT-CREATE", f"OTHER({st})",
                    "create outcome recorded in ag3_create.txt")

    # AG-4..6 binding legs — only on a conversation WE created.
    vid = seed["profiles"]["V"]["id"]
    sid = seed["profiles"]["S"]["id"]
    if conv_id_new:
        path = create_path.rstrip("/")
        rev = create_rev
        # AG-6 (run first, must not mutate): RO key attempts the bind.
        bind_body = {"data": {"type": "customer-agent-conversation",
                              "id": conv_id_new,
                              "attributes": {"profile": vid}}}
        st_ro, _js, raw_ro = rest_fn("PATCH", f"{path}/{conv_id_new}/",
                                     ro_key, bind_body, revision=rev)
        run.save("ag6_ro_patch.txt", raw_ro)
        run.verdict("KL1-AGENT-RO-SCOPE",
                    "HELD" if st_ro == 403 else f"CHECK({st_ro})",
                    f"RO key PATCH bind -> {st_ro} (403 expected: "
                    "agents is read-only on the RO key)")
        # AG-4: FULL key binds V's profile.
        st_b, js_b, raw_b = rest_fn("PATCH", f"{path}/{conv_id_new}/",
                                    full_key, bind_body, revision=rev)
        run.save("ag4_bind.txt", raw_b)
        st_g, js_g, raw_g = rest_fn("GET", f"{path}/{conv_id_new}/",
                                    full_key, revision=rev)
        run.save("ag4_readback.txt", raw_g)
        bound = contains_id(js_g, vid) if js_g else False
        print(f"[AG-4] bind PATCH -> {st_b}; read-back contains V id: "
              f"{bound}", flush=True)
        run.verdict("KL1-AGENT-BIND",
                    "BOUND" if bound else f"UNCONFIRMED({st_b})",
                    "profile binding observed in conversation read-back"
                    if bound else "binding not visible in read-back shape; "
                    "see ag4_readback.txt")
        # AG-5: rebind attempt to a DIFFERENT profile (add-once invariant).
        rebind_body = {"data": {"type": "customer-agent-conversation",
                                "id": conv_id_new,
                                "attributes": {"profile": sid}}}
        st_r, _js2, raw_r = rest_fn("PATCH", f"{path}/{conv_id_new}/",
                                    full_key, rebind_body, revision=rev)
        run.save("ag5_rebind.txt", raw_r)
        st_g2, js_g2, raw_g2 = rest_fn("GET", f"{path}/{conv_id_new}/",
                                       full_key, revision=rev)
        run.save("ag5_readback.txt", raw_g2)
        now_sid = contains_id(js_g2, sid) if js_g2 else False
        still_vid = contains_id(js_g2, vid) if js_g2 else False
        print(f"[AG-5] rebind PATCH -> {st_r}; now S id: {now_sid}, "
              f"still V id: {still_vid}", flush=True)
        if now_sid and not still_vid:
            run.verdict("KL1-AGENT-REBIND", "REBIND-ACCEPTED",
                        "conversation profile binding was REPLACED after "
                        "being set — documented add-once invariant broken")
        elif st_r in (400, 409, 422) or (still_vid and not now_sid):
            run.verdict("KL1-AGENT-REBIND", "HELD",
                        "second bind rejected / original binding kept")
        else:
            run.verdict("KL1-AGENT-REBIND", f"UNCONFIRMED({st_r})",
                        "read-back shape ambiguous; see ag5_readback.txt")
    else:
        run.verdict("KL1-AGENT-BIND", "SKIPPED",
                    "no API-created conversation; binding legs need a "
                    "channel-born conversation (UI lane)")
        run.verdict("KL1-AGENT-REBIND", "SKIPPED", "same as bind")
        run.verdict("KL1-AGENT-RO-SCOPE", "SKIPPED",
                    "no conversation id to PATCH")
    return {"working_path": working[0] if working else None,
            "existing_conversation": bool(conv_id_existing),
            "created_conversation": bool(conv_id_new)}

# ------------------------------------------------------------- ID legs ------

def _probe_landed(rest_fn, key, lookup, marker_key, marker_val):
    kind, val = lookup
    if kind == "email":
        _st, prof, _raw = find_by_email(rest_fn, key, val)
    elif kind == "ext":
        _st, prof, _raw = find_by_external_id(rest_fn, key, val)
    else:
        _st, prof, _raw = find_by_phone(rest_fn, key, val)
    if not prof:
        return False, None
    return find_prop(prof, marker_key) == marker_val, prof.get("id")

def id_legs(rest_fn, full_key, run_id, run, seed):
    """Identifier-resolution precedence legs (documented order:
    Profile ID > External ID > Email > Phone; external-ID-only profiles
    never auto-merge). Each leg writes a unique kl1_probe value and the
    verdict comes from independent read-backs of ALL involved profiles."""
    ev = seed["profiles"]["V"]["email"]
    es = seed["profiles"]["S"]["email"]
    ext_e = seed["ext_e"]
    phone_v = seed["phone_v"]
    en = marker_email("n", run_id)  # fresh email, never pre-created
    violations = []

    # ID-1 baseline: email-only write onto existing V.
    val = f"ID1-{run_id}"
    st, _js, raw = create_profile(rest_fn, full_key, {
        "email": ev, "properties": {"kl1_probe": val}})
    run.save("id1_write.txt", raw)
    landed, _ = _probe_landed(rest_fn, full_key, ("email", ev),
                              "kl1_probe", val)
    print(f"[ID-1] email-only write -> {st}; landed on V: {landed}",
          flush=True)
    run.verdict("KL1-ID1-EMAIL-WRITE", "LANDS" if landed else "NO-LAND",
                "baseline: a bare email identifier mutates the existing "
                "profile (by-design create-or-update; context for ID-2..4)")

    # ID-2 collision: V's email + E's external_id in ONE write.
    # Documented: External ID > Email -> write must land on E, not V.
    val = f"ID2-{run_id}"
    st, _js, raw = create_profile(rest_fn, full_key, {
        "email": ev, "external_id": ext_e,
        "properties": {"kl1_probe": val}})
    run.save("id2_write.txt", raw)
    on_v, _ = _probe_landed(rest_fn, full_key, ("email", ev),
                            "kl1_probe", val)
    on_e, _ = _probe_landed(rest_fn, full_key, ("ext", ext_e),
                            "kl1_probe", val)
    print(f"[ID-2] ext+email write -> {st}; on V: {on_v}, on E: {on_e}",
          flush=True)
    if on_e and not on_v:
        run.verdict("KL1-ID2-PRECEDENCE", "AS-DOCUMENTED",
                    "external_id beat email, write landed on E only")
    elif on_v and not on_e:
        violations.append("ID-2")
        run.verdict("KL1-ID2-PRECEDENCE", "VIOLATED",
                    "email beat external_id — documented precedence "
                    "(External ID > Email) inverted")
    elif on_v and on_e:
        violations.append("ID-2-merge")
        run.verdict("KL1-ID2-PRECEDENCE", "VIOLATED",
                    "write landed on BOTH profiles (merge/fan-out across "
                    "identifiers that docs keep separate)")
    else:
        run.verdict("KL1-ID2-PRECEDENCE", f"NO-LAND({st})",
                    "write landed nowhere; shape in id2_write.txt")

    # ID-3 collision: FRESH email + V's phone in ONE write.
    # Two defensible readings of the documented precedence exist:
    # (anchoring) a present email anchors identity -> NEW profile, V
    # untouched; (matching) the highest-precedence MATCHING identifier
    # wins -> the phone match pulls the write onto V. The observation is
    # recorded descriptively (PHONE-ANCHORED), NOT scored a violation:
    # which reading the vendor intends is a docs question, and for the
    # merchant-key surface both are operator-authorized writes anyway.
    # What matters for KL-1 is that the resolution machinery is now
    # characterized for the channel/binding legs that inherit it.
    val = f"ID3-{run_id}"
    st, _js, raw = create_profile(rest_fn, full_key, {
        "email": en, "phone_number": phone_v,
        "properties": {"kl1_probe": val}})
    run.save("id3_write.txt", raw)
    vid_seed = seed["profiles"]["V"]["id"]
    _s, prof_ev, _r = find_by_email(rest_fn, full_key, ev)
    _s, prof_en, _r = find_by_email(rest_fn, full_key, en)
    _s, prof_ph, _r = find_by_phone(rest_fn, full_key, phone_v)

    def _hit(prof):
        return bool(prof) and find_prop(prof, "kl1_probe") == val
    v_hit = _hit(prof_ev) and prof_ev.get("id") == vid_seed
    v_hit = v_hit or (_hit(prof_ph) and prof_ph.get("id") == vid_seed)
    en_is_v = bool(prof_en) and prof_en.get("id") == vid_seed
    n_hit = _hit(prof_en) and not en_is_v
    pid_n = prof_en.get("id") if n_hit else None
    print(f"[ID-3] new-email+V-phone write -> {st}; probe on V: {v_hit}"
          f", on distinct new profile: {n_hit}, V absorbed fresh email:"
          f" {en_is_v}", flush=True)
    if n_hit and not v_hit:
        run.verdict("KL1-ID3-PRECEDENCE", "AS-DOCUMENTED",
                    "email anchored identity; fresh profile created, "
                    "V untouched")
    elif v_hit and not n_hit:
        run.verdict("KL1-ID3-PRECEDENCE", "PHONE-ANCHORED",
                    "the phone match pulled a write carrying a FRESH "
                    "email onto the existing profile"
                    + (" (which also absorbed the fresh email)"
                       if en_is_v else "")
                    + " — resolution is matching-based, not "
                    "anchoring-based (observation; see design note "
                    "for the two readings)")
    elif v_hit and n_hit:
        violations.append("ID-3-fanout")
        run.verdict("KL1-ID3-PRECEDENCE", "VIOLATED",
                    "write landed on BOTH the phone owner and a distinct "
                    "fresh-email profile (fan-out across identities)")
    else:
        run.verdict("KL1-ID3-PRECEDENCE", f"NO-LAND({st})",
                    "write landed nowhere; shape in id3_write.txt")

    # ID-4 rebind: PATCH E (external-ID-only profile) setting its email
    # to V's email. Watch: acceptance, duplicate email identities, or
    # an outright merge of E into V.
    eid = seed["profiles"]["E"]["id"]
    body = {"data": {"type": "profile", "id": eid,
                     "attributes": {"email": ev}}}
    st, _js, raw = rest_fn("PATCH", f"/api/profiles/{eid}/", full_key, body)
    run.save("id4_patch.txt", raw)
    _s1, prof_e, _r1 = find_by_external_id(rest_fn, full_key, ext_e)
    _s2, prof_v, _r2 = find_by_email(rest_fn, full_key, ev)
    e_has_ev = bool(prof_e) and contains_id(prof_e, ev)
    v_alive = bool(prof_v) and prof_v.get("id") == seed["profiles"]["V"]["id"]
    e_alive = bool(prof_e) and prof_e.get("id") == eid
    print(f"[ID-4] PATCH E email:=V.email -> {st}; E alive: {e_alive}, "
          f"E has V email: {e_has_ev}, V intact: {v_alive}", flush=True)
    if st in (200, 201) and e_has_ev and v_alive and e_alive:
        violations.append("ID-4")
        run.verdict("KL1-ID4-REBIND", "DUPLICATE-IDENTITY",
                    "two live profiles now share the victim email — "
                    "email uniqueness / merge discipline broken")
    elif st in (400, 409, 422):
        run.verdict("KL1-ID4-REBIND", "HELD",
                    f"PATCH rejected with {st}")
    elif not e_alive and v_alive:
        # Observation only, not scored a violation: an operator's
        # explicit PATCH setting an email may legitimately trigger a
        # deterministic merge; the docs' "never auto-matched" statement
        # covers resolution-time matching, which ID-2/ID-3 measure.
        run.verdict("KL1-ID4-REBIND", "MERGED",
                    "E disappeared into V after the explicit email set "
                    "(merge-on-set observed; recorded, not scored)")
    else:
        run.verdict("KL1-ID4-REBIND", f"CHECK({st})",
                    "outcome recorded in id4_patch.txt + read-backs")

    if violations:
        run.verdict("KL1-ID-PRECEDENCE", "VIOLATED",
                    "legs: " + ", ".join(violations))
    else:
        run.verdict("KL1-ID-PRECEDENCE", "AS-DOCUMENTED",
                    "all collision legs resolved per documented order")
    return {"extra_profile_ids": [pid_n] if pid_n else []}

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
    run.verdict("KL1-CLEANUP", "OK",
                f"{len(results)} deletion job(s) submitted")
    return results

# --------------------------------------------------------------- main -------

def _finish(run, keys, code):
    run.save("verdict.json", run.verdicts)
    scrub_tree(OUT_DIR, [k for k in keys if k])
    print(f"[DONE] verdicts in outputs/kl1/{run.run_id}/verdict.json",
          flush=True)
    return code

def main_live():
    key_x, key_y = get_env_keys()
    run_id = time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + \
        secrets.token_hex(2)
    run = Run(run_id)
    if not keys_ready(key_x, key_y):
        run.verdict("KL1-GUARD", "REFUSED",
                    "KLAVIYO_KEY_X / KLAVIYO_KEY_Y missing or identical")
        return _finish(run, (key_x, key_y), 2)
    ro_key, full_key = resolve_keys(rest, key_x, key_y, run_id, run)
    if not full_key:
        run.verdict("KL1-STEP0", "ABORT",
                    "key discrimination failed (need exactly one FULL "
                    "and one RO, both reading /api/accounts/ at 200)")
        return _finish(run, (key_x, key_y), 3)
    run.verdict("KL1-TENANT", "NOTE",
                "keys belong to ONE tenant (B); cross-tenant legs need "
                "tenant-A keys, not yet issued — battery is "
                "tenant-relative")
    seed = seed_profiles(rest, full_key, run_id, run)
    if seed is None:
        run.verdict("KL1-SEED", "CONTROL-FAILURE",
                    "control profiles could not be created/verified")
        return _finish(run, (key_x, key_y), 3)
    ag = ag_legs(rest, ro_key, full_key, run, seed)
    ids = id_legs(rest, full_key, run_id, run, seed)
    # Cleanup: every profile we can still resolve, incl. step-0 probes.
    all_ids = [p["id"] for p in seed["profiles"].values()]
    all_ids += ids.get("extra_profile_ids", [])
    for role in ("v", "s", "n"):
        _st, prof, _raw = find_by_email(rest, full_key,
                                        marker_email(role, run_id))
        if prof:
            all_ids.append(prof["id"])
    for label in ("x", "y"):
        em = marker_email("x0", run_id) + f".{label}"
        _st, prof, _raw = find_by_email(rest, full_key, em)
        if prof:
            all_ids.append(prof["id"])
    cleanup(rest, full_key, run, all_ids)
    return _finish(run, (key_x, key_y), 0)

# ------------------------------------------------------------ selftest ------

class FakeKlaviyo:
    """In-memory transport with switchable behaviour modes.
    Modes: documented | phone_anchor | plan_gated | creatable |
    rebind_ok | both_full."""

    FULL = "pk_FAKE_FULL_KEY_0001"
    RO = "pk_FAKE_RO_KEY_0002"

    def __init__(self, mode):
        self.mode = mode
        self.profiles = {}       # id -> attributes dict
        self.convs = {}          # id -> bound profile id or None
        self._n = 0

    # -- profile store -------------------------------------------------
    def _new_id(self):
        self._n += 1
        return f"prof-{self._n}"

    def _by(self, field, val):
        for pid, attrs in self.profiles.items():
            if attrs.get(field) == val:
                return pid
        return None

    def _profile_json(self, pid):
        return {"id": pid, "type": "profile",
                "attributes": dict(self.profiles[pid])}

    def _create_or_update(self, attrs):
        ext = attrs.get("external_id")
        email = attrs.get("email")
        phone = attrs.get("phone_number")
        target = None
        if self.mode == "phone_anchor":
            # first MATCHING identifier in precedence order wins
            if ext and self._by("external_id", ext):
                target = self._by("external_id", ext)
            elif email and self._by("email", email):
                target = self._by("email", email)
            elif phone and self._by("phone_number", phone):
                target = self._by("phone_number", phone)
        else:
            # anchoring: strongest PRESENT identifier decides identity
            if ext:
                target = self._by("external_id", ext)
            elif email:
                target = self._by("email", email)
            elif phone:
                target = self._by("phone_number", phone)
        if target is None:
            target = self._new_id()
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

    # -- transport ------------------------------------------------------
    def __call__(self, method, path, key, body=None, revision=None,
                 timeout=None):
        clean = path.split("?")[0]
        if clean == "/api/accounts/" and method == "GET":
            return 200, {"data": []}, '{"data": []}'
        if clean == "/api/profiles/" and method == "GET":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            filt = (q.get("filter") or [""])[0]
            m = re.match(r'equals\((\w+),"(.*)"\)', filt)
            pid = self._by(m.group(1), m.group(2)) if m else None
            data = [self._profile_json(pid)] if pid else []
            js = {"data": data}
            return 200, js, json.dumps(js)
        if clean == "/api/profiles/" and method == "POST":
            if key == self.RO and self.mode != "both_full":
                return 403, {"errors": []}, '{"errors": []}'
            attrs = body["data"]["attributes"]
            pid = self._create_or_update(attrs)
            js = {"data": self._profile_json(pid)}
            return 201, js, json.dumps(js)
        m = re.match(r"^/api/profiles/([^/]+)/$", clean)
        if m and method == "PATCH":
            pid = m.group(1)
            attrs = body["data"]["attributes"]
            new_email = attrs.get("email")
            if new_email:
                other = self._by("email", new_email)
                if other and other != pid:
                    return 409, {"errors": []}, '{"errors": []}'
            self.profiles[pid].update(attrs)
            js = {"data": self._profile_json(pid)}
            return 200, js, json.dumps(js)
        if clean == "/api/data-privacy-deletion-jobs/" and method == "POST":
            return 201, {"data": {}}, '{"data": {}}'
        # --- customer agent conversations ---
        if clean in ("/api/customer-agent-conversations/",):
            if method == "GET":
                if self.mode in ("plan_gated", "creatable", "rebind_ok"):
                    data = [{"id": cid, "type":
                             "customer-agent-conversation",
                             "attributes": {"profile": b}}
                            for cid, b in self.convs.items()]
                    js = {"data": data}
                    return 200, js, json.dumps(js)
                return 404, None, "not found"
            if method == "POST":
                if self.mode == "plan_gated":
                    raw = ('{"errors": [{"detail": "Customer Agent is '
                           'not included in your plan. Upgrade to use '
                           'conversations."}]}')
                    return 403, _try_json(raw), raw
                if self.mode in ("creatable", "rebind_ok"):
                    cid = f"conv-{len(self.convs) + 1}"
                    self.convs[cid] = None
                    js = {"data": {"id": cid, "type":
                                   "customer-agent-conversation",
                                   "attributes": {}}}
                    return 201, js, json.dumps(js)
                return 405, None, "method not allowed"
        m = re.match(r"^/api/customer-agent-conversations/([^/]+)/$", clean)
        if m:
            cid = m.group(1)
            if method == "GET":
                js = {"data": {"id": cid,
                               "type": "customer-agent-conversation",
                               "attributes": {"profile":
                                              self.convs.get(cid)}}}
                return 200, js, json.dumps(js)
            if method == "PATCH":
                if key == self.RO:
                    return 403, {"errors": []}, '{"errors": []}'
                newp = body["data"]["attributes"].get("profile")
                if self.convs.get(cid) and self.mode != "rebind_ok":
                    return 400, {"errors": []}, '{"errors": []}'
                self.convs[cid] = newp
                js = {"data": {"id": cid,
                               "type": "customer-agent-conversation",
                               "attributes": {"profile": newp}}}
                return 200, js, json.dumps(js)
        return 404, None, "not found"

def selftest():
    import tempfile
    global OUT_DIR
    OUT_DIR = Path(tempfile.mkdtemp(prefix="kl1-selftest-")) / "kl1"
    failures = []

    def check(name, cond):
        print(f"[SELFTEST] {name}: {'ok' if cond else 'FAIL'}", flush=True)
        if not cond:
            failures.append(name)

    def run_mode(mode):
        fake = FakeKlaviyo(mode)
        run = Run(f"selftest-{mode}")
        ro, full = resolve_keys(fake, FakeKlaviyo.RO, FakeKlaviyo.FULL,
                                f"st{mode[:4]}", run)
        return fake, run, ro, full

    rid = "st0001"
    # guard paths
    check("guard rejects empty keys", not keys_ready("", ""))
    check("guard rejects identical keys", not keys_ready("a", "a"))
    fake = FakeKlaviyo("both_full")
    run = Run("selftest-bothfull")
    ro, full = resolve_keys(fake, FakeKlaviyo.RO, FakeKlaviyo.FULL,
                            "stbf01", run)
    check("both-full keys abort discrimination", full is None)

    # documented mode: everything holds
    fake, run, ro, full = run_mode("documented")
    check("documented: keys resolved", bool(full))
    seed = seed_profiles(fake, full, rid, run)
    check("documented: seed ok", seed is not None)
    ag_legs(fake, ro, full, run, seed)
    id_legs(fake, full, rid, run, seed)
    v = run.verdicts
    check("documented: ID1 lands",
          v["KL1-ID1-EMAIL-WRITE"]["verdict"] == "LANDS")
    check("documented: ID2 as-documented",
          v["KL1-ID2-PRECEDENCE"]["verdict"] == "AS-DOCUMENTED")
    check("documented: ID3 as-documented",
          v["KL1-ID3-PRECEDENCE"]["verdict"] == "AS-DOCUMENTED")
    check("documented: ID4 held",
          v["KL1-ID4-REBIND"]["verdict"] == "HELD")
    check("documented: precedence overall as-documented",
          v["KL1-ID-PRECEDENCE"]["verdict"] == "AS-DOCUMENTED")
    check("documented: agent create not api-reachable",
          v["KL1-AGENT-CREATE"]["verdict"] == "NOT-API-REACHABLE")

    # phone_anchor mode: ID-3 write rides the phone onto V (observation,
    # NOT scored a precedence violation — see note in id_legs)
    fake, run, ro, full = run_mode("phone_anchor")
    seed = seed_profiles(fake, full, rid, run)
    id_legs(fake, full, rid, run, seed)
    v = run.verdicts
    check("phone_anchor: ID3 phone-anchored",
          v["KL1-ID3-PRECEDENCE"]["verdict"] == "PHONE-ANCHORED")

    # plan_gated mode
    fake, run, ro, full = run_mode("plan_gated")
    seed = seed_profiles(fake, full, rid, run)
    ag_legs(fake, ro, full, run, seed)
    check("plan_gated: create plan-gated",
          run.verdicts["KL1-AGENT-CREATE"]["verdict"] == "PLAN-GATED")

    # creatable mode: bind once holds, RO scope holds
    fake, run, ro, full = run_mode("creatable")
    seed = seed_profiles(fake, full, rid, run)
    ag_legs(fake, ro, full, run, seed)
    v = run.verdicts
    check("creatable: create reachable",
          v["KL1-AGENT-CREATE"]["verdict"] == "REACHABLE")
    check("creatable: bind bound",
          v["KL1-AGENT-BIND"]["verdict"] == "BOUND")
    check("creatable: rebind held",
          v["KL1-AGENT-REBIND"]["verdict"] == "HELD")
    check("creatable: RO scope held",
          v["KL1-AGENT-RO-SCOPE"]["verdict"] == "HELD")

    # rebind_ok mode: the add-once invariant breaks
    fake, run, ro, full = run_mode("rebind_ok")
    seed = seed_profiles(fake, full, rid, run)
    ag_legs(fake, ro, full, run, seed)
    check("rebind_ok: rebind accepted detected",
          run.verdicts["KL1-AGENT-REBIND"]["verdict"] ==
          "REBIND-ACCEPTED")

    # scrub: planted key material must vanish
    victim = OUT_DIR / "scrub-probe.txt"
    victim.parent.mkdir(parents=True, exist_ok=True)
    victim.write_text(f"leak {FakeKlaviyo.FULL} and pk_deadbeef here",
                      encoding="utf-8")
    scrub_tree(OUT_DIR, [FakeKlaviyo.FULL, FakeKlaviyo.RO])
    text = victim.read_text(encoding="utf-8")
    check("scrub removes key material",
          FakeKlaviyo.FULL not in text and "pk_" not in text)

    print(f"[SELFTEST] {'ALL OK' if not failures else 'FAILURES: ' + str(failures)}",
          flush=True)
    return 0 if not failures else 1

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main_live())
