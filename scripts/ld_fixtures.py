#!/usr/bin/env python3
"""ld_fixtures.py — LaunchDarkly dynamic phase, fixture setup (runs in moka-harness Actions).

Response-shape-first (per skill): the FIRST call is GET /api/v2/members/me with the
admin PAT; its raw response and a structure-only shape are saved under outputs/
before anything else is built on top of it.

Does, in order:
  1. GET /members/me (LD_PAT_A_ADMIN) -> shape capture; A's member id.
  2. GET /tokens -> hunt the stray token api-f04a9605-d25a-4eef-8cee-4e2d81213a12
     (match if any field of a token item contains the hex fragment f04a9605);
     DELETE it if found and deletable by its _id. Not listable / not found -> note, move on.
  3. Ensure projects ld-p1 and ld-p2 exist (list first; create only if missing).
  4. Ensure boolean marker flag marker-flag-1 exists in ld-p1.
  5. GET /members (admin view) + GET /members/me with LD_PAT_B (ground truth for B)
     -> B's member id, current base role, custom roles -> outputs/fixtures.json.

Secrets come from env only (LD_PAT_A_ADMIN required, LD_PAT_B optional-but-expected).
Stdout prints ONLY redacted summaries; full responses go to outputs/ artifacts.
Verdict words: PASS = step did what it should, HELD = n/a here, ERROR = transport/shape failure.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://app.launchdarkly.com/api/v2"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
OUTDIR = os.path.join(os.getcwd(), "outputs")
os.makedirs(OUTDIR, exist_ok=True)

STRAY_FRAGMENT = "f04a9605"  # stray token api-f04a9605-d25a-4eef-8cee-4e2d81213a12

RESULTS = []  # (case, verdict, detail)


def note(case, verdict, detail=""):
    RESULTS.append((case, verdict, detail))
    print(f"CASE {case}: {verdict}" + (f" ({detail})" if detail else ""), flush=True)


def save(name, payload):
    path = os.path.join(OUTDIR, name)
    with open(path, "w") as f:
        if isinstance(payload, str):
            f.write(payload)
        else:
            json.dump(payload, f, indent=2, default=str)


def shape_of(obj):
    """Structure-only copy: field names, nesting, types, string lengths. No values."""
    if isinstance(obj, dict):
        return {k: shape_of(v) for k, v in list(obj.items())[:60]}
    if isinstance(obj, list):
        return [shape_of(obj[0])] if obj else []
    if isinstance(obj, str):
        return f"str(len={len(obj)})"
    if isinstance(obj, bool):
        return "bool"
    if obj is None:
        return "null"
    return type(obj).__name__


def _tryjson(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None


def call(method, url, token=None, body=None):
    """One HTTP call. Returns (status, parsed_json_or_None, raw_text). 429 -> one retry."""
    for attempt in (0, 1):
        headers = {"User-Agent": UA, "Accept": "application/json"}
        data = None
        if token:
            headers["Authorization"] = token
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read().decode("utf-8", "replace")
                return r.status, _tryjson(raw), raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            if e.code == 429 and attempt == 0:
                time.sleep(10)
                continue
            return e.code, _tryjson(raw), raw
        except Exception as e:  # transport failure is NOT a permission verdict
            return -1, None, f"TRANSPORT: {type(e).__name__}: {e}"
    return -1, None, "TRANSPORT: retry exhausted"


def items_of(obj):
    """LD list endpoints wrap results in {'items': [...]}. Fail loudly if absent."""
    if isinstance(obj, dict) and isinstance(obj.get("items"), list):
        return obj["items"]
    return None


def redact_email(em):
    if not em or "@" not in em:
        return "?"
    local, dom = em.split("@", 1)
    return f"{local[:3]}***@{dom}"


def main():
    pat_a = os.environ.get("LD_PAT_A_ADMIN", "").strip()
    pat_b = os.environ.get("LD_PAT_B", "").strip()
    print(f"START ld_fixtures pats: A_ADMIN={'set' if pat_a else 'MISSING'}"
          f"(len={len(pat_a)}) B={'set' if pat_b else 'MISSING'}(len={len(pat_b)})", flush=True)
    if not pat_a:
        note("env", "ERROR", "LD_PAT_A_ADMIN missing")
        print("DONE ld_fixtures cases: 0 PASS, 0 HELD, 1 ERROR")
        return

    fixtures = {}

    # --- 1. Shape capture: GET /members/me with the admin PAT -------------------
    st, me, raw = call("GET", f"{API}/members/me", pat_a)
    save("shape-members-me-a.raw.json", raw if st != -1 else {"transport": raw})
    if isinstance(me, dict):
        save("shape-members-me-a.shape.json", shape_of(me))
    if st != 200 or not isinstance(me, dict) or "_id" not in me:
        note("shape-members-me", "ERROR", f"status={st}; see outputs/shape-members-me-a.raw.json")
        print("DONE ld_fixtures cases: 0 PASS, 0 HELD, 1 ERROR")
        return
    note("shape-members-me", "PASS", f"status=200 role={me.get('role')!r}")
    a_id = me["_id"]
    fixtures["a_member_id"] = a_id
    fixtures["a_role"] = me.get("role")

    # --- 2. Stray token hunt ----------------------------------------------------
    st, toks, raw = call("GET", f"{API}/tokens", pat_a)
    save("tokens-list.raw.json", raw if st != -1 else {"transport": raw})
    stray = "not_listable"
    if st == 200:
        items = items_of(toks)
        if items is None:
            stray = "list_shape_unknown"
            note("stray-token", "ERROR", "tokens list has no items[]; shape saved")
        else:
            hit = None
            for it in items:
                if isinstance(it, dict) and STRAY_FRAGMENT in json.dumps(it):
                    hit = it
                    break
            if hit is None:
                stray = "not_found"
                note("stray-token", "PASS", f"no item matches fragment among {len(items)} tokens")
            else:
                tid = hit.get("_id")
                if not tid:
                    stray = "matched_but_no_id"
                    note("stray-token", "ERROR", "fragment matched an item without _id; not deleted")
                else:
                    dst, _, draw = call("DELETE", f"{API}/tokens/{tid}", pat_a)
                    save("tokens-delete-stray.raw.json", draw)
                    if dst in (200, 204):
                        stray = "deleted"
                        note("stray-token", "PASS", f"deleted token _id suffix ...{str(tid)[-6:]}")
                    else:
                        stray = f"delete_failed_{dst}"
                        note("stray-token", "ERROR", f"DELETE returned {dst}; see raw")
    else:
        note("stray-token", "ERROR", f"GET /tokens status={st}; stray hunt skipped")
    fixtures["stray_token"] = stray

    # --- 3. Projects (idempotent) ------------------------------------------------
    st, projs, raw = call("GET", f"{API}/projects", pat_a)
    save("projects-list-a.raw.json", raw if st != -1 else {"transport": raw})
    existing = set()
    if st == 200:
        items = items_of(projs)
        if items is not None:
            existing = {p.get("key") for p in items if isinstance(p, dict)}
    for key, name in (("ld-p1", "LD P1"), ("ld-p2", "LD P2")):
        if key in existing:
            note(f"project-{key}", "PASS", "already exists, skipped")
            continue
        cst, _, craw = call("POST", f"{API}/projects", pat_a, {"key": key, "name": name})
        save(f"project-create-{key}.raw.json", craw)
        if cst in (200, 201):
            note(f"project-{key}", "PASS", f"created status={cst}")
        elif cst == 409:
            note(f"project-{key}", "PASS", "409 on create = already exists")
        else:
            note(f"project-{key}", "ERROR", f"create status={cst}; see raw")
    fixtures["projects"] = ["ld-p1", "ld-p2"]

    # --- 4. Marker flag in ld-p1 --------------------------------------------------
    st, flags, raw = call("GET", f"{API}/flags/ld-p1", pat_a)
    save("flags-list-ld-p1.raw.json", raw if st != -1 else {"transport": raw})
    flag_keys = set()
    if st == 200:
        items = items_of(flags)
        if items is not None:
            flag_keys = {f.get("key") for f in items if isinstance(f, dict)}
    if "marker-flag-1" in flag_keys:
        note("flag-marker-flag-1", "PASS", "already exists, skipped")
    else:
        body = {
            "key": "marker-flag-1",
            "name": "Marker Flag 1",
            "kind": "boolean",
            "description": "LD battery marker flag (ld_fixtures)",
            "variations": [{"value": True, "name": "true"}, {"value": False, "name": "false"}],
        }
        cst, _, craw = call("POST", f"{API}/flags/ld-p1", pat_a, body)
        save("flag-create-marker-flag-1.raw.json", craw)
        if cst in (200, 201):
            note("flag-marker-flag-1", "PASS", f"created status={cst}")
        elif cst == 409:
            note("flag-marker-flag-1", "PASS", "409 on create = already exists")
        else:
            note("flag-marker-flag-1", "ERROR", f"create status={cst}; see raw")
    fixtures["flags_ld_p1"] = ["marker-flag-1"]

    # --- 5. Members: B's identity + current role ----------------------------------
    st, members, raw = call("GET", f"{API}/members", pat_a)
    save("members-list-a.raw.json", raw if st != -1 else {"transport": raw})
    member_items = items_of(members) if st == 200 else None
    if member_items is None:
        note("members-list", "ERROR", f"status={st} or no items[]; B lookup degraded")

    b_id = b_email = b_role = None
    b_custom = None
    if pat_b:
        bst, bme, braw = call("GET", f"{API}/members/me", pat_b)
        save("shape-members-me-b.raw.json", braw if bst != -1 else {"transport": braw})
        if bst == 200 and isinstance(bme, dict) and "_id" in bme:
            b_id = bme["_id"]
            b_email = bme.get("email")
            note("members-me-b", "PASS", f"B self-view role={bme.get('role')!r}")
        else:
            note("members-me-b", "ERROR", f"status={bst}; see raw")
    if b_id and member_items is not None:
        for m in member_items:
            if isinstance(m, dict) and m.get("_id") == b_id:
                b_role = m.get("role")
                b_custom = m.get("customRoles")
                if not b_email:
                    b_email = m.get("email")
                break
        if b_role is None:
            note("member-b-in-list", "ERROR", "B's _id not found in A's member list")
        else:
            note("member-b-in-list", "PASS",
                 f"B role (admin view)={b_role!r} customRoles={len(b_custom or [])}")
    fixtures["b_member_id"] = b_id
    fixtures["b_email"] = b_email
    fixtures["b_role_current"] = b_role
    fixtures["b_custom_roles"] = b_custom
    fixtures["member_count_admin_view"] = len(member_items) if member_items is not None else None
    save("fixtures.json", fixtures)
    print(f"INFO fixtures: B={redact_email(b_email)} role={b_role!r} stray={stray}", flush=True)

    p = sum(1 for _, v, _ in RESULTS if v == "PASS")
    e = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    print(f"DONE ld_fixtures cases: {p} PASS, 0 HELD, {e} ERROR")


if __name__ == "__main__":
    main()
    sys.exit(0)
