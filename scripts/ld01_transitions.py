#!/usr/bin/env python3
"""ld01_transitions.py — LD-01: personal-token lifecycle enforcement battery.

Question (candidates.md LD-01): docs promise a personal token follows its creator's
CURRENT authority and is deactivated on member removal. Measure enforcement on
FRESH requests after each lifecycle transition, applied by admin A to member B,
probing with B's own PAT (LD_PAT_B).

Transitions:
  T1 downgrade          A: PATCH member role writer -> reader
  T2 role removal       if B holds custom roles: A clears /customRoles;
                        else: A sets base role -> "no_access" (strongest removal
                        the API offers; ERROR-plan if the plan rejects it)
  T3 member removal     A: DELETE member; then re-invite (restore) via POST /members
Between transitions B is restored to Writer and the restore is VERIFIED by a
successful B write, so each transition starts from the same baseline.

Probe verbs (chosen at baseline, control-first):
  write = PATCH /flags/ld-p1/marker-flag-1 description (JSON Patch).
          If B-as-Writer cannot do it, fall back to POST create of a probe flag.
  read  = GET /flags/ld-p1/marker-flag-1
Control: LD_PAT_A_READER (a reader-scoped token of admin A) must FAIL the write
verb while B-as-Writer succeeds; if the control cannot discriminate, the battery
reports ERROR instead of verdicts.

After each transition: probe immediately AND after a 10 s delay.
Grade per transition: HELD-immediate / PASS-lagged (first probe succeeds, delayed
fails) / PASS-absent (both succeed). PASS = the lost authority survived = finding.
Stdout: redacted summaries only. Full responses -> outputs/ artifacts.
Assumed shapes (flagged): member PATCH uses JSON Patch [{op,path,value}] with
paths /role and /customRoles; flag PATCH likewise on /description. Raw error
bodies are saved so a wrong assumption surfaces as ERROR with the vendor's shape.
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


def _tryjson(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None


def call(method, url, token=None, body=None):
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
        except Exception as e:
            return -1, None, f"TRANSPORT: {type(e).__name__}: {e}"
    return -1, None, "TRANSPORT: retry exhausted"


def is2xx(st):
    return 200 <= st < 300


class Probes:
    """B's write/read probes with a fixed verb chosen at baseline."""

    def __init__(self, pat_b):
        self.pat_b = pat_b
        self.mode = None  # "patch" or "create"
        self.counter = 0

    def write(self, tag):
        self.counter += 1
        if self.mode == "create":
            key = f"ld01-probe-{int(time.time())}-{self.counter}"
            st, _, raw = call("POST", f"{API}/flags/ld-p1", self.pat_b,
                              {"key": key, "name": f"LD01 probe {tag}",
                               "kind": "boolean",
                               "variations": [{"value": True}, {"value": False}]})
            save(f"ld01-{tag}-write.raw.json", raw)
            return st, key
        body = [{"op": "replace", "path": "/description",
                 "value": f"ld01 probe {tag} {int(time.time())}"}]
        st, _, raw = call("PATCH", f"{API}/flags/ld-p1/marker-flag-1", self.pat_b, body)
        save(f"ld01-{tag}-write.raw.json", raw)
        return st, None

    def read(self, tag):
        st, obj, raw = call("GET", f"{API}/flags/ld-p1/marker-flag-1", self.pat_b)
        save(f"ld01-{tag}-read.raw.json", raw)
        return st


def member_patch(pat_a, b_id, ops, tag):
    st, obj, raw = call("PATCH", f"{API}/members/{b_id}", pat_a, ops)
    save(f"ld01-{tag}-memberpatch.raw.json", raw)
    return st, obj


def grade_transition(name, w0, w10):
    """w0/w10: write-probe success booleans, immediate and after 10 s."""
    if w0 and w10:
        return "PASS-absent"
    if w0 and not w10:
        return "PASS-lagged"
    if not w0 and not w10:
        return "HELD-immediate"
    return "ERROR"  # failed first, succeeded later: incoherent, inspect raw


def main():
    pat_a = os.environ.get("LD_PAT_A_ADMIN", "").strip()
    pat_b = os.environ.get("LD_PAT_B", "").strip()
    pat_r = os.environ.get("LD_PAT_A_READER", "").strip()
    print(f"START ld01 pats: A_ADMIN={'set' if pat_a else 'MISSING'} "
          f"B={'set' if pat_b else 'MISSING'} A_READER={'set' if pat_r else 'MISSING'}",
          flush=True)
    if not (pat_a and pat_b and pat_r):
        note("env", "ERROR", "one or more LD_PAT_* missing")
        print("DONE ld01 cases: 0 PASS, 0 HELD, 1 ERROR")
        return

    # --- Identity + shape capture ------------------------------------------------
    st, bme, raw = call("GET", f"{API}/members/me", pat_b)
    save("ld01-members-me-b.raw.json", raw)
    if st != 200 or not isinstance(bme, dict) or "_id" not in bme:
        note("identity-b", "ERROR", f"GET /members/me with B status={st}")
        print("DONE ld01 cases: 0 PASS, 0 HELD, 1 ERROR")
        return
    b_id, b_email = bme["_id"], bme.get("email")
    note("identity-b", "PASS", f"B self-view role={bme.get('role')!r}")

    st, bview, raw = call("GET", f"{API}/members/{b_id}", pat_a)
    save("ld01-member-b-adminview.raw.json", raw)
    if st == 200 and isinstance(bview, dict):
        b_custom0 = bview.get("customRoles") or []
        note("identity-b-adminview", "PASS",
             f"role={bview.get('role')!r} customRoles={len(b_custom0)}")
    else:
        b_custom0 = []
        note("identity-b-adminview", "ERROR", f"status={st}; continuing with customRoles=[]")

    # Response-shape-first captures: B listing projects (expect 200) + reader contrast.
    st, obj, raw = call("GET", f"{API}/projects", pat_b)
    save("ld01-projects-b.raw.json", raw)
    note("shape-projects-b", "PASS" if st == 200 else "ERROR", f"status={st}")
    st, obj, raw = call("GET", f"{API}/projects", pat_r)
    save("ld01-projects-areader.raw.json", raw)
    note("shape-projects-areader", "PASS" if st == 200 else "ERROR", f"status={st}")

    probes = Probes(pat_b)

    # --- Baseline: choose the write verb; control must discriminate ---------------
    wst, _, wraw = call("PATCH", f"{API}/flags/ld-p1/marker-flag-1", pat_b,
                        [{"op": "replace", "path": "/description", "value": "ld01 baseline"}])
    save("ld01-baseline-writepatch.raw.json", wraw)
    if is2xx(wst):
        probes.mode = "patch"
    else:
        probes.mode = "create"
    wst2, probe_key = probes.write("baseline")
    if not is2xx(wst2):
        note("baseline-write", "ERROR",
             f"B-as-Writer write failed via mode={probes.mode} status={wst2}; battery invalid")
        print("DONE ld01 cases: 0 PASS, 0 HELD, 1 ERROR")
        return
    note("baseline-write", "PASS", f"mode={probes.mode} status={wst2}")
    if probe_key:  # cleanup the baseline probe flag with admin rights
        call("DELETE", f"{API}/flags/ld-p1/{probe_key}", pat_a)

    # Control: reader-scoped token must FAIL the same write verb.
    if probes.mode == "patch":
        cst, _, craw = call("PATCH", f"{API}/flags/ld-p1/marker-flag-1", pat_r,
                            [{"op": "replace", "path": "/description", "value": "ld01 control"}])
    else:
        cst, _, craw = call("POST", f"{API}/flags/ld-p1", pat_r,
                            {"key": f"ld01-control-{int(time.time())}", "name": "LD01 control",
                             "kind": "boolean", "variations": [{"value": True}, {"value": False}]})
    save("ld01-control-areader-write.raw.json", craw)
    if is2xx(cst):
        note("control-areader-write", "ERROR",
             f"reader-scoped token SUCCEEDED at the write verb (status={cst}); probe cannot discriminate")
        print("DONE ld01 cases: 0 PASS, 0 HELD, 1 ERROR")
        return
    note("control-areader-write", "HELD", f"reader token refused write status={cst} (control valid)")

    rst = probes.read("baseline")
    note("baseline-read", "PASS" if is2xx(rst) else "ERROR", f"status={rst}")

    def probe_pair(tag):
        w, key = probes.write(tag)
        if key:
            call("DELETE", f"{API}/flags/ld-p1/{key}", pat_a)
        r = probes.read(tag)
        return is2xx(w), w, r

    def restore_writer(tag, custom=None):
        ops = [{"op": "replace", "path": "/role", "value": "writer"}]
        if custom is not None:
            ops.append({"op": "replace", "path": "/customRoles", "value": custom})
        st, _ = member_patch(pat_a, b_id, ops, f"{tag}-restore")
        ok, w, _r = probe_pair(f"{tag}-restorecheck")
        note(f"{tag}-restore", "PASS" if (is2xx(st) and ok) else "ERROR",
             f"patch status={st} write-after-restore status={w}")
        return ok

    # --- T1: downgrade Writer -> Reader -------------------------------------------
    st, _ = member_patch(pat_a, b_id, [{"op": "replace", "path": "/role", "value": "reader"}], "t1")
    if not is2xx(st):
        note("T1-downgrade", "ERROR", f"role patch status={st}; see raw")
    else:
        w0, ws0, rs0 = probe_pair("t1-imm")
        time.sleep(10)
        w10, ws10, rs10 = probe_pair("t1-delay")
        g = grade_transition("T1", w0, w10)
        note("T1-downgrade", g,
             f"write imm={ws0} delay={ws10}; read imm={rs0} delay={rs10}")
        restore_writer("t1")

    # --- T2: role removal -----------------------------------------------------------
    st, bnow, raw = call("GET", f"{API}/members/{b_id}", pat_a)
    save("ld01-t2-member-before.raw.json", raw)
    customs = (bnow.get("customRoles") or []) if isinstance(bnow, dict) else []
    if customs:
        st, _ = member_patch(pat_a, b_id,
                             [{"op": "replace", "path": "/customRoles", "value": []}], "t2")
        if not is2xx(st):
            note("T2-customrole-removal", "ERROR", f"patch status={st}; see raw")
        else:
            w0, ws0, rs0 = probe_pair("t2-imm")
            time.sleep(10)
            w10, ws10, rs10 = probe_pair("t2-delay")
            g = grade_transition("T2", w0, w10)
            note("T2-customrole-removal", g,
                 f"had {len(customs)} custom roles; write imm={ws0} delay={ws10}; read imm={rs0} delay={rs10}")
        restore_writer("t2", custom=customs)
    else:
        st, _ = member_patch(pat_a, b_id,
                             [{"op": "replace", "path": "/role", "value": "no_access"}], "t2")
        if not is2xx(st):
            note("T2-role-removal", "ERROR",
                 f"no_access patch status={st} (plan may lack no_access); see raw")
            restore_writer("t2")
        else:
            w0, ws0, rs0 = probe_pair("t2-imm")
            time.sleep(10)
            w10, ws10, rs10 = probe_pair("t2-delay")
            g = grade_transition("T2", w0, w10)
            note("T2-role-removal-noaccess", g,
                 f"write imm={ws0} delay={ws10}; read imm={rs0} delay={rs10} (reads should also die)")
            restore_writer("t2")

    # --- T3: member removal ---------------------------------------------------------
    st, _, raw = call("DELETE", f"{API}/members/{b_id}", pat_a)
    save("ld01-t3-delete.raw.json", raw)
    if not is2xx(st):
        note("T3-removal", "ERROR", f"DELETE member status={st}; see raw")
    else:
        w0, ws0, rs0 = probe_pair("t3-imm")
        time.sleep(10)
        w10, ws10, rs10 = probe_pair("t3-delay")
        g = grade_transition("T3", w0, w10)
        note("T3-removal", g,
             f"write imm={ws0} delay={ws10}; read imm={rs0} delay={rs10} (docs: token deactivated)")
        # Restore: re-invite. A fresh membership requires B to accept in a browser;
        # the OLD PAT is expected to stay dead either way (documented deactivation).
        if b_email:
            ist, _, iraw = call("POST", f"{API}/members", pat_a,
                                {"email": b_email, "role": "writer"})
            save("ld01-t3-reinvite.raw.json", iraw)
            if is2xx(ist):
                note("T3-restore", "PASS",
                     f"re-invite sent status={ist}; MANUAL step remains: B must accept the invite")
            else:
                note("T3-restore", "ERROR",
                     f"re-invite status={ist}; MANUAL restore of B's membership needed")
        else:
            note("T3-restore", "ERROR", "B email unknown; MANUAL restore needed")

    p = sum(1 for _, v, _ in RESULTS if v.startswith("PASS"))
    h = sum(1 for _, v, _ in RESULTS if v.startswith("HELD"))
    e = sum(1 for _, v, _ in RESULTS if v.startswith("ERROR"))
    print(f"DONE ld01 cases: {p} PASS, {h} HELD, {e} ERROR")


if __name__ == "__main__":
    main()
    sys.exit(0)
