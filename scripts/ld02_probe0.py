#!/usr/bin/env python3
"""ld02_probe0.py — LD-02 probe 0: the /internal access-check credential question.

Source-backed shape (work/rea slice common-accesscheck__s00.js, verbatim): the SPA
evaluates UI permissions via
    POST /internal/authorization/access-check/{service}/bulk
    header: Authorization: document.cookie        <- credential is a client parameter
    body:   [{action, resource}, ...]             (batch <= 25)
    service = "gonfalon"
(/internal lives on the app host, NOT under /api/v2.)

Probe: send the same call shape with, as the Authorization credential,
  (a) nothing (transport control), (b) a garbage credential,
  (c) LD_PAT_A_ADMIN, (d) LD_PAT_A_READER, (e) LD_PAT_B,
plus (f) A_ADMIN against a bogus {service} name (service-param validation).
If the endpoint RETURNS per-check verdicts for PAT-class credentials, it is
evaluating whatever credential it is handed on an internal session surface —
the credential-oracle / class-substitution form from candidates.md LD-02.
If every non-cookie credential is refused, that is the verdict and we stop.

Verdict words: PASS = endpoint evaluated a PAT (oracle surface live);
HELD = refused all PATs; ERROR = surface unreachable / shape unreadable.
Stdout: redacted summaries + booleans only. Full responses -> outputs/.
Assumed shapes (flagged): checks are {action, resource} objects with LD policy
resource strings (proj/<key>:env/<key>:flag/<key>); the verdict field name in
the response is unknown — the parser accepts any of allowed/authorized/effect/
allow and otherwise saves the raw shape for manual reading.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

APP = "https://app.launchdarkly.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
OUTDIR = os.path.join(os.getcwd(), "outputs")
os.makedirs(OUTDIR, exist_ok=True)

RESULTS = []

CHECKS = [
    {"action": "updateFlag", "resource": "proj/ld-p1:env/test:flag/marker-flag-1"},
    {"action": "updateProject", "resource": "proj/ld-p1"},
    {"action": "bogusActionXYZ", "resource": "proj/ld-p1"},  # shape discriminator
]
VERDICT_KEYS = ("allowed", "authorized", "allow", "effect", "decision")


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


def call_internal(service, credential, tag):
    url = f"{APP}/internal/authorization/access-check/{service}/bulk"
    headers = {"User-Agent": UA, "Accept": "application/json",
               "Content-Type": "application/json"}
    if credential:
        headers["Authorization"] = credential
    data = json.dumps(CHECKS).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:
        save(f"ld02-{tag}.raw.txt", f"TRANSPORT: {type(e).__name__}: {e}")
        return -1, None, ""
    save(f"ld02-{tag}.raw.json", raw)
    return status, _tryjson(raw), raw


def extract_verdicts(obj):
    """Return list of (action, verdict-bool-or-str) if the response carries
    per-check verdicts in any plausible shape; else None."""
    entries = None
    if isinstance(obj, list):
        entries = obj
    elif isinstance(obj, dict):
        for k in ("items", "results", "checks", "data"):
            if isinstance(obj.get(k), list):
                entries = obj[k]
                break
    if not entries:
        return None
    out = []
    for e in entries:
        if not isinstance(e, dict):
            return None
        hit = None
        for k in VERDICT_KEYS:
            if k in e:
                hit = e[k]
                break
        if hit is None:
            return None
        out.append((e.get("action"), hit))
    return out


def classify(status, obj):
    if status == -1:
        return "TRANSPORT"
    if status in (401, 403):
        return "REFUSED"
    verdicts = extract_verdicts(obj)
    if verdicts is not None:
        return "EVALUATED"
    return "OTHER"


def main():
    pat_a = os.environ.get("LD_PAT_A_ADMIN", "").strip()
    pat_b = os.environ.get("LD_PAT_B", "").strip()
    pat_r = os.environ.get("LD_PAT_A_READER", "").strip()
    print(f"START ld02_probe0 pats: A_ADMIN={'set' if pat_a else 'MISSING'} "
          f"B={'set' if pat_b else 'MISSING'} A_READER={'set' if pat_r else 'MISSING'}",
          flush=True)
    if not (pat_a and pat_b and pat_r):
        note("env", "ERROR", "one or more LD_PAT_* missing")
        print("DONE ld02_probe0 cases: 0 PASS, 0 HELD, 1 ERROR")
        return

    runs = [
        ("noauth", None),
        ("garbage", "api-00000000-dead-beef-dead-beefdeadbeef"),
        ("a-admin", pat_a),
        ("a-reader", pat_r),
        ("b-writer", pat_b),
    ]
    outcomes = {}
    evaluated_detail = {}
    for tag, cred in runs:
        st, obj, _raw = call_internal("gonfalon", cred, tag)
        cls = classify(st, obj)
        outcomes[tag] = (st, cls)
        detail = f"status={st} class={cls}"
        if cls == "EVALUATED":
            evaluated_detail[tag] = extract_verdicts(obj)
            # Print booleans only — which checks each credential passed.
            detail += " verdicts=" + ",".join(
                f"{a}:{v}" for a, v in evaluated_detail[tag])
        note(f"accesscheck-{tag}", "INFO", detail)
        time.sleep(0.3)

    # (f) service-name validation with the strongest credential
    st, obj, _raw = call_internal("bogussvc", pat_a, "bogus-service")
    cls = classify(st, obj)
    note("accesscheck-bogus-service", "INFO", f"status={st} class={cls}")

    pat_classes = [outcomes[t][1] for t in ("a-admin", "a-reader", "b-writer")]
    if all(c == "OTHER" and outcomes[t][0] == outcomes["noauth"][0]
           for t, c in zip(("a-admin", "a-reader", "b-writer"), pat_classes)) \
            and outcomes["noauth"][1] in ("OTHER",):
        note("probe0-verdict", "ERROR",
             "all requests (incl. no-auth) returned the same non-auth shape; "
             "/internal is not API-reachable from this lane — see raw files")
    elif any(c == "EVALUATED" for c in pat_classes):
        who = [t for t in ("a-admin", "a-reader", "b-writer") if outcomes[t][1] == "EVALUATED"]
        contrast = ""
        if "a-admin" in evaluated_detail and "a-reader" in evaluated_detail:
            adm = dict(evaluated_detail["a-admin"])
            rdr = dict(evaluated_detail["a-reader"])
            diffs = [a for a in adm if a in rdr and str(adm[a]) != str(rdr[a])]
            contrast = (f"; admin-vs-reader verdicts differ on {diffs} "
                        "(endpoint faithfully evaluates each credential's authority)"
                        if diffs else "; admin/reader verdicts identical")
        note("probe0-verdict", "PASS",
             f"/internal access-check EVALUATED PAT credentials: {who}{contrast}")
    elif all(c == "REFUSED" for c in pat_classes):
        note("probe0-verdict", "HELD",
             "endpoint refused every PAT-class credential (session-only surface)")
    else:
        note("probe0-verdict", "ERROR",
             f"mixed/unreadable classes {pat_classes}; raw shapes saved for manual reading")

    p = sum(1 for _, v, _ in RESULTS if v == "PASS")
    h = sum(1 for _, v, _ in RESULTS if v == "HELD")
    e = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    print(f"DONE ld02_probe0 cases: {p} PASS, {h} HELD, {e} ERROR")


if __name__ == "__main__":
    main()
    sys.exit(0)
