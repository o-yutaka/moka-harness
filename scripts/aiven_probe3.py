#!/usr/bin/env python3
"""Aiven dynamic probe - run 3: application-user privilege matrix (own test org only)."""
import json
import os
import re
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
if not T1:
    print("token missing", flush=True)
    sys.exit(2)

A1 = "a5eea5b45dff"
P1 = "bugcrowdninja-b1ee"
os.makedirs("outputs", exist_ok=True)
CALLS = []


def req(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Authorization": f"aivenv1 {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERROR {e}"[:200]


def call(who, method, path, token, body=None, keep=1200):
    status, resp = req(method, path, token, body)
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": resp[:keep]})
    print(f"{who} {method} {path} -> {status} ({len(resp)}B)", flush=True)
    return status, resp


def find_field(text, *names):
    for n in names:
        m = re.search(rf'"{n}"\s*:\s*"([^"]+)"', text or "")
        if m:
            return m.group(1)
    return None


def main():
    _, me = call("T1", "GET", "/me", T1)
    _, ac = call("T1", "GET", f"/account/{A1}", T1)
    org_candidates = []
    for src in (ac, me):
        for m in re.findall(r'"organization_id"\s*:\s*"([^"]+)"', src or ""):
            if m not in org_candidates:
                org_candidates.append(m)
    if A1 not in org_candidates:
        org_candidates.append(A1)
    print(f"org candidates: {org_candidates}", flush=True)

    org = None
    low_uid = ctrl_uid = None
    low_tok = ctrl_tok = None
    for cand in org_candidates:
        s, b = call("T1", "POST", f"/organization/{cand}/application-users",
                    T1, {"name": "moka-lowperm-probe"})
        if s in (200, 201):
            org = cand
            low_uid = find_field(b, "user_id")
            break
    if not org:
        print("could not create app user in any candidate org", flush=True)
        dump()
        return
    print(f"org={org} low_uid={low_uid}", flush=True)

    s, b = call("T1", "POST", f"/organization/{org}/application-users",
                T1, {"name": "moka-superadmin-probe", "is_super_admin": True})
    ctrl_uid = find_field(b, "user_id")
    print(f"ctrl_uid={ctrl_uid}", flush=True)

    def mint(uid):
        s, b = req("POST",
                   f"/organization/{org}/application-users/{uid}/access-tokens",
                   T1, {"description": "moka-run3"})
        tok = find_field(b, "token", "access_token")
        print(f"mint uid={uid} -> {s} token={'yes' if tok else 'NO'}",
              flush=True)
        CALLS.append({"who": "T1", "method": "POST",
                      "path": f"/organization/{org}/application-users/{uid}/access-tokens",
                      "status": s, "len": len(b), "body": "(token redacted)"})
        return tok

    if low_uid:
        low_tok = mint(low_uid)
    if ctrl_uid:
        ctrl_tok = mint(ctrl_uid)

    if low_tok:
        for method, path, body in [
            ("GET", "/me", None),
            ("GET", f"/organization/{org}", None),
            ("GET", f"/organization/{org}/user", None),
            ("GET", f"/organization/{org}/application-users", None),
            ("GET", f"/organization/{org}/billing-groups", None),
            ("GET", f"/project/{P1}", None),
            ("GET", f"/project/{P1}/service", None),
            ("GET", f"/account/{A1}", None),
            ("GET", f"/account/{A1}/projects", None),
            ("GET", f"/account/{A1}/events", None),
            ("GET", f"/account/{A1}/authentication", None),
            ("POST", f"/project/{P1}/service", {}),
        ]:
            call("LOW", method, path, low_tok, body)
        if ctrl_uid:
            call("LOW", "POST",
                 f"/organization/{org}/application-users/{ctrl_uid}/access-tokens",
                 low_tok, {"description": "guardrail-probe"})

    if ctrl_tok:
        for path in [f"/organization/{org}/user", f"/account/{A1}/events",
                     f"/project/{P1}"]:
            call("CTRL", "GET", path, ctrl_tok)

    for uid in (low_uid, ctrl_uid):
        if uid:
            call("T1", "DELETE", f"/organization/{org}/application-users/{uid}",
                 T1)
    dump()


def dump():
    with open("outputs/aiven_probe_run3.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
