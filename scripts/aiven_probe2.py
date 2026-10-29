#!/usr/bin/env python3
"""Aiven dynamic probe - run 2: cross-tenant boundary matrix (own test accounts only)."""
import json
import os
import re
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
ADMIN = "https://admin-api.aiven.io:4343"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
T2 = os.environ.get("AIVEN_TOKEN_2", "")
if not T1 or not T2:
    print("tokens missing", flush=True)
    sys.exit(2)

A1, A2 = "a5eea5b45dff", "a5eea797c7ff"
P1, P2 = "bugcrowdninja-b1ee", "bugcrowdninja-631c"
os.makedirs("outputs", exist_ok=True)
CALLS = []


def raw(url, token, scheme="aivenv1"):
    req = urllib.request.Request(
        url, method="GET",
        headers={"Authorization": f"{scheme} {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERROR {e}"[:200]


def call(who, token, path, base=BASE, scheme="aivenv1", keep=2000):
    status, body = raw(base + path, token, scheme)
    CALLS.append({"who": who, "path": path, "status": status,
                  "len": len(body), "body": body[:keep]})
    print(f"{who} GET {path} -> {status} ({len(body)}B)", flush=True)
    return status, body


def org_ids_from(*texts):
    found = []
    for t in texts:
        for m in re.findall(r'"organization_id"\s*:\s*"([^"]+)"', t or ""):
            if m not in found:
                found.append(m)
    return found


def main():
    _, me1 = call("T1", T1, "/me")
    _, ac1 = call("T1", T1, f"/account/{A1}")
    _, me2 = call("T2", T2, "/me")
    _, ac2 = call("T2", T2, f"/account/{A2}")
    orgs1 = org_ids_from(me1, ac1)
    orgs2 = org_ids_from(me2, ac2)
    print(f"org ids: T1={orgs1} T2={orgs2}", flush=True)

    for suffix in ["", "/projects", "/events", "/authentication"]:
        call("T1", T1, f"/account/{A2}{suffix}")
        call("T2", T2, f"/account/{A1}{suffix}")
    call("T1", T1, f"/account/{A2}/project/{P2}/teams")
    call("T2", T2, f"/account/{A1}/project/{P1}/teams")
    call("T1", T1, f"/project/{P2}")
    call("T2", T2, f"/project/{P1}")
    call("T1", T1, f"/project/{P2}/service")
    call("T2", T2, f"/project/{P1}/service")

    for o in orgs2:
        for suffix in ["", "/user", "/projects", "/billing-groups",
                       "/application-users"]:
            call("T1", T1, f"/organization/{o}{suffix}")
    for o in orgs1:
        for suffix in ["", "/user", "/projects", "/billing-groups",
                       "/application-users"]:
            call("T2", T2, f"/organization/{o}{suffix}")

    call("T1", T1, f"/account/{A1}/project/{P1}/teams")
    call("T2", T2, f"/account/{A2}/project/{P2}/teams")

    call("T1", T1, "/v1/billing/groups", base=ADMIN, scheme="aivenv1")
    call("T1", T1, "/v1/billing/groups", base=ADMIN, scheme="Bearer")

    with open("outputs/aiven_probe_run2.json", "w") as f:
        json.dump({"orgs1": orgs1, "orgs2": orgs2,
                   "me1": me1[:2000], "me2": me2[:2000], "calls": CALLS},
                  f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
