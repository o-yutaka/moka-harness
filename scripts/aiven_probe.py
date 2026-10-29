#!/usr/bin/env python3
"""Aiven dynamic probe - run 1: baseline mapping (READ-ONLY)."""
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
TOKEN = os.environ.get("AIVEN_TOKEN_1", "")
if not TOKEN:
    print("AIVEN_TOKEN_1 not set", flush=True)
    sys.exit(2)

OUT = []
os.makedirs("outputs", exist_ok=True)


def call(method, path):
    req = urllib.request.Request(
        BASE + path,
        method=method,
        headers={"Authorization": f"aivenv1 {TOKEN}",
                 "Content-Type": "application/json"},
    )
    status = 0
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read()
        status = e.code
    except Exception as e:
        OUT.append({"method": method, "path": path, "error": str(e)[:120]})
        print(f"{method} {path} -> ERROR {e}", flush=True)
        return None, 0
    OUT.append({"method": method, "path": path, "status": status,
                "len": len(body),
                "sha256": hashlib.sha256(body).hexdigest()[:16]})
    print(f"{method} {path} -> {status} ({len(body)}B)", flush=True)
    try:
        return json.loads(body), status
    except Exception:
        return None, status


def main():
    me, _ = call("GET", "/me")
    orgs, _ = call("GET", "/organization")
    accts, _ = call("GET", "/account")
    call("GET", "/project")

    account_ids = []
    if isinstance(accts, dict):
        for a in accts.get("accounts", []) or []:
            if a.get("account_id"):
                account_ids.append(a["account_id"])
    for aid in account_ids:
        for suffix in ["", "/teams", "/billing-group", "/payment_methods",
                       "/projects", "/events", "/authentication"]:
            call("GET", f"/account/{aid}{suffix}")
    org_ids = []
    if isinstance(orgs, dict):
        for o in orgs.get("organizations", []) or []:
            if o.get("id"):
                org_ids.append(o["id"])
    for oid in org_ids:
        call("GET", f"/organization/{oid}")
        call("GET", f"/organization/{oid}/projects")
        call("GET", f"/organization/{oid}/user")

    with open("outputs/aiven_probe_run1.json", "w") as f:
        json.dump({"me": me, "account_ids": account_ids,
                   "org_ids": org_ids, "calls": OUT}, f, indent=1)
    print(f"DONE calls={len(OUT)}", flush=True)


if __name__ == "__main__":
    main()
