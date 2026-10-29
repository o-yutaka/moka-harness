#!/usr/bin/env python3
"""Aiven run 8: AccountMove consent matrix (A4) - own test accounts only."""
import json
import os
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
T2 = os.environ.get("AIVEN_TOKEN_2", "")
if not T1 or not T2:
    print("tokens missing", flush=True)
    sys.exit(2)

A1 = "a5eea5b45dff"
A2 = "a5eea797c7ff"
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


def call(who, method, path, token, body=None, keep=900):
    status, resp = req(method, path, token, body)
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": resp[:keep]})
    print(f"{who} {method} {path} -> {status} ({len(resp)}B)", flush=True)
    return status, resp


def main():
    call("T1", "PUT", f"/account/{A2}/parent_account", T1,
         {"parent_account_id": A1})
    call("T2", "PUT", f"/account/{A1}/parent_account", T2,
         {"parent_account_id": A2})

    s, _ = call("T2", "PUT", f"/account/{A2}/parent_account", T2,
                {"parent_account_id": A1})
    if s == 200:
        print("OWN-MOVE SUCCEEDED - inspecting visibility", flush=True)
        call("T2", "GET", f"/account/{A2}", T2)
        call("T1", "GET", "/account", T1)
        call("T1", "GET", f"/account/{A2}", T1)
        call("T1", "GET", f"/account/{A2}/projects", T1)
        call("T2", "PUT", f"/account/{A2}/parent_account", T2,
             {"parent_account_id": ""})

    with open("outputs/aiven_accountmove.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
