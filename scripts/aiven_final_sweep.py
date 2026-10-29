#!/usr/bin/env python3
"""Aiven run 10: final low-privilege WRITE sweep + seed cleanup."""
import json
import os
import re
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
T2 = os.environ.get("AIVEN_TOKEN_2", "")
if not T1:
    print("tokens missing", flush=True)
    sys.exit(2)

ORG = "org5eea5b7d496"
SRC = "bugcrowdninja-b1ee"
INVITEE = "mimi05741b+account3@bugcrowdninja.com"
os.makedirs("outputs", exist_ok=True)
CALLS = []


def req(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Authorization": f"aivenv1 {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERROR {e}"[:200]


def call(who, method, path, token, body=None, keep=420):
    status, resp = req(method, path, token, body)
    safe = re.sub(r'"full_token"\s*:\s*"[^"]+"', '"full_token":"<redacted>"',
                  resp[:keep])
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "body": safe})
    print(f"{who} {method} {path} -> {status} :: {safe[:170]}", flush=True)
    return status, resp


def main():
    s, b = call("T1", "GET", f"/organization/{ORG}/user", T1, keep=4000)
    t2_uid = None
    try:
        for u in json.loads(b).get("users", []):
            if "account2" in ((u.get("user_info") or {}).get("user_email")
                              or ""):
                t2_uid = u.get("user_id")
    except Exception:
        pass
    print(f"t2={t2_uid}", flush=True)

    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-low-sweep"})
    m = re.search(r'"user_id"\s*:\s*"([^"]+)"', b or "")
    low_uid = m.group(1) if m else None
    s, b = call("T1", "POST",
                f"/organization/{ORG}/application-users/{low_uid}/access-tokens",
                T1, {"description": "sweep"})
    low = None
    try:
        low = json.loads(b).get("full_token")
    except Exception:
        pass
    print(f"LOW uid={low_uid} token={bool(low)}", flush=True)

    if low:
        call("LOW", "POST", f"/organization/{ORG}/invitation", low,
             {"user_email": INVITEE})
        call("LOW", "GET", f"/organization/{ORG}/invitation", low)
        if t2_uid:
            call("LOW", "GET",
                 f"/organization/{ORG}/user/{t2_uid}/access-tokens", low)
        call("LOW", "POST", f"/organization/{ORG}/user-groups", low,
             {"user_group_name": "moka-low-group", "description": "sweep"})
        call("LOW", "POST", "/access_token", low,
             {"description": "sweep-self", "max_age_seconds": 3600})
        call("LOW", "DELETE",
             f"/organization/{ORG}/application-users/{low_uid}", low)

    if T2:
        call("T2", "POST", f"/organization/{ORG}/invitation", T2,
             {"user_email": INVITEE})

    call("T1", "DELETE", f"/organization/{ORG}/invitation/{INVITEE}", T1)
    if low_uid:
        call("T1", "DELETE",
             f"/organization/{ORG}/application-users/{low_uid}", T1)
    call("T1", "DELETE", f"/project/{SRC}/service/moka-seed-my", T1)
    with open("outputs/aiven_final_sweep.json", "w") as fh:
        json.dump({"calls": CALLS}, fh, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
