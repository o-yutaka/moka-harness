#!/usr/bin/env python3
"""Aiven run 7b: delegation guardrails (A2), member-uid parse fixed."""
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


def call(who, method, path, token, body=None, keep=1000):
    status, resp = req(method, path, token, body)
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": resp[:keep]})
    print(f"{who} {method} {path} -> {status} ({len(resp)}B)", flush=True)
    return status, resp


def field(text, *names):
    for n in names:
        m = re.search(rf'"{n}"\s*:\s*"([^"]+)"', text or "")
        if m:
            return m.group(1)
    return None


def grant(principal_id, principal_type, perms, resource_type="organization",
          resource_id=None):
    return call("T1", "PUT",
                f"/organization/{ORG}/permissions/{resource_type}/{resource_id or ORG}",
                T1, {"permissions": [{"principal_id": principal_id,
                                      "principal_type": principal_type,
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
    print(f"t2 member uid={t2_uid}", flush=True)
    if not t2_uid:
        dump()
        return

    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-priv-app"})
    priv_uid = field(b, "user_id")
    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-plain-app"})
    plain_uid = field(b, "user_id")
    print(f"priv={priv_uid} plain={plain_uid}", flush=True)
    if priv_uid:
        grant(priv_uid, "user", ["role:organization:admin"])

    grant(t2_uid, "user", ["organization:app_users:write"])
    call("T1", "GET", f"/organization/{ORG}/user/{t2_uid}/permissions", T1)
    if plain_uid:
        s, _ = call("T2", "POST",
                    f"/organization/{ORG}/application-users/{plain_uid}/access-tokens",
                    T2, {"description": "delegated-allowed"})
        print(f"delegated mint PLAIN -> {s} (documented: allowed)", flush=True)
    if priv_uid:
        s, _ = call("T2", "POST",
                    f"/organization/{ORG}/application-users/{priv_uid}/access-tokens",
                    T2, {"description": "delegated-forbidden"})
        print(f"delegated mint PRIV -> {s} (documented: FORBIDDEN)", flush=True)

    s, b = call("T1", "POST", f"/organization/{ORG}/user-groups",
                T1, {"user_group_name": "moka-gpriv", "description": "probe"})
    gpriv = field(b, "user_group_id")
    s, b = call("T1", "POST", f"/organization/{ORG}/user-groups",
                T1, {"user_group_name": "moka-gplain", "description": "probe"})
    gplain = field(b, "user_group_id")
    print(f"gpriv={gpriv} gplain={gplain}", flush=True)
    if gpriv:
        grant(gpriv, "user_group", ["role:organization:admin"],
              resource_type="user_group", resource_id=gpriv)
    grant(t2_uid, "user", ["organization:groups:write"])
    if gpriv:
        s, _ = call("T2", "PATCH",
                    f"/organization/{ORG}/user-groups/{gpriv}/members",
                    T2, {"member_ids": [t2_uid], "operation": "add_members"})
        print(f"delegated add-to-PRIV-group -> {s} (documented: FORBIDDEN)",
              flush=True)
    if gplain:
        s, _ = call("T2", "PATCH",
                    f"/organization/{ORG}/user-groups/{gplain}/members",
                    T2, {"member_ids": [t2_uid], "operation": "add_members"})
        print(f"delegated add-to-PLAIN-group -> {s} (documented: allowed)",
              flush=True)

    if gplain:
        call("T1", "PATCH", f"/organization/{ORG}/user-groups/{gplain}/members",
             T1, {"member_ids": [t2_uid], "operation": "remove_members"})
    for gid in (gpriv, gplain):
        if gid:
            call("T1", "DELETE", f"/organization/{ORG}/user-groups/{gid}", T1)
    for uid in (priv_uid, plain_uid):
        if uid:
            call("T1", "DELETE",
                 f"/organization/{ORG}/application-users/{uid}", T1)
    grant(t2_uid, "user", [])
    dump()


def dump():
    with open("outputs/aiven_delegation.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
