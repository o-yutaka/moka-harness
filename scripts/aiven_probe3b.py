#!/usr/bin/env python3
"""Aiven run 3b: application-user privilege matrix, fixed."""
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


def call(who, method, path, token, body=None, keep=1200):
    status, resp = req(method, path, token, body)
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": resp[:keep]})
    print(f"{who} {method} {path} -> {status} ({len(resp)}B)", flush=True)
    return status, resp


def uid_of(text):
    m = re.search(r'"user_id"\s*:\s*"([^"]+)"', text or "")
    return m.group(1) if m else None


def mint(uid, body_extra=None):
    body = {"description": "moka-run3b"}
    if body_extra:
        body.update(body_extra)
    s, b = req("POST",
               f"/organization/{ORG}/application-users/{uid}/access-tokens",
               T1, body)
    tok = None
    keys = []
    try:
        parsed = json.loads(b)
        keys = sorted(parsed.keys())
        tok = parsed.get("full_token")
    except Exception:
        pass
    print(f"mint uid={uid} extra={list(body_extra or {})} -> {s} "
          f"keys={keys} token={'yes' if tok else 'NO'}", flush=True)
    CALLS.append({"who": "T1", "method": "POST",
                  "path": f"/organization/{ORG}/application-users/{uid}/access-tokens",
                  "status": s, "len": len(b),
                  "body": f"(keys={keys}, token redacted)"})
    return tok


def main():
    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-lowperm2"})
    low_uid = uid_of(b)
    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-admin2"})
    ctrl_uid = uid_of(b)
    print(f"low_uid={low_uid} ctrl_uid={ctrl_uid}", flush=True)
    if not low_uid:
        dump()
        return

    if ctrl_uid:
        call("T1", "PUT", f"/organization/{ORG}/permissions/organization/{ORG}",
             T1, {"permissions": [{"principal_id": ctrl_uid,
                                   "principal_type": "user",
                                   "permissions": ["role:organization:admin"]}]})
    for uid, tag in [(low_uid, "low"), (ctrl_uid, "ctrl")]:
        if uid:
            call("T1", "GET", f"/organization/{ORG}/user/{uid}/permissions",
                 T1)

    low_tok = mint(low_uid)
    low_scoped = mint(low_uid, {"scopes": ["user:read"]})
    ctrl_tok = mint(ctrl_uid) if ctrl_uid else None

    if low_tok:
        for method, path, body in [
            ("GET", "/me", None),
            ("GET", f"/organization/{ORG}", None),
            ("GET", f"/organization/{ORG}/user", None),
            ("GET", f"/organization/{ORG}/application-users", None),
            ("GET", f"/organization/{ORG}/billing-groups", None),
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
                 f"/organization/{ORG}/application-users/{ctrl_uid}/access-tokens",
                 low_tok, {"description": "guardrail-probe"})

    if low_scoped:
        for path in [f"/account/{A1}/events", f"/account/{A1}/authentication",
                     f"/organization/{ORG}/user", f"/project/{P1}",
                     "/me"]:
            call("SCOPED", "GET", path, low_scoped)

    if ctrl_tok:
        for path in [f"/organization/{ORG}/user", f"/account/{A1}/events",
                     f"/project/{P1}"]:
            call("CTRL", "GET", path, ctrl_tok)

    for uid in (low_uid, ctrl_uid):
        if uid:
            call("T1", "DELETE",
                 f"/organization/{ORG}/application-users/{uid}", T1)
    dump()


def dump():
    with open("outputs/aiven_probe_run3b.json", "w") as f:
        json.dump({"calls": CALLS}, f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
