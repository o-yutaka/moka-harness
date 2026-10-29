#!/usr/bin/env python3
"""Aiven run 9b: fork scoping controls."""
import json
import os
import re
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
if not T1:
    print("tokens missing", flush=True)
    sys.exit(2)

ORG = "org5eea5b7d496"
SRC = "bugcrowdninja-b1ee"
DST = "moka-fork-target"
SRC_SVC = "moka-seed-my"
CLOUD = "google-europe-west3"
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
    print(f"{who} {method} {path} -> {status} :: {safe[:200]}", flush=True)
    return status, resp


def field(text, *names):
    for n in names:
        m = re.search(rf'"{n}"\s*:\s*"([^"]+)"', text or "")
        if m:
            return m.group(1)
    return None


def fork_body(name):
    return {"service_type": "mysql", "plan": "hobbyist",
            "service_name": name, "cloud": CLOUD,
            "user_config": {"service_to_fork_from": SRC_SVC}}


def main():
    s, _ = call("T1", "POST", f"/project/{SRC}/service", T1,
                fork_body("moka-fork-same"))
    print(f"owner same-project fork -> {s}", flush=True)
    if s in (200, 201):
        call("T1", "DELETE", f"/project/{SRC}/service/moka-fork-same", T1)

    s, _ = call("T1", "POST", f"/project/{DST}/service", T1,
                fork_body("moka-fork-ctl2"))
    print(f"owner cross-project fork -> {s}", flush=True)
    if s in (200, 201):
        call("T1", "DELETE", f"/project/{DST}/service/moka-fork-ctl2", T1)

    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-fork-f2"})
    f_uid = field(b, "user_id")
    for proj, perms in ((SRC, ["role:project:admin"]),
                        (DST, ["role:project:admin"])):
        call("T1", "PUT", f"/organization/{ORG}/permissions/project/{proj}",
             T1, {"permissions": [{"principal_id": f_uid,
                                   "principal_type": "user",
                                   "permissions": perms}]})
    s, b = call("T1", "POST",
                f"/organization/{ORG}/application-users/{f_uid}/access-tokens",
                T1, {"description": "fork-test2"})
    ft = field(b, "full_token")
    print(f"F2 token captured: {bool(ft)}", flush=True)
    if ft:
        s, _ = call("FT", "POST", f"/project/{DST}/service", ft,
                    fork_body("moka-fork-fx"))
        print(f"F(admin-on-source) cross-project fork -> {s}", flush=True)
        if s in (200, 201):
            call("T1", "DELETE", f"/project/{DST}/service/moka-fork-fx", T1)
    if f_uid:
        call("T1", "DELETE",
             f"/organization/{ORG}/application-users/{f_uid}", T1)
    with open("outputs/aiven_fork_test2.json", "w") as fh:
        json.dump({"calls": CALLS}, fh, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
