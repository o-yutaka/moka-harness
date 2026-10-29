#!/usr/bin/env python3
"""Aiven run 4: fork-test infrastructure (own org1 only)."""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
if not T1:
    print("token missing", flush=True)
    sys.exit(2)

A1 = "a5eea5b45dff"
P1 = "bugcrowdninja-b1ee"
TARGET_PROJECT = "moka-fork-target"
SVC = "moka-seed-pg"
os.makedirs("outputs", exist_ok=True)
LOG = []


def req(method, path, body=None, token=T1):
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


def log(who, method, path, status, extra=""):
    LOG.append({"who": who, "method": method, "path": path,
                "status": status, "extra": extra})
    print(f"{who} {method} {path} -> {status} {extra}", flush=True)


def main():
    s, b = req("POST", "/project",
               {"account_id": A1, "project": TARGET_PROJECT})
    log("T1", "POST", "/project", s, TARGET_PROJECT)

    created = False
    for plan in ["hobbyist", "free", "startup-4", "business-4"]:
        s, b = req("POST", f"/project/{P1}/service",
                   {"service_type": "pg", "plan": plan,
                    "service_name": SVC})
        log("T1", "POST", f"/project/{P1}/service", s, f"plan={plan}")
        if s in (200, 201):
            created = True
            break
        if s == 409:
            created = True
            break
    if not created:
        dump()
        return

    state = "?"
    svc_body = ""
    for _ in range(24):
        s, svc_body = req("GET", f"/project/{P1}/service/{SVC}")
        try:
            state = json.loads(svc_body)["service"]["state"]
        except Exception:
            state = "?"
        print(f"state={state}", flush=True)
        if state == "RUNNING":
            break
        time.sleep(20)
    log("T1", "GET", f"/project/{P1}/service/{SVC}", s, f"state={state}")
    if state != "RUNNING":
        dump()
        return

    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)
    uri = json.loads(svc_body)["service"]["service_uri"]
    u = urllib.parse.urlparse(uri)
    import ssl as sslmod
    import pg8000
    conn = pg8000.connect(
        host=u.hostname, port=u.port, database=u.path.lstrip("/"),
        user=urllib.parse.unquote(u.username or ""),
        password=urllib.parse.unquote(u.password or ""),
        ssl_context=sslmod.create_default_context())
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS moka_seed "
                "(id int PRIMARY KEY, marker text)")
    cur.execute("INSERT INTO moka_seed VALUES (1, 'MOKA-SEED-PROJ1') "
                "ON CONFLICT (id) DO UPDATE SET marker = EXCLUDED.marker")
    conn.commit()
    cur.execute("SELECT count(*) FROM moka_seed")
    n = cur.fetchone()[0]
    conn.close()
    log("SQL", "SEED", SVC, 200, f"rows={n}")
    dump()


def dump():
    with open("outputs/aiven_fork_prep.json", "w") as f:
        json.dump({"log": LOG}, f, indent=1)
    print(f"DONE entries={len(LOG)}", flush=True)


if __name__ == "__main__":
    main()
