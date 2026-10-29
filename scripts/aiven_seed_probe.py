#!/usr/bin/env python3
"""Aiven run 4h: find a service type where a created user can seed data."""
import json
import os
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

P1 = "bugcrowdninja-b1ee"
CLOUD = "google-europe-west3"
os.makedirs("outputs", exist_ok=True)
RESULT = {}


def req(method, path, token=T1, body=None):
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


def wait_running(name, tries=18):
    for i in range(tries):
        s, b = req("GET", f"/project/{P1}/service/{name}")
        if s != 200:
            return None
        svc = json.loads(b)["service"]
        if svc.get("state") == "RUNNING":
            return svc
        time.sleep(20)
    return None


def create_user(svc_name, username):
    s, b = req("POST", f"/project/{P1}/service/{svc_name}/user",
               body={"username": username})
    print(f"create user {username} on {svc_name} -> {s}", flush=True)
    if s not in (200, 201):
        return None
    u = json.loads(b).get("user") or {}
    pw = u.get("password") or ""
    print(f"user pw len={len(pw)}", flush=True)
    return pw if len(pw) > 10 else None


def probe_pg():
    svc_name = "moka-seed-pg2"
    s, b = req("GET", f"/project/{P1}/service/{svc_name}")
    if s != 200:
        print("pg2 missing", flush=True)
        return False
    sup = json.loads(b)["service"].get("service_uri_params") or {}
    pw = create_user(svc_name, "moka_su2")
    if not pw:
        return False
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)
    import ssl as sslmod
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    import pg8000
    try:
        conn = pg8000.connect(host=sup["host"], port=int(sup["port"]),
                              database="defaultdb", user="moka_su2",
                              password=pw, ssl_context=ctx)
        cur = conn.cursor()
        cur.execute("CREATE SCHEMA IF NOT EXISTS moka_schema")
        cur.execute("CREATE TABLE IF NOT EXISTS moka_schema.moka_seed "
                    "(id int PRIMARY KEY, marker text)")
        cur.execute("INSERT INTO moka_schema.moka_seed VALUES "
                    "(1, 'MOKA-SEED-PROJ1') ON CONFLICT (id) DO UPDATE "
                    "SET marker = EXCLUDED.marker")
        conn.commit()
        cur.execute("SELECT id, marker FROM moka_schema.moka_seed")
        rows = cur.fetchall()
        conn.close()
        print(f"PG SEED OK rows={rows}", flush=True)
        RESULT["pg"] = {"service": svc_name, "user": "moka_su2",
                        "rows": [list(r) for r in rows]}
        return True
    except Exception as e:
        print(f"PG schema route failed: {str(e)[:160]}", flush=True)
        return False


def probe_mysql():
    svc_name = "moka-seed-my"
    s, b = req("POST", f"/project/{P1}/service",
               body={"service_type": "mysql", "plan": "hobbyist",
                     "service_name": svc_name, "cloud": CLOUD})
    print(f"create mysql -> {s}", flush=True)
    if s not in (200, 201):
        print(f"body: {b[:250]}", flush=True)
        return False
    svc = wait_running(svc_name)
    if not svc:
        print("mysql did not reach RUNNING", flush=True)
        return False
    sup = svc.get("service_uri_params") or {}
    pw = create_user(svc_name, "moka_su")
    if not pw:
        return False
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pymysql"],
                   check=False)
    import ssl as sslmod
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    import pymysql
    try:
        conn = pymysql.connect(host=sup["host"], port=int(sup["port"]),
                               user="moka_su", password=pw,
                               database=sup.get("dbname") or "defaultdb",
                               ssl=ctx)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS moka_seed "
                    "(id INT PRIMARY KEY, marker VARCHAR(64))")
        cur.execute("INSERT INTO moka_seed VALUES (1, 'MOKA-SEED-PROJ1') "
                    "ON DUPLICATE KEY UPDATE marker = VALUES(marker)")
        conn.commit()
        cur.execute("SELECT id, marker FROM moka_seed")
        rows = cur.fetchall()
        conn.close()
        print(f"MYSQL SEED OK rows={rows}", flush=True)
        RESULT["mysql"] = {"service": svc_name, "user": "moka_su",
                           "rows": [list(r) for r in rows]}
        return True
    except Exception as e:
        print(f"mysql route failed: {str(e)[:160]}", flush=True)
        return False


def probe_valkey():
    svc_name = "moka-seed-vk"
    s, b = req("POST", f"/project/{P1}/service",
               body={"service_type": "valkey", "plan": "hobbyist",
                     "service_name": svc_name, "cloud": CLOUD})
    print(f"create valkey -> {s}", flush=True)
    if s not in (200, 201):
        print(f"body: {b[:250]}", flush=True)
        return False
    svc = wait_running(svc_name)
    if not svc:
        print("valkey did not reach RUNNING", flush=True)
        return False
    sup = svc.get("service_uri_params") or {}
    pw = create_user(svc_name, "moka_su")
    if not pw:
        return False
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "redis"],
                   check=False)
    import redis
    try:
        r = redis.Redis(host=sup["host"], port=int(sup["port"]),
                        username="moka_su", password=pw,
                        ssl=True, ssl_cert_reqs=None,
                        decode_responses=True, socket_timeout=20)
        r.set("moka_seed", "MOKA-SEED-PROJ1")
        val = r.get("moka_seed")
        print(f"VALKEY SEED OK value={val}", flush=True)
        RESULT["valkey"] = {"service": svc_name, "user": "moka_su",
                            "value": val}
        return True
    except Exception as e:
        print(f"valkey route failed: {str(e)[:160]}", flush=True)
        return False


def main():
    ok = probe_pg()
    if not ok:
        ok = probe_mysql()
    if not ok:
        probe_valkey()
    with open("outputs/aiven_seed_probe.json", "w") as f:
        json.dump(RESULT, f, indent=1)
    print(f"DONE result_keys={list(RESULT.keys())}", flush=True)


if __name__ == "__main__":
    main()
