#!/usr/bin/env python3
"""Aiven run 4d: seed using service_uri_params / service users credentials."""
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
if not T1:
    print("token missing", flush=True)
    sys.exit(2)

P1 = "bugcrowdninja-b1ee"
SVC = "moka-seed-pg"
os.makedirs("outputs", exist_ok=True)


def req(method, path, token=T1):
    r = urllib.request.Request(
        BASE + path, method=method,
        headers={"Authorization": f"aivenv1 {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERROR {e}"[:200]


def try_seed(label, host, port, db, user, password, ctx):
    import pg8000
    try:
        conn = pg8000.connect(host=host, port=int(port), database=db,
                              user=user, password=password, ssl_context=ctx)
    except Exception as e:
        print(f"[{label}] connect failed: {str(e)[:140]}", flush=True)
        return False
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS moka_seed "
                "(id int PRIMARY KEY, marker text)")
    cur.execute("INSERT INTO moka_seed VALUES (1, 'MOKA-SEED-PROJ1') "
                "ON CONFLICT (id) DO UPDATE SET marker = EXCLUDED.marker")
    conn.commit()
    cur.execute("SELECT id, marker FROM moka_seed")
    rows = cur.fetchall()
    conn.close()
    print(f"[{label}] SEED OK rows={rows}", flush=True)
    with open("outputs/aiven_fork_seed.json", "w") as f:
        json.dump({"source": label, "rows": [list(r) for r in rows]},
                  f, indent=1)
    return True


def main():
    s, svc_body = req("GET", f"/project/{P1}/service/{SVC}")
    svc = json.loads(svc_body)["service"]
    print(f"state={svc.get('state')}", flush=True)
    sup = svc.get("service_uri_params") or {}
    print(f"service_uri_params keys: {sorted(sup.keys())}", flush=True)
    print(f"sup: user={sup.get('user')} db={sup.get('dbname')} "
          f"port={sup.get('port')} pwlen={len(sup.get('password') or '')}",
          flush=True)
    users = svc.get("users") or []
    print(f"users: {[(u.get('username'), len(u.get('password') or '')) for u in users]}",
          flush=True)

    import ssl as sslmod
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)

    candidates = []
    if sup.get("host") and sup.get("password"):
        candidates.append(("service_uri_params", sup["host"], sup["port"],
                           sup.get("dbname") or "defaultdb", sup["user"],
                           sup["password"]))
    for u in users:
        if u.get("password"):
            candidates.append((f"users:{u.get('username')}", sup.get("host"),
                               sup.get("port"), sup.get("dbname") or "defaultdb",
                               u["username"], u["password"]))
    for label, host, port, db, user, pw in candidates:
        if host and try_seed(label, host, port, db, user, pw, ctx):
            print("DONE", flush=True)
            return
    print("DONE (no candidate worked)", flush=True)


if __name__ == "__main__":
    main()
