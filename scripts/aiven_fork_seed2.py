#!/usr/bin/env python3
"""Aiven run 4c: diagnose PG credentials structure, then seed."""
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
import urllib.parse

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
        print(f"[{label}] connect failed: {type(e).__name__} {str(e)[:140]}",
              flush=True)
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
    print(f"service keys: {sorted(svc.keys())}", flush=True)
    ci = svc.get("connection_info") or {}
    print(f"connection_info keys: {sorted(ci.keys())}", flush=True)

    import ssl as sslmod
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE

    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)

    candidates = []
    uri = svc.get("service_uri") or ""
    if uri:
        u = urllib.parse.urlparse(uri)
        candidates.append(("service_uri", u.hostname, u.port,
                           u.path.lstrip("/"),
                           urllib.parse.unquote(u.username or ""),
                           urllib.parse.unquote(u.password or "")))
        print(f"service_uri: user={u.username} db={u.path.lstrip('/')} "
              f"port={u.port} pwlen={len(urllib.parse.unquote(u.password or ''))}",
              flush=True)
    pgp = ci.get("pg_params") or {}
    if pgp:
        print(f"pg_params: user={pgp.get('user')} db={pgp.get('dbname')} "
              f"port={pgp.get('port')} pwlen={len(pgp.get('password') or '')}",
              flush=True)
        print(f"passwords equal across sources: "
              f"{(pgp.get('password') or '') == (candidates[0][5] if candidates else None)}",
              flush=True)
        candidates.append(("pg_params", pgp.get("host"), pgp.get("port"),
                           pgp.get("dbname"), pgp.get("user"),
                           pgp.get("password")))
    for label, host, port, db, user, pw in candidates:
        if host and pw and try_seed(label, host, port, db, user, pw, ctx):
            print("DONE", flush=True)
            return
    print("DONE (no candidate worked)", flush=True)


if __name__ == "__main__":
    main()
