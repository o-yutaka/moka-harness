#!/usr/bin/env python3
"""Aiven run 4e: reset avnadmin password, then seed in the same run."""
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


def req(method, path, token=T1, body=None):
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


def find_password(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "password" and isinstance(v, str) and len(v) > 10:
                return v
        for v in obj.values():
            r = find_password(v)
            if r:
                return r
    if isinstance(obj, list):
        for v in obj:
            r = find_password(v)
            if r:
                return r
    return None


def main():
    s, b = req("GET", f"/project/{P1}/service/{SVC}")
    svc = json.loads(b)["service"]
    sup = svc.get("service_uri_params") or {}
    host, port = sup.get("host"), sup.get("port")
    print(f"state={svc.get('state')} host/port known: {bool(host)}/{bool(port)}",
          flush=True)

    s, b = req("PUT", f"/project/{P1}/service/{SVC}/user/avnadmin/credentials/reset",
               body={})
    print(f"reset -> {s} ({len(b)}B)", flush=True)
    pw = find_password(json.loads(b)) if s == 200 else None
    print(f"new password captured: {bool(pw)} len={len(pw or '')}", flush=True)
    if not pw:
        print("DONE (reset gave no password)", flush=True)
        return

    import ssl as sslmod
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)
    import pg8000
    conn = pg8000.connect(host=host, port=int(port), database="defaultdb",
                          user="avnadmin", password=pw, ssl_context=ctx)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS moka_seed "
                "(id int PRIMARY KEY, marker text)")
    cur.execute("INSERT INTO moka_seed VALUES (1, 'MOKA-SEED-PROJ1') "
                "ON CONFLICT (id) DO UPDATE SET marker = EXCLUDED.marker")
    conn.commit()
    cur.execute("SELECT id, marker FROM moka_seed")
    rows = cur.fetchall()
    conn.close()
    print(f"SEED OK rows={rows}", flush=True)
    with open("outputs/aiven_fork_seed.json", "w") as f:
        json.dump({"rows": [list(r) for r in rows]}, f, indent=1)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
