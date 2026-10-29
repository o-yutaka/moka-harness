#!/usr/bin/env python3
"""Aiven run 4b: seed the fork-source PG (fixes run4's SSL failure)."""
import json
import os
import re
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


def find_pem(text):
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  text or "", re.S)
    return m.group(0) if m else None


def main():
    s, svc_body = req("GET", f"/project/{P1}/service/{SVC}")
    print(f"GET service -> {s}", flush=True)
    svc = json.loads(svc_body)["service"]
    print(f"state={svc.get('state')}", flush=True)

    ca_pem = find_pem(svc_body)
    source = "service-body"
    if not ca_pem:
        s2, ca_body = req("GET", f"/project/{P1}/ca")
        print(f"GET project ca -> {s2} ({len(ca_body)}B)", flush=True)
        ca_pem = find_pem(ca_body)
        if not ca_pem:
            try:
                ca_pem = find_pem(json.loads(ca_body).get("certificate", ""))
            except Exception:
                pass
        source = "project-ca-endpoint"
    import ssl as sslmod
    if ca_pem:
        with open("/tmp/aiven_ca.pem", "w") as f:
            f.write(ca_pem)
        ctx = sslmod.create_default_context(cafile="/tmp/aiven_ca.pem")
        print(f"TLS: verified with CA from {source}", flush=True)
    else:
        ctx = sslmod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = sslmod.CERT_NONE
        print("TLS: FALLBACK unverified (no CA obtainable)", flush=True)

    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)
    uri = svc["service_uri"]
    u = urllib.parse.urlparse(uri)
    import pg8000
    conn = pg8000.connect(
        host=u.hostname, port=u.port, database=u.path.lstrip("/"),
        user=urllib.parse.unquote(u.username or ""),
        password=urllib.parse.unquote(u.password or ""),
        ssl_context=ctx)
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
        json.dump({"state": svc.get("state"), "tls": source if ca_pem else "fallback",
                   "rows": [list(r) for r in rows]}, f, indent=1)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
