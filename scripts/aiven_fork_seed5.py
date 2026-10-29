#!/usr/bin/env python3
"""Aiven run 4f: locate an unmasked PG password source, then seed."""
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


def shape(obj, prefix=""):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += shape(v, f"{prefix}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:3]):
            out += shape(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        out.append(f"{prefix} str len={len(obj)}")
    else:
        out.append(f"{prefix} {type(obj).__name__}")
    return out


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


def seed(host, port, user, pw, label):
    import ssl as sslmod
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    import pg8000
    try:
        conn = pg8000.connect(host=host, port=int(port), database="defaultdb",
                              user=user, password=pw, ssl_context=ctx)
    except Exception as e:
        print(f"[{label}] connect failed: {str(e)[:130]}", flush=True)
        return False
    try:
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
            json.dump({"user": user, "rows": [list(r) for r in rows]},
                      f, indent=1)
        return True
    except Exception as e:
        print(f"[{label}] write failed: {str(e)[:160]}", flush=True)
        return False


def main():
    s, b = req("GET", f"/project/{P1}/service/{SVC}")
    svc = json.loads(b)["service"]
    sup = svc.get("service_uri_params") or {}
    host, port = sup.get("host"), sup.get("port")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pg8000"],
                   check=False)

    s, b = req("GET", f"/project/{P1}/service/{SVC}/user/avnadmin")
    print(f"ServiceUserGet -> {s}", flush=True)
    if s == 200:
        j = json.loads(b)
        print("shape:", "; ".join(shape(j)[:14]), flush=True)
        pw = find_password(j)
        print(f"avnadmin pw from ServiceUserGet: len={len(pw or '')}",
              flush=True)
        if pw and seed(host, port, "avnadmin", pw, "userget"):
            print("DONE", flush=True)
            return

    s, b = req("POST", f"/project/{P1}/service/{SVC}/user",
               body={"username": "moka_seed_u"})
    print(f"ServiceUserCreate -> {s}", flush=True)
    if s in (200, 201):
        j = json.loads(b)
        print("shape:", "; ".join(shape(j)[:14]), flush=True)
        pw = find_password(j)
        print(f"new user pw: len={len(pw or '')}", flush=True)
        if pw and seed(host, port, "moka_seed_u", pw, "usercreate"):
            print("DONE", flush=True)
            return

    s, b = req("PUT", f"/project/{P1}/service/{SVC}/user/avnadmin/credentials/reset",
               body={})
    print(f"reset -> {s}", flush=True)
    if s == 200:
        j = json.loads(b)
        print("shape:", "; ".join(shape(j)[:20]), flush=True)
        pw = find_password(j)
        print(f"reset pw: len={len(pw or '')}", flush=True)
        if pw and seed(host, port, "avnadmin", pw, "reset"):
            print("DONE", flush=True)
            return
    print("DONE (no unmasked password source)", flush=True)


if __name__ == "__main__":
    main()
