#!/usr/bin/env python3
"""Modern Treasury cross-org probe runner (GitHub Actions lane).
Reads credentials from env: MT_ORG_A, MT_KEY_A, MT_ORG_B, MT_KEY_B.
Prints JSON lines; never prints key material. Usage: python3 scripts/mt_probe.py [mode]
modes: baseline | pairswap | asyncprobe   (default: baseline)
"""
import os, sys, json, uuid, urllib.request, urllib.error, base64

BASE = "https://app.moderntreasury.com"
ORGA, KEYA = os.environ.get("MT_ORG_A", ""), os.environ.get("MT_KEY_A", "")
ORGB, KEYB = os.environ.get("MT_ORG_B", ""), os.environ.get("MT_KEY_B", "")

def req(method, path, org, key, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    tok = base64.b64encode(f"{org}:{key}".encode()).decode()
    r.add_header("Authorization", "Basic " + tok)
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()[:2000]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:2000]
    except Exception as e:
        return -1, f"ERR {e}"

def out(tag, status, body):
    print(json.dumps({"tag": tag, "status": status, "body": body}))

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    if not (ORGA and KEYA):
        print(json.dumps({"fatal": "MT_ORG_A/MT_KEY_A missing"})); return
    if mode == "baseline":
        for path in ("/api/internal_accounts", "/api/payment_orders", "/api/counterparties"):
            out(f"A GET {path}", *req("GET", path, ORGA, KEYA))
        if ORGB and KEYB:
            out("B GET /api/internal_accounts", *req("GET", "/api/internal_accounts", ORGB, KEYB))
    elif mode == "pairswap":
        out("A-org + B-key", *req("GET", "/api/internal_accounts", ORGA, KEYB))
        out("B-org + A-key", *req("GET", "/api/internal_accounts", ORGB, KEYA))
    elif mode == "asyncprobe":
        ia_b = os.environ.get("MT_IA_B", ""); cp_a = os.environ.get("MT_CP_A", "")
        body = {"originating_account_id": ia_b, "receiving_account_id": cp_a,
                "type": "ach", "currency": "USD", "amount": 100, "direction": "credit"}
        out("async cross A-creds", *req("POST", "/api/payment_orders/create_async", ORGA, KEYA, body))
        out("sync cross A-creds", *req("POST", "/api/payment_orders", ORGA, KEYA, body))

if __name__ == "__main__":
    main()
