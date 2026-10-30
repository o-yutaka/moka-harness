#!/usr/bin/env python3
"""Affirm battery 2 — C2 cross-merchant binding (decisive).
Keys from env AFFIRM_A_PUB/PRIV, AFFIRM_B_PUB/PRIV (GitHub Secrets).
A creates a checkout; B tries to read and authorize it. Full bodies saved."""
import base64, json, os, subprocess

BASE = "https://sandbox.affirm.com"
OUT = "outputs/affirm-battery2"
os.makedirs(OUT, exist_ok=True)

def basic(pub, priv):
    return "Basic " + base64.b64encode(f"{pub}:{priv}".encode()).decode()

def call(name, method, path, auth, body=None):
    cmd = ["curl", "-s", "-m", "30", "-X", method,
           "-H", f"Authorization: {auth}", "-H", "Content-Type: application/json",
           "-w", "\n%{http_code}", BASE + path]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    raw, _, code = out.rpartition("\n")
    status = int(code) if code.isdigit() else 0
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        f.write(raw)
    print(f"{name}: HTTP {status} :: {raw[:220]}")
    return status, raw

A = basic(os.environ.get("AFFIRM_A_PUB", ""), os.environ.get("AFFIRM_A_PRIV", ""))
B = basic(os.environ.get("AFFIRM_B_PUB", ""), os.environ.get("AFFIRM_B_PRIV", ""))

checkout_body = {
    "merchant": {
        "user_confirmation_url": "https://example.com/confirm",
        "user_cancel_url": "https://example.com/cancel",
        "user_confirmation_url_action": "POST",
        "name": "Moka Test Merchant A",
    },
    "shipping": {"name": {"first": "Test", "last": "Buyer"},
                 "address": {"line1": "548 Market St", "city": "San Francisco",
                             "state": "CA", "zipcode": "94104", "country": "USA"}},
    "billing": {"name": {"first": "Test", "last": "Buyer"},
                "address": {"line1": "548 Market St", "city": "San Francisco",
                            "state": "CA", "zipcode": "94104", "country": "USA"}},
    "items": [{"display_name": "Probe Item", "sku": "PROBE-001", "unit_price": 1000, "qty": 1}],
    "order_id": "MOKA-A-002",
    "total": 1000,
}

st, raw = call("01_A_create_checkout", "POST", "/api/v2/checkout/direct", A, checkout_body)
cid, ctok = "", ""
try:
    d = json.loads(raw)
    cid = d.get("checkout_id", "") or d.get("id", "")
    ctok = d.get("checkout_token", "")
except Exception:
    pass
print(f"CHECKOUT_ID={cid} TOKEN_PRESENT={bool(ctok)}")

if cid:
    call("02_A_read_own", "GET", f"/api/v2/checkout/{cid}", A)
    call("03_B_read_cross", "GET", f"/api/v2/checkout/{cid}", B)
    call("04_B_charges_list", "GET", "/api/v2/charges", B)
if ctok:
    call("05_B_authorize_cross", "POST", "/api/v2/charges", B,
         {"checkout_token": ctok, "order_id": "MOKA-B-CROSS-001"})
print("DONE")
