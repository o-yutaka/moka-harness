#!/usr/bin/env python3
"""Affirm battery 1 — merchant A baseline + C1 (public-key boundary).
Keys come from GitHub Secrets env: AFFIRM_A_PUB / AFFIRM_A_PRIV.
Shape-first: the baseline create+read responses are saved in full under
outputs/affirm-battery1/ before any verdict logic runs.
Affirm API auth = HTTP Basic(public_key, private_key) against sandbox.affirm.com.
"""
import base64, json, os, subprocess, time

BASE = "https://sandbox.affirm.com"
OUT = "outputs/affirm-battery1"
os.makedirs(OUT, exist_ok=True)
PUB = os.environ.get("AFFIRM_A_PUB", "")
PRIV = os.environ.get("AFFIRM_A_PRIV", "")

def call(name, method, path, auth=None, data=None):
    cmd = ["curl", "-s", "-m", "30", "-X", method, "-H", "Content-Type: application/json",
           "-H", "Accept: application/json", "-w", "\n%{http_code}"]
    if auth:
        cmd += ["-H", "Authorization: Basic " + base64.b64encode(auth.encode()).decode()]
    if data is not None:
        cmd += ["-d", json.dumps(data)]
    cmd.append(BASE + path)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    raw, _, code = out.rpartition("\n")
    status = int(code) if code.isdigit() else 0
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        f.write(raw)
    print(f"{name}: HTTP {status} :: {raw[:150]}")
    time.sleep(1.1)
    try:
        return status, json.loads(raw)
    except Exception:
        return status, {}

ADDR = {"street1": "548 Market St", "city": "San Francisco", "state": "CA",
        "zipcode": "94104", "country": "USA"}
NAME = {"first": "Test", "last": "Buyer"}
payload = {
    "merchant": {"user_confirmation_url": "https://example.com/confirm",
                 "user_cancel_url": "https://example.com/cancel",
                 "user_confirmation_url_action": "POST"},
    "items": [{"display_name": "Test Item", "sku": "TEST-1", "unit_price": 1000, "qty": 1}],
    "shipping": {"name": NAME, "address": ADDR},
    "billing": {"name": NAME, "address": ADDR},
    "metadata": {"shipping_type": "UPS Ground"},
    "order_id": "MOKA-A-001",
    "currency": "USD",
    "total": 1000,
}

# baseline: create + read with the full key pair
_, created = call("01_create_full", "POST", "/api/v2/checkout/direct", auth=f"{PUB}:{PRIV}", data=payload)
cid = created.get("checkout_id") or created.get("id") or ""
print("CHECKOUT_ID:", cid)
if cid:
    call("02_read_full", "GET", f"/api/v2/checkout/{cid}", auth=f"{PUB}:{PRIV}")
    # C1: public key only, three auth shapes
    call("03_read_pub_only", "GET", f"/api/v2/checkout/{cid}", auth=f"{PUB}:{PUB}")
    call("04_read_pub_empty", "GET", f"/api/v2/checkout/{cid}", auth=f"{PUB}:")
    call("05_read_noauth", "GET", f"/api/v2/checkout/{cid}")
    # C1b: charges list/read attempts with public-only
    call("06_charges_pub_only", "GET", "/api/v2/charges", auth=f"{PUB}:{PUB}")
    call("07_charges_full", "GET", "/api/v2/charges", auth=f"{PUB}:{PRIV}")
print("DONE")
