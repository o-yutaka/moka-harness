#!/usr/bin/env python3
"""Affirm consumer battery 1 — own-session controls (shape-first).
Cookie from GitHub Secrets env AFFIRM_CONSUMER_COOKIE. Full bodies saved."""
import json, os, subprocess

BASE = "https://sandbox.affirm.com"
OUT = "outputs/affirm-consumer1"
os.makedirs(OUT, exist_ok=True)
COOKIE = os.environ.get("AFFIRM_CONSUMER_COOKIE", "")

def call(name, path):
    cmd = ["curl", "-s", "-m", "30", "-H", f"Cookie: {COOKIE}",
           "-H", "Accept: application/json", "-w", "\n%{http_code}", BASE + path]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    raw, _, code = out.rpartition("\n")
    status = int(code) if code.isdigit() else 0
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        f.write(raw)
    print(f"{name}: HTTP {status} :: {raw[:200]}")
    return status

call("01_session", "/api/v2/session/")
call("02_user_self", "/api/v2/users/8395-5583-PQFA")
call("03_loans_list", "/api/v4/loans/?show_confirmed_first_data_loans=true&is_current=1")
call("04_loan_detail_own", "/api/v3/loans/2AR7-3GYT")
call("05_virtual_cards", "/api/v3/virtual_cards/?active=1")
call("06_repayment", "/api/v1/repayment_summary?limit=0")
print("DONE")
