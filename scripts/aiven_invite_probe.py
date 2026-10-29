#!/usr/bin/env python3
"""Aiven run 6: organization invitation binding (A8) - own test accounts only."""
import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error

BASE = "https://api.aiven.io/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
T2 = os.environ.get("AIVEN_TOKEN_2", "")
if not T1 or not T2:
    print("tokens missing", flush=True)
    sys.exit(2)

ORG1 = "org5eea5b7d496"
A1 = "a5eea5b45dff"
INVITEES = ["mimi05741b+account3@bugcrowdninja.com",
            "mimi05741b+account4@bugcrowdninja.com"]
os.makedirs("outputs", exist_ok=True)
CALLS = []


def req(method, path, token, body=None):
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


def call(who, method, path, token, body=None, keep=1200, redact=None):
    status, resp = req(method, path, token, body)
    shown = resp
    if redact:
        shown = shown.replace(redact, "<CODE>")
    CALLS.append({"who": who, "method": method, "path": path,
                  "status": status, "len": len(resp), "body": shown[:keep]})
    print(f"{who} {method} {path} -> {status} ({len(resp)}B)", flush=True)
    return status, resp


def find_codes(text):
    codes = []
    for pat in [r'"invite_verification_code"\s*:\s*"([^"]+)"',
                r'"verification_code"\s*:\s*"([^"]+)"',
                r'"invitation_code"\s*:\s*"([^"]+)"',
                r'"code"\s*:\s*"([A-Za-z0-9_\-]{16,})"']:
        for m in re.findall(pat, text or ""):
            if m not in codes:
                codes.append(m)
    return codes


def fingerprint(code):
    return f"len={len(code)} sha={hashlib.sha256(code.encode()).hexdigest()[:10]}"


def accept_flow(code, label):
    fp = fingerprint(code)
    s, b = call("T2", "POST",
                f"/organization/{ORG1}/invitation/weblink/{code}",
                T2, {}, redact=code)
    print(f"[{label}] accept by T2 ({fp}) -> {s}", flush=True)
    if s in (200, 201, 204):
        call("T2", "GET", f"/organization/{ORG1}/user", T2)
        call("T2", "GET", f"/organization/{ORG1}", T2)
        for suffix in ["", "/projects", "/events", "/authentication"]:
            call("T2", "GET", f"/account/{A1}{suffix}", T2)
        call("T2", "POST",
             f"/organization/{ORG1}/invitation/weblink/{code}",
             T2, {}, redact=code)
    return s


def main():
    codes = []
    for email in INVITEES:
        s, b = call("T1", "POST", f"/organization/{ORG1}/invitation",
                    T1, {"user_email": email})
        codes += find_codes(b)
    s, b = call("T1", "GET", f"/organization/{ORG1}/invitation", T1)
    codes += [c for c in find_codes(b) if c not in codes]
    print(f"codes found via API: {len(codes)} "
          f"{[fingerprint(c) for c in codes]}", flush=True)

    accepted = 0
    for i, code in enumerate(codes[:2]):
        if accept_flow(code, f"invite{i+1}") in (200, 201, 204):
            accepted += 1
    print(f"wrong-account acceptances: {accepted}", flush=True)

    with open("outputs/aiven_invite_probe.json", "w") as f:
        json.dump({"calls": CALLS,
                   "codes_found": len(codes), "accepted": accepted},
                  f, indent=1)
    print(f"DONE calls={len(CALLS)}", flush=True)


if __name__ == "__main__":
    main()
