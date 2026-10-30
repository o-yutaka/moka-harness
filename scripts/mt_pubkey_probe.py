#!/usr/bin/env python3
"""Does the publishable key (or its embedded suffix) double as an API credential? Redacted stdout."""
import os, json, base64, urllib.request, urllib.error

BASE = "https://app.moderntreasury.com"
ORG = os.environ.get("MT_ORG_B", "")
KEY = os.environ.get("MT_KEY_B", "")
PUB = "publishable-test-MzBlZjZlOGItNDJhMC00NzA5LTk1ZGUtNjA5NGNmM2UwN2M1OmJhUVVHQVdnRHN6c2hZcGZuMXlkSHpWa1d0VmdxZ21NeXR2d1VLdmk2M1VBVm5xZlZzeW5FZUxpRk1LcHdFUms="

def req(auth_header):
    r = urllib.request.Request(BASE + "/api/internal_accounts", method="GET")
    r.add_header("Authorization", auth_header)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, len(body)
    except urllib.error.HTTPError as e:
        return e.code, len(e.read().decode())
    except Exception as e:
        return -1, str(e)

def basic(u, p):
    return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()

def main():
    if not (ORG and KEY):
        print(json.dumps({"fatal": "MT_ORG_B/MT_KEY_B missing"})); return
    raw = PUB.split("-", 2)[2]
    decoded = base64.b64decode(raw).decode()
    org_in_key, suffix = decoded.split(":", 1)
    print(json.dumps({"decoded_org_matches": org_in_key == ORG, "suffix_len": len(suffix)}))
    tests = [
        ("control org+key", basic(ORG, KEY)),
        ("org + pubkey_suffix", basic(ORG, suffix)),
        ("org + full_publishable", basic(ORG, PUB)),
        ("suffix + key", basic(suffix, KEY)),
        ("bearer publishable", "Bearer " + PUB),
        ("bearer suffix", "Bearer " + suffix),
    ]
    for tag, hdr in tests:
        s, n = req(hdr)
        print(json.dumps({"tag": tag, "status": s, "body_len": n}))
    print("DONE")

if __name__ == "__main__":
    main()
