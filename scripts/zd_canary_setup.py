#!/usr/bin/env python3
"""zd_canary_setup.py — provision two webhook.site canaries (A and B) for the
Zendesk battery. Runs on the Actions runner (clean egress). Writes the token
details to outputs/canary.json (artifact) and prints only the public URLs.
The token UUIDs are canary credentials of minimal sensitivity; the battery
verifies hits by long random marker strings, not by endpoint secrecy.
"""
import json, os, sys, urllib.request

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "Content-Type": "application/json", "Accept": "application/json"}

def create_token():
    body = json.dumps({"default_status": 200, "default_content": "ok",
                       "timeout": 0, "expiry": None}).encode()
    req = urllib.request.Request("https://webhook.site/token", data=body,
                                 headers=UA, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def main():
    out = {}
    for name in ("A", "B"):
        t = create_token()
        out[name] = {
            "uuid": t["uuid"],
            "url": f"https://webhook.site/{t['uuid']}",
            "requests_url": f"https://webhook.site/token/{t['uuid']}/requests?sorting=newest",
        }
        print(f"[CANARY-{name}] url={out[name]['url']}")
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/canary.json", "w") as f:
        json.dump(out, f, indent=2)
    print("[DONE] canary.json written")
    return 0

if __name__ == "__main__":
    sys.exit(main())
