#!/usr/bin/env python3
"""zd_canary_b2 — provision a DIFFERENT-DOMAIN canary B for ZD-3 Leg A.

ZD-3's domainWhitelist test needs canary A (webhook.site) and canary B on
different domains, otherwise the whitelist cannot discriminate. Tries
hookbin first, then requestbin.net. Writes the resulting URLs ONLY into
the outputs artifact (canary-b2.env); stdout carries status lines only.
"""
import json
import os
import urllib.request
import urllib.error
from pathlib import Path

OUT = Path(os.environ.get("ZD_OUT", "outputs/zd"))
OUT.mkdir(parents=True, exist_ok=True)
UA = {"User-Agent": "moka-zd-canary/1.0"}


def req(method, url, data=None, ctype="application/json"):
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method,
                               headers={**UA, "Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"


def try_hookbin():
    st, raw = req("POST", "https://hookbin.com/api/bins", {})
    print(f"[B2] hookbin create -> {st}")
    if st not in (200, 201):
        return None
    try:
        d = json.loads(raw)
    except Exception:
        print("[B2] hookbin response not JSON")
        return None
    bin_id = d.get("id") or d.get("bin_id") or d.get("name")
    if not bin_id:
        print(f"[B2] hookbin JSON keys: {sorted(d.keys())}")
        return None
    return {
        "provider": "hookbin",
        "url": f"https://hookbin.com/{bin_id}",
        "poll": f"https://hookbin.com/api/bins/{bin_id}/requests",
    }


def try_requestbin():
    st, raw = req("POST", "https://requestbin.net/api/v1/bins",
                  {"private": "false"})
    print(f"[B2] requestbin create -> {st}")
    if st not in (200, 201):
        return None
    try:
        d = json.loads(raw)
    except Exception:
        print("[B2] requestbin response not JSON")
        return None
    name = d.get("name")
    if not name:
        print(f"[B2] requestbin JSON keys: {sorted(d.keys())}")
        return None
    return {
        "provider": "requestbin.net",
        "url": f"https://requestbin.net/r/{name}",
        "poll": f"https://requestbin.net/api/v1/bins/{name}/requests",
    }


def main():
    got = try_hookbin() or try_requestbin()
    if not got:
        print("REFUSED: no different-domain canary could be provisioned")
        return 2
    # Sanity: poll endpoint answers (may be an empty list at first).
    st, raw = req("GET", got["poll"])
    print(f"[B2] poll sanity -> {st} bytes={len(raw)}")
    env = (f"CANARY_B_URL={got['url']}\n"
           f"CANARY_B_POLL={got['poll']}\n"
           f"# provider: {got['provider']}\n")
    (OUT / "canary-b2.env").write_text(env)
    print(f"[B2] provider={got['provider']} saved to artifact")
    print("[DONE] zd_canary_b2 complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
