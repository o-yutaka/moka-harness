#!/usr/bin/env python3
"""zd_low_mint — exchange a FRESH authorization code for the LOW agent
(mimi05741b+zendesk-low@bugcrowdninja.com) and save the resulting token
JSON into the outputs artifact (zd/bootstrap-low-token.json) so the
refresh token can be harvested into a GitHub Secret afterwards.

Prints ONLY redacted status lines (public Actions logs).
Env: ZD_AUTH_CODE_LOW, ZD_CLIENT_ID, ZD_CLIENT_SECRET,
     ZENDESK_SUBDOMAIN, ZD_OUT.
"""
import json
import os
import sys
import urllib.request
import urllib.error

SUB = os.environ.get("ZENDESK_SUBDOMAIN", "bb-mimi05741b")
OUT = os.environ.get("ZD_OUT", "outputs/zd")


def post_json(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": "moka-harness/zd-low-mint"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": type(e).__name__}


def main():
    code = os.environ.get("ZD_AUTH_CODE_LOW", "").strip()
    cid = os.environ.get("ZD_CLIENT_ID", "").strip()
    secret = os.environ.get("ZD_CLIENT_SECRET", "").strip()
    if not code or not cid or not secret:
        print("REFUSED: missing ZD_AUTH_CODE_LOW / client credentials",
              flush=True)
        return 2
    status, body = post_json(
        f"https://{SUB}.zendesk.com/oauth/tokens",
        {"grant_type": "authorization_code",
         "code": code,
         "client_id": cid,
         "client_secret": secret,
         "redirect_uri": "https://example.com/oauth/callback",
         "scope": "read write"})
    print(f"[LOWAUTH] code exchange -> {status}", flush=True)
    if status != 200 or "access_token" not in body:
        err = body.get("error", "")
        print(f"[LOWAUTH] error={err}", flush=True)
        print("REFUSED: LOW exchange failed", flush=True)
        return 1
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "bootstrap-low-token.json")
    with open(path, "w") as fh:
        json.dump(body, fh)
    print(f"[LOWAUTH] scope={body.get('scope')} "
          f"expires_in={body.get('expires_in')} "
          f"refresh_expires_in={body.get('refresh_token_expires_in')}",
          flush=True)
    # Confirm identity: this token must belong to the LOW agent.
    req = urllib.request.Request(
        f"https://{SUB}.zendesk.com/api/v2/users/me.json",
        headers={"Authorization": f"Bearer {body['access_token']}",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            me = json.loads(r.read().decode()).get("user", {})
        print(f"[LOWME] id={me.get('id')} role={me.get('role')} "
              f"email={me.get('email')}", flush=True)
    except Exception as e:
        print(f"[LOWME] check failed: {type(e).__name__}", flush=True)
    print("[DONE] zd_low_mint complete", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
