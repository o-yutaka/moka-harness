#!/usr/bin/env python3
"""Zendesk OAuth authorization-code exchange + shape probe (Actions lane).

Env: ZD_AUTH_CODE, ZD_CLIENT_ID, ZD_CLIENT_SECRET,
     ZD_SUBDOMAIN (default bb-mimi05741b), ZD_REDIRECT_URI.
Stdout: statuses, field names, lengths ONLY. Full bodies -> outputs/zd/.
On success the access/refresh tokens are written ONLY to outputs/zd/token.json
(artifact); a scrub pass removes client-secret/code strings from outputs.
"""
import json, os, sys, urllib.request, urllib.error

SUB = os.environ.get("ZD_SUBDOMAIN", "bb-mimi05741b")
BASE = f"https://{SUB}.zendesk.com"
OUT = os.path.join("outputs", "zd")
os.makedirs(OUT, exist_ok=True)

def scrub():
    secrets = [os.environ.get("ZD_CLIENT_SECRET", ""), os.environ.get("ZD_AUTH_CODE", "")]
    for root, _dirs, files in os.walk(OUT):
        for fn in files:
            p = os.path.join(root, fn)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            orig = data
            for s in secrets:
                if s and s.encode() in data:
                    data = data.replace(s.encode(), b"[SCRUBBED]")
            if data != orig:
                open(p, "wb").write(data)
                print(f"[SCRUB] scrubbed {p}")

def req(method, url, body=None, headers=None):
    data = None
    h = {"User-Agent": "moka-harness-zd/1.0", "Accept": "application/json"}
    if headers:
        h.update(headers)
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # transport
        return -1, f"TRANSPORT {type(e).__name__}: {e}"

def main():
    code = os.environ.get("ZD_AUTH_CODE", "")
    cid = os.environ.get("ZD_CLIENT_ID", "")
    secret = os.environ.get("ZD_CLIENT_SECRET", "")
    redirect = os.environ.get("ZD_REDIRECT_URI", "https://example.com/oauth/callback")
    if not (code and cid and secret):
        print("REFUSE: missing ZD_AUTH_CODE / ZD_CLIENT_ID / ZD_CLIENT_SECRET")
        return 2
    status, text = req("POST", f"{BASE}/oauth/tokens", body={
        "grant_type": "authorization_code",
        "code": code,
        "client_id": cid,
        "client_secret": secret,
        "redirect_uri": redirect,
        "scope": "read write",
    })
    print(f"[EXCHANGE] POST /oauth/tokens -> {status}")
    try:
        payload = json.loads(text)
    except Exception:
        payload = None
    if status != 200 or not payload or "access_token" not in payload:
        keys = sorted(payload.keys()) if isinstance(payload, dict) else "non-json"
        print(f"[EXCHANGE] FAILED keys={keys}")
        open(os.path.join(OUT, "exchange-error.json"), "w").write(text[:4000])
        scrub()
        return 1
    open(os.path.join(OUT, "token.json"), "w").write(json.dumps(payload, indent=1))
    tok = payload["access_token"]
    print(f"[EXCHANGE] OK token_len={len(tok)} fields={sorted(payload.keys())}")
    # shape probe: who does this token act as?
    st2, text2 = req("GET", f"{BASE}/api/v2/users/me",
                     headers={"Authorization": f"Bearer {tok}"})
    print(f"[SHAPE] GET /api/v2/users/me -> {st2}")
    if st2 == 200:
        me = json.loads(text2)
        u = me.get("user", {})
        safe = {k: u.get(k) for k in ("id", "email", "role", "name", "verified", "active")}
        print(f"[SHAPE] user={json.dumps(safe, ensure_ascii=False)}")
        open(os.path.join(OUT, "me.json"), "w").write(text2)
    scrub()
    print("DONE zd_exchange")
    return 0

if __name__ == "__main__":
    sys.exit(main())
