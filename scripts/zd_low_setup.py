#!/usr/bin/env python3
"""zd_low_setup.py — create the LOW (restricted-candidate) agent in tenant A
and probe the restriction machinery available on this plan.

Bootstraps an ADMIN token from a fresh auth code (same env pattern as
zd_exchange / zd_battery: ZD_AUTH_CODE6 > 5 > ... > base), then:
  1. POST /api/v2/users.json  {name, email, role: "agent"} for the LOW agent
     (skips creation if a user with that email already exists).
  2. GET  /api/v2/custom_roles.json  (does this plan expose custom roles?)
  3. GET  /api/v2/roles.json         (legacy roles endpoint, status only)
Prints statuses and the created user id ONLY; full bodies -> outputs/zd/.
Env: ZD_AUTH_CODE6.. / ZD_CLIENT_ID / ZD_CLIENT_SECRET /
     ZENDESK_SUBDOMAIN / ZENDESK_EMAIL_LOW.
"""
import json, os, sys, urllib.request, urllib.error, urllib.parse

SUB = os.environ.get("ZENDESK_SUBDOMAIN", "bb-mimi05741b")
BASE = f"https://{SUB}.zendesk.com"
LOW_EMAIL = os.environ.get("ZENDESK_EMAIL_LOW",
                           "mimi05741b+zendesk-low@bugcrowdninja.com")
OUT = os.path.join("outputs", "zd")
os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "moka-harness-zd/1.0", "Accept": "application/json"}

def req(method, url, body=None, token=None):
    h = dict(UA)
    data = None
    if token:
        h["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, f"TRANSPORT {type(e).__name__}: {e}"

def save(name, text):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)

def main():
    cid = os.environ["ZD_CLIENT_ID"]
    csec = os.environ["ZD_CLIENT_SECRET"]
    token = None
    for name in ("ZD_AUTH_CODE9", "ZD_AUTH_CODE8", "ZD_AUTH_CODE7", "ZD_AUTH_CODE6", "ZD_AUTH_CODE5",
                 "ZD_AUTH_CODE4",
                 "ZD_AUTH_CODE3", "ZD_AUTH_CODE2", "ZD_AUTH_CODE"):
        code = os.environ.get(name, "").strip()
        if not code:
            continue
        st, body = req("POST", f"{BASE}/oauth/tokens",
                       {"grant_type": "authorization_code", "code": code,
                        "client_id": cid, "client_secret": csec,
                        "redirect_uri": "https://example.com/oauth/callback",
                        "scope": "read write"})
        print(f"[AUTH] code:{name} -> {st}")
        if st == 200:
            token = json.loads(body)["access_token"]
            break
        save(f"auth-error-{name}.json", body)
    if not token:
        print("[FAIL] no admin token")
        return 1

    st, body = req("GET", f"{BASE}/api/v2/users/me.json", token=token)
    me = json.loads(body).get("user", {}) if st == 200 else {}
    print(f"[SHAPE] admin id={me.get('id')} role={me.get('role')}")

    st, body = req("GET", f"{BASE}/api/v2/users/search.json"
                   f"?query={urllib.parse.quote(LOW_EMAIL)}", token=token)
    save("low-search.json", body)
    existing = []
    if st == 200:
        existing = [u for u in json.loads(body).get("users", [])
                    if u.get("email") == LOW_EMAIL]
    if existing:
        u = existing[0]
        print(f"[LOW] already exists id={u.get('id')} role={u.get('role')} "
              f"verified={u.get('verified')} active={u.get('active')}")
    else:
        st, body = req("POST", f"{BASE}/api/v2/users.json",
                       {"user": {"name": "Moka Low",
                                 "email": LOW_EMAIL,
                                 "role": "agent"}}, token=token)
        save("low-create.json", body)
        if st in (200, 201):
            u = json.loads(body).get("user", {})
            print(f"[LOW] created id={u.get('id')} role={u.get('role')} "
                  f"verified={u.get('verified')} active={u.get('active')}")
        else:
            print(f"[LOW] create -> {st} (body in outputs/zd/low-create.json)")

    for path, name in (("/api/v2/custom_roles.json", "custom-roles"),
                       ("/api/v2/roles.json", "roles")):
        st, body = req("GET", BASE + path, token=token)
        save(f"{name}.json", body)
        extra = ""
        if st == 200:
            try:
                d = json.loads(body)
                key = "custom_roles" if "custom_roles" in d else "roles"
                extra = f" count={len(d.get(key, []))}"
            except Exception:
                pass
        print(f"[ROLES] {path} -> {st}{extra}")
    print("[DONE] zd_low_setup complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
