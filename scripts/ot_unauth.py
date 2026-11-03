import urllib.request, urllib.error, json, time

BASE = "https://pentest-app.onetrust.com"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"}

def probe(name, method, path, data=None, headers=None):
    h = dict(UA)
    if headers: h.update(headers)
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            body = r.read().decode("utf-8", "replace")[:300]
            print(f"PROBE {name} {r.status} {time.time()-t:.1f}s {body!r}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        print(f"PROBE {name} {e.code} {time.time()-t:.1f}s {body!r}")
    except Exception as e:
        print(f"PROBE {name} ERROR {type(e).__name__} {e} after {time.time()-t:.1f}s")

print("START ot_unauth")
probe("get_userinfo_noauth", "GET", "/api/access/v1/users/current/legacy")
probe("get_tenants_context_noauth", "GET", "/api/access/v1/tenants/context")
probe("token_password_garbage", "POST", "/api/access/v1/oauth/token",
      data=b"grant_type=password&username=nobody%40example.com&password=wrongpass&client_id=onetrust",
      headers={"Content-Type": "application/x-www-form-urlencoded"})
probe("token_clientcred_garbage", "POST", "/api/access/v1/oauth/token",
      data=b"grant_type=client_credentials&client_id=deadbeef&client_secret=deadbeef",
      headers={"Content-Type": "application/x-www-form-urlencoded"})
probe("token_unsupported_grant", "POST", "/api/access/v1/oauth/token",
      data=b"grant_type=authorization_code&code=deadbeef&client_id=onetrust",
      headers={"Content-Type": "application/x-www-form-urlencoded"})
probe("userinfo_querykey_garbage", "GET", "/api/access/v1/users/current/legacy?Authorization=Bearer+garbagekey123")
print("DONE ot_unauth")
