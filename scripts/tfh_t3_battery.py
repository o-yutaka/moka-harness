#!/usr/bin/env python3
"""TFH T3 battery: does every API-key endpoint match (key -> team -> app)?
Keys come from GitHub Secrets env (TFH_KEY_1 / TFH_KEY_2). App IDs are public
identifiers of our own two test apps. Prints ONLY status + error snippets.
Full bodies -> outputs/tfh-t3-results.json (artifact)."""
import json, os, urllib.request, urllib.error, pathlib

KEY1 = os.environ["TFH_KEY_1"]
KEY2 = os.environ["TFH_KEY_2"]
APP1 = "app_a834cd108ab340e07eaa03ac5fe94f34"   # team tfh probe 1 (key1)
APP2 = "app_71078332900ba4de65ec988a3887cc89"   # team tfh probe 2 (key2)
APPX = "app_00000000000000000000000000000000"   # nonexistent
BASE = "https://developer.world.org"
RESULTS = []

def call(label, method, path, key, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
    req.add_header("Accept", "application/json, text/plain, */*")
    req.add_header("Accept-Language", "en-US,en;q=0.9")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=40) as r:
            text = r.read().decode()
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode()
    except Exception as e:
        status = -1
        text = f"TRANSPORT: {e}"
    snippet = text[:200].replace("\n", " ")
    RESULTS.append({"label": label, "status": status, "body": text[:2000]})
    print(f"[{label}] HTTP {status} :: {snippet}", flush=True)

NOTIF = lambda app: {"app_id": app, "wallet_addresses": [], "title": "probe", "message": "probe"}
ACTION = {"name": "probe-action", "action_description": "probe"}

call("M1 key1->app1 (control)", "GET", f"/api/v2/minikit/app-metadata/{APP1}", KEY1)
call("M2 key1->app2 (CROSS)", "GET", f"/api/v2/minikit/app-metadata/{APP2}", KEY1)
call("M3 key2->app1 (CROSS)", "GET", f"/api/v2/minikit/app-metadata/{APP1}", KEY2)
call("M4 key1->appX (nonexistent)", "GET", f"/api/v2/minikit/app-metadata/{APPX}", KEY1)
call("M5 no-key->app1", "GET", f"/api/v2/minikit/app-metadata/{APP1}", None)

call("N1 key1 notify app1 (control)", "POST", "/api/v2/minikit/send-notification", KEY1, NOTIF(APP1))
call("N2 key1 notify app2 (CROSS)", "POST", "/api/v2/minikit/send-notification", KEY1, NOTIF(APP2))
call("N3 key2 notify app1 (CROSS)", "POST", "/api/v2/minikit/send-notification", KEY2, NOTIF(APP1))
call("N4 key1 notify appX", "POST", "/api/v2/minikit/send-notification", KEY1, NOTIF(APPX))

call("A1 key1 action app1 (control)", "POST", f"/api/v2/create-action?app_id={APP1}", KEY1, dict(ACTION))
call("A2 key1 action app2 (CROSS)", "POST", f"/api/v2/create-action?app_id={APP2}", KEY1, dict(ACTION))
call("A3 key2 action app1 (CROSS)", "POST", f"/api/v2/create-action?app_id={APP1}", KEY2, dict(ACTION))
call("A4 key1 action appX", "POST", f"/api/v2/create-action?app_id={APPX}", KEY1, dict(ACTION))

out = pathlib.Path("outputs")
out.mkdir(exist_ok=True)
(out / "tfh-t3-results.json").write_text(json.dumps(RESULTS, indent=1, ensure_ascii=False))
print("DONE tfh_t3_battery", flush=True)
