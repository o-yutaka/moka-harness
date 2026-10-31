#!/usr/bin/env python3
"""TFH T3b battery: create-action (fixed body), GraphQL proxy cross-team reads,
transaction-by-id error shapes. Keys from env TFH_KEY_1 / TFH_KEY_2.
Prints ONLY status + snippets. Full bodies -> outputs/tfh-t3b-results.json."""
import json, os, urllib.request, urllib.error, pathlib

KEY1 = os.environ["TFH_KEY_1"]
KEY2 = os.environ["TFH_KEY_2"]
APP1 = "app_a834cd108ab340e07eaa03ac5fe94f34"   # team1
APP2 = "app_71078332900ba4de65ec988a3887cc89"   # team2
APPX = "app_00000000000000000000000000000000"
TEAM1 = "team_155f3fae65df2a77672767978a165586"
TEAM2 = "team_82a0ff2058296879f791c86de56f14fa"
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
            text = r.read().decode(); status = r.status
    except urllib.error.HTTPError as e:
        status = e.code; text = e.read().decode()
    except Exception as e:
        status = -1; text = f"TRANSPORT: {e}"
    RESULTS.append({"label": label, "status": status, "body": text[:2000]})
    print(f"[{label}] HTTP {status} :: {text[:200].replace(chr(10),' ')}", flush=True)

# create-action with schema-valid body (action required; RP gate expected on control)
ACT = {"action": "probe-action"}
call("A1 key1 action app1 (control)", "POST", f"/api/v2/create-action/{APP1}", KEY1, dict(ACT))
call("A2 key1 action app2 (CROSS)", "POST", f"/api/v2/create-action/{APP2}", KEY1, dict(ACT))
call("A3 key2 action app1 (CROSS)", "POST", f"/api/v2/create-action/{APP1}", KEY2, dict(ACT))
call("A4 key1 action appX", "POST", f"/api/v2/create-action/{APPX}", KEY1, dict(ACT))

# GraphQL proxy: by_pk reads own vs cross
def gql(label, key, query, var_id):
    call(label, "POST", "/api/v1/graphql", key, {"query": query, "variables": {"id": var_id}})
QAPP = "query($id:String!){app_by_pk(id:$id){id}}"
QTEAM = "query($id:String!){team_by_pk(id:$id){id}}"
gql("G1 key1 app1 (control)", KEY1, QAPP, APP1)
gql("G2 key1 app2 (CROSS)", KEY1, QAPP, APP2)
gql("G3 key2 app1 (CROSS)", KEY2, QAPP, APP1)
gql("G4 key1 team1 (control)", KEY1, QTEAM, TEAM1)
gql("G5 key1 team2 (CROSS)", KEY1, QTEAM, TEAM2)

# transaction-by-id: error shapes only (no real transaction exists)
TX = "00000000-0000-0000-0000-000000000000"
call("T1 no-key tx app1", "GET", f"/api/v2/minikit/transaction/{TX}?app_id={APP1}&type=payment", None)
call("T2 key1 tx app1", "GET", f"/api/v2/minikit/transaction/{TX}?app_id={APP1}&type=payment", KEY1)
call("T3 key1 tx app2 (cross-shape)", "GET", f"/api/v2/minikit/transaction/{TX}?app_id={APP2}&type=payment", KEY1)

pathlib.Path("outputs").mkdir(exist_ok=True)
pathlib.Path("outputs/tfh-t3b-results.json").write_text(json.dumps(RESULTS, indent=1))
print("DONE tfh_t3b_battery", flush=True)
