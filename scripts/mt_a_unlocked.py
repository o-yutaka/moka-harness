import os, json, base64, uuid, urllib.request, urllib.error

API = "https://api.moderntreasury.com"
OUT = "outputs"
os.makedirs(OUT, exist_ok=True)

def basic(org, key):
    return "Basic " + base64.b64encode(f"{org}:{key}".encode()).decode()

def call(method, path, org, key, body=None, raw=None, ctype="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", basic(org, key))
    if data is not None:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, str(e)

def save(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2)

org_a = os.environ["MT_ORG_A"]; key_a = os.environ["MT_KEY_A"]
org_b = os.environ["MT_ORG_B"]; key_b = os.environ["MT_KEY_B"]
key_ro = os.environ.get("MT_KEY_A_RO", "")
FLOW_A = "d36e0941-2d74-404a-9447-a45198f85c15"
CP_B = "bb3e7067-a962-4cf3-a85f-c7b7ac59ff4c"

st, b = call("GET", "/api/legal_entities", org_a, key_a)
le_a = None
try:
    arr = json.loads(b)
    if st == 200 and arr: le_a = arr[0]["id"]
except Exception: pass
print("LE_A_LIST", st, "id_found", bool(le_a))
st, b = call("GET", "/api/legal_entities", org_b, key_b)
le_b = None
try:
    arr = json.loads(b)
    if st == 200 and arr: le_b = arr[0]["id"]
except Exception: pass
print("LE_B_LIST", st, "id_found", bool(le_b))
save("le_ids.json", {"le_a": le_a, "le_b": le_b})

st, b = call("GET", f"/api/account_collection_flows/{FLOW_A}", org_a, key_a)
tok = None; cp_a_from_flow = None; flow_status = None
if st == 200:
    try:
        j = json.loads(b); tok = j.get("client_token"); cp_a_from_flow = j.get("counterparty_id"); flow_status = j.get("status")
    except Exception: pass
print("FLOW_A_GET", st, "status", flow_status, "token_present", bool(tok))
save("flow_a.json", {"flow_id": FLOW_A, "status": flow_status, "counterparty_id": cp_a_from_flow, "client_token": tok})

ro_tests = []
def ro(label, method, path, body=None):
    st, b = call(method, path, org_a, key_ro, body)
    ro_tests.append({"label": label, "status": st, "body_head": b[:300]})
    print("RO", label, st)
ro("events_list_ALLOW_expected", "GET", "/api/events")
ro("internal_accounts_DENY_expected", "GET", "/api/internal_accounts")
ro("counterparties_list_DENY_expected", "GET", "/api/counterparties")
ro("payment_orders_list_DENY_expected", "GET", "/api/payment_orders")
ro("acf_get_DENY_expected", "GET", f"/api/account_collection_flows/{FLOW_A}")
ro("counterparty_create_DENY_expected", "POST", "/api/counterparties", {"name": "RO Probe CP", "party_type": "business"})
if cp_a_from_flow:
    ro("acf_create_DENY_expected", "POST", "/api/account_collection_flows", {"counterparty_id": cp_a_from_flow, "payment_types": ["ach"]})
st, b = call("POST", "/api/counterparties", org_a, key_a, {"name": "FullKey Control CP", "party_type": "business"})
print("FULLKEY counterparty_create control", st)
ro_tests.append({"label": "fullkey_counterparty_create_control", "status": st, "body_head": b[:300]})
save("ro_battery.json", ro_tests)

def multipart(file_bytes, filename):
    boundary = "----moka" + uuid.uuid4().hex
    head = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n".encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + file_bytes + tail, f"multipart/form-data; boundary={boundary}"

c6 = []
def doc(label, method, path, org, key, upload=False):
    if upload:
        raw, ctype = multipart(b"moka-c6-probe", "moka-c6.txt")
        st, b = call(method, path, org, key, raw=raw, ctype=ctype)
    else:
        st, b = call(method, path, org, key)
    c6.append({"label": label, "status": st, "body_head": b[:400]})
    print("C6", label, st)

if le_a: doc("control_A_to_LE_A", "POST", f"/api/legal_entities/{le_a}/documents", org_a, key_a, upload=True)
if le_b: doc("cross_A_to_LE_B", "POST", f"/api/legal_entities/{le_b}/documents", org_a, key_a, upload=True)
doc("cross_A_to_CP_B", "POST", f"/api/counterparties/{CP_B}/documents", org_a, key_a, upload=True)
if le_b:
    doc("verify_B_lists_LE_B_docs", "GET", f"/api/legal_entities/{le_b}/documents", org_b, key_b)
    doc("crossread_A_lists_LE_B_docs", "GET", f"/api/legal_entities/{le_b}/documents", org_a, key_a)
doc("verify_B_lists_CP_B_docs", "GET", f"/api/counterparties/{CP_B}/documents", org_b, key_b)
save("c6_docs.json", c6)
print("DONE")
