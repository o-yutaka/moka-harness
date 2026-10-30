#!/usr/bin/env python3
"""MT Org B: mint a fresh account_collection_flow, delete it, re-read it.
Full bodies go ONLY to outputs/mt_flow2.json (artifact). Stdout is redacted."""
import os, json, hashlib, urllib.request, urllib.error, base64

BASE = "https://app.moderntreasury.com"
ORG = os.environ.get("MT_ORG_B", "")
KEY = os.environ.get("MT_KEY_B", "")
CP = "ba89cac0-4103-43c9-a019-454a555cd58c"

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    tok = base64.b64encode(f"{ORG}:{KEY}".encode()).decode()
    r.add_header("Authorization", "Basic " + tok)
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, f"ERR {e}"

def summ(tag, status, body):
    info = {"tag": tag, "status": status}
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            if "id" in obj: info["id"] = obj["id"]
            if "status" in obj: info["flow_status"] = obj["status"]
            t = obj.get("client_token")
            if isinstance(t, str):
                info["client_token"] = {"prefix": t[:10], "len": len(t), "sha12": hashlib.sha256(t.encode()).hexdigest()[:12]}
            if "errors" in obj: info["errors"] = json.dumps(obj["errors"])[:200]
    except Exception:
        info["body_prefix"] = body[:160]
    print(json.dumps(info))

def main():
    if not (ORG and KEY):
        print(json.dumps({"fatal": "MT_ORG_B/MT_KEY_B missing"})); return
    results = {}
    s, b = req("POST", "/api/account_collection_flows", {"counterparty_id": CP, "payment_types": ["ach"]})
    results["create"] = {"status": s, "body": b}; summ("create", s, b)
    fid = None
    try: fid = json.loads(b)["id"]
    except Exception: pass
    if fid:
        s, b = req("DELETE", f"/api/account_collection_flows/{fid}")
        results["delete"] = {"status": s, "body": b}; summ("delete", s, b)
        s, b = req("GET", f"/api/account_collection_flows/{fid}")
        results["get_after"] = {"status": s, "body": b}; summ("get_after", s, b)
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/mt_flow2.json", "w") as f:
        json.dump(results, f, indent=2)
    print("DONE")

if __name__ == "__main__":
    main()
