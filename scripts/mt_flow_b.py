#!/usr/bin/env python3
"""MT Org B flow minter (GitHub Actions lane). Full bodies go ONLY to outputs/mt_flow_b.json (artifact). Stdout is redacted."""
import os, json, hashlib, urllib.request, urllib.error, base64

BASE = "https://app.moderntreasury.com"
ORG = os.environ.get("MT_ORG_B", "")
KEY = os.environ.get("MT_KEY_B", "")
PHASE1_FLOW_B = "9e7b0c9e-62ee-4d54-aba3-17b32a176cbf"

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

def redact(tag, status, body):
    info = {"tag": tag, "status": status}
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            info["keys"] = sorted(obj.keys())
            if "id" in obj: info["id"] = obj["id"]
            if "status" in obj: info["flow_status"] = obj["status"]
            t = obj.get("client_token")
            if isinstance(t, str):
                info["client_token"] = {"prefix": t[:10], "len": len(t), "sha12": hashlib.sha256(t.encode()).hexdigest()[:12]}
        else:
            info["body_prefix"] = body[:200]
    except Exception:
        info["body_prefix"] = body[:200]
    print(json.dumps(info))

def main():
    if not (ORG and KEY):
        print(json.dumps({"fatal": "MT_ORG_B/MT_KEY_B missing"})); return
    results = {}
    s, b = req("GET", f"/api/account_collection_flows/{PHASE1_FLOW_B}")
    results["phase1_get"] = {"status": s, "body": b}; redact("phase1_get", s, b)
    s, b = req("POST", "/api/account_collection_flows", {})
    results["create_empty"] = {"status": s, "body": b}; redact("create_empty", s, b)
    if s >= 400:
        s2, b2 = req("GET", "/api/counterparties")
        results["counterparties"] = {"status": s2, "body": b2}; redact("counterparties", s2, b2)
        try:
            cps = json.loads(b2)
            if isinstance(cps, list) and cps:
                s3, b3 = req("POST", "/api/account_collection_flows", {"counterparty_id": cps[0]["id"]})
                results["create_cp"] = {"status": s3, "body": b3}; redact("create_cp", s3, b3)
        except Exception as e:
            print(json.dumps({"counterparty_retry_error": str(e)}))
    s, b = req("POST", "/api/payment_flows", {})
    results["payment_flow_create"] = {"status": s, "body": b}; redact("payment_flow_create", s, b)
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/mt_flow_b.json", "w") as f:
        json.dump(results, f, indent=2)
    print("DONE")

if __name__ == "__main__":
    main()
