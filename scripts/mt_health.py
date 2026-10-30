import os, base64, urllib.request, urllib.error
org = os.environ["MT_ORG_B"]; key = os.environ["MT_KEY_B"]
req = urllib.request.Request("https://api.moderntreasury.com/api/internal_accounts", method="GET")
req.add_header("Authorization", "Basic " + base64.b64encode(f"{org}:{key}".encode()).decode())
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("HEALTH", r.status)
except urllib.error.HTTPError as e:
    print("HEALTH", e.code)
except Exception as e:
    print("HEALTH -1", str(e)[:120])
print("DONE")
