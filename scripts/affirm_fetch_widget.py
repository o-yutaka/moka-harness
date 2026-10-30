#!/usr/bin/env python3
"""Fetch the Affirm MCP widget's JS (cdn1.affirm.com/assets/mcp_widget/master/checkout.js)
into outputs/affirm-widget/ and print structural summaries only."""
import hashlib, os, re, subprocess

OUT = "outputs/affirm-widget"
os.makedirs(OUT, exist_ok=True)
URL = "https://cdn1.affirm.com/assets/mcp_widget/master/checkout.js"
path = os.path.join(OUT, "checkout.js")
subprocess.run(["curl", "-sL", "-m", "60", "-o", path, URL], check=False)
data = open(path, "rb").read() if os.path.exists(path) else b""
text = data.decode("utf-8", "ignore")
print("BYTES:", len(data))
print("SHA256:", hashlib.sha256(data).hexdigest())
paths = sorted(set(re.findall(r"['\"](/api/[a-zA-Z0-9._~:/?#@!$&'()*+,;=-]+)['\"]", text)))
for p in paths[:40]:
    print("APIPATH:", p)
print("postMessage_count:", text.count("postMessage"))
print("openai_refs:", text.count("openai"))
print("skybridge_refs:", text.count("skybridge"))
print("callTool_refs:", text.count("callTool"))
print("checkout_token_refs:", text.count("checkout_token"))
print("DONE")
