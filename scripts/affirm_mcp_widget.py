#!/usr/bin/env python3
"""Affirm MCP battery 3 — read the checkout-widget resource in full.
Unauthenticated resources/read for ui://affirm-mcp/checkout-widget.
Full body saved to outputs/affirm-mcp3/; the log prints only the body's
length, the URL hosts/paths it references, and counts of key-like tokens."""
import json, os, re, subprocess

URL = "https://sandbox.affirm.com/api/pba/v1/mcp"
OUT = "outputs/affirm-mcp3"
os.makedirs(OUT, exist_ok=True)

def rpc(name, payload):
    cmd = ["curl", "-s", "-m", "30", "-X", "POST",
           "-H", "Content-Type: application/json",
           "-H", "Accept: application/json, text/event-stream",
           "-d", json.dumps(payload), URL]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    data = out
    for line in out.splitlines():
        if line.startswith("data:"):
            data = line[5:].strip()
    with open(os.path.join(OUT, name + ".txt"), "w") as f:
        f.write(out)
    return data

rpc("01_initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-03-26", "capabilities": {},
               "clientInfo": {"name": "moka-probe", "version": "0.1"}}})
body = rpc("02_read_widget", {"jsonrpc": "2.0", "id": 2, "method": "resources/read",
    "params": {"uri": "ui://affirm-mcp/checkout-widget"}})
print("WIDGET_BODY_CHARS:", len(body))
hosts = sorted(set(re.findall(r"https?://([a-zA-Z0-9.-]+)(/[a-zA-Z0-9._~:/?#@!$&'()*+,;=-]*)?", body)))
for h in hosts[:40]:
    print("REF:", h[0] + (h[1] or "")[:80])
print("script_src_count:", len(re.findall(r"<script", body)))
print("postMessage_count:", body.count("postMessage"))
print("public_key_like:", len(re.findall(r"public_key|publicKey|api_key", body)))
print("DONE")
