#!/usr/bin/env python3
"""Affirm sandbox MCP probe — does sandbox.affirm.com expose /api/pba/v1/mcp
(the production host has a directory-listed MCP server 'pba-mcp')?
Unauthenticated GET + JSON-RPC initialize/tools/list. Full bodies saved."""
import json, os, subprocess

BASE = "https://sandbox.affirm.com"
OUT = "outputs/affirm-mcp"
os.makedirs(OUT, exist_ok=True)

def call(name, method, path, data=None, headers=None):
    cmd = ["curl", "-s", "-m", "30", "-X", method, "-H", "Accept: application/json", "-w", "\n%{http_code}"]
    for h in (headers or []):
        cmd += ["-H", h]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    cmd.append(BASE + path)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    raw, _, code = out.rpartition("\n")
    status = int(code) if code.isdigit() else 0
    with open(os.path.join(OUT, name + ".txt"), "w") as f:
        f.write(raw)
    print(f"{name}: HTTP {status} :: {raw[:200]}")

call("01_get_mcp", "GET", "/api/pba/v1/mcp")
call("02_rpc_initialize", "POST", "/api/pba/v1/mcp",
     data={"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                      "clientInfo": {"name": "moka-probe", "version": "0.1"}}})
call("03_rpc_tools_list", "POST", "/api/pba/v1/mcp",
     data={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
print("DONE")
