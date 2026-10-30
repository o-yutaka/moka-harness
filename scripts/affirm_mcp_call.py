#!/usr/bin/env python3
"""Affirm MCP battery 2 — actually CALL the tools on sandbox.affirm.com.
Unauthenticated. One process: initialize (capture Mcp-Session-Id header if
issued), then tools/call get_checkout with empty args, resources/list, and
tools/call get_promos. Full bodies + headers saved to outputs/affirm-mcp2."""
import json, os, re, subprocess

URL = "https://sandbox.affirm.com/api/pba/v1/mcp"
OUT = "outputs/affirm-mcp2"
os.makedirs(OUT, exist_ok=True)

def rpc(name, payload, session=None):
    cmd = ["curl", "-s", "-m", "30", "-X", "POST",
           "-H", "Content-Type: application/json",
           "-H", "Accept: application/json, text/event-stream",
           "-D", "-", "-d", json.dumps(payload)]
    if session:
        cmd += ["-H", f"Mcp-Session-Id: {session}"]
    cmd.append(URL)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    head, _, body = out.partition("\r\n\r\n")
    if not body:
        head, _, body = out.partition("\n\n")
    status = 0
    m = re.search(r"HTTP/\S+ (\d+)", head)
    if m:
        status = int(m.group(1))
    sid = None
    m2 = re.search(r"(?i)mcp-session-id:\s*(\S+)", head)
    if m2:
        sid = m2.group(1).strip()
    with open(os.path.join(OUT, name + ".txt"), "w") as f:
        f.write(head + "\n\n" + body)
    # SSE framing: take the last data: line if present
    data = body
    for line in body.splitlines():
        if line.startswith("data:"):
            data = line[5:].strip()
    print(f"{name}: HTTP {status} session={sid} :: {data[:250]}")
    return sid, data

sid, _ = rpc("01_initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-03-26", "capabilities": {},
               "clientInfo": {"name": "moka-probe", "version": "0.1"}}})
rpc("02_initialized_note", {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
rpc("03_call_get_checkout", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {"name": "get_checkout", "arguments": {}}}, sid)
rpc("04_resources_list", {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}}, sid)
rpc("05_call_get_promos", {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
    "params": {"name": "get_promos", "arguments": {"amount": 100}}}, sid)
print("DONE")
