#!/usr/bin/env python3
"""ZD-3 canary B listener: subscribe to a smee.io channel via SSE and record
every delivered event to outputs/zd_smee_listen/events.jsonl.

Usage: zd_smee_listen.py <channel_url> <hold_seconds>
Prints [LISTEN]/[EVENT] markers; ends with [DONE] events=N needle_seen=X.
Needle = the ZD-3 dummy secret value; grading reads the artifact, not stdout.
"""
import json
import os
import sys
import time
import urllib.request

NEEDLE = "ZD3DUMMYSECRET-7d3a91c4"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept": "text/event-stream"}


def main():
    channel = sys.argv[1]
    hold = int(sys.argv[2]) if len(sys.argv) > 2 else 1800
    outdir = os.path.join("outputs", "zd_smee_listen")
    os.makedirs(outdir, exist_ok=True)
    events_path = os.path.join(outdir, "events.jsonl")
    deadline = time.time() + hold
    count = 0
    needle_seen = False
    print(f"[LISTEN] channel={channel} hold={hold}s", flush=True)
    with open(events_path, "a", buffering=1) as out:
        while time.time() < deadline:
            try:
                req = urllib.request.Request(channel, headers=UA)
                resp = urllib.request.urlopen(req, timeout=75)
                print("[LISTEN] connected", flush=True)
                buf = []
                while time.time() < deadline:
                    line = resp.readline()
                    if not line:
                        break
                    line = line.decode("utf-8", "replace").rstrip("\r\n")
                    if line == "":
                        if buf:
                            data = "\n".join(buf)
                            buf = []
                            if data and data != "ready":
                                count += 1
                                if NEEDLE in data:
                                    needle_seen = True
                                out.write(json.dumps(
                                    {"t": time.time(), "data": data}) + "\n")
                                print(f"[EVENT] #{count} len={len(data)} "
                                      f"needle={NEEDLE in data}", flush=True)
                        continue
                    if line.startswith("data:"):
                        buf.append(line[5:].lstrip())
            except Exception as e:  # reconnect until deadline
                print(f"[LISTEN] drop: {type(e).__name__}: {e}", flush=True)
                time.sleep(3)
    print(f"[DONE] events={count} needle_seen={needle_seen}", flush=True)


if __name__ == "__main__":
    main()
