#!/usr/bin/env python3
"""zd_smee_test — prove the smee.io live-observer model on Actions egress.

Creates a channel, subscribes to its SSE stream in a thread, POSTs a
needle to the channel, and reports whether the needle came back through
the stream. Status lines only.
"""
import json
import threading
import time
import urllib.request
import urllib.error

UA = {"User-Agent": "moka-zd-smee/1.0"}
NEEDLE = "SMEE-NEEDLE-ACTIONS-1"
buf = []
stop = False


def subscribe(url):
    global stop
    req = urllib.request.Request(url, headers={**UA,
                                     "Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            for raw in r:
                if stop:
                    break
                line = raw.decode("utf-8", "replace").strip()
                if line:
                    buf.append(line)
    except Exception as e:
        print(f"[SMEE] subscribe ended: {type(e).__name__}")


def main():
    global stop
    req = urllib.request.Request("https://smee.io/new", headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            channel = r.geturl()
    except Exception as e:
        print(f"REFUSED: channel create failed {type(e).__name__}")
        return 2
    print(f"[SMEE] channel host ok: {channel.split('/')[2]}")
    t = threading.Thread(target=subscribe, args=(channel,), daemon=True)
    t.start()
    time.sleep(8)
    body = json.dumps({"key": NEEDLE}).encode()
    req = urllib.request.Request(channel, data=body, method="POST",
                                 headers={**UA,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"[SMEE] post -> {r.status}")
    except urllib.error.HTTPError as e:
        print(f"[SMEE] post -> {e.code}")
    except Exception as e:
        print(f"[SMEE] post failed {type(e).__name__}")
    time.sleep(10)
    stop = True
    joined = "\n".join(buf)
    print(f"[SMEE] stream lines={len(buf)} needle_seen={NEEDLE in joined}")
    print("[DONE] zd_smee_test complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
