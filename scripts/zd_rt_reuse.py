#!/usr/bin/env python3
"""ZD-RT-REUSE: port of the Moneytree MT-1 battery to Zendesk OAuth.

Question: does a JUST-SPENT Zendesk refresh token redeem again
(Moneytree-style), or does rotation kill it immediately?

Prior evidence (zd_battery.py comment): run #674's refresh invalidated
the stored token and run #677 got 400 — but between those runs the
successor was itself used, which does not discriminate between
(a) invalidation on spend and (b) invalidation on successor use.
This battery discriminates:
  S1 exchange head RT0 -> pair1 (AT1, RT1)          [RT0 spent]
  S2 IMMEDIATELY replay RT0 (nothing else used yet) -> 200 = BREAK
  S3 if S2==200: replay RT0 again; refresh RT1 (family survival?)
  S4 if S2!=200: present AT1 (users/me), replay RT0 -> still dead?
Chain safety: the final confirmed-live head of the MAIN lineage is
written back to ZD_REFRESH_TOKEN via zb.self_update_secret.
Prints statuses and sha fingerprints only — never token values.
"""
import json
import os
import sys
import hashlib
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zd_battery as zb  # noqa: E402

SUB = os.environ.get("ZENDESK_SUBDOMAIN", "bb-mimi05741b")
OUT = Path(os.environ.get("ZD_OUT", "outputs/zd")) / "rt-reuse"
OUT.mkdir(parents=True, exist_ok=True)
CID = os.environ.get("ZD_CLIENT_ID", "")
CSEC = os.environ.get("ZD_CLIENT_SECRET", "")
URL = f"https://{SUB}.zendesk.com/oauth/tokens"
UA = getattr(zb, "UA", "moka-harness")


def fp(v):
    return hashlib.sha256(v.encode()).hexdigest()[:12]


def exchange(rt):
    body = {"grant_type": "refresh_token", "refresh_token": rt,
            "client_id": CID, "client_secret": CSEC, "scope": "read write"}
    req = urllib.request.Request(
        URL, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"neterr": type(e).__name__}


def me(at):
    req = urllib.request.Request(
        f"https://{SUB}.zendesk.com/api/v2/users/me.json", method="GET",
        headers={"Authorization": f"Bearer {at}", "Accept": "application/json",
                 "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def main():
    if not (CID and CSEC):
        print("REFUSE no client credentials")
        return
    head_name, rt0 = None, ""
    for name in ("ZD_REFRESH_TOKEN", "ZD_REFRESH_TOKEN2", "ZD_REFRESH_TOKEN3"):
        v = os.environ.get(name, "").strip()
        if v:
            head_name, rt0 = name, v
            break
    if not rt0:
        print("REFUSE no refresh head in env")
        return
    print(f"START head={head_name} fp={fp(rt0)}")
    log = {}

    st, p1 = exchange(rt0)
    print(f"S1 exchange RT0 -> {st}")
    log["s1"] = st
    if st != 200:
        print("ABORT S1 failed; chain untouched, no writeback needed")
        (OUT / "result.json").write_text(json.dumps(log, indent=1))
        print("DONE")
        return
    at1, rt1 = p1.get("access_token", ""), p1.get("refresh_token", "")
    print(f"S1 pair1 RT fp={fp(rt1) if rt1 else '-'}")
    # Until writeback, the emergency head is rt1.
    live_head = rt1

    st2, p2 = exchange(rt0)
    print(f"S2 immediate replay RT0 -> {st2} "
          f"{'TOKEN-ISSUED' if st2 == 200 else p2.get('error', '')}")
    log["s2"] = st2

    if st2 == 200:
        # Moneytree-class break. Map the shape.
        rtb = p2.get("refresh_token", "")
        stb, _pb = exchange(rt0)
        print(f"S3 replay RT0 again -> {stb}")
        log["s3_replay_again"] = stb
        stf, pf = exchange(rt1)
        print(f"S3 family: refresh RT1 (main lineage) -> {stf}")
        log["s3_family_rt1"] = stf
        if stf == 200 and pf.get("refresh_token"):
            live_head = pf["refresh_token"]
        elif rtb:
            live_head = rtb
        stm = me(p2.get("access_token", ""))
        print(f"S3 branch AT users/me -> {stm}")
        log["s3_branch_me"] = stm
        print("VERDICT BROKEN spent RT redeems again immediately")
        log["verdict"] = "BROKEN"
    else:
        stm = me(at1)
        print(f"S4 AT1 users/me -> {stm}")
        log["s4_me"] = stm
        st5, _p5 = exchange(rt0)
        print(f"S4 replay RT0 after AT1 use -> {st5}")
        log["s4_replay_after_use"] = st5
        print("VERDICT HELD spent RT stays dead (immediate invalidation)")
        log["verdict"] = "HELD"

    if live_head:
        print(f"WRITEBACK head fp={fp(live_head)}")
        zb.self_update_secret("ZD_REFRESH_TOKEN", live_head)
        log["writeback_fp"] = fp(live_head)
    (OUT / "result.json").write_text(json.dumps(log, indent=1))
    print("DONE")


if __name__ == "__main__":
    main()
