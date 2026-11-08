#!/usr/bin/env python3
"""Midas mTBILL feed — on-chain trajectory check (Cantina #394 dispute
evidence, axis 3). Read-only eth_call against public RPCs.

Reads the DataFeed's latestRoundData and walks back recent rounds to
measure: current answer, per-round and per-day growth, remaining
distance to the deployed ceiling (1.11, on-chain verified 2026-10-30
in the original report), and a conditional projection of days to the
ceiling at the measured velocity. Also reads the CustomFeed's latest
round for cross-checking the push cadence.

Selectors (canonical, AggregatorV3Interface):
  latestRoundData()      0xfeaf968c
  getRoundData(uint80)   0x9a6fc8f5
Answers are 8-decimal fixed point per the original report's reading.
Stdout: numbers only. No secrets involved.
"""
import json
import sys
import urllib.request

DATAFEED = "0xfCEE9754E8C375e145303b7cE7BEca3201734A2B"
CUSTOMFEED = "0x056339C044055819E8Db84E71f5f2E1F536b2E5b"
CAP = 1.11          # deployed maxExpectedAnswer, verified 2026-10-30
FLOOR = 0.90        # deployed minExpectedAnswer, verified 2026-10-30
RPCS = [
    "https://eth.llamarpc.com",
    "https://ethereum-rpc.publicnode.com",
    "https://cloudflare-eth.com",
    "https://eth.drpc.org",
]
BACK = 14           # rounds to walk back


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "User-Agent": "moka-harness-midas/1.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        out = json.loads(resp.read().decode())
    if "error" in out:
        raise RuntimeError(str(out["error"])[:120])
    return out["result"]


class Client:
    def __init__(self):
        self.url = None
        for u in RPCS:
            try:
                rpc(u, "eth_blockNumber", [])
                self.url = u
                break
            except Exception as e:
                print(f"[RPC] {u} failed: {type(e).__name__}", flush=True)
        if not self.url:
            raise SystemExit("REFUSED: no public RPC reachable")

    def call(self, to, data):
        return rpc(self.url, "eth_call", [{"to": to, "data": data},
                                          "latest"])


def decode_round(raw):
    h = raw[2:]
    words = [int(h[i:i + 64], 16) for i in range(0, 320, 64)]
    round_id, answer, _started, updated_at, _answered_in = words
    return round_id, answer / 1e8, updated_at


def get_round(c, to, rid):
    data = "0x9a6fc8f5" + format(rid, "064x")
    return decode_round(c.call(to, data))


def main():
    c = Client()
    print(f"[RPC] using {c.url}", flush=True)
    blk = int(rpc(c.url, "eth_blockNumber", []), 16)
    print(f"[CHAIN] block={blk}", flush=True)

    rid, ans, ts = decode_round(c.call(DATAFEED, "0xfeaf968c"))
    print(f"[DATAFEED] latest round={rid} answer={ans:.8f} "
          f"updated_at={ts}", flush=True)
    rows = [(rid, ans, ts)]
    for back in range(1, BACK + 1):
        try:
            r2, a2, t2 = get_round(c, DATAFEED, rid - back)
            rows.append((r2, a2, t2))
        except Exception as e:
            print(f"[DATAFEED] getRoundData({rid - back}) failed: "
                  f"{type(e).__name__}", flush=True)
            break
    rows.sort()
    for r2, a2, t2 in rows:
        print(f"[ROUND] id={r2} answer={a2:.8f} ts={t2}", flush=True)

    if len(rows) >= 2:
        (r0, a0, t0), (r1, a1, t1) = rows[0], rows[-1]
        span_days = max((t1 - t0) / 86400.0, 1e-9)
        growth = a1 - a0
        per_round = growth / max(r1 - r0, 1)
        per_day = growth / span_days
        print(f"[VELOCITY] rounds {r0}->{r1} over {span_days:.2f} days: "
              f"growth={growth:.8f} per_round={per_round:.8f} "
              f"per_day={per_day:.8f}", flush=True)
        head = CAP - a1
        print(f"[DISTANCE] ceiling={CAP} current={a1:.8f} "
              f"headroom={head:.8f} ({head / CAP * 100:.2f}% of cap, "
              f"{head / a1 * 100:.2f}% above current)", flush=True)
        if per_day > 0:
            eta = head / per_day
            print(f"[PROJECTION] at measured velocity: ~{eta:.0f} days "
                  f"to ceiling (conditional on accrual rate and push "
                  f"cadence staying as measured; NOT a certainty)",
                  flush=True)
        if per_round > 0:
            print(f"[PROJECTION] rounds remaining at per-round growth: "
                  f"~{head / per_round:.0f}", flush=True)

    try:
        crid, cans, cts = decode_round(c.call(CUSTOMFEED, "0xfeaf968c"))
        print(f"[CUSTOMFEED] latest round={crid} answer={cans:.8f} "
              f"updated_at={cts}", flush=True)
    except Exception as e:
        print(f"[CUSTOMFEED] latestRoundData failed: "
              f"{type(e).__name__}", flush=True)
    print("[DONE] midas_feed_check", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
