#!/usr/bin/env python3
"""WT-1 / WT-5 bytecode identification.
Read-only eth_getCode for 3 Ethereum mainnet addresses from multiple public RPCs.
Computes length / keccak256 codehash / sha256, cross-checks across >=2 RPCs,
compares cbETH impl vs cbBTC impl, and probes Sourcify + Blockscout for the
oracle contract identity. Writes everything under outputs/wt/.
Stdlib only (keccak implemented in pure python; cross-checked with pycryptodome if present).
"""
import hashlib, json, os, sys, time, urllib.request, urllib.error

OUT = os.path.join("outputs", "wt")
os.makedirs(OUT, exist_ok=True)

ADDRS = {
    "cbeth_impl": "0x31724Ca0C982a31fbb5C57f4217AB585271fC9a5",
    "cbbtc_impl": "0x7458bfdc30034eb860b265e6068121d18fa5aa72",
    "cbeth_oracle": "0x9b37180d847b27adc13c2277299045c1237ae281",
}

RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://ethereum.blockpi.network/v1/rpc/public",
    "https://eth.drpc.org",
    "https://eth-mainnet.public.blastapi.io",
    "https://rpc.mevblocker.io",
    "https://cloudflare-eth.com",
    "https://1rpc.io/eth",
]

# ---------- pure-python Keccak-256 ----------
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,
      0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,
      0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
      0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
MASK = (1<<64)-1
def rol(x,n): return ((x<<n)|(x>>(64-n))) & MASK if n else x
def keccak_f(state):
    for rnd in range(24):
        C = [state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20] for x in range(5)]
        D = [C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): state[x+5*y] ^= D[x]
        B = [0]*25
        for x in range(5):
            for y in range(5): B[y+5*((2*x+3*y)%5)] = rol(state[x+5*y], R[x][y])
        for x in range(5):
            for y in range(5):
                state[x+5*y] = B[x+5*y] ^ ((~B[(x+1)%5+5*y]) & B[(x+2)%5+5*y])
        state[0] ^= RC[rnd]
def keccak256(data: bytes) -> bytes:
    rate = 136
    state = [0]*25
    # pad10*1 with 0x01 domain (Keccak, not SHA3 0x06)
    padded = bytearray(data); padded.append(0x01)
    while len(padded) % rate != rate-1: padded.append(0x00)
    padded.append(0x80)
    for off in range(0, len(padded), rate):
        block = padded[off:off+rate]
        for i in range(rate//8):
            state[i] ^= int.from_bytes(block[i*8:(i+1)*8], "little")
        keccak_f(state)
    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out[:32]

# sanity: keccak256("") known vector
assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak self-test failed"
try:
    from Crypto.Hash import keccak as _k
    def keccak256_lib(b):
        h = _k.new(digest_bits=256); h.update(b); return h.digest()
    assert keccak256_lib(b"").hex() == keccak256(b"").hex()
    KECCAK_SRC = "pure-python (pycryptodome cross-check OK)"
except Exception:
    KECCAK_SRC = "pure-python (self-test vector OK)"

def http_post(url, payload, timeout=40):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "wt-bytecode/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def http_get(url, timeout=40):
    req = urllib.request.Request(url, headers={"User-Agent": "wt-bytecode/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()

def rpc_call(rpc, method, params):
    res = http_post(rpc, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if "error" in res: raise RuntimeError(str(res["error"]))
    return res["result"]

results = {}
codes = {}
for name, addr in ADDRS.items():
    per_rpc = []
    got = {}
    for rpc in RPCS:
        try:
            bn = rpc_call(rpc, "eth_blockNumber", [])
            code = rpc_call(rpc, "eth_getCode", [addr, "latest"])
            raw = bytes.fromhex(code[2:])
            entry = {"rpc": rpc, "block": int(bn, 16), "len": len(raw),
                     "keccak256": "0x" + keccak256(raw).hex(),
                     "sha256": hashlib.sha256(raw).hexdigest()}
            per_rpc.append(entry)
            got.setdefault(entry["keccak256"], raw)
            print(f"[{name}] OK {rpc} block={entry['block']} len={entry['len']} keccak={entry['keccak256']}", flush=True)
        except Exception as e:
            per_rpc.append({"rpc": rpc, "error": repr(e)[:300]})
            print(f"[{name}] FAIL {rpc}: {e!r}", flush=True)
        if len(got) >= 1 and sum(1 for e in per_rpc if "keccak256" in e) >= 3:
            break
        time.sleep(0.3)
    hashes = [e["keccak256"] for e in per_rpc if "keccak256" in e]
    agree = len(set(hashes))
    results[name] = {"address": addr, "per_rpc": per_rpc,
                     "distinct_codehashes": agree,
                     "consensus": hashes[0] if hashes and agree == 1 else None}
    if hashes and agree == 1:
        raw = got[hashes[0]]
        codes[name] = raw
        with open(os.path.join(OUT, f"{name}.hex"), "w") as f:
            f.write("0x" + raw.hex())
    print(f"[{name}] distinct_codehashes={agree} consensus={results[name]['consensus']}", flush=True)

# ---- WT-5: cbETH impl vs cbBTC impl comparison ----
cmp_out = {}
if "cbeth_impl" in codes and "cbbtc_impl" in codes:
    a, b = codes["cbeth_impl"], codes["cbbtc_impl"]
    cmp_out["len_cbeth"] = len(a); cmp_out["len_cbbtc"] = len(b)
    cmp_out["identical"] = (a == b)
    if a != b:
        # common prefix / suffix
        p = 0
        while p < min(len(a), len(b)) and a[p] == b[p]: p += 1
        s = 0
        while s < min(len(a), len(b)) - p and a[len(a)-1-s] == b[len(b)-1-s]: s += 1
        cmp_out["common_prefix_len"] = p
        cmp_out["common_suffix_len"] = s
        # diff ranges on the shorter-aligned comparison (bytewise over min len, plus tail)
        ranges = []
        start = None
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else None
            bv = b[i] if i < len(b) else None
            if av != bv and start is None: start = i
            if av == bv and start is not None:
                ranges.append([start, i-1]); start = None
        if start is not None: ranges.append([start, max(len(a), len(b))-1])
        cmp_out["diff_ranges"] = ranges[:50]
        cmp_out["diff_range_count"] = len(ranges)
        cmp_out["total_diff_bytes_in_overlap"] = sum(1 for i in range(min(len(a), len(b))) if a[i] != b[i])
        # metadata trailer detection: decode last bytes
        def trailer(x):
            t = x[-64:]
            return t.hex()
        cmp_out["cbeth_tail64"] = trailer(a)
        cmp_out["cbbtc_tail64"] = trailer(b)
        # check whether diffs are confined to last 100 bytes
        cmp_out["diffs_confined_to_last_100_bytes"] = all(r[0] >= min(len(a), len(b)) - 100 for r in ranges)
results["wt5_comparison"] = cmp_out
print("WT5:", json.dumps(cmp_out)[:1200], flush=True)

# ---- WT-1: oracle identification via Sourcify / Blockscout (public, no keys) ----
ident = {}
for name, addr in ADDRS.items():
    info = {}
    try:
        st, body = http_get(f"https://sourcify.dev/server/v2/contract/1/{addr}")
        j = json.loads(body)
        info["sourcify_v2_status"] = st
        info["sourcify_match"] = j.get("match")
        info["sourcify_creation_match"] = j.get("creationMatch")
        info["sourcify_runtime_match"] = j.get("runtimeMatch")
        comp = (j.get("compilation") or {})
        info["sourcify_contract_name"] = comp.get("name")
        info["sourcify_compiler"] = comp.get("compilerVersion")
        print(f"[sourcify {name}] match={info['sourcify_match']} runtime={info['sourcify_runtime_match']} name={info['sourcify_contract_name']}", flush=True)
    except Exception as e:
        info["sourcify_error"] = repr(e)[:300]
        print(f"[sourcify {name}] FAIL {e!r}", flush=True)
    try:
        st, body = http_get(f"https://eth.blockscout.com/api/v2/smart-contracts/{addr}")
        j = json.loads(body)
        info["blockscout_name"] = j.get("name")
        info["blockscout_is_verified"] = j.get("is_verified")
        info["blockscout_compiler"] = j.get("compiler_version")
        info["blockscout_file_path"] = j.get("file_path")
        print(f"[blockscout {name}] name={info['blockscout_name']} verified={info['blockscout_is_verified']}", flush=True)
    except Exception as e:
        info["blockscout_error"] = repr(e)[:300]
        print(f"[blockscout {name}] FAIL {e!r}", flush=True)
    ident[name] = info
results["identification"] = ident

# oracle interface probes (read-only calls via first working RPC)
def sel(sig): return "0x" + keccak256(sig.encode())[:4].hex()
probes = {}
oracle = ADDRS["cbeth_oracle"]
for sig in ["owner()", "tokenContract()"]:
    for rpc in RPCS:
        try:
            out = rpc_call(rpc, "eth_call", [{"to": oracle, "data": sel(sig)}, "latest"])
            probes[sig] = {"rpc": rpc, "result": out}
            print(f"[oracle probe] {sig} -> {out} via {rpc}", flush=True)
            break
        except Exception as e:
            probes[sig] = {"error": repr(e)[:200]}
results["oracle_probes"] = probes

results["keccak_source"] = KECCAK_SRC
results["generated_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
with open(os.path.join(OUT, "summary.json"), "w") as f:
    json.dump(results, f, indent=2)
print("DONE. summary written.", flush=True)
