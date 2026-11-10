#!/usr/bin/env python3
"""RA-1: AgentKit hardcoded fallback keys (Allora / Enso) liveness differential
from the GitHub Actions egress.

Design (matches notes/coinbase-reattack-20261110.md RA-1 card):
- Keys are extracted AT RUNTIME from the public coinbase/agentkit repo.
  No key value is embedded in this script, and no key value is printed:
  outputs carry only provider tag, length and last-3 chars.
- Exactly ONE read-only GET per arm, no retries:
    Enso   GET https://api.enso.build/api/v1/tokens?chainId=1
           arms: (a) no key (b) fake (shape-preserved zeroed) (c) real constant
    Allora GET https://api.upshot.xyz/v2/allora/consumer/topics
           arms: (a) no key (b) fake (UP- + zeros, same length) (c) real constant
- Local-egress baseline (2026-11-10): Enso none=403 key-required,
  fake=401 invalid_api_key, real=403 "Not allowed." (+portalUrl).
  Allora was Cloudflare-blocked locally (undeterminable).
"""
import re
import sys

import requests

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
RAW = "https://raw.githubusercontent.com/coinbase/agentkit/main/"


def fetch_text(url):
    r = requests.get(url, headers=UA, timeout=30)
    r.raise_for_status()
    return r.text


def extract(text, pattern):
    m = re.search(pattern, text)
    return m.group(1) if m else None


def get_once(url, headers, redact=()):
    """One GET, no retry. Returns (status_or_None, body_excerpt)."""
    try:
        r = requests.get(url, headers=headers, timeout=25)
        body = r.text[:220]
        for v in redact:
            if v:
                body = body.replace(v, "***")
        return r.status_code, body.replace("\n", " ")[:220]
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:140]}"


def shape_zero(key):
    """Same length/format, hex+alnum zeroed -> definitively fake, same shape."""
    return "".join("0" if c.isalnum() else c for c in key)


def main():
    enso_key = allora_key = None
    try:
        t = fetch_text(RAW + "typescript/agentkit/src/action-providers/enso/constants.ts")
        enso_key = extract(t, r'ENSO_API_KEY\s*=\s*"([^"]+)"')
    except Exception as e:  # noqa: BLE001
        print(f"[enso] source fetch failed: {type(e).__name__}: {str(e)[:120]}")
    try:
        t = fetch_text(RAW + "typescript/agentkit/src/action-providers/allora/alloraActionProvider.ts")
        allora_key = extract(t, r'DEFAULT_API_KEY\s*=\s*"([^"]+)"')
    except Exception as e:  # noqa: BLE001
        print(f"[allora] source fetch failed: {type(e).__name__}: {str(e)[:120]}")

    results = {}

    if enso_key:
        print(f"[enso] constant: len={len(enso_key)} tail=...{enso_key[-3:]}")
        url = "https://api.enso.build/api/v1/tokens?chainId=1"
        fake = shape_zero(enso_key)
        arms = {
            "none": {},
            "fake": {"Authorization": f"Bearer {fake}"},
            "real": {"Authorization": f"Bearer {enso_key}"},
        }
        for name, extra in arms.items():
            st, body = get_once(url, {**UA, **extra}, redact=(enso_key, fake))
            results[("enso", name)] = (st, body)
            print(f"[enso] arm={name}: HTTP {st} body={body!r}")
    else:
        print("[enso] constant NOT extracted")

    if allora_key:
        print(f"[allora] constant: len={len(allora_key)} tail=...{allora_key[-3:]}")
        url = "https://api.upshot.xyz/v2/allora/consumer/topics"
        fake = "UP-" + "0" * (len(allora_key) - 3)
        arms = {
            "none": {},
            "fake": {"X-Api-Key": fake},
            "real": {"X-Api-Key": allora_key},
        }
        for name, extra in arms.items():
            st, body = get_once(url, {**UA, **extra}, redact=(allora_key, fake))
            results[("allora", name)] = (st, body)
            print(f"[allora] arm={name}: HTTP {st} body={body!r}")
    else:
        print("[allora] constant NOT extracted")

    # ---- verdict lines (data-level; interpretation stays with the analyst) ----
    def sig(res):
        if res is None:
            return None
        st, body = res
        low = body.lower()
        if st is None:
            return ("neterr", low[:60])
        if "invalid_api_key" in low or "invalid api key" in low:
            return (st, "invalid_key")
        if "require an api key" in low or "requires an api key" in low or "missing" in low:
            return (st, "key_required")
        if "not allowed" in low:
            return (st, "not_allowed")
        if "error code: 1010" in low or "attention required" in low or "cloudflare" in low:
            return (st, "cloudflare_block")
        return (st, "other")

    for prov in ("enso", "allora"):
        sn, sf, sr = (sig(results.get((prov, a))) for a in ("none", "fake", "real"))
        print(f"VERDICT[{prov}] none={sn} fake={sf} real={sr}")
        if prov == "enso":
            if sr and sr[0] == 200:
                print("VERDICT[enso-summary] real key returned 200 from Actions egress: key is fully valid")
            elif sr and sf and sr != sf:
                print("VERDICT[enso-summary] real != fake differential reproduced from Actions egress: server recognizes the real constant as a key")
            elif sr and sf and sr == sf:
                print("VERDICT[enso-summary] real == fake from Actions egress: no recognition differential on this egress")
            else:
                print("VERDICT[enso-summary] undeterminable from this run (see arm lines)")
        else:
            if sr and sr[1] == "cloudflare_block":
                print("VERDICT[allora-summary] Cloudflare block also on Actions egress: undeterminable")
            elif sr and sr[0] == 200:
                print("VERDICT[allora-summary] real key returned 200: key recognized and usable on a read endpoint")
            elif sr and sf and sr != sf:
                print("VERDICT[allora-summary] real != fake differential: server recognizes the real constant as a key (usability per arm body)")
            elif sr and sf and sr == sf:
                print("VERDICT[allora-summary] real == fake: no recognition differential (constant treated like garbage / dead)")
            else:
                print("VERDICT[allora-summary] undeterminable from this run (see arm lines)")
    print("RA1_DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
