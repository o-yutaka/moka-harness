#!/usr/bin/env python3
"""Databricks PAT revocation-lag, cycle 5 (Actions lane).
Creates a disposable PAT with the owner PAT, verifies it, deletes it,
then tests the deleted token at +0 / +20 / +35 minutes.
Prior cycles 1-4: alive at +0/+7m, dead at +32-33m. Cycle 4's +20m point
was lost when the local sleeper died; this cycle re-measures exactly that point.
Token VALUES are never printed (token_id prefix + HTTP statuses only).
Creds come from env: DATABRICKS_HOST / DATABRICKS_TOKEN (repo secrets).
"""
import json
import os
import sys
import time

import requests

HOST = os.environ["DATABRICKS_HOST"].replace("https://", "").rstrip("/")
OWNER = os.environ["DATABRICKS_TOKEN"]
BASE = f"https://{HOST}"


def call(token, method, path, body=None):
    try:
        r = requests.request(method, BASE + path, json=body,
                             headers={"Authorization": f"Bearer {token}"},
                             timeout=60)
        return r.status_code, r.text[:2000]
    except Exception as e:
        return -1, str(e)[:200]


def test(tval, label, t0):
    s1, _ = call(tval, "GET", "/api/2.1/clusters/list")
    s2, _ = call(tval, "GET", "/api/2.0/token/list")
    el = round((time.time() - t0) / 60, 2)
    print(f"RESULT {label} elapsed_min={el} clusters={s1} token_list={s2}", flush=True)
    return s1


def main():
    s, body = call(OWNER, "POST", "/api/2.0/token/create",
                   {"comment": "pat-lag-cycle5-retry", "lifetime_seconds": 86400})
    if s != 200:
        print(f"VERDICT CREATE_FAILED status={s} body={body[:200]}", flush=True)
        sys.exit(1)
    try:
        info = json.loads(body)
    except Exception:
        print(f"VERDICT CREATE_BAD_JSON body_len={len(body)}", flush=True)
        sys.exit(1)
    if not isinstance(info, dict) or "token_id" not in info or "token_value" not in info:
        keys = sorted(info.keys()) if isinstance(info, dict) else type(info).__name__
        err = {}
        if isinstance(info, dict):
            err = {k: str(info.get(k))[:120] for k in ("error_code", "message") if k in info}
        print(f"VERDICT CREATE_SHAPE_MISMATCH keys={keys} error={err}", flush=True)
        sys.exit(1)
    tid, tval = info["token_id"], info["token_value"]
    print(f"CREATED token_id_prefix={tid[:12]}", flush=True)

    s1, _ = call(tval, "GET", "/api/2.1/clusters/list")
    print(f"SANITY pre-delete clusters={s1}", flush=True)
    if s1 != 200:
        print(f"VERDICT ABORT sanity_not_200", flush=True)
        sys.exit(1)

    s, _ = call(OWNER, "POST", "/api/2.0/token/delete", {"token_id": tid})
    t0 = time.time()
    print(f"DELETED status={s}", flush=True)
    s, body = call(OWNER, "GET", "/api/2.0/token/list")
    print(f"OWNER_LIST_AFTER_DELETE status={s} token_present={tid in body}", flush=True)

    test(tval, "plus_0m", t0)
    for target, label in ((20, "plus_20m"), (35, "plus_35m")):
        wait = t0 + target * 60 - time.time()
        if wait > 0:
            print(f"WAITING {round(wait)}s until {label}", flush=True)
            time.sleep(wait)
        test(tval, label, t0)
    print("VERDICT CYCLE5_COMPLETE", flush=True)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print(f"VERDICT EXCEPTION {type(e).__name__}: {str(e)[:120]}", flush=True)
        sys.exit(1)
