#!/usr/bin/env python3
"""ZD-3: set the Moka Probe ZD3 installation's secure setting via API.

Lists app installations, identifies the Moka Probe ZD3 installation,
prints settings KEYS (values redacted; sha256 fingerprint prefix only),
then PUTs settings.probeApiKey = the ZD-3 dummy and verifies presence.

Run via moka-harness: script=zd3_settings (no args).
"""
import hashlib
import os

import zd_battery as zb

DUMMY = "ZD3DUMMYSECRET-7d3a91c4"
MANAGE_ID = "5789614446110"  # id in the Manage-app URL (app or installation)


def fp(value):
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def main():
    sub = os.environ["ZENDESK_SUBDOMAIN"]
    run = zb.Run("ZD-3-SET")
    tok = zb.bootstrap_token(sub, run.dir)
    client = zb.Client(sub, f"Bearer {tok}", run.dir)

    st, parsed, _ = client.call("list-apps", "GET", "/apps.json")
    print(f"STEP apps status={st}")
    app_id = None
    for app in (parsed or {}).get("apps", []):
        print(f"APP id={app.get('id')} name={app.get('name')}")
        if "Probe ZD3" in str(app.get("name")):
            app_id = app.get("id")

    st, parsed, _ = client.call("list-installations", "GET",
                                "/apps/installations")
    print(f"STEP installations status={st}")
    target = None
    for inst in (parsed or {}).get("installations", []):
        keys = sorted((inst.get("settings") or {}).keys())
        title = (inst.get("settings") or {}).get("title")
        print(f"INST id={inst.get('id')} app_id={inst.get('app_id')} "
              f"title={title} settings_keys={keys}")
        if app_id is not None and inst.get("app_id") == app_id:
            target = inst
        if str(inst.get("id")) == MANAGE_ID:
            target = inst
    if target is None:
        print("VERDICT ZD-3-SET: NO-TARGET")
        return
    iid = target["id"]
    aid = target["app_id"]
    cur = (target.get("settings") or {}).get("probeApiKey")
    print(f"TARGET installation={iid} app_id={aid} "
          f"probeApiKey_present={cur is not None} fp={fp(cur)} "
          f"matches_dummy={cur == DUMMY}")

    st, parsed, _ = client.call(
        "update-installation", "PUT", f"/apps/installations/{iid}",
        body={"app_id": aid,
              "settings": {"title": "Moka Probe ZD3",
                           "probeApiKey": DUMMY}})
    print(f"STEP update status={st} body_keys="
          f"{sorted((parsed or {}).keys())}")

    st, parsed, _ = client.call("verify-installation", "GET",
                                f"/apps/installations/{iid}")
    inst = (parsed or {}).get("installation", {})
    val = (inst.get("settings") or {}).get("probeApiKey")
    print(f"VERIFY status={st} probeApiKey_present={val is not None} "
          f"fp={fp(val)} matches_dummy={val == DUMMY}")
    print("VERDICT ZD-3-SET: DONE")


if __name__ == "__main__":
    main()
