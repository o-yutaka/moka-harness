#!/usr/bin/env python3
"""
zd5_role_create.py — the custom_roles UPDATE endpoint silently no-ops
on ticket_comment_access (measured twice, runs #734/#737). Try the
CREATE path: clone LOW's Contributor configuration with exactly one
key changed (ticket_comment_access -> "public"), create a new role,
verify by read-back (value applied AND custom_objects scopes still
empty for moka_probe), only then assign it to LOW, and re-prove the
object restriction (LOW direct GET of a fresh record must stay
403 / marker-free).

Verdicts: ROLECREATE APPLIED-AND-RESTRICTION-HELD |
          VALUE-STRIPPED-AT-CREATE | SCOPES-DIFFER (abort) |
          ASSIGN-FAILED | RESTRICTION-BROKE (stop signal).
No traffic without --run.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zd_battery as zb  # noqa: E402


class Run:
    def __init__(self):
        root = Path(os.environ.get("ZD5RC_OUT", "outputs")) / "zd5rolecreate"
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {"probe": "ZD-5-ROLECREATE", "run_id": self.id,
                         "created": [], "notes": []}
        self.flush()

    def add(self, kind, ident, extra=None):
        self.manifest["created"].append(
            {"kind": kind, "id": ident, **(extra or {})})
        self.flush()

    def note(self, text):
        self.manifest["notes"].append(text)
        self.flush()

    def flush(self):
        (self.dir / "manifest.json").write_text(
            json.dumps(self.manifest, indent=2, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        print("SELFTEST ok")
        return 0
    if not args.run:
        zb.die_refuse("pass --run")
        return 2
    subdomain = os.environ["ZENDESK_SUBDOMAIN"]
    low_email = os.environ["ZENDESK_EMAIL_LOW"]
    run = Run()
    token = zb.bootstrap_token(subdomain, run.dir)
    client = zb.Client(subdomain, f"Bearer {token}", run.dir)
    low = zb.low_client(subdomain, run)

    st, parsed, _ = client.call("rc-find-low", "GET",
        "/users/search.json?query=" +
        urllib.parse.quote(low_email, safe=""))
    low_user = ((parsed or {}).get("users") or [{}])[0]
    low_id = low_user.get("id")
    crid = low_user.get("custom_role_id")
    print(f"LOW id={low_id} custom_role_id={crid}")
    st, parsed, _ = client.call("rc-get-role", "GET",
                                f"/custom_roles/{crid}.json")
    role = ((parsed or {}).get("custom_role") or {})
    config = json.loads(json.dumps(role.get("configuration") or {}))
    base_scopes = ((config.get("custom_objects") or {})
                   .get("moka_probe") or {}).get("scopes")
    print(f"base moka_probe scopes={json.dumps(base_scopes)} "
          f"ticket_comment_access={config.get('ticket_comment_access')}")
    config["ticket_comment_access"] = "public"
    st, parsed, _ = client.call("rc-create-role", "POST",
                                "/custom_roles.json",
                                {"custom_role": {
                                    "name": "Moka Contributor Public",
                                    "description": "ZD-5 chain fixture: "
                                        "Contributor clone with public "
                                        "comment access; object scopes "
                                        "unchanged (none).",
                                    "configuration": config}})
    new_role = ((parsed or {}).get("custom_role") or {})
    new_id = new_role.get("id")
    print(f"ROLECREATE POST status={st} new_role_id={new_id}")
    if not new_id:
        print("VERDICT ROLECREATE: CREATE-FAILED")
        return 0
    run.add("custom_role", str(new_id))
    st, parsed, _ = client.call("rc-get-new-role", "GET",
                                f"/custom_roles/{new_id}.json")
    got = ((parsed or {}).get("custom_role") or {})
    got_cfg = got.get("configuration") or {}
    got_scopes = ((got_cfg.get("custom_objects") or {})
                  .get("moka_probe") or {}).get("scopes")
    print(f"ROLECREATE read-back: ticket_comment_access="
          f"{got_cfg.get('ticket_comment_access')} "
          f"moka_probe scopes={json.dumps(got_scopes)}")
    if got_cfg.get("ticket_comment_access") != "public":
        print("VERDICT ROLECREATE: VALUE-STRIPPED-AT-CREATE")
        return 0
    if got_scopes != base_scopes:
        print("VERDICT ROLECREATE: SCOPES-DIFFER (abort, not assigned)")
        return 0
    st, parsed, _ = client.call("rc-assign", "PUT",
                                f"/users/{low_id}.json",
                                {"user": {"custom_role_id": new_id}})
    print(f"ROLECREATE assign status={st}")
    st, parsed, _ = client.call("rc-verify-low", "GET",
                                f"/users/{low_id}.json")
    cur_role = ((parsed or {}).get("user") or {}).get("custom_role_id")
    print(f"ROLECREATE LOW custom_role_id now={cur_role}")
    if cur_role != new_id:
        print("VERDICT ROLECREATE: ASSIGN-FAILED")
        return 0

    # Re-prove the object restriction under the new role.
    marker = zb.marker("ZD5RC")
    st, parsed, _ = client.call("rc-create-record", "POST",
        "/custom_objects/moka_probe/records.json", {
            "custom_object_record": {
                "name": marker,
                "custom_object_fields": {"marker_field": marker}}})
    rec = ((parsed or {}).get("custom_object_record") or {})
    rec_id = rec.get("id")
    if not rec_id:
        print(f"VERDICT ROLECREATE: INCONCLUSIVE (record create {st})")
        return 0
    run.add("custom_object_record", str(rec_id))
    st_get, _, raw = low.call("rc-low-get", "GET",
        f"/custom_objects/moka_probe/records/{rec_id}.json")
    raw_text = raw.decode("utf-8", "replace") if raw else ""
    held = not (st_get == 200 and marker in raw_text)
    print(f"ROLECREATE restriction re-proof: LOW GET status={st_get} "
          f"held={held}")
    print("VERDICT ROLECREATE: "
          + ("APPLIED-AND-RESTRICTION-HELD" if held
             else "RESTRICTION-BROKE"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
