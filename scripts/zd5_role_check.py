#!/usr/bin/env python3
"""
zd5_role_check.py — why can LOW not make a public reply?
Dumps (fingerprints/values are role-config only, no secrets):
  - LOW user object (role, custom_role_id)
  - the custom role's full configuration JSON
  - ticket 35 basics (via channel, status, assignee, requester)
Artifacts under outputs/zd5role/<run_id>/; stdout prints the config.
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
        root = Path(os.environ.get("ZD5RC_OUT", "outputs")) / "zd5role"
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {"probe": "ZD-5-ROLECHECK", "run_id": self.id,
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

    st, parsed, _ = client.call("rc-find-low", "GET",
        "/users/search.json?query=" +
        urllib.parse.quote(low_email, safe=""))
    users = (parsed or {}).get("users") or []
    low = users[0] if users else {}
    print(f"LOW id={low.get('id')} role={low.get('role')} "
          f"custom_role_id={low.get('custom_role_id')} "
          f"role_type={low.get('role_type')}")
    crid = low.get("custom_role_id")
    if crid:
        st, parsed, _ = client.call("rc-get-role", "GET",
                                    f"/custom_roles/{crid}.json")
        role = ((parsed or {}).get("custom_role") or {})
        print(f"ROLE name={role.get('name')}")
        print("ROLE configuration:")
        print(json.dumps(role.get("configuration") or {},
                         indent=2, ensure_ascii=False))
        (run.dir / "role.json").write_text(json.dumps(
            role, indent=2, ensure_ascii=False))
    st, parsed, _ = client.call("rc-ticket35", "GET", "/tickets/35.json")
    t = ((parsed or {}).get("ticket") or {})
    print(f"TICKET35 via={json.dumps(t.get('via') or {})} "
          f"status={t.get('status')} assignee={t.get('assignee_id')} "
          f"requester={t.get('requester_id')}")
    print("DONE ZD-5-ROLECHECK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
