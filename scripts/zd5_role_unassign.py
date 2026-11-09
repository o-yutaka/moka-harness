#!/usr/bin/env python3
"""
zd5_role_unassign.py — Contributor is a Zendesk SYSTEM role
(UI-verified 2026-11-09): not editable via API (silent no-op) and
custom-role creation is plan-gated (402). Test the remaining fixture
route: UNASSIGN the custom role from LOW (LOW becomes a default
agent, which can post public replies by default) and immediately
re-prove the moka_probe object restriction. If the restriction
breaks, AUTO-REVERT to the original role and report.

Verdicts: ROLEUNASSIGN HELD-UNASSIGNED | RESTRICTION-BROKE-REVERTED |
          UNASSIGN-FAILED | REVERT-FAILED (stop signal).
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
        root = Path(os.environ.get("ZD5RU_OUT", "outputs")) / "zd5roleunassign"
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {"probe": "ZD-5-ROLEUNASSIGN", "run_id": self.id,
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


def get_low(client, low_id):
    st, parsed, _ = client.call("ru-get-low", "GET",
                                f"/users/{low_id}.json")
    return ((parsed or {}).get("user") or {})


def restriction_proof(client, low, run, tag):
    marker = zb.marker(tag)
    st, parsed, _ = client.call(f"{tag}-create-record", "POST",
        "/custom_objects/moka_probe/records.json", {
            "custom_object_record": {
                "name": marker,
                "custom_object_fields": {"marker_field": marker}}})
    rec = ((parsed or {}).get("custom_object_record") or {})
    rec_id = rec.get("id")
    if not rec_id:
        return None, marker
    run.add("custom_object_record", str(rec_id))
    st_get, _, raw = low.call(f"{tag}-low-get", "GET",
        f"/custom_objects/moka_probe/records/{rec_id}.json")
    raw_text = raw.decode("utf-8", "replace") if raw else ""
    held = not (st_get == 200 and marker in raw_text)
    print(f"ROLEUNASSIGN proof[{tag}]: LOW GET status={st_get} "
          f"held={held}")
    return held, marker


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

    st, parsed, _ = client.call("ru-find-low", "GET",
        "/users/search.json?query=" +
        urllib.parse.quote(low_email, safe=""))
    low_user = ((parsed or {}).get("users") or [{}])[0]
    low_id = low_user.get("id")
    orig_role = low_user.get("custom_role_id")
    print(f"LOW id={low_id} original custom_role_id={orig_role}")
    run.note(f"original custom_role_id={orig_role}")

    st, parsed, _ = client.call("ru-unassign", "PUT",
                                f"/users/{low_id}.json",
                                {"user": {"custom_role_id": None}})
    print(f"ROLEUNASSIGN PUT status={st}")
    cur = get_low(client, low_id)
    print(f"ROLEUNASSIGN read-back custom_role_id="
          f"{cur.get('custom_role_id')} role={cur.get('role')}")
    if cur.get("custom_role_id") is not None:
        print("VERDICT ROLEUNASSIGN: UNASSIGN-FAILED")
        return 0

    held, _ = restriction_proof(client, low, run, "ZD5RU")
    if held is None:
        print("VERDICT ROLEUNASSIGN: INCONCLUSIVE (record create)")
        return 0
    if held:
        print("VERDICT ROLEUNASSIGN: HELD-UNASSIGNED")
        return 0
    # Restriction broke -> auto-revert.
    print("ROLEUNASSIGN restriction BROKE; reverting...")
    st, parsed, _ = client.call("ru-revert", "PUT",
                                f"/users/{low_id}.json",
                                {"user": {"custom_role_id": orig_role}})
    cur = get_low(client, low_id)
    print(f"ROLEUNASSIGN revert read-back custom_role_id="
          f"{cur.get('custom_role_id')}")
    if cur.get("custom_role_id") == orig_role:
        held2, _ = restriction_proof(client, low, run, "ZD5RV")
        print("VERDICT ROLEUNASSIGN: RESTRICTION-BROKE-REVERTED "
              f"(post-revert held={held2})")
    else:
        print("VERDICT ROLEUNASSIGN: REVERT-FAILED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
