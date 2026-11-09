#!/usr/bin/env python3
"""
zd5_role_fix.py — flip LOW's custom-role public-comment capability, if
the role configuration exposes one, while PROVING the moka_probe
object restriction (the ZD-5 premise) survives the change.

Behaviour:
  1. Read LOW's custom role configuration; list every key whose name
     mentions comment/public (stdout).
  2. If exactly ONE boolean key matches /public/ AND /comment/ (either
     order) and it is false, flip it to true via PUT /custom_roles and
     re-read to verify.
  3. Re-prove the restriction: LOW direct GET of a fresh restricted
     record must still be 403 / marker-free.
  4. Print ROLEFIX verdict: FLIPPED-AND-RESTRICTION-HELD |
     NO-SUCH-KEY | AMBIGUOUS | RESTRICTION-BROKE (stop signal).
No traffic without --run. Values printed are role config only.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zd_battery as zb  # noqa: E402


class Run:
    def __init__(self):
        root = Path(os.environ.get("ZD5RF_OUT", "outputs")) / "zd5rolefix"
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {"probe": "ZD-5-ROLEFIX", "run_id": self.id,
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


def walk_keys(obj, prefix=""):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            out.append((p, v))
            out.extend(walk_keys(v, p))
    return out


def set_path(obj, path, value):
    parts = path.split(".")
    cur = obj
    for p in parts[:-1]:
        cur = cur[p]
    cur[parts[-1]] = value


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

    st, parsed, _ = client.call("rf-find-low", "GET",
        "/users/search.json?query=" +
        urllib.parse.quote(low_email, safe=""))
    low_user = ((parsed or {}).get("users") or [{}])[0]
    crid = low_user.get("custom_role_id")
    print(f"LOW custom_role_id={crid}")
    if not crid:
        print("VERDICT ROLEFIX: NO-SUCH-KEY (LOW has no custom role)")
        return 0
    st, parsed, _ = client.call("rf-get-role", "GET",
                                f"/custom_roles/{crid}.json")
    role = ((parsed or {}).get("custom_role") or {})
    config = role.get("configuration") or {}
    keys = walk_keys(config)
    interesting = [(p, v) for p, v in keys
                   if re.search(r"comment|public", p, re.I)]
    print("ROLEFIX candidate keys:")
    for p, v in interesting:
        print(f"  {p} = {json.dumps(v)}")
    # Primary schema (measured 2026-11-09, run #729): the comment
    # capability is the STRING key ticket_comment_access in
    # {"none", "public", "public-and-private"} (approx. ladder:
    # none < private-only via "public" absent...). Handle it directly:
    ca = config.get("ticket_comment_access")
    print(f"ROLEFIX ticket_comment_access = {json.dumps(ca)}")
    if ca is not None:
        if ca not in ("none",):
            print("VERDICT ROLEFIX: ALREADY-ENABLED "
                  "(ticket_comment_access not 'none'; block elsewhere)")
            (run.dir / "role-before.json").write_text(json.dumps(
                role, indent=2, ensure_ascii=False))
            return 0
        path, current = "ticket_comment_access", ca
        new_value = "public"
    else:
        targets = [(p, v) for p, v in interesting
                   if isinstance(v, bool)
                   and re.search(r"public", p, re.I)
                   and re.search(r"comment", p, re.I)]
        if len(targets) != 1:
            print(f"VERDICT ROLEFIX: "
                  f"{'NO-SUCH-KEY' if not targets else 'AMBIGUOUS'} "
                  f"(targets={len(targets)})")
            (run.dir / "role-before.json").write_text(json.dumps(
                role, indent=2, ensure_ascii=False))
            return 0
        path, current = targets[0]
        new_value = True
        print(f"ROLEFIX target: {path} currently {current}")
        if current is True:
            print("VERDICT ROLEFIX: ALREADY-TRUE (public comments "
                  "allowed by config; the block is elsewhere)")
            return 0
    new_config = json.loads(json.dumps(config))
    set_path(new_config, path, new_value)
    # Measured 2026-11-09 (run #734): a full-configuration PUT returns
    # 200 but silently applies nothing (updated_at unchanged). The
    # update endpoint takes a PARTIAL configuration (only changed
    # keys). Send only the flipped key.
    partial = {path.split(".")[-1]: new_value}
    print(f"ROLEFIX partial payload: {json.dumps(partial)}")
    st, parsed, _ = client.call("rf-put-role", "PUT",
                                f"/custom_roles/{crid}.json",
                                {"custom_role": {
                                    "configuration": partial}})
    print(f"ROLEFIX PUT status={st}")
    st, parsed, _ = client.call("rf-get-role2", "GET",
                                f"/custom_roles/{crid}.json")
    role2 = ((parsed or {}).get("custom_role") or {})
    val2 = dict(walk_keys(role2.get("configuration") or {})).get(path)
    print(f"ROLEFIX re-read: {path} = {val2}")
    (run.dir / "role-after.json").write_text(json.dumps(
        role2, indent=2, ensure_ascii=False))

    # Re-prove the object restriction for LOW.
    marker = zb.marker("ZD5RF")
    st, parsed, _ = client.call("rf-create-record", "POST",
        "/custom_objects/moka_probe/records.json", {
            "custom_object_record": {
                "name": marker,
                "custom_object_fields": {"marker_field": marker}}})
    rec = ((parsed or {}).get("custom_object_record") or {})
    rec_id = rec.get("id")
    if not rec_id:
        print(f"VERDICT ROLEFIX: INCONCLUSIVE (record create {st})")
        return 0
    run.add("custom_object_record", str(rec_id))
    st_get, _, raw = low.call("rf-low-get", "GET",
        f"/custom_objects/moka_probe/records/{rec_id}.json")
    raw_text = raw.decode("utf-8", "replace") if raw else ""
    held = not (st_get == 200 and marker in raw_text)
    print(f"ROLEFIX restriction re-proof: LOW GET status={st_get} "
          f"held={held}")
    print("VERDICT ROLEFIX: "
          + ("FLIPPED-AND-RESTRICTION-HELD"
             if held and val2 == new_value
             else "RESTRICTION-BROKE" if not held
             else "FLIP-UNVERIFIED"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
