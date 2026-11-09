#!/usr/bin/env python3
"""ZD-5 calibration: find the macro-apply surface that actually renders
the lookup placeholder server-side (admin context only).

Run #695 measured: POST /tickets/{tid}/macros/{mid}/apply.json -> 404
InvalidEndpoint. This probe reuses the fixtures from that run (lookup
field + macro found by title), plants a fresh record + linked ticket,
then tries the remaining apply-surface variants and reports, per
variant: HTTP status and whether the response contains the marker
(rendered = good), the raw placeholder (unrendered), or neither.
Imports zd_battery for the OAuth bootstrap / Client / Run plumbing.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zd_battery as zb  # noqa: E402

OBJ_KEY = "moka_probe"
CALIB_MARKER = "ZD5CALIB-9f2c41d7"


def main():
    sub = os.environ["ZENDESK_SUBDOMAIN"]
    run = zb.Run("ZD-5-CALIB")
    tok = zb.bootstrap_token(sub, run.dir)
    client = zb.Client(sub, f"Bearer {tok}", run.dir)

    # Reuse lookup field + macro from run #695 (by title).
    st, parsed, _ = client.call("calib-list-fields", "GET",
                                "/ticket_fields.json")
    lookup_id = None
    for f in ((parsed or {}).get("ticket_fields") or []):
        if f.get("title") == "moka zd5 link":
            lookup_id = f.get("id")
    print(f"CALIB lookup_id={lookup_id}")
    st, parsed, _ = client.call("calib-list-macros", "GET", "/macros.json")
    macro_id = None
    for m in ((parsed or {}).get("macros") or []):
        if m.get("title") == "moka zd5 macro":
            macro_id = m.get("id")
    print(f"CALIB macro_id={macro_id}")
    if not (lookup_id and macro_id):
        print("CALIB ABORT: fixtures from run #695 not found")
        return 3

    # Fresh record with the fixed calibration marker + linked ticket.
    st, parsed, _ = client.call("calib-create-record", "POST",
                                f"/custom_objects/{OBJ_KEY}/records.json", {
        "custom_object_record": {
            "name": "moka-zd5-calib",
            "custom_object_fields": {"marker_field": CALIB_MARKER}}})
    rec_id = ((parsed or {}).get("custom_object_record") or {}).get("id")
    st, parsed, _ = client.call("calib-create-ticket", "POST",
                                "/tickets.json", {
        "ticket": {"subject": "moka zd5 calib", "tags": ["moka_zd5_calib"],
                   "comment": {"body": "calib ticket", "public": True},
                   "custom_fields": [{"id": lookup_id, "value": rec_id}]}})
    tid = ((parsed or {}).get("ticket") or {}).get("id")
    print(f"CALIB rec_id={rec_id} ticket_id={tid}")
    if not (rec_id and tid):
        print("CALIB ABORT: fixture creation failed; see saved bodies")
        return 3

    placeholder_raw = ("{{ticket.ticket_field_%s.custom_fields."
                       "marker_field}}" % lookup_id)

    def probe(tag, method, path, body=None):
        st, parsed, raw = client.call(f"calib-{tag}", method, path, body)
        has_marker = CALIB_MARKER.encode() in raw
        has_ph = placeholder_raw.encode() in raw
        print(f"CALIB {tag}: status={st} marker={has_marker} "
              f"raw_placeholder={has_ph} bytes={len(raw)}")
        return st, has_marker

    # Variant 1: GET macro changes (the pre-2026 battery's call).
    probe("get-apply", "GET", f"/macros/{macro_id}/apply.json")
    # Variant 2: same, with the ticket id as a query param.
    probe("get-apply-tid", "GET",
          f"/macros/{macro_id}/apply.json?ticket_id={tid}")
    # Variant 3: POST macro changes with a ticket body.
    probe("post-apply-body", "POST", f"/macros/{macro_id}/apply.json",
          {"ticket": {"id": tid}})
    # Variant 4: POST nested apply (the 404 from #695, repeated here so
    # this run's artifact holds the comparison in one place).
    probe("post-nested", "POST",
          f"/tickets/{tid}/macros/{macro_id}/apply.json")
    # Variant 5: ticket update carrying the macro id (workspace-style).
    probe("ticket-update-macro", "PUT", f"/tickets/{tid}.json",
          {"ticket": {"macro_id": macro_id}})
    st, parsed, raw = client.call("calib-comments", "GET",
                                  f"/tickets/{tid}/comments.json")
    print(f"CALIB comments-after: marker={CALIB_MARKER.encode() in raw} "
          f"bytes={len(raw)}")
    print("CALIB DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
