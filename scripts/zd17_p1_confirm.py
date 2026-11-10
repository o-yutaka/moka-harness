#!/usr/bin/env python3
"""ZD-17 P1 confirmation run (NEW, 2026-11-11): second reproduction of
the scope-narrowing leg first measured in Actions run #818, this time
RECORDING the scope field the token endpoint actually returns.

Run #818 showed: refresh(scope="read") -> narrowed AT -> ticket-create
201 (a write succeeded on a supposedly read-only token). Unrecorded
there: the exchange response's own `scope` value, which decides the
claim shape:
  (a) returned scope == "read" yet the AT writes -> enforcement gap
  (b) returned scope silently widened to the full set -> the endpoint
      ignores the narrowing request (declaration gap)

Leg (admin chain only):
  bootstrap refresh (default scope) -> refresh(scope="read"), logging
  the token response's key set and its `scope` value verbatim ->
  users/me with the narrowed AT -> ticket-create attempt (deleted
  immediately if created) -> explicit RESULT / SUMMARY lines.

Chain safety is inherited from zd17_battery.Chain: every successful
refresh rotates the head and the successor is persisted FIRST (GitHub
secret self-update in Actions mode, 600 fixture locally). Statuses and
sha256 fingerprints only -- token values are never printed.

This script is a continuation of the ZD-17 refresh-token lifecycle
battery (zd17_battery.py, whose Chain implementation it reuses). It is
NOT an authorization-code exchange/replay script, NOT a
side-conversation script, and NOT a report skeleton.
Own tenant / own user only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zd17_battery import (API, CID, CSEC, FIX, Chain, fp, load_env, me,
                          req, say)


def main():
    if not (CID and CSEC):
        say("REFUSE no client credentials in fixture")
        return
    admin_fix = load_env(FIX / "zendesk-admin-refresh.env")
    admin = Chain("ADMIN", FIX / "zendesk-admin-refresh.env",
                  "ZD_REFRESH_TOKEN_NEXT", "ZD_REFRESH_TOKEN",
                  [os.environ.get("ZD_REFRESH_TOKEN", "").strip(),
                   os.environ.get("ZD_REFRESH_TOKEN2", "").strip(),
                   os.environ.get("ZD_REFRESH_TOKEN3", "").strip(),
                   admin_fix.get("ZD_REFRESH_TOKEN_NEXT")])
    say(f"P1CONF START admin candidates={len(admin.candidates)}")

    # ---- bootstrap: get a live head at the default scope ----
    st, _ = admin.refresh(label="P1CONF bootstrap")
    if st != 200:
        say("P1CONF ADMIN CHAIN STALE - INCONCLUSIVE")
        say("DONE")
        return
    stm, admin_id, _ = me(admin.at)
    say(f"P1CONF bootstrap AT users/me -> {stm} id={admin_id}")

    # ---- the narrow leg, with the returned scope recorded verbatim ----
    st, body = admin.refresh(scope="read", label="P1CONF narrow")
    if st != 200 or not isinstance(body, dict):
        say(f"P1CONF narrow exchange failed st={st} - INCONCLUSIVE")
        say("DONE")
        return
    returned_scope = body.get("scope")
    say(f"P1CONF narrow response keys={sorted(body.keys())}")
    say(f"P1CONF narrow returned scope={returned_scope!r}")
    say(f"P1CONF narrowed AT fp={fp(admin.at)}")

    stm, uid, susp = me(admin.at)
    say(f"P1CONF narrowed AT users/me -> {stm} id={uid} suspended={susp}")

    stw, wb = req("POST", f"{API}/tickets.json", token=admin.at,
                  body={"ticket": {"subject": "ZD17 P1-confirm scope probe",
                                   "comment": {"body": "probe"}}})
    say(f"P1CONF narrowed AT ticket-create -> {stw}")
    tid = (wb.get("ticket") or {}).get("id") if isinstance(wb, dict) else None
    if tid:
        std, _ = req("DELETE", f"{API}/tickets/{tid}.json",
                     token=admin.at)
        say(f"P1CONF cleanup delete ticket {tid} -> {std}")

    if stw == 201:
        say("P1CONF RESULT ticket-create with read-scoped AT: SUCCEEDED "
            "(write NOT blocked)")
    elif stw in (401, 403):
        say(f"P1CONF RESULT ticket-create with read-scoped AT: BLOCKED "
            f"({stw}) - narrowing enforced on this leg")
    else:
        say(f"P1CONF RESULT ticket-create unexpected status {stw}")
    say(f"P1CONF SUMMARY returned_scope={returned_scope!r} "
        f"users_me={stm} ticket_create={stw}")
    say("DONE")


if __name__ == "__main__":
    main()
