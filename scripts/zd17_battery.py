#!/usr/bin/env python3
"""ZD-17 lifecycle battery (NEW, 2026-11-11): revocation-propagation legs
that run #758 (spent-RT replay = HELD) did NOT cover:

  P1 scope legs: refresh with narrowed scope / mixed-format scope /
     bogus scope -> what is actually issued and enforced?
  P2 suspension leg: admin suspends LOW -> does LOW's OAuth lineage
     (pre-suspension AT + fresh RT exchange) keep working?
  P3 access-token revocation lag: DELETE an AT's token record, then
     re-present that AT immediately / +60s / +180s (Databricks-type).

Chain safety: every successful refresh ROTATES the head; the successor
is written back to the 600 fixture BEFORE any other call. Statuses and
sha256 fingerprints only -- token values are never printed.
Own tenant / own users only.
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent  # work/
FIX = BASE / "fixtures"
OUT = BASE / "zd17-out"
OUT.mkdir(parents=True, exist_ok=True)
LOG = []
UA = "moka-zd-battery/1.0 (Bugcrowd research; own test tenant only)"


def fp(v):
    return hashlib.sha256(v.encode()).hexdigest()[:12] if v else "-"


def say(msg):
    print(msg, flush=True)
    LOG.append(msg)


def load_env(path):
    d = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
    return d


def save_fixture(path, key, value):
    path.write_text(f"{key}={value}\n")
    os.chmod(path, 0o600)


OAUTH = load_env(FIX / "zendesk-a-oauth.env")
SUB = os.environ.get("ZENDESK_SUBDOMAIN",
                     OAUTH.get("ZENDESK_SUBDOMAIN", "bb-mimi05741b"))
CID = os.environ.get("ZD_CLIENT_ID", "") or OAUTH.get("ZENDESK_CLIENT_ID", "")
CSEC = (os.environ.get("ZD_CLIENT_SECRET", "")
        or OAUTH.get("ZENDESK_CLIENT_SECRET", ""))

try:
    import zd_battery as _zb  # for self_update_secret in Actions mode
except Exception:
    _zb = None
TOKEN_URL = f"https://{SUB}.zendesk.com/oauth/tokens"
API = f"https://{SUB}.zendesk.com/api/v2"


def req(method, url, token=None, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("User-Agent", UA)
    r.add_header("Accept", "application/json")
    if data:
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw) if raw else {}
        except Exception:
            return e.code, {"raw": raw[:200]}
    except Exception as e:
        return 0, {"neterr": type(e).__name__}


def exchange(rt, scope="read write"):
    return req("POST", TOKEN_URL, body={
        "grant_type": "refresh_token", "refresh_token": rt,
        "client_id": CID, "client_secret": CSEC, "scope": scope})


def me(at):
    st, body = req("GET", f"{API}/users/me.json", token=at)
    u = body.get("user", {}) if isinstance(body, dict) else {}
    return st, u.get("id"), u.get("suspended")


class Chain:
    """One rotating RT lineage. Candidates are tried in order until one
    exchanges 200 (stale heads just 400 and harm nothing). On rotation
    the successor is persisted FIRST: GitHub secret self-update when
    GH_PAT_SECRETS is present (Actions mode), the 600 fixture in local
    mode, and always a backup file under OUT for artifact chaining."""

    def __init__(self, name, fixture, key, secret_name, candidates):
        self.name = name
        self.fixture = fixture
        self.key = key
        self.secret_name = secret_name
        self.candidates = [c for c in candidates if c]
        self.head = None
        self.at = None

    def _persist(self):
        if os.environ.get("GH_PAT_SECRETS", "").strip() and _zb is not None:
            _zb.self_update_secret(self.secret_name, self.head)
        try:
            save_fixture(self.fixture, self.key, self.head)
        except Exception:
            pass
        p = OUT / f"zd17-{self.name.lower()}-head.txt"
        p.write_text(self.head)
        os.chmod(p, 0o600)

    def refresh(self, scope="read write", label=""):
        if self.head is None:
            for cand in self.candidates:
                st, body = exchange(cand, scope=scope)
                say(f"[{self.name}] {label} candidate fp={fp(cand)} "
                    f"exchange(scope={scope!r}) -> {st} "
                    f"err={body.get('error') if isinstance(body, dict) else '?'}")
                if st == 200 and body.get("refresh_token"):
                    self.head = body["refresh_token"]
                    self.at = body.get("access_token")
                    self._persist()
                    say(f"[{self.name}] {label} new head fp={fp(self.head)} "
                        f"persisted")
                    return st, body
            say(f"[{self.name}] {label} ALL CANDIDATES STALE")
            return 400, {}
        st, body = exchange(self.head, scope=scope)
        say(f"[{self.name}] {label} exchange(scope={scope!r}) -> {st} "
            f"err={body.get('error') if isinstance(body, dict) else '?'}")
        if st == 200 and body.get("refresh_token"):
            self.head = body["refresh_token"]
            self._persist()
            self.at = body.get("access_token")
            say(f"[{self.name}] {label} new head fp={fp(self.head)} "
                f"persisted")
        return st, body


def main():
    if not (CID and CSEC):
        say("REFUSE no client credentials in fixture")
        return
    admin_fix = load_env(FIX / "zendesk-admin-refresh.env")
    low_fix = load_env(FIX / "zendesk-low-refresh.env")
    admin = Chain("ADMIN", FIX / "zendesk-admin-refresh.env",
                  "ZD_REFRESH_TOKEN_NEXT", "ZD_REFRESH_TOKEN",
                  [os.environ.get("ZD_REFRESH_TOKEN", "").strip(),
                   os.environ.get("ZD_REFRESH_TOKEN2", "").strip(),
                   os.environ.get("ZD_REFRESH_TOKEN3", "").strip(),
                   admin_fix.get("ZD_REFRESH_TOKEN_NEXT")])
    low = Chain("LOW", FIX / "zendesk-low-refresh.env", "ZD_REFRESH_LOW",
                "ZD_REFRESH_LOW",
                [os.environ.get("ZD_REFRESH_LOW", "").strip(),
                 os.environ.get("ZD_REFRESH_LOW2", "").strip(),
                 os.environ.get("ZD_REFRESH_LOW3", "").strip(),
                 low_fix.get("ZD_REFRESH_LOW")])
    say(f"START admin candidates={len(admin.candidates)} "
        f"low candidates={len(low.candidates)}")

    # ---- P0: admin bootstrap ----
    t0 = time.time()
    st, _ = admin.refresh(label="P0 bootstrap")
    if st != 200:
        say("P0 ADMIN CHAIN STALE - admin legs skipped")
        admin_ok = False
    else:
        admin_ok = True
        stm, admin_id, _ = me(admin.at)
        say(f"P0 admin AT users/me -> {stm} id={admin_id}")

    # ---- P1: scope legs (admin chain) ----
    if admin_ok:
        # narrowed scope
        st, body = admin.refresh(scope="read", label="P1 narrow")
        if st == 200:
            stm, _, _ = me(admin.at)
            say(f"P1 narrow AT users/me -> {stm}")
            stw, wb = req("POST", f"{API}/tickets.json", token=admin.at,
                          body={"ticket": {"subject": "ZD17 scope probe",
                                           "comment": {"body": "probe"}}})
            say(f"P1 narrow AT ticket-create -> {stw}")
            tid = (wb.get("ticket") or {}).get("id") if isinstance(wb, dict) else None
            if tid:
                std, _ = req("DELETE", f"{API}/tickets/{tid}.json",
                             token=admin.at)
                say(f"P1 cleanup delete ticket {tid} -> {std}")
        # mixed-format scope
        admin.refresh(scope="read write tickets:read", label="P1 mixedfmt")
        # bogus scope
        admin.refresh(scope="read write bogus:scope", label="P1 bogus")

    # ---- P2: LOW suspension propagation ----
    stl, _ = low.refresh(label="P2 baseline")
    if stl != 200:
        say("P2 LOW CHAIN STALE - suspension leg INCONCLUSIVE")
    elif not admin_ok:
        say("P2 SKIPPED (no admin AT to suspend with)")
    else:
        stm, low_id, susp = me(low.at)
        say(f"P2 LOW AT users/me -> {stm} id={low_id} suspended={susp}")
        pre_at = low.at
        st_s, _ = req("PUT", f"{API}/users/{low_id}.json", token=admin.at,
                      body={"user": {"suspended": True}})
        say(f"P2 suspend LOW -> {st_s}")
        stm2, _, susp2 = me(pre_at)
        say(f"P2 pre-suspension AT while suspended -> {stm2} "
            f"suspended_flag={susp2}")
        stx, _ = low.refresh(label="P2 exchange-while-suspended")
        if stx == 200:
            stm3, _, _ = me(low.at)
            say(f"P2 fresh AT (minted while suspended) users/me -> {stm3}")
        st_u, _ = req("PUT", f"{API}/users/{low_id}.json", token=admin.at,
                      body={"user": {"suspended": False}})
        say(f"P2 unsuspend LOW -> {st_u}")
        stv, _ = low.refresh(label="P2 post-restore liveness")
        say(f"P2 LOW chain alive after restore: {stv == 200}")

    # ---- P3: AT revocation lag (admin chain, last) ----
    if admin_ok:
        # victim AT: one more exchange; its successor RT becomes the head
        # and a SEPARATE later AT does the revoking, so the head survives
        # even if revocation is family-wide for the victim's record only.
        t_v = time.time()
        stv, _ = admin.refresh(label="P3 victim-mint")
        victim_at = admin.at
        sth, _ = admin.refresh(label="P3 head-advance")
        if stv == 200 and sth == 200 and victim_at:
            stl2, lst = req("GET", f"{API}/oauth/tokens.json",
                            token=admin.at)
            toks = lst.get("tokens", []) if isinstance(lst, dict) else []
            say(f"P3 tokens list -> {stl2} count={len(toks)}")
            victim_rec = None
            for t in toks:
                ca = t.get("created_at", "")
                # created_at ISO; victim minted at t_v (epoch)
                try:
                    import datetime
                    ts = datetime.datetime.fromisoformat(
                        ca.replace("Z", "+00:00")).timestamp()
                except Exception:
                    continue
                if abs(ts - t_v) <= 15:
                    victim_rec = t
            if victim_rec:
                vid = victim_rec.get("id")
                say(f"P3 victim token record id={vid} "
                    f"scopes={victim_rec.get('scopes')}")
                std, _ = req("DELETE", f"{API}/oauth/tokens/{vid}.json",
                             token=admin.at)
                say(f"P3 DELETE token record -> {std}")
                for wait, tag in ((0, "+0s"), (60, "+60s"), (120, "+180s")):
                    if wait:
                        time.sleep(wait)
                    stm4, _, _ = me(victim_at)
                    say(f"P3 revoked AT re-present {tag} -> {stm4}")
            else:
                say("P3 victim record not identifiable - leg skipped")
        else:
            say("P3 mint failed - leg skipped")

    (OUT / "zd17-log.json").write_text(json.dumps(LOG, indent=1))
    say("DONE")


if __name__ == "__main__":
    main()
