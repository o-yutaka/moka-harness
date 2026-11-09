#!/usr/bin/env python3
"""
zd5_run3.py — ZD-5 evidence-hardening run 3 (per-form placeholder reach).

Runs #701/#702 (and the filed report, submission 169f1cb9) proved the
`.name` form: a LOW agent with No access to custom object type
`moka_probe` (direct GET = 403) reads the restricted record's name via
macro apply-preview placeholder rendering. The report's Impact claims
"any field of any record", but only `.name` was ever rendered — the
exact seam triage will press. This run proves (or refutes) the other
two documented forms against a FRESH record carrying TWO distinct
markers:

  NAME  = record name                    -> marker A (ZD5R3NAME-xxxx)
  FIELD = custom text field value        -> marker B (ZD5R3FIELD-xxxx)
          via {{ticket.ticket_field_<FID>.custom_fields.<field_key>}}
  ID    = record id                      -> the record's own ID string
          via {{ticket.ticket_field_<FID>.id}}

One macro whose comment body is a compound line with distinguishable
prefixes (NAME= / FIELD= / ID=) renders all three forms in a single
apply, so each form is judged independently on the same response.

Fixture facts are docs-verified (work/zd5-fixture-facts.md): the
placeholder prefix is SINGULAR (ticket_field_<FID>), the ticket lookup
field needs relationship_target_type = "zen:custom_object:moka_probe",
and the apply surface is GET /macros/{id}/apply.json?ticket_id={tid}
(calibrated run #698; POST shapes answer 404).

Order of legs follows probe_zd5 ("as before"): restriction proof
first (LOW direct GET must NOT return the record), then the CONTROL
leg (admin apply must render, or the plumbing is unproven and nothing
is read as HELD), then the TEST leg (LOW apply on a ticket assigned
to LOW). Per-form verdicts: RENDERED (LOW rendered it, control did
too), HELD (control rendered it, LOW did not), INCONCLUSIVE (control
never rendered that form — its plumbing is unproven).

Plumbing is imported from zd_battery (zb): bootstrap_token (OAuth
with self-healing refresh chain), low_client, Client, marker. This
script performs NO traffic without the explicit --run flag.

Env (required for --run):
  ZENDESK_SUBDOMAIN    e.g. bb-mimi05741b
  ZENDESK_EMAIL_LOW    the restricted (LOW) agent's email
  ZD_CLIENT_ID / ZD_CLIENT_SECRET / ZD_REFRESH_TOKEN*
                       admin OAuth material (zb.bootstrap_token)
  ZD_REFRESH_LOW* or ZENDESK_ACCESS_TOKEN_LOW
                       LOW OAuth material (zb.low_client)
Env (optional):
  ZD5R3_OUT            output root (default: ./outputs). Artifacts land
                       in <root>/zd5r3/<run_id>/ (manifest.json,
                       verdict.json, summary.txt, per-step bodies).
  ZD5R3_OBJECT_KEY     object type key (default: moka_probe)
  ZD5R3_FIELD_KEY      force the text field key (default: auto-detect;
                       the probe object carries exactly one text field,
                       "marker_field", created by probe_zd5)

Stdout discipline (Actions logs are public): step names, statuses,
verdicts, and sha256 fingerprints only. Marker VALUES and the record
ID live only in files under the run dir.

Exit codes: 0 = ran to a verdict | 2 = refused / precondition unmet |
            3 = response-shape mismatch (stop, inspect saved bodies)
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

FORMS = ("NAME", "FIELD", "ID")
LOOKUP_TITLE = "moka zd5 link"
PREFERRED_FIELD_KEY = "marker_field"


def fp(value):
    """Short sha256 fingerprint for stdout (values never printed)."""
    return hashlib.sha256(str(value).encode()).hexdigest()[:12]


def make_markers():
    """Two DISTINCT markers: A rides the record name, B the field."""
    a = zb.marker("ZD5R3NAME")
    b = zb.marker("ZD5R3FIELD")
    while b == a:  # paranoia; token_hex makes this unreachable in practice
        b = zb.marker("ZD5R3FIELD")
    return a, b


def compound_body(lookup_id, field_key):
    """The macro comment: all three placeholder forms on one line,
    each behind a distinguishable literal prefix. Singular
    `ticket_field_` form per the docs-verified fixture facts."""
    name = "{{ticket.ticket_field_%s.name}}" % lookup_id
    field = ("{{ticket.ticket_field_%s.custom_fields.%s}}"
             % (lookup_id, field_key))
    rid = "{{ticket.ticket_field_%s.id}}" % lookup_id
    return f"NAME={name} | FIELD={field} | ID={rid}"


def extract_apply_body(parsed):
    """The rendered comment body of a macro apply response:
    result.ticket.comment.body. '' when the shape differs."""
    try:
        body = parsed["result"]["ticket"]["comment"]["body"]
    except (TypeError, KeyError, AttributeError):
        return ""
    return body if isinstance(body, str) else ""


def judge_render(text, needles):
    """Per-form render judgement on a rendered text.

    needles: {form: value}. A form is RENDERED when its value appears
    in the text; `adjacent` records the stronger signal that the value
    sits immediately behind its literal prefix (NAME=<value> etc.),
    i.e. that this exact placeholder produced it."""
    out = {}
    for form in FORMS:
        value = needles.get(form)
        if not value:
            out[form] = {"rendered": False, "adjacent": False}
            continue
        out[form] = {
            "rendered": value in text,
            "adjacent": f"{form}={value}" in text,
        }
    return out


def choose_field_key(fields):
    """Pick the object's text field key from its field list.
    Prefers the probe_zd5 field ("marker_field"); otherwise the sole
    text field; otherwise None (caller creates "marker_field")."""
    keys = {f.get("key"): f for f in (fields or []) if isinstance(f, dict)}
    if PREFERRED_FIELD_KEY in keys:
        return PREFERRED_FIELD_KEY
    text_keys = [k for k, f in keys.items() if f.get("type") == "text"]
    if len(text_keys) == 1:
        return text_keys[0]
    return None


def assemble(control, test):
    """Fold control/test judgements into per-form verdicts + overall.

    control/test: judge_render dicts or None.
    A form the CONTROL never rendered is INCONCLUSIVE (plumbing for
    that form is unproven — never read a silent form as HELD)."""
    forms = {}
    for form in FORMS:
        c = bool(control and control[form]["rendered"])
        t = bool(test and test[form]["rendered"])
        if not c:
            forms[form] = "INCONCLUSIVE"
        elif t:
            forms[form] = "RENDERED"
        else:
            forms[form] = "HELD"
    if forms["FIELD"] == "RENDERED" or forms["ID"] == "RENDERED":
        overall = "EXTENDED-RENDER"
    elif forms["NAME"] == "RENDERED":
        overall = "NAME-ONLY"
    elif all(v == "HELD" for v in forms.values()):
        overall = "HELD"
    else:
        overall = "INCONCLUSIVE"
    return forms, overall


class Run3:
    """Run context: outputs/zd5r3/<run_id>/ with a zd_battery-shaped
    manifest (so `zd_battery.py --cleanup <manifest>` stays usable),
    plus verdict.json and summary.txt."""

    def __init__(self):
        root = Path(os.environ.get("ZD5R3_OUT", "outputs")) / "zd5r3"
        self.id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {"probe": "ZD-5-RUN3", "run_id": self.id,
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
    if not subdomain:
        zb.die_refuse("ZENDESK_SUBDOMAIN not set. No traffic sent.")
    if not low_email:
        zb.die_refuse("ZENDESK_EMAIL_LOW not set: the restricted-agent "
                      "legs cannot run. No traffic sent.")
    obj_key = os.environ.get("ZD5R3_OBJECT_KEY", "moka_probe")

    run = Run3()
    token = zb.bootstrap_token(subdomain, run.dir)
    client = zb.Client(subdomain, f"Bearer {token}", run.dir)
    low = zb.low_client(subdomain, run)

    marker_a, marker_b = make_markers()
    run.note(f"marker A (record name) fp={fp(marker_a)}")
    run.note(f"marker B (field value) fp={fp(marker_b)}")
    run.manifest["markers"] = {"name": marker_a, "field": marker_b}
    run.flush()
    print(f"ZD5R3 run_id={run.id} dir={run.dir}")
    print(f"ZD5R3 markers: NAME fp={fp(marker_a)} FIELD fp={fp(marker_b)}")

    def finish(payload, lines, code=0):
        run.write_verdict(payload, lines)
        return code

    def inconclusive(reasons, extra=None):
        payload = {"probe": "ZD-5-RUN3", "run_id": run.id,
                   "overall": "INCONCLUSIVE", "forms": {},
                   "reasons": reasons, **(extra or {})}
        lines = [f"VERDICT ZD-5-RUN3: INCONCLUSIVE"] + \
            [f"  - {r}" for r in reasons]
        return finish(payload, lines)

    # Preflight: Custom Objects surface present on this plan?
    st, parsed, _ = client.call("zd5r3-preflight", "GET",
                                "/custom_objects.json")
    if st in (401, 403, 404):
        payload = {"probe": "ZD-5-RUN3", "run_id": run.id,
                   "overall": "PLAN-GATED", "forms": {},
                   "reasons": [f"GET /custom_objects.json -> {st}; "
                               "Custom Objects unavailable on this plan"]}
        return finish(payload, ["VERDICT ZD-5-RUN3: PLAN-GATED",
                                f"  - preflight status={st}"])
    if st != 200:
        print("SHAPE: unexpected preflight response; inspect saved body.")
        return 3

    # Object type (create-or-reuse, as probe_zd5).
    st, parsed, _ = client.call("zd5r3-create-object", "POST",
                                "/custom_objects.json", {
        "custom_object": {"key": obj_key, "title": "Moka Probe",
                          "title_pluralized": "Moka Probes"}})
    if st not in (200, 201, 422):
        return inconclusive([f"object create status={st}; see saved body"])

    # Text field key: forced env > auto-detect > create marker_field.
    field_key = os.environ.get("ZD5R3_FIELD_KEY", "").strip() or None
    if not field_key:
        st, parsed, _ = client.call(
            "zd5r3-list-fields", "GET",
            f"/custom_objects/{obj_key}/fields.json")
        fields = ((parsed or {}).get("custom_object_fields") or [])
        field_key = choose_field_key(fields)
    if not field_key:
        st, parsed, _ = client.call(
            "zd5r3-create-field", "POST",
            f"/custom_objects/{obj_key}/fields.json", {
                "custom_object_field": {"key": PREFERRED_FIELD_KEY,
                                        "title": "Marker",
                                        "type": "text"}})
        if st not in (200, 201, 422):
            return inconclusive(
                [f"field create status={st}; see saved body"])
        field_key = PREFERRED_FIELD_KEY
    print(f"ZD5R3 field_key={field_key}")
    run.manifest["field_key"] = field_key
    run.flush()

    # Fresh record: name = marker A, text field = marker B (distinct).
    st, parsed, _ = client.call("zd5r3-create-record", "POST",
                                f"/custom_objects/{obj_key}/records.json", {
        "custom_object_record": {
            "name": marker_a,
            "custom_object_fields": {field_key: marker_b}}})
    record = ((parsed or {}).get("custom_object_record") or {})
    rec_id = record.get("id")
    if st == 422 or not rec_id:
        print("SHAPE-MISMATCH on record create — inspect the saved body.")
        return 3
    rec_id = str(rec_id)
    run.add("custom_object_record", rec_id, {"object": obj_key})
    print(f"ZD5R3 record fp={fp(rec_id)}")

    # Ticket lookup field -> this object (create-or-find by title).
    st, parsed, _ = client.call("zd5r3-create-lookup", "POST",
                                "/ticket_fields.json", {
        "ticket_field": {"type": "lookup", "title": LOOKUP_TITLE,
                         "relationship_target_type":
                         f"zen:custom_object:{obj_key}"}})
    lookup_id = ((parsed or {}).get("ticket_field") or {}).get("id")
    if not lookup_id:
        st, parsed, _ = client.call("zd5r3-list-ticket-fields", "GET",
                                    "/ticket_fields.json")
        for f in ((parsed or {}).get("ticket_fields") or []):
            if f.get("title") == LOOKUP_TITLE:
                lookup_id = f.get("id")
    if not lookup_id:
        return inconclusive(["lookup field creation failed; see saved "
                             "bodies. Not HELD."])
    run.add("ticket_field", lookup_id)

    # LOW agent must exist and be verified (probe_zd5 parity).
    st, parsed, _ = client.call(
        "zd5r3-find-low", "GET",
        "/users/search.json?query=" +
        urllib.parse.quote(low_email, safe=""))
    users = (parsed or {}).get("users") or []
    low_user = users[0] if users else None
    if not low_user or not low_user.get("verified"):
        return inconclusive([
            "LOW agent missing or not verified; the restricted legs "
            "cannot run. Not HELD."])
    low_id = low_user.get("id")
    print(f"ZD5R3 low-user verified=True role={low_user.get('role')}")

    needles = {"NAME": marker_a, "FIELD": marker_b, "ID": rec_id}

    # Restriction proof: LOW direct GET must NOT return the record.
    st_get, _, raw = low.call("zd5r3-low-get-record", "GET",
                              f"/custom_objects/{obj_key}/records/"
                              f"{rec_id}.json")
    raw_text = raw.decode("utf-8", "replace") if raw else ""
    if st_get == 200 and (marker_a in raw_text or marker_b in raw_text):
        return inconclusive([
            "SETUP INVALID: LOW can read the record directly (200 with "
            "marker content), so the restriction is not in effect."])
    print(f"ZD5R3 restriction: LOW GET record status={st_get} "
          "(non-200 = restriction in effect)")

    # Macro with the compound three-form comment body.
    body_text = compound_body(lookup_id, field_key)
    st, parsed, _ = client.call("zd5r3-create-macro", "POST",
                                "/macros.json", {
        "macro": {"title": "moka zd5 run3 macro", "active": True,
                  "actions": [{"field": "comment_value",
                               "value": body_text}]}})
    macro_id = ((parsed or {}).get("macro") or {}).get("id")
    if not macro_id:
        return inconclusive([f"macro creation failed status={st}; "
                             "see saved body"])
    run.add("macro", macro_id)

    def linked_ticket(as_client, tag, assignee=None):
        body = {"ticket": {
            "subject": f"moka zd5r3 {tag}", "tags": [tag],
            "comment": {"body": "zd5 run3 probe ticket", "public": True},
            "custom_fields": [{"id": lookup_id, "value": rec_id}]}}
        if assignee:
            body["ticket"]["assignee_id"] = assignee
        st, parsed, _ = as_client.call(f"zd5r3-ticket-{tag}", "POST",
                                       "/tickets.json", body)
        tid = ((parsed or {}).get("ticket") or {}).get("id")
        if tid:
            run.add("ticket", tid)
        return tid

    def apply_and_judge(as_client, tid, tag):
        """Apply the macro in this identity's context; judge the
        rendered comment body per form. Falls back to the ticket's
        comments (probe_zd5 parity) when the apply body renders
        nothing at all."""
        st, parsed, raw = as_client.call(
            f"zd5r3-apply-{tag}", "GET",
            f"/macros/{macro_id}/apply.json?ticket_id={tid}")
        print(f"ZD5R3 apply-{tag} status={st}")
        text = extract_apply_body(parsed)
        source = "apply-body"
        if not text:
            text = raw.decode("utf-8", "replace") if raw else ""
            source = "apply-raw"
        judged = judge_render(text, needles)
        if not any(j["rendered"] for j in judged.values()) and tid:
            st2, parsed2, raw2 = as_client.call(
                f"zd5r3-comments-{tag}", "GET",
                f"/tickets/{tid}/comments.json")
            ctext = raw2.decode("utf-8", "replace") if raw2 else ""
            judged = judge_render(ctext, needles)
            source = "comments"
        print(f"ZD5R3 judge-{tag} source={source} " + " ".join(
            f"{f}={'RENDER' if judged[f]['rendered'] else 'no'}"
            f"{'/adj' if judged[f]['adjacent'] else ''}"
            for f in FORMS))
        return judged, source

    # CONTROL leg: admin applies to a linked ticket. At least one form
    # MUST render, or the plumbing is unproven for every form.
    t_admin = linked_ticket(client, "moka_zd5r3_control")
    if not t_admin:
        return inconclusive(["control ticket creation failed; see "
                             "saved body"])
    control, control_src = apply_and_judge(client, t_admin, "control")
    if not any(control[f]["rendered"] for f in FORMS):
        return inconclusive([
            "Control leg rendered NO form: placeholder syntax or "
            "macro-apply plumbing unproven — inspect the saved apply "
            "bodies. Do NOT read any form as HELD."])

    # TEST leg: linked ticket assigned to LOW; LOW applies the macro
    # in their own context.
    t_test = linked_ticket(client, "moka_zd5r3_test", assignee=low_id)
    if not t_test:
        return inconclusive(["test ticket creation failed; see saved "
                             "body"])
    test, test_src = apply_and_judge(low, t_test, "test")

    forms, overall = assemble(control, test)
    reasons = [
        f"restriction proof: LOW direct GET of the record -> "
        f"{st_get} (no marker content returned); restriction in "
        "effect, as in runs #701/#702",
        f"control leg (admin apply, source={control_src}): " +
        ", ".join(f"{f}={'rendered' if control[f]['rendered'] else 'no'}"
                  for f in FORMS),
        f"test leg (LOW apply, source={test_src}): " +
        ", ".join(f"{f}={'rendered' if test[f]['rendered'] else 'no'}"
                  for f in FORMS),
    ]
    if overall == "EXTENDED-RENDER":
        reasons.append(
            "At least one of FIELD/ID rendered for LOW: the filed "
            "report's any-field reach is now directly evidenced, not "
            "just .name.")
    elif overall == "NAME-ONLY":
        reasons.append(
            "Only .name rendered for LOW (as in runs #701/#702); the "
            "unrendered forms are HELD for this surface — the report's "
            "Impact wording should be narrowed accordingly.")
    elif overall == "HELD":
        reasons.append(
            "Control rendered all forms for admin; LOW rendered none. "
            "This surface enforces the permission on render after all.")
    payload = {
        "probe": "ZD-5-RUN3", "run_id": run.id,
        "object": obj_key, "field_key": field_key,
        "record_id": rec_id,
        "needles_fp": {f: fp(needles[f]) for f in FORMS},
        "control": {"source": control_src, "forms": control},
        "test": {"source": test_src, "forms": test},
        "forms": forms, "overall": overall, "reasons": reasons,
    }
    lines = [f"VERDICT ZD-5-RUN3: {overall}"] + \
        [f"  - {f}: {forms[f]}" for f in FORMS] + \
        [f"  - {r}" for r in reasons]
    return finish(payload, lines)


# ----------------------------------------------------------------------
# Selftest (no network): pure functions only.
# ----------------------------------------------------------------------
def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))
        print(f"SELFTEST {name}: {'OK' if cond else 'FAIL'}")

    a, b = make_markers()
    check("markers-distinct", a != b)
    check("markers-prefixes",
          a.startswith("ZD5R3NAME-") and b.startswith("ZD5R3FIELD-"))

    body = compound_body(12345, "marker_field")
    check("body-name-form",
          "{{ticket.ticket_field_12345.name}}" in body)
    check("body-field-form",
          "{{ticket.ticket_field_12345.custom_fields.marker_field}}"
          in body)
    check("body-id-form", "{{ticket.ticket_field_12345.id}}" in body)
    check("body-singular-only", "ticket_fields_" not in body)
    check("body-prefixes",
          body.startswith("NAME=") and " | FIELD=" in body
          and " | ID=" in body)

    check("fp-shape", len(fp("x")) == 12 and fp("x") == fp("x")
          and fp("x") != fp("y"))

    sample = {"result": {"ticket": {"comment": {"body": "hello"}}}}
    check("extract-body", extract_apply_body(sample) == "hello")
    check("extract-body-missing",
          extract_apply_body({}) == "" and extract_apply_body(None) == "")

    needles = {"NAME": a, "FIELD": b, "ID": "987654"}
    full = f"NAME={a} | FIELD={b} | ID=987654"
    j = judge_render(full, needles)
    check("judge-full", all(j[f]["rendered"] and j[f]["adjacent"]
                            for f in FORMS))
    partial = (f"NAME={a} | "
               "FIELD={{ticket.ticket_field_12345.custom_fields."
               "marker_field}} | ID=987654")
    j = judge_render(partial, needles)
    check("judge-partial", j["NAME"]["rendered"]
          and not j["FIELD"]["rendered"] and j["ID"]["rendered"])
    empty_field = f"NAME={a} | FIELD= | ID=987654"
    j = judge_render(empty_field, needles)
    check("judge-empty-field", not j["FIELD"]["rendered"])
    loose = f"prefix {a} suffix | FIELD={b} | ID=987654"
    j = judge_render(loose, needles)
    check("judge-loose", j["NAME"]["rendered"]
          and not j["NAME"]["adjacent"])

    check("fieldkey-preferred",
          choose_field_key([{"key": "marker_field", "type": "text"},
                            {"key": "other", "type": "text"}])
          == "marker_field")
    check("fieldkey-sole-text",
          choose_field_key([{"key": "note", "type": "text"},
                            {"key": "n", "type": "number"}]) == "note")
    check("fieldkey-none",
          choose_field_key([{"key": "n", "type": "number"}]) is None
          and choose_field_key([]) is None)

    allr = {f: {"rendered": True, "adjacent": True} for f in FORMS}
    none_r = {f: {"rendered": False, "adjacent": False} for f in FORMS}
    t = dict(allr)
    t["ID"] = {"rendered": False, "adjacent": False}
    forms, overall = assemble(allr, t)
    check("assemble-extended",
          forms == {"NAME": "RENDERED", "FIELD": "RENDERED",
                    "ID": "HELD"} and overall == "EXTENDED-RENDER")
    t = dict(none_r)
    t["NAME"] = {"rendered": True, "adjacent": True}
    forms, overall = assemble(allr, t)
    check("assemble-name-only",
          forms["NAME"] == "RENDERED" and forms["FIELD"] == "HELD"
          and overall == "NAME-ONLY")
    forms, overall = assemble(allr, none_r)
    check("assemble-held",
          all(v == "HELD" for v in forms.values())
          and overall == "HELD")
    c = dict(allr)
    c["FIELD"] = {"rendered": False, "adjacent": False}
    t = dict(none_r)
    t["FIELD"] = {"rendered": True, "adjacent": True}
    forms, overall = assemble(c, t)
    check("assemble-control-unproven",
          forms["FIELD"] == "INCONCLUSIVE")

    ok = sum(1 for _, v in results if v)
    print(f"SELFTEST: {ok}/{len(results)} ALL OK"
          if ok == len(results) else
          f"SELFTEST: {ok}/{len(results)} — FAILURES PRESENT")
    return 0 if ok == len(results) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", action="store_true",
                    help="execute the run-3 measurement (network)")
    ap.add_argument("--selftest", action="store_true",
                    help="pure-function selftest; no network")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.run:
        return run_probe()
    zb.die_refuse("no mode selected: pass --run or --selftest. "
                  "Nothing fires by default.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
