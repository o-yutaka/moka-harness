#!/usr/bin/env python3
"""Aiven run 5: admin-api (Regatta backend) sweep with a CUSTOMER token. GET only."""
import json
import os
import sys
import urllib.request
import urllib.error

ADMIN = "https://admin-api.aiven.io:4343/v1"
T1 = os.environ.get("AIVEN_TOKEN_1", "")
if not T1:
    print("token missing", flush=True)
    sys.exit(2)

PATHS = ['/addresses', '/addresses/1', '/addresses/1/events', '/aiven/dc2', '/billing/commitment', '/billing/commitments', '/billing/discount', '/billing/discount/1', '/billing/discounts', '/billing/dunning/pause', '/billing/extra-charges', '/billing/group-ids', '/billing/group/event-log', '/billing/group/1', '/billing/group/1/activate', '/billing/group/1/activate-users', '/billing/group/1/netsuite/export', '/billing/group/1/projects', '/billing/group/1/suspend', '/billing/group/1/suspend-users', '/billing/group/1/users', '/billing/groups', '/billing/groups/1', '/billing/groups/1/dunning', '/billing/groups/1/payment-method', '/billing/invoice/describe', '/billing/invoice/reset', '/billing/invoice/retry/charge', '/billing/invoice/set-state', '/billing/invoice/1/change-log', '/billing/invoice/1/csv', '/billing/invoice/1/dunning', '/billing/invoice/1/netsuite/export', '/billing/invoice/1/pdf', '/billing/invoices', '/billing/metronome/customer-contract', '/billing/netsuite/export-invoices', '/billing/partner-report', '/billing/payment-methods', '/billing/services', '/cmaps/', '/com.snowplowanalytics.snowplow/tp2', '/console/feature-flags', '/console/feature-flags/1', '/credits', '/credits/assign', '/credits/code', '/credits/promotion', '/credits/search', '/credits/1', '/credits/1/events', '/emails/1', '/marketplace/metering/fee-breakdown/aggregate', '/marketplace/metering/fee-breakdown/aggregate/csv', '/marketplace/metering/fee-breakdown/csv', '/marketplace/one-time-charges', '/marketplace/one-time-charges/1', '/mfa/challenge', '/node-types', '/oauth/token', '/organizations/1', '/organizations/1/activate', '/organizations/1/activate-users', '/organizations/1/audit-log', '/organizations/1/billing-report', '/organizations/1/dunning', '/organizations/1/features', '/organizations/1/payment-methods/bank-transfers', '/organizations/1/payment-methods/bank-transfers/1', '/organizations/1/payment-methods/custom', '/organizations/1/payment-methods/custom/1', '/organizations/1/payment-methods/1', '/organizations/1/suspend', '/organizations/1/suspend-users', '/organizations/1/trial', '/plan-specs', '/plan-specs/usage-from-aivendb', '/plan-specs/1/access', '/plan-specs/1/1', '/plan-specs/1/1/access', '/plan-specs/1/1/availability', '/plan-specs/1/1/events', '/plans/migrate-source', '/pricing/plan-pricing-calc', '/regatta/acls/check', '/regatta/config', '/regatta/dunning/organizations-with-paused-resources', '/regatta/dunning/overdue-invoices', '/regatta/dunning/paused', '/regatta/dunning/sent', '/regatta/feature-flags', '/regatta/feature-flags/1', '/regatta/organization/1/users', '/regatta/organizations', '/regatta/projects', '/regatta/projects/1/acls', '/regatta/salesforce-cases', '/regatta/salesforce-cases/1/comments', '/regatta/salesforce/accounts', '/regatta/salesforce/accounts/1', '/regatta/salesforce/accounts/1/organizations', '/regatta/users/search', '/regatta/users/1/permissions', '/service-plan-proposals', '/service-plan-proposals/validate-specs', '/service-plan-proposals/1', '/service-plan-proposals/1/approval', '/service-plan-proposals/1/availability', '/service-plan-proposals/1/deploy', '/service-plan-proposals/1/events', '/service-plan-proposals/1/possible-regions-based-on-node-types', '/service-plan-proposals/1/tco-scenarios', '/standard_fonts/', '/support/contract/v3', '/support/contracts/v3', '/suspension-cases', '/suspension-cases/bookmark', '/suspension-cases/investigation', '/suspension-cases/invoices', '/suspension-cases/1', '/suspension-cases/1/comment', '/suspension-cases/1/entities', '/suspension-cases/1/event-logs', '/suspension-cases/1/invoices', '/suspension-cases/1/state', '/suspension-cases/1/work-items', '/tco-scenarios', '/tco-scenarios/byoc-service-plan-proposals', '/tco-scenarios/calc', '/tco-scenarios/service-plans/1', '/tco-scenarios/standard-service-plan-proposals', '/tco-scenarios/1', '/tco-scenarios/1/calc', '/tco-scenarios/1/clone', '/tco-scenarios/1/csv', '/users/me', '/users/me/regatta/feature-flags', '/users/me/token/restricted', '/users/me/tokens', '/users/me/tokens/1', '/users/1']

os.makedirs("outputs", exist_ok=True)
RESULTS = []


def get(path, token):
    headers = {}
    if token:
        headers["Authorization"] = f"aivenv1 {token}"
    r = urllib.request.Request(ADMIN + path, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERROR {e}"[:200]


def main():
    for p in ["/billing/groups", "/users/me", "/regatta/organizations"]:
        s, b = get(p, None)
        RESULTS.append({"path": p, "auth": "none", "status": s,
                        "len": len(b), "body": b[:300]})
        print(f"CTRL none GET {p} -> {s} ({len(b)}B)", flush=True)
    hits = 0
    for p in PATHS:
        s, b = get(p, T1)
        interesting = s != 404
        if interesting:
            hits += 1
        RESULTS.append({"path": p, "auth": "customer", "status": s,
                        "len": len(b),
                        "body": b[:600] if interesting else b[:80]})
        print(f"T1 GET {p} -> {s} ({len(b)}B)", flush=True)
    with open("outputs/aiven_admin_sweep.json", "w") as f:
        json.dump({"results": RESULTS}, f, indent=1)
    print(f"DONE paths={len(PATHS)} non404={hits}", flush=True)


if __name__ == "__main__":
    main()
