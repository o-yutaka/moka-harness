#!/usr/bin/env python3
"""TFH cleanup: delete 'probe-action' actions created by the T3 battery on app1.
Uses the GraphQL proxy with TFH_KEY_1 (own team only)."""
import json, os, urllib.request, urllib.error

KEY1 = os.environ["TFH_KEY_1"]
APP1 = "app_a834cd108ab340e07eaa03ac5fe94f34"
BASE = "https://developer.world.org"

def gql(query, variables=None):
    req = urllib.request.Request(BASE + "/api/v1/graphql", method="POST")
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
    req.add_header("Accept", "application/json, text/plain, */*")
    req.add_header("Authorization", "Bearer " + KEY1)
    req.add_header("Content-Type", "application/json")
    data = json.dumps({"query": query, "variables": variables or {}}).encode()
    try:
        with urllib.request.urlopen(req, data=data, timeout=40) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")

s, r = gql('{action(where:{app_id:{_eq:"%s"}}){id action}}' % APP1)
print("LIST", s, json.dumps(r)[:400], flush=True)
ids = [a["id"] for a in (r.get("data") or {}).get("action", []) if a.get("action") == "probe-action"]
print("PROBE_ACTIONS", ids, flush=True)
for aid in ids:
    s, r = gql('mutation($id:String!){delete_action_by_pk(id:$id){id}}', {"id": aid})
    print("DELETE", aid, s, json.dumps(r)[:200], flush=True)
s, r = gql('{action(where:{app_id:{_eq:"%s"}}){id action}}' % APP1)
print("AFTER", s, json.dumps(r)[:400], flush=True)
print("DONE tfh_cleanup", flush=True)
