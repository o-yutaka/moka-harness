#!/usr/bin/env python3
import json, os, subprocess, urllib.request, zipfile, io

OP_VER = "v2.31.0"
OP_URL = "https://cache.agilebits.com/dist/1P/op2/pkg/" + OP_VER + "/op_linux_amd64_" + OP_VER + ".zip"

def sh(args, env):
    r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, (r.stdout or ""), (r.stderr or "")

def main():
    tok = os.environ.get("OP_SA_TOKEN", "")
    print("TOKEN_PRESENT:", bool(tok), "len", len(tok))
    if not tok:
        print("DONE no-token"); return
    try:
        data = urllib.request.urlopen(OP_URL, timeout=120).read()
        z = zipfile.ZipFile(io.BytesIO(data))
        z.extractall("/tmp/opbin")
        op = "/tmp/opbin/op"
        os.chmod(op, 0o755)
        print("OP_DOWNLOAD ok bytes", len(data))
    except Exception as e:
        print("OP_DOWNLOAD FAIL", repr(e)); print("DONE"); return
    env = dict(os.environ)
    env["OP_SERVICE_ACCOUNT_TOKEN"] = tok
    env["OP_FORMAT"] = "json"
    rc, out, err = sh([op, "--version"], env)
    print("OP_VERSION:", out.strip(), "rc", rc)

    def run(label, args):
        rc, out, err = sh([op] + args, env)
        body = out.strip()
        try:
            parsed = json.loads(body) if body else None
        except Exception:
            parsed = None
        print("--- " + label + " rc=" + str(rc))
        if err.strip():
            print("  stderr:", err.strip()[:300])
        return rc, parsed, body

    rc, who, _ = run("whoami", ["whoami"])
    if isinstance(who, dict):
        print("  whoami keys:", sorted(who.keys()))

    rc, vaults, _ = run("vault list", ["vault", "list"])
    vnames = [v.get("name") for v in vaults] if isinstance(vaults, list) else None
    print("  vaults visible:", vnames)

    rc, items, _ = run("item list scope-test", ["item", "list", "--vault", "scope-test"])
    titles, ids = [], {}
    if isinstance(items, list):
        for it in items:
            titles.append(it.get("title")); ids[it.get("title")] = it.get("id")
    print("  scope-test items:", titles)

    rc, items_arch, _ = run("item list scope-test incl-archive", ["item", "list", "--vault", "scope-test", "--include-archive"])
    titles_arch = [it.get("title") for it in items_arch] if isinstance(items_arch, list) else None
    print("  scope-test items incl-archive:", titles_arch)
    if isinstance(items_arch, list):
        for it in items_arch:
            ids.setdefault(it.get("title"), it.get("id"))

    if ids.get("probe-login"):
        rc, got, _ = run("item get probe-login", ["item", "get", ids["probe-login"], "--vault", "scope-test"])
        if isinstance(got, dict):
            fields = [(f.get("label"), f.get("type"), len(str(f.get("value") or ""))) for f in got.get("fields", [])]
            print("  probe-login fields(label,type,len):", fields)
    if ids.get("probe-archived"):
        rc, got, raw = run("item get probe-archived (archived)", ["item", "get", ids["probe-archived"], "--vault", "scope-test"])
        print("  archived get rc:", rc, "body-head:", raw[:120])
    rc, na_items, raw = run("item list no-access", ["item", "list", "--vault", "no-access"])
    print("  no-access list rc:", rc, "body-head:", raw[:160])
    rc, na_get, raw = run("item get offlimits-login in no-access", ["item", "get", "offlimits-login", "--vault", "no-access"])
    print("  no-access get rc:", rc, "body-head:", raw[:160])
    rc, created, raw = run("item create in scope-test (write probe)", ["item", "create", "--vault", "scope-test", "--category", "login", "--title", "write-probe", "username=x@example.com", "password=dummy"])
    print("  create rc:", rc, "body-head:", raw[:160])
    rc, vc, raw = run("vault create (probe)", ["vault", "create", "sa-vault-probe"])
    print("  vault create rc:", rc, "body-head:", raw[:160])
    print("DONE")

if __name__ == "__main__":
    main()
