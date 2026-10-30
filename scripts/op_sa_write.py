#!/usr/bin/env python3
import json, os, subprocess

def sh(args, env):
    r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, (r.stdout or ""), (r.stderr or "")

def main():
    tok = os.environ.get("OP_SA_TOKEN", "")
    print("TOKEN_PRESENT:", bool(tok))
    op = "/tmp/opbin/op"
    if not os.path.exists(op):
        import urllib.request, zipfile, io
        OP_VER = "v2.31.0"
        data = urllib.request.urlopen("https://cache.agilebits.com/dist/1P/op2/pkg/" + OP_VER + "/op_linux_amd64_" + OP_VER + ".zip", timeout=120).read()
        zipfile.ZipFile(io.BytesIO(data)).extractall("/tmp/opbin")
        os.chmod(op, 0o755)
        print("OP fetched")
    env = dict(os.environ); env["OP_SERVICE_ACCOUNT_TOKEN"] = tok
    envj = dict(env); envj["OP_FORMAT"] = "json"
    rc, out, err = sh([op, "item", "get", "otvk75ien46wiaipskn72gk5eq", "--vault", "scope-test"], envj)
    print("archived get rc", rc)
    try:
        got = json.loads(out)
        fields = [(f.get("label"), f.get("type"), len(str(f.get("value") or ""))) for f in got.get("fields", [])]
        print("archived fields(label,type,len):", fields)
    except Exception as e:
        print("archived parse fail", repr(e), out[:120])
    rc, out, err = sh([op, "item", "create", "--vault", "scope-test", "--category", "login", "--title", "write-probe", "username=x@example.com", "password=dummy"], env)
    print("create rc", rc, "err:", err.strip()[:200], "out:", out.strip()[:120])
    rc, out, err = sh([op, "item", "edit", "probe-login", "--vault", "scope-test", "password=newdummy"], env)
    print("edit rc", rc, "err:", err.strip()[:200])
    rc, out, err = sh([op, "item", "delete", "probe-login", "--vault", "scope-test"], env)
    print("delete rc", rc, "err:", err.strip()[:200])
    rc, out, err = sh([op, "item", "share", "probe-login", "--vault", "scope-test", "--emails", "x@example.com"], env)
    print("share rc", rc, "err:", err.strip()[:200], "out:", out.strip()[:80])
    print("DONE")

if __name__ == "__main__":
    main()
