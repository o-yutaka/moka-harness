#!/usr/bin/env python3
"""Dump Modern Treasury public code for AI audit: clone SDKs + OpenAPI spec,
extract auth/org-scoping relevant material, package everything as an artifact.
Output: outputs/mt-dump.tar.gz + outputs/INDEX.txt (file list, sizes, sha256).
"""
import os, subprocess, hashlib, tarfile, glob

REPOS = [
    "https://github.com/modern-treasury/modern-treasury-python",
    "https://github.com/modern-treasury/modern-treasury-go",
    "https://github.com/modern-treasury/modern-treasury-ruby",
    "https://github.com/modern-treasury/openapi",
]
KEYWORDS = ("auth", "organization", "org_id", "webhook", "signature",
            "client_token", "publishable", "api_key", "basic")

def sh(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)

def main():
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("dump", exist_ok=True)
    for url in REPOS:
        name = url.rstrip("/").split("/")[-1]
        try:
            sh(["git", "clone", "--depth", "1", url, f"dump/{name}"])
        except subprocess.CalledProcessError:
            print("CLONE FAILED", url, flush=True)
    hits = []
    for path in glob.glob("dump/**/*", recursive=True):
        if not os.path.isfile(path) or "/.git/" in path:
            continue
        low = path.lower()
        hit = any(k in low for k in KEYWORDS)
        if not hit and os.path.getsize(path) < 400_000:
            try:
                with open(path, "rb") as f:
                    data = f.read().decode("utf-8", "ignore").lower()
                hit = any(k in data for k in ("organization_id", "x-organization", "basic " + "auth"))
            except OSError:
                pass
        if hit:
            hits.append(path)
    os.makedirs("dump/_extracted", exist_ok=True)
    with open("dump/_extracted/hits.txt", "w") as f:
        f.write("\n".join(sorted(hits)))
    with tarfile.open("outputs/mt-dump.tar.gz", "w:gz") as tar:
        tar.add("dump")
    digest = hashlib.sha256(open("outputs/mt-dump.tar.gz", "rb").read()).hexdigest()
    with open("outputs/INDEX.txt", "w") as f:
        f.write(f"sha256: {digest}\nfiles_in_tar: see _extracted/hits.txt\n")
        for p in sorted(hits)[:300]:
            f.write(f"{os.path.getsize(p)}\t{p}\n")
    print("DONE", digest, "hits:", len(hits), flush=True)

if __name__ == "__main__":
    main()
