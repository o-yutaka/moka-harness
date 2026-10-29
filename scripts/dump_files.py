#!/usr/bin/env python3
"""File-granular code dump (GitHub Actions lane).
Usage: python3 scripts/dump_files.py "<group>;;<group>;;..."
  group = "<git repo URL>" or "<git repo URL>|<glob>|<glob>|..."
Clones each repo (depth 1), copies every file matching any glob (or all files
if no glob given) into outputs/files/<repo>/<relative path>, and writes
outputs/INDEX.txt with per-file size + sha256. Each file stays individually
retrievable from the artifact — no monolithic tarball.
"""
import os, sys, subprocess, hashlib, fnmatch, shutil

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    spec = sys.argv[1] if len(sys.argv) > 1 else ""
    groups = [g.strip() for g in spec.split(";;") if g.strip()]
    if not groups:
        print("NO SPEC"); return
    os.makedirs("outputs/files", exist_ok=True)
    index = []
    for group in groups:
        parts = [p.strip() for p in group.split("|")]
        url, globs = parts[0], parts[1:]
        name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        dest = f"work/{name}"
        subprocess.run(["git", "clone", "--depth", "1", url, dest], check=True)
        for root, dirs, files in os.walk(dest):
            if ".git" in root.split(os.sep):
                continue
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, dest)
                if globs and not any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fn, g) for g in globs):
                    continue
                out = os.path.join("outputs/files", name, rel)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copy2(full, out)
                index.append((f"{name}/{rel}", os.path.getsize(full), sha256(full)))
    with open("outputs/INDEX.txt", "w") as f:
        for rel, size, digest in sorted(index):
            f.write(f"{size}\t{digest}\t{rel}\n")
    print(f"DONE files={len(index)}")

if __name__ == "__main__":
    main()
