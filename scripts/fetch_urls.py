#!/usr/bin/env python3
"""Fetch URLs file-by-file (GitHub Actions lane).
Usage: python3 scripts/fetch_urls.py "<url>;;<url>;;..."
Saves each URL under outputs/files/<host>/<basename>. For HTML pages, also
fetches one level of <script src> / <link href> assets (JS/CSS bundles).
Writes outputs/INDEX.txt with per-file size + sha256.
"""
import os, sys, re, hashlib, urllib.request, urllib.parse

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(), r.headers.get_content_type()

def save(url, data, index):
    p = urllib.parse.urlparse(url)
    base = os.path.basename(p.path) or "index.html"
    if p.query:
        base += "_" + hashlib.sha256(p.query.encode()).hexdigest()[:8]
    out = os.path.join("outputs/files", p.netloc, base)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(data)
    index.append((f"{p.netloc}/{base}", len(data), sha256(data)))

def main():
    spec = sys.argv[1] if len(sys.argv) > 1 else ""
    urls = [u.strip() for u in spec.split(";;") if u.strip()]
    if not urls:
        print("NO SPEC"); return
    index = []
    for url in urls:
        try:
            data, ctype = fetch(url)
        except Exception as e:
            print(f"FAIL {url}: {e}"); continue
        save(url, data, index)
        if "html" in (ctype or ""):
            html = data.decode("utf-8", "replace")
            refs = re.findall(r'<script[^>]+src="([^"]+)"', html) + \
                   re.findall(r'<link[^>]+href="([^"]+\.(?:js|css))"', html)
            for ref in refs:
                asset = urllib.parse.urljoin(url, ref)
                try:
                    adata, _ = fetch(asset)
                    save(asset, adata, index)
                except Exception as e:
                    print(f"FAIL asset {asset}: {e}")
    with open("outputs/INDEX.txt", "w") as f:
        for rel, size, digest in sorted(index):
            f.write(f"{size}\t{digest}\t{rel}\n")
    print(f"DONE files={len(index)}")

if __name__ == "__main__":
    main()
