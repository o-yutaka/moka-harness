#!/usr/bin/env python3
import os, hashlib, urllib.request
url = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3&x=id%3Daeblfdkhhhdcdjpifhhbdiojplfjncoa%26uc"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"})
data = urllib.request.urlopen(req, timeout=120).read()
os.makedirs("outputs", exist_ok=True)
open("outputs/op.crx", "wb").write(data)
print("SIZE", len(data))
print("SHA256", hashlib.sha256(data).hexdigest())
print("MAGIC", data[:4])
print("DONE fetch_crx")
