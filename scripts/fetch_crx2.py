#!/usr/bin/env python3
import os, re, hashlib, urllib.request
xml = ('<?xml version="1.0" encoding="UTF-8"?>'
       '<request protocol="3.0" version="1.3.23.9" shell_version="1.3.21.103" ismachine="1" sessionid="{11111111-2222-3333-4444-555555555555}" installsource="ondemand" requestid="{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}" dedup="cr">'
       '<hw sse="1" sse2="1" sse3="1" ssse3="1" sse41="1" sse42="1" avx="1" physmemory="16"/>'
       '<os platform="win" version="10.0.0" arch="x64"/>'
       '<app appid="aeblfdkhhhdcdjpifhhbdiojplfjncoa" version="" ap="" lang="en-US" brand="" installage="-1" installdate="-1">'
       '<updatecheck/></app></request>')
req = urllib.request.Request("https://tools.google.com/service/update2", data=xml.encode(), headers={"User-Agent": "Google Update/1.3.36.151;winhttp", "Content-Type": "application/x-www-form-urlencoded"})
resp = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
print("OMAHA", resp[:600])
m = re.search(r'codebase="([^"]+)"', resp)
print("CODEBASE", m.group(1) if m else "NONE")
if m:
    r2 = urllib.request.Request(m.group(1), headers={"User-Agent": "Mozilla/5.0"})
    data = urllib.request.urlopen(r2, timeout=120).read()
    os.makedirs("outputs", exist_ok=True)
    open("outputs/op.crx", "wb").write(data)
    print("SIZE", len(data))
    print("SHA256", hashlib.sha256(data).hexdigest())
    print("MAGIC", data[:4])
print("DONE fetch_crx2")
