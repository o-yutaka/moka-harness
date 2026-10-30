#!/usr/bin/env python3
import urllib.request, urllib.error

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

url = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3&x=id%3Daeblfdkhhhdcdjpifhhbdiojplfjncoa%26uc"
opener = urllib.request.build_opener(NoRedirect)
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"})
try:
    r = opener.open(req, timeout=60)
    print("STATUS", r.status)
    print("HEADERS", dict(r.headers))
    print("BODYLEN", len(r.read()))
except urllib.error.HTTPError as e:
    print("HTTPERROR", e.code)
    print("HEADERS", dict(e.headers))
    print("BODYLEN", len(e.read()))
print("DONE diag_crx")
