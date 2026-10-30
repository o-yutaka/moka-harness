import re, os, time, hashlib, urllib.request, urllib.error, ssl
from urllib.parse import urljoin
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'}
def get(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.geturl(), r.read()
def harvest(label, start_url):
    OUT = 'outputs/affirm-' + label
    os.makedirs(OUT, exist_ok=True)
    try:
        st, fin, body = get(start_url)
        print(label.upper(), 'INDEX', st, len(body), fin[:100])
        open(os.path.join(OUT, 'index.html'), 'wb').write(body)
        html = body.decode('utf-8', 'ignore')
        srcs = re.findall(r'<script[^>]+src="([^"]+)"', html) + re.findall(r'<link[^>]+href="([^"]+\.js)"', html)
        print(label.upper(), 'SCRIPTS', len(srcs))
        for i, s in enumerate(srcs[:16]):
            u = urljoin(fin, s)
            name = re.sub(r'[^A-Za-z0-9._-]', '_', u.split('/')[-1].split('?')[0]) or ('a%d.js' % i)
            try:
                st2, fu2, b2 = get(u)
                open(os.path.join(OUT, '%02d-%s' % (i, name)), 'wb').write(b2)
                print(label.upper(), 'DL', i, st2, len(b2), hashlib.sha256(b2).hexdigest()[:10], u[:100])
            except Exception as e:
                print(label.upper(), 'DLFAIL', i, repr(e)[:80], u[:100])
            time.sleep(1)
    except Exception as e:
        print(label.upper(), 'FAIL', repr(e)[:140])
harvest('dash', 'https://sandbox.affirm.com/dashboard/signin')
harvest('uapp', 'https://sandbox.affirm.com/u/loans')
print('DONE')
