import re, os, time, hashlib, urllib.request, ssl
OUT = 'outputs/affirm-web'
os.makedirs(OUT, exist_ok=True)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'}
def get(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.geturl(), r.read()
try:
    status, final, body = get('https://sandbox.affirm.com/')
    print('INDEX status=', status, 'final=', final, 'bytes=', len(body))
    open(os.path.join(OUT, 'index.html'), 'wb').write(body)
    html = body.decode('utf-8', 'ignore')
    srcs = re.findall(r'<script[^>]+src="([^"]+)"', html)
    print('SCRIPTS found:', len(srcs))
    from urllib.parse import urljoin
    n = 0
    for s in srcs:
        u = urljoin(final, s)
        name = re.sub(r'[^A-Za-z0-9._-]', '_', u.split('/')[-1].split('?')[0]) or ('asset%d.js' % n)
        try:
            st, fu, b = get(u)
            open(os.path.join(OUT, '%02d-%s' % (n, name)), 'wb').write(b)
            print('DL', n, st, len(b), hashlib.sha256(b).hexdigest()[:12], u[:110])
        except Exception as e:
            print('DLFAIL', n, repr(e)[:90], u[:110])
        n += 1
        if n >= 14: break
        time.sleep(1)
except Exception as e:
    print('INDEXFAIL', repr(e)[:160])
print('DONE')
