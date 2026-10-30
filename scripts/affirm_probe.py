import os, time, urllib.request, urllib.error, ssl
OUT = 'outputs/affirm-probe'
os.makedirs(OUT, exist_ok=True)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'}
PATHS = ['/login', '/signup', '/dashboard', '/dashboard/', '/merchant', '/merchants', '/checkout', '/apply', '/account', '/register', '/business/login', '/api/v2/checkout', '/api/v2/charges', '/api/v1/checkout', '/charge', '/loans', '/onboarding']
def probe(url):
    req = urllib.request.Request(url, headers=UA, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            b = r.read()
            return r.status, r.geturl(), len(b), b
    except urllib.error.HTTPError as e:
        try: b = e.read()
        except Exception: b = b''
        return e.code, url, len(b), b
    except Exception as e:
        return 0, url, 0, ('ERR ' + repr(e)[:100]).encode()
for p in PATHS:
    st, fin, n, b = probe('https://sandbox.affirm.com' + p)
    print('PROBE', p, '->', st, n, fin[:100])
    time.sleep(1)
try:
    st, fin, n, b = probe('https://cdn1.affirm.com/js/v2/affirm.js')
    print('AFFIRMJS ->', st, n, fin[:100])
    open(os.path.join(OUT, 'affirm.js'), 'wb').write(b)
except Exception as e:
    print('AFFIRMJS FAIL', repr(e)[:120])
print('DONE')
