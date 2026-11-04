import subprocess, sys, time

def sh(*args):
    print("+", " ".join(args), flush=True)
    r = subprocess.run(args, capture_output=True, text=True)
    print((r.stdout or "")[-1500:], flush=True)
    print((r.stderr or "")[-1500:], flush=True)
    return r.returncode

print("PROBE_START upwork_signup_reachability", flush=True)
sh(sys.executable, "-m", "pip", "install", "-q", "playwright")
sh(sys.executable, "-m", "playwright", "install", "chromium")

from playwright.sync_api import sync_playwright

URL = "https://www.upwork.com/nx/signup/?regv1=1"
verdict = "PROBE_CHALLENGE_STUCK"
with sync_playwright() as p:
    b = p.chromium.launch(headless=True, args=["--no-sandbox"])
    pg = b.new_page(locale="en-US", viewport={"width": 1280, "height": 900})
    try:
        pg.goto(URL, wait_until="domcontentloaded", timeout=60000)
    except Exception as e:
        print("PROBE_GOTO_ERR", str(e)[:120], flush=True)
    for i in range(30):
        try:
            title = pg.title()
        except Exception:
            title = "?"
        try:
            n = pg.locator("input").count()
        except Exception:
            n = -1
        body = ""
        try:
            body = pg.locator("body").inner_text()[:2000]
        except Exception:
            pass
        print(f"PROBE_POLL {i*5}s title={title!r} inputs={n}", flush=True)
        if n >= 3 or "First name" in body or "Create my account" in body:
            verdict = "PROBE_FORM_REACHABLE"
            break
        time.sleep(5)
    b.close()
print("PROBE_VERDICT", verdict, flush=True)
print("PROBE_DONE", flush=True)
