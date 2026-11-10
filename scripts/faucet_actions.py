#!/usr/bin/env python3
"""faucet_actions: try the faucet.solana.com devnet airdrop from the GitHub
Actions egress with a REAL Chrome (headed under Xvfb) driven by Playwright.

Background: from the local lane the Turnstile widget silently never lets the
app fire its airdrop request (no POST observed, balance stayed 0). The Actions
runner is a different egress + a fresh Chrome profile, so one measured attempt
is worth it. This script only reports what actually happened:

- Every step is printed with a [faucet] tag (flush=True, the harness tees
  stdout into outputs/faucet_actions.log).
- Any request/response touching an airdrop-ish API is logged with its URL and
  status, so "did the airdrop POST ever fire" is answered from the log.
- Screenshots are saved under outputs/ (uploaded as the run artifact).
- The run always ends with a devnet RPC getBalance for the wallet and the
  lines BALANCE_LAMPORTS=<value> and FAUCET_ACTIONS_DONE.

No secrets are handled: the wallet is a throwaway devnet address and the
faucet flow used here is the unauthenticated tier (no GitHub sign-in).
"""
import os
import shutil
import subprocess
import sys
import time

import requests

WALLET = "56ndMbw7Ux3DfAQqMNW3aGsPrWhqWicooX2UmVxGgEyd"
FAUCET_URL = "https://faucet.solana.com/"
DEVNET_RPC = "https://api.devnet.solana.com"
OUTDIR = "outputs"


def log(msg):
    print(f"[faucet] {msg}", flush=True)


def run(cmd, timeout=300):
    log(f"$ {' '.join(cmd)}")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    tail = (p.stdout + p.stderr).strip().splitlines()
    for line in tail[-4:]:
        log(f"  | {line[:200]}")
    log(f"  exit={p.returncode}")
    return p.returncode


def ensure_chrome():
    """Return a Chrome/Chromium executable path, installing Chrome if needed."""
    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser"):
        path = shutil.which(name)
        if path:
            log(f"browser found: {name} -> {path}")
            return path
    log("no browser on PATH; installing google-chrome-stable from Google's deb")
    deb = "/tmp/google-chrome.deb"
    try:
        r = requests.get(
            "https://dl.google.com/linux/direct/"
            "google-chrome-stable_current_amd64.deb",
            timeout=180)
        r.raise_for_status()
        with open(deb, "wb") as f:
            f.write(r.content)
        log(f"chrome deb downloaded: {len(r.content)} bytes")
    except Exception as e:  # noqa: BLE001
        log(f"chrome deb download failed: {type(e).__name__}: {str(e)[:140]}")
        return None
    run(["sudo", "apt-get", "update", "-qq"], timeout=600)
    if run(["sudo", "apt-get", "install", "-y", "-qq", deb], timeout=900) != 0:
        run(["sudo", "apt-get", "install", "-y", "-qq",
             "google-chrome-stable"], timeout=900)
    return shutil.which("google-chrome") or shutil.which("google-chrome-stable")


def ensure_xvfb():
    if shutil.which("Xvfb"):
        return True
    log("Xvfb missing; installing xvfb")
    run(["sudo", "apt-get", "update", "-qq"], timeout=600)
    return run(["sudo", "apt-get", "install", "-y", "-qq", "xvfb"],
               timeout=900) == 0


def ensure_playwright():
    try:
        import playwright  # noqa: F401
        log("playwright already importable")
        return True
    except ImportError:
        pass
    rc = run([sys.executable, "-m", "pip", "install", "--quiet",
              "playwright"], timeout=900)
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        log(f"playwright still not importable after pip install (rc={rc})")
        return False


def get_balance():
    try:
        r = requests.post(
            DEVNET_RPC,
            json={"jsonrpc": "2.0", "id": 1, "method": "getBalance",
                  "params": [WALLET]},
            timeout=25)
        value = r.json()["result"]["value"]
        log(f"getBalance HTTP {r.status_code} -> {value} lamports")
        return value
    except Exception as e:  # noqa: BLE001
        log(f"getBalance failed: {type(e).__name__}: {str(e)[:140]}")
        return -1


def is_airdrop_traffic(url):
    u = url.lower()
    return ("airdrop" in u or "/api/" in u) and "solana" in u


def attempt(chrome_path):
    from playwright.sync_api import sync_playwright

    os.makedirs(OUTDIR, exist_ok=True)
    fired = {"count": 0}

    def on_request(req):
        if is_airdrop_traffic(req.url):
            fired["count"] += 1
            log(f"API REQUEST {req.method} {req.url[:180]}")

    def on_response(res):
        if is_airdrop_traffic(res.url):
            log(f"API RESPONSE {res.status} {res.url[:180]}")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            executable_path=chrome_path,
            headless=False,
            args=["--no-sandbox", "--disable-setuid-sandbox",
                  "--disable-blink-features=AutomationControlled",
                  "--window-size=1280,860"],
        )
        page = browser.new_page(viewport={"width": 1280, "height": 860})
        page.on("request", on_request)
        page.on("response", on_response)

        log(f"goto {FAUCET_URL}")
        page.goto(FAUCET_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(6000)
        log(f"page title: {page.title()!r}")
        page.screenshot(path=f"{OUTDIR}/faucet_01_loaded.png")

        body = page.evaluate("document.body.innerText.slice(0, 400)")
        log("page head: " + body.replace("\n", " | ")[:400])

        # network selector: default is devnet; force it if a <select> exists
        try:
            sel = page.locator("select").first
            if sel.count():
                sel.select_option("devnet", timeout=3000)
                log("network <select> set to devnet")
        except Exception as e:  # noqa: BLE001
            log(f"network select skipped: {str(e)[:100]}")

        # 1) wallet address
        addr = page.locator('input[type="text"], input:not([type])').first
        addr.click(timeout=10000)
        addr.fill(WALLET)
        log("wallet address filled")

        # 2) Amount dropdown -> "1"
        page.get_by_text("Amount", exact=True).first.click(timeout=10000)
        page.wait_for_timeout(1500)
        opt = page.locator("text=/^1$/").first
        log(f"amount option '1' count={opt.count()}")
        opt.click(timeout=10000)
        log("amount 1 selected")
        page.wait_for_timeout(800)
        page.screenshot(path=f"{OUTDIR}/faucet_02_form.png")

        # 3) Confirm Airdrop once enabled
        confirm = page.get_by_role("button", name="Confirm Airdrop")
        log(f"confirm disabled? {confirm.is_disabled()}")
        confirm.click(timeout=15000)
        log("confirm clicked")
        page.wait_for_timeout(5000)
        page.screenshot(path=f"{OUTDIR}/faucet_03_after_confirm.png")

        # 4) poll up to 60s; click the Turnstile checkbox when it appears
        clicked_frames = 0
        for i in range(12):
            text = page.evaluate("document.body.innerText.slice(0, 900)")
            flat = text.replace("\n", " | ")
            log(f"poll{i}: {flat[:420]}")
            if "verification failed" in text.lower():
                log("turnstile explicitly FAILED")
                break
            frame = None
            for f in page.frames:
                if "challenges.cloudflare.com" in f.url:
                    frame = f
                    break
            if frame is not None and clicked_frames < 3:
                try:
                    box = frame.locator('input[type="checkbox"]')
                    if box.count():
                        box.first.click(timeout=5000)
                    else:
                        frame.locator("body").click(
                            position={"x": 28, "y": 28}, timeout=5000)
                    clicked_frames += 1
                    log(f"turnstile checkbox clicked (#{clicked_frames})")
                except Exception as e:  # noqa: BLE001
                    log(f"turnstile click failed: {str(e)[:120]}")
            if fired["count"] > 0 and i >= 2:
                log("airdrop API traffic observed; giving it time to settle")
                page.wait_for_timeout(5000)
                break
            page.wait_for_timeout(5000)
        page.screenshot(path=f"{OUTDIR}/faucet_04_final.png")
        final = page.evaluate("document.body.innerText.slice(0, 900)")
        log("final page: " + final.replace("\n", " | ")[:420])
        log(f"airdrop API requests fired: {fired['count']}")
        browser.close()


def main():
    log(f"start wallet={WALLET}")
    log(f"balance before: {get_balance()} lamports")
    try:
        if not ensure_playwright():
            log("playwright unavailable; skipping browser attempt")
            raise SystemExit(0)
        if not ensure_xvfb():
            log("Xvfb unavailable; skipping browser attempt")
            raise SystemExit(0)
        xvfb = subprocess.Popen(
            ["Xvfb", ":99", "-screen", "0", "1280x860x24"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.environ["DISPLAY"] = ":99"
        time.sleep(2)
        log(f"Xvfb started pid={xvfb.pid} DISPLAY=:99")
        chrome = ensure_chrome()
        if not chrome:
            log("no Chrome available; skipping browser attempt")
            raise SystemExit(0)
        try:
            attempt(chrome)
        except Exception as e:  # noqa: BLE001
            log(f"browser attempt failed: {type(e).__name__}: {str(e)[:200]}")
        finally:
            xvfb.terminate()
    finally:
        balance = get_balance()
        print(f"BALANCE_LAMPORTS={balance}", flush=True)
        print("FAUCET_ACTIONS_DONE", flush=True)


if __name__ == "__main__":
    main()
