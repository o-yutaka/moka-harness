#!/usr/bin/env python3
"""Build the d-you sandbox APK (+ wallet backend jar) from pinned source.

Purpose: produce the real artifacts so REA's Android/JVM lanes and
compare-source-to-bundle have something to bite on. Source-build route
was closed for *registration* (gateway credential gate) — this build is
for static analysis only.

Pins (dyou/work/repos/PINS.md, 2026-11-01):
  android 3cb054ba2598da3306891796b6a7e25c97c31f43 (submodules recorded in tree)
  backend 7e0ed7389c8ac944d6723ac39d775fcc12c7abcd
Outputs: APK(s) + backend jar copied to outputs/ with sha256 lines.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import time

ANDROID_URL = "https://github.com/german-national-wallet/de-eudi-wallet-android.git"
ANDROID_SHA = "3cb054ba2598da3306891796b6a7e25c97c31f43"
BACKEND_URL = "https://github.com/german-national-wallet/de-eudi-wallet-backend.git"
BACKEND_SHA = "7e0ed7389c8ac944d6723ac39d775fcc12c7abcd"

ROOT = os.getcwd()
OUT = os.path.join(ROOT, "outputs")
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "dyou_build.log"), "a", buffering=1)


def say(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.write(line + "\n")


RUN_SEQ = [0]


def run(cmd, cwd, timeout=3000):
    say(f"$ {' '.join(cmd)}  (cwd={cwd})")
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, timeout=timeout)
    RUN_SEQ[0] += 1
    full = os.path.join(OUT, f"cmd_{RUN_SEQ[0]:02d}.log")
    with open(full, "w") as fh:
        fh.write(p.stdout)
    lines = p.stdout.splitlines()
    head = "\n".join(lines[:15])
    tail = "\n".join(lines[-25:])
    LOG.write(head + "\n...[full output: " + os.path.basename(full) + "]...\n" + tail + "\n")
    print(tail, flush=True)
    say(f"rc={p.returncode}")
    return p.returncode


def clone(url, sha, dest):
    rc = run(["git", "clone", "--filter=blob:none", url, dest], ROOT, timeout=1200)
    if rc != 0:
        return False
    rc = run(["git", "checkout", sha], dest, timeout=600)
    gw = os.path.join(dest, "gradlew")
    if os.path.exists(gw):
        os.chmod(gw, 0o755)
    return rc == 0


# The OSS sync strips submodule gitlinks: .gitmodules exists but the tree has
# no core/ or openid4vci/ entries, so `git submodule update` is a no-op.
# Populate both library checkouts manually at the .gitmodules branches.
LIB_CHECKOUTS = [
    ("core", "https://github.com/german-national-wallet/eudi-lib-android-wallet-core",
     "develop-0.30.2", "document-manager"),
    ("openid4vci", "https://github.com/german-national-wallet/eudi-lib-jvm-openid4vci-kt",
     "develop-0.14.0", None),
]


def populate_libs(dest):
    for sub, url, branch, marker in LIB_CHECKOUTS:
        target = os.path.join(dest, sub)
        probe = os.path.join(target, marker) if marker else target
        if os.path.exists(probe):
            say(f"lib {sub}: already present")
            continue
        if os.path.isdir(target):
            shutil.rmtree(target)
        rc = run(["git", "clone", "--branch", branch, url, target], ROOT, timeout=1200)
        say(f"lib {sub}: clone rc={rc} marker_exists={os.path.exists(probe)}")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ship(path, tag):
    dst = os.path.join(OUT, os.path.basename(path))
    shutil.copy2(path, dst)
    say(f"ARTIFACT {tag}: {dst} size={os.path.getsize(dst)} sha256={sha256(dst)}")


def build_android():
    dest = os.path.join(ROOT, "de-eudi-wallet-android")
    if not clone(ANDROID_URL, ANDROID_SHA, dest):
        say("VERDICT_APK: CLONE_FAIL")
        return
    run(["git", "submodule", "update", "--init", "--recursive"], dest, timeout=1200)
    populate_libs(dest)
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    sdkmanager = os.path.join(sdk, "cmdline-tools", "latest", "bin", "sdkmanager")
    if os.path.exists(sdkmanager):
        try:
            p = subprocess.run([sdkmanager, "--licenses"], input="y\n" * 30,
                               capture_output=True, text=True, timeout=300)
            say(f"licenses rc={p.returncode}")
        except Exception as e:  # noqa: BLE001
            say(f"licenses step skipped: {e}")
    rc = run(["./gradlew", ":app:assembleSandboxDebug", "--stacktrace", "--no-daemon"],
             dest, timeout=3000)
    if rc != 0:
        say("assembleSandboxDebug failed, falling back to assembleDebug")
        rc = run(["./gradlew", ":app:assembleDebug", "--stacktrace", "--no-daemon"],
                 dest, timeout=3000)
    apks = []
    for base, _dirs, files in os.walk(os.path.join(dest, "app", "build", "outputs", "apk")):
        for f in files:
            if f.endswith(".apk"):
                apks.append(os.path.join(base, f))
    if not apks:
        say("VERDICT_APK: NO_APK_PRODUCED")
        return
    for a in sorted(apks):
        ship(a, "APK")
    say(f"VERDICT_APK: OK count={len(apks)}")


def build_backend():
    dest = os.path.join(ROOT, "de-eudi-wallet-backend")
    if not clone(BACKEND_URL, BACKEND_SHA, dest):
        say("VERDICT_BACKEND: CLONE_FAIL")
        return
    rc = run(["./gradlew", "bootJar", "--stacktrace", "--no-daemon"], dest, timeout=3000)
    jars = []
    libdir = os.path.join(dest, "build", "libs")
    if os.path.isdir(libdir):
        for f in os.listdir(libdir):
            if f.endswith(".jar"):
                jars.append(os.path.join(libdir, f))
    if rc != 0 or not jars:
        say(f"VERDICT_BACKEND: NO_JAR rc={rc}")
        return
    for j in sorted(jars):
        ship(j, "BACKEND_JAR")
    say(f"VERDICT_BACKEND: OK count={len(jars)}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    say(f"dyou_build_apk start mode={mode}")
    if mode in ("all", "apk"):
        try:
            build_android()
        except Exception as e:  # noqa: BLE001
            say(f"VERDICT_APK: EXCEPTION {e}")
    if mode in ("all", "backend"):
        try:
            build_backend()
        except Exception as e:  # noqa: BLE001
            say(f"VERDICT_BACKEND: EXCEPTION {e}")
    say("dyou_build_apk done")


if __name__ == "__main__":
    main()
