#!/usr/bin/env python3
"""d-you GHA emulator probe — stage 1 (no credentials, no sign-in attempt).

Question: on a GitHub-hosted ubuntu runner, does a google_apis_playstore
x86_64 emulator (API 35) boot, present the Play stack, and declare the
hardware features the d-you sandbox app hard-requires?
App requirements (from source, assembly-logic manifest, all required=true):
  android.hardware.nfc / android.hardware.bluetooth / android.hardware.bluetooth_le
If any is missing, Play filtering kills this lane exactly like MuMu.
Outputs land in outputs/ (harness uploads them as the run artifact).
Exit code is always 0; verdicts are printed as VERDICT_* lines.
"""
import os
import subprocess
import sys
import time

OUT = "outputs"
os.makedirs(OUT, exist_ok=True)
SDK = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk"
ADB = os.path.join(SDK, "platform-tools", "adb")
EMU = os.path.join(SDK, "emulator", "emulator")
SDKM = os.path.join(SDK, "cmdline-tools", "latest", "bin", "sdkmanager")
AVDM = os.path.join(SDK, "cmdline-tools", "latest", "bin", "avdmanager")
SYSIMG = "system-images;android-35;google_apis_playstore;x86_64"
REQUIRED = ["android.hardware.nfc", "android.hardware.bluetooth", "android.hardware.bluetooth_le"]


def run(cmd, timeout=300, inp=None, echo=True):
    if echo:
        print(f"$ {cmd}", flush=True)
    try:
        p = subprocess.run(cmd, shell=True, input=inp, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        if echo:
            print(out[-4000:], flush=True)
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        print(f"TIMEOUT after {timeout}s: {cmd}", flush=True)
        return -1, (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")


def adb(args, timeout=120):
    return run(f'"{ADB}" {args}', timeout=timeout)


def save(name, text):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)


def main():
    print("=== dyou_emu_probe stage 1 ===", flush=True)
    print(f"SDK={SDK}", flush=True)
    run("uname -a; nproc; free -m; df -h / | tail -1; ls -la /dev/kvm 2>&1; java -version 2>&1 | head -2")

    # KVM permission (standard step for GitHub-hosted runners)
    run("echo 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0666\", OPTIONS+=\"static_node=kvm\"' | sudo tee /etc/udev/rules.d/99-kvm4all.rules && sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm; ls -la /dev/kvm")

    # SDK packages
    run(f'yes | "{SDKM}" --licenses > /dev/null 2>&1; "{SDKM}" "platform-tools" "emulator" "platforms;android-35" "{SYSIMG}"', timeout=1800)
    run("df -h / | tail -1")

    # AVD
    run(f'echo no | "{AVDM}" create avd -n emu -k "{SYSIMG}" -d pixel_6 --force', timeout=180)
    run(f'"{EMU}" -list-avds')

    # Boot
    emu_log = open(os.path.join(OUT, "emulator.log"), "w")
    proc = subprocess.Popen(
        [EMU, "-avd", "emu", "-no-window", "-no-audio", "-no-boot-anim",
         "-gpu", "swiftshader_indirect", "-no-snapshot", "-wipe-data", "-memory", "2048"],
        stdout=emu_log, stderr=subprocess.STDOUT)
    print(f"emulator pid={proc.pid}", flush=True)
    adb("wait-for-device", timeout=180)
    booted = False
    for i in range(60):
        rc, out = adb("shell getprop sys.boot_completed", timeout=30)
        if "1" in out.strip().splitlines()[-1:][0:]:
            booted = True
            break
        if proc.poll() is not None:
            print("EMULATOR_EXITED_EARLY", flush=True)
            break
        time.sleep(10)
    print(f"VERDICT_BOOT: {'OK' if booted else 'FAIL'}", flush=True)
    if not booted:
        run(f"tail -50 {OUT}/emulator.log")
        return

    time.sleep(5)
    _, props = adb("shell getprop", timeout=60)
    save("getprop.txt", props)
    for key in ["ro.build.fingerprint", "ro.product.model", "ro.build.version.sdk",
                "ro.build.version.release", "ro.build.tags", "ro.product.cpu.abilist"]:
        for line in props.splitlines():
            if key in line:
                print(line.strip(), flush=True)

    _, feats = adb("shell pm list features", timeout=60)
    save("features.txt", feats)
    have = set()
    for line in feats.splitlines():
        if "feature:" in line:
            have.add(line.split("feature:")[1].strip())
    missing = [f for f in REQUIRED if f not in have]
    print(f"VERDICT_FEATURES: {'PASS' if not missing else 'FAIL'} missing={missing}", flush=True)
    for extra in ["android.hardware.fingerprint", "android.hardware.camera",
                  "android.hardware.camera.front", "android.software.device_admin"]:
        print(f"feature {extra}: {'present' if extra in have else 'absent'}", flush=True)

    _, pkgs = adb("shell pm list packages", timeout=60)
    play = [p for p in pkgs.splitlines() if any(k in p for k in ["vending", "android.gms", "gsf"])]
    print("play stack packages:", play, flush=True)
    _, ver = adb("shell dumpsys package com.android.vending | grep -m1 versionName", timeout=60)
    print(f"VERDICT_PLAY: {'PRESENT ' + ver.strip() if play else 'ABSENT'}", flush=True)

    def shot(name):
        rc, _ = run(f'"{ADB}" exec-out screencap -p > {OUT}/{name}', timeout=60)
        print(f"screenshot {name} rc={rc} size={os.path.getsize(os.path.join(OUT, name)) if os.path.exists(os.path.join(OUT, name)) else -1}", flush=True)

    shot("shot-home.png")
    adb("shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n com.android.vending/.AssetBrowserActivity", timeout=60)
    time.sleep(12)
    shot("shot-play.png")
    _, ui = adb("shell uiautomator dump /sdcard/play.xml && cat /sdcard/play.xml", timeout=90)
    save("play-ui.xml", ui)
    texts = []
    import re
    for m in re.finditer(r'text="([^"]{2,80})"', ui):
        if m.group(1) not in texts:
            texts.append(m.group(1))
    print("play UI texts:", texts[:25], flush=True)
    print("VERDICT_STAGE1: DONE", flush=True)

    run(f'"{ADB}" emu kill', timeout=60)
    proc.terminate()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"PROBE_EXCEPTION: {type(e).__name__}: {e}", flush=True)
    sys.exit(0)
