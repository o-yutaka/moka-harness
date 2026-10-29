"""Environment report: proves the Actions lane works and records runner facts."""
import json
import os
import platform
import sys
import urllib.request


def egress_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=10) as r:
            return json.loads(r.read().decode())["ip"]
    except Exception as e:
        return f"unavailable ({e})"


def main():
    report = {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "egress_ip": egress_ip(),
        "runner_os": os.environ.get("RUNNER_OS", ""),
        "github_repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
    }
    text = json.dumps(report, indent=2)
    print(text)
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/report.json", "w") as f:
        f.write(text + "\n")


if __name__ == "__main__":
    main()
