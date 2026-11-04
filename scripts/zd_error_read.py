import io, json, os, zipfile
import requests

ARTIFACT_ID = 13359936146
URL = f"https://api.github.com/repos/o-yutaka/moka-harness/actions/artifacts/{ARTIFACT_ID}/zip"
resp = requests.get(URL, headers={"Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}", "Accept": "application/vnd.github+json", "User-Agent": "moka-harness"}, timeout=60)
print('[ARTIFACT] status=' + str(resp.status_code))
resp.raise_for_status()
z = zipfile.ZipFile(io.BytesIO(resp.content))
names = z.namelist()
print('[ARTIFACT] names=' + str(names))
target = next((n for n in names if n.endswith('exchange-error.json')), None)
if not target:
    raise SystemExit('exchange-error.json not found')
payload = json.loads(z.read(target).decode())
print('[ERROR] ' + str(payload.get('error')))
