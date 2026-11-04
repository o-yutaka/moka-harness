import io, json, os, urllib.request, zipfile

ARTIFACT_ID = 13359936146
URL = f"https://api.github.com/repos/o-yutaka/moka-harness/actions/artifacts/{ARTIFACT_ID}/zip"
req = urllib.request.Request(URL, headers={"Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}", "Accept": "application/vnd.github+json", "User-Agent": "moka-harness"})
with urllib.request.urlopen(req) as resp:
    data = resp.read()
z = zipfile.ZipFile(io.BytesIO(data))
names = z.namelist()
print('[ARTIFACT] names=' + str(names))
target = next((n for n in names if n.endswith('exchange-error.json')), None)
if not target:
    raise SystemExit('exchange-error.json not found')
payload = json.loads(z.read(target).decode())
print('[ERROR] ' + str(payload.get('error')))
