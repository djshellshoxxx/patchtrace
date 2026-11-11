# Runbook: verify the BinDiff v8 pin (U8, closes the BinDiff part of G-U3)

`tools/bindiff_pin.json` holds trust-on-first-use values: the digests were computed from the official release assets, twice, through one egress proxy, and upstream publishes no per-asset digest. `verified` is `false`, and `python -m tools.unified.bindiff_pin verify --require-verified` exits 3, so G-U3's oracle part stays `blocked`. Nothing in the repository may set `verified` to `true` except the steps below, done by a person (or a dispatch job they review) with network access. Never copy a digest from this page or from anywhere but your own run.

What counts as verified (checked by `tools/unified/bindiff_pin.py`): the pin schema holds; every digest field (`assets.*.sha256`, `assets.linux.executable_sha256`, `signature.sha256`) is a real 64-digit lowercase SHA-256, not a placeholder (all zeros, short, repeated pattern, the digest of empty input, `TODO`, `unpinned`); `signature.verified` is `true` and `signature.signature_verified_by` names who or what checked the `.asc`; `verified` is `true`. The advisory Windows asset may stay unverified, but if it is listed its digests must still be real.

## 1. Re-hash the assets from a network path independent of the first two runs
Use a machine or runner that is not the research egress proxy.

```bash
mkdir -p "$HOME/bindiff-verify" && cd "$HOME/bindiff-verify"
base=https://github.com/google/bindiff/releases/download/v8
curl -fsSLO "$base/bindiff_8_amd64.deb"
curl -fsSLO "$base/bindiff_8_amd64.deb.asc"
curl -fsSLO "$base/bindiff8.msi"
sha256sum bindiff_8_amd64.deb bindiff_8_amd64.deb.asc bindiff8.msi
stat -c '%n %s' bindiff_8_amd64.deb bindiff_8_amd64.deb.asc bindiff8.msi
```

Compare each line with the pin (`assets.linux.sha256`/`size`, `signature.sha256`/`size`, `assets.windows.sha256`/`size`). A mismatch is a finding: stop, do not edit the pin, record both values and the network path in `docs/qa.md`, and ask which is right (the release may have been replaced).

## 2. Verify the detached signature
The pin records issuer key id `4EB27DB2A3B88B8B`. Obtain the public key from two independent channels (for example the key file published by the google/bindiff project and a keyserver) and compare the full fingerprint across both before trusting it.

```bash
gpg --keyserver hkps://keys.openpgp.org --recv-keys 4EB27DB2A3B88B8B   # or import the project's published key file
gpg --fingerprint 4EB27DB2A3B88B8B
gpg --verify bindiff_8_amd64.deb.asc bindiff_8_amd64.deb
```

Proceed only on `Good signature` from that key. A missing key or `BAD signature` leaves the pin unverified.

## 3. Check the executable digest
```bash
python - <<'PY'
import hashlib, io, sys, tarfile
# stdlib ar reader: data.tar.* member of the .deb, then the bindiff executable
data = open('bindiff_8_amd64.deb', 'rb').read()
assert data[:8] == b'!<arch>\n'
pos = 8
while pos < len(data):
    name = data[pos:pos + 16].decode().strip().rstrip('/'); size = int(data[pos + 48:pos + 58]); body = data[pos + 60:pos + 60 + size]
    pos += 60 + size + (size & 1)
    if name.startswith('data.tar'):
        with tarfile.open(fileobj=io.BytesIO(body)) as tar:
            exe = tar.extractfile('./opt/bindiff/bin/bindiff').read()
        print(len(exe), hashlib.sha256(exe).hexdigest()); sys.exit()
PY
```
It must print the pin's `executable_size` and `executable_sha256`. (`tools/provision_bindiff.py` performs the same check with its hardened extractor; running `python tools/provision_bindiff.py` per `.github/workflows/live-bindiff.yml` is an equivalent.)

## 4. Record the result in the pin (only after steps 1 to 3 all agree)
```bash
who="gpg $(gpg --version | head -1 | awk '{print $3}') key 4EB27DB2A3B88B8B, re-hashed on $(date -u +%F) by <your name>"
jq --arg who "$who" '.verified = true | .signature.verified = true | .signature.signature_verified_by = $who
  | .trust = "signature verified against the issuer key and digests re-hashed from an independent network path; see signature.signature_verified_by"' \
  tools/bindiff_pin.json > pin.new && mv pin.new tools/bindiff_pin.json
python -m tools.unified.bindiff_pin verify --require-verified
python -m pytest tests/test_unified_bindiff_pin.py tests/test_provision_bindiff.py -q
```
If a digest changed in step 1, edit that field from your own `sha256sum` output instead (never from this page). `tests/test_provision_bindiff.py::test_committed_pin_holds_real_v8_values_marked_trust_on_first_use` pins the TOFU wording and `verified is False`; update that test in the same commit. Then dispatch `live-bindiff.yml` and note both run URLs and the `verify` output in `docs/qa.md`.

## 5. Without a workstation: a dispatch job
A reviewed `workflow_dispatch` job on a GitHub-hosted runner can run steps 1 and 3 (it cannot establish key trust by itself; step 2 still needs a person to compare the fingerprint). It must print the `sha256sum` and `gpg --verify` output into the job summary and change nothing in the repository; the owner then applies step 4. The gate workflow reads the result of the check with:

```yaml
- id: bindiff_pin
  run: python -m tools.unified.bindiff_pin verify --github-output "$GITHUB_OUTPUT"
# later steps: if: steps.bindiff_pin.outputs.bindiff_pin_verified == 'true'
```
Exit 2 (malformed pin or placeholder) must fail the job; exit 0 with `bindiff_pin_verified=false` means the BinDiff oracle part stays `blocked`.
