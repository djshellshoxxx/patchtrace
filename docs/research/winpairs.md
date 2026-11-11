# Winbindex before/after binary pairs (accuracy cases)

Helper: `python -m tools.research_qualification.winpairs --manifest CASES.json --out-dir DIR --pair-manifest OUT.json [--case id,id] [--resolve-only]`. Workflow: `.github/workflows/winbindex-pairs.yml` (workflow_dispatch only). Input is an `rq-case-manifest/1` file (for example `docs/research/accuracy-cases/windows-candidates.json`, added by PR #260; the workflow default points there). Output is `rq-pair-manifest/1`.

## Contract

- Each case side (`older`, `newer`) names a binary. Explicit keys win: `file`, `version`, `kb`, `sha256`, `month` (`YYYY-MM`), `machine` (`amd64` default, `x86`, `arm64`). Otherwise the free-text `ref` is mined: first token is the file, then a `10.x.y.z` version, a `KBnnnnnnn`, and a `YYYY-Mon` month.
- Selection never guesses. If more than one distinct sha256 matches and the case has no version, KB or sha256 pin, the side is `missing` with reason `ambiguous`. A pinned multi-match picks highest version, then newest timestamp, then sha256 (deterministic). Many current candidate refs are month-only, so expect `missing` until the case is pinned.
- Download: https only, hosts `winbindex.m417z.com` and `msdl.microsoft.com`; redirects are followed by hand (max 3) and every hop is re-checked. A redirect hop may additionally land on `*.blob.core.windows.net` (see Verified). 200 MiB cap per binary, 64 MiB cap on the compressed index plus a decompression cap, 60 s timeout. sha256 of the download must equal the Winbindex sha256 or the side becomes `missing` and the file is deleted.
- Manifest records case id, file, version, timestamp, virtual size, expected and actual sha256, size, symbol-server URL, relative path, status `found`/`missing` and a reason. Redirect (signed blob) URLs are never recorded. A case is `found` only when both sides are.
- Exit codes: 0 at least one case found, 1 every requested case missing, 2 blocked or usage (bad manifest, unknown case id, unsafe name, path outside the allowed roots via `pathguard.confine`). Missing pairs are data, not errors.
- Fetched binaries are never executed and never committed. The workflow uploads them as `winpairs-binaries` and the manifest as `winpairs-manifest`, both with 7-day retention.

## Verified (2026-11-06, live from this shell, not from memory)

- `https://winbindex.m417z.com/data/by_filename_compressed/<name>.json.gz` returns 200 for `afd.sys` (lower-case file name). JSON is an object keyed by file sha256. Each value has `fileInfo` (`size`, `md5`, `sha1`, `sha256`, `machineType`, `timestamp`, `virtualSize`, `version`, ...) and `windowsVersions[<release>][<KB>]` with `updateInfo.releaseDate`/`heading`. `machineType` 34404 is amd64 (0x8664). Zero of 294 `afd.sys` entries lacked `timestamp`, but the code still skips any entry that does.
- Symbol path `<name>/<TIMESTAMP %08X><virtualSize %x>/<name>` is accepted: for an `afd.sys` 10.0.22621.317 entry the server answered 302 (not 404). A full run of the helper for two `afd.sys` builds (10.0.26100.6899 and .7171) downloaded both files and both sha256 values matched Winbindex.
- `msdl.microsoft.com` redirects to a signed `*.blob.core.windows.net` URL, which is why that suffix is allowed on redirect hops only.
- Offline: 35 pytest tests (URL builder, selection, ambiguity, allowlist, redirects, caps, gzip bomb, hash mismatch, missing, exit codes, confinement).

## Unverified

- Whether Winbindex timestamp/virtualSize is the PE TimeDateStamp/SizeOfImage for every entry type (assumed from the 302 above; no PE was parsed).
- Winbindex data completeness for the candidate cases (e.g. whether older/newer builds exist for every month listed) and the `ntoskrnl.exe`/`win32kfull.sys` pairs: only `afd.sys` was exercised live.
- Symbol-server rate limits (none published, see `kb-winbindex-packages.md` F7) and the licence wording (G4: use is limited to debugging and testing "with Microsoft software"). The owner must settle whether patch-diffing use fits before the workflow is run routinely.
- The `run_ghidriff` step: written but never executed. It skips with a message unless `pip install ghidriff` works and `GHIDRA_INSTALL_DIR` points to a Ghidra install (ubuntu-latest has none by default), so it will normally skip.
- GitHub Actions behaviour of the workflow (YAML parses with `yaml.safe_load`; nothing else was run).

## Open gates

- A real `workflow_dispatch` run is only possible after this workflow is on `main`. Until then the live evidence above is a local run only.
- Month-only refs in the candidate manifest need version/KB pins before they resolve.
