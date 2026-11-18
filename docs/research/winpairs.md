# Winbindex before/after binary pairs (accuracy cases)

Helper: `python -m tools.research_qualification.winpairs --manifest CASES.json --out-dir DIR --pair-manifest OUT.json [--case id,id] [--resolve-only]`. Workflow: `.github/workflows/winbindex-pairs.yml` (workflow_dispatch only). Input is an `rq-case-manifest/1` file (for example `docs/research/accuracy-cases/windows-candidates.json`, added by PR #260; the workflow default points there). Output is `rq-pair-manifest/1`.

## Contract

- Each case side (`older`, `newer`) names a binary. Explicit keys win: `file`, `version`, `kb`, `sha256`, `month` (`YYYY-MM`), `machine` (`amd64` default, `x86`, `arm64`). Otherwise the free-text `ref` is mined: first token is the file, then a `10.x.y.z` version, a `KBnnnnnnn`, and a `YYYY-Mon` month.
- Selection never guesses. Every query must resolve to exactly one SHA-256 identity. Version, KB and month constraints narrow candidates but do not authorize choosing the highest version or newest timestamp among different hashes. A version is matched as four exact integer components, not as a textual prefix. Distinct remaining hashes or conflicting identity metadata for one hash make the side `missing` with reason `ambiguous`; add an independently verified exact hash to resolve distinct-hash ambiguity. A valid Winbindex SHA-256 is required before downloading.
- Download: https only, hosts `winbindex.m417z.com` and `msdl.microsoft.com`; redirects are followed by hand (max 3) and every hop is re-checked. A redirect hop may additionally land on `*.blob.core.windows.net` (see Verified). 200 MiB cap per binary, 64 MiB cap on the compressed index plus a decompression cap, 60 s timeout. The downloaded SHA-256 must equal the Winbindex SHA-256 and its byte length must agree with a supplied size. A mismatch makes the side `missing`; it never removes or changes an earlier artifact.
- Manifest records case id, file, version, timestamp, virtual size, expected and actual sha256, size, symbol-server URL, relative path, status `found`/`missing` and a reason. Redirect (signed blob) URLs are never recorded. A case is `found` only when both sides are.
- Exit codes: 0 at least one case found, 1 every requested case missing, 2 blocked or usage (bad manifest, unknown case id, unsafe name, path outside the allowed roots via `pathguard.confine`). Missing pairs are data, not errors.
- Fetched binaries are never executed and never committed. The workflow uploads them as `winpairs-binaries` and the manifest as `winpairs-manifest`, both with 7-day retention.

### Immutable output and retry amendment (2026-11-18)

Use a new output location for each acquisition attempt. Existing binary paths,
including links and directories, are refused before downloading that side. An
existing pair-manifest path is refused before any network operation. An earlier
valid or damaged result is never overwritten, adopted or deleted by a retry.
The manifest and each binary are staged in their destination directory, flushed
and fsynced, then published atomically without replacing any existing destination.
A destination created concurrently wins; its contents remain intact. Failed or
interrupted publication cleans up only the exact staging object owned by this
attempt. Successful earlier sides remain available if a later side or the manifest
fails. These are separate immutable artifacts, not an all-files transaction.

### Open-file publication amendment (2026-11-18)

Path checks alone do not establish ownership. Publication must bind both its
source and destination parent to open filesystem objects. A renamed/replaced
parent must never redirect publication or cleanup into the replacement directory.
The staged byte length, SHA-256 and open-file identity are checked before
publication. Cleanup must not unlink a staging name that could now belong to a
different file. Parent replacement makes the attempt blocked, with no verified
receipt for the replacement path. If the replacement occurs after the atomic
publication, an already published owned artifact may remain in the original
directory; the helper must not delete either directory's final path.

On Linux, staging is an anonymous `O_TMPFILE` in a no-follow, descriptor-anchored
parent. An exclusive link from the owned open file publishes that exact inode;
closing the descriptor cleans up an unpublished anonymous stage. Every parent is
opened without following links, and the named parent's identity is checked before
and after publication. `O_TMPFILE` and linking the owned descriptor through procfs
must be supported by the host and filesystem. No named-stage fallback is allowed.

On Windows, ordinary ancestor directories are opened root to leaf and held without
write/delete sharing. All child opens and creation use the held parent as their
`RootDirectory`, with reparse processing refused; sharing locks alone do not cover
attribute changes. The source handle also denies write/delete sharing. Publication
renames the exact source handle into the held parent with `ReplaceIfExists = FALSE`;
failure cleanup marks only that held source handle for deletion. The named parent's
identity is checked before and after publication. Reparse parents are refused.

If the platform, filesystem or sharing environment cannot support this contract,
publication reports `BLOCKED: safe publication ...` rather than performing a
path-based replacement. A blocked binary side uses the existing `missing` status
with that explicit reason; the CLI returns 2 if any side is blocked. A blocked
manifest publication also returns 2. The persisted `rq-pair-manifest/1` schema is
unchanged. Local Linux regressions do not certify the Windows API path; native
Windows tests remain a separate acceptance gate.

This helper proves acquired byte identity only. Its `found` status does not prove
the two sides have the same product scope, that their chronology is correct, or
that any changed function fixes a CVE. Those facts require the separately reviewed
case/pin provenance and qualification protocol. Exact-hash disambiguation does not
replace that review. No real binary or native engine acceptance follows from the
authored offline regression tests for this amendment.

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
