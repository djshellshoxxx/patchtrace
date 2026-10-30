# BUNDLE import path: offline ZIP inspector, private per-user install and the consent dialog

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Extends SPEC-06 (`docs/specs/offline-backend-installer.md`) sections 3, 5, 6, 7 with the behaviour that is actually implemented, the gaps found while reading it, and the hardening to close them. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` step G12. Code: `src/patchtrace/offline_bundle.py` (`inspect_offline_bundle`, `validate_manifest`, `_safe_relative`, `_zip_entries`, `_verify_stream`, `install_offline_bundle`, `build_offline_bundle`), `src/patchtrace/ui.py` (`import_offline_bundle`, `_finish_offline_inspection`, `_offline_installed`), tests `tests/test_offline_bundle.py`, `tests/test_offline_bundle_linux.py`, `tests/stress/test_fuzz_archives.py`, `tests/test_ui_bundle_setup.py`.

## 1. Purpose and non-goals

Purpose: a user can import a prepared offline backend ZIP (the "importer ZIP", `PatchTrace-<ver>-backend-windows-amd64.zip`, or its re-joined split parts) into a private per-user directory, and nothing hostile in the archive can write outside that directory, execute, or replace an existing runtime. Also: the user sees what they are installing and must explicitly consent.
Non-goals: publisher authentication (a self-hashed manifest proves integrity only; signing is the WIN track), Linux import through the GUI (Linux uses the tar.gz full download; the default importer platform is Windows only), automatic updates, running anything from the archive.

## 2. Definitions

- **Importer ZIP**: top-level `manifest.json` plus `payload/<path>` for every path in `manifest.files[]`; nothing else.
- **Plan** (`OfflineBundlePlan`): the verified result of inspection: archive path, archive SHA-256, runtime id, file list, manifest bytes, platform.
- **Trusted expected SHA-256**: the optional 64-hex string typed into Setup "Trusted offline ZIP checksum" (`bundle_sha`); when present the archive digest must equal it.
- **Runtimes root**: `%LOCALAPPDATA%\PatchTrace\runtimes` (Windows; the UI refuses to install when `LOCALAPPDATA` is unset: `PT-OFFLINE: LOCALAPPDATA is unavailable; Windows per-user install required`).

## 3. Contract: manifest (schema 1, unchanged and additive-only)

Exact key set `format` (`patchtrace-offline-runtime`), `schema_version` (int 1), `runtime_id` (`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$`, not ending in `.`, first dotted segment not a reserved device name), `platform` (`windows|linux`), `architecture` (`amd64`), `python` (`python/python.exe` or `python/bin/python3`), `ghidra` (`ghidra`), `java` (`jdk`), `versions` (exactly `python`, `ghidra`, `jdk`, `ghidriff_revision`, each `^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,95}$`), `files[]` (4 to 60,000 objects with exactly `path`, `size` (0 to 2 GiB), `sha256` (64 lowercase hex)). Required files per platform include `LICENSES/NOTICE.txt`, the interpreter, `ghidra/Ghidra/application.properties`, the JDK `java` binary; Windows markers match case-insensitively, Linux exactly. Total declared size <= 8 GiB. Duplicate JSON keys, NaN/Infinity and non-UTF-8 are rejected. Manifest size <= `MAX_MANIFEST` = 16 MiB (a comment in `backend_bundle.py` still says 4 MiB: stale, to be corrected).

## 4. Algorithm and refusals

### 4.1 Inspect (`inspect_offline_bundle`, no extraction, no execution)

```
1. cancel check; expected sha format check
2. archive must be a file; hash the whole file in 1 MiB chunks (cancellable); if expected given, must equal
3. open as ZIP; exactly one entry named manifest.json, size <= MAX_MANIFEST; read at most MAX_MANIFEST+1 bytes
4. strict JSON (no duplicate keys, finite numbers, UTF-8); validate_manifest(platforms=(default windows))
5. _zip_entries: for every entry
     _safe_relative(name)                                       # portable name rules below
     NFC+casefold key must be unique                            # duplicate or collision
     not a directory, not encrypted (flag bit 0), method in {STORED, DEFLATED}
     external_attr file type must be 0 or regular               # no symlink/special
     file_size <= 2 GiB and not (file_size > 1024 and compress_size*200 < file_size)    # bomb ratio > 200:1
   entry count must equal len(files)+1; manifest.json present;
   every payload/<path> present with the exact name (case-exact) and exact size; no other entry
6. for every file: stream-decompress and verify length <= declared and sha256 == declared (cancellable)
7. return plan (archive hash, runtime id, files, manifest bytes)
```
Name rules (`_safe_relative`): non-empty string, length <= 512, not starting with `/`, no `\`, no `//`, no control characters (<32, 127), no component equal to `''`, `.`, `..`, no component ending in space or dot, no `:` (blocks alternate data streams and drive letters), none of `<>"|?*`, first dotted segment (spaces stripped) not in `WINDOWS_RESERVED` (`CON PRN AUX NUL COM1-9 LPT1-9` including the superscript digits `¹ ² ³`, `CONIN$`, `CONOUT$`).

### 4.2 Refusal table (message prefix `PT-OFFLINE: `; all raise `OfflineBundleError`)

| Hostile input | Refusal text | Covered by |
|---|---|---|
| `../x`, `/abs`, `a//b`, `x/./y`, `bell\x07`, `a:stream`, `COM¹/x`, trailing dot/space | `unsafe archive path` | fuzz `test_known_hostile_names_are_refused`, property test against an oracle |
| backslash member | `unsafe archive path` | fuzz `backslash-name` (**skipped on Windows hosts**, gap) |
| symlink or special file | `symlink or special file in ZIP is forbidden` | fuzz `symlink-payload`, `test_rejects_symlink_member` |
| directory entry | `unsupported directory, encryption or compression in ZIP` | fuzz `directory-entry` |
| encrypted or bzip2/other method | same text | fuzz `test_bzip2_member_is_refused_as_unsupported_compression` |
| exact duplicate name | `duplicate or Windows-colliding ZIP paths` | fuzz `exact-duplicate`, `test_rejects_duplicate_zip_entries` |
| case collision (`MANIFEST.JSON`, `payload/licenses/notice.txt`), NFD vs NFC (`café`) | same | fuzz `case-collision-*`, `nfd-collision`, `test_rejects_case_insensitive_member_collision` |
| reserved device (`payload/CON`, `COM¹.txt`) | `unsafe archive path` | fuzz `reserved-member`, `reserved-com1-superscript` |
| extra unlisted file | `ZIP entries do not match the exact manifest inventory` / `ZIP has unexpected files` | fuzz `extra-unlisted-file` |
| notice dropped | `portable runtime or license notice component is missing` / count mismatch | fuzz `notice-dropped` |
| member whose compressed size makes a >200:1 ratio | `ZIP member exceeds safe size or compression limits` | fuzz `test_compression_bomb_member_is_refused` |
| declared size exceeded while decompressing | `decompressed payload exceeded declared size` | `_verify_stream` |
| wrong hash/size | `payload SHA-256 hash or size mismatch` | `test_rejects_hash_mismatch_and_missing_components` |
| archive digest differs from the typed one | `archive SHA-256 differs from the trusted expected SHA-256` | `test_external_sha_is_checked` |
| manifest > 16 MiB or duplicated/missing | `exactly one bounded manifest.json is required` / `manifest exceeds size limit` | builder test `test_manifest_larger_than_the_importer_cap_fails_loudly` |
| invalid UTF-8 member name | typed `OfflineBundleError` | fuzz `test_invalid_utf8_member_name_is_a_typed_offline_error` |
| corrupt/truncated bytes | `cannot read or verify offline ZIP (<ExceptionName>)` | fuzz `test_corrupted_bundle_bytes_only_raise_offline_error`, `test_truncated_bundles_only_raise_o...` |
| non-Windows manifest through the default importer | `this bundle is not a Windows x64 backend` | `test_linux_manifest_refused_by_default` |
| more than 60,001 entries / 60,000 files | `ZIP contains too many entries` / `invalid manifest file count` | `_zip_entries` |

### 4.3 Gap to close (G12)

On a Windows host `zipfile` replaces `os.sep` by `/` while reading a name, so a member stored as `payload\jdk\x` reaches `_safe_relative` as `payload/jdk/x` and is accepted if it matches the manifest. The builder already handles this (`_reject_raw_backslash_names`), the user-facing inspector does not (VERIFIED by reading both files). Specification of the fix:

```
_reject_raw_central_directory_names(zf):                       # run before iterating infolist
  size = file length; require zf.start_dir <= size and size-zf.start_dir <= 64 MiB
  read bytes [start_dir, end of central directory) ; pos = 0
  for _ in range(min(len(zf.infolist()), MAX_MEMBERS+1)):
      require buf[pos:pos+4] == b'PK\x01\x02' else stop
      n, m, k = unpack('<HHH', buf[pos+28:pos+34])             # name, extra, comment lengths
      require pos+46+n+m+k <= len(buf)
      raw = buf[pos+46:pos+46+n]
      refuse if b'\\' in raw or b'\x00' in raw or raw.startswith(b'/')
      pos += 46+n+m+k
```
Then the fuzz case uses a raw-bytes writer (patching the name bytes after writing) so it also runs on Windows; the skip marker is removed. No attacker-controlled length may exceed the buffer.

### 4.4 Install (`install_offline_bundle`)

```
cancel check; destination_root = _validated_root(runtimes_root)         # absolute, no '.'/'..', not fs root, not OS dir
no symlink/junction/reparse point in the destination or any ancestor
re-inspect the archive with expected_sha256 = plan.sha256; runtime id, files and manifest bytes must equal the plan
destination = root/<runtime id>; must not exist ("runtime already installed; existing files were not overwritten")
free space >= total bytes + min(512 MiB, total//10)
lock = root/.runtime-<id>.lock created O_CREAT|O_EXCL (stale lock -> error, never stolen)
stage = mkdtemp('.install-', dir=root)
for each file: Windows path length of the final target must be < 248; open target 'xb'; stream, verify size+sha256 while writing
write manifest.json; re-hash the archive once more; destination must still be absent
_publish_no_replace(stage, destination)     # Windows: os.replace to an absent dir; POSIX: mkdir reservation then rename
finally: remove only our stage; on cleanup failure report the exact stage path; remove our lock
```
The result `InstalledRuntime` exposes paths for Setup: python, ghidra, java home. Nothing is run. Cancellation raises `PT-CANCEL: installation cancelled; existing runtimes were preserved`.

## 5. Consent dialog (implemented, VERIFIED)

`QMessageBox` Question, title `Install verified offline backend?`, plain text only (`setTextFormat(PlainText)`; archive name and runtime id come from an untrusted file), default button **No**:
```
Bundle: <archive name>
Runtime: <runtime id>
Files: <n>; uncompressed: <bytes> bytes
Archive SHA-256: <hex>

The file hashes match its own manifest. This does NOT prove publisher authenticity. Verify the archive checksum against a trusted
source and review the included LICENSES/NOTICE.txt before relying on this software.

Continue with private per-user installation?
```
Decline: diagnostics text `Offline bundle checked; installation not authorized.` After success: `Offline backend installed at <root>.` + instruction to Diagnose then Save; no system-wide setting changed.

**Additions required (G12)**: (1) component list with SPDX read from `LICENSES/THIRD-PARTY.json` inside the verified archive (read via the already-open ZipFile, bounded 1 MiB, parsed with the strict loader; absence is shown as "no component list"); (2) target directory `%LOCALAPPDATA%\PatchTrace\runtimes\<id>`; (3) free-space line `Needs <bytes> plus reserve; <free> available`; (4) a sentence that the hash typed into Setup was or was not supplied ("No trusted checksum was supplied" in bold-free plain text); (5) the Yes button must stay non-default.

## 6. Private per-user install and settings

Destination is private to the user profile; the installed `backend` is never made world-readable by the installer (inherits profile ACLs). Setup stores only non-secret paths. A failed or cancelled install leaves configured paths unchanged (`test_verify_progress_and_cancel_leave_settings_unchanged` covers the verify path). Discovery precedence: explicit setting > bundle next to the executable > per-user runtime > others (`runtime_discovery.py`).

## 7. Error codes

`PT-OFFLINE: ...` (importer; message list above), `PT-CANCEL` (cooperative cancel), runtime-side `PT-BUNDLE-*` for the bundle next to the executable (see the code table in `BUNDLE-payload-strip-jlink-size-spec.md`). The two namespaces are intentionally distinct: `PT-OFFLINE` is import time, `PT-BUNDLE` is build and run time.

## 8. Determinism and limits

Producer (`build_offline_bundle`): records sorted by path, compact sorted JSON manifest, ZIP date 1980-01-01, `external_attr` 0o100644 for every member (so the importer ZIP loses Unix execute bits; it is Windows-only by design), deflate level 6, atomic `os.link` publication, re-inspection of its own output. Deflate bytes depend on zlib (see the canonical-form and reproducibility specs). Limits: 60,000 members, 2 GiB/file, 8 GiB total, 16 MiB manifest, bomb ratio 200:1, path <= 512 (and <= 150 under `backend/` by the builder gate), install path < 248.

## 9. Security invariants

1. No archive byte is interpreted as a path, command or link: names validated before any write, links and special files refused.
2. Everything written is hashed against the manifest *during* the write (not only before).
3. The archive digest is re-checked after extraction (swap detection).
4. Existing runtimes are never overwritten, modified or deleted; locks are never stolen; unknown stage directories are never deleted.
5. The installer starts no process, opens no socket, writes no registry and requires no elevation.
6. Authenticity is explicitly disclaimed in the UI.
7. Untrusted strings are shown as plain text.

## 10. Test plan

Existing suites listed in the header cover sections 4.1 to 4.4 (VERIFIED names above). To add: `test_raw_backslash_member_is_refused_on_every_host`, `test_raw_nul_in_member_name_is_refused`, `test_central_directory_length_beyond_the_file_is_not_followed`, `test_consent_text_lists_target_directory_and_free_space`, `test_consent_default_button_is_no` (offscreen), `test_consent_lists_components_from_third_party_json`, `test_stale_manifest_cap_comment` (grep `MAX_MANIFEST_BYTES` comment), `test_install_refuses_a_path_of_248_characters_on_windows` (exists in spirit; keep).

## 11. Open questions

1. Should the GUI also import the Linux tar.gz/zip? Default: no (Linux users extract the full tarball).
2. Should a split archive be joined by the app? Default: no; document the manual join and the `.sha256` check.
3. Should the importer require the typed trusted checksum? Default: optional with a prominent warning; owner may harden before 1.0.

## 12. Acceptance

All refusal rows have a passing test on both Linux and Windows hosts (no Windows-only skip for security cases); the consent dialog test shows the added fields; an import of the real importer ZIP from a green run succeeds on Windows with the typed checksum and leaves `%LOCALAPPDATA%\PatchTrace\runtimes\<id>\payload\...` identical to the manifest (`backend verify --full` ok).
