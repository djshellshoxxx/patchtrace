# BUNDLE pin file, digest sources and the pin upgrade procedure

Status: approved for build (documents only; no code is changed by this file). Date: 2026-10-15. Base commit: `54fd085` (branch `claude/instance-d-gui`). Extends: `docs/specs/program-e/BUNDLE-integration-plan.md` section 7.1, `docs/specs/offline-backend-installer.md` (SPEC-06) section 2. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` (steps G2, G10, G14). Owner of code: `tools/backend_pin.json`, `tools/check_backend_pin.py`, `tools/verify_backend_pins.py`, `tools/build_backend_bundle.py` (`gate_pin`, `fetch_verified`).

## 1. Purpose and non-goals

Purpose: one file, `tools/backend_pin.json` (schema `patchtrace-backend-pin/1`), names every byte that enters the offline backend bundle and the evidence that justifies each digest, so a build is a pure function of the pin plus the source repository. This spec fixes the field contract, the allowed digest sources per component class, the verification algorithms, the error codes and the procedure to change a pin safely.

Non-goals: licence policy content (see `BUNDLE-licence-notices-and-source-offer-spec.md`), strip lists and jlink (see `BUNDLE-payload-strip-jlink-size-spec.md`), signing of PatchTrace binaries (SPEC-52), BinDiff pins (`tools/bindiff_pin.json`, `docs/runbooks/bindiff-pin.md`).

## 2. Definitions

- **Pin entry**: an object with `url` (https only), `sha256` (64 lowercase hex), `size` (positive integer bytes), `digest_source`, `status` (`pinned` or `placeholder`), plus `spdx` and `version` for components.
- **Digest source** (field `digest_source`), exhaustive list in `tools/check_backend_pin.py` `DIGEST_SOURCES`:
  - `vendor-file`: the vendor publishes a digest file next to the asset (`*.sha256.txt`, `SHA256SUMS`); the pin records `digest_file`. Used by `python-linux`, `jdk-windows`, `jdk-linux`, `jdk_source_offer`, the python-build-standalone fallback.
  - `vendor-listing`: digest read from the vendor's release page and re-hashed from a full download by the resolver. Used by `ghidra` (`c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120`, 509,952,513 bytes, VERIFIED equal in the research doc by a full download).
  - `pypi-json`: PyPI JSON API `urls[].digests.sha256` over TLS, cross-checked against Ghidra's own `pypkg/dist` where present. Used by every wheel/sdist.
  - `sigstore-verified`: the digest was recorded only after `sigstore verify identity` succeeded for the asset with a named identity and issuer. Allowed only for `python-windows`.
  - `gpg-verified`: same with a detached `.asc` and a fingerprint cross-checked on the vendor page. Allowed only for `python-windows`.
  - `git-rebuilt`: the digest of an archive that this repository rebuilds deterministically from a pinned git commit (never downloaded). Allowed only for `ghidriff.source_tarball`.
  - `none`: only for `status: placeholder` (carries the literal `PLACEHOLDER-UNRESOLVED`, size `null`). A release build refuses any placeholder (`release_problems`, exit 3).
- **No trust on first use**: a digest that no vendor, signature or reproducible rebuild vouches for is refused. `tofu` is not an accepted digest source anywhere (VERIFIED: absent from `DIGEST_SOURCES`; `_restrict_source` rejects `VERIFIED_ONLY` sources on other components).
- **Whole-file digest** vs **content digest** vs **tar digest** (Ghidriff tarball only): see the canonical-form spec.
- **Lane**: `windows`, `linux`, `any` wheel sections; the build for a platform uses its lane plus `any`.

## 3. Contract (fields, additive-only)

Top level (all VERIFIED present in the committed file): `schema`, `resolved_on`, `runtime_id_format` (`ghidra-{ghidra}-ghidriff-{sha7}-{os}-amd64`, validated literally), `trust` (prose), `components` (exactly `python-windows`, `python-linux`, `ghidra`, `jdk-windows`, `jdk-linux`), `jdk_source_offer`, `wheels` (exactly `windows`, `linux`, `any`), `ghidriff`, `ghidra_pypkg_crosscheck`, `ci_lane_freeze`, `jdk_decision`, `license_policy`, `strip`, `jlink`.

Component fields: `status`, `digest_source`, `url`, `sha256`, `size`, `spdx`, `version`, optional `digest_file`, `note`, `fallback` (python-windows only; must be fully pinned, placeholders not allowed there).

Wheel entry fields: `name`, `kind` (`wheel` or `sdist-built-to-wheel`), `distribution`, `version`, `url` (must end with `name`), `sha256`, `size`, `spdx`, `digest_source`, optional `note`. Wheel tags: `any` lane `-py3-none-any.whl`; `windows` lane `-cp312-cp312-win_amd64.whl`; `linux` lane `-cp312-cp312-manylinux*x86_64*.whl` (`_wheel_tag_ok`). Required distributions in every lane: `jpype1`, `pyghidra`, `packaging`, `mdutils`; `jpype1` must be `1.5.2`, `mdutils` `1.6.0`, `pyghidra` major 3.

`ghidriff`: `repo`, `sha` (40 hex), `spdx`, `spdx_note`, `requires`, `source_tarball` {`name`, `status`, `digest_source` (`git-rebuilt`), `url` (must contain the commit), `sha256`, `size`, `content_sha256`, `note`}.

**Additive changes defined by this plan** (old readers ignore unknown keys; `validate_pin` must learn them): `ghidriff.source_tarball.tar_sha256` (64 hex); `strip.protected` (list of globs); `components.<name>.verified_on` (ISO date of the last re-verification); optional top-level `candidate` (never in the main pin).
Validation gap (VERIFIED): `check_backend_pin.validate_pin` does not currently validate `content_sha256`; the fix is a shared `_hex_field(where, value)` rule.

Rules enforced today (VERIFIED by reading `tools/check_backend_pin.py`): https URLs; version consistency (`python-windows`/`python-linux` same version; Ghidra URL contains `ghidra_<version>_PUBLIC`; JDK versions start `21.` and URLs contain exactly one `%2B`); every copyleft SPDX must be listed in `license_policy.allowed` with identical SPDX and a matching `match` id; `ghidra-GPL-dir` consistent with `strip.ghidra`/`strip.keep`.

## 4. Algorithms

### 4.1 Download verification (`fetch_verified`)

```
fetch_verified(entry, cache_dir, fetcher, label):
  require sha256 matches ^[0-9a-f]{64}$ and size is int > 0          else PT-BUNDLE-PIN
  dest = cache_dir/<sha256[:16]>-<safe file name>                      # name matches ^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}$
  if dest exists and size==pin.size and sha256_file(dest)==pin.sha256: return dest   # cached copy is re-hashed every time
  part = dest + ".part"; fetcher(url, part, max_bytes=pin.size)       # https only, redirect must stay https,
                                                                      # aborts when more than pin.size bytes arrive
  (size, digest) = stat/hash(part)
  if size != pin.size or digest != pin.sha256: delete part; PT-BUNDLE-PIN-MISMATCH
  os.replace(part, dest)
```
Cache keys never trust a file name; the hash is recomputed on every use.

### 4.2 Pin gate (`gate_pin` / `check_backend_pin.py --release`)

`validate_pin(data)` -> problems; `release_problems(data)` -> placeholders; `unapproved_licenses(data)` -> shipped copyleft entries with `owner_approved != true`. Exit codes: 0 ok; 1 malformed; 3 `--release` and a placeholder; 4 `--release` and unapproved licences (downgraded to a warning by `--allow-unapproved-licenses`, which only non-publishing runs may use: the workflow passes it unless `publish` is true). The builder refuses a pin that fails either check (`PT-BUNDLE-PIN`).

### 4.3 Verification-only pins (`tools/verify_backend_pins.py verify`)

```
python-windows:
  fetch zip, .sigstore, .asc (https, bounded, identity encoding)
  run: python -m sigstore verify identity --bundle B --cert-identity ID --cert-oidc-issuer ISS file
  require ID text appears on the fetched python.org pages (identity_named_on_python_org_pages)   # integrator-supplied identity is not self-authenticating
  proposed_digest_source = sigstore-verified | gpg-verified; any failed check -> problem, exit 1
ghidriff:
  fetch commit (git init; git fetch --depth 1 repo commit; FETCH_HEAD^{commit} == commit)
  build tarball twice; require identical; fetch GitHub archive; compare member by member (names, sha256, exec bit, link targets) -> identical required
  proposed record: sha256, size, git-rebuilt
```
The tool writes evidence JSON (`patchtrace-pin-verify/1`) and never edits the pin. A person records the values (owner approval for supply-chain changes).

## 5. Error codes (builder, pin and tarball related)

| Code | Raised by | Meaning |
|---|---|---|
| `PT-BUNDLE-PIN` | `gate_pin`, `fetch_verified`, `rebuild_ghidriff_tarball` | pin malformed, placeholder, unresolved entry, unsafe file name |
| `PT-BUNDLE-PIN-MISMATCH` | `fetch_verified`, `rebuild_ghidriff_tarball`, `install_wheels`, Ghidra version check, `join_parts` | digest/size/version differs from the pin |
| `PT-BUNDLE-FETCH` | `download`, `_default_source_builder` | non-HTTPS URL, redirect left HTTPS, network error, nothing downloaded |
| `PT-BUNDLE-SOURCE-DIGEST` (new) | build | a quoted digest (sidecar, offer, THIRD-PARTY) differs from the shipped source tarball bytes |
| `PT-BUNDLE-LICENSE` | `check_backend_pin`, builder | licence policy or file missing |

The full table of all `PT-BUNDLE-*` codes (runtime and build) is in the game plan section 4 and in `BUNDLE-payload-strip-jlink-size-spec.md` section 5.

## 6. Determinism

Pin file: UTF-8, LF, trailing newline (tests `test_committed_pin_is_lf_json_with_trailing_newline`, `.gitattributes` rule). The pin's SHA-256 is recorded in `THIRD-PARTY.json` as `pin_sha256`, binding every artifact to the exact pin text.

## 7. Pin upgrade procedure (how to bump a pin safely)

Rule 0: one component per change; never combine a pin bump with a code change; never copy a digest from a document, a chat or an LLM (digests come from the declared source in step 2).

1. Open an issue/PR titled `pin: <component> <old> -> <new>`; run G0 preflight.
2. Obtain the digest from the declared source:
   - Temurin JDK: `curl -fsSL <asset>.sha256.txt` (same release directory), download the asset, `sha256sum`, require equality; also bump `jdk_source_offer` (the matching `OpenJDK21U-jdk-sources_<ver>.tar.gz` and its `.sha256.txt`) and `jdk_decision` text; JDK must stay 21.x (checked).
   - python-build-standalone: `SHA256SUMS` of the release tag; asset name contains the CPython version and the build date tag.
   - Python embeddable: run `pin_verify` (sigstore) for the new version; the identity must be the 3.12 release manager listed on python.org; update `PAGES` in `verify_backend_pins.py` for a new release-page URL (it names `python-31210`).
   - Ghidra: release page digest + full re-hash; also re-read `application.properties` version (the builder checks it: `PT-BUNDLE-PIN-MISMATCH: Ghidra application.properties says X, pinned Y`), re-check `pypkg/dist` against the pinned PyGhidra/JPype/packaging wheels (`ghidra_pypkg_crosscheck`), update `strip` if layout changed (G7).
   - Wheels: PyPI JSON for the exact file; record `url`, `sha256`, `size`; read `Requires-Dist` from the wheel `METADATA` and make every unconditional requirement a pinned entry (no unpinned dependency may remain: `test_every_dependency_closure_member_pinned_per_lane`).
   - Ghidriff commit: update `sha`, run `pin_verify` (tarball rebuild + GitHub comparison), update `requires` from the commit's `setup.cfg`, the runtime id suffix (`sha7`) and the release asset names (`ghidriff-<sha7>-source.tar.gz`).
3. Run `python tools/check_backend_pin.py` and `python tools/check_backend_pin.py --release`; run `python -m pytest -q tests/test_backend_pin.py tests/test_verify_backend_pins.py tests/test_build_backend_bundle.py`.
4. Dispatch `backend-bundle.yml` with `platforms=both`; both acceptance jobs must pass; compare sizes with the previous run (budget gate).
5. Owner approval for any supply-chain change (new vendor, new digest source, new GPL-family component) and for any change to `license_policy`.
6. Merge. Record the run URL and the verification date in `docs/qa.md` and in the pin `note`.

`tools/backend_pin_bump.py` (planned, G14) automates steps 2 and 3 as a print-only proposer.

Drift detection: the optional weekly `schedule` job builds and accepts but never publishes; a failure means an upstream asset vanished or changed.

## 8. Security invariants

1. Every byte entering the payload is hash-checked against the pin before use; a mismatch is fatal, never a warning.
2. Downloads happen only in the builder and `verify_backend_pins.py`, only over HTTPS, bounded by the pinned size, never in the app.
3. The pin is the single source of versions; no workflow or script hard-codes a digest (VERIFIED for the bundle workflow; `live-backend.yml` pins Ghidra's digest separately: a consistency test is planned).
4. Evidence tools never write the pin.
5. No component with `status: placeholder` can reach a release build.
6. A verification-only digest source cannot be used for a different component (checked by `_restrict_source`).

## 9. Budgets

Pin file under 64 KiB; `check_backend_pin.py` under 1 s; `pin_verify` job under 20 minutes (workflow `timeout-minutes: 20`); digest recomputation of cached downloads (about 0.9 GB) under 60 s.

## 10. Test plan

Existing (VERIFIED names): `tests/test_backend_pin.py` (valid pin, LF, known values, digest sources traceable, no http, closure pinned, policy structure, release gate), `tests/test_verify_backend_pins.py`, `tests/test_build_backend_bundle.py::test_digest_mismatch_is_a_hard_failure`, `::test_cached_download_is_reverified`, `::test_unresolved_pin_placeholders_are_refused_before_any_download`.
To add: `test_content_and_tar_digest_fields_are_hex`, `test_strip_protected_is_a_list_of_safe_globs`, `test_bump_tool_prints_patch_without_writing`, `test_bump_tool_refuses_unsourced_digest`, `test_live_backend_ghidra_digest_equals_the_pin` (workflow text vs pin).

## 11. Open questions

1. Should `verified_on` be mandatory and expire after N days (a stale-verification warning in `--release`)? Default: warning at 90 days.
2. Should the python-build-standalone fallback be wired for Windows? Default: no (changes layout), keep documented.
3. Should the pin carry the sigstore client version used for verification? Default: yes, in `components.python-windows.note`.

## 12. Acceptance

A reviewer can rebuild every digest in the pin from its declared source, `check_backend_pin.py --release` exits 0, the bump procedure was rehearsed once on a JDK patch version, and no digest source outside section 2 appears.
