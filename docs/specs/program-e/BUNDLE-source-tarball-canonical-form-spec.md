# BUNDLE Ghidriff source tarball: canonical form, digests and the content fallback

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Supersedes the fallback description in `docs/handoff/beta/07-ci-reading-and-known-failures.md` section 3.8 and the commit message of `7c1f5a2`. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` steps G1, G2. Code: `tools/verify_backend_pins.py` (`fetch_commit`, `_normalised_tar`, `build_tarball`, `content_digest`, `describe_tarball`, `rebuild_tarball`), `tools/build_backend_bundle.py` (`rebuild_ghidriff_tarball`, sidecar/offer/THIRD-PARTY writers).

## 1. Purpose and non-goals

Purpose: the GPL-3.0 corresponding source of the shipped Ghidriff must be one exact file whose digest is the same on every runner, appears in the pin, in `SOURCES/`, in the release asset, in its `.sha256` sidecar, in `SOURCE-OFFER.txt` and in `THIRD-PARTY.json`, and equals the bytes that were actually verified. The tarball is never downloaded (GitHub's archive tarball is not byte-stable); it is rebuilt from the pinned commit.

Non-goals: building the Ghidriff wheel (see `BUNDLE-wheelhouse-and-pyghidra-spec.md`), licence wording (`BUNDLE-licence-notices-and-source-offer-spec.md`).

## 2. Evidence this spec is built on

1. VERIFIED (log of job 116386600394, run 38686279359): on `ubuntu-22.04` with `git version 2.55.0; python 3.12.15` the rebuild had the same size (7,086,648) but sha256 `8f96e687c72ae191def725e1753e3701be74bb80d30f5a29f7294717322802bc`; pin `613449a2743e50a11c96b8a6cf6856095816cfece77a021c49cac6e4fe4fe87f`.
2. VERIFIED (local rebuild, git 2.43.0, Python 3.13.16, zlib 1.3): sha256 equals the pin; all 16 `describe_tarball` lines equal the runner's (`ghidriff-4f5d895 n=1 951b5414c31904b9`, ..., `www n=86 684b1390386f979e`). `content_digest` = pinned `content_sha256` `b7c9aec8ee249be052256c5db06cdaf876dba5cefc955e249c26d6ff3b75d9fc`.
3. VERIFIED: Python 3.11.17, 3.12.3, 3.13.16 (all zlib 1.3) reproduce the pinned gzip bytes. The pinned stream has 110 stored blocks of irregular size (first three 65531, 32773, 65535; last data block 41416; then an empty final block). Decompressed tar = 7,086,080 bytes, sha256 `b3bc93fa3e315d25338210d8038f250cfdd9e8b887ecb06588145974469cc5c6`. Header bytes: `1f8b08000000000000ff`.
4. HYPOTHESIS (settled by the first run of the plan's G1): the runner's Python links a different zlib or buffering strategy so stored-block boundaries differ; the decompressed tar is identical.

Consequence: "gzip at level 0" is not a byte-stable recipe across zlib builds, although it looks like one. The recipe must not depend on zlib at all.

## 3. Definitions

- **Normalised tar**: the output of `git archive --format=tar --prefix=ghidriff-<sha7>/ <commit>` (with `core.autocrlf=false`, `core.eol=lf`), rewritten member by member by `_normalised_tar`: name unchanged, `mtime=315532800`, `uid=gid=0`, `uname=gname=''`, directories `0755`, regular files `0755` if any execute bit else `0644`, symlinks `0777` with `linkname`, GNU tar format, member order as `git archive` emits (tree order). Any other member type fails (`unsupported member type in git archive`).
- **tar digest** (`tar_sha256`): SHA-256 of the normalised tar bytes (uncompressed).
- **Canonical gzip**: 10-byte header `1f 8b 08 00 00 00 00 00 00 ff` (no name, mtime 0, XFL 0, OS 255), then the normalised tar split into stored deflate blocks of exactly 65,535 bytes except the last (which is shorter and has BFINAL=1; there is no trailing empty block), each block `<BFINAL:1 byte 0x00|0x01> <LEN:uint16 LE> <NLEN:uint16 LE> <data>`, then trailer `<CRC32 of tar:uint32 LE> <len(tar) mod 2^32:uint32 LE>`. Size = `len(tar) + 10 + 8 + 5*ceil(len(tar)/65535)`.
- **content digest** (`content_sha256`): `sha256` of the `\n`-joined sorted rows `name\0kind\0execbit\0` + (body sha256 digest for files, link target for symlinks, empty for directories); ignores tar and gzip bytes (VERIFIED in `content_digest`).
- **whole-file digest** (`sha256`, `size`): of the canonical gzip bytes.

For the pinned commit the canonical gzip is 7,086,643 bytes with sha256 `c93b5d07fea5aaa03ac82b59ee649ebbf0aa5a576ca301a28ea48060bead0cbc` (VERIFIED by an experiment on a local rebuild with this writer; it must be re-derived through `pin_verify` and approved by the owner before the pin changes).

## 4. Contract (pin fields, additive)

`ghidriff.source_tarball.{sha256,size}` = canonical gzip digest and size. `content_sha256` stays. New optional `tar_sha256`. `digest_source` stays `git-rebuilt`. Evidence file `pin-verify.json` gains `ghidriff.tar_sha256`, `ghidriff.canonical_sha256`, `ghidriff.canonical_size`. `build-report.json` gains `ghidriff_source` = `{"path": "exact" | "tar" | "content-refused", "sha256": "<shipped digest>", "size": N}`.

## 5. Algorithm

```
rebuild_ghidriff_tarball(ghidriff_pin, work):
  assert digest_source == git-rebuilt and sha256/size resolved                         # PT-BUNDLE-PIN
  raw_tar = git_archive(fetch_commit(repo, sha))                                       # PT-BUNDLE-FETCH on failure
  tar     = normalise(raw_tar)                      # members rewritten as in section 3
  gz      = canonical_gzip(tar)                     # no zlib; section 3
  if (len(gz), sha256(gz)) == pinned (size, sha256):  path = "exact"; return gz
  if tar_sha256 pinned and sha256(tar) == tar_sha256:
        # cannot happen when gz is canonical and tar identical: raise as an internal error with both digests
        PT-BUNDLE-PIN-MISMATCH: canonical gzip differs although the tar digest matches (writer bug)
  details = describe_tarball(gz): git version, python, zlib, tar digest, per-directory digests, block count
  if content_digest(gz) == pinned content_sha256:
        PT-BUNDLE-PIN-MISMATCH (message says: contents equal, tar layout differs: git archive framing changed;
        re-run pin_verify and have the owner re-pin tar_sha256 and sha256)           # never ship a different layout
  else: PT-BUNDLE-PIN-MISMATCH with details
after success: shipped_path = gz; every derived digest comes from sha256_file(shipped_path)
assert pin.sha256 == sha256_file(shipped_path) else PT-BUNDLE-SOURCE-DIGEST
```
Why `content_sha256` no longer accepts bytes: it vouches for *what* is in the archive but not for the exact file named in the offer. The previous fallback (commit `7c1f5a2`) accepted whatever the runner produced and then wrote the pinned digest into the sidecar and the offer (VERIFIED defect). The content digest remains as a diagnostic and as the human-readable proof that two layouts carry the same files.

Transition rule until the owner re-pins: the old fallback may remain enabled only if the code also writes the sidecar, offer and `THIRD-PARTY.json` from `sha256_file(shipped)` and adds `warnings: ["ghidriff source tarball accepted by content digest; whole-file digest differs from the pin"]` to `build-report.json`. The release gate (`--release`) must refuse a build with that warning.

## 6. Error codes

`PT-BUNDLE-PIN-MISMATCH` (digest/size), `PT-BUNDLE-FETCH` (git fetch or archive failure, commit differs from the pin), `PT-BUNDLE-SOURCE-DIGEST` (shipped bytes differ from a quoted digest), `PT-BUNDLE-PIN` (pin unresolved). Sample real line to reproduce in tests: `PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: rebuilt 7086648 bytes sha256 8f96e687..., pinned 7086648 bytes sha256 613449a2...`.

## 7. Determinism

Inputs: commit SHA (full 40 hex; the fetch checks `FETCH_HEAD^{commit} == commit` and records the tree hash `adcb9bb4faf3d429aa29b2f415763400b92426b1`, VERIFIED locally), `git archive` content (independent of commit date; test `test_rebuild_is_deterministic_across_commit_dates`), fixed mtime, fixed owners, fixed modes, fixed member order from git, zlib-independent gzip. Environment variables must not matter: run with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=` (unset), `core.autocrlf=false`, `core.eol=lf`; export-subst and export-ignore attributes in the repository are part of the content (the GitHub comparison catches a difference). The git version is recorded in diagnostics, not trusted for equality.

## 8. Security invariants

1. The tarball bytes that are scanned, hashed, copied to `SOURCES/`, attached to the release and described by the offer are the same file object.
2. The commit is fetched by full SHA with `--depth 1` and rejected if the fetched commit differs.
3. The wheel built from this tarball is byte-compared with it (`compare_wheel_to_source`), so source and binary agree.
4. A content-only match never changes what is shipped.
5. The re-pin of `sha256`, `size`, `tar_sha256` requires an owner-approved `pin_verify` run (rebuilt twice identical and identical to the GitHub archive member by member).

## 9. Budgets

Rebuild < 10 s; tar 7.1 MB; gzip 7.09 MB (about equal; stored blocks do not compress, hence the release asset is 7.1 MB). Memory: the whole tar in memory is acceptable (7 MB); bound by `limit = 64 MiB` and refuse a larger `git archive` output.

## 10. Test plan

- `test_canonical_gzip_round_trips_with_gzip_and_tar_modules`.
- `test_canonical_gzip_is_independent_of_zlib` (monkeypatch `zlib.compressobj` to raise).
- `test_canonical_gzip_block_layout` (all blocks 65535 except the last; only the last has BFINAL; size formula).
- `test_rebuild_identical_across_python_minor_versions` (run under 3.11/3.12/3.13 when present; skip otherwise, never pass vacuously).
- `test_pin_digest_equals_canonical_rebuild_of_a_synthetic_repo` (build a tiny git repo in a temp dir).
- `test_fallback_path_never_ships_a_different_layout`.
- `test_sidecar_offer_and_third_party_use_the_shipped_digest` (red today).
- `test_describe_tarball_prints_tar_digest_and_block_count`.
- Existing to keep green: `test_builder_rebuilds_from_the_commit_and_checks_the_pin`, `test_builder_refuses_other_tarball_sources`, `test_compare_with_github_style_archive`, `test_tarball_metadata_is_normalised`.

## 11. Open questions

1. Is a pre-built tarball artifact from one producer job (handoff R1 option 1) preferable to the canonical writer? Default: no; the writer removes the cross-environment variable instead of centralising it; the producer job remains the fallback if a future `git archive` changes framing.
2. Should the pin store the tar digest instead of the gzip digest as the primary? Default: both; the gzip digest names the release asset.
3. Does the GitHub-archive comparison need to include `export-subst` expansion? Default: it already compares file bytes; leave.

## 12. Acceptance

Three environments (local 3.11/3.12/3.13 and a GitHub runner) produce the same canonical sha256; the Linux build log shows `ghidriff source tarball: canonical bytes match the pin`; `sha256sum -c ghidriff-4f5d895-source.tar.gz.sha256` passes in CI on the uploaded asset; `SOURCE-OFFER.txt` contains that digest; the pin records the owner-approved values.
