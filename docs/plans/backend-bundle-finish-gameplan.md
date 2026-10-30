# Backend bundle: game plan to a green beta

Status: plan, written 2026-10-15 from branch `claude/instance-d-gui` at `54fd085` (worktree branch `worktree-agent-ac3a42464815a2864`, reset to that head before writing). Documents only: no code, test, workflow or existing doc was changed. Companion specs (all new, `docs/specs/program-e/`): `BUNDLE-pin-digest-and-upgrade-spec.md`, `BUNDLE-source-tarball-canonical-form-spec.md`, `BUNDLE-payload-strip-jlink-size-spec.md`, `BUNDLE-wheelhouse-and-pyghidra-spec.md`, `BUNDLE-licence-notices-and-source-offer-spec.md`, `BUNDLE-acceptance-isolation-spec.md`, `BUNDLE-import-inspector-and-consent-spec.md`, `BUNDLE-runtime-policy-spec.md`, `BUNDLE-reproducibility-spec.md`. Existing and still binding: `docs/specs/program-e/BUNDLE-integration-plan.md` (parent plan), `docs/specs/program-e/BUNDLE-release-checklist.md` (release rules, W1 to W9), `docs/specs/offline-backend-installer.md` (SPEC-06), `docs/handoff/backend-bundle.md`, `docs/runbooks/backend-bundle.md`, `docs/plans/owner-decisions-20261015.md`.

"Bundle" here means the offline, verified, pinned backend: Ghidra 12.0.4, a jlink-reduced Temurin 21.0.12.1+1 JDK, private CPython 3.12.10, PyGhidra 3.0.2, JPype1 1.5.2, packaging 25.0, mdutils 1.6.0 (built from sdist) and unmodified GPL-3.0 Ghidriff at commit `4f5d895`, built by `.github/workflows/backend-bundle.yml` and imported offline by the app.

## 0. How to read this plan

Every verifiable statement is marked **VERIFIED** (checked in this session against the repository, a command I ran, or a GitHub API/log read on 2026-10-15), **UNVERIFIED** (could not be checked here), or **HYPOTHESIS** (reasoned, with the experiment that settles it). Model tiers use the T0 to T3 scale of `docs/handoff/beta/09-model-selection-guide.md` section 3 (T0 cheap, T1 standard, T2 hard, T3 critical); supply-chain security steps are T3 for design/review and T2 for implementation, as that guide's bundle row says. Effort classes: S (under 2 h wall-clock, under 150k tokens), M (half a day, 150k to 600k), L (1 to 2 days, 600k to 2M), XL (more). "Owner dep" names the human action that can block the step.

## 1. Verified state (supersedes the 2026-10-15 handoff where they differ)

| Fact | Evidence | Status |
|---|---|---|
| Run 38676664372 (#9, head `4f56b9f`, 2026-10-15): `build-windows-full-bundle` success (05:13:11 to 05:18:52Z), artifact `bundle-windows-assets` 1,125,774,418 bytes, id 11950241206, `expired:false`, `expires_at 2026-10-22T05:18:33Z` | `list_workflow_jobs`, `list_workflow_run_artifacts` | VERIFIED |
| Same run: `accept-windows-no-network-readonly` (job 116261209710) **FAILED** at step 7 in 18 s (08:22:23 to 08:22:41Z). Log: `PatchTrace-0.1.0-windows-x64-full.zip: OK`, then `processed file: D:\a\_temp\Patch Trace ?\PatchTrace\backend` / `Successfully processed 1 files; Failed processing 0 files`, then a traceback in `bundle_acceptance.py` `run_acceptance` line 454 `base = _run(probe, env, 30)` ending `PermissionError: [WinError 5] Access is denied`. No `acceptance-windows.json` was written (artifact upload: `No files were found`). The handoff says "queued when read; result UNVERIFIED": that is now resolved to FAILED | `get_job_logs` job 116261209710 | VERIFIED |
| Same run: `build-linux-full-bundle` failed in 6 s at `PT-BUNDLE-PIN-MISMATCH` (tarball). Linux acceptance jobs skipped | job list | VERIFIED |
| Run 38686279359 (#10, head `9fbeba9`, 2026-10-15T05:20Z): `build-linux-full-bundle` failed at 11:30:31Z with the real line `error: PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: rebuilt 7086648 bytes sha256 8f96e687c72ae191def725e1753e3701be74bb80d30f5a29f7294717322802bc, pinned 7086648 bytes sha256 613449a2743e50a11c96b8a6cf6856095816cfece77a021c49cac6e4fe4fe87f` followed by `git version 2.55.0; python 3.12.15` and 16 `describe_tarball` lines. Windows build and both acceptance jobs were skipped in that run (the `platforms` input was linux) | job 116386600394 log | VERIFIED |
| The 16 per-directory digests printed by the runner (`ghidriff-4f5d895 n=1 951b5414c31904b9`, `.../ghidriff n=14 c01c9e0c12ae9dce`, `.../www n=86 684b1390386f979e`, ...) are **identical** to the ones I computed locally (git 2.43.0, Python 3.13.16, zlib 1.3) for a rebuild whose whole-file sha256 equals the pin (`613449a2...`, 7086648 bytes). So names, modes, sizes and contents are the same; only tar/gzip framing differs | local rebuild with `tools/verify_backend_pins.py rebuild`, compared line by line | VERIFIED |
| Local `content_digest` of that rebuild equals the pinned `content_sha256` `b7c9aec8ee249be052256c5db06cdaf876dba5cefc955e249c26d6ff3b75d9fc` | `content_digest()` run locally | VERIFIED |
| The pinned gzip is 110 stored (level-0) deflate blocks of **irregular** sizes (first three: 65531, 32773, 65535; last data block 41416, then an empty final block). Python 3.11.17, 3.12.3 and 3.13.16 on a host with zlib 1.3 all reproduce the pinned bytes exactly. Decompressed tar: 7,086,080 bytes, sha256 `b3bc93fa3e315d25338210d8038f250cfdd9e8b887ecb06588145974469cc5c6`. Same total size on the runner is consistent with the same block count but different split points | local experiment | VERIFIED (that framing depends on zlib/CPython buffering); the runner's decompressed tar digest is UNVERIFIED |
| Neither run exercised the B7 changes (jlink, extended strip list, runtime policy): the pin at both run heads has no `jlink` key and no `Jython` strip entry (`git show 4f56b9f:tools/backend_pin.json`, `git show 9fbeba9:tools/backend_pin.json`: 0 matches). The 1.126 GB artifact is a pre-B7 payload | git show | VERIFIED |
| No release or tag of this bundle has ever been published; nothing is signed | handoff, workflow has never had `publish_prerelease=true` run | UNVERIFIED for GitHub releases list (not queried) |
| `content_sha256` fallback (`7c1f5a2`) is in the base branch, has unit tests, and has **never run on a runner** | git log, run list (no run after 11:30Z) | VERIFIED |
| **New defect found by this plan**: when the fallback accepts a runner-laid tarball, `build_backend` still writes `<tarball>.sha256` with `tarball_entry['sha256']` (the pinned, different digest) and `SOURCE-OFFER.txt` quotes the same pinned digest, while the shipped bytes (`SOURCES/ghidriff-4f5d895.tar.gz`, the release asset) hash differently. `THIRD-PARTY.json` uses the real file hash. The workflow's "Check release sidecars" step only checks the full zip sidecar, so nothing would catch it | `tools/build_backend_bundle.py` lines 431 to 436, 401 to 403, 523 | VERIFIED by reading |
| The Windows full zip is built with `shutil.make_archive` and the Linux tar.gz by `write_tar_gz`; neither normalises mtimes (zip) / sets `mtime` (tar), `built_at` in provenance is `datetime.now`, and the workflow never sets `SOURCE_DATE_EPOCH`. Only the importer ZIP (`build_offline_bundle`) is byte-deterministic modulo zlib | `tools/build_windows.py` 141 to 143, `tools/build_linux.py` `write_tar_gz`, `attach_backend` | VERIFIED |
| `build_backend(keep_fid=False)` is the default and the only caller path from the CLI/workflow, so FID databases are **stripped** (pin `strip.ghidra_fid`). The handoff table says "Keep for the first prerelease". There is no `--keep-fid` CLI flag and no workflow input | `tools/build_backend_bundle.py` `build_backend`, `main` | VERIFIED |
| `payload/config/runtime-policy.json` is written by the builder but read by nothing in `src/` or `tools/`; `RUNTIME_POLICY.analysis_timeout_s` is 7200 while `BackendConfig.timeout_seconds` defaults to 3600 | grep | VERIFIED |
| `inspect_offline_bundle` (the user's import path) has no raw central-directory backslash check; the builder has one (`_reject_raw_backslash_names`). On a Windows host `zipfile` rewrites `\` to `/` before the inspector sees the name, so the fuzz case `backslash-name` is skipped on Windows | `offline_bundle.py`, `tests/stress/test_fuzz_archives.py` `BACKSLASH_WINDOWS` | VERIFIED |
| Local test evidence of the handoff (518 passed, 2 skipped) was not re-run here (no dependencies installed for the full suite) | n/a | UNVERIFIED |

## 2. Roadmap at a glance

Phases: **A** make the Linux build green (G0 to G3); **B** make Windows acceptance green (G4, G5); **C** shrink and harden (G6 to G10); **D** compliance and app path (G11 to G13); **E** process (G14, G15); **F** publish a prerelease and hand the owner the clean-machine test (G16 to G19).

| Id | Title | Tier | Effort | Owner dep |
|---|---|---|---|---|
| G0 | Preflight: branch, PRs, run facts | T0 | S | none |
| G1 | Prove the `content_sha256` fallback on a real runner | T0 | S | none |
| G2 | Canonical source tarball, sidecar and offer consistency | T3 design, T2 implement | M | owner approves re-pin |
| G3 | First full Linux bundle run (22.04 and 24.04 acceptance) | T1 | M | none |
| G4 | Read and fix the Windows acceptance failure | T2 | M | none |
| G5 | Windows bundle run with B7 (strip, jlink) green | T1 | M | none |
| G6 | Size budgets, split parts, recorded numbers | T1 | S | none |
| G7 | Strip rules: protected-path gate and `keep_fid` flag | T2 | M | owner FID decision |
| G8 | jlink module list proof (jdeps, Windows jmods) | T2 | M | none |
| G9 | Wheelhouse hash locks and PyGhidra 3.0.2 vs 3.1.0 | T2 | M | owner acceptance |
| G10 | Python embeddable pin: re-verification and fallback | T3 | S | none |
| G11 | Licence obligations: notices, source offer, THIRD-PARTY | T2 | M | owner legal read |
| G12 | Import path in the app: inspector parity and consent | T3 design, T2 implement | M | none |
| G13 | Runtime policy: consume the policy file, symbol servers off, bounds | T2 | M | none |
| G14 | Pin upgrade procedure and drift schedule | T2 | M | owner approves schedule |
| G15 | Reproducibility: double build and compare | T2 | M | none |
| G16 | First prerelease publication | T0 dispatch, T1 if workflow edits | S | owner confirms token |
| G17 | BinDiff pin provisioning (separate) | T1 | S | owner/network |
| G18 | Docs slice B9, QA rows, handoff refresh | T0 | S | none |
| G19 | Owner clean-machine test W1 to W9 | owner | M | owner |

### Dependency graph

```
G0 -> G1 -> G2 -> G3 ----------------------+
G0 -> G4 -> G5 ----------------------------+--> G6 --> G7
                                           |     \--> G8
G3,G5 -> G9 ; G10 (independent) ; G11 (independent, needs G3/G5 only for run evidence)
G12 (independent) ; G13 -> needs G5 for end-to-end proof
G2 -> G14 ; G3,G5 -> G15
G3,G5,(G7,G8 optional for size) -> G16 -> G18 -> G19
G17 (independent, owner/network)
```

### PR slicing order (small, mergeable; workflow changes in their own PR as the parent plan requires)

1. **PR-0 (this change, docs only)**: this plan and the nine specs.
2. **PR-1 code (G2)**: canonical gzip writer, `tar_sha256`, sidecar/offer consistency, diagnostics, tests. Pin change in a separate commit **after** the owner approves the re-pin (G2 step 6).
3. **PR-2 harness (G4)**: `tools/bundle_acceptance.py` Windows ACL fix, always-write evidence, exec checks, tests.
4. **PR-3 workflow**: `reuse_run_id`, `pin_file`, `keep_fid`, `SOURCE_DATE_EPOCH`, sidecar checks for every asset (G4, G9, G7, G15). One workflow PR, reviewed alone.
5. **PR-4 app (G12, G13)**: inspector central-directory check, runtime-policy consumption, tests. Touch `src/patchtrace/offline_bundle.py`, `backend.py`: check the open PRs first (`chatgpt/deferred-audit-fixes-1`, PR #67, touched `backend.py` per the handoff).
6. **PR-5 strips (G7, G8)**: pin strip/jlink edits only after a run proves them; one change per dispatch.
7. **PR-6 docs (G18)**.
Runs (G1, G3, G5, G16) are dispatches, not PRs.

## 3. Steps

Headings are identical for every step. "Tests" use paths that exist or are named for creation; test names are proposals unless marked existing.

---

### G0. Preflight: default-branch SHA, open PRs, checks, run facts

**Goal.** Start every work session from facts, not from this document or the 2026-10-15 handoff.

**Why it matters for beta.** `CLAUDE.md` forbids reusing snapshot facts; parallel contributors touch `backend.py`, workflow files and `tools/`.

**Preconditions.** GitHub read access (MCP github tools or `gh`).

**Exact method and technique.**
1. `gh api repos/djshellshoxxx/patchtrace/commits/main --jq .sha` and the same for `claude/instance-d-gui`. Record both SHAs.
2. `gh pr list --state open --json number,title,headRefName,statusCheckRollup`. For each PR touching `tools/build_backend_bundle.py`, `tools/bundle_acceptance.py`, `tools/backend_pin.json`, `.github/workflows/backend-bundle.yml`, `src/patchtrace/backend.py`, `src/patchtrace/offline_bundle.py`, read the diff before editing.
3. `gh run list --workflow backend-bundle.yml --limit 10 --json databaseId,headSha,conclusion,createdAt,event`. Compare against section 1 of this plan; update the plan's table if a newer run exists.
4. Confirm the working branch contains `7c1f5a2` (fallback), `db64e04` (diagnostic) and `0268517` (NTFS modes): `git log --oneline | grep -E '7c1f5a2|db64e04|0268517'`.

**Files to create/change.** none.

**Contract/schema.** none.

**Red tests.** none.

**Local commands.** `git fetch origin && git log --oneline origin/claude/instance-d-gui -5`; `python tools/check_backend_pin.py --release` (expected `backend pin ok`, exit 0).

**CI jobs and workflow_dispatch inputs.** none.

**Expected success output.** A short note in the PR description with both SHAs, the open-PR list and the latest run ids.

**Expected failure output.** An open PR that edits the same file: stop and coordinate; never push to another worker's branch.

**Definition of done.** SHAs and run ids recorded in the PR body.

**Rollback.** n/a.

**Risks.** Stale facts; the plan table in section 1 ages quickly.

**Recommended model tier.** T0.

**Effort.** S, 20k tokens, 10 minutes, no owner dependency.

---

### G1. Prove the `content_sha256` fallback on a real runner

**Goal.** One Linux dispatch whose log shows the pin check passing through the fallback path, plus the data that decides how G2 proceeds.

**Why it matters for beta.** The Linux build has failed in both runs that reached it; the fallback (`7c1f5a2`) is the owner-approved unblock but has never executed on a runner.

**Preconditions.** G0 done; branch contains `7c1f5a2`. The workflow file must have a log of the fallback path: today there is **none** (the fallback returns silently), so a one-line progress/warning addition is part of G2; for G1 alone read the absence of the mismatch error plus the later step names.

**Exact method and technique.**
1. Dispatch: `gh workflow run backend-bundle.yml --ref claude/instance-d-gui -f platforms=linux -f version=0.1.0` (inputs: `platforms` linux, `version` 0.1.0, `publish_prerelease` false (default), `pin_report_only` false, `pin_verify` false). Watch: `gh run watch <id>`.
2. Read the job `build-linux-full-bundle`, step "Build the backend payload (pinned, hash-checked downloads)": `gh run view <id> --job <jobid> --log | grep -n -E "fetching and verifying|PT-BUNDLE|assembling|jlink|strip|licences|gates"`.
3. Decision tree on the log:
   - Line `fetching and verifying pinned components` appears, **no** `PT-BUNDLE-PIN-MISMATCH` follows, and later progress lines `assembling payload trees`, `building the jlink runtime`, `applying pinned strip rules`, `building wheels from source and installing hash-locked wheels`, `collecting licences and writing notices`, `checking path, mode and size gates` appear: the fallback worked (case A).
   - `PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: rebuilt ... pinned ...` again with `content` rows: the contents differ on this runner (case B): compare the 16 describe lines with section 1 of this plan; the differing top-level directory is the lead.
   - A different code (`PT-BUNDLE-JLINK`, `PT-BUNDLE-STRIP`, `PT-BUNDLE-TOOL`, `PT-BUNDLE-MODE`): the fallback passed and B7 code is now the first failure; go to G3/G7/G8.
4. Case A: download artifact `bundle-linux-assets` and run `sha256sum -c ghidriff-4f5d895-source.tar.gz.sha256` inside it. **Expected to FAIL today** (new defect, section 1 last rows): `ghidriff-4f5d895-source.tar.gz: FAILED`. That confirms the G2 defect on a real runner.
5. Compute the runner's decompressed tar digest: `gzip -dc ghidriff-4f5d895-source.tar.gz | sha256sum`; compare with `b3bc93fa3e315d25338210d8038f250cfdd9e8b887ecb06588145974469cc5c6`. Equal means gzip framing is the sole difference (HYPOTHESIS verified); different means tar framing also differs (git 2.55 `git archive` output, then Python tarfile) and the canonical writer must include a tar rewrite (specified in the tarball spec section 5).
6. Record: runner image version (from the "Set up job" step), `python -c "import zlib;print(zlib.ZLIB_VERSION, zlib.ZLIB_RUNTIME_VERSION)"` (needs a one-off debug step: see G2 step 7), git version.

**Files to create/change.** none for the dispatch.

**Contract/schema.** none.

**Red tests.** none (existing: `tests/test_verify_backend_pins.py::test_builder_accepts_other_tar_layout_with_the_same_contents_and_refuses_changed_contents`).

**Local commands.** `python tools/verify_backend_pins.py rebuild --repo https://github.com/clearbluejar/ghidriff --commit 4f5d895fcbb1eacd65efd81145922c15bb7e741d --out /path/new/dir/ghidriff-source.tar.gz` (expected `"sha256": "613449a2...fe87f"`, size 7086648 on a zlib 1.3 host: VERIFIED here).

**CI jobs and workflow_dispatch inputs.** `build-linux-full-bundle`; inputs as in step 1.

**Expected success output.** Log excerpt (case A, today without a fallback line):
```
fetching and verifying pinned components
assembling payload trees
building the jlink runtime
applying pinned strip rules
...
built ghidra-12.0.4-ghidriff-4f5d895-linux-amd64: <N> files, <bytes> payload bytes, <sha>  PatchTrace-0.1.0-backend-linux-amd64.zip
```
**Expected failure output.** Case B/old behaviour:
```
error: PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: rebuilt 7086648 bytes sha256 8f96e687..., pinned 7086648 bytes sha256 613449a2...
git version 2.55.0; python 3.12.15
ghidriff-4f5d895 n=1 951b5414c31904b9
...
##[error]Process completed with exit code 3.
```

**Definition of done.** The decision-tree case recorded in `docs/qa.md` row BUNDLE-LIN-1 with the run URL; the sidecar-failure observation attached.

**Rollback.** none (read-only run).

**Risks.** Runner image drift changes the result; the Linux job costs about 1 runner-minute until the failure, up to 10 minutes if it passes.

**Recommended model tier.** T0 (running and reading logs by rule).

**Effort.** S, 40k tokens, 30 minutes wall-clock, no owner dependency.

---

### G2. Canonical source tarball; sidecar and source-offer consistency

**Goal.** The Ghidriff source tarball that is hashed, pinned, shipped in `SOURCES/`, attached as a release asset and quoted in `SOURCE-OFFER.txt` is byte-identical on every runner, and every quoted digest equals the shipped bytes.

**Why it matters for beta.** The GPL-3.0 corresponding-source obligation depends on shipping the exact source that the offer names. Today a fallback-accepted build ships bytes whose digest differs from the digest in the sidecar and offer (section 1). Supply-chain safety also needs one digest that every environment can verify.

**Preconditions.** G1 result (case A or B). Owner decision to re-pin (the existing digest `613449a2...` was never released, so no downstream consumer breaks).

**Exact method and technique.** Full algorithm in `BUNDLE-source-tarball-canonical-form-spec.md`. Summary:
1. Keep stage 1 as is: fetch exactly the pinned commit (`git init; git fetch --depth 1 <repo> <sha>`; `git rev-parse FETCH_HEAD^{commit}` must equal the pin), `git archive --format=tar --prefix=ghidriff-<sha7>/ <sha>` with `core.autocrlf=false`, `core.eol=lf`.
2. Replace gzip-by-zlib with a writer that does not depend on zlib: parse the archive with `tarfile`, rewrite headers exactly as `_normalised_tar` does (mtime 315532800, uid/gid 0, empty names, modes 0644/0755, GNU format), then emit gzip as a 10-byte header `1f 8b 08 00 00 00 00 00 00 ff`, stored blocks of at most 65535 bytes (last block marked final, no trailing empty block), trailer `CRC32 | ISIZE` little endian. For the pinned commit this yields 7,086,643 bytes, sha256 `c93b5d07fea5aaa03ac82b59ee649ebbf0aa5a576ca301a28ea48060bead0cbc` (VERIFIED locally; the experiment is in section 1).
3. Add additive pin fields `tar_sha256` (`b3bc93fa...`, the decompressed tar, VERIFIED locally) next to the existing `content_sha256`. Verification order in `rebuild_ghidriff_tarball` (exact pseudocode in the tarball spec section 5): (a) build the normalised tar from the runner's own `git archive`, emit the canonical gzip, compare `sha256`+`size` with the pin; (b) on mismatch print `tar_sha256`, block count and per-directory digests; (c) `content_sha256` is a diagnostic only and never accepts a different byte layout into the shipped bundle. Anything else fails with `PT-BUNDLE-PIN-MISMATCH`.
4. Whatever is shipped is exactly what was verified: the release tarball, `SOURCES/ghidriff-<sha7>.tar.gz`, the `.sha256` sidecar, `SOURCE-OFFER.txt` and `THIRD-PARTY.json` all derive from `sha256_file(path_of_shipped_bytes)`, and the builder asserts equality with the pin before writing them (new code `PT-BUNDLE-SOURCE-DIGEST`).
5. Surface which path was taken: `build-report.json` gains `ghidriff_source: {"path": "exact|tar|content", "sha256": ...}` and the progress stream prints `ghidriff source tarball: canonical bytes match the pin`.
6. Re-pin: run `backend-bundle.yml` with `pin_verify=true` (inputs `sigstore_identity=thomas@python.org`, `sigstore_issuer=https://accounts.google.com`; these were the values of run 38661029764) and require `ghidriff.rebuilt_twice_identical=true` plus `content_comparison.identical=true` in `pin-verify.json`; the owner approves writing `sha256`, `size`, `tar_sha256` into the pin (decision recorded in `docs/plans/owner-decisions-<date>.md`).
7. One-off diagnostic step in the workflow (only in the PR-3 workflow change): print `python -c "import zlib,sys;print(sys.version, zlib.ZLIB_VERSION, zlib.ZLIB_RUNTIME_VERSION)"` and `git --version` before the build, so a future framing difference is attributable.

**Files to create/change.** `tools/verify_backend_pins.py` (`build_tarball`, new `canonical_gzip`, `tar_digest`, `describe_tarball` prints tar digest and block count), `tools/build_backend_bundle.py` (`rebuild_ghidriff_tarball`, sidecar and offer code at lines 401 to 436), `tools/backend_pin.json`, `tools/check_backend_pin.py` (validate `tar_sha256`/`content_sha256` as 64-hex), `tests/test_verify_backend_pins.py`, `tests/test_build_backend_bundle.py`, `tests/test_backend_pin.py`.

**Contract/schema.** `ghidriff.source_tarball` gains optional `tar_sha256` (64 lowercase hex). Additive: old readers ignore it; `check_backend_pin.validate_pin` today does not check `content_sha256` (VERIFIED, no reference in the file) so add a shared rule for both. `build-report.json` gains `ghidriff_source`. `THIRD-PARTY.json` schema `patchtrace-third-party/1` is unchanged.

**Red tests.**
- `tests/test_verify_backend_pins.py::test_canonical_gzip_is_independent_of_zlib` : monkeypatch `zlib.compressobj` to raise; `canonical_gzip(tar)` must still return bytes whose `gzip.decompress` equals `tar` and whose sha256 equals a golden value computed from a small fixture tar.
- `::test_canonical_gzip_blocks_are_65535_and_final_flag_only_on_last`.
- `::test_rebuild_is_identical_when_python_gzip_block_split_changes` : patch `gzip.GzipFile.write` to split at 16 KiB; digest unchanged.
- `tests/test_build_backend_bundle.py::test_fallback_tarball_sidecar_and_offer_hash_match_the_shipped_bytes` : a `source_builder` producing a different gzip layout of the same tar; assert `sha256sum`-style check of the `.sha256` sidecar against the copied file, and that `SOURCE-OFFER.txt` contains `sha256_file(SOURCES/...)`. Red today.
- `::test_content_only_match_is_refused_for_shipping` : tar differs, content equal: expect `PT-BUNDLE-PIN-MISMATCH` unless canonical re-emission makes the whole digest match.
- `::test_changed_member_content_is_refused` (existing analogue stays green).
- `tests/test_backend_pin.py::test_source_tarball_digest_fields_are_hex`.

**Local commands.** `python -m pytest -q tests/test_verify_backend_pins.py tests/test_build_backend_bundle.py tests/test_backend_pin.py`; `python tools/verify_backend_pins.py rebuild ...` twice on two Python versions (3.11, 3.12, 3.13 are installed on the Linux sandbox: VERIFIED present) and compare `sha256`.

**CI jobs and workflow_dispatch inputs.** `pin-verify-signatures-and-rebuild` (`pin_verify=true`, `sigstore_identity`, `sigstore_issuer`) on ubuntu-latest; then `build-linux-full-bundle` (`platforms=linux`).

**Expected success output.** pin-verify: `"rebuilt_twice_identical": true`, `"result": "verified"`; build log: `ghidriff source tarball: canonical bytes match the pin`; `sha256sum -c` of every release sidecar passes.

**Expected failure output.**
```
error: PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: canonical rebuild 7086643 bytes sha256 <x>, pinned 7086643 bytes sha256 <y>
tar_sha256 <a> (pinned <b>)
```
and, for the new gate, `error: PT-BUNDLE-SOURCE-DIGEST: shipped source tarball sha256 <a> differs from the digest in SOURCE-OFFER.txt <b>`.

**Definition of done.** Same `sha256` from three different environments (local Python 3.11/3.12/3.13 and a runner); runner log shows the success line; sidecar check passes in CI for the source tarball; the pin shows the owner-approved new digests; `tests/test_backend_pin.py` green.

**Rollback.** Revert the code PR; the pin keeps `content_sha256` fallback (accepting but with the sidecar defect, so also set the fallback path to copy the digest it computed). Restore the old pin lines from git.

**Risks.** The hand-written gzip must remain valid for every reader (`gzip.decompress` and `tar -xzf` verified in tests); the owner must approve the new digest or the supply-chain "no trust on first use" rule is broken; a git release that changes `git archive` framing would change `tar_sha256` (then step 3b is skipped and the tar rewrite is the stable layer).

**Recommended model tier.** T3 for the design review of the digest chain, T2 to implement (matches guide row "pin and digest logic").

**Effort.** M, 700k tokens, 1 day wall-clock including one `pin_verify` run; owner approval of the re-pin.

---

### G3. First full Linux bundle run (build plus acceptance on 22.04 and 24.04)

**Goal.** `build-linux-full-bundle` and both legs of `accept-linux-no-network-readonly (ubuntu-22.04|ubuntu-24.04)` green on one run.

**Why it matters for beta.** Linux is a supported target ("experimental" label until owner test) and the Linux run is the first place the B7 strip and jlink changes execute.

**Preconditions.** G2 merged (or G1 case A with the sidecar defect accepted for a throwaway run); `sudo` available on runners (it is on GitHub-hosted Ubuntu).

**Exact method and technique.**
1. Dispatch `-f platforms=linux -f version=0.1.0`.
2. Build job: expect `reduce_jdk` to run `jlink --module-path <jdk>/jmods --add-modules <26 modules> --strip-debug --no-man-pages --no-header-files --compress=zip-6 --output <work>/jlink-runtime`. Failure `PT-BUNDLE-JLINK: jlink produced no runtime image (lib/modules is missing)` means the tool failed: read the preceding `PT-BUNDLE-TOOL` text (tail 1500 characters of stderr).
3. Strip: `strip_tree` must not raise `PT-BUNDLE-STRIP`. Note `keep` is a weak gate (section G7).
4. Mode gate: `PT-BUNDLE-MODE: N file(s) lost the execute bit (pattern 'jdk/bin/*')` would mean the jlink image modes were mis-derived. The NTFS-only variant of this error was fixed in `0268517`; on Linux modes come from `(jdk/name).stat().st_mode & 0o111`.
5. Acceptance legs: read `acceptance-linux-ubuntu-22.04` and `-24.04` artifacts. Expected step names in the JSON in order: `layout`, `path-shape`, `env-scrub`, `path-has-no-java-python`, `digest-before`, `control-before`, `control-after` (verdict `proven`), `readonly-effective`, `backend-verify-full`, `backend-selftest`, `ghidriff-compare`, `no-external-connections`, `digest-after-equal`.
6. 24.04 risk (UNVERIFIED): AppArmor restricts unprivileged user namespaces, but the harness uses `sudo unshare --net` (root), which is unaffected. If `control-after` shows `denial-ineffective`, the namespace did not isolate: check `ip link set lo up` and that the probe target is not reachable through `lo`.
7. Record sizes (`ls -l assets`, `build-report.json`), file count, and extracted size.

**Files to create/change.** Only if a harness bug appears: `tools/bundle_acceptance.py` (`linux_denial_argv`, `linux_sampler`), `tests/test_bundle_acceptance_unit.py`.

**Contract/schema.** none new.

**Red tests.** One test per bug found, first in `tests/test_bundle_acceptance_unit.py`.

**Local commands.** `python -m pytest -q tests/test_bundle_acceptance_unit.py tests/test_build_backend_bundle.py -k "linux or jlink or strip"`; `python tools/bundle_acceptance.py <fake-root> --dry-run ...` (the existing dry-run test `test_dry_run_with_fake_bundle_proves_denial_and_equal_digest` proves the namespace denial on a Linux box with `unshare`).

**CI jobs and workflow_dispatch inputs.** `build-linux-full-bundle`, `accept-linux-no-network-readonly (ubuntu-22.04)`, `(ubuntu-24.04)`; `platforms=linux`.

**Expected success output.** Build: `built ghidra-12.0.4-ghidriff-4f5d895-linux-amd64: ...`; `PatchTrace-0.1.0-linux-x86_64-full.tar.gz: OK` in "Check release sidecars". Acceptance JSON: `"wording": "passed with OS network block (positive control proven)"`, `"ok": true`.

**Expected failure output.** `PT-BUNDLE-MODE`, `PT-BUNDLE-JLINK`, `PT-BUNDLE-SIZE-LIMIT: PatchTrace-0.1.0-linux-x86_64-full.tar.gz is N bytes; split or fall back to lite + backend ZIP pair`, or in the JSON `{"name": "control-after", "ok": false, "data": {"verdict": "denial-ineffective"}}` (then the run stops by design, `return ev`).

**Definition of done.** All three jobs green, URL recorded in `docs/qa.md` BUNDLE-LIN-2, sizes recorded for G6.

**Rollback.** Do not publish; revert the specific strip/jlink pin edit that caused the failure (one change per dispatch).

**Risks.** First real jlink run; Ghidra may need a module the static scan missed (see G8); the Linux label stays "experimental".

**Recommended model tier.** T1.

**Effort.** M, 400k tokens, 3 to 5 hours with reruns, no owner dependency.

---

### G4. Read and fix the Windows acceptance failure

**Goal.** `accept-windows-no-network-readonly` runs to the end and writes `acceptance-windows.json` (green or with a precise red step).

**Why it matters for beta.** Windows is the primary beta platform; no Windows end-to-end evidence exists.

**Preconditions.** None. The failing build artifact `bundle-windows-assets` (run 38676664372) is downloadable until **2026-10-22T05:18Z** (VERIFIED `expires_at`): iterate on acceptance without rebuilding.

**Exact method and technique.**
1. **Read the log (done in this plan; repeat for any new run).** MCP: `get_job_logs(owner=djshellshoxxx, repo=patchtrace, job_id=116261209710, return_content=true, tail_lines=120)`; CLI: `gh run view 38676664372 --job 116261209710 --log`, or `gh api repos/djshellshoxxx/patchtrace/actions/jobs/116261209710/logs` (follows a redirect to the log text). Search for the first `Traceback` or `##[error]`; ignore the large `env:` blocks printed by `ilammy/msvc-dev-cmd`.
2. **What the log says (VERIFIED).** icacls reported success on the backend directory, then the very first subprocess of the harness, `_run(probe, env, 30)` with `probe = [bundle python.exe, '-I', '-c', ...]`, raised `PermissionError: [WinError 5] Access is denied` from `CreateProcess`. The positive-control step never ran; the harness crashed before `Evidence.to_json()`, so no artifact exists.
3. **Root cause (HYPOTHESIS, ranked).**
   - H1 (most likely): `windows_readonly_command` denies `(OI)(CI)(W,D,DC)` to `%USERNAME%`. icacls "W" is the generic write mask `FILE_GENERIC_WRITE`, which includes `SYNCHRONIZE` and `READ_CONTROL`; a deny ACE on `SYNCHRONIZE` inherited by every file under `backend\` makes `CreateProcess` fail to open the image (`ERROR_ACCESS_DENIED`). Settles it: run `icacls <python.exe>` after the deny and look for `(DENY)(Rc,S,WD,AD,WEA,WA,...)`; or on a scratch tree apply `/deny "%USERNAME%:(OI)(CI)(WD,AD,WEA,WA,DE,DC)"` and confirm `python.exe -I -c pass` runs.
   - H2: Defender real-time blocking of the freshly extracted `python.exe` (check `Get-MpThreatDetection`; unlikely, the same files ran in the build job's PyInstaller step).
   - H3: the non-ASCII path (`Patch Trace é中`, shown as `?` in the console log only) breaks the ACL tool or the executable path (the later `PatchTrace.exe --self-test` ran in a different path).
   - H4: the scrubbed environment (`PATH=%SystemRoot%\System32;%SystemRoot%`, `TEMP`, `USERPROFILE`, `LOCALAPPDATA`, `SystemRoot`) is missing something `python.exe` needs at start; unlikely because the failure is `CreateProcess` access denied, not a start-up error from the child.
4. **Fix design (see `BUNDLE-acceptance-isolation-spec.md` section 4).**
   - Replace the deny ACE by specific rights that never include `SYNCHRONIZE`, `READ_CONTROL`, `FILE_READ_*`, `FILE_EXECUTE`: `icacls <backend> /deny "<account>:(OI)(CI)(WD,AD,WEA,WA,DE,DC)"`; remove it in `finally` with `icacls <backend> /remove:d <account> /T`.
   - Add an executability probe before and after the lock: run `python.exe -I -c "print(1)"` under the scrubbed env; record steps `exec-before-readonly` and `exec-after-readonly` in the evidence.
   - Add a Windows `readonly-effective` probe: creating `backend\.pt-write-probe` must raise `PermissionError` under the lock.
   - Wrap `run_acceptance` in `try/except BaseException`: on any exception append a step `harness-exception` with the traceback text and still write the evidence JSON; never lose the evidence file. `main` must write `--evidence` before returning.
   - Add the workflow input `reuse_run_id` (number): when set, `build` jobs are skipped and the acceptance job downloads `bundle-windows-assets` from that run (`actions/download-artifact@v4` with `run-id` and `github-token`, `permissions: actions: read`). Use `reuse_run_id=38676664372` to iterate until 2026-10-22.
5. Do not weaken the positive control (`control_verdict` returns `proven` only if before connects and after is blocked).

**Files to create/change.** `tools/bundle_acceptance.py` (`windows_readonly_command`, `run_acceptance`, `main`), `tests/test_bundle_acceptance_unit.py`, `.github/workflows/backend-bundle.yml` (separate PR-3), `tests/test_backend_bundle_workflow.py` (assert the new input is only used through `env:`).

**Contract/schema.** Evidence JSON schema `patchtrace-bundle-acceptance/1` gains steps `exec-before-readonly`, `exec-after-readonly`, `readonly-effective` (Windows) and `harness-exception`. Additive; consumers read `steps[]` by name.

**Red tests.**
- `test_windows_readonly_command_denies_only_write_and_delete_rights`: assert the argv string contains `WD,AD,WEA,WA,DE,DC` and **not** the substrings `(W,` or `,W,` or `SYNCHRONIZE`; existing `test_windows_readonly_command_pair` must be updated, not deleted.
- `test_windows_readonly_removal_is_issued_in_finally` (inject a failing step; assert `deny=False` command is run).
- `test_run_acceptance_writes_partial_evidence_on_exception` (monkeypatch `_run` to raise `PermissionError`; assert `harness-exception` step and JSON file).
- `test_main_writes_evidence_even_when_run_raises`.
- `test_exec_probe_failure_is_reported_before_the_control` (fake `_run`).

**Local commands.** `python -m pytest -q tests/test_bundle_acceptance_unit.py`. On a Windows box: `icacls` experiment from H1 on a scratch folder with a copy of any `.exe`.

**CI jobs and workflow_dispatch inputs.** `accept-windows-no-network-readonly`; `platforms=windows`, `reuse_run_id=38676664372` (new input), `version=0.1.0`.

**Expected success output.** Log: `PatchTrace-0.1.0-windows-x64-full.zip: OK`, then the JSON printed by `ba.main`: `"ok": true`, `"wording": "passed with OS network block (positive control proven)"`, steps through `digest-after-equal`.

**Expected failure output.** For H1 unresolved: `{"name": "exec-after-readonly", "ok": false, "detail": "[WinError 5] Access is denied"}`. For a blocked control: `{"name": "control-after", "ok": false, "data": {"verdict": "denial-ineffective"}}`. For a missing baseline: `"verdict": "invalid-no-baseline"` (the runner has no outbound route to `1.1.1.1:443`: switch `--control` to a GitHub IP or a loopback server started by the harness, and keep the wording rule).

**Definition of done.** One green acceptance JSON on a real Windows runner for a build that contains B7 (that is G5), or a red JSON naming a step that is not a harness bug.

**Rollback.** The harness is CI-only; revert the PR. A leftover deny ACE on a runner disappears with the runner.

**Risks.** Windows firewall rules need admin (GitHub runners are admin: UNVERIFIED for the current image; `New-NetFirewallRule` failure raises `CalledProcessError` because `check=True`: also catch it into a step). Loopback exemption of Windows Firewall is UNVERIFIED (plan 10.2).

**Recommended model tier.** T2 (platform-specific, plausible wrong answers easy).

**Effort.** M, 500k tokens, 4 to 6 hours with 3 to 4 dispatches of about 5 minutes each (artifact reuse), no owner dependency.

---

### G5. Windows bundle run with B7 (strip, jlink) green

**Goal.** A Windows build that contains the B7 strip list, the jlink image and the runtime policy, passes acceptance.

**Why it matters for beta.** All size reductions are unproven on Windows; Windows jlink needs the Windows `jmods` (research: UNVERIFIED).

**Preconditions.** G4 harness fix merged (otherwise acceptance cannot judge); G2 not required for Windows (the Windows runner passed the tarball check in run #9).

**Exact method and technique.**
1. Dispatch `-f platforms=windows -f version=0.1.0`. The build job runs `python tools/build_backend_bundle.py build --platform windows --out bundle-out --cache-dir .bundle-cache --version 0.1.0 --split --json` then `python tools/build_windows.py --full --backend-payload bundle-out/backend --version 0.1.0`.
2. Read the build log lines in order (each is a `progress` line on stderr): `fetching and verifying pinned components`, `assembling payload trees`, `building the jlink runtime`, `applying pinned strip rules`, `building wheels from source and installing hash-locked wheels`, `collecting licences and writing notices`, `checking path, mode and size gates`. The JSON from `--json` carries `files`, `payload_bytes`, `stripped_files`, `stripped_bytes`, `warnings`.
3. jlink on Windows: the JDK zip contains `jmods`; `bin\jlink.exe --module-path jdk\jmods ...` is expected to work for a Windows target on a Windows host (same platform: low risk; the cross-platform case is not needed because the builder runs on the target OS).
4. After acceptance green, open `acceptance-windows.json` and record: seconds per step, `ghidriff-compare` returncode, the result file names.
5. Compare against the pre-B7 numbers: artifact 1,125,774,418 bytes (three files). Record the new full zip size, importer zip size, extracted size, file count (limit 60,000 members, `policy.MAX_MEMBERS`).

**Files to create/change.** `tools/backend_pin.json` only if a strip pattern removed a needed Ghidra file (error text will name a missing class or file; remove that one pattern; never weaken `keep`).

**Contract/schema.** none.

**Red tests.** If a Ghidra file is needed: `tests/test_build_backend_bundle.py::test_strip_list_never_removes_<name>` (G7 provides the generic protected-path test).

**Local commands.** `python tools/check_backend_pin.py --release --allow-unapproved-licenses`; `python -m pytest -q tests/test_build_backend_bundle.py tests/test_build_full_variants.py`.

**CI jobs and workflow_dispatch inputs.** `build-windows-full-bundle`, `accept-windows-no-network-readonly`; `platforms=windows`.

**Expected success output.** Build: `built ghidra-12.0.4-ghidriff-4f5d895-windows-amd64: <files> files, <bytes> payload bytes, <sha>  PatchTrace-0.1.0-backend-windows-amd64.zip` and in "Check release sidecars": `PatchTrace-0.1.0-windows-x64-full.zip: OK` / `PatchTrace-0.1.0-windows-x64.zip: OK`. Acceptance green as in G4.

**Expected failure output.** `PT-BUNDLE-JLINK`, `PT-BUNDLE-STRIP: strip rules removed everything matching keep pattern 'licenses/**'`, `PT-BUNDLE-PATH-LENGTH`, or at runtime inside acceptance `backend-selftest` exit 3 with a Java `ClassNotFoundException`/`NoClassDefFoundError` naming a stripped module (then add the module to `jlink.modules`, G8, or drop the strip, G7).

**Definition of done.** Green build and acceptance on one run; numbers recorded in `docs/qa.md` BUNDLE-5 and BUNDLE-3.

**Rollback.** Remove the failing item from `strip.ghidra` or `jlink` (one commit per item), rerun.

**Risks.** `Ghidra/Debug` removal affects only the debugger; `Extensions/**` removal breaks nothing at headless; FID databases removal changes function identification for statically linked library code (not a failure). Defender slowdowns on 40k files.

**Recommended model tier.** T1; T2 only for a demonstrated JPype/Ghidra headless failure on Windows.

**Effort.** M, 400k tokens, 3 to 6 hours.

---

### G6. Size budgets, split parts and recorded numbers

**Goal.** Written, enforced budgets and a recorded size table for every asset; a clear rule for parts.

**Why it matters for beta.** GitHub's release-asset limit is 2 GiB; today only the importer ZIP can be split, and the full zip hard-fails above 1.9 GiB.

**Preconditions.** G3 and G5 produce real sizes.

**Exact method and technique.** Budgets and algorithm are in `BUNDLE-payload-strip-jlink-size-spec.md` section 6. Summary: hard gate `ASSET_LIMIT = 1.9 GiB = 2,040,109,465` bytes (`int(1.9*1024**3)`); `SIZE_WARN = 1.2e9`; research estimate for stripB + jlink is about 0.31 GB extracted (Ghidra + JDK) and about 0.15 GB zipped (HYPOTHESIS from Linux, one small PE). Add a lower **budget gate** `BUDGET_FULL_ARCHIVE = 700 MB` as a warning that fails only with `--release`, so growth is noticed. The split algorithm (`split_file`, parts `<name>.001`, `.002`, each at most `asset_limit`, `.parts.sha256` file and whole-file `.sha256`) exists for the importer ZIP; decide explicitly that the **full** archives are never split (a user must be able to double-click-extract one file) and fall back to "lite + backend ZIP pair" above the gate. Join procedure for parts: `cat PatchTrace-0.1.0-backend-windows-amd64.zip.* > ...zip` or `join_parts(parts, dest, expected_sha256)`; document it in `docs/windows.md` (G18). Record in a table with columns: asset, bytes, sha256, files, extracted bytes, run URL.

**Files to create/change.** `tools/build_backend_bundle.py` (`BUDGET` constants, build-report `sizes`), `tests/test_build_backend_bundle.py`, `docs/qa.md` (G18).

**Contract/schema.** `build-report.json` adds `sizes: {archive_bytes, payload_bytes, largest_files[10]}`.

**Red tests.** `test_size_budget_warning_is_a_hard_failure_only_in_release_mode`, `test_build_report_lists_the_ten_largest_files`, existing `test_split_archive_parts_fit_the_limit_and_join_back` stays.

**Local commands.** `python -m pytest -q tests/test_build_backend_bundle.py -k "size or split"`.

**CI jobs and workflow_dispatch inputs.** the build jobs; no new input (the budget is a constant; `--asset-limit` exists on the CLI).

**Expected success output.** `warning:` lines absent; `build-report.json` `"sizes"` populated.

**Expected failure output.** `error: PT-BUNDLE-SIZE-LIMIT: PatchTrace-0.1.0-backend-windows-amd64.zip is 2100000000 bytes, above the 2040109465 byte release-asset limit: re-run with --split, or fall back to the lite build plus the backend ZIP pair`; in the app build `PT-BUNDLE-SIZE-LIMIT: PatchTrace-0.1.0-windows-x64-full.zip is N bytes; split or fall back to lite + backend ZIP pair`.

**Definition of done.** Size table in `docs/qa.md`; budget gate tested.

**Rollback.** Remove the budget constant.

**Risks.** Zip sizes vary by compression library; do not compare sizes across runners for reproducibility (G15).

**Recommended model tier.** T1.

**Effort.** S, 150k tokens, 2 hours.

---

### G7. Strip rules: protected-path gate and the `keep_fid` flag

**Goal.** A strip list that cannot silently remove something Ghidra needs, and an explicit, tested way to keep FID databases.

**Why it matters for beta.** The `keep` gate is weak: `Ghidra/Features/**` still matches after Jython, BSim and GhidraServer are removed, so `PT-BUNDLE-STRIP` cannot fire for them (VERIFIED by reading `strip_tree`). The FID default contradicts the handoff.

**Preconditions.** G5 (Windows) and G3 (Linux) produced one green run with the current list.

**Exact method and technique.**
1. Protected paths: add to the pin a list `strip.protected` (additive) of exact required files/directories: `Ghidra/Features/Decompiler/**`, `Ghidra/Features/PDB/**`, `Ghidra/Features/Base/**` (minus `typeinfo/golang/**`), `Ghidra/Features/PyGhidra/**`, `Ghidra/Features/VersionTracking/**`, `Ghidra/Processors/x86/**`, `Ghidra/Framework/**`, `Ghidra/application.properties`, `support/**`, `LICENSE`, `licenses/**`. `strip_tree` fails with `PT-BUNDLE-STRIP: strip rule <rule> would remove protected path <path>` if any strip glob matches a protected file (check **before** deleting, for every matched file).
2. `keep_fid`: expose as `build --keep-fid` and a workflow_dispatch boolean input `keep_fid` (default false) passed through `env: KEEP_FID` (never interpolated into the shell). With the flag the `ghidra_fid` globs are not appended (code already supports it: `keep_fid` parameter and test `test_keep_fid_pin_flag_retains_the_function_id_databases`).
3. FID decision (owner): research shows FID is 204 MB uncompressed, 79.5 MB zipped; no evidence that it helps kernel images. Recommendation: ship the first prerelease **without** FID (current behaviour) and record the A/B acceptance (`keep_fid=true` vs false: same `read_item` result) so a later release can flip it.
4. One change per dispatch; record sizes before/after.

**Files to create/change.** `tools/backend_pin.json` (`strip.protected`), `tools/check_backend_pin.py` (validate list of strings), `tools/build_backend_bundle.py` (`strip_tree`, `main`), `.github/workflows/backend-bundle.yml` (PR-3), `tests/test_build_backend_bundle.py`, `tests/test_backend_pin.py`, `tests/test_backend_bundle_workflow.py`.

**Contract/schema.** `strip.protected`: list of non-empty glob strings, no `..`, additive.

**Red tests.** `test_strip_rule_matching_a_protected_path_is_refused`, `test_committed_strip_list_matches_no_protected_path` (run against a synthetic tree built from the real Ghidra layout list in the research doc), `test_keep_fid_cli_flag_reaches_build_backend`, `test_workflow_keep_fid_input_goes_through_env`.

**Local commands.** `python -m pytest -q tests/test_build_backend_bundle.py tests/test_backend_pin.py tests/test_backend_bundle_workflow.py`.

**CI jobs and workflow_dispatch inputs.** build jobs; new input `keep_fid` (boolean, default false).

**Expected success output.** Build summary `stripped_files` and `stripped_bytes` reported; with `keep_fid=true`, `stripped_bytes` smaller by about 204 MB (Linux, research).

**Expected failure output.** `error: PT-BUNDLE-STRIP: strip rule 'Ghidra/Features/Base/**' would remove protected path 'Ghidra/Features/Base/lib/Base.jar'`.

**Definition of done.** Gate and flag merged; A/B acceptance results in `docs/qa.md` BUNDLE-5.

**Rollback.** Remove `strip.protected` (gate becomes a no-op); flag default unchanged.

**Risks.** Over-broad protected list blocks legitimate strips; keep it minimal and test against the real list.

**Recommended model tier.** T2.

**Effort.** M, 400k tokens, 3 hours; owner FID decision.

---

### G8. jlink module list proof

**Goal.** The 26-module list is justified, minimal and proven on both OS; a stripped module can never be silently required.

**Why it matters for beta.** A missing module shows up only at analysis time as a Java error; the list came from a static scan on Linux (research section 5.2).

**Preconditions.** G3, G5.

**Exact method and technique.** Current list (VERIFIED in the pin): `java.base, java.desktop, java.xml, java.logging, java.datatransfer, java.management, java.sql, java.naming, java.rmi, java.scripting, java.compiler, java.net.http, java.security.jgss, java.prefs, java.instrument, jdk.unsupported, jdk.xml.dom, jdk.security.auth, jdk.net, jdk.management, jdk.crypto.ec, jdk.zipfs, jdk.charsets, jdk.jdi, jdk.jshell, jdk.compiler`. Procedure: (1) in CI after extraction run `jdeps --multi-release 21 --ignore-missing-deps -summary -R --module-path jdk/jmods <each Ghidra jar>` **one jar at a time** (a multi-jar run fails on automatic modules, research), union the `java.*`/`jdk.*` names, diff against the pin list, fail with `PT-BUNDLE-JLINK: modules required by Ghidra jars but missing from jlink.modules: [...]`; (2) behavioural proof: acceptance `ghidriff-compare` must pass; additionally run `java --list-modules` in the produced runtime and assert the set equals the pin list plus `java.base` dependencies; (3) keep `jdk.compiler` (PyGhidra imports `pyghidra.javac.java_compile`; removal untested); (4) licence: copy `legal/` and root licence files (the code does; `find_tree_licenses` finds `legal/*`). Option to evaluate (not now): `jlink --add-modules ... --bind-services`.

**Files to create/change.** `tools/build_backend_bundle.py` (new `jdeps_modules()` check run under `--verify-modules`), `tests/test_build_backend_bundle.py`.

**Contract/schema.** none.

**Red tests.** `test_jlink_module_gap_is_reported_with_the_missing_names` (fake runner returning jdeps output), `test_jlink_modules_listing_must_equal_the_pin`.

**Local commands.** `python -m pytest -q tests/test_build_backend_bundle.py -k jlink`; Linux manual: `jdeps -summary <jar>`.

**CI jobs and workflow_dispatch inputs.** build jobs; no new input.

**Expected success output.** `jlink runtime modules verified: 26`.

**Expected failure output.** `error: PT-BUNDLE-JLINK: modules required by Ghidra jars but missing from jlink.modules: ['jdk.localedata']`.

**Definition of done.** Both OS runs pass with the verified list; sizes recorded (research estimate 78 MB on disk, UNVERIFIED on Windows).

**Rollback.** Remove the `jlink` key from the pin: the builder keeps the full JDK (`test_pin_without_jlink_keeps_the_full_jdk`).

**Risks.** Service providers and reflection are invisible to jdeps; mitigations are the behavioural acceptance run and the conservative extra modules.

**Recommended model tier.** T2.

**Effort.** M, 400k tokens, 4 hours.

---

### G9. Wheelhouse hash locks and PyGhidra 3.0.2 versus 3.1.0

**Goal.** The wheelhouse stays hash-locked and index-free, and the PyGhidra version question gets an evidence-based answer.

**Why it matters for beta.** CI live lanes install PyGhidra unpinned (3.1.0 satisfies `>=3.0.0,<4`); the bundle ships 3.0.2 (the version inside Ghidra 12.0.4). A difference would make bundle results differ from CI results.

**Preconditions.** G3/G5 green on 3.0.2.

**Exact method and technique.** Details in `BUNDLE-wheelhouse-and-pyghidra-spec.md`.
1. Lock mechanics (VERIFIED in code): `write_requirements` emits `<dist>==<ver> --hash=sha256:<hash>` for each wheel; the install is `python -I -m pip install --no-index --find-links <wheelhouse> --no-deps --only-binary=:all: --require-hashes --no-compile --target <site> --platform ... --python-version 3.12 --implementation cp --abi cp312 -r requirements.lock.txt`, env scrubbed (`PIP_NO_INDEX=1`, `PIP_CONFIG_FILE=/dev/null`). Wheels built from source (mdutils sdist, Ghidriff) are locked by the digest of the wheel built in this run, so those two are verified by (a) the sdist/tarball digest from the pin and (b) `compare_wheel_to_source` byte comparison, not by a pinned wheel hash.
2. A/B: add a workflow_dispatch input `pin_file` (string, default `tools/backend_pin.json`, validated by `^tools/backend_pin[A-Za-z0-9._-]*\.json$`) so a candidate pin `tools/backend_pin.pyghidra31.json` (pyghidra 3.1.0 wheel with its PyPI digest, `kind wheel`, same `any` lane) can be built without touching the main pin. Compare acceptance outputs: same `read_item` match, same number of matches, JSON result digest equal after volatile fields are removed.
3. Decision rule: ship 3.0.2 unless 3.1.0 fixes a reproduced failure; if 3.1.0 is adopted, the wheel must come from PyPI JSON with `digest_source: pypi-json`, JPype1 must stay 1.5.2 unless 3.1.0 declares otherwise (check `Requires-Dist` in the wheel `METADATA`, which the builder can print), and the Ghidra `pypkg/dist` cross-check becomes "newer than vendor" (record as accepted deviation by the owner).
4. Guard: `ghidra_pypkg_crosscheck` already records that PyPI 3.0.2 and Ghidra's copy have identical members but different zip container bytes (hence different whole-file digests); keep PyPI's as the pin.

**Files to create/change.** `.github/workflows/backend-bundle.yml` (`pin_file` input, PR-3), `tools/build_backend_bundle.py` (print wheel `Requires-Dist` for pins), `tests/test_backend_bundle_workflow.py`, `tests/test_backend_pin.py`.

**Contract/schema.** `--pin` already exists; the workflow input is new and path-validated.

**Red tests.** `test_pin_file_input_is_regex_validated_and_not_shell_interpolated`, `test_pip_install_rejects_a_wheel_with_a_wrong_hash` (existing analogue: `test_pip_install_is_hash_locked_wheels_only_and_index_free`), `test_requires_dist_of_each_locked_wheel_is_satisfied_by_the_lock` (new: parse `METADATA`, every `Requires-Dist` without a marker excluding extras must be in the lock).

**Local commands.** `python -m pytest -q tests/test_build_backend_bundle.py tests/test_backend_pin.py -k "pip or wheel or pin"`.

**CI jobs and workflow_dispatch inputs.** build + accept jobs with `pin_file=tools/backend_pin.pyghidra31.json`, `platforms=windows`.

**Expected success output.** `requirements.lock.txt` lines appear only in the failure tail; success is silent; `site-packages` contains `pyghidra-3.0.2.dist-info`.

**Expected failure output.** `error: PT-BUNDLE-PIN-MISMATCH: wheelhouse file jpype1-1.5.2-cp312-cp312-win_amd64.whl does not match its lock hash` or pip: `THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE` wrapped in `PT-BUNDLE-TOOL`.

**Definition of done.** Written decision (3.0.2 retained or 3.1.0 adopted) in the owner-decisions file with the A/B evidence.

**Rollback.** Keep the main pin untouched; the candidate pin file is deleted.

**Risks.** Candidate pin files multiply; restrict to one at a time and delete after the decision.

**Recommended model tier.** T2.

**Effort.** M, 450k tokens, 4 hours; owner acceptance of the decision.

---

### G10. Python embeddable pin: re-verification and fallback

**Goal.** The python.org embeddable zip digest stays tied to a Sigstore verification, with a documented fallback.

**Why it matters for beta.** The private interpreter runs every analysis; python.org publishes no plain checksum file the vendor-file way. The pin is `sigstore-verified` (identity `thomas@python.org`, issuer `https://accounts.google.com`, sigstore 4.5.0, run 38661029764).

**Preconditions.** none.

**Exact method and technique.** (1) Re-run `pin_verify=true` before every release candidate: `gh workflow run backend-bundle.yml --ref <branch> -f pin_verify=true -f sigstore_identity=thomas@python.org -f sigstore_issuer=https://accounts.google.com`. (2) The job installs `sigstore==4.5.0` (exact; 3.6.2 fails `unsupported key type`, 4.4.0 failed: both VERIFIED by the run list and handoff), downloads `python-3.12.10-embed-amd64.zip`, `.sigstore` and `.asc`, runs `python -m sigstore verify identity --bundle ... --cert-identity ... --cert-oidc-issuer ...`, and requires that the identity string is printed on the python.org pages (`identity_named_on_python_org_pages`). (3) Compare `pin-verify.json` `python_windows.sha256` and `size` (11,133,606) with the pin; any difference is a finding (a silent upstream replacement) and blocks release. (4) The fallback (python-build-standalone Windows install_only_stripped, digest from `SHA256SUMS`, `vendor-file`) changes layout (`python/python.exe`, `Lib/site-packages`) and the `._pth` logic: using it requires a code review slice (it is not wired). (5) Rotating sigstore versions is a pin change: update the workflow pin, run, record.

**Files to create/change.** none for re-verification; `docs/runbooks/backend-bundle.md` (G18) gets the commands.

**Contract/schema.** none.

**Red tests.** existing `tests/test_verify_backend_pins.py::test_bad_sigstore_signature_is_reported`, `::test_verify_without_inputs_records_nothing`, `tests/test_backend_bundle_workflow.py::test_pin_verify_job_is_ubuntu_pinned_and_uploads_evidence`. Add `test_sigstore_client_version_is_pinned_exactly_in_the_workflow`.

**Local commands.** `python -m pytest -q tests/test_verify_backend_pins.py -k "sigstore or digest_sources"`.

**CI jobs and workflow_dispatch inputs.** `pin-verify-signatures-and-rebuild`; `pin_verify`, `sigstore_identity`, `sigstore_issuer`, `gpg_fingerprint` (optional secondary check).

**Expected success output.** `"result": "verified"`, `"verified_by": ["sigstore"]`, `"proposed_digest_source": "sigstore-verified"`, `"identity_named_on_python_org_pages": true`.

**Expected failure output.** `FAIL: python-windows signature verification FAILED: sigstore` or `FAIL: the sigstore identity is not named on the fetched python.org pages (supplied by the integrator, not confirmed)`; exit 1.

**Definition of done.** A `pin-verify.json` newer than the last pin edit, with equal digest.

**Rollback.** Revert any pin edit; do not publish on a failed verification.

**Risks.** python.org changes its release-manager table or pages; sigstore trust-root rotation (Rekor key types) breaks old clients: the pin to 4.5.0 may need a bump (test in a separate dispatch).

**Recommended model tier.** T3 for review of any change to this chain; T0 to run.

**Effort.** S, 80k tokens, 30 minutes.

---

### G11. Licence obligations: notices, source offer, THIRD-PARTY

**Goal.** Every shipped component has licence files in the payload, the Ghidriff source and a written offer for the JDK source ship with exact digests, and the notices say what the code enforces.

**Why it matters for beta.** Distribution of GPL-3.0 Ghidriff (separate process), GPL-2.0+CE Temurin and Apache/MIT/PSF components needs complete notices; the owner approved shipping the JDK (2026-10-15, recorded in the pin) and Ghidriff `owner_approved: true`; the legal read of the Ghidriff separate-process position is still an open owner decision (parent plan open question 1, checklist rule 3).

**Preconditions.** G3/G5 payloads available as evidence (`evidence-windows/LICENSES`).

**Exact method and technique.** Full spec in `BUNDLE-licence-notices-and-source-offer-spec.md`. Steps: (1) verify `LICENSES/NOTICE.txt`, `GPL-3.0.txt`, `THIRD-PARTY.json`, `LICENSES/<id>/...` present (the builder enforces via `PT-BUNDLE-LICENSE`); (2) add a standalone verifier `tools/check_bundle_licences.py` that runs on the **extracted release artifact** (not the build tree): every `THIRD-PARTY.json` `license_files` path exists in `manifest.json` `files[]`, every `source.kind==in-bundle` path exists and its sha256 equals the file's, `ghidriff.modified is false`, `process_boundary == separate-process`, SPDX strings equal the pin; (3) fix the offer-digest defect (G2); (4) the JDK offer: URL `https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk-sources_21.0.12.1_1.tar.gz`, sha256 `573057d03584ae793fb7ec9a14c76d826d9187a53efeefd99da47403a5308234`, 115,126,841 bytes (pin, `vendor-file`); keep the "valid for at least three years after the release" wording (VERIFIED in `source_offer_text`) and add the exact release tag; if the owner/legal asks, bundle the 115 MB tarball (cost: +115 MB, mind the budget); (5) GPL boundary statement: Ghidriff is started only as `python -I -m ghidriff` (VERIFIED in `backend.py` line 587); add a source-scan test that nothing in `src/patchtrace` or `tools` imports `ghidriff` (VERIFIED absent today by `grep -rnE "^\s*(import|from)\s+ghidriff" src tools`, no match; the test keeps it so); (6) Ghidra `GPL/**` stays stripped (`owner_approved: false`, `shipped: false`).

**Files to create/change.** `tools/check_bundle_licences.py` (new, stdlib), `tests/test_bundle_licences.py` (new), `tools/build_backend_bundle.py` (offer text), `.github/workflows/backend-bundle.yml` (call the verifier in the acceptance jobs, PR-3).

**Contract/schema.** none new (reads existing `patchtrace-third-party/1`).

**Red tests.** `test_no_module_under_src_imports_ghidriff`, `test_extracted_bundle_licence_inventory_is_complete`, `test_source_offer_names_the_shipped_digest`, `test_third_party_spdx_equals_the_pin`, `test_ghidra_gpl_dir_absent_from_manifest`.

**Local commands.** `python -m pytest -q tests/test_bundle_licences.py tests/test_build_backend_bundle.py -k "licen or third or notice"`.

**CI jobs and workflow_dispatch inputs.** acceptance jobs call `python tools/check_bundle_licences.py <extracted root>`.

**Expected success output.** `bundle licences ok: 12 components, 0 problems`.

**Expected failure output.** `PT-BUNDLE-LICENSE: licence file(s) not in the payload: ['LICENSES/jpype1/LICENSE']` or `PT-BUNDLE-LICENSE: component ghidriff ships no licence file`.

**Definition of done.** Verifier green on both OS artifacts; owner recorded the legal read (open owner action).

**Rollback.** Remove the workflow call; builder gates remain.

**Risks.** This repository states a policy gate, not legal compliance; do not word notices as legal advice.

**Recommended model tier.** T2 (licence logic), T3 only for the final legal wording review by the owner.

**Effort.** M, 400k tokens, half a day; owner legal read.

---

### G12. Import path in the app: inspector parity and consent text

**Goal.** The importer (Setup > Install offline backend ZIP) refuses every hostile archive on every host, uses the same checks as the builder, and shows complete consent text.

**Why it matters for beta.** This is the only path where untrusted bytes meet a user's disk. Tests exist for most refusals, but one is skipped on Windows, which is where users run it.

**Preconditions.** none.

**Exact method and technique.** Full spec: `BUNDLE-import-inspector-and-consent-spec.md`.
1. Close the Windows gap: add `_reject_raw_central_directory_names(zf)` to `inspect_offline_bundle` (port of `build_backend_bundle._reject_raw_backslash_names`): parse the central directory with `struct` (`PK\x01\x02`, offsets 28/30/32 name/extra/comment lengths, name at 46) and refuse any raw name containing `\`, a NUL, a leading `/`, or bytes that are not valid UTF-8 unless general purpose bit 11 says otherwise. Then the fuzz case `backslash-name` can run on Windows too (remove the skip, keep the reason comment) using a raw-bytes builder instead of `ZipInfo`.
2. Keep the existing refusals (VERIFIED in code and `tests/stress/test_fuzz_archives.py`): traversal, absolute, backslash (POSIX hosts), symlink/special, directory entries (`info.is_dir()`), exact duplicates, casefold (`MANIFEST.JSON`, `payload/licenses/notice.txt`) and NFD collisions, reserved device names including `COM¹`, extra unlisted file, dropped notice, compression bombs (`file_size > 1024 and compress_size*200 < file_size`), unsupported methods (bzip2), encrypted members, entry count `> MAX_MEMBERS+1` (60,001), per-file `MAX_FILE` 2 GiB, total `MAX_TOTAL` 8 GiB, manifest `MAX_MANIFEST` 16 MiB, hash and size verification of every file on inspect **and again** during extraction.
3. Consent text (VERIFIED in `ui.py` `_finish_offline_inspection`): shows archive name, runtime id, file count, uncompressed bytes, archive SHA-256, the authenticity warning, instruction to compare against a trusted source and read `LICENSES/NOTICE.txt`, default button **No**, plain text only. Gaps to close: show the licence summary list from `LICENSES/THIRD-PARTY.json` (component, SPDX) read from the verified archive without extracting; show free disk space needed vs available; show the target directory (`%LOCALAPPDATA%\PatchTrace\runtimes\<runtime-id>`); keep the explicit Yes.
4. Per-user private install: `install_offline_bundle` stages in `.install-XXXX` under the same parent, exclusive lock `.runtime-<id>.lock` (O_EXCL), writes `xb` (exclusive create), `_publish_no_replace`, refuses symlinked ancestors, system dirs, relative roots, existing destination; it never overwrites. Linux import is intentionally absent (importer accepts `platforms=('windows',)` default); Linux ships tar.gz extracted by the user. Document that explicitly (G18).
5. Stale comment fix: `backend_bundle.py` says "the importer's 4 MiB cap" while `MAX_MANIFEST` is 16 MiB (VERIFIED), update the comment.

**Files to create/change.** `src/patchtrace/offline_bundle.py`, `src/patchtrace/ui.py` (consent text, small hunk), `src/patchtrace/backend_bundle.py` (comment), `tests/stress/test_fuzz_archives.py`, `tests/test_offline_bundle.py`, `tests/test_ui_offline_consent.py` (new, offscreen).

**Contract/schema.** none (error strings `PT-OFFLINE: ...` unchanged; message additions only).

**Red tests.** `test_raw_backslash_member_is_refused_on_every_host` (raw bytes zip), `test_raw_nul_in_member_name_is_refused`, `test_consent_dialog_lists_components_and_target_directory`, `test_consent_default_button_is_no`, `test_install_never_overwrites_an_existing_runtime` (existing), `test_manifest_cap_constant_documented` (grep the comment).

**Local commands.** `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_offline_bundle.py tests/stress/test_fuzz_archives.py tests/test_ui_offline_consent.py`.

**CI jobs and workflow_dispatch inputs.** the normal Linux/Windows QA gates (not the bundle workflow).

**Expected success output.** pytest green; on Windows the formerly skipped case passes.

**Expected failure output.** `PT-OFFLINE: unsafe archive path`, `PT-OFFLINE: ZIP member exceeds safe size or compression limits`, `PT-OFFLINE: duplicate or Windows-colliding ZIP paths`, `PT-OFFLINE: ZIP entries do not match the exact manifest inventory`, `PT-OFFLINE: archive SHA-256 differs from the trusted expected SHA-256`.

**Definition of done.** Fuzz suite has no Windows-only skip for security cases; consent test green.

**Rollback.** Revert the inspector hunk; behaviour returns to the current baseline.

**Risks.** The central-directory parser must not itself be a vulnerability: bound every length, never allocate by attacker length beyond the file size.

**Recommended model tier.** T3 design review (security invariant), T2 implementation.

**Effort.** M, 600k tokens, 6 hours.

---

### G13. Runtime policy: symbol servers off, bounded analysis, policy file consumed

**Goal.** One authoritative runtime policy, applied by the app, evidenced by the acceptance run.

**Why it matters for beta.** The offline claim depends on Ghidriff not contacting symbol servers; today the policy file is dead data and two timeouts disagree.

**Preconditions.** G5 for end-to-end proof.

**Exact method and technique.** Spec: `BUNDLE-runtime-policy-spec.md`. (1) `config/runtime-policy.json` (`patchtrace-runtime-policy/1`: `ghidriff_args ['--no-symbols']`, `symbol_servers disabled`, `analysis_timeout_s 7200`, `timeout_enforced_by process`) is read once by `bundle_backend_kwargs` after the fast check (it is inside `files[]`, so hash-covered), and mapped to `BackendConfig(timeout_seconds=min(policy, user setting) ...)`; a user may lower but not exceed the policy unless an explicit "allow longer" setting exists. (2) `allow_symbol_downloads` default False already appends `--no-symbols`; add a unit test asserting argv for `bundle=True` always contains `--no-symbols` unless the consent flag is True. (3) Acceptance proof: `no-external-connections` and the blocked positive control; also assert in the acceptance JSON that the `ghidriff` argv recorded contains `--no-symbols`. (4) Heap floor (research row L-03): refuse to start with less than 4 GiB RAM available with a clear message; add `-XX:+CrashOnOutOfMemoryError`.

**Files to create/change.** `src/patchtrace/backend_bundle.py` (`bundle_backend_kwargs`), `src/patchtrace/backend.py` (heap floor message; check PR #67 first), `tools/build_backend_bundle.py` (policy writer unchanged), `tests/test_backend_bundle.py`, `tests/test_backend_bundle_env.py`.

**Contract/schema.** `runtime-policy.json` `patchtrace-runtime-policy/1` documented as a contract in the spec; consumers must ignore unknown keys.

**Red tests.** `test_bundle_kwargs_apply_the_policy_timeout`, `test_policy_file_with_unknown_symbol_servers_value_is_refused`, `test_bundle_argv_always_has_no_symbols_without_consent`, `test_policy_timeout_cannot_be_raised_by_a_setting_without_explicit_allow`.

**Local commands.** `python -m pytest -q tests/test_backend_bundle.py tests/test_backend_bundle_env.py`.

**CI jobs and workflow_dispatch inputs.** acceptance jobs; no new input.

**Expected success output.** Acceptance JSON step `ghidriff-compare` detail includes `results=[...]` and `no-external-connections` `polls=<n>; seen=[]`.

**Expected failure output.** `PT-BACKEND: bundle runtime policy is unreadable or unsupported`, `no-external-connections ... seen=['93.184.216.34:443']`.

**Definition of done.** Policy file consumed and tested; acceptance run shows zero connections.

**Rollback.** Ignore the file (fall back to the constants).

**Risks.** Policy drift between builder constants and app expectations: share one constant module.

**Recommended model tier.** T2.

**Effort.** M, 450k tokens, 4 hours.

---

### G14. Pin upgrade procedure and drift schedule

**Goal.** A written, tool-assisted way to bump any pin without trust on first use, plus an optional weekly drift check.

**Why it matters for beta.** Ghidra 12.0.4 stays through beta (owner decision O3), but JDK patch releases, PyPI wheels and python.org change; every bump must be re-verified.

**Preconditions.** G2 (digest chain settled).

**Exact method and technique.** Procedure in `BUNDLE-pin-digest-and-upgrade-spec.md` section 7. Per component class: vendor-file (Adoptium `.sha256.txt`, python-build-standalone `SHA256SUMS`): fetch the digest file over TLS, download the asset, hash, compare, record both URLs; vendor-listing (Ghidra release page digest + local re-hash); pypi-json (PyPI JSON `urls[].digests.sha256`, plus `Requires-Dist` check); sigstore-verified / gpg-verified (G10); git-rebuilt (G2). Always: `python tools/check_backend_pin.py` and `--release`, then `pytest tests/test_backend_pin.py`, then a `platforms=both` dispatch, then owner approval. Add `tools/backend_pin_bump.py --component <name> --version <v> [--apply]` that **only prints** a proposed JSON patch with sources unless `--apply` and never writes a digest it did not obtain from the declared source. Drift schedule: add `schedule: cron` (weekly, build + acceptance, `publish` forced false) only after G3 and G5 are stable; the workflow header comment says there is none today (VERIFIED); needs the owner's cost decision (parent plan open question 8, default yes).

**Files to create/change.** `tools/backend_pin_bump.py` (new), `tests/test_backend_pin_bump.py` (new), `.github/workflows/backend-bundle.yml` (schedule, PR-3), `docs/runbooks/backend-bundle.md` (G18).

**Contract/schema.** none (reads/writes the existing pin schema).

**Red tests.** `test_bump_refuses_a_digest_without_a_declared_source`, `test_bump_prints_a_patch_and_writes_nothing_without_apply`, `test_bump_rejects_http_urls`, `test_schedule_trigger_never_publishes` (workflow test: `publish` false when `github.event_name == 'schedule'`).

**Local commands.** `python tools/backend_pin_bump.py --component jdk-linux --version 21.0.13+1` (prints the patch); `python tools/check_backend_pin.py --release`.

**CI jobs and workflow_dispatch inputs.** schedule trigger; `pin_report_only` already prints digests of placeholders only.

**Expected success output.** `proposed patch for components.jdk-linux (digest_source vendor-file) ... NOT applied`.

**Expected failure output.** `FAIL: components.jdk-linux: digest file https://.../OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_1.tar.gz.sha256.txt not reachable`; `FAIL: downloaded sha256 differs from the vendor digest file`.

**Definition of done.** Runbook section plus tool merged; first dry bump rehearsed on JDK patch version.

**Rollback.** Delete the tool; manual procedure in the runbook still works.

**Risks.** A bump tool that writes digests invites trust on first use; keep it print-only by default and test it.

**Recommended model tier.** T2 implement, T3 review (supply chain).

**Effort.** M, 500k tokens, 5 hours; owner decision on the schedule.

---

### G15. Reproducibility: double build and compare

**Goal.** Know and bound what is byte-reproducible and fail loudly on unexpected drift.

**Why it matters for beta.** A bundle that cannot be rebuilt identically cannot be audited; today only the manifest and importer-inventory are deterministic.

**Preconditions.** G3/G5 green.

**Exact method and technique.** Spec: `BUNDLE-reproducibility-spec.md`. (1) Set `SOURCE_DATE_EPOCH` in the workflow to the commit time (`git log -1 --format=%ct`) for build jobs; the builder already uses it for `built_at` and defaults to 315532800 for pip. (2) Define reproducible layers: pinned downloads (hash), wheels built from sdist (set `SOURCE_DATE_EPOCH`; compare), `manifest.json` (sorted, compact JSON; file hashes), `THIRD-PARTY.json` (sorted; `built_at` from the epoch). The importer ZIP uses fixed mtimes (1980-01-01), sorted members, fixed `external_attr`, but `zlib` level 6 output can differ across zlib builds; the full zip (`make_archive`) and tar.gz are not normalised. (3) Add a job `repro-check` (ubuntu, after builds) that rebuilds the payload a second time in a fresh directory and compares `manifest.json` bytes and the sorted list of `(path, sha256)`: they must be equal; archives are compared only by their decompressed member lists, not by their own digests. (4) Normalise the full archives: Windows zip via a writer with sorted entries and `date_time` from the epoch; Linux tar via `filter` setting `mtime` to the epoch and PAX/GNU format fixed. (5) Record `.pyc` determinism: `compileall --invalidation-mode unchecked-hash` + `PYTHONDONTWRITEBYTECODE`.

**Files to create/change.** `.github/workflows/backend-bundle.yml` (PR-3), `tools/build_linux.py` (`tar_filter` mtime), `tools/build_windows.py` (zip writer), `tools/build_backend_bundle.py` (built_at), `tests/test_build_full_variants.py` (extend `test_tar_gz_modes_owners_and_determinism`), `tests/test_build_backend_bundle.py`.

**Contract/schema.** `build-provenance.json` keeps `built_at`; add `source_date_epoch`.

**Red tests.** `test_full_zip_is_byte_identical_for_two_builds_of_the_same_tree`, `test_tar_gz_member_mtimes_equal_source_date_epoch`, `test_two_payload_builds_have_equal_manifest_bytes` (fake components), `test_built_at_comes_from_source_date_epoch`.

**Local commands.** `python -m pytest -q tests/test_build_full_variants.py tests/test_build_backend_bundle.py -k "determin or repro or epoch"`.

**CI jobs and workflow_dispatch inputs.** new job `repro-check`; no new input.

**Expected success output.** `reproducible: manifest.json identical (sha256 <x>), 41230 files compared`.

**Expected failure output.** `PT-BUNDLE-REPRO: manifest.json differs between builds: payload/python/Lib/site-packages/ghidriff/__pycache__/... sha256 <a> vs <b>`.

**Definition of done.** Job green on both OS; document what is not reproducible (PyInstaller output, zlib-dependent archive bytes).

**Rollback.** Remove the job.

**Risks.** PyInstaller output is not reproducible; do not claim it.

**Recommended model tier.** T2.

**Effort.** M, 500k tokens, 5 hours.

---

### G16. First prerelease publication

**Goal.** A prerelease (never final, never draft) carrying exactly the accepted assets.

**Why it matters for beta.** Testers need a download.

**Preconditions.** G3, G5 green on the same commit; `python tools/check_backend_pin.py --release` exit 0 **without** `--allow-unapproved-licenses`; owner confirms the Ghidriff/JDK answer for prerelease (non-final is allowed by the checklist; final needs owner say-so).

**Exact method and technique.** Dispatch `gh workflow run backend-bundle.yml --ref <branch> -f platforms=both -f version=0.1.0 -f publish_prerelease=true`. Tag is `v0.1.0-bundle.<run_number>`. Job `publish-prerelease-assets` has `permissions: contents: write`, runs only if `needs.pin.outputs.publish == 'true'` and each selected platform's acceptance job succeeded; it creates `gh release create "$TAG" --prerelease --target "$TARGET_SHA"`, refuses an existing release that is not `true,false` for `isPrerelease,isDraft`, uploads `release/*` with `--clobber`, and compares remote asset names. Verify afterwards: `gh release view <tag> --json isPrerelease,isDraft,assets` and `sha256sum -c` for each downloaded sidecar. Asset names (exact): `PatchTrace-0.1.0-windows-x64-full.zip(.sha256)`, `PatchTrace-0.1.0-linux-x86_64-full.tar.gz(.sha256)`, `PatchTrace-0.1.0-backend-windows-amd64.zip(.sha256)` (or `.001`... parts), `ghidriff-4f5d895-source.tar.gz(.sha256)`, `THIRD-PARTY.json`, `THIRD-PARTY-linux.json`. Add the sidecar check for the source tarball and importer zip in the workflow (today only the two full archives are checked, VERIFIED).

**Files to create/change.** `.github/workflows/backend-bundle.yml` (sidecar checks, PR-3).

**Contract/schema.** none.

**Red tests.** `test_every_release_asset_with_a_sidecar_is_checked_in_ci` (workflow text test), existing `test_publish_is_prerelease_only_and_fails_loudly`, `test_publish_requires_explicit_input_never_tag_alone`.

**Local commands.** `python -m pytest -q tests/test_backend_bundle_workflow.py`.

**CI jobs and workflow_dispatch inputs.** all jobs; `publish_prerelease=true`.

**Expected success output.** `Attached 12 assets to prerelease v0.1.0-bundle.11`; `gh release view` shows `"isPrerelease": true, "isDraft": false`.

**Expected failure output.** `::error::could not create prerelease v0.1.0-bundle.11; the workflow token lacks contents write permission or the tag is invalid. Nothing was published.` Report "build green, release not published"; do not retry in a loop or use another credential (checklist rule 4).

**Definition of done.** Release exists, checks above pass, release notes state unsigned/SmartScreen/Linux experimental/open gates.

**Rollback.** `gh release delete <tag> --cleanup-tag` only on the owner's request.

**Risks.** Token permission (403); asset limit; accidental promotion to final by a person.

**Recommended model tier.** T0 to dispatch and verify; T1 for workflow edits. Release creation by anything but this job is owner-only.

**Effort.** S, 120k tokens, 2 hours.

---

### G17. BinDiff pin provisioning (separate payload)

**Goal.** Keep BinDiff out of this bundle; finish its own pin verification.

**Why it matters for beta.** The unified engine's oracle gate G-U3 is blocked on a verified BinDiff pin (`tools/bindiff_pin.json` has `verified: false`).

**Preconditions.** Network not behind the research egress proxy; owner or a reviewed dispatch job.

**Exact method and technique.** Follow `docs/runbooks/bindiff-pin.md` (VERIFIED to exist): re-hash `bindiff_8_amd64.deb`, `.deb.asc`, `bindiff8.msi` from `https://github.com/google/bindiff/releases/download/v8/`; verify the detached signature from two independent key channels (issuer key id `4EB27DB2A3B88B8B`); only then set `verified` and `signature.signature_verified_by`; run `python -m tools.unified.bindiff_pin verify --require-verified`. Provisioning (`tools/provision_bindiff.py`) downloads only from `https://github.com/google/bindiff/releases/download/`, verifies size and SHA-256 against the pin, extracts without installing (stdlib `ar` + `tar`; Windows `msiexec /a`, advisory). It never executes BinDiff and is not part of `backend-bundle.yml`.

**Files to create/change.** `tools/bindiff_pin.json` (by the person running the runbook), nothing else.

**Contract/schema.** `bindiff-pin/1` unchanged.

**Red tests.** existing `tools/unified/bindiff_pin.py` tests; none new.

**Local commands.** see runbook; `python tools/provision_bindiff.py --os linux --cache <dir> --dest <dir>` (CI-only; needs network).

**CI jobs and workflow_dispatch inputs.** `.github/workflows/live-bindiff.yml` (VERIFIED present); not `backend-bundle.yml`.

**Expected success output.** `bindiff pin verified`; provisioning status `ok` JSON under `build/live-status`.

**Expected failure output.** `blocked (pin-missing)` exit 0; `failed` exit 1 for integrity failures; a digest mismatch is a finding, not an edit.

**Definition of done.** `verified: true` with a named verifier recorded by the owner; `docs/qa.md` row updated.

**Rollback.** Revert the pin edit.

**Risks.** Upstream replaces the release asset; trust-on-first-use values must not be copied from any document.

**Recommended model tier.** T1 (docs/commands), owner for the verification.

**Effort.** S, 100k tokens, 1 hour; owner/network.

---

### G18. Docs slice B9, QA rows, handoff refresh

**Goal.** User and QA documents match reality, each claim with a run link.

**Why it matters for beta.** `docs/qa.md` has no BUNDLE rows; `docs/windows.md` has no full-bundle text (handoff R6); the handoff itself is stale on run #9 acceptance.

**Preconditions.** G3/G5 run links.

**Exact method and technique.** Append-only blocks under unique headings `### [B9:...]`: `docs/windows.md` (download, verify sidecar, Properties > Unblock or `Unblock-File`, extract to a short path, read-only tree, where per-user data lives `%LOCALAPPDATA%\PatchTrace\work`, importer ZIP steps, parts join), `docs/linux.md` (tar.gz, experimental), `docs/qa.md` rows BUNDLE-1..7, `tasks/todo.md` link, SPEC-06 amendment (full download layout), `tools/milestone_notes.py` preamble. Refresh `docs/handoff/backend-bundle.md` section 1 (run #9 acceptance FAILED with the quoted line; run #10 Linux failed; B7 not yet exercised). Never write "air-gapped" without the acceptance run link. `AGENTS.md` line "Ghidra/Java/Ghidriff remain external" is a policy file: owner approval first.

**Files to create/change.** `docs/windows.md`, `docs/linux.md`, `docs/qa.md`, `tasks/todo.md`, `docs/specs/offline-backend-installer.md` (amendment), `tools/milestone_notes.py`, `docs/handoff/backend-bundle.md`, `docs/runbooks/backend-bundle.md`.

**Contract/schema.** none.

**Red tests.** keep `tests/test_spec_registry.py` and docs-scan tests green; registry rows for the new specs (owner of REGISTRY.md adds them: see the proposed rows in the final report).

**Local commands.** `python -m pytest -q tests/test_spec_registry.py`.

**CI jobs and workflow_dispatch inputs.** normal QA.

**Expected success output.** docs tests green.

**Expected failure output.** registry test fails if a new file under `docs/specs/` (excluding `program-e/`) is not cited in `REGISTRY.md`.

**Definition of done.** every BUNDLE-n row has a link or the text BLOCKED external.

**Rollback.** revert docs.

**Risks.** Over-claiming.

**Recommended model tier.** T0.

**Effort.** S, 120k tokens, 2 hours.

---

### G19. Owner clean-machine test (W1 to W9)

**Goal.** Recorded owner results for the exact prerelease zip on a clean Windows 11 machine, network disabled.

**Why it matters for beta.** This is the only gate that proves SmartScreen/Defender/first-run behaviour, DPI and accessibility; automated evidence cannot close it.

**Preconditions.** G16 prerelease; a clean VM or PC.

**Exact method and technique.** `docs/specs/program-e/BUNDLE-release-checklist.md` section 4 (W1 to W9) verbatim: hash check (`Get-FileHash <zip> -Algorithm SHA256` equals the sidecar and release notes), Unblock, extract to `%USERPROFILE%\Downloads\PatchTrace`, SmartScreen note, M01 to M18, network off, "Bundled runtime: ok (fast check)", "Verify bundle files", compare a real pair, first-start duration with Defender, JPype without VC++ redistributable if possible, AV scan with upload consent.

**Files to create/change.** `docs/qa.md` row BUNDLE-7 (owner or worker transcribing the owner's result).

**Contract/schema.** none.

**Red tests.** none.

**Local commands.** PowerShell as in the checklist.

**CI jobs and workflow_dispatch inputs.** none.

**Expected success output.** Pass/fail per W row with Windows build number, date, zip SHA-256.

**Expected failure output.** Recorded as findings; never silenced.

**Definition of done.** W1 to W9 recorded; until then notes say "owner clean-machine test pending" and the item is reported as BLOCKED external, separately from automated evidence.

**Rollback.** n/a.

**Risks.** Unsigned binaries trigger warnings (expected, SignPath application is a parallel owner task).

**Recommended model tier.** owner.

**Effort.** M for the owner, no tokens; owner dependency is total.

---

## 4. Failure atlas

| # | Symptom (real log line where VERIFIED) | Where it appears | Cause | First action | Step |
|---|---|---|---|---|---|
| 1 | `error: PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: rebuilt 7086648 bytes sha256 8f96e687... , pinned 7086648 bytes sha256 613449a2...` (VERIFIED) | `build-linux-full-bundle`, "Build the backend payload" | gzip stored-block layout depends on zlib/CPython; contents identical (VERIFIED) | canonical gzip, G2 | G1, G2 |
| 2 | `PermissionError: [WinError 5] Access is denied` at `base = _run(probe, env, 30)` (VERIFIED) | `accept-windows-no-network-readonly` | deny ACE `(W,D,DC)` includes SYNCHRONIZE (HYPOTHESIS) | specific-rights deny + exec probe | G4 |
| 3 | `No files were found with the provided path: acceptance-windows.json` (VERIFIED) | acceptance upload step | harness crashed before writing evidence | always write partial evidence | G4 |
| 4 | `PT-BUNDLE-MODE: 2 file(s) lost the execute bit (pattern 'jdk/bin/*'): ['jdk/bin/java', 'jdk/bin/javac']` (VERIFIED in handoff 07 section 3.4, fixed `0268517`) | `tests/test_build_backend_bundle.py::*[linux]` on Windows | modes read from NTFS | treat `bin/` as executable when `os.name == 'nt'` | G3/G5 |
| 5 | `unsupported key type` from sigstore 3.6.2; 4.4.0 run 38661022664 failed; 4.5.0 passes | `pin-verify-signatures-and-rebuild` | Rekor key type unsupported by older clients | keep `sigstore==4.5.0` exact | G10 |
| 6 | invalid workflow YAML from an unquoted `pip install 'sigstore==...'` | workflow parse | quoting | keep the quoted form (test exists) | G10 |
| 7 | python.org page text arrives as raw gzip | `pin_verify` log | server ignores identity encoding | `_fetch` decodes gzip (PR #55) | G10 |
| 8 | `DID NOT RAISE OfflineBundleError` for `backslash-name` on Windows (VERIFIED, handoff 07 section 3.4) | `tests/stress/test_fuzz_archives.py` | `zipfile` rewrites `os.sep` | central-directory check | G12 |
| 9 | `PT-BUNDLE-STRIP: strip rules removed everything matching keep pattern 'licenses/**'` | build | bad strip glob | fix glob; add protected list | G7 |
| 10 | `PT-BUNDLE-JLINK: jlink produced no runtime image (lib/modules is missing)` or a Java `NoClassDefFoundError` at selftest | build / acceptance | missing module or jlink failure | jdeps check, add module | G8 |
| 11 | `PT-BUNDLE-PATH-LENGTH` / `PT-BUNDLE-PATH` (`windows-reserved-device-name`, `trailing-space-or-dot`) | build `gate_paths` | vendor file name unsafe on NTFS | `build_backend_bundle.py check <tree>` and strip/rename after review | G5 |
| 12 | `PT-BUNDLE-SIZE-LIMIT: ... is N bytes, above the 2040109465 byte release-asset limit` | build | archive over 1.9 GiB | split importer zip; full falls back to lite + backend pair | G6 |
| 13 | `PT-BUNDLE-LICENSE: owner approval pending for ...; a release build is refused` | publish path with `--release` | `owner_approved` false | owner decision recorded in pin | G11, G16 |
| 14 | `PT-BUNDLE-LICENSE: payload ships Ghidra GPL/ files ... but license_policy ghidra-GPL-dir is not shipped and owner-approved` | gate | `GPL/**` kept | keep stripped | G11 |
| 15 | `could not create prerelease ...; the workflow token lacks contents write permission` | `publish-prerelease-assets` | token scope | report "build green, release not published"; no retry loop | G16 |
| 16 | `PT-BUNDLE-WHEEL-MISMATCH: ghidriff-...whl: ghidriff/x.py differs from the source tarball` | build | wheel build modified sources (e.g. line endings) | check `core.autocrlf`, build backend | G9 |
| 17 | `PT-BUNDLE-PYTHON-MISMATCH: builder runs Python 3.13 but the bundle is Python 3.12.10` | local build | bytecode would not load | use 3.12 or `--no-compile` | G5 |
| 18 | `denial-ineffective` / `invalid-no-baseline` in the acceptance JSON | acceptance | namespace or firewall not applied, or no baseline route | change control target; fix denial | G3, G4 |
| 19 | sidecar of the source tarball does not match the shipped bytes (not yet observed in CI; found by reading) | release assets | fallback path writes the pinned digest | G2 gate `PT-BUNDLE-SOURCE-DIGEST` | G2 |
| 20 | `PT-BUNDLE-MANIFEST-SIZE: manifest.json would be about N bytes, above the 16777216 byte importer cap` | build | too many files | strip more or reduce | G6 |

## 5. Owner-only actions

1. Approve the re-pin of the Ghidriff source tarball digest (G2) after reading `pin-verify.json`.
2. Decide FID databases (G7): ship without (recommended, current behaviour) or with.
3. Accept or reject PyGhidra 3.1.0 (G9) after the A/B evidence.
4. Legal read of shipping unmodified GPL-3.0 Ghidriff as a separate process with source tarball and offer, and of the JDK written source offer (parent plan open questions 1 and 2); required before any non-prerelease.
5. Approve the weekly drift schedule and its runner cost (G14).
6. Confirm the workflow token can create releases (G16) and that artifacts may be published.
7. Run the clean-machine Windows test W1 to W9 (G19); apply to SignPath Foundation (checklist section 5; owner decision 9 of 2026-10-15); decide the BinDiff pin verification (G17).
8. Any final (non-prerelease) release, signing, and the `AGENTS.md` policy line change.

Everything else in this plan is automatable. Automated evidence and owner/external acceptance are reported in separate lists.

## 6. Definition of "green beta" for the backend bundle

Automated: G3 (Linux build + both acceptance legs) and G5 (Windows build + acceptance) green on one commit; G2 sidecar/offer gate in place; G12 and G13 merged; G16 prerelease published by the workflow with verified sidecars; docs (G18) carry run links. External, reported separately: G19 W1 to W9 recorded; owner legal read; signing application. Not claimed: reproducible archives (G15 bounds this), signed binaries, "air-gapped" wording without the acceptance link.
