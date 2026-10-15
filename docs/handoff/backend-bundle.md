# Handoff: BACKEND / BUNDLE (zero-download full build)

Written 2026-10-15 from branch `claude/instance-d-gui` at `b853996` (PR #64), for an engineer or Claude session with no chat history. Facts come from the repository, `git log`, and GitHub Actions run records read on 2026-10-15. Anything not checked is marked UNVERIFIED. Companion spec: `docs/specs/program-e/BUNDLE-release-checklist.md` (Windows alpha acceptance and release rules). Parent plan: `docs/specs/program-e/BUNDLE-integration-plan.md`.

Cost rule (CLAUDE.md): sonnet is enough for everything below; opus only for the named hard blockers. Never publish a final release; never silence a failing gate.

## 1. Purpose and current state

Goal: `PatchTrace-<ver>-windows-x64-full.zip` and `PatchTrace-<ver>-linux-x86_64-full.tar.gz`: the lite app plus `backend/` (private Python 3.12.10, Temurin JDK 21.0.12.1+1, Ghidra 12.0.4, pyghidra 3.0.2, JPype1 1.5.2, unmodified GPL-3.0 Ghidriff at commit `4f5d895`), so a user extracts and compares two PE builds with nothing to install and no network. All downloads are hash-pinned in `tools/backend_pin.json`.

State in one paragraph. All code slices of the plan (B1 to B8, B3b, B5a, B5b, B7) are merged. Pins are fully resolved (no placeholders). The Windows full build ran green once on GitHub (run 38676664372, job `build-windows-full-bundle`, 2026-10-15; artifact `bundle-windows-assets` 1,125,774,418 bytes). The Linux full build failed in the same run at the Ghidriff tarball check (`PT-BUNDLE-PIN-MISMATCH`). Windows acceptance (`accept-windows-no-network-readonly`) was still queued when read; its result is UNVERIFIED. No prerelease has ever been published. No owner clean-machine test has happened. Nothing is signed.

Commands that prove the local part (run on 2026-10-15 in this worktree; results in brackets):

```
python tools/check_backend_pin.py --release                      # [backend pin ok, exit 0]
python -m pytest -q tests/test_backend_pin.py tests/test_verify_backend_pins.py tests/test_build_backend_bundle.py \
  tests/test_build_backend_bundle_check.py tests/test_backend_bundle.py tests/test_backend_bundle_env.py \
  tests/test_backend_bundle_workflow.py tests/test_bundle_acceptance_unit.py tests/test_build_full_variants.py \
  tests/test_offline_bundle.py tests/test_offline_bundle_linux.py tests/test_runtime_discovery_bundle.py \
  tests/test_ui_bundle_setup.py                                   # [518 passed, 2 skipped]
```

GitHub evidence (read through the API on 2026-10-15; re-read before relying on it). Workflow file `.github/workflows/backend-bundle.yml`, runs:

| run | what | result |
|---|---|---|
| 38622292405 (#1, main) | dispatch at the time of PR #48 | success (content UNVERIFIED) |
| 38650022556, 38655055924, 38660818187, 38660893572 (#2 to #5, main) | `pin_verify` attempts | the `pin-verify-signatures-and-rebuild` job failed (run #5 verified by job list); reasons from commit messages: sigstore 3.6.2 rejected python.org bundles, "unsupported key type" |
| 38661029764 (#7, instance-d-gui) | `pin_verify=true`, sigstore 4.5.0 | success; produced the two verified pins |
| 38676664372 (#9, instance-d-gui, `4f56b9f`) | full build, both platforms | Windows build success; Linux build failed (tarball mismatch); Windows acceptance queued when read; Linux acceptance skipped |
| 38686279359 (#10, instance-d-gui, `9fbeba9`) | dispatch | pending when read; inputs and result UNVERIFIED |

Run #9 predates commit `db64e04` (the member-digest diagnostic), so its log has no `describe_tarball` lines. `db64e04` is in the current branch.

In-flight branches (names only; check each before touching): `origin/claude/instance-d-gui` (integration, PR #64), `origin/main` (at `00db4c9` when read), `origin/claude/instance-c-research` (PR #66, label training; also carries workflow fix history), `origin/claude/instance-b-features`, `origin/claude/bundle-license-gate` (merged as #65), `origin/chatgpt/deferred-audit-fixes-1` (PR #67, "Ghidriff integrity, isolated launches and consent": may touch `backend.py`; read before editing it), other `origin/chatgpt/*` drafts (#68 to #72, not bundle related). Do not overwrite any of them.

## 2. What is DONE

| Item | Where | Evidence |
|---|---|---|
| Pin file, schema `patchtrace-backend-pin/1`, every digest traced (`vendor-file`, `vendor-listing`, `pypi-json`, `sigstore-verified`, `git-rebuilt`), licence policy, strip lists | `tools/backend_pin.json`, `tools/check_backend_pin.py` | `tests/test_backend_pin.py`; `check_backend_pin.py --release` exit 0 |
| python.org embeddable zip verified by Sigstore (identity `thomas@python.org`, issuer `https://accounts.google.com`, sigstore 4.5.0) | `tools/verify_backend_pins.py verify`, workflow input `pin_verify` | run 38661029764; note in the pin file |
| Ghidriff source tarball rebuilt from the pinned commit (deterministic recipe), compared member by member with the GitHub archive (117 identical), rebuilt twice identical | `tools/verify_backend_pins.py` (`build_tarball`, `compare_tarballs`) | same run; `tests/test_verify_backend_pins.py` |
| Builder: fetch+verify, extract with Windows path policy, hash-locked `pip install --target`, wheel built from the source tarball and byte-compared, strips, bytecode precompile, notices, `THIRD-PARTY.json`, size/path/mode gates, split | `tools/build_backend_bundle.py` (`check` and `build`) | `tests/test_build_backend_bundle*.py` (fake components, no network); real Windows build in run #9 |
| Payload validation before attach and licence policy (Ghidra `GPL/**` stripped by default; JDK owner approval 2026-10-15) | `gate_paths`, `gate_pin`, `license_policy` | PR #65; `tests/test_backend_pin.py` |
| Full variants of the app builders | `tools/build_windows.py --full`, `tools/build_linux.py --full` (`--backend-payload DIR --version V`) | `tests/test_build_full_variants.py`; run #9 Windows |
| Manifest Linux platform, public `validate_manifest` | `src/patchtrace/offline_bundle.py` | `tests/test_offline_bundle_linux.py` |
| Runtime module: find, fast/full verify, backend kwargs | `src/patchtrace/backend_bundle.py` | `tests/test_backend_bundle.py` |
| Bundle mode in backend (`BackendConfig.bundle`: `python -I -X utf8 -m ghidriff`, restricted env, `JAVA_HOME_OVERRIDE`, scratch outside `backend/`, symbol downloads off) | `src/patchtrace/backend.py` | `tests/test_backend_bundle_env.py` |
| Discovery, `patchtrace backend status\|verify [--full]\|selftest\|diagnose`, Setup row | `runtime_discovery.py`, `backend_cli.py`, `ui_bundle_setup.py` | `tests/test_runtime_discovery_bundle.py`, `tests/test_ui_bundle_setup.py` |
| Acceptance harness: env scrub, read-only tree, tree digest before/after, positive-control socket probe, Linux `unshare --net`, Windows firewall rules, connection sampling | `tools/bundle_acceptance.py` | `tests/test_bundle_acceptance_unit.py`; real run only in CI |
| Workflow with prerelease-only publication | `.github/workflows/backend-bundle.yml` | `tests/test_backend_bundle_workflow.py` |
| Research on headless Ghidra, sizes, jlink, signing | `docs/research/ghidra-headless-large-pe.md`, `docs/research/windows-signing-options.md` | notes only; measurements are Linux-only |

## 3. What REMAINS (ordered)

Common commands: dispatch with `gh workflow run backend-bundle.yml --ref <branch> -f platforms=<both|windows|linux> -f version=<x.y.z> [-f publish_prerelease=true] [-f pin_report_only=true] [-f pin_verify=true -f sigstore_identity=... -f sigstore_issuer=... -f gpg_fingerprint=...]`. Input names are exactly those in `on.workflow_dispatch.inputs` of the workflow file; `gh workflow run -f` is the standard gh syntax. Read results with `gh run view <id> --log-failed` or the Actions web page.

### R1. Fix the Ghidriff tarball digest mismatch on the Linux runner
- Goal: `build-linux-full-bundle` passes the `ghidriff.source_tarball` check with the existing pin, or the pin/recipe changes so every runner agrees.
- Facts: run #9 `build-linux-full-bundle` (ubuntu-22.04, Python 3.12.15, git 2.55.0 as printed by the post-job step) failed with `rebuilt 7086648 bytes sha256 8f96e687c72ae191def725e1753e3701be74bb80d30f5a29f7294717322802bc, pinned 7086648 bytes sha256 613449a2743e50a11c96b8a6cf6856095816cfece77a021c49cac6e4fe4fe87f`. Same size, different digest. The Windows job in the same run passed the same check, and the pin was recorded from `pin_verify` on `ubuntu-latest` where two rebuilds were identical. So the recipe is stable per environment but not across all of them. The sandbox rebuild (the earlier observation that started this item) also differed; its digest is not recorded in the repo (UNVERIFIED).
- Why equal size matters: a different gzip block split or different content length would change the size. Equal size points at metadata or ordering inside the tar (mode, mtime, uid, member order, type flag, long-name handling), at gzip header bytes, or at a same-length content difference. This is a hypothesis, not a finding (UNVERIFIED).
- Files: none to change for the investigation. Fix options touch `tools/verify_backend_pins.py` (`build_tarball`, `_normalised_tar`), `tools/build_backend_bundle.py` (`rebuild_ghidriff_tarball`), `tools/backend_pin.json`, `tests/test_verify_backend_pins.py`, `tests/test_build_backend_bundle.py`.
- HOW, investigation (no code change):
  1. Make sure the branch you dispatch from contains `db64e04` (merge `claude/instance-d-gui` first). Since that commit the builder appends `describe_tarball(path)` output to the `PT-BUNDLE-PIN-MISMATCH` message: first line `<git --version>; python <version>`, then one line per top-level directory: `ghidriff-4f5d895/<name> n=<member count> <16 hex of sha256 over name, mode, size, type, content hash>`.
  2. Dispatch `-f platforms=linux` on that branch. The build step fails within seconds; read the lines in the job log (step "Build the backend payload").
  3. Get the reference lines from a known-good environment: `pin_verify` does not call `describe_tarball`, so run locally (needs network to github.com): `python tools/verify_backend_pins.py rebuild --repo https://github.com/clearbluejar/ghidriff --commit 4f5d895fcbb1eacd65efd81145922c15bb7e741d --out <dir>/ghidriff-source.tar.gz`, then print `describe_tarball` from a `python -I -c` one-liner that loads `tools/verify_backend_pins.py` by path. Check that its sha256 equals the pin (`613449a2...`). If it does not, the local machine shows the same bug and the investigation can continue offline.
  4. Compare line by line. A differing top-level directory narrows the cause. If every directory line is equal, the difference is in tar framing or the gzip header: gunzip both and `cmp -l | head`, and compare the first 10 bytes of each file.
  5. Check the environment differences first: git version, zlib version (`python -c "import zlib; print(zlib.ZLIB_VERSION)"`; level-0 gzip output depends on stored-block splitting), and `git archive` on a shallow clone (`fetch_commit` uses `--depth 1`).
- Fix options, in preferred order:
  1. Single producer (safest, no recipe guess): one job on ubuntu-latest (the environment that produced the pin) rebuilds the tarball, checks it against the pin and uploads it as an artifact; `bld-win` and `bld-lin` download it instead of rebuilding. Changes `.github/workflows/backend-bundle.yml` plus a builder argument that accepts a prebuilt tarball (red test first). Cost: one more job, one workflow PR.
  2. Make the recipe independent of git and zlib: write the tar from `git ls-tree -r -z` and `git cat-file --batch` in Python (no `git archive`), and write gzip with a hand-made stored-block writer (fixed 65535-byte blocks). Then rerun `pin_verify` for the new digest and update the pin with owner approval.
  3. Pin the uncompressed tar digest or the git tree hash (`tree` is in `pin-verify.json`) and treat the `.gz` as derived. Additive pin field plus `check_backend_pin.py` rule changes.
  4. Last resort: per-platform digests. Not recommended; the source offer must name one file.
- Tests first: option 2: `test_rebuild_independent_of_gzip_stored_block_size` (monkeypatch the chunk size; digest unchanged). Option 1: `test_build_accepts_prebuilt_source_tarball_only_if_digest_matches` and `test_build_rejects_prebuilt_tarball_with_wrong_digest`. Keep green: `tests/test_verify_backend_pins.py`, `tests/test_build_backend_bundle.py`, `tests/test_backend_pin.py`.
- Local commands: the pytest list in section 1.
- CI proof: workflow `backend-bundle.yml`, dispatch `platforms=linux`, job `build-linux-full-bundle` green through "Lite build smoke then full build".
- Acceptance gate: Linux build green with the pin unchanged (options 1, 2 with same digest) or with a new pin recorded from a `pin_verify` run and approved by the owner.
- Size: M. Tier: sonnet; opus only if two attempts at option 2 still disagree across runners. Depends on: nothing.

### R2. Confirm Windows full build plus acceptance on a clean run
- Goal: `build-windows-full-bundle` and `accept-windows-no-network-readonly` both green on one run, `acceptance-windows.json` and `evidence-windows` artifacts present.
- Files: none unless acceptance fails. Suspects: `tools/bundle_acceptance.py` (firewall rule step, `icacls` read-only step), `src/patchtrace/backend.py` bundle env, `strip.ghidra` in the pin (a stripped file that is needed).
- HOW: (1) read the result of run #9 job `accept-windows-no-network-readonly` (id 116261209710); (2) if green, still dispatch once from the final branch state (`-f platforms=windows -f version=0.1.0`); (3) if red, read artifact `acceptance-windows` (`acceptance-windows.json`) first: it names the failing step; fix the smallest cause with a red unit test; for a missing Ghidra file remove that pattern from `strip.ghidra` and rebuild. Do not weaken the positive-control check.
- Tests first: one case in `tests/test_bundle_acceptance_unit.py` per harness bug found.
- CI proof: jobs `build-windows-full-bundle` then `accept-windows-no-network-readonly`.
- Gate: acceptance JSON shows the network probe succeeded before the block and failed after, tree digest equal before/after, `backend selftest` exit 0 with `read_item` found. The run link goes into `docs/qa.md` row BUNDLE-3 (R6).
- Size: S if green, M if not. Tier: sonnet; opus only for a demonstrated Ghidra/JPype headless failure on Windows. Depends on: none.

### R3. Linux full build and acceptance (22.04 and 24.04)
- Goal: both `accept-linux-no-network-readonly` matrix legs green; label Linux experimental until an owner test (plan open question 6).
- Files: `tools/bundle_acceptance.py` (`linux_denial_argv`, `linux_sampler`) and the workflow step "extract to a hostile path". 24.04 restricts unprivileged user namespaces (plan 10.2, UNVERIFIED); the harness uses `sudo unshare --net` plus `setpriv`, check that path first.
- HOW: after R1 dispatch `-f platforms=linux`; read artifacts `acceptance-linux-ubuntu-22.04` and `-24.04`. Fix with unit tests in `tests/test_bundle_acceptance_unit.py`.
- CI proof: jobs `build-linux-full-bundle`, `accept-linux-no-network-readonly (ubuntu-22.04|ubuntu-24.04)`.
- Gate: both legs green. Size: M. Tier: sonnet. Depends on: R1.

### R4. Size and offline improvements (research-backed, each gated by acceptance)
- Goal: smaller assets without changing analysis output.
- Facts: research (`docs/research/ghidra-headless-large-pe.md` section 5; Linux only, one small non-MSVC PE): Ghidra 847 MB as shipped, 394 MB after removing FID databases, golang typeinfo, docs, Extensions, other-OS natives, 234 MB after also removing Jython, BSim, GhidraServer and `Debug`; analysis hashes identical at every step. A jlinked 26-module JDK was 78 MB versus 346 MB with the same output. The pin today strips only `docs/**`, `Extensions/Eclipse/**`, other-OS natives, `GPL/**` (Ghidra) and `lib/src.zip`, `jmods/**` (JDK), and keeps `Ghidra/Debug/**`. The Windows artifact is 1,125,774,418 bytes partly because it holds the full zip, the importer backend zip and the source tarball (payload zipped twice).
- Files: `tools/backend_pin.json` (`strip`), `tools/build_backend_bundle.py` (`expand_strip_patterns`, `strip_tree`; a new jlink stage only if approved), `tests/test_backend_pin.py`, `tests/test_build_backend_bundle.py`.
- HOW, lowest risk first, one change per dispatch so a failure names its cause: (a) add `Ghidra/Features/Jython/**`, `Ghidra/Features/BSim/**`, `Ghidra/Features/GhidraServer/**`, `Ghidra/Features/Base/data/typeinfo/golang/**` to `strip.ghidra`, then move `Ghidra/Debug/**` from `strip.keep` to strip; (b) FID databases (`Ghidra/Features/FunctionID/data/*.fidbf`) only after an owner decision (section 4); (c) jlink stage: run `jdeps -summary` per Ghidra jar, then `jlink --add-modules <list> --strip-debug --no-man-pages --no-header-files --compress=zip-6`, copy `legal/` explicitly; only after R2 is green; a Windows jlink needs the Windows `jmods` (UNVERIFIED); (d) lower the 1.9 GiB `ASSET_LIMIT` gate only after real sizes are known. Never remove `Decompiler`, `PDB`, `Base`, `PyGhidra`, `VersionTracking`, processors, or `jdk.compiler`.
- Tests first: `test_strip_list_never_removes_required_ghidra_parts` (protected paths not matched by any pattern); `test_strip_patterns_expand_per_target`.
- CI proof: `backend-bundle.yml` on both OS, acceptance green after each step.
- Gate: acceptance green; before/after sizes recorded in `docs/qa.md` row BUNDLE-5.
- Size: S per strip step, L for jlink. Tier: sonnet. Depends on: R2 (Windows), R3 (Linux).

### R5. First prerelease publication
- Goal: a PRERELEASE carrying the accepted full assets, created only by the workflow, never final, never draft.
- Files: none. Risk is the token: job `pub` needs `contents: write` and fails with an explicit message if it cannot create the release.
- HOW: after R1 to R3 are green, dispatch `-f platforms=both -f version=0.1.0 -f publish_prerelease=true` on the commit to release. The tag is `v<version>-bundle.<run_number>` (computed in job `pin`). A pushed `v*` tag builds and tests but never publishes. If the release step returns 403, report "build green, release not published"; do not loop.
- Verify: `gh release view <tag> --json isPrerelease,isDraft,assets`; each `.sha256` sidecar matches; asset names match plan 7.7; notes say unsigned and list open gates.
- Gate: `isPrerelease=true`, `isDraft=false`, every uploaded name present (the job also checks this).
- Size: S. Tier: haiku for dispatch and verification; sonnet if the workflow needs a permission change. Depends on: R1 to R3. Anything beyond a prerelease needs owner say-so (section 4).

### R6. Documentation slice B9 (not done)
- Goal: user and QA docs match reality.
- Files: `docs/windows.md` (has no full-bundle text today), `docs/linux.md`, `docs/qa.md` (rows BUNDLE-1 to BUNDLE-7 do not exist), `tasks/todo.md` (link the plan), `docs/specs/offline-backend-installer.md` (amendment per plan 10.1), `tools/milestone_notes.py` preamble (lead with full downloads). `docs/install.md` already has the Unblock step. The `AGENTS.md` line "Ghidra/Java/Ghidriff remain external" is a policy file: owner approval first (section 4).
- HOW: append-only blocks under unique headings `### [B9:...]`; every claim links a run; do not write "air-gapped" without the acceptance run link.
- Tests first: keep `tests/test_spec_registry.py` and the docs-scan tests green.
- Size: S. Tier: haiku. Depends on: R2, R3 for run links.

### R7. Symbol policy end-to-end and research follow-ups (small, optional until R2 shows a need)
- Current state by reading: `allow_symbol_downloads=False` by default and `--no-symbols` in analysis options (`backend.py` around lines 446-454); `backend_cli.py` line 166 forces False for selftest. Not yet shown by a bundle run (UNVERIFIED end to end).
- Items: VC++ redistributable check for JPype on a clean Windows (research question 7; shows up in the owner VM test), heap floor message (research row 1), `-XX:+CrashOnOutOfMemoryError`.
- Size: S each. Tier: sonnet. Depends on: R2.

### R8. Owner-only: Windows VM test and signing application
See section 4 and the checklist spec. Not automatable. Depends on: R5.

## 4. Decisions only the owner can make

| Decision | Recommendation |
|---|---|
| Publish anything that is not a prerelease | Not until R1 to R3 are green, the owner VM test passes (checklist spec section 4) and the Ghidriff GPL-3.0 and JDK source-offer questions (plan open questions 1, 2) have a recorded answer. Until then prerelease only. |
| Ghidriff GPL-3.0 wording and legal view of shipping it as a separate unmodified process with source tarball and offer | Ship as designed (`owner_approved: true` in the pin); owner confirms before the first non-draft release. |
| Temurin JDK shipped (GPL-2.0 with Classpath exception) | Approved 2026-10-15 (`approved_via` in the pin). Keep the written source offer; bundle the source tarball only if legal asks. |
| Ghidra `GPL/` directory | Stay stripped (`owner_approved: false`). |
| FID databases (about 80 MB zipped) | Keep for the first prerelease; remove only after someone shows no benefit on kernel images. |
| jlink-trimmed JDK | After Windows acceptance is green; saves about 270 MB of 350 MB. |
| Weekly pin-drift schedule | The workflow has no `schedule` trigger (header comment says so; plan open question 8 said yes). Add only after R1 to R3 are stable: build only, no publishing. |
| Linux support label | "experimental" until an owner test. |
| Signing provider | Apply to SignPath Foundation now in parallel (free for eligible OSS; certificate publisher is the foundation); stay unsigned for the alpha series; Azure Artifact Signing Basic ($9.99/month) only if the owner is in the US/Canada with an Individual billing account or has an organisation; OV on cloud HSM about $220 to $440/year as the fallback; do not buy EV. Facts are snippet-level, re-check at application time (`docs/research/windows-signing-options.md` sections 7 and 11). |
| Attestation and a `SHA256SUMS` release asset | Approve only after confirming workflow permissions; flagged as a possible 403 on publish. |
| `AGENTS.md` line "Ghidra/Java/Ghidriff remain external" | Amend to "except in the full distribution" when approved. |

## 5. Pitfalls and lessons

- Sigstore client version: sigstore 3.6.2 rejected python.org bundles ("unsupported key type"); 4.4.0 was tried first (run 38661022664 failed); 4.5.0 works. The workflow pins `sigstore==4.5.0`. Do not float it.
- The `pip install 'sigstore==...'` line must stay quoted in the workflow YAML (an earlier revision was invalid YAML).
- python.org pages arrived as raw gzip text; `verify_backend_pins.py` now requests identity encoding and decodes gzip (PR #55). The Sigstore identity and issuer are supplied by the integrator and must appear on the fetched page text, otherwise `verify` records a problem.
- GitHub's archive tarball is not a stable pin; that is why the pin is `git-rebuilt` from the commit. The recipe is deterministic only with `core.autocrlf=false` and the steps in the `verify_backend_pins.py` docstring. R1 is the unresolved cross-runner difference.
- Pin gate: non-publish runs use `check_backend_pin.py --release --allow-unapproved-licenses`; publish runs omit the flag. Both exit 0 today.
- `pin_report_only` and `pin_verify` never build; a tag push builds and accepts but cannot publish (publish needs the dispatch input).
- Windows path rules already enforced: reserved names, trailing dots, case-fold collisions, backslash zip members, a 150-character guard under `backend/` for the 260-character Explorer limit, LF in `_pth`.
- Keep JPype1 1.5.2 exact (pyghidra 3.0.0 pinned it to avoid a Windows crash with 1.6.0; research section 2).
- JDK fallback: the plan said "flip to JDK 25", but Ghidra 12.0.4 documents JDK 21 only (research section 6). If 21 fails, try another 21.0.x patch first.
- `bundle-windows-assets` is uploaded with `compression-level: 0` and holds several files; do not read its size as one release asset's size.
- Tests that count lines in `cli.py` (CLI seam baselines) break when it grows; update the baseline in the same commit.

## 6. Verification checklist before calling the area finished

- [ ] `python tools/check_backend_pin.py --release` exits 0 without `--allow-unapproved-licenses`.
- [ ] The section 1 pytest list passes; the full Linux and Windows CI gates of PR #64 are green.
- [ ] One dispatch run (`platforms=both`) with `build-windows-full-bundle`, `accept-windows-no-network-readonly`, `build-linux-full-bundle` and both `accept-linux-no-network-readonly` legs green; the URL is recorded in `docs/qa.md`.
- [ ] Each acceptance JSON shows the positive control connected before the block and failed after, equal tree digests, `selftest` exit 0 with `read_item`.
- [ ] A prerelease exists (`isPrerelease=true`, `isDraft=false`) with the asset names of plan 7.7 and matching `.sha256` sidecars; notes say unsigned and list open gates.
- [ ] `docs/windows.md`, `docs/linux.md`, `docs/qa.md` rows BUNDLE-1 to BUNDLE-7, `tasks/todo.md`, the SPEC-06 amendment and the notes preamble are updated, every claim with a run link.
- [ ] BUNDLE-7 (owner clean-machine test) is reported as BLOCKED external until the owner records a result; automated evidence is reported separately.
- [ ] No Microsoft binary, PDB or label data committed; no GPL code copied into the repository.

Counts at write time: 8 remaining items (R1 to R8). UNVERIFIED items in this file: 9 (R1 same-size hypothesis; R1 sandbox digest; R1 shallow-clone effect; run #1 content; run #9 Windows acceptance result; run #10 inputs and result; Windows jlink; R7 end-to-end symbol policy; Linux 24.04 namespace behaviour).
