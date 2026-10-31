Warning: truncated output (original token count: 56986)
Total output lines: 941

# QA and audit record

## Current evidence
2026-10-11: source inspection of pinned upstream revisions completed. Linux Qt offscreen desktop self-test starts and displays the synthetic project. Integrated Linux QA: 91 tests passed, 2 Windows-only tests skipped; Ruff and Qt offscreen desktop self-test passed. Domain, transport, worker, schema and UI tests are included. Synthetic fixtures and mocked providers verify wiring and validation, not real matching accuracy or model interpretation correctness.

## Repaired audit defects
- Ghidra rejected `runs/.quarantine-<uuid>/raw` with `Path element starting with '.' is not permitted`. Active and normalization-failed run directories now use `quarantine-<uuid>`. Preflight validates every resolved output ancestor, with an actionable error for dot-prefixed names and excessively long Windows output paths. The fake backend reproduces this exact rejection; native Ghidriff confirmation on Windows and clean-user reinstall remain release checks.
- Artifact storage could escape project roots: pure models and disk paths now reject traversal, absolute/drive paths and symlinks.
- Same-run evidence could be cited against the wrong function match: exact match/function and explicit neighbor associations are enforced.
- Repeated content-addressed contexts could conflict with global uniqueness: identical context/evidence can be shared; conflicting identities rejected.
- Backend module imports could be shadowed by project-local modules: configured trusted runtime cwd and removal of PYTHONPATH/PYTHONHOME.
- Windows process descendants require containment before running: suspended launch, Job Object assignment, kill-on-close then resume; failure terminates suspended child.
- Identical analysis result and failed runs needed separate transactional persistence rather than treating a directory as completed JSON.
- SQLite connections must remain on their creating thread; background project creation closes its connection before GUI reopens.
- Split/merged code view line offsets must map exact evidence lines rather than equal addresses/line numbers.
- Dynamic imported labels use plain text rather than automatic rich text.
- Large import parsing/normalization moved behind prepare/apply worker seam; atomic project changes on GUI thread.
- Ghidra/Python/pyghidra versions and dependency diagnostics are recorded, with unverified Java compatibility visible.
- Missing persisted instruction arrays are displayed as unavailable, never fabricated assembly.

- Unchanged Windows inputs were incorrectly rejected because path and open-handle ctime semantics differ: compare each source consistently, with native ChangeTime protecting against hidden edits.
- Large repetitive code could spend excessive time in line matching: bounded strategies and a disclosed linear fallback now cap the expensive path.
- Failed normalization after native execution needed quarantine and a persisted failed attempt; late cancellation cannot promote output.
- Export preview and actual bytes needed identical option handling and deterministic rendering.
- Optional Qt image/input plugins pulled unused PDF and virtual-keyboard dependencies into the freeze: custom desktop plugin collection now prevents those imports, with an executable-component rejection gate and post-build ZIP inspection.
- Qt wheels lacked redistributed license texts: exact upstream notice sources are vendored; the builder refuses missing required notices and excluded WebEngine/PDF collection.

- Native Ghidra workspace isolation: new regression tests require Ghidriff to receive an external private `--project-location` and `--gzfs-path`, check cleanup on success/failure, and preserve case-owned JSON/logs. Temporary engine workspaces should not be inside synced project directories; new Windows native compatibility must be rerun after this change.

- Ghidriff symbol-server behavior is now opt-in via an explicit saved GUI setting. The backend passes `--no-symbols` by default and records the choice in run provenance. Tests exercise both modes and reject ambiguous types. A passing no-symbols CLI fixture is not proof of OS-enforced network isolation.

- Local runtime discovery is a separate, read-only stdlib module with bounded direct-child scanning and no process execution. Setup prefills only unique existing candidates and preserves analyst-selected paths. This reduces manual path navigation but does not install or validate the full runtime; automated fixture coverage is distinct from real Windows/OneDrive acceptance.

- Native backend failure classifier maps supported error signatures to fixed actionable guidance (JDK mismatch, missing Ghidriff, Ghidra path, heap/disk/permissions), preserving original exit code and sanitized log. Unknown signatures retain the generic inspect-analysis.log message. Regression tests assert no tokens from raw upstream output are echoed.

- Offline bundle importer: strict versioned manifest/ZIP inventory SHA-256 checks, Windows path/type checks, per-user atomic staging/lock with cancellation/rollback, no network or payload execution in the install path, dedicated child-only Java environment. Synthetic payload fixtures verify importer plumbing, not a functional relocatable Ghidriff distribution. Spec-06 full disconnected Windows bundle acceptance remains pending.

## 2026-10-12 delivery session

- Cached-PDB `FileExistsError` under `--no-symbols` (PR #9): root cause traced in pinned Ghidriff `setup_project()` (skips `setup_symbol_server` then calls `get_pdb(allow_remote=False)`, which consults the persisted SymbolServerService) and Ghidra 12.0.4 `ApplicationUtilities.getDefaultUserSettingsDir` (`application.settingsdir`, then `XDG_CONFIG_HOME` on every OS). Fix: per-run `XDG_CONFIG_HOME` in private scratch. Native Windows CI matrix: plain Ghidriff with a persisted store **reproduces** the failure; PatchTrace analysis **passes** with the persisted store (with and without PDBs at the embedded path) and clean. The user's clfs.sys pair and Ghidra 12.1.4 were not available; the fixture is the compiled bounds-check DLL. A CI fixture regression (MSVC `/DEBUG` implying `/INCREMENTAL` thunks) was fixed with `/INCREMENTAL:NO`.
- Linux x86-64 onedir package: CI smoke on Ubuntu 22.04/24.04 offscreen and Xvfb/xcb (initial failure: missing Qt xcb libraries on runners; full list now installed and documented). Frozen Linux binary runs `rank` end to end locally.
- Offline installer (PR #7) security review: 8 defects fixed with regression tests (non-normalized/system install roots, junctions, PT-CANCEL, cleanup masking, zlib errors, extended device names, POSIX replace race, plan contract). Real relocatable runtime payload and air-gapped Windows acceptance remain open.
- Phase 2 enrichment (SPEC-07, PatchTrace-authored; supplied handoff schema/examples absent): B1 detectors, B2 WIL, B3 CVE normalization/transport/contextual ranking, B4 cache, additive storage, pipeline, CLI, desktop and report wiring. Independent review found 6 defects, all fixed with reproducing tests: cancelled stages cached as empty results (scores later dropped to 0); non-default CLI profiles shown as the default in GUI/export; cache hits not revalidated against live ownership; file-loaded CVE snapshots trusted for feature IDs and stale snapshots unreported; non-object weights traceback; stale rows recording the live revision. Storage tests also caught non-atomic DDL in Python's legacy sqlite3 mode (fixed with explicit `BEGIN IMMEDIATE`). Benchmark found the WIL stage never hit the cache when empty (fixed).
- CVE endpoints probed live once by the B3 implementer (2026-10-12): NVD CVE API 2.0 and MSRC `sug/v2.0` per-CVE; fixtures are trimmed real responses for CVE-2024-38063. No live fetch runs in tests. Model/transport success does not validate CVE relevance.
- Benchmark (`tools/bench_enrichment.py`, synthetic 10,000 pairs / 110,000 lines, 4 vCPU Linux container, Python 3.12.3): cold pipeline 6.6 s and 240 MiB peak RSS in a fresh process (objectives 10 s / 512 MiB met on this machine); derived-cache hit 3.1 s, **objective 500 ms not met** (dominated by input hashing and ownership revalidation, which are required for correctness). UI responsiveness at this scale not measured. Windows timings not measured.

- Release `v0.1.0-beta.80` (prerelease) built by CI from merge commit `0d22e9c` (PR #10), tag verified to point at that commit. Downloaded assets: `PatchTrace-0.1.0-windows-x64.zip` 47,682,397 bytes and `PatchTrace-0.1.0-linux-x86_64.tar.gz` 74,017,268 bytes; both `.sha256` sidecars verified locally. Extracted Linux artifact in a clean `env -i`: `--self-test` exit 0, `rank` on the synthetic sample returns `read_item` (score 26), `flags` exit 4 (no results), missing project exit 2. Windows ZIP: 452 entries, contains `PatchTrace.exe`, enrichment schemas and updated README; the Windows frozen self-test and `rank --help` CLI smoke ran in CI `qa (windows-latest)`. No hands-on Windows GUI session was performed.
- Remote branches already integrated into `main` but not deleted (the session's branch deletion was refused by the environment): `access-test-noprefix`, `claude/access-test-1791773355`, `claude/symbol-policy-isolated-settings` (#9), `feat/verified-offline-runtime-bundle` (#7), `feat/enrichment-contracts` (#10), `feat/enrichment-{signals,wil,cve,cache}` (in #10), `fix/*` (#2-#6), `feat/local-runtime-discovery` (#5), `codex/patchtrace-beta` (#1). Retained with unmerged work: `claude/patchtrace-cli-dotpath-spec-er6hha` (SPEC-05 CLI/config/build-provenance draft; its exit-code table conflicts with the Phase 2 contract and its config/buildinfo modules are not integrated).

## 2026-10-12 full code audit (5 areas) and repairs

Every fix has a test that fails before and passes after. Confirmed defects fixed:
- Runtime (A): URL credential redaction leaked partial passwords and missed non-HTTP schemes; backend probe failed whenever the interpreter wrote a stderr warning (wrong "install ghidriff" diagnosis); Ghidra discovery could miss installs in crowded folders; a scratch-cleanup failure turned a completed analysis into a failure (now bounded retries + warning); post-kill wait timeouts and output-inspection OSErrors escaped without failure.txt; quoted secret values and bare GitHub/AWS/Bearer tokens were not redacted.
- Core (B): project database creation was not atomic (failed create left an unusable folder); strict JSON accepted overflowing floats and raised untyped errors on huge integers; save accepted a foreign project or lower revision; public annotate could forge match-override records; failed-backup cleanup could fail on read-only files; backup publish had a POSIX replace race; service.project went stale after backup recovered interrupted runs.
- AI/reports (C): provider requests had no total deadline (slow-drip servers held them open, ignoring Cancel); Windows paths with spaces leaked usernames into reports; Markdown ranking cells could be broken by line breaks.
- Desktop (D): untrusted bundle names rendered as rich text in the install consent prompt; tooltips fed binary names, model summaries and signal rationales could render rich text; empty export destination crashed on format change; failed self-test leaked the project lock; corrupt numeric settings crashed window construction.
- Enrichment/CLI (E): BND missed Ghidra cast pointer arithmetic and `else if` guards; SIZE fired on decompiler temporary spills; WIL qualified whitespace/rename-only edits and treated string/comment text as sites; WIL qualifying-hunk recomputation was quadratic (121 s on a 4,100-site function, now ~1 s); cancelled correlate and Ctrl-C in JSON mode broke the exit/envelope contract; zero-pairing rank could never exit 4; misleading stale note for non-default profiles; quarantine could move a just-republished valid cache entry; leased entries could be evicted when the lease file failed; prune trash was unreclaimable; one failed or malformed provider response discarded the others; any CWE dispute blocked agreed CWEs; duplicate snapshots double-counted; cancelled rankings were published.
- CLI/GUI/export agreement for the default ranking: verified identical (rank, match, score, raw, evidence, status, config digest).

Documented hypotheses left open (not reproduced): POSIX killpg PID-reuse race, setsid descendants holding pipes, Windows environment block sort order, diagnostic phrase false positives, Ghidra-directory sys.path shadowing, duplicate upstream addresses in Ghidriff JSON, ignored extra modified-entry keys, undo limited to the latest correction, off-thread `prepare_*` reads of service state (safe while mutating controls are disabled), export overwrite without confirmation for typed paths, positional project-directory argument (unspecified). Windows-only confirmations pending: tooltip/QMessageBox rendering, read-only backup cleanup, scratch retry sufficiency, pid liveness and junction checks in the cache.

Phase 3a acquisition (SPEC-08, headless): Winbindex parsing, consented msdl download with blob-only redirect, quarantine and PE/PA30 identification, CLI `acquire search|fetch`. Manual live probe: afd.sys `D37888A1b2000` downloaded through the transport, 744,832 bytes, SHA-256 matched Winbindex. `delta.py` (msdelta ctypes) has not run on Windows. Desktop dialog not yet built.

- Phase 2 completion (PR #12): profiles and raw-output cache; native Windows CI `raw-cache-hit` ran real Ghidra 12.0.4 / Temurin 25 twice and verified the second run was a cache hit with byte-identical raw JSON and identical matches.
- Phase 3 (PR #13): N-way series, acquisition dialog, BinDiff/rz-diff secondary engines. Windows CI ran the msdelta `CreateDeltaB` → `ApplyDeltaB` round trip successfully. Two Windows-only test defects found by per-test CI jobs and fixed: a 64 MiB pytest parameter id stalled the Windows console (QA hung 18+ minutes), and a POSIX path literal in an rz-diff probe test. QA jobs are now capped at 30 minutes.
- Release `v0.1.0-beta.90` built from `7eea001` (tag verified): Windows ZIP 47,861,849 bytes, Linux tar.gz 74,215,035 bytes, both sidecar checksums verified after download; extracted Linux artifact passes `--self-test` and every headless command answers `--help` with exit 0. No live BinDiff/rizin run, no hands-on Windows GUI session.

## 2026-10-13 SPEC-26 alpha session (Claude Code)

Merged: #19 (recorded file overview), #20 (handoff docs), #21 (verified artifact byte seam), #22 (PE overview + Authenticode probe), #23 (Hex/Binary/Base64 providers), #24 (tooltip registry). Each merged only after its own green GitHub Actions run: Ubuntu and Windows pytest + Ruff, Windows onedir freeze, Linux package + 22.04/24.04 smoke, and the native Windows Ghidriff matrix.

Automated evidence (actual results):
- Baseline main `f0086f7` before work: Linux local 774 passed / 5 skipped, Ruff clean.
- PR #22 Windows `qa (windows-latest)`: 875 passed / 10 skipped. JUnit shows `test_native_unsigned_file_does_not_raise` **passed** on the Windows runner, i.e. a real `WinVerifyTrust` call on an unsigned temp file returned without error. This is not acceptance of signed/trusted/revoked samples.
- Integration branch (PE comparison in File overview, raw views, Authenticode row): Linux local 973 passed / 6 skipped, Ruff clean. Windows result: see the integration PR checks.

Release publication (handoff B1) root cause: run 38492874312 (commit `64fda061`) built and tested successfully but `softprops/action-gh-release` got HTTP 403 `Resource not accessible by integration` although the job token had `contents: write`. That commit added `.github/workflows/import-agent-skills-once.yml`. GitHub refuses to let `GITHUB_TOKEN` create refs/tags on a commit whose diff adds or changes workflow files (the token can never hold the `workflows` permission). The next main runs 101 and 103 published `v0.1.0-beta.101` and `v0.1.0-beta.103` normally, and the repository has no rulesets. Conclusion: not a standing permission problem; no settings change required. Expect the same 403 on any future main push whose head commit edits `.github/workflows/*`; that run's ZIP stays available as an Actions artifact. A maintainer PAT with `workflow` scope would avoid it but is not recommended for an automated job.

Not performed in this session: interactive clean-Windows GUI walk-through, DPI/theme checks, signed/trusted/revoked Authenticode samples, fuzzing beyond the synthetic hostile-PE fixtures, live Ghidriff on new inputs beyond the CI fixture matrix.

## Acceptance gates
- Windows unit/Qt suite: 93 passed; Ruff passed ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38126515355)). Frozen desktop smoke passed on the final curated package ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38127040440)). That run repeats 93 Windows passes and 91 Linux passes with 2 Windows-only skips.
- Real native Ghidriff known bounds-check DLL patch: passed ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38126512208)). Python 3.12.10, Ghidra 12.0.4, Temurin Java 25; pinned Ghidriff revision from research. Both MSVC-built DLLs were statically analyzed, never executed. One modified change record contains the expected check. This single fixture does not establish general matching accuracy.
- Live Ollama and remote provider paths: unverified; no configured model/credentials supplied. Mocked HTTP request/envelope/schema tests are present. Follow SPEC-03 acceptance procedures; successful transport does not validate model truth.
- Clean Windows interactive resize/keyboard/code/evidence test: pending actual package and user testing.
- Matching precision/recall, held-out real patch corpus and resource targets: unmeasured. No accuracy or speed benchmark claimed.
- Dependency archive audit: CI ZIP downloaded and inspected; SHA-256 matched, all listed files existed, 47 Core/GUI attribution pages and required notice texts were present; two Qt Network attribution pages were subsequently added for the linked Network DLL. Curated package: 46,370,158 bytes, 417 ZIP entries; SHA-256 `c5783e25146029a741a5450209638a15cf9f955e6e24582c04277325079e95b2`. Qt Core/Gui/Network/Widgets and Windows/offscreen/style/network/TLS plugins remain. No PDF/WebEngine/QML/Quick/virtual-keyboard executable components. Final release is rebuilt from the merged commit and has its own accompanying checksum.

## Practical limits
Provider cancellation is cooperative around network reads; an active read can wait until the 120-second timeout, and transmitted remote context cannot be recalled. Native decompiler crashes/timeouts preserve logs and quarantined output; process isolation is not an OS sandbox. Backend output contracts are pinned to inspected Ghidriff; unknown output fields fail clearly. Only static PE AMD64 is initially supported. Call graph visualization, runtime debugging, automatic reproduction, auto-download and additional formats are deferred. The synthetic sample is authored and explicitly labeled.

## 2026-10-14 rz-diff stream separation
`jobs.run_process(separate_streams=True)` drains stdout and stderr on independent bounded threads (Windows: second inheritable pipe, Job Object containment unchanged). rz-diff parses stdout only and reports stderr on non-zero exit. Local Linux: 981 passed, 6 skipped; Ruff clean. Windows pipe path and real rizin remain unverified until CI/live runs.

## 2026-10-14 full code audit
See `docs/plans/audit-20261014-and-next-phase.md` for findings, fixes, deferred items and the next-phase plan. Local Linux: 1004 passed, 6 skipped; Ruff clean. Windows pytest, freeze and native Ghidriff results are those of the PR's CI run; clean-profile interactive GUI acceptance remains unverified.

## 2026-10-14 enrichment hardening (SPEC-07h correctness slice)
Re-baselines (deliberate): `signals`/`wil` group keys change because `_TEMP` is now a closed table (H6); SignalSet/ranking status semantics (H3: missing code is `partial`, one-sided pairings no longer degrade the run); contextual identifier points need binary evidence (H4, e.g. a signal-less pairing with a matching name no longer gains +16); `select_latest` merges providers (H13). Stage versions signals 2, wil 2, ranking 2, contextual 2 invalidate derived caches and stored rows by design. Local Linux: full suite and Ruff clean; Windows CI not run from this worktree.
## 2026-10-14 enrichment hardening H7 / H2 / H8 / H9 / H10
Local Linux automated evidence only (see PR checks for CI): new tests `test_child_env.py`, `test_history_bound.py`, `test_raw_single_copy.py`, `test_cancel_latency.py`, `test_nvd_pacing.py`; `test_enrichment_intelligence.py` re-baselined deliberately (NVD retry sleeps now include 6 s keyless pacing top-ups; keyed 403 is retried and ends as recoverable `PT-ENRICH-NETWORK`).
- H7: `backend.build_child_env` + `BackendConfig.restrict_env` / `env_passthrough` (Setup: checkbox and field). **Default OFF**: the Windows variable list is unvalidated by a native run, so the allowlist stays opt-in; `PATCHTRACE_CHILD_ENV=inherit` overrides. Open gate: native Windows `raw-cache-hit` job with `restrict_env=True` and a seeded `JAVA_TOOL_OPTIONS`/fake token probe; flip the default only after it is green. rz-diff CLI path still inherits (builder supports `for_tool='rizin'`, not wired).
- H2: history keeps newest 100 rows / 512 MiB, never the current snapshot or the newest row of each revision; identical-hash re-saves add no row. Not done: pre-prune verified backup.
- H8: backend output inside `runs/<id>/` is reused in place; staged import copies are deleted on `discard_import`. Not done: startup cleanup of duplicate files in legacy projects.
- H9: `netutil.interruptible` (daemon thread, cap of 4 abandoned) on CVE and LLM provider connects/reads; cancel observed in about 0.1 s in fake-blocker tests. Not verified on native Windows sockets.
- H10: NVD spaced 6 s keyless / 0.6 s keyed, 403 from NVD retried with backoff, overall deadline (`expected + 120 s`), CLI consent preview prints the expected duration. NVD's real enforcement is unverified live.
## 2026-10-14 CI additions: live rizin and frozen EXE smoke (not yet run in CI)
Live engine acceptance (not mocked): `.github/workflows/live-rizin.yml` (workflow_dispatch plus paths-filtered push/PR) installs rizin 0.9.1 on ubuntu-latest (`rizin-v0.9.1-static-x86_64.tar.xz`) and windows-latest (`rizin-windows-static-v0.9.1.zip`), verifies the pinned archive SHA-256 and fails closed on a missing, malformed or mismatched hash, builds a synthetic PE pair from `tests/fixtures/old.c`/`new.c` (MinGW on Linux, MSVC on Windows; no Microsoft binaries), runs `tools/live_rzdiff_check.py` (probe, version equals pin, `-C -j -t` present in `-h`, `run_rzdiff` match count > 0, hash round trip) and uploads `live-rzdiff-<os>.json`. Its results are never summed with pytest counts.
- Pinned SHA-256 gap: GitHub's API and release page were not reachable from the authoring session, so no upstream-published digest was compared. The two digests in the workflow were computed by downloading the official release assets on 2026-10-14 (Linux 137,626,404 bytes `9102249a...e8cf`; Windows 115,391,593 bytes `2d14e0a6...1d28`). Trust is therefore trust-on-first-use; cross-check against the release's displayed asset digests before treating the pin as independently verified.
- Unverified until a CI run: the extracted layout (`bin/rz-diff` on Linux; `rz-diff.exe` located by search on Windows), MinGW/MSVC build of the fixtures, whether `-h` lists `-C -j -t` verbatim, and `match_count > 0` on a one-function DLL pair. Rows under "Live engine acceptance (not mocked)" are added by hand from the artifact after green runs on both OSes; none exist yet. BinDiff remains blocked (no licensed install on runner).
- Frozen EXE smoke: `tools/frozen_smoke.py` (A1 `--help` for every registered command (`names()`), A2 unknown command exit 2, A3 missing project exit 2, A4 `--self-test` exit 0 and temp directory removed) runs as a Window…44986 tokens truncated…. `tests/test_gui_core_manifest.py` (it names pilot modules) 22 passed.
- Digest evidence: an independent hand-built hash (the oracle of `test_fabric_origins.py`, written separately from `domain_id`) gives `affccb01...` for the 15-row table PIL shipped before (equal to the old committed golden, so the formula did not change), `3370b2c8...bc18` for the shared 19-row table under `pilot-origins` (the new PIL golden) and `a48c53ab...3f10` under `fabric-origins` (the unchanged fabric golden).
- Mutation spot-check: 18 deliberate defects applied one at a time to `pilot/origins.py`, `pilot/ports.py` and `fabric/origins.py` (wrong domain, leaked fabric error, chained cause, wrong slug or code, digest without sources or without the override, a copied tag tuple, table or calculus, a locally redefined registry port, a dropped sink, unsorted or version-less payload, a changed pre-adoption row, an extra row); 17 of 18 failed the focused tests on the first run. The survivor (the `sorted()` of `payload()` is invisible through the digest, because canonical JSON sorts keys) was a test gap; `test_registry_payload_is_the_hashed_table_in_sorted_order_and_hands_out_copies` closes it and the mutation is killed (18 of 18). Each file was restored after its run and compared by hash, and `git status` showed no stray change.
- Not verified here: Windows and CI; the full suite (the integrator runs it); a real PIL publisher (none exists yet); the interplay with A41's `pilot/{store,report,cli,review}.py` (parallel work, not on this base).
### [R3:rules-candidates] R3 (2026-10-14, Linux container, CPython 3.13.16, yara-x 1.21.0; synthetic images, recorded real-tool goldens)
| Check | Method | Result |
|---|---|---|
| Tests | `tests/test_rules_candidates.py` with the R0 and R2 rules tests | 140 pass in 3 s; 562 pass in all four rules files (24 s) |
| Pipeline on goldens | capa-api `term`, `log`, `env` and floss-static `main` through `FlossStrings`/`CapaCapabilities`/`PeImports`, the reference renderer and the REAL engine | each candidate hits its own build and misses the other one; `log` older and any pair without channels give "no feature" with the channel reported `unavailable` |
| Escaping against the engine | hostile bytes (quote, backslash, CR/LF, NUL, 0xFF, comment end, a bidi byte sequence) and 40 hypothesis byte strings: `escape_text` inside quotes, scanned by YARA-X | every one matches exactly its own bytes at the expected offset; one byte short does not match; `wide` Latin-1 text matches UTF-16LE |
| Mutation sanity | 45 one-line mutations of the five source files (boundaries of every gate, separation rules, tick policy, ids, hash checks, stale checks, API resolution, subscope skip) | 36 killed first; the 9 survivors were test gaps (unknown on the older table, 256-byte limit, 6-byte anchor, `imports-unknown` note, per-direction lineage, run in the candidate id, reader hash check, exact-name preference, subscope rules) and got tests; 45 of 45 killed after |
| Lint | `ruff check src/patchtrace/rules tests/test_rules_candidates.py tests/rules_fixtures.py` | clean |
Not verified here: Windows; real binaries, a real Ghidriff pairing and real capa/FLOSS output on them; the interplay with R1's `synth` (a reference renderer stands in); API names come from capa's spelling (R4 pins are exact).
### [R4:rules-bytes] R4 (2026-10-14, Linux container 4 vCPU, CPython 3.13.16, yara-x 1.21.0; iced-x86 1.21.0 only in a scratch `pip install --target` outside the repository; SYNTHETIC images, none of it live evidence)
| Check | Method | Result |
|---|---|---|
| Tests | `tests/test_rules_masks.py` (98), `tests/test_rules_synergy.py` (20) and `tests/test_rules_candidates.py` (140; R4 touched one line) | 247 pass and 11 skip without iced-x86 (the 10 tests that need it and the pin guard) in 4.4 s; with the scratch iced-x86 on `PYTHONPATH` 257 pass and 1 skips (the guard, which passes or fails by itself once `pyproject.toml` declares the pin); all six rules files together 669 pass, 11 skip in 24 s; the pe_overview and intel-tools suites around the new module are unchanged (403 pass, 8 skip) |
| Known answer (plan s5) | five rules from `term` of the accepted `capa-api` pair (exact bytes, masked bytes, import only, masked + import, masked + call-target pin) over eleven builds, scanned by the REAL YARA-X in process and once through the hidden worker child; the golden `tests/fixtures/rules/synergy-matrix.json` is compared with the table parsed from the plan | identical in both paths. Exact bytes hit V1 and V1t only (the rebuild V1r escapes); masked bytes hit all three rebuilds and also the look-alikes LA and BOTH; import only hits the rebuilds, IMP and BOTH; masked + import still hits BOTH; only the call-target pin hits exactly V1, V1r and V1t and no other build |
| Windows of the card | `propose` on the three `capa-api` pairs with the real YARA-X | term older 24 B (20 literal, longest run 15, mask `rip-disp`, pin TerminateProcess), log newer 38 B (30, 14, WriteFile), env newer 35 B (23, 8, GetEnvironmentVariableA): the numbers of the card, from the policy "changed range plus one instruction each side, grown until the checks pass"; each window is found once in its build and not in the other |
| Decoder | the stand-in decoder (tests only) against iced-x86 1.21.0 on 6 fixture images and on hand-checked encodings of every flow kind; the edges (a jump to the first byte of the body stays inside, one to the byte after the last leaves it; a target at exactly 2**32 is not an RVA); the adapter's version and its fallback to the pin when the distribution metadata is missing | equal on all of them; invalid or cut-short bytes are `PT-RULE-DECODE` with both |
| Diff cost | `diff_opcodes` on masked bodies of 12,000 instructions, 6 shapes (distinct, all alike, 2 keys, 4 keys, half and half reversed, 50 scattered edits) | `difflib` alone: 5 shapes took 14 to 32 s (the distinct one 46 ms); with the bound (shared ends cut off, a middle over 1,000,000 equal-instruction pairs not compared) all 6 take 2 to 5 ms; the worst bodies just under the bound took 0.14 to 0.46 s. Hit counting over 8 MiB of x64-like bytes: 11 ms for a pattern with a literal start, 58 ms for one that starts with a wildcard |
| Mutation sanity | 89 one-line mutations of `tables`, `masks`, `window`, the bytes path of `candidates` and the iced adapter (off-by-ones on every cap and boundary, the tiling check, relocation reach, pin conditions, context size, growth order, ranking, budget, diff direction and cache key, hit-count semantics, stale and size checks, coverage) | 87 killed in the final run. The gaps found on the way got tests (body edges, 2**32, version fallback, tail and head overlap, unequal lengths, direction without opcodes, cache key); the 2 survivors are equivalent (the relocation loop bound that `low < high` repeats; `has_immediate`, which iced always sets for a near branch) |
| Lint | `ruff check` on the new and changed files | clean |
Not verified here: Windows (a CRLF checkout of the golden, process and clock behaviour); real compiler output (jump tables, thunks, SEH funclets, hot-patch NOPs: the stand-in decoder knows a subset and answers `PT-RULE-DECODE` for the rest); real `.pdata` (covered by `pe_builder` images, not by the grid); iced-x86 in the CI matrix; the interplay with R1's `synth`.
### [REDACT-2:redaction-coverage] redact_log coverage and linear time (2026-10-14, worker A40 on the CONSENT base d793ac3; Linux container; CPython 3.13.16; synthetic data only)
- Red first (`tests/test_redaction_coverage.py` against the unchanged code): 39 of the 53 non-timing tests failed (every Cookie, SAS, Slack, JWT, argv and generated-secret case and the CLI cases); the 14 that passed are the prose, digest, idempotence and URL-regression guards. Both timing tests failed: the 1 MiB corpus test was killed at its 180 s limit on its first input (`'a' * 1048576`), the hypothesis mixtures test failed at 64 KiB (2.8 s against 2 s). Cause, found by that test: the existing `_URL_AUTH` rule was quadratic (`redact_log('a' * N)`: 10k 0.69 s, 20k 3.3 s, 40k 15 s; hours for 1 MiB), and `redact_log` runs over child logs of up to 2 MiB (`backend.py:606`), so an unlucky or hostile log could stall the analysis worker.
- Green: the new file 57 passed in about 10 s (6.5 s of it the 1 MiB corpus, 36 inputs timed in one child, each about 0.2 s against an 8 s budget); `ruff check` clean on it, `diagnostics.py` and `cli.py`. Existing tests that import `diagnostics` or run `cli.main`: 677 passed, 4 skipped (the skips are existing) over 32 files in one run, and 17 further Qt, CLI and engine files (`test_ui`, `test_ui_engine_setup*`, `test_acceptance_smoke`, `test_nway_*`, the rules and kbc files, ...) pass one process per file. Stacking those 17 into a single process hit `MemoryError` in Qt fixtures; each file passes alone, and the batch did not contain the new file.
- Benign text is unchanged and not slower: output identical to the old function on log-like text, 0.197 s per MiB against 0.218 s (the literal-anchored `://` rule is faster than the old one and pays for the five added passes).
- Exploration beyond the committed 60-example properties (scratch, nothing committed): 30,000 generated secrets per shape, none survived; idempotent on all 30,000 realistic line mixtures. Of 30,000 adversarial fragment mixtures 55 were not idempotent, all inside the old `_ASSIGNMENT` rule (a quoted value directly followed by more text, for example `token=''--token`), none involving the new rules; left as is.
- Mutation check (scratch copy outside the repository): 21 single-point mutants of `diagnostics.py` and `cli.py` (each new rule removed or weakened, the old quadratic rule restored, the CLI left raw on stderr or in JSON); 19 killed. The 2 survivors remove a lookbehind from the JWT or argv rule: the explicit caps already bound the damage (about 5.5 s against 0.19 s on `'eyJ' * N`, 2.7 s against 0.23 s on `'--' * N` per MiB), so they stay as a 12 to 29 times speed-up that is not test-pinned. Reviewing the JWT lookbehind during the mutation work showed that it would miss a token after an escaped delimiter (`%3DeyJ...`); the escape alternative and a `jwt-escaped` case were added, and a mutant without the alternative is killed. The marker guard of the argv rule is pinned both ways (removed, and loosened so that `[redacted]` with text glued to it leaks).
- Limits: a JWT segment longer than its cap (8 KiB, 64 KiB, 8 KiB) or a token that follows base64url text directly is not recognised; the Cookie rule hides the rest of the line, including JSON that follows on the same line; `-p x` and `curl -u user:pass` are not covered. Not verified here: Windows and CPython 3.12 (the tests avoid POSIX-only calls; possessive quantifiers need 3.11 or later and the project requires 3.12), the frozen executable, the full suite.
### [WBQ-S8:codetext-marks] WBQ S8 (2026-10-14, Linux container, 4 vCPU shared with other workers, CPython 3.13.16 and 3.12.3 (throwaway venv, wheels only), hypothesis 6.169.1, pytest 9.1.1; SYNTHETIC text only, none of it live evidence)
| Check | Evidence | Result |
|---|---|---|
| Slice tests | `tests/test_codetext_marks.py` (337), `QT_QPA_PLATFORM=offscreen nice -n 10 python -m pytest ... -q -p no:cacheprovider`; hypothesis `FAST` profile (150 examples) | 3.13.16: 337 passed in 7 s (the three codetext files 642 passed, 1 skipped); 3.12.3: the three codetext files 641 passed, 2 skipped (S7's colorspacious and PySide6 parity tests) |
| Hypothesis sweep | the same file with 1,500 examples (seed 1) and 3,000 examples (seeds 7, 42, 2026, 31337) | 337 passed each; 1 to 2 minutes per seed |
| Lint | `python -m ruff check` on `src/patchtrace/codetext` and the test file | clean |
| SYN-WBQ-1 (the plan's s5) | the real `align_lines` on the reconstructed text: 15 aligned rows, 8 non-equal, 4 replace hunks; `diff_row` per paired row | 1 changed pair (`0x20` -> `0x40`, `constant`, line 8 of 15), 1 address-only (line 1), 4 rename-maybe (lines 4, 5, 7, 8), rows 10 and 11 skipped as "paired by position only" (0.63, 0.75); the two plan sentences for lines 1 and 8 are reproduced word for word |
| Mutation property | every unmasked token of 13 hand-written lines (C and assembly) replaced by 11 spellings (>= 150 clean single-token edits), plus 150 to 3,000 generated lines | each yields exactly one `changed` mark on each side, covering exactly the replaced token; a masked token (auto-name, temporary) yields `address-only` or `rename-maybe`, never `changed` |
| Shift-only controls | C: SYN text with the +0x40 shift and the renumbering and no edit; assembly: a 14-line listing, 3 rows differ; hypothesis over shifted names and image-range numbers | 0 `changed`; only `address-only` (4) and `rename-maybe` (7) in C, 3 `address-only` in assembly |
| Named symbols never masked | `CreateFileW` -> `CreateFileA`, `strcpy` -> `strncpy`, an import call, a decorated name, auto-name <-> name | always `changed`, label `callee` or `data-ref`; the oracle is never asked |
| Alignment optimum | exhaustive search over every order-keeping pairing of lines of up to 6 tokens from a 10-atom alphabet (masked collisions frequent) | the result equals the minimum of (inserted + removed, renames with another spelling, address pairs with another spelling, runs); the bit-parallel common subsequence equals a classic table on lists of up to 40 tokens; swapping the lines keeps the cost |
| Mutation check (scratch, not committed) | 165 textual mutants of the five new modules (`<scratchpad>/S8/mutate.py`), the S8 test file run against a copy of the package | first run: 17 survived (frame register names, cost-weight order, head and tail trimming, cell-cap boundary, label negatives, oracle arity, scan limits and others); after one round of added tests 6 survived (one was an equivalent shortcut); after a second round none. Final run on the final code: 165 of 165 killed |
| Bounds | 256 tokens and 4,096 characters per side; at most 8,192 table cells per pair; a refresh stops at 200 rows or 250,000 cells; LRUs of 4,096 rows | boundary tests (inclusive and exclusive sides); a row that fails the gate builds no table; the worst case measured below |
| Time (best of 7, shared CPU) | 200 typical pairs (the SYN rows) `refresh`: 18 ms (plan budget 60 ms; gate in the test 150 ms, best of 3). One typical `diff_row`: about 150 microseconds, of which the S7 tokenizer is 30. 80 hostile pairs (250 tokens, every 17th respelled, 7,200 cells each): the refresh stops after 35 rows at 177 ms. 200 `diff_row` over four worst-case shapes: 219 ms. `spans` for 400 cold blocks: 5.3 ms (plan 4.5 to 7.9 ms for 121) | within the plan's budgets; the deterministic guarantee is the cell cap, the timing tests only bound everything else |
| Hostile text | hypothesis over arbitrary text and soups of quotes, comment markers, controls, bidi and astral characters, lone surrogates, in both languages; twelve pathological 4,096-character lines; every mark on a token boundary, sorted, in range, on the right side; the summary one printable line (no category Cc, Cf, Cs, Zl, Zp, no space but U+0020) of at most 1,200 characters | holds; 50 invisible or control code points (C0, C1, spaces, bidi, default ignorables, tags, lone surrogate) each written as `<U+XXXX>` |
| Not verified here | Windows and the frozen EXE; the Windows runner's timing; real SPEC-31 instruction text and real Microsoft-built decompiler output (the SYN text follows Ghidra's forms, it is not a real listing); the Qt side (S9: formats, `QTextBlock.text()` equality with the rows, `compose_selections`, F8, labels, accessibility); the full suite (the integrator runs it) | open, see tasks/todo.md [WBQ-S8:codetext-marks] |

### [UE-WIRE:decompile] S3b live check (open)
Automated evidence only: a fake interpreter answers the real `decompile` request of the real runner over synthetic projects. Not verified: a live Ghidra decompile through `patchtrace unified run --python ... --ghidra-dir ...` on a project whose run retained `runs/<run>/unified/gzf/<side>.gzf`, and the CRT-row rate on a real pair.
### [PIL-C1:store-report-cli] Patch-intent localization store, report and CLI (2026-10-14, builder worktree on 9e9595c (work/a); Linux container, CPython 3.13.16, synthetic data only)
- Focused run: `tests/test_pilot_store.py` 51, `tests/test_pilot_report.py` 45, `tests/test_pilot_cli.py` 26 passed (122 new tests, about 17 s); `tests/test_cli_registry.py` and `tests/test_acceptance_smoke.py`, which now see the `pilot` verb (adapter rule, smoke list, `--help` without Qt), 71 passed and 1 skipped (the opt-in nightly freeze of `test_cli_registry`; the live rz-diff check was deselected). `ruff check src/patchtrace/pilot src/patchtrace/cli_commands tests/test_pilot_*.py` clean. The new modules byte-compile on CPython 3.12.3 (no pydantic there, so the tests were not run on it). The full suite was not run: no existing source file changed (new files and appended documentation only).
- Evidence for the gates: round trip and stale detection (guard moved, raw output changed, orientation swapped, each naming the inputs that differ), damaged sidecars (cut manifest, edited manifest, truncated, swapped and missing part, a decompression bomb) skipped without hiding an intact older result, a pointer that disagrees with its manifest, a symlinked directory, six ownership refusals, idempotent re-publish, replacement of other content under one id, a failed pointer row leaves the previous row and no directory behind; retention keeps three per family and leaves reviews, other kinds and unreadable rows alone, writes one verified backup that holds the rows, refuses to delete without one and does not reuse a backup that lacks the rows; orphan sweep; real-process exit codes 0/2/3/4/5; the unified path on the S0 fixture project; the append-only review round trip through the CLI; hostile function names from a real project (markup, a Markdown link, a pipe, a bidi override) inert in the terminal listing, the Markdown report and the table cells.
- Mutation check (throwaway script, one single-point change per run, restore): 27 mutants of the store, review, report, collect and cli. 24 killed; the 3 survivors are equivalent because a second layer enforces the same rule (the id check in `publish` is repeated when the staged manifest is read back; the decompression bound is repeated by the part digest; the row-id prefix filter of `delete_results` is repeated by its SQL `LIKE` clause). Two mutants that first survived (the pair missing from the retention family, the kind clause missing from the delete) led to stronger tests and are killed.
- Scale (this container, CPU time): 3,000 candidates with 2 CVEs (2,100 persisted leads, 3,400 queue rows counted) localize in 0.33 s, `stage` takes 0.29 s (4.2 MB canonical JSON, 264 KB gzip), `read_sidecar` 0.26 s, the Markdown 30 ms (162 KB), the JSON 50 ms. A result over 64 MiB is not stored (a warning) and the JSON export over 32 MiB is refused.
- Found while building: (1) `--action` of `review` collided with the sub-command destination `action` (the verb is now `args.verb`). (2) A stored unified result of the sample project is never current (its raw output is missing, the manifest source version is `1 [raw-missing]`, so its result id is not the plan's): the adapters fall back with a note, which the CLI passes on. (3) `result_id` does not hash the CVE selection, so `--cve` could not safely narrow a run (see the todo block).
- Not verified here: Windows (path lengths, `os.replace` retries against a real indexer, symlink privilege), real Ghidriff/capa/FLOSS/DiE/unified data, the frozen executable, the 250,000-candidate bound and the P-08 memory bound through the store, concurrent writers (one owner thread is assumed, as everywhere in the enrichment store).

### [R5:rules-store] YRX-wire and R5 (2026-10-14, Linux container, CPython 3.13, yara-x 1.21.0; SYNTHETIC images, none of it live evidence)
| Check | Method | Result |
|---|---|---|
| Section 5 grid with the real renderer | `tests/test_rules_synergy.py` builds the five rules with `synth` and compares the grid with the plan's table and, in a new test, with the grid of the reference renderer | equal |
| Tests | `tests/test_rules_store.py` (14), `test_rules_matrix.py` (34), `test_rules_export.py` (20), `test_rules_cli.py` (28), plus `test_rules_candidates.py`, `test_rules_synergy.py`, `test_rules_synth.py`, `test_cli_registry.py`, `test_kev_cli.py`, `test_fabric_cli.py`, `test_acceptance_smoke.py` | pass |
| Known gates | append-only (same row no-op, other content refused), resume after a crash between decision and version, export golden, no bulk flag, accept and export are separate (no `.yar` after accept; one `rule-export` row and no version after export), a file that was not read is never `no match`, header without path or user name, secret strings refused, `rules` imports neither `yara_x`, `iced_x86` nor Qt | pinned by named tests |
| Real child | `rules _rules-worker` answers a probe request file (exit 0, empty stdout) and refuses a bad one (exit 2); `rules test` through the real worker gives the expected grid | pass |
Not verified here: Windows; the frozen executable; a live backend for `rules propose` (the tests use a fixture backend); a real series.

### [WBQ-S6-S9:qt-modules]
| Item | Evidence |
|---|---|
| Tests | `tests/test_ui_pemeta.py` (39), `tests/test_ui_codetext.py` (34), offscreen, `tools/qt_gate.py --repeat 5` over both: 365 passed |
| Budgets measured here (offscreen, Linux, shared CPU) | scroll window refresh 5-10 ms at 6.5k and 65k lines (gate 30 ms); 65k-line install adds about 135 ms per pane over a plain `setPlainText` (gate 450 ms); 100,000 API rows: table swap and 100,000 `data()` calls inside 3x the plan budget |
| Not verified | Windows; NVDA/Narrator; DPI; high contrast; Consolas bold advance; pixel probe; the 20x single-session repeat (5x run) |
### [UE-S4b:ui-unified] Unified panel automated evidence (2026-10-15, Linux offscreen)
- tests/test_ui_unified.py + tests/test_unified_panel_spec.py: 39 passed; `tools/qt_gate.py --repeat 20 tests/test_ui_unified.py`: 700 passed, no abort. Blocked, not run: Windows CI, NVDA/Narrator, DPI scaling.
### [PIL-C2:leads]

| Item | Evidence |
|---|---|
| Tests | `tests/test_pilot_read_model.py` (35), `tests/test_ui_leads.py` (61) offscreen on Linux; `python tools/qt_gate.py --repeat 6 tests/test_ui_leads.py`: 366 passed, no abort |
| Known gates | one test per state L0-L8 and each gate and window banner; banned-string sweep over every producible string (stems `probab`, `likelihood`, `confidence`, `percent`, `vulnerab`, `exploit`, `proven`, `certain`, `verified`, `safe`, `secure`, with the sanctioned phrases removed); no enum slug and no percent sign in any cell; hostile names, notes and tooltips stay text; `a11y_audit` clean in every state; no new top-level window; late results dropped on a project switch; shutdown cancels and waits |
| Not verified here | Windows; real screen readers; a PE-backed project (the resolver finds no row in the synthetic sample, so Go to function is only exercised with an injected resolver); the freeze of the GUI-thread collection on a large project |
### [QA-CLI:stress] CLI and persistence stress (2026-10-15, Linux, root host)

| Item | Evidence |
|---|---|
| Tests | `tests/stress/test_cli_stress_{verbs,paths,concurrency,recovery,perf}.py`: 158 collected, 150 passed, 1 skipped (read-only directory, root), 7 strict xfail; 22.9 s |
| Open bugs (xfail) | QA-CLI-1 (Medium) `--json` parse failure prints no document; QA-CLI-2 (Low) offline `correlate --cve bad` exits 4; QA-CLI-3 (Medium) `cache verify` on a file `--cache-dir` exits 0 `complete` with `_Unsafe`; QA-CLI-4 (Low) `rank` ignores an unusable `--cache-dir` silently |
| Measured, not gated | 10k-pair cold 5-7 s, cache hit 1.5-3 s (objective 500 ms not met), peak RSS 547 MiB (objective 512 MiB); details in `docs/audits/20261015-qa-cli-persistence.md` |
| Not verified | Windows; read-only directory as a non-root user |


### [UE4:code-panes] Unified code view
| Item | Result |
|---|---|
| Tests | `tests/test_unified_pair_text.py`, `tests/test_ui_unified_code.py`, `tests/test_ui_unified.py`, `tests/test_ui_unified_pipeline.py` offscreen on Linux; `python tools/qt_gate.py --repeat 5` over the Unified files |
| Known gates | every code state, hostile text in code, provenance and notes, accessibility audit, tooltip registry, a 100,000 line function (capped with the notice, only hunks inside the cut navigable), a tampered or malformed decompile part is not shown |
| Not verified here | Windows; real screen readers; real decompiled text (no pipeline writes the part yet, the tests store C with the product's part writer) |

### [LBL-02-04:tranche-recipes] libdeflate, stb, c-ares recipes (2026-10-15, Linux, mingw-w64 gcc 13-win32)
- Network-verified: peeled tag commits (ls-remote of tags) for libdeflate v1.15-v1.24 and c-ares cares-1_26_0 to v1.30.0; stb has no tags (five version-bump commits, all ancestors of master); every licence file hashed from the pinned commit.
- Built here: `tier_r fetch` and `build-card --opt O2` for all 13 new cards (libdeflate 5, stb 4, c-ares 4), 0 disagreements after the declared lists were taken from the factory labels; `aa` byte-identical for libdeflate v1.19, stb_image-2.26 and cares-1_28_0. c-ares needed `Recipe.libs` wired into the link line (ws2_32, iphlpapi, advapi32).
- Not verified: the same runs on an Actions runner (R1); the untagged c-ares pins 035c4c37 and a804c04d (CVE-2024-25629 pair) were hashed but no card was built from them; the Windows MSVC leg.

### [LBL-14:ci-summary]
Automated: tests/test_ci_summary.py (counts, 90% warning, error status, determinism, workflow invariants). Not run: the nightly schedule and the determinism step on a real runner (needs main plus Actions).

### [LBL-prereg:tools]
Automated evidence only: `python -m tools.calibration.prereg --qa docs/qa.md` verifies the recorded `C9-PREREG-v1` SHA after the lock; no lock exists yet.

### [LBL-13:channels]
Automated only: `tests/test_calib_channels_*.py` (synthetic pairs). No channel value is claimed on real builds; `rules` is blocked until YARA-X is available.


### [U3-U8:cli-pin]
- Automated: `tests/test_unified_cli.py` and `tests/test_unified_bindiff_pin.py` (hermetic). Blocked on the owner: BinDiff v8 digest verification (needs an independent network path and the issuer key), so G-U3 oracle part is not run.

### [LBL-08:msvc-cl]
- Automated (Linux): argv, banner, host gating, nuisance variants and a build through fake `cl`/`link` pass; the real-compiler test records `blocked` (profile msvc builds only on a Windows host).
- Not verified: any real `cl` build (A/A byte identity, PDB source-path normalisation via `/d1trimfile`, `llvm-strip` on a MSVC image, `llvm-pdbutil` inventory). Needs the windows-2022 advisory job.

### [LBL-07:mutations-ir-opt]
- `tests/test_mutations_ir.py` (27) and `tests/test_mutations_opt.py` (11): hand-computed IR goldens, fake process runner, and one real-tool test per layer that asserts BLOCKED when clang/opt is absent. Real clang/opt 18.1.3 on Linux: `mergefunc`, `always-inline`, `loop-extract`, `hotcoldsplit` change the module; `partial-inliner` returned `unchanged` on the sample (its trigger is narrow), reported as a rejected attempt, not a pass.
- Not verified: the Windows runner (`opt` availability is [unverified] per the LBL plan); agreement rates on real mutants (needs the farm).


### [WB2-G8:whole-program-sources]
Automated only: `pytest tests/test_callgraph_sources.py` (14). No live BinExport/IR acceptance run.


### [WB3-S9:strings-live]
| check | evidence |
|---|---|
| goldens equal what the committed FLOSS 3.1.1 output yields through the run service (no tool needed) | `tests/test_live_strings.py::test_goldens_match_the_committed_floss_output` |
| pinned FLOSS on the synthetic pair equals the goldens (Linux CI; Windows advisory leg) | `tests/test_live_strings.py::test_pinned_floss_reproduces_the_string_goldens`; BLOCKED here: `PATCHTRACE_FLOSS` is not provisioned, the test records `blocked` and prints `LIVE ACCEPTANCE BLOCKED` |
| run orchestration: consent hash recorded, cancel, stale, project switch | `tests/test_ui_strings_run.py` (fake FLOSS, synthetic pairs) |
Goldens are derived from committed tool output, not from a new live capture; they become real-run goldens only when CI passes the live test. Real-binary string counts, Windows onefile start time and AV behaviour stay owner or CI items.

### [STRESS2:stress-deep-2]
- Automated (Linux, synthetic, seeded): tests/stress/test_stress2_{pilot,kev,kbcorrelation,enrichment_store,unified_parts,rules}.py; 78 passed, 5 strict xfail. Scale knob PATCHTRACE_STRESS_SCALE (default 1).
- Defects (product code unchanged): QA-S2-1 pilot universe() echoes caller CVE text into PilotError.message; QA-S2-2 project store connection is bound to its creating thread (lock-serialised writer threads all fail with ProgrammingError); QA-S2-3 NaN in an enrichment body escapes as ValueError, not PT-ENRICH-INPUT; QA-S2-4 unified part_lines does not enforce the 4 MiB line cap on newline-terminated lines; QA-S2-5 rules not_mostly_wildcards(0,0) raises ZeroDivisionError.
- Not exercised: YARA-X lint path (yara_x not installed in the worker venv); unified retention with many published results (needs staged result dirs).

### [D7:buildenv-timeline]
- `tests/test_buildenv_timeline.py` (12): cells, adjacent hops only, not-run is not a difference, tool-version guard, header-only stays unknown, bounds.
- Not verified: offscreen strip test (strip not built; needs the nway/ui_series seam).

### [D9:buildenv-value-gate]
- `tests/test_buildenv_value_gate.py` (12): hand-computed golden counts, control and leakage checks, no-data, determinism, input rejection, CLI.
- Not verified: any real M4 pair; the targets are [inf] proposals.

### [D8:live-buildenv]
- Locally both cases record BLOCKED (no diec here); the job is dispatch-only. Not verified: any live run, including the golden equality and the provisioning step with `--engine diec`.


### [WB1-S7:search-panel]
Automated: `tests/test_ui_search_panel.py` (offscreen, 29 tests, `tools/qt_gate.py --repeat 5` clean). Not verified: real index on a project, Windows, screen readers.


### [WB2-G5G6:calls-panel]
Offscreen: `QT_QPA_PLATFORM=offscreen python tools/qt_gate.py --repeat 5 tests/test_ui_graph_panel.py`. Screen-reader and high-contrast passes are owner gates, not done.


### [WB3-S7b:strings-panel]

Automated: `tests/test_ui_strings_panel.py` (offscreen, qt_gate x5). Owner-only: NVDA and Narrator pass, high-contrast and DPI check of the Strings dock.


### [CAP-6:capabilities-panel]
| Item | Result |
|---|---|
| Tests | `tests/test_ui_capabilities_panel.py` (35) offscreen on Linux; `python tools/qt_gate.py --repeat 5 tests/test_ui_capabilities_panel.py`: 175 passed |
| Not verified | Windows; screen readers; a real capa program; a PE-backed project (all data through injected fakes) |


### [K3:kev-panel]
Automated: `tests/test_ui_kev_panel.py` offscreen, `tools/qt_gate.py --repeat 5` clean. Not verified: NVDA/Narrator, high contrast, live CISA download.


### [FAB-6:related]
| Tests | `tests/test_ui_related_panel.py` (35) offscreen on Linux; `python tools/qt_gate.py --repeat 5 tests/test_ui_related_panel.py`: 175 passed |
| Not verified here | Windows; screen readers; the real project store read from a worker thread (reader is injected) |

### [LBL-20/21:tier-w-fetch-symbols]
Automated: `tests/test_tier_w_fetch.py` (33 passed) and `tests/test_tier_w_symbols.py` (29 passed, 1 xfailed). The xfail is the live Ghidra export, recorded BLOCKED (no Ghidra on the runner). The live llvm-pdbutil parity test ran against the self-made PDB (LLVM 18.1.3). Not evidenced: any real Microsoft download or PDB (O1, owner only).

### [LBL-22:tier-w-labels]
- Synthetic fixtures only: `tests/test_tier_w_labels.py`, `tests/test_tier_w_audit.py`. Not verified: any real symbol map.

### [LBL-24:tier-w-aggregate]
- `tests/test_tier_w_aggregate.py` (suppression at n < 30, no pooling, no names in output). Not verified: owner-run data.

### [T9:extern-c-linkage] C source function locator regression (2026-10-20, Linux container)
| Check | Evidence | Result |
|---|---|---|
| Focused tests | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_tier_r_csrc.py tests/test_mutations_ops.py` | 29 passed, 23 skipped; skips are compiler-backed mutation acceptance checks because Clang is not installed/on PATH |
| Lint and patch hygiene | `python -m ruff check tools/calibration/tier_r/csrc.py tests/test_tier_r_csrc.py`; `git diff --check` | clean |
| Scope | `find_functions` tests cover definitions before, inside, and after `extern "C" {}` linkage blocks plus standalone `extern "C"` declarations | pass |
| Independent review | reviewed parser boundary handling and tests | approved; tests do not invoke a C/C++ preprocessor |

### Full-suite Linux container run (2026-10-20; CPython 3.12)
| Check | Evidence | Result |
|---|---|---|
| Full suite | `QT_QPA_PLATFORM=offscreen python -m pytest -q` | 15,716 passed, 12 failed, 83 skipped, 4 xfailed in 1,711.93 s |
| Locally reproducible product issues | screenshot renderer and unknown mutation operator failures listed above | both fixed; combined rerun of `tests/test_site_screens.py` and `tests/test_tier_r_eval_cli.py`: 27 passed, 2 skipped |
| Environment-limited failures | isolated `python -I` import checks, local AF_UNIX socket test, and three time-budget tests | `-I` subprocesses cannot see this environment's editable install (`ModuleNotFoundError`); AF_UNIX creation is denied by the container; budget tests failed under full-suite load but the 26 relevant cases passed in isolation |
| Cross-runner confirmation | GitHub Actions run 39456546905 on Windows and Ubuntu | both runners passed the complete pytest suite and Ruff; Windows later failed only at the NSIS installer compile step, tracked under PR #95 |

### [site-screens:files-panel] Site screenshot renderer follows the current panel UI (2026-10-20, Linux offscreen)
| Check | Evidence | Result |
|---|---|---|
| Screenshot generation | `QT_QPA_PLATFORM=offscreen python tools/site/render_screenshots.py --only overview` | rendered current Files dock at 1440x900; synthetic project; no engine probing |
| Site screenshot suite | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_site_screens.py` | 12 passed |
| Lint and patch hygiene | `python -m ruff check tools/site/render_screenshots.py tests/test_site_screens.py`; `git diff --check` | clean |
| Updated visual asset | `site/assets/screens/overview.png`, `.webp`, `screens.json` | reflects the Files dock in the workspace rather than the removed overview dialog |

### [T9:mutation-cli-usage] Unknown mutation operator validation (2026-10-20, Linux container)
| Check | Evidence | Result |
|---|---|---|
| Regression test | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_tier_r_eval_cli.py` | 15 passed, 2 skipped; compiler/toolchain acceptance cases remain blocked because Clang/LLVM tools are not installed/on PATH |
| Lint and patch hygiene | `python -m ruff check tools/calibration/tier_r/cli.py tests/test_tier_r_eval_cli.py`; `git diff --check` | clean |
| Behavior | Unknown `mutate --operator` is rejected as a usage error before probing compiler tools; JSON status is `error` and exit code is 2 | pass |
### Windows installer source-path fix (PR #95 follow-up)
- GitHub Actions run 39012939220 failed compiling `installer/PatchTrace.nsi`: NSIS could not open the relative `LICENSE` path from the script's directory.
- Anchored installer input and output paths to `${__FILEDIR__}..` with `REPO_ROOT`; added static regression coverage for the license, bundle, notice, generated uninstaller manifest, and output paths.
- Local verification on Linux: `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_windows_installer_manifest.py` (4 passed); `python -m ruff check tests/test_windows_installer_manifest.py` clean; `git diff --check` clean.
- Not verified yet: compile with pinned NSIS 3.13 and run installer lifecycle on Windows CI.
### SPEC-53 local symbol mode and launcher (2026-10-21, Linux container)
| Check | Evidence | Result |
|---|---|---|
| Staging, PDB identity reader, launcher, backend integration, CLI flag validation | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_symbols_staging.py tests/test_ptlaunch.py tests/test_backend_symbol_local.py tests/test_nway_series.py` | full suite 15584 passed, 6 failed (pre-existing, rapidfuzz extra not installed), 286 skipped |
| Scope of the evidence | all runs use a FAKE `ghidriff` package and synthetic PDBs/PEs | Not evidence that real Ghidriff 4f5d895 or Ghidra 12.0.4 honours an empty server list; not an air-gap test (GHR-5 open, needs Windows and an OS-level network block) |
### SPEC-DA-01 Diaphora Mode A import (2026-10-21, Linux container)
| Check | Evidence | Result |
|---|---|---|
| Guard, parser, address mapping, provenance, store, bridge, CLI, schemas | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_diaphora_import.py tests/test_diaphora_cli.py tests/test_diaphora_schemas.py` | full suite 15584 passed, 6 failed (pre-existing, rapidfuzz extra not installed), 286 skipped |
| Scope of the evidence | synthetic result databases only (`tests/diaphora_support.py`), never produced by Diaphora; no real Diaphora, IDA or Hex-Rays run | Not evidence of compatibility with Diaphora 3.4.3 output (EA text encoding, ratio range and `type` strings are assumptions). The live gate and value-over-Ghidriff evaluation are open |

### Continuation integration checkpoint (2026-10-22)
| Check | Evidence | Result |
|---|---|---|
| Missing optional dependency diagnosis | Before installing the declared `search` extra, `tests/test_search_capability.py` and `tests/test_search_synergy.py` had 6 failures; after installing pinned `rapidfuzz==3.14.6`, the same tests passed | 37 passed; failures were dependency-installation failures, not PR #100 regressions |
| Combined PR #100 feature tests | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_symbols_staging.py tests/test_backend_symbol_local.py tests/test_ptlaunch.py tests/test_ui_symbol_local.py tests/test_diaphora_cli.py tests/test_diaphora_import.py tests/test_diaphora_schemas.py tests/test_mutations_more.py` | 128 passed, 23 skipped; compiler-dependent cases are BLOCKED because Clang is absent in this container |
| Lint | `python -m ruff check src tests tools` | clean on the combined tree before the current mutation investigation |
| Integration source state | Isolated `codex/patchtrace-completion-20261022`: PR #64 integration branch + current `main` + eight PR #100 commits | Not yet run through full Linux/Windows CI |
| Prior Windows regression gate | PR #64 QA run `39559162804`, merge SHA `a815670a48ae05a1ca7b2e8c2850cb880d57f825` | FAILED: 2 mutation tests (`string-literal-shout`, `callee-swap-dispatch`), 17,988 passed, 79 skipped, 6 xfailed. Must reproduce/fix and verify on Windows before release |
| PR #100 standalone gate | Actions at `66e9adc50fb118c04e5e24eacd0c221ca483a130`: QA Windows/Linux and native Windows Ghidriff acceptance | Passed on PR #100 alone; does not validate the combined branch |

### [LBL-WIN-COFF:masked-body] COFF semantic-label false positives (2026-10-22)
| Check | Evidence | Result |
|---|---|---|
| Red regression fixtures | Added `test_masked_body_coff_quoted_rip_string_symbols_are_addresses` and five parameterized `test_masked_body_stops_at_function_boundary` cases; before the code change these produced **5 failures, 1 pass** | Reproduces quoted MSVC `??_C@...` RIP operand drift and missing COFF `.seh_endproc`, `.def`, `.section`, and next-symbol boundaries without requiring Clang |
| Fixed parser + focused suite | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_mutations_more.py::test_masked_body_coff_quoted_rip_string_symbols_are_addresses tests/test_mutations_more.py::test_masked_body_stops_at_function_boundary tests/test_mutations_more.py` | 36 passed, 23 skipped; all compiler-backed skipped cases are BLOCKED because Clang is absent |
| Lint and patch hygiene | `python -m ruff check tools/calibration/mutations/engine.py tests/test_mutations_more.py`; `git diff --check` | clean |
| Required remaining verification | Current-head Windows QA using its real Clang 20.1.8; specifically recheck `string-literal-shout` and `callee-swap-dispatch` | PENDING; synthetic assembly tests do not replace native compiler evidence |

### Continuation branch verification follow-up (2026-10-22)
| Check | Evidence | Result |
|---|---|---|
| Combined PR #100 and COFF regression suites | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_diaphora_import.py tests/test_diaphora_schemas.py tests/test_diaphora_cli.py tests/test_symbols_staging.py tests/test_symbols_decoration.py tests/test_backend_symbol_local.py tests/test_ui_symbol_local.py tests/test_ptlaunch.py tests/test_mutations_more.py` | 314 passed, 24 skipped in 63.91 s; compiler-backed mutation cases skipped because Clang is not installed |
| Full-suite attempt | `QT_QPA_PLATFORM=offscreen python -m pytest -q` | Interrupted after nearly 10 minutes at about 1% progress; run remained CPU-bound. A separate `--collect-only` attempt was also interrupted after over 2 minutes without completing discovery. No full-suite result is claimed. |
| Branch publication | GitHub Git Data API created commit `b8e0a6705cfda603e0ee0d0cf831731eda58cf08` from exact local tree `fd7fa581cf1c7f28ba08676991efdb2b36aeaeff`; ref update used expected prior head `fb3645350f8f38d61dc507d7751377696aa1bcc3` | PR #64 head advanced; tree hash matched local `HEAD` exactly. Shell `git push` remains unavailable because no Git credential is exposed. |
| Current-head CI | Actions query `actions/runs?head_sha=f0af3fe2b4bfd6a8413d6d3cec093238d34e9d93` | No workflow runs had been created at query time. Git Data and Contents API commits advanced the PR head, but did not create Actions runs; an owner-side authenticated push or workflow dispatch is still required. |
| Release status | Combined continuation branch | Not release-ready: current-head Windows/Linux CI, frozen Windows smoke, and installer lifecycle remain unverified. |

### [SPEC-53:setup-modes] Symbol mode radios and local PDB folder list (2026-10-22, Linux offscreen)
| Check | Evidence | Result |
|---|---|---|
| Setup behavior and tooltip audit | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_tooltips.py::test_setup_dialog_all_tabs_and_profiles tests/test_ui_symbol_local.py` | 7 passed in 51.77 s; covers radio exclusivity, legacy online migration, local config persistence, folder deduplication/removal, 16-folder cap, accessible names and Setup tooltip coverage |
| Lint and patch hygiene | `python -m ruff check src tests tools`; `git diff --check` | clean |
| Scope | Qt offscreen tests only | No Windows visual, DPI, screen reader, or real Ghidriff/air-gap evidence; GHR-5 remains open. |

### [SPEC-53:profile-local] Profile symbol-policy narrowing (2026-10-22, Linux)
| Check | Evidence | Result |
|---|---|---|
| Profile validation, digest, GUI, settings matrix, schema regeneration | `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_profiles.py tests/test_ui_profiles.py tests/test_unified_contracts.py::test_generate_schemas_reproduces_committed_files` | 55 passed in 73.46 s; local policy has a new digest, and a named profile cannot enable a mode above Setup |
| Schema | `docs/schemas/profile/AnalysisProfile.json` regenerated | `symbol_policy` enum is `disabled | local | online`; prior enum values and digest inputs remain unchanged |
| Lint and patch hygiene | `python -m ruff check src tests tools`; `git diff --check` | clean |


## 2026-10-30 consolidation review

Baseline PR #123 head `99f8328` passed QA run `41004210486` and native Windows Ghidriff run `41004210319`; these validate the baseline only. The new consolidation selectively ports #67 launch/consent/import safeguards and #102 parser/checksum protections, fixes client product-scope identity and failed decompile refresh preservation, and corrects hidden worker help. See `docs/audits/20261030-consolidation-review.md` for findings and source dispositions.

Local focused checks: 149 parser/GUI tests; 175 unified tests; 155 KB tests; 262 backend/core tests with 3 skips; 53 independent safety-review tests; 7 installer/help tests. These runs overlap and must not be added. `python -m pip check` and `python -m ruff check src tests tools` passed. Full combined `QT_QPA_PLATFORM=offscreen python -m pytest -q` is running. New exact-head Linux/Windows QA, repeated Qt, native Ghidriff and packaging are pending; no completion/native acceptance claim is made.

Consolidation verification follow-up: the first user-site test run was stopped because isolated subprocesses could not import a user-site editable install. A dedicated venv was installed and its isolated import verified. The complete venv suite at the first consolidation snapshot reported **18,258 passed, 136 skipped, 7 xfailed, 4 failed** in 347.91 s. One failure is the executor denying AF_UNIX socket creation (PermissionError); three are synthetic secret-redaction children formerly injected via cwd. Their fixtures now invoke an explicit absolute fake script while retaining production -I/private-cwd arguments and all redaction assertions. A separate real symlinked venv regression exposed base-interpreter selection from Path.resolve; probe and analysis now preserve the selected absolute executable path. The new runtime suite passes **46 tests**. The final combined full suite and remote gates must validate these corrections. No AF_UNIX test has been removed or skipped to hide the host restriction.

Final runtime integration full run at `8bf483c`: **18,265 passed, 135 skipped, 7 xfailed, 2 failed** in 362.09 s. The remaining product-independent AF_UNIX denial is unchanged. The other failure was the old corpus workflow test requiring every action use a mutable version tag; it rejected the verified MSVC full commit pin. The assertion now validates that exact approved commit while retaining existing checks for other actions. The actual workflow structure is also checked with PyYAML installed locally. A final rerun follows this test-only correction.

Full d34efeb snapshot before final Qodo repairs: **18,304 passed, 128 skipped, 7 xfailed, 1 failed** in 371.25 s. Only failure: executor denies AF_UNIX socket creation. Final substantive Qodo findings are repaired and focused-tested (see 20261030-consolidation-review.md); a new combined full suite and exact-head GitHub gates follow. Schema regeneration completed without schema-file changes.

## 2026-10-30 controlled branch consolidation — integration lane (pre-final gates)

- **Pinned main at coordinator start:** `a04f5a299a8d4afef023261e52e08d14678cf1e7`. Its exact-head QA and Windows standalone push workflow, [run 41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610), completed **success**. This is **main's baseline evidence**, not proof that later integration commits pass.
- **Dedicated remote branch:** `integration/controlled-consolidation-20261030` created from that commit. Full conservative branch/PR snapshot is in [`docs/branch-pr-inventory-2026-10-30.md`](branch-pr-inventory-2026-10-30.md): 126 branches in API listing including main/new integration, 28 open PRs. Uncommitted/untracked local worker files and worktrees are not observable through GitHub; their status remains **unknown**.
- **PR #98 selective source preservation:** copied six unique `docs/wiki/*.md` blobs byte-for-byte from `docs/readme-and-wiki@ad8fbe9f2f041653760c02e9d18a91a66dd11c39` into integration commit `e81adbe882ae6eb2c26a5854b24aa6acff2b27a2`. Adapted the wiki-source reference into the **current** README rather than replacing newer main content (`c307aaad162cff1f4464b62469792ead8d877385`). Original PR #98 and source branch retained. The old PR head had successful Linux and Windows QA, but those are **not** evidence for this new integration branch. Its README text must not overwrite modern main.
- **PR #61 is not merge-ready:** the observed exact-head checks for `4467d1f3c6e113a7da808a67e8dee9d4aa5083d8` include Windows QA **failure**, Linux QA success, and skipped package/release jobs. It also alters `AGENTS.md` and `CLAUDE.md`. No direct/wholesale integration before root-cause repair and current-contract review.
- **PR #102 is not merge-ready:** its head `9fddf99e2635e28129b2deda0ff155b00d9ba471` is 13 commits ahead / 416 behind pinned main. It changes code, CLI, resources, release workflow, and packaging and overlaps already merged integration repairs. Keep author's branch untouched; port only reviewed unique, compatible fixes with red/green regressions.
- **PR #126 is active code, not documentation-only:** observed head `8d958f0a1950a29c1d1cef9525a114654f4c9904`, 9 ahead / 0 behind main, modifies callgraph, KB, detection rules and tests despite a docs-style title; reserve worker branch and require its own exact-head acceptance. R1–R8 research PRs received same-day updates and are preserved untouched.
- **Not run on new integration branch:** local offscreen pytest, Ruff, schema generation, Linux/Windows CI, live native Ghidriff/secondary engines, Windows frozen smoke. This environment has GitHub repository API access but **no local PatchTrace checkout and no network path for Git clone** (`git ls-remote` fails DNS resolution). Do not interpret these as passing. Open an integration PR to trigger GitHub Actions; verify checks on its exact resulting head before marking ready.
- **Acceptance stop rule:** main remains unchanged, no code changes may be promoted merely because docs-only code is green. PRs are not closed until all unique source content has merged into main and equivalence is established.


## GT-01 executable verification continuation (2026-10-30 Pacific)

This entry supersedes the earlier no-checkout limitation for this session only.
Reviewed source: PR #140 `b87193d1dd30635fce33986f80ceade136507a1a`, stacked on
#139; neither draft is accepted or merged by this entry.

- Reproduced both invalid A/A regression fixtures (equal hashes incorrectly labelled
  `release`) and two Ruff findings; corrected the fixture stratum and import/fixture
  registration annotations without relaxing the label contract.
- Independent review found failed extraction staging could poison the next pair or
  orientation. The new regression first failed twice with `FileExistsError`, then
  passed after comparison-owned extraction staging. The real project store and
  unified pipeline remain exercised; the external runner is synthetic in this test.
- Focused GT-01 suites: **30 passed**. `python -m ruff check src tests tools` and
  `git diff --check`: clean. Independent review approved the recovery repair.
- Real Linux static smoke: pinned Ghidriff `4f5d895`, PyGhidra 3.0.2, verified
  Ghidra 12.0.4 archive, OpenJDK 21.0.12.1, authored one-function PE fixtures
  compiled with Zig 0.17.0. Changed pair: completed/imported, `read_item` modified,
  unified `material`. Two independent equal-byte controls: completed/imported,
  two hash-verified retained GZF sides each, extracted IR, current unified result,
  `read_item` unchanged. Receipt: [gt01-native-smoke-20261030.json](qa/gt01-native-smoke-20261030.json).
  No target DLL ran. These tiny exported-name-visible fixtures are not a Tier R,
  G-U1..G-U8, different-image orientation, Windows or general accuracy claim.
- An initial native launch failed during JDK auto-selection under the read-only
  host home; successful attempts use the supported explicit JDK/restricted-env
  configuration. The failed project/log is retained in session scratch.
- Initial parallel full run: **18,290 passed, 49 failed, 9 errors, 126 skipped,
  7 xfailed** in 476.79 s. Socket creation was denied by the shell network sandbox;
  two subprocess cases resolved the symlinked venv interpreter to its unprovisioned
  base. A copied venv interpreter and explicit shell network capability made
  **36 environment rechecks pass**. The rule-export check still sees the sandbox's
  empty read-only `/tmp/.git` marker as a repository; no production protection was
  weakened to conceal that host artifact. A final complete run is pending.
- Prior #140 remote QA run [41152314039](https://github.com/djshellshoxxx/patchtrace/actions/runs/41152314039)
  failed on those two invalid A/A fixtures on both OSes; its Windows repeated-Qt
  leg also timed out in discovery. The discovery check passes **30 repetitions**
  locally, but that is not Windows confirmation and the remote gate stays open.

Remaining: final-source full suite, exact-head Linux/Windows QA and repeated Qt,
real native corpus workflow with evaluated denominators and all required G-U gates,
then reviewed integration and release acceptance. Advisory-green parents do not
establish child-job acceptance.
## GT-01 local repair checkpoint (2026-10-30, Windows)

Base: PR #140 b87193d1dd30635fce33986f80ceade136507a1a; isolated project venv, Python 3.14.5. Original 7-Zip quarantine inspection confirms 105,077,223 bytes of JSON against a 104,857,600-byte ceiling; hashes and limitations are in [the diagnosis](plans/gt01-native-output-diagnosis-20261030.md). Original files were preserved.

- Red reporting regressions: **7 failed, 2 passed in 54.13 s** against unchanged backend messages (both corrected A/A fixture orientations passed).
- Focused backend/harness selection: **74 passed, 4 skipped in 89.95 s** across test_jobs, test_unified_live_force_identical, test_unified_live_pairs, test_unified_live_pairs_r1, test_unified_live_workflow and test_unified_live_native_failure_details. Fake external processes are not native acceptance.
- Full repository Ruff and git diff --check passed.
- Isolated Windows Qt discovery reproduction: **1 passed in 31.34 s**. The earlier repeated-CI timeout remains unresolved; one pass does not establish stability.
- Full offscreen suite and a local installed-runtime native A/A smoke are running at this checkpoint. No completed full/native result is claimed. The smoke uses synthetic PE bytes and Ghidra 12.1.4/Ghidriff 1.0.0; it is not the pinned cross-platform G-U matrix.
- Required new-head Linux/Windows CI, repeated Qt, evaluated native G-U1–G-U8 and applicable independent review remain open. Workflow dispatch is blocked: connector has no dispatch operation, CLI has no authenticated session and the available browser is signed out. No merge or GT-01 completion is claimed.


### GT-01 concurrent-source reconciliation

The Windows coordinator advanced #140 to `fb91cff6d91c77a2c539c896b670d81180dcc637`
while the Linux repair was being verified. A guarded ref update did not move
that branch. Both append-only QA/todo sections and the Windows output-diagnostic
repair are retained in the local reconciliation. Combined focused backend/harness
checks: **87 passed, 3 skipped** in 7.34 s; Ruff and patch hygiene clean.
The complete Linux run started from the earlier `b705659` source snapshot;
it cannot attest the subsequent concurrent diagnostic changes. New combined-head
CI remains required. The independent extraction repair is published separately
so the active coordinator's branch is not overwritten.


## Complete combined continuation check (2026-10-30 Pacific)

Combined tested tree `fc27f77c9c822b114d3479bf36efe89aa2b32c17`:
**18,384 passed, 1 failed, 126 skipped, 7 xfailed** in 389.17 s. The sole
failure is the rule-export test observing the sandbox's read-only `/tmp/.git`
marker. Full Ruff and patch hygiene passed; schema regeneration changed no
schemas. Exact-head PR #141 native Windows Ghidriff run 41166712588 passed
all five scoped jobs. Actual Linux live-pair harness same-image controls
completed both orientations with known-endpoint unchanged outcomes. Neither
result establishes required corpus or full Windows release acceptance.
See [continuation verification](qa/continuation-verification-20261030.md) for
source-tree equivalence, native receipts, failed node, draft PRs and open gates.

## Matching/semantic continuation — October 30 Pacific / October 31 UTC

Candidate #144 builds on #143, preserves original #129/#131/#135 refs and combines
R2 matching/evidence/CFG repairs with R3/R8 semantic corrections. Extra integrated
regressions cover LLP64 signed-L radix, exponent floats, typed-key fact consumers,
and rejection of false machine anchors from type-only literal exchanges. Scoped
independent reviews approved after repairs. Latest combined focused selection:
136 passed; counts overlap earlier receipts and are not summed. Ruff passed and
schema regeneration produced no tracked schema changes. Stable-source full pytest
started at `c592b680eb1013f02c8472e544bbdb417e11fdde`; results pending here.
Native corpus/Windows package and release acceptance remain open. See the single
extended coordinator `docs/plans/milestone-ledger-20261030.md` and its linked
135-branch/100-registry-entry content inventory. No main merge, source deletion,
confidence promotion or target execution occurred in this continuation.
