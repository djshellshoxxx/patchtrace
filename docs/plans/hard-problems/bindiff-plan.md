# Real BinDiff execution plan (C4), ordered

Date 2026-10-14. Inputs: `docs/specs/bindiff-execution.md` (spec, SPEC-29), `docs/research/phase-c/bindiff-automation.md` (research "R", item numbers C1..C17 and U1..U11 refer to it). Triage: `bindiff-troubleshooting.md`. Evidence: **[M]** measured on the real BinDiff 8 Linux CLI in the research session; **[H]** unconfirmed.

## 0. Key new facts that change the plan
1. BinDiff 8 can be provisioned and run **without root on Linux today** (`dpkg-deb -x`, 62.7 MB, runs under `env -i`) [M]. The spec's "blocked: no BinDiff" state is only true for Windows now.
2. Pin values exist (R section 5): sizes and SHA-256 of `.deb` and `.msi`. Upstream publishes no digest, so the pin is trust-on-first-use of one download until a human re-hashes from a second network path and verifies the `.asc` (issuer key id `4EB27DB2A3B88B8B`, public key not yet obtained).
3. A SIGKILLed run leaves a **valid-looking partial `.BinDiff` plus `-journal`** (R C10). The importer must never see output from a stopped run.
4. User config at `~/.bindiff/bindiff.json` silently changes results (similarity 0% in a test); `--config` with `{}` neutralises it (R C6). The spec's isolation design is validated.
5. Exit code 0 does not prove a result exists (no inputs prints help and exits 0).

## 1. Ordered steps

| # | Step | Decision point | Acceptance (measurable) | Fallback |
|---|---|---|---|---|
| S0 | **Docs PR** applying spec edits (section 4 here) and filling `tools/bindiff_pin.json` with the R section 5 values, `verified:false` until S2 | none | Spec diff reviewed; pin has url/size/sha256 for linux and windows; `provision_bindiff.py` dry-run fails closed only if hash differs | Keep nulls (current behaviour) |
| S1 | Fake-exe harness + failure taxonomy (spec P3) | none | Every kind in spec section 6 reachable; argv equality test; env allowlist test; `spawn-grandchild` dies; no stderr path leak | none |
| S2 | **Provision on Linux CI** (`provision_bindiff.py --os linux`: download, size+sha256, `dpkg-deb -x` into cache, locate `bin/bindiff`, resolve symlinks) | D1: accept trust-on-first-use pin? Human re-hash from another network + `gpg --verify` with the maintainer key | Job logs version string `BinDiff 8 (@568181968, Sep 25 2023)`, exit 0; second run hits cache; sha mismatch -> `failed(provision)` not `blocked` | If download blocked: status `blocked`, tests use fakes + committed golden |
| S3 | **Live probe + run (Linux)**: `probe()`, then `--output_format=bin` on a committed BinExport pair | D2: which pair (see section 3) | `import_bindiff` accepts output; matches > 0; `file.hash` pair equals artifact hashes; exactly 1 file in `out/`; no `*-journal`; `unshare -rn` run passes; `HOME` dir contains only `.bindiff` | If BinDiff rejects the pair: regenerate with Ghidra BinExport once (section 3) |
| S4 | **Windows provision spike** (`windows-latest`): try `msiexec /a bindiff8.msi /qn TARGETDIR=...`; if `bin\bindiff.exe` absent try `lessmsi`-free fallback `msiexec /i ... INSTALLDIR=` on the ephemeral runner | D3: admin extract vs ephemeral install | Records: path of `bindiff.exe`, exit codes, runtime DLL load (`--version` exit 0), VC++ runtime present on runner image | Ephemeral install (accept PATH/Run-key side effects on the throwaway runner); never on dev machines |
| S5 | **Windows live run** with the same pair | D4: console output encoding and `ProgramData` read | Same assertions as S3 minus `unshare`; `Procmon`-free check via second run with `PROGRAMDATA` pointing to an empty dir, same result | If exe fails to start: `probe-failed` with exit code hex; add redist install step in CI only |
| S6 | Importer gaps (spec P4): `max_page_count`/`cell_size_check`, progress-handler deadline, per-table row caps, hostile-DB fuzz | D5: caps (rows) | Hypothesis 2,000 examples on header/schema/value mutation: only `SecondaryError`; golden from S3 imports in < 2 s | none |
| S7 | Interruption safety: kill-mid-write test on both OSes | none | Test starts real BinDiff on the 100k-function synthetic pair (R section 6), kills at first byte of output, asserts status `cancelled`, no match set stored, workdir removed | n/a |
| S8 | Resource baseline on a real driver pair | D6: memory cap (spec D10) | `docs/qa.md` row: wall, peak RSS / PeakJobMemoryUsed for one real ~1-10 MB pair; if RSS > 2 GiB for a 10 MB BinExport add `memory_limit_bytes` (Job `JOB_MEMORY` / `RLIMIT_AS`) | Keep timeout only, document |
| S9 | Make `live-bindiff` required after 10 green scheduled runs (spec section 10) | D7: product owner | 10 consecutive green weekly/dispatch runs on both OS | stay advisory |
| S10 | Golden `.BinDiff` + stdout + README provenance committed | none | files <= 200 KiB, README lists tool version, argv, input hashes, date | none |

## 2. Decision points (recommended answers)
- D1 trust-on-first-use: accept for alpha because the artifact is only parsed by our hardened importer after running in a contained child; escalate to a second-path hash + signature check before beta.
- D2/D3/D4 resolved by live data in S3-S5; do not code Windows specifics before S4 output exists.
- D5 row caps: `function`, `basicblock`, `instruction` <= 20 M rows total; reject above, report LIMIT.
- Spec D11 (refuse non-SHA-256 `executable_id`) stands; revisit only after U9 data.
- Config: always pass `--config=<workdir>/bindiff.json` containing `{}` and a private HOME/USERPROFILE.

## 3. BinExport inputs for CI
Preferred: a maintainer-generated pair from our compiled fixtures via Ghidra headless (`analyzeHeadless <proj> <dir> -preScript BinExport.java <out>` per BinExport README), committed with provenance, <= 1 MiB. Interim (works today): generate a pair with a ~60-line stdlib wire-encoder (functions with distinct mnemonic sequences, call edges, `executable_id` = SHA-256 of the artifact bytes); R U10 shows BinDiff 8 accepts such graphs and produced 20/20 matches. The encoder lives in `tests/` (not `tools/`), with the real-BinExport golden as the authority once available.

## 4. Spec edits to make in S0
1. Section 2 probe: `--help` exits **1** (accept 0/1, already allowed); `--version` text sample `BinDiff 8 (@568181968, Sep 25 2023)`; resolve symlinks and execute the resolved path (the `.deb` ships `bin/bindiff_ui -> bindiff`).
2. Section 4.2 env: document that `HOME/.bindiff` is created and read; no `FLAGS_*`; `--flagfile`, `--fromenv`, `--tryfromenv`, `--undefok` are forbidden flags (extend the argv-equality test and the "never passed" list).
3. Section 4.3 guard: tolerate a transient `older_vs_newer.BinDiff-journal` in `out/` during the run; after exit 0 it must be absent (otherwise `output-ambiguous`).
4. Section 4.4: add "exit 0 without output means help was printed" (R C3); and "any non-clean stop (timeout, cancel, kill, output-limit) discards `out/` unread" (R C10).
5. Section 7.2: importer layers list gains `max_page_count`, `cell_size_check`, progress deadline; remove the wording that triggers/views are a "new hardening" (done in code).
6. Section 12: replace U1, U3-U7, U11 with the R section 9 answers; keep U2, U8, U9, and the Windows halves live-only. Remove `[inf]` on `--config {}`.
7. D5 Windows: record the MSI layout (`ProgramFiles/BinDiff/bin/bindiff.exe`) and that the exe needs the VC++ 2015-2022 x64 runtime; add `redist` to the preflight list.
8. D1: strengthen rationale with the measured fact that `bindiff.jar` embeds the yFiles `y/` classes and that the `.deb` copyright text is ambiguous.
9. Section 3 note: output name derives from the input *file name*, truncated at 250 characters including directory (keep workdir short on Windows).

## 5. Risks
| Risk | L | Impact | Mitigation |
|---|---|---|---|
| Pin trust-on-first-use | M | supply-chain | S2 human re-hash + signature; cache keyed by hash; never run as admin on a developer box |
| Windows exe missing runtime / MSI admin extract yields no CLI | M | no Windows live proof | S4 spike first; ephemeral install fallback; if impossible, Windows acceptance stays `blocked` with a recorded reason, Linux proves the engine |
| Partial output imported | L | wrong evidence | S7 test; only accept after clean exit 0 and single file |
| Memory blow-up on large drivers (about 18x input) | M | host OOM, slow CI | S8 measurement, cap, `max_parallel <= 2` |
| User/machine config alters results | L | silent wrong matches | `--config {}` + private HOME; record `config_sha256` |
| AV locks `out/` or `bindiff.exe` on Windows | M | spurious failures | retry cleanup, never block result status; troubleshooting file |
| Upstream flag drift in v9 | L | probe unsupported | feature probe on `--help` text, `untested_version` flag |
| yFiles/JRE licence if bundled later | L | legal | keep D1 (no bundle) |

## 6. What only a live install can answer, and how CI captures it
| Question | Captured by |
|---|---|
| Windows run, exit codes, console encoding, VC++ runtime, `msiexec /a` layout | S4/S5 job writes `build/live-status/bindiff-windows.json` (status, bindiff path, `--version` text, exit code hex, DLL-load error if any) and uploads it |
| Real-driver runtime/memory (U8) | S8 job records `wall_ms`, `peak_rss` (POSIX `resource`), `PeakJobMemoryUsed` (Windows) into the same JSON and the step summary |
| Exporter `executable_id` formats (U9) | a Ghidra-produced BinExport committed once; test asserts 64-hex; IDA/Binary Ninja stay unknown, `binexport-unbound` is the user-facing result |
| Windows config path and network (U5/U6) | second run with `PROGRAMDATA`, `APPDATA` pointed to empty dirs; assert identical match set; firewall check is manual (noted in `docs/qa.md`) |
| Upstream signature | one-time human step, recorded in `tools/bindiff_pin.json` (`signature_verified_by`, date) |

## 7. Fallbacks if BinDiff cannot be provisioned in CI
1. Fakes + committed golden `.BinDiff` (from S3 once) keep the merge gate green; job reports `LIVE ACCEPTANCE BLOCKED: bindiff (reason)`, never a silent skip.
2. Linux-only live acceptance (works today) with Windows `blocked`: acceptable for the alpha, tracked in `docs/qa.md` and `tasks/todo.md`.
3. Self-hosted or cached artifact: upload the verified `.deb`/`.msi` to a private cache keyed by SHA-256 (no redistribution outside the repo owner's CI).
4. Build from source (Apache-2.0, needs BinExport 12, Boost, CMake; CLI only, `-DBINEXPORT_ENABLE_IDAPRO=OFF`): last resort, slow, only when upstream assets vanish.
5. User-run mode: the app still imports a user-produced `.BinDiff` (`secondary import-bindiff`), so the feature degrades to import-only.

## 8. Status after the C4 follow-up (2026-10-14)
- S0 done: section 4 items 1-9 applied to SPEC-29, code and tests; pin filled (trust-on-first-use, `verified:false`).
- S2/S3 done **locally on Linux** (not yet on GitHub): stdlib provisioning, probe, end-to-end via `run_engines` + `BinDiffAdapter` on the synthetic encoder pair (`tests/bindiff_live_pair.py`, D2 answered: synthetic until a repo-owned real pair exists), `unshare -rn`.
- S7 done locally: cancel at the first output byte and a 0.5 s timeout on a 50k-function synthetic pair discard the partial output unread (live checks), plus fake-based tests for cancel/timeout/SIGKILL.
- S10 partly done: real v8 `.BinDiff` + stdout on the synthetic pair committed with provenance; a golden from real-driver exports is still open.
- S6 partly done: `cell_size_check`, `max_page_count`, progress deadline; per-table row caps open.
- Open: S4/S5 (Windows leg runs advisory: records `blocked`/unverified instead of failing), S8 (real-driver resources), S9 (promotion after 10 green runs), D1 second-path re-hash and `.asc` verification.
