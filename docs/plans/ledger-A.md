# Ledger A (Instance A: integration owner; unified engine, patch-intent, Pages, builds)

| Item | State | Evidence |
|---|---|---|
| E-0 Phase D wave 0 | merged 2026-10-14, prerelease v0.1.0-beta.202 | PR #42, 67e5a6c |
| Routine (12h) | created 2026-10-14 | trigger `trig_01CQuCdegLavS7fnxMULdyBS` (00:34Z / 12:34Z) |
| E-1 integration plans (KB, KB2, KEV, LBL, PIL, DIE, WB1-3, WBQ, CAP, YRX, GUI) | merged | PR #46, 0142c5d |
| UE S0a-FIX, S0b (registry, adapters, fusion, pipeline, CLI) | merged | PR #49, 98182e5 |
| UE S1 (Ghidra extractor, ingest, MD index, `retain_gzf`) | merged; live-unified green on Windows (MSVC DLLs) and Linux, cross-OS `content_digest` equal | PR #49 checks on 70be874 |
| UE S2 (pass ladder P00-P15, parity harness) | merged | PR #46 |
| PIL-A1 contracts, PIL-K1/K2 CSAF reports + `intelligence` CLI | merged | PR #46, PR #49 |
| K-FIX, AM1 (reserved KINDS, `text_anchors`) | merged | PR #46 |
| Pages tooling (`site/`, `tools/site/`, `pages.yml`) | merged; `pages.yml` was invalid YAML until PR #50 (67090de); its build steps ran locally in a clean venv, the first CI run waits for the owner to enable Pages; deploy needs owner inputs | owner: logo, Monero address, Settings > Pages > Source: GitHub Actions |
| Workflow YAML guard | `tests/test_workflows.py` checks every workflow for plain scalars with `: ` | PR #50 |
| Live L5 relation | redefined after the first MSVC run (A-27): export fidelity plus refinement, not class equality | `tools/live_unified_check.py`, `docs/qa.md` |
| BUNDLE (zero-download Ghidra + Ghidriff + Java + Python) | owner: C; PR #48 open | essential priority |
| Prerelease with the unified engine | published 2026-10-14 18:42Z: v0.1.0-beta.225 (main 98182e5): Windows zip 60,640,443 B sha256 05138b1fe480361d1b6d812de76635c6ae9cf39931e5a5da07f178449e191473, Linux tar.gz 89,535,839 B sha256 2fdb5ece075b63c32c9ec9d673d9f4171c5fd3fb8b201d526736f068956f15ae; Windows pytest 4884 passed, Linux 4891 passed, frozen smoke and Linux smoke 22.04 / 24.04 pass | run 38614929154 |
| Everything else (E-2 frameworks, UE S3-S6, PIL B-D, B and C feature tracks, E-4..E-6) | HELD until C reports "bundle done" | `program-e-roadmap.md` section 0 |

## Update 2026-10-14 18:30Z
- Weekly account limit is at `allowed_warning` (resets 2026-10-21 01:00Z): no Opus workers, no new waves while the bundle is open.
- Open owner items: logo file, Monero address, Pages source setting, Microsoft permission question for the MSRC fixture, Tier W runs, Windows desktop acceptance (DPI, NVDA, Narrator).
- Next on A after "bundle done": GUI panel registry + CLI-command registry, anchor fabric, UE S3-S6, PIL waves B-D.

## Update 2026-10-14 21:30Z: feature build phase and Haiku specs
- Orders: guided RE teacher deferred; 23 workers each on A and B, 12 on C; builds at every third milestone (slice RG); plan `program-e-execution-plan.md`, briefs `worker-brief.md` and `spec-writer-brief.md`.
- Wave 1 on A (18 build workers) running: GUI F1/F1b, RG, UE S3/S5/S6a, PIL T/A2/A3/B1, FAB-0, KEV K0-K1b, YRX R0-R2, WBQ S1-S2/S4/S7/S10. GUI F0 merged (b2b3c87). AI-FIX worker running.
- Haiku spec drafts landed on `claude/clever-clarke-s4nhi6` with registry rows (code-checked): SPEC-41 AI provider, SPEC-42 network egress and privacy, SPEC-43 app settings, SPEC-44 CLI umbrella, SPEC-45 accessibility baseline. C writes C9 preregistration + licences, SPEC-46 KEV, SPEC-47 YARA-X, non-goals, SPEC-49 BinExport/Ghidra-host ADR, then the registry refresh. SPEC-48 reserved for the anchor fabric.
- Follow-ups found by the spec drafts (schedule in E-4 or earlier): consent/socket-denial tests missing for Ghidriff symbol-off, accepted LLM send, keys never in settings or logs, calibration download and tier-R fetch (SPEC-42); CLI exit-code inconsistencies (partial 0 vs 3, zero results 4 vs 0, no bundle 4 vs 2, intel-tools delta complete with exit 2, timeout minimums 60 vs 10; SPEC-44 s8, owner decision); 54 controls without accessible names (SPEC-45; F5/F8 migration plus a sweep); settings-doc drift in `enrichment.md:145`, `bindiff-execution.md:12`, GUI plan l.120 and `provider/model` free text (SPEC-43); GUI F0 leftovers (WB2 G9 and WBQ section 10 seams, DIE D4, YRX C6 fallback, GDE G3 `cli.py` hook, phase-d rows 11-12).
- Harness fact: new worktrees start from `origin/main`, not from `work/a`: wave-2 prompts begin with `git merge --ff-only work/a`; Haiku spec workers leave files untracked (copy, add a registry row, commit).
- Open doc PRs #40, #41, #43 (ChatGPT, content already integrated by PR #46) now conflict with the F0 amendments: recommend the owner closes them.

## Update 2026-10-14 22:00Z: PR #52 merged, wave 2 and audit routing
- PR #52 merged as 5e9a021 (milestone 1 of 3 since beta.225): release gate RG, CLI registry F1b, GUI F0, WBQ S4/S10, PIL-B1, SPEC-41..45. Windows QA needed one fix (fixture line endings: `.gitattributes` `tests/fixtures/wbq/** text eol=lf`); one native job (`raw-cache-hit`) flaked once because `_java_version` returned unknown after its 15 s probe (re-run green; hardening suggested to C for `backend.py`).
- Merged on `work/a` for PR #53: PIL-A2/A3/T, WBQ S1/S2/S7, YRX R0/R2, FAB-0 core and FAB-2 converters, FAB plan amendments, KEV K0/K1a/K1b, GUI F1 (+ `cli_commands/panels.py`), random audit 1.
- Decisions: FAB `ir` maps to `D_ghidra` (no new independence tag), `emulation` is a group kind only, `capa` keeps the PIL single tag until CAP-7 (FAB open question 3); navigation stays in the GUI `NavigationPort`; SPEC-44 s8 stays "keep existing codes" (additive rule) until E-4.
- Random audit 1 (`docs/audits/random-audit-1-20261014.md`): 0 High, 4 Medium, 6 Low. Routing: RA-1/4/8/9/10 to RA-FIX-1, RA-2/5/6 to RA-FIX-2, RA-7 to AI-FIX, RA-3 (slow-drip in CSAF and enrichment transports, sibling of C-01) to B13.
- Running on A: UE S3/S4a/S5/S6a, WBQ S8, PIL-B2, YRX R1 and R3>R4, FAB-1>FAB-4, KEV K2>K6 and K4>K5, AI-FIX, CONSENT tests, RA-FIX-1/2.
