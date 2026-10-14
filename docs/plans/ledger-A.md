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
| Pages tooling (`site/`, `tools/site/`, `pages.yml`) | merged; `pages.yml` was invalid YAML until the fix below; deploy needs owner inputs | owner: logo, Monero address, Settings > Pages > Source: GitHub Actions |
| Workflow YAML guard | `tests/test_workflows.py` checks every workflow for plain scalars with `: ` | pages.yml fix |
| Live L5 relation | redefined after the first MSVC run (A-27): export fidelity plus refinement, not class equality | `tools/live_unified_check.py`, `docs/qa.md` |
| BUNDLE (zero-download Ghidra + Ghidriff + Java + Python) | owner: C; PR #48 open | essential priority |
| Everything else (E-2 frameworks, UE S3-S6, PIL B-D, B and C feature tracks, E-4..E-6) | HELD until C reports "bundle done" | `program-e-roadmap.md` section 0 |

## Update 2026-10-14 18:30Z
- Weekly account limit is at `allowed_warning` (resets 2026-10-21 01:00Z): no Opus workers, no new waves while the bundle is open.
- Open owner items: logo file, Monero address, Pages source setting, Microsoft permission question for the MSRC fixture, Tier W runs, Windows desktop acceptance (DPI, NVDA, Narrator).
- Next on A after "bundle done": GUI panel registry + CLI-command registry, anchor fabric, UE S3-S6, PIL waves B-D.
