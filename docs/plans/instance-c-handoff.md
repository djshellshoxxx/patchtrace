# Instance C handoff (2026-10-15): what is done, what is open, how to work

Audience: another assistant (for example ChatGPT) or a human picking up the Instance C tracks (label training, specs, user guide, audits). It cannot run the repository, so everything below says where to look and what to hand back. Read `AGENTS.md` first (authoritative policy), then `CLAUDE.md`, then this file.

## 1. Rules that never bend

- Never execute a target binary. Never upload anything without operation-specific consent and an exact preview. Never fabricate unavailable evidence.
- Calibration display stays `ordinal` unless a valid artifact passes its gates. Synthetic-corpus (Tier R) results never claim real-world accuracy. No percent or probability shown to users.
- Microsoft-derived data, and anything built from Microsoft binaries, is never committed.
- Mocked tests are never live evidence. Report blocked external acceptance separately from automated evidence.
- No skip or release markers (`[skip ci]`, `[release]`) in any commit message, PR title or squash message. Never push to a branch you do not own. Never force-push.
- No TOFU pins: pins are verified (sigstore, GPG, or a deterministic rebuild), never recorded from "whatever we downloaded".
- Do not publish a final release.

## 2. What is on main from Instance C

| Area | Where | Notes |
|---|---|---|
| Tier R known-answer corpus factory | `tools/calibration/tier_r/`, `tools/calibration/mutations/`, `.github/workflows/corpus-tier-r.yml` | 13 project recipes under `tier_r/catalogue/recipes.d/`, release cards under `releases.d/`, CVE list `cves.json` |
| Statistics and scoring helpers | `tools/calibration/evalcore/` | hardened in #55 |
| Honest-scope policy | `tools/calibration/` `scope`, `ledger`, `context`; `docs/audits/20261014-C-label-training.md` | |
| Training driver and shift ladder | `tools/calibration/train.py`, `shift.py`, `report.py` (`TIER_R_CLAIM`) | merged #66 |
| mbedtls 3.6.0 to 3.6.1 card | `tier_r/catalogue/*mbedtls*`, `cves.json` | merged #75; 3.6.1 to 3.6.2 not added (CVE-2024-49195 needs `MBEDTLS_USE_PSA_CRYPTO`; default recipe shows 0 changed functions) |
| Backend bundle licence gate | `tools/backend_pin.json` `license_policy`, `tools/build_*.py`, `docs/notices.md` | owner approved shipping the Temurin JDK on 2026-10-15; Ghidra `GPL/**` stays stripped; Ghidriff stays a separate unmodified GPL-3.0 component |
| Pin verification | `tools/verify_backend_pins.py` | sigstore / gpg / deterministic git rebuild |
| Codex audit-2 follow-ups | `tests/test_codex_pkg_*.py`, workflows, `pyproject.toml`, `docs/notices.md` | CODEX-2, 3, 4, 7, 8, 10, 11, 12 fixed (#74) |
| Audits | `docs/audits/20261014-C-*.md` | open findings are routed to owners in each file |
| Specs | `docs/specs/program-e/` (E6, OUTSTANDING ledger, SPEC26D2, WIN, GHR, RPT2), SPEC-46/47/49/55 | next free SPEC number is 56 |
| Ledger | `docs/plans/ledger-C.md` | append-only status log |

## 3. Open items (pick one; each is independent)

Each item says what to hand back. Hand back whole files (full replacements), not diffs, so they can be pasted in one go.

1. **C9 preregistration** (`docs/plans/c9-preregistration-v1.md`). Open: questions Q1 and Q2, and the SHA placeholder (the code reads it at `tools/calibration/run_locked_test.py` near line 21). The SHA is computed from the committed file, so a human or Claude Code records it after the text is final. Hand back: the completed document text with Q1/Q2 answered as recommendations plus the exact wording the owner must sign off. Do not claim the lock is done.
2. **`_java_version` timeout and retry** (`src/patchtrace/backend.py`). On a slow first start the probe can time out. Hand back: the full replacement function, a bounded retry (for example 2 attempts, increasing timeout), and one pytest that fails before and passes after, in the style of the neighbouring tests.
3. **CODEX-1, 5, 6, 9, 14** (see `docs/audits/codex-workflows-1.md`, `docs/audits/codex-packaging-1.md`; the tests are the strict xfails in `tests/test_codex_pkg_workflows.py` and `tests/test_codex_pkg_packaging.py`). 1 is pinning remote GitHub Actions by commit SHA (each SHA must be verified against the action's tag, not guessed), 5 pip downloads with hashes, 6 corpus cache must not skip verification, 9 see the audit, 14 Linux package full CLI smoke. Hand back: for each, the full replacement workflow or script text, the removal of the xfail mark in the same change, and a list of every SHA or hash you could not verify.
4. **Label training, next slices** (`docs/plans/lbl-remaining-plan.md` on branch `claude/instance-d-gui` until merged; `docs/specs/program-e/LBL-integration-plan.md` on branch `claude/clever-clarke-s4nhi6`). D owns slice 11 (scoring), the libdeflate/stb/c-ares recipes and the `csrc` `extern "C"` fix; do not duplicate those. Free: 06 mutation operators (a worker is doing part A), 07 IR/opt mutations, 14 `ci_summary.py`, 18 GUI scope line, 19 reports and `calibration status`, 20 to 25 Tier W (Windows-binary evaluation, self-made fixtures only), plus a PSA-enabled mbedtls recipe variant. Hand back: a spec or code for one slice at a time with its tests.
5. **Tracker hygiene** (`tasks/todo.md`): collapse duplicate lines (series window, 3c/3d, the SPEC-31 decision line appears with U-01..U-10 and U-01..U-12), and close "Reconcile SPEC-07 with the supplied handoff package" by decision (the package was never supplied). Hand back the full edited file.
6. **Spec text gaps** in `docs/specs/program-e/OUTSTANDING-specs-ledger.md` sections 3 to 5: F1 (series window should become a dock), F7. Hand back full replacement spec sections.

## 4. Do not start

- The real Tier R training run. It needs, in order: scoring (slice 11), the pre-lock audit (slice 26), the preregistration lock with owner sign-off, then one locked look. A premature run burns the single look.
- GDE (guided-RE teacher) code. Deferred by the owner; commits on a local branch are not to be merged.
- Anything that dispatches `.github/workflows/backend-bundle.yml` (Instance D drives it).

## 5. How work lands (for whoever applies it)

One small PR per item, from a branch you own, to `main`. Run focused tests locally (`python -m pytest -q <files>`, `python -m ruff check src tests tools`), rely on CI for the full Linux and Windows gates, and squash-merge only when every check is green (use the expected head SHA). Append a short entry to `docs/plans/ledger-C.md` for each merge. Report exact test output, PR links and open gates; never claim a successful release.
