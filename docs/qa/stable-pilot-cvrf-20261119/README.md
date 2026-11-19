# Stable pilot/CVRF recovery — 2026-11-19

**Outcome:** bounded PR #314 recovery passes the affected Linux/offscreen suite: **2,009 passed, 0 failed, 0 errors, 0 skipped in 168.63 seconds**. Ruff over all source/tests/tools, pilot schema drift checks, and whitespace checks pass. Full combined hosted and native Windows qualification remain pending.

## Exact source and scope

- Base stable candidate: `d436a7ec571efa75dcd627ca9835c65f60e09c74`.
- Tested code head: `cd96aa9183d1c28c0d08da0198b515f9ab87f29e`.
- Tested code tree: `f83652cbc189ab02867410e072c8d8c771b4f083`.
- Original PR #314 head: `b41d6631e679ad2777d248fa087ea71582a5bf63`.
- Later staging ownership source: `028a67abc5c1a48ef27f9d218179ce095bead798`, with its regression/specification `fbd47d097a9fdf6ba22a023ab2ba5fe0fb08a373`.
- Recovery: 13 original source/spec/test commits, two staging ownership commits, then the one owned CVRF fixture adjustment.

The recovered behavior shares owner-thread current-evidence capture across production pilot reads, publication, desktop navigation, and report/2 exports. Historical assessments and analyst reviews remain readable. Retained CVRF fields can supply documentary context outside the CSAF universe; CSAF keeps precedence, malformed/unavailable context is withheld, and source identity, complete-row metadata budgets and current evidence are checked without reopening the project.

Nine runtime files match the reviewed original #314 source or the required later staging ownership repair byte-for-byte. Five protected baseline files remain unchanged: KB context construction, finite saved scope, KB service, advisory storage, and the shared publication helper. The source-map JSON records their exact Git blobs. No inventory CLI/dialog/store or native research caller changes were imported.

The internal advisory port changes without a persisted model change. Existing pilot schemas and examples remain current according to the generator check.

## Source/spec/test commit mapping

| Original source | Recovered commit | Purpose |
|---|---|---|
| `f3cf68dbfecd254e5e5acefb02f82922f4091bf5` | `9b7c27cb41f5772125328690544e653a4b6f1287` | test(pilot): specify current assessment ownership and staleness [no release] |
| `328a3a363cfe6ffe2334eccfab71c72dc456eea7` | `2e3983ecbec1d77c521739dafb8f522d53812007` | fix(pilot): recheck assessment ownership and current evidence [no release] |
| `8ace1999ff6e83369963e0c3bc9690f7f16ff2f9` | `59b93c7a857d19fbced11260a2c8b74ef08d4817` | test(report): require current pilot evidence at export [no release] |
| `c3a09b43175bcd023596c1dcd7c083be5d5434b9` | `13a88a7457d5b81302bfbd728366fa1afc7f792a` | fix(report): share pilot current-evidence checks [no release] |
| `8291396f92a1b577027270c88c43c90bcdc393c9` | `7b19299e69a7e9b7cc9341c7b4de190c36423db3` | spec(pilot): define retained CVRF fallback and refusal controls [no release] |
| `35a0dd44dedb56019d9fc93ee652c692b12a2b0a` | `01cd27c148afcf4ecd1e80b95ebefe641803ea8d` | feat(pilot): consume bounded retained CVRF context with CSAF precedence [no release] |
| `4c231c558c6fe4ea62dfc0df98454e109ce19b02` | `31a8d45dbdc704fa101e889d8a027a13075aaa91` | spec(pilot): refuse malformed retained SQLite row types [no release] |
| `870287f2f54fbf9e5715cc256ea5a98ea2646319` | `e22ee86de1ce630b15c3c635f7a6e429bea85e2d` | fix(pilot): withhold malformed retained SQLite primitives [no release] |
| `2b197589da370be204499c02c69b4545d115527f` | `50b642b67bea566c335c4853184edb38d90ed433` | test(pilot): require retained CVRF identities on current assessment reads [no release] |
| `dfa0be3f4c99dcae8ff16bd6635d4b89114c0565` | `a04a336446d776ba2611e519736add48c5b0ea4c` | test(pilot): persist context withdrawal for independent child reads [no release] |
| `d1a7998ac520d1a77eef09303d1e83e3d2eadde2` | `9d86d9fa7dcbeb37decc6757caaa79ac9dc69dee` | fix(pilot): compare retained CVRF identity in current assessment capture [no release] |
| `c6723e64cffb5210eafd2ec449baff82a088d4c8` | `2ac68a800b8a336cc3db897e3270f06c5ca51af1` | spec(pilot): cap all retained context fields before loading [no release] |
| `402d47eeedb3628ed22ad9aa18d5c2d2cdafd03c` | `94d3a864348316901f09504ae2944d44a8c2f529` | fix(pilot): include retained row metadata in capture budget [no release] |
| `fbd47d097a9fdf6ba22a023ab2ba5fe0fb08a373` | `e605fb76aea6fc56d4502fffbc685e9d4688d344` | test(pilot): require staging creation ownership before cleanup [no release] |
| `028a67abc5c1a48ef27f9d218179ce095bead798` | `add9fc9deb453f0df71afed40f5eeec6641679d7` | fix(pilot): preserve unowned staging paths on failed creation [no release] |
| `a07fc1cf1c8d618d8d4b451888c286815a4e02de (fixture hunk only)` | `cd96aa9183d1c28c0d08da0198b515f9ab87f29e` | test(pilot): retain saved-scope coverage in CVRF fixture |

The last fixture change supplies its real reverse-index coverage to `context.build_bundle`. It preserves the #317 production saved-scope refusal contract. Other files from that multi-feature fixture commit were not recovered. Every full cherry-pick applied without conflict and retains the original author and source trailer.

## Fresh validation

| Check | Result |
|---|---|
| Pilot, Leads, report2, advisory storage/CLI/explain, saved-scope and shared publication controls | 2,009 passed; 0 failures/errors/skips; 168.63 seconds |
| `python -m ruff check src tests tools` | PASS |
| `python tools/generate_pilot_schemas.py --check` | PASS; no persisted schema drift |
| `git diff --check` | PASS |

Exact affected command:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src /workspace/scratch/80dddc5347b2/patchtrace-venv/bin/python -m pytest -q tests/test_pilot*.py tests/test_ui_leads*.py tests/test_report2*.py tests/test_advisory_read_bounds.py tests/test_intel_storage.py tests/test_intel_cli.py tests/test_intel_explain.py tests/test_kbc_saved_scope*.py tests/test_kbc_card_context_sources.py tests/test_owned_publication.py --junitxml=/workspace/scratch/80dddc5347b2/pilot-cvrf-targeted.xml
```

Runtime: Python 3.12.14, pytest 9.2.0, PySide6 6.12.0, pydantic 2.13.5 and Ruff 0.17.5 on Linux 6.18.57 x86_64/glibc 2.41. `PYTHONPATH=src` selected this worktree; recorded module paths confirm that selection. Qt ran with `QT_QPA_PLATFORM=offscreen`.

The suite exercises current-input changes, retained CVRF admission and precedence, malformed SQLite primitives, whole-row metadata bounds, read-only restoration, stale report omission, action-time navigation refusal, staging collisions, and interruption cleanup. These are authored-data and local filesystem controls. CLI subprocess checks do not constitute live provider or native analysis compatibility evidence.

## Historical receipts and analyst help

`historical-evidence-manifest.json` pins 24 original files totaling 532,703 bytes, copied byte-for-byte from the #314 head and #316 staging follow-up. Each record includes the original commit, Git blob, SHA-256 and size. The prior red/green logs, exact-source manifests, malformed-row/budget failures and independent reviews are retained unchanged. Their old results are not claimed as fresh current-candidate results.

Help in `docs/help/70-cli-pilot.md` recovers the source-authored retained KB/CVE continuation, uncertainty and staleness explanation. The matching cross-link in `docs/help/67-cli-kb.md` was inserted against the current stable help without adding the separate inventory workflow. No broad historical completion ledger or old QA/todo status was substituted for the current records.

## Qualification limits

- The parent integration owns the full application suite, required hosted checks, combined Qt repeats, and final head-qualified review.
- No native Windows filesystem, desktop or package acceptance was performed here. Linux/offscreen results do not qualify Windows.
- No live provider retrieval, real CVE attribution, native engine accuracy, or downloadable release acceptance is claimed.
- Global total advisory-store I/O, broader sidecar publication races, and per-revision archival behavior remain outside the recovered source scope.
- PR #307 broad inventory/native caller work and the rest of mixed PR #316 remain outside this port.

The evidence files are committed separately from runtime/spec/test changes. No remote mutation, branch deletion, force push, or check bypass was performed.
