# Cycle4 initial exact-source and evidence audit

Independent auditor: `cycle4_record_audit`. Inspection completed on 2026-11-21 UTC.
This audit read Git objects, receipts, JUnit files, wheel metadata/bytes and evidence
manifests. It did not rerun repository tests, install packages, execute analyzed
targets, mutate coordinator source or write any remote resource.

## Result

**No blocking factual, source-binding, test-accounting or evidence-integrity finding
in the inspected local records.** One early receipt has a potentially misleading
label; its actual command must be described precisely below. Final archive,
ledger, publication mapping and live-ref validation remain a subsequent step.

Machine-readable checks: `record-audit-evidence/initial-checks.json`.
Reproducible read-only checker: `record-audit-checks.py`.

## Exact source and preserved scope

| Role | Commit | Complete tree |
| --- | --- | --- |
| Published baseline | `11f51c105bf63946f59373ae605b937c4fee607a` | `4939056ceb0e02b419c820b9e5748c869c40a857` |
| Reviewed Build environment integration | `b65fba2f5567f0b129331364bbf6db1cd699c901` | `889c6383fb4d231fd6698b71511214e8c9c8fac0` |
| Reviewed Pages author source | `305d2d10fafeb4a7c8e566cdd0a3f67cccd97ec1` | `9bb0dd33372693c0ccf3836d39c97d7c6afca94f` |
| Combined tested source | `8c5e77e2c1ad3f6cfa62c2e474f7bcc2f4af1dd5` | `6fe242cc10a5e7c3afe74c40a0f701cbab73aef1` |
| Documentation correction inspected | `36584f8153983d64605dd7f4141e88c9fabfa6ef` | `377a07bdde10a13bb46b0f5bef5c2b96af9d7210` |

All eight changed code/test/workflow/lock blobs in the combined tested source and
documentation head equal their corresponding reviewed sources: the two Build
environment production modules, its regression file, the global tooltip audit,
the Pages workflow, dependency lock and two Pages test files. The change from
the tested source to the documentation head affects **only `site/README.md`**.

The ten local commits and their ordered parents are retained. Both author
histories remain ancestors through explicit merge parents. Their contract commits
precede regression and implementation commits. No history rewriting was found.

`service.py`, `persistence.py`, `search/qt_panel.py`, `tests/conftest.py` and
`pyproject.toml` are byte-identical to the baseline. The Pages Action `uses:`
references are unchanged. The local diff is confined to the assigned header-help
and Pages install/test scopes, their specifications and README text. Local Git
evidence cannot by itself prove the absence of every remote mutation by other
sessions; the coordinator must retain its fresh prepublication ref/ownership
observation. This auditor made no remote writes or workflow calls.

## Test identities and accounting

The final JUnit file contains **393 unique identities: 391 passed and 2 expected
failures**, with no errors, ordinary failures or ordinary skips. The receipt
records clean source `8c5e77e2…` before and after the run. Its two expected failures
are exactly:

- `tests.test_codex_pkg_workflows::test_remote_actions_are_immutable` — CODEX-1.
- `tests.test_codex_pkg_workflows::test_pip_downloads_require_hashes` — CODEX-5.

| Retained observation | Actual result | Identities overlapping the final selection |
| --- | --- | --- |
| Build environment missing-help baseline | 14 failed, 1 passed | 15 |
| Build environment implementation regressions | 15 passed | 15 |
| Author affected selection before host-audit integration | 124 passed, 1 failed | 110 of 125 |
| Integrated Build environment selection | 132 passed | 132 |
| Independent global registry positive control | 1 passed | 1 |
| Independent removed-Basis control | 1 deliberate failure | 1 |
| Original site-only workflow command | 1 setup error | 1 |
| Same-source site-only fixture-isolation diagnostic | 243 passed, 1 skipped | 244 |
| Final Pages site-only selection | 247 passed, 1 skipped | 248 |
| Pages contract baseline before implementation | 4 failed | 4 |

The 15 author identities outside the final selection are the unchanged
`tests.test_gui_tips` cases. Their passing author evidence remains valid at its
recorded source, but they are not part of the final **391**. Do not sum author,
reviewer or diagnostic counts into that total.

The Pages-only skip is the existing
`tests.test_site_screens::test_renderer_draws_the_real_gui_offscreen`, caused by
deliberately absent PySide6. That same identity **passed** in the combined full
dependency environment. This establishes the precise local distinction and does
not establish native Windows accessibility acceptance.

### Receipt-label precision

`root-evidence/buildenv-host-audit-baseline.json` actually invokes
`test_main_window_every_action_and_control_has_a_registry_tooltip`. It does **not**
invoke the modified `test_every_registry_id_is_applied_somewhere`, so its one pass
must not be used as evidence that the new Build environment host activation ran.
The later 132- and 391-case selections include the modified audit, and the
independent positive and missing-Basis controls directly exercise it. The source
change is therefore qualified despite the early receipt's broad label.

## Dependency and installation evidence

All seven retained wheel files were independently rehashed and compared with the
committed lock, their saved version-specific PyPI JSON, expected sizes and wheel
`METADATA` identities. All checks passed; the selected upstream files are not
marked yanked. Marker evaluation for CPython 3.12/Linux x86-64 yields exactly four
active dependency edges from pytest to iniconfig, packaging, pluggy and Pygments;
all are satisfied by the lock. Six wheels are platform-independent; Pillow is the
recorded CPython 3.12 manylinux 2.27/2.28 x86-64 wheel. No broader platform claim is
supported by this evidence.

The actual positive pip command includes `--require-hashes`,
`--only-binary=:all:`, **`--no-index --find-links`** and the checked-in lock. It
therefore establishes a real installation from the verified local wheelhouse,
not hosted PyPI index-resolution acceptance. The initial environment contained
only pip. Its final isolated `python -I` receipt contains pip plus exactly the
seven locked distributions and confirms that pydantic, PySide6 and installed
PatchTrace are absent.

The wrong-Pillow-hash control exits 1 with the intended expected-versus-actual
SHA-256 error. The missing-pluggy control exits 1 because hash mode refuses its
unpinned transitive requirement. Their separate fresh environments retain only
pip afterward. These deliberate refusals are positive control evidence, not
unresolved candidate failures. The original pydantic setup error and four
preimplementation source-contract failures remain intact.

The real site build exits 0 and reports five existing screenshots. Its logo and
donation warnings describe the already absent owner logo and empty configured
address; no material was invented. Other unhashed workflow lanes remain open;
the global CODEX-5 expected failure remains in the tested source.

## Integrity and remaining publication checks

Twenty-eight command receipts have matching Git trees, clean before/after status
and unchanged source heads. All 30 payloads across the three Build environment
loose manifests verified. Both worker archives have exact membership and valid
per-payload sizes/SHA-256 values:

| Archive | Payloads plus manifest | Bytes | SHA-256 |
| --- | --- | --- | --- |
| `codex5-research-evidence.zip` | 19 + 1 | 209,264 | `00fe3991af2ea6973fa015e1ec77f8357f524a3f8ef3bd001f7769885769305a` |
| `pages-implementation-evidence.zip` | 26 + 1 | 20,876 | `eed5fcdd73b40dffc6bf667aae5f4c079b97df9db395087bc86d75f9c8952de8` |

The final record audit should check the assembled archive/ledger and publication
mapping against these frozen observations, retain any final coordinator Ruff,
dependency and source-binding receipts, and verify the original source bundle.
Hosted qualification, native/manual acceptance, the parallel owner's integration
and CODEX-1 work, and all broader release gates remain separate. Nothing in this
local record audit authorizes a main merge, release or deployment.
