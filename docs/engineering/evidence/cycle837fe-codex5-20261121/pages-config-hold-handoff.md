# Pages configuration hold repair

## Frozen candidate

- Head: `0cdd5bf37130206c2ddec399450be6338ae8e4fd`.
- Tree: `6d532dd606a1fdf987245a03271970758a03fe57`.
- Exact parent: `5b5328ee83ee4990b3311f7ac90e2f5e5f76f800`.
- Worktree: `/workspace/scratch/837fe19aae3a/repair-pages-config-hold`.
- Branch: `codex/patchtrace-pages-config-hold-20261121-837fe`.
- Isolated environment: `/workspace/scratch/837fe19aae3a/pages-config-hold-venv`.
- Commit contains both `[no release]` and `[no deploy]`; worktree is clean.

Owned delta is exactly `.github/workflows/pages.yml`, `docs/specs/pages-deployment-control.md`, its existing `docs/specs/REGISTRY.md` row, and `tests/test_site_workflow.py`. The workflow delta is one added `if` line on the pinned configure-pages action, copied exactly from the unchanged deploy job predicate. Every other workflow byte is unchanged, including pins, permissions, triggers, build commands, unconditional artifact upload, and the entire deploy job. All other tracked repository paths match the parent.

The spec was updated before the test and workflow implementation. The previous broad assertion prohibiting the marker anywhere in the build job has been replaced by a per-step assertion: the configure action shares the exact deploy predicate; all other build steps and the build job remain unconditional. The site test module retains its dependency-free text-check design.

## Original failure and action evidence

This is a post-main defect from merge `9023761a4066ac1c50c127ac09d0ba5f56cdc9e4`, Pages run `44889511406`, build job `136802040292`. That hosted job passed 247 site tests with one existing GUI-unavailable skip, built the site, then failed the configure-pages GET with 404 because Pages was not enabled. Deploy job `136802309849` was skipped. The raw job, complete log and pinned action sources are retained under `observed-failure/`; they are separate from the successful premerge PR349 qualification.

Pinned configure-pages defaults enablement to false and queries the Pages service. Pinned upload-pages-artifact tars its supplied directory and uploads that archive; it consumes no configure outputs. The current workflow provides no configure step id and consumes no output. Therefore the held push can skip that query while preserving normal artifact upload after successful preceding steps. Unmarked pushes and manual dispatch preserve their existing configuration/deployment behavior. No Pages enablement, workflow dispatch, settings change, remote ref update or CI manipulation was performed. The upload action's existing nested mutable reference is a separate preexisting transitive-action limit.

## Validation

All process argv, working directories, elapsed times and exit statuses are recorded in the corresponding `*-receipt.json`; stdout/stderr and JUnit XML are retained. No full pytest attempt was made.

1. New regression against the original workflow: **1 failed, 7 passed**, with the intended missing-configuration-hold assertion. `pages.yml` was still byte-identical to parent 5b.
2. Full `tests/test_site_*.py` selection using `--noconftest --disable-plugin-autoload -q -ra`: **249 passed**. This local environment includes the GUI dependency, so the existing offscreen screenshot test ran; this is not native packaging acceptance and differs from the hosted site-only environment's skip.
3. Separate `tests/test_codex5_command_audit_20261121.py`, `tests/test_codex_pkg_workflows.py`, and `tests/test_spec_registry.py`, with the same isolation flags: **226 passed, 2 strict CODEX-5 xfailed**. Broad hash closure remains open; neither expected-failure mechanism changed.
4. Bounded Ruff on the modified workflow test and affected scanner/workflow/registry modules: **passed**. `pip check`: **passed**. Isolated `python -I` module import and editable direct_url both identify this owned worktree.
5. After a wording-only clarification in the spec explanatory paragraph, exact frozen-head workflow and registry checks: **119 passed**, clean before and after. These overlap the earlier green runs; do not add their count to them. Workflow, test and runtime bytes were identical throughout all green selections.

CODEX-5 census remains **21 workflows / 200 step.run scalars / 42 explicit pip installs / 41 unprotected installs**. The single Pages protected install is unchanged. `source-and-invariants.json` retains the pre-freeze validation snapshot; `frozen-candidate.json`, `final-candidate.diff` and `final-source/` bind the final committed bytes. The older `candidate.diff` records the exact working diff used for the initial green processes.

The dedicated environment was created without pip, reused installed dependencies through a plain `.pth` pointing to `/workspace/scratch/patchtrace-95fe-c3/venv/lib/python3.12/site-packages`, and installed only this owned editable source using `pip install --no-deps --no-build-isolation --no-index -e .`. No dependency downloads or rebinding of frozen environments occurred; setup receipts are retained.

## Integration and remaining boundary

Root owns integration and records in `PatchTrace-codex5-followup`; that worktree and the accepted scratch records helper were not modified. Root should preserve the original cycle3 deploy-only history and append this post-main failure/repair record. Independent exact-source review is separate and pending at author handoff. A later automatic held main push is needed to establish hosted configure-skip/artifact-upload behavior; static checks do not execute GitHub's expression engine or prove hosted deployment. Existing CODEX-5, native, release, manual, trust and accessibility gates remain separate.

`evidence-manifest.json` lists SHA-256 and size for every payload member; `archive-receipt.json` records the external ZIP and manifest hashes after CRC and member verification.
