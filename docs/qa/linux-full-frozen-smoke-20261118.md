# Linux full frozen CLI smoke wiring: bounded handoff

Spec/tests `509199fa` precede production `dd0ad00b0c3a8a1e2e95f06f3dce1de944520783`,
tree `0daba8cd1fd61c79e47de64fecbe92e83d87cd43`.
Test-only lint cleanup `2a7e3147abda0450840e885dc075cf319a59ccaa` removes an unused pytest
import after the final xfail marker is removed; every test function is unchanged.

The Linux builder now invokes the existing full `tools/frozen_smoke.py` harness
with the host interpreter, the exact staged executable as a separate argv item,
source-root cwd, inherited Qt platform (offscreen default), checked exit and a
900-second aggregate timeout. It runs before lite/full archive or digest creation.
The previous self-test plus only `rank --help` calls are replaced by the shared
registry-based harness, which already includes those acceptance boundaries.
No harness logic or command registry changed: its only edit is explanatory text
about the Linux caller, proved by AST equality apart from the module docstring.

## Actual results and retained failures

| Invocation | Exact result | Interpretation |
| --- | --- | --- |
| Spec/test-first six controls | 6 failed, 0.48 s | Actual missing complete-smoke invocation and unchecked publication after a modeled failure/timeout; original CODEX-14 assertion included |
| Exact production ten-file gate | 490 passed / 1 failed, 16.90 s | All five builder controls and 34 real source-CLI acceptance cases pass; one unrelated baseline import-purity failure remains |
| Unchanged import-purity node at original c7d3f258 baseline | 1 failed, 0.64 s | Confirms preexisting ctypes import reachability, not introduced by this two-tool change |
| Unchanged original four after this source | 3 passed / 1 failed, 0.18 s | CODEX-1/6/14 pass; dependency-hash CODEX-5 remains unresolved |
| First required Ruff | 1 F401 | Unused pytest import after removing the last expected-failure marker; raw diagnostic retained |
| Required full Ruff after the isolated import cleanup | Passed | Test functions and production source unchanged |

The full affected gate is **not green**. Its unchanged failing node is
`tests/test_unified_packaging.py::test_ir_and_retention_import_without_qt_network_or_process_modules`.
An isolated read-only import stack identifies:
`unified/ir/place.py` -> `ingestion.py` -> `offline_bundle.py` ->
`directory_publication.py` top-level `import ctypes`. All four modules and the
original purity test are byte-identical between baseline and this production
commit. The original failure, baseline replay, actual stack and source proofs
remain here. Root assigned a separate narrow import-boundary repair; this packet
credits none of that future work and weakens no purity assertion.

The five builder controls use inert owned files and a recorded subprocess seam.
They establish publication ordering, complete harness selection, argv/path/Qt
handling and refusal after an error/timeout. They do not build or execute a frozen
package. The existing source-CLI tests invoke this exact source through the normal
entrypoint with absolute PYTHONPATH and offscreen Qt, using synthetic owned data.
No target or analysis engine is executed. Counts are per invocation and are not
added into a completion percentage. No historical failure/log/probe was replaced.

## Remaining qualification

Actual Linux and Windows frozen compatibility, real backend/disconnected gates,
manual desktop checks and release qualification remain exact-source hosted/native
requirements. Existing unpacked Linux offscreen/xcb smoke and full backend scope
are unchanged. This slice adds no dependency installation, workflow dispatch,
remote mutation or release. The dependency-lock design remains separate.

Archive: `linux-full-frozen-smoke-20261118.zip`; 56 members, 170408 bytes. SHA-256 `54db8bf76d790f12b8c5fdf4845473777a6d52a9d9e50208ea837ef2e161f541`.
