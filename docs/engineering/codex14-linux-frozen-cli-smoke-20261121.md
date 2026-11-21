# CODEX-14 — full CLI smoke of the extracted frozen Linux artifact

2026-11-21 UTC. Isolated successor of draft PR #348 at immutable parent `6b6fcd3597a604212032ffc453477aeb6edc69ff`.

## Root cause and scope

The production Linux job first checks the archive's SHA-256 and runs extracted `PatchTrace/PatchTrace --self-test` under both offscreen and Xvfb/xcb. It did **not** invoke the existing `tools/frozen_smoke.py` complete CLI harness against that executable. Source-based `tests/test_acceptance_smoke.py` and the Windows frozen smoke cannot qualify the Linux archive. The inherited `CODEX-14` strict expected failure correctly exposed this omission.

The normative contract was extended first in `docs/linux.md` (`68cfff469618f0123df81740c4ab2a0bf3e24e00`). The maintained packaging test was changed next (`d34f6100c01d06c4ff2681d3b6ca6d6fca07ed8d`), replacing only its `CODEX-14` expected failure with explicit positive assertions and adding an independent preservation assertion for both Qt-platform tests. Finally, the workflow was repaired (`93a6698b1a8f38e26199638ee9d72d2adc985dd3`).

The `linux-smoke` job runs on Ubuntu 22.04 and 24.04. It checks out the same Actions source SHA **before** downloading the built archive, preventing checkout's default clean operation from deleting the artifact. Python 3.12 installs existing declared development/search/rules dependencies for the host fixture generator. After the unchanged archive SHA check and extraction/executable-bit test, unchanged offscreen and Xvfb GUI self-tests run. Then `python tools/frozen_smoke.py "$PWD/PatchTrace/PatchTrace"` tests the extracted executable with `QT_QPA_PLATFORM=offscreen` and `LANG=C.UTF-8`. Host Python creates only synthetic project/CSAF/BinExport fixtures; live target execution, Ghidra, remote acquisition, installer execution and source runtime CLI substitutions are not introduced. The existing smoke harness itself was not modified.

## Author-side evidence and limitations

A read-after-write source inspection verified the contract, exact source blobs and 13 structural invariants: expected two OS matrix entries, checkout before artifact, declared Python setup/install, SHA-before-extraction-before-full-CLI ordering, direct extracted executable argument, removal of the `CODEX-14` xfail, original GUI tests and environment. All 13 checks passed **as static inspections of connector-fetched source**. This is not an imported repository pytest run, YAML engine validation, frozen CLI execution, independent external reviewer or complete hosted acceptance.

Exact-source hosted qualification requires the two `linux-smoke` matrix legs to reach success **after** Linux package, Linux/Windows QA and Qt gates. Windows native matrix and source status must also be read independently. Failing/queued jobs remain real blockers. Neither the previous PR #346 or #347 successes nor original PR #345 feed outage can qualify this new source.

## Open and unchanged

- `CODEX-1` mutable Action tags, `CODEX-5` unhashed package installs, and `CODEX-6` cache-hit bypasses remain open. This patch does not pin actions or strengthen installs.
- The full CLI harness iterates `names()` top-level verbs; it is not full nested-subcommand coverage. Actual Linux frozen execution is not claimed until hosted results.
- All Windows manual/trust/screen-reader checks, full raw Winbindex provenance, historical semantic backlog 181 unmatched/16 patch-equivalent, and independent L1/L2/L3 accuracy gates remain open.
- Source-free local environment did not contain the prior `/tmp/patchtrace-2bad-cycle2` checkout, and the GitHub host is not resolvable by the shell, so checked-out pytest/Ruff cannot be responsibly claimed locally.

See [continuation](../engineering-handoffs/codex14-linux-frozen-cli-smoke-20261121.md) and the authoritative [task ledger](task-ledger.json).
