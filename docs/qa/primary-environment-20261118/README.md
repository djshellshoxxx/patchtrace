# Primary child environment defaults — 2026-11-18

The reviewed implementation is `1f9ad8635d2952e2f65d752fe4f7df3faca8f49a`, tree `ad43ac3dbcee546c58689e996cee44512f09adb6`, on published PR #307 `58fc130631f602b6e907bb054d30c21d810551d4`. Specification and failing regressions preceded the implementation at `2e3678a28a5086e7382b56a88254cdaa77d46900`. This later checkpoint changes documentation/evidence only.

## Reproduced defect and bounded repair

Default external primary-engine configuration inherited unrelated environment credentials, JVM injection settings and proxy configuration even with symbol lookup disabled. The original reviewer used authored dummy values, and root added pure, actual fake-child and desktop controls: **9 failed, 4 positive controls passed in 2.27 s**. No real credential or target binary was used.

The repair changes `BackendConfig.restrict_env` to `True` and gives both absent-key desktop readers the same default. Existing allowlist construction, argv isolation and bundle enforcement are reused. No environment name was added to the allowlist. Automatic proxy/CA inheritance still follows explicit online symbol mode. The tooltip accurately describes the default and compatibility choices.

Existing saved `False`, explicit `restrict_env=False`, validated named passthrough and external-only `PATCHTRACE_CHILD_ENV=inherit` remain explicit compatibility choices. Bundles still ignore full-inheritance opt-outs. Historical saved `False` cannot be distinguished from an intentional choice and is not silently rewritten. Reading defaults and discovery write no settings. This is a repair to default process-environment inheritance, not a network sandbox or a complete environment prohibition under opt-out.

## Actual verification

| Run | Actual result | Scope |
|---|---|---|
| Root test-first controls | 9 failed / 4 passed, 2.27 s | Original default exposure; preserved |
| Initial affected run | 4 failed / 355 passed / 3 skipped, 49.78 s | Existing fixtures depended on full inheritance; preserved |
| Corrected affected run | 359 passed / 3 skipped, 55.58 s | Production bytes matching final implementation |
| Final default controls | 13 passed, 1.92 s | Final test source after Windows case-normalization correction |
| Independent exact-commit affected + external controls | 370 passed / 3 skipped, 60.43 s | Detached `1f9ad863`; includes all 359 affected checks and eleven independent controls |
| Required Ruff and whitespace | Passed | Required `src tests tools` scope and final diff |

The four intermediate failures were repaired in test setup only. The redaction fixture explicitly selects unrestricted external mode so its existing assertion that the dummy secrets were printed, and every redaction assertion, remains meaningful. The unified cancellation/timeout fixture explicitly passes only its `PT_TEST_BEAT` heartbeat variable; process-tree termination and cleanup assertions are unchanged. An initial invocation named nonexistent `test_backend_cache.py` (exit4, no tests); the corrected selection uses `test_raw_cache.py`. An initial fixture import lint error was corrected through an explicit module fixture binding. All these receipts remain.

Independent review by the `ci_qualification` worker found no blocker in the inspected production delta. Eleven additional controls exercise an actual isolated Python child, dependency/JVM probe wiring, approved named proxy passthrough, forced bundle isolation, refused injection-variable passthrough and pure Windows case handling. The reviewer verified its import paths against the detached checkout. Root checked the independent test-source hash and JUnit totals. The runs overlap and are not additive.

## Reproduction and provenance

The [manifest](manifest.json) binds all source hashes and original [raw receipts](evidence.zip). `independent/command.json` in the archive gives exact argv, checkout, source/tree, UTC execution times and exit0. Reproduce its pytest command with the manifest's absolute `PYTHONPATH`, `QT_QPA_PLATFORM=offscreen` and `H7_REVIEW_ROOT` pointing to the reviewed checkout. The independent test-source file is in that same archive.

Root's affected selection contains `test_primary_environment_defaults.py`, `test_child_env.py`, `test_backend_bundle_env.py`, `test_network_consent_symbols.py`, `test_network_consent_secrets.py`, `test_ui_bundle_setup.py`, `test_jobs.py`, `test_raw_cache.py`, `test_backend_java_version.py`, `test_backend_sec1.py`, `test_backend_sec3.py`, `test_backend_symbol_local.py`, `test_unified_extract_runner.py`, `test_backend_cli.py`, `test_ui.py`, `test_tooltips.py` and `test_gui_host_seam.py`.

## Native and promotion limits

Three existing Windows-native process checks are skipped on Linux. The existing `live-backend.yml` matrix is Windows-only and contains no authored secret/JVM-option probe. Its PatchTrace and raw-cache harnesses use the configuration default, so this candidate changes their real execution environment. `live-unified.yml` runs an actual primary Ghidriff comparison on Linux and Windows, but does not supply the historical Linux seeded-store/cache matrix or a native-job sentinel receipt. None of those native requirements has been satisfied by fake children or pure Windows-name tests.

The focused PR remains stacked on #307 until the #304 → #307 chain and its own applicable gates qualify. Native H7 Linux/Windows, full exact-head QA, packaging, security and manual acceptance remain unverified. Primary-process memory and total-output caps are separate unresolved work. No release, tag, deployment, target execution or accuracy claim follows from this repair.
