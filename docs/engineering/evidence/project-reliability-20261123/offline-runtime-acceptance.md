# Offline runtime acceptance

**Open.** The desktop can inspect and import a prepared runtime. Earlier Windows builds produced a full bundle. No successful disconnected Windows acceptance job appeared among the 11 observed runs of backend-bundle.yml. None ran on main commit ea16019601486c831941f9bc1a7ba5862a170317. The 59 releases returned by GitHub had no assets with names containing “backend” or “full” (case-insensitive).

| Gate | Source and observation | Acceptance |
|---|---|---|
| ZIP validation, synthetic installation, platform handling and CLI | Actual repository suites on Linux, Python 3.12.14, at main. `python -m pytest -q tests/test_runtime_cli.py tests/test_offline_bundle.py tests/test_offline_bundle_linux.py` returned 128 passed, one duplicate-name warning from a deliberate ZIP fixture. Both runtime verb help commands returned 0. | Passed for these fixtures. |
| Full Windows payload builder | [Run 41007128696, job 123904967993](https://github.com/djshellshoxxx/PatchTrace/actions/runs/41007128696/job/123904967993), source 7ac57759f3b9b332eaafb48c82f366566892f1b1. Windows full builder passed. | Historical artifact production. |
| Full Windows disconnected acceptance | [Job 123906675909](https://github.com/djshellshoxxx/PatchTrace/actions/runs/41007128696/job/123906675909), same source. The initial probe could not start. The log shows PermissionError [WinError 5] Access is denied at base = _run(probe, env, 30). An earlier full attempt also failed. | Historical failure. Current candidate requires a fresh artifact and disconnected Windows run. Root cause remains unverified. |
| Linux full payload | [Job 123904968059](https://github.com/djshellshoxxx/PatchTrace/actions/runs/41007128696/job/123904968059), same source. Launching bundled jlink failed with [Errno 13] Permission denied. Linux acceptance skipped. | Historical failure. |
| Distribution | Release assets and run history are in hosted-packaging-evidence.json. Three successful workflow conclusions exercised pin planning or signature verification. Each skipped Windows acceptance. | No approved release asset or successful disconnected runtime validation identified. |

Qualification requires the exact candidate SHA, pinned inputs and notices, artifact and inner payload digests, and a completed disconnected Windows installation record. Record host, non-admin account, offline state, startup, paths containing spaces, isolation, rollback and replacement behavior.

## Documentation candidate

At 5627c2a30baa566deb3a295e3a4d5644562161f5, the same three suites gave 128 passes, one deliberate ZIP warning. All local Markdown targets in the two changed documents resolve. The manifest and acceptance-harness unit suites added 50 passes and three skips because Linux network namespace creation was unavailable. The skips provide no disconnected network evidence.
