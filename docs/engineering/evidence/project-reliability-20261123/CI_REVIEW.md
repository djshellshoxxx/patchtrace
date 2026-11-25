# Hosted and local verification, 23 November 2026

Repository `djshellshoxxx/PatchTrace`. Run IDs, job IDs, checkout identities and log extracts are in `ci-evidence.json`. Full-suite counts are per OS. Qt repetitions overlap the suite.

| Source | Hosted run and checkout | Linux | Windows | Outcome |
|---|---|---|---|---|
| Main `ea16019601486c831941f9bc1a7ba5862a170317` | [Push QA 44919714193](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193), exact main checkout | 24,336 passed, 53 skipped, 4 xfailed | 24,205 passed, 185 skipped, 3 xfailed | 12 successful jobs. Actual release skipped. Windows Qt 10,620 passed. Separate Windows consumer verified desktop installation and uninstall. |
| PR 358 `18edf3012a26eaeb037c2b970a252cc14481fba8` | [QA 44926645738](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44926645738), tested merge `d462c9bfbf8f6e1ccfbb86938a41344d7b094043` | 1 failed, 24,367 passed, 53 skipped, 4 xfailed | 1 failed, 24,236 passed, 185 skipped, 3 xfailed | Both failures concern the old Sigstore installer assertion. All 5 Qt jobs passed. |
| PR 359 `173f18d3a6ddd88aaaf514ced71b1be0c3db7954` | [QA 45197121455](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45197121455), tested merge `0ad5890649120dc55ec69d26f2788ac2e2e7c47d` | 24,368 passed, 53 skipped, 4 xfailed | 24,237 passed, 185 skipped, 3 xfailed | 11 successful jobs and 2 skipped publication jobs. Windows Qt 10,620 passed. |

`git show -s --format='%H %T %P'` verified that head and tested merge trees match for PR 358 (`6798e06fcc100d430865c2e995471628e055ddb6`) and PR 359 (`8760cc87be24b1274febd4f3404d6a5e2315aa65`). The earlier PR 357 head `d60ac40daf767fe6a93ae152feb21235f6e75e0b`, its tested merge `254d26e58ef03a03e50c78b5f90c6ef7d9bf9e57` and current main all have tree `4a07cd88ded407bef30a8aeb81961e4041822dc2`.

The [main push native Windows run](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714141) lists five successful jobs. The clean Windows lane checked out exact main. The disconnected production bundle, other optional backends and manual Windows acceptance still require their own qualification. The pending state in `docs/engineering/cycle837fe-network-recovery-20261121.md` on PR 358 is superseded for these two main push runs.

## Integration order

1. Draft PR 359 stacks directly on PR 358. Its only changed file, `tests/test_backend_bundle_workflow.py`, replaces a stale regex with an exact installer command that checks hash enforcement, wheel-only resolution and the lock path. The independent lock-closure fixture remains in place. Neither head has a submitted GitHub review. Both have a successful Snyk status.
2. PR 358 contains the exact tips of PRs 352, 353, 354, 355 and 356 by Git ancestry. None is a main ancestor. The historical PR 356 Windows QA failure, job 136832744817, was a timeout in the loopback HTTP response setup. PR 359 has newer evidence for the combined tree.
3. PR 342 and PR 343 exact heads are main ancestors. PR 342's Windows Qt lane timed out twice waiting for an offline dialog operation. PR 343 added timeout diagnostics. Its Windows Qt lane passed on `0419518c466f3aa0f700fad4198e1670c22636f7`. Later main was green. The cause of the historical timeout remains unestablished.
4. Further changes require exact-candidate CI and independent review. Publication stayed skipped. This review performed read-only GitHub operations.

## Independent local replay for PR 359

In detached Linux checkouts with Python 3.12 and `QT_QPA_PLATFORM=offscreen PYTHONPATH=src`:

- On PR 358, `python -m pytest -q tests/test_backend_bundle_workflow.py::test_pin_verify_job_is_ubuntu_pinned_and_uploads_evidence` returned 1 failure matching both hosted traces.
- On PR 359, `python -m pytest -q tests/test_backend_bundle_workflow.py tests/test_sigstore_dependency_lock.py` returned 17 passed. `python -m ruff check tests/test_backend_bundle_workflow.py` passed.
- Logs are `359-before.log` and `359-after.log`. These tests validate workflow structure and pinned dependencies. A live signed bundle installation needs separate evidence.
