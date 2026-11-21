# PT-BUG-OPT-002 — optional package initialization failure aborts startup

- **Date:** 2026-11-21 (UTC)
- **Classification:** CONFIRMED, P2 (startup reliability)
- **Component:** `src/patchtrace/optional_deps.py`
- **Source:** `main` `9023761a4066ac1c50c127ac09d0ba5f56cdc9e4`; original file blob `2de1a4a884bdc404f3604641be837b297174e33e`
- **Fix branch:** `fix/optional-import-init-exceptions-20261121-0318`
- **Status:** Fixed on isolated branch; hosted exact-source QA and independent review pending

## Reproduction and root cause

The module promises that optional packages cannot prevent PatchTrace startup. Its import blocks for `rapidfuzz`, `iced_x86` and `yara_x` catch only `ImportError`. An installed optional native extension may instead raise an ordinary `RuntimeError` during initialization; before repair, that exception aborts importing `patchtrace.optional_deps` and thus any code path importing the capability module.

`tests/test_optional_import_recovery.py` contains three parametrized source-module import tests. Each substitutes an extension initializer raising `RuntimeError` while keeping all other imports normal. Before the repair, **3 tests failed** with the uncaught exception on the original byte-identical module.

## Minimal repair

Change only the three `except ImportError` import handlers to `except Exception`, preserving the existing capability registry, remediation text, and error detail. Do not catch `BaseException`: `KeyboardInterrupt` and `SystemExit` retain their standard control-flow behavior. No new capability, dependency, or interface is introduced.

## Verification

- Byte-identical original module reproduced 3/3 failures before the repair.
- Byte-identical repaired module passed the 3 new regressions plus 4 existing tests from `tests/test_optional_deps.py`: **7 passed**, zero failures or skips (local source mirror; Python 3.13 / pytest 9.0.2).
- Repaired source blob `b99ebfb1f24bf86123dd244204d80601d8bcb628`; added test blob `01b5dcb2c056cc79498801f3e5f76f1be054485e`.
- Existing test source blob `05117137daf0a5495c92703d6cf4f13f7ae7edd6` used for the local selection.
- New tests use module-local isolated import replay; no actual extension ABI/native initialization was exercised. This is a deterministic fault-injection test, not native-platform acceptance.

## Gates

- [x] Original actual-source reproduction and failing regressions.
- [x] Narrow repair and matching source/test SHA-1 blobs.
- [x] Local focused regression and existing module selection green.
- [ ] Entire checked-out repository pytest and Ruff.
- [ ] Hosted Linux and Windows exact-head QA.
- [ ] Genuine independent review.
- [ ] Owner/branch qualification and guarded merge into `main`.

No release, deployment or qualified main merge has occurred. Do not merge while hosted verification or independent review remains outstanding.
