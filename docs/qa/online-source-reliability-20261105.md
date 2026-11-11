# A1/A3 monthly CVRF network boundary repair

Base: published PR #218 `afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`.
Worktree: `/tmp/pt-independent-online-20261105`.
Branch: `work/online-adapter-20261105`. Date: 2026-11-05.

## Reproduced failures and behavior

Seven new controls failed on the base before implementation:

- Two malformed redirect references (`https://[` and an authority containing a fullwidth solidus) escaped as `ValueError` while URL joining, aborting the whole monthly iterator.
- Cancellation and deadline expiration while receiving redirect headers still allowed another request.
- Both HTTP 429 and 503 with a seven-second Retry-After consumed fourteen seconds of retry waits despite a five-second document and plan budget.
- A redirect after three elapsed seconds still received the original five-second connection timeout.

The redirect join now sits inside the typed URL-validation boundary. Each request and returned response is checked for cancellation/deadline; connection timeouts use the remaining document budget. A per-document retry-sleep wrapper refuses a wait that would exhaust that budget and rechecks after a permitted wait. The adapter continues to use the shared transport's retry status, attempt limits, backoff, cancellation and response closure. The shared acquisition transport is unchanged.

The source specification was updated before the behavior change. There are no new model fields, schemas, modules, dependencies, network destinations or consent rules.

## Completed checks

Source binding: `PYTHONPATH=$PWD/src python -c 'import patchtrace;print(patchtrace.__file__)'` resolves this worktree's `src/patchtrace/__init__.py`; interpreter is Python 3.14.2.

- Initial new controls: **7 failed**; log `/tmp/pt-independent-online-red.log`.
- First repaired selection: **70 passed**; log `/tmp/pt-independent-online-green.log`.
- Final selection: `PYTHONPATH=$PWD/src QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_online_source_reliability_20261105.py tests/test_kbc_cvrf_fetch.py tests/test_kbc_net_plan.py tests/test_kbc_scope.py tests/test_kbc_msrc_cvrf.py`: **144 passed in 12.38 s**; log `/tmp/pt-independent-online-focused.log`. Counts overlap.
- `python -m ruff check src tests tools`: passed.
- `git diff --check`: passed.

Additional positive controls preserve successful Retry-After zero/two-second and fallback waits within budget, reduced retry connection timeouts, response closure and failure when a permitted wait overshoots its deadline. Existing controls exercise explicit consent, offline refusal, original source provenance, strict import, caps, repeated failures, partial coverage and later-month continuation.

## Primary references and reuse

- CPython **v3.14.2**, commit `df793163d5821791d4e7caf88885a2c11a107986`, [urllib.parse implementation](https://github.com/python/cpython/blob/df793163d5821791d4e7caf88885a2c11a107986/Lib/urllib/parse.py), checked 2026-11-05. URL joining parses the authority and can raise before a later explicit `urlsplit`. [Python URL parsing documentation](https://docs.python.org/3/library/urllib.parse.html) documents malformed-bracket and NFKC authority failures. The runtime's [PSF and historical license terms](https://github.com/python/cpython/blob/df793163d5821791d4e7caf88885a2c11a107986/LICENSE) remain applicable; no implementation code was copied.
- **RFC 9110**, June 2022, [section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3), checked 2026-11-05: Retry-After describes the requested delay before follow-up. The local policy fails when that wait cannot fit, instead of retrying early. RFC text is under the IETF Trust provisions linked in its copyright notice; no RFC code or prose was copied into the implementation.

These tests use injected openers, response objects and clocks under the existing `no_sockets` fixture. They supply deterministic acceptance evidence only. No MSRC/Winbindex request, real advisory capture, production source-compatibility claim, Windows acceptance or full-suite result is supplied. Connection interruption still depends on an opener honoring the supplied timeout. PR #205's frozen source/suite and the native workers' builds, inputs and logs were untouched. Full, native, Windows and package gates remain with their existing owners.
