# Canonical Windows process creation identity repair

## Outcome and source

The bounded receipt-validation repair passes **213 focused tests**, including the
root reviewer's four unchanged controls. Normal Ruff over `src tests tools`
passes. This is portable validation/orchestration evidence; **native Windows SDK,
AppContainer, Winsock, lifecycle and actual BinDiff qualification remain pending**.

| Checkpoint | Commit |
| --- | --- |
| Original implementation, retained unchanged | `8800bef2c2ec5b425d6e3e3ea7d4c0033cc07c17` |
| Original sealed QA baseline | `f6afc21b4aaf941071458c58c8babb145be8f4e8` |
| Follow-up specification and failing controls | `95e12e8b54ab0b158f518275af50d9e134907967` |
| Repaired implementation | `857a78e93dd8072c8517c58a31ff14941ce16e8b` |
| Repaired implementation tree | `0de13c20de0101c96260b6fd44c342f3d1846f3c` |

Branch: `codex/windows-bindiff-network-20261118`. This appends to the original
candidate history without rewriting it. The code change is confined to
`tools/windows_bindiff_network.py`: 11 inserted and seven removed lines. The
three native C source files are byte-identical to the original implementation.
Product code, workflows, release policy and scanner policy are unchanged.

## Confirmed defect and repair

The previous validator accepted Unicode decimal digits and leading zeroes as
creation times, then used the raw string in a `(PID, creation time)` duplicate
set. A second serial launch could therefore claim the same numeric identity
using a different spelling and be counted as distinct. The independent probe
reproduced two failures and two positive controls at the original source. This
is malformed-evidence acceptance, not an observed native process or network
escape.

The shared creation-time validator now accepts precisely the native helper's
canonical form: an ASCII decimal string of one to twenty characters, no leading
zero, and numerical value in `1..2^64-1`. The bounded syntax check precedes integer
conversion. It rejects missing and non-string values, zero, alternate Unicode
spellings, signs, whitespace, overflow and overlong strings with a controlled
`NetworkEvidenceError`.

Validation applies to probe and lifecycle chains, aggregate native launches,
`NativeContext.started`, and `NativeContext.gone` before a liveness helper can be
invoked. Existing equality checks continue to bind probe/lifecycle launch
records to their canonical chain identity. Duplicate canonical serial identities
are refused, while genuine PID reuse with a different creation time still
passes. The unrelated profile-creation boolean remains a separate ownership
flag.

## Tests first and verification

The follow-up spec and tests were committed before the implementation. The red
run selected all creation-identity controls plus the unchanged reviewer probe:
**60 failed, 25 passed, 128 deselected**, in 0.99 seconds. No process was launched
by that unit run. The full raw log and JUnit remain `red.log` and `red.xml`; no
assertion or fixture correction was needed after that checkpoint.

Eighty new authored cases cover alternate spellings in twelve probe/serial/
lifecycle locations, preserving linked identities together so an ordinary
ownership mismatch cannot hide the encoding defect. They also exercise missing,
malformed and oversized values at both early launch admission and liveness-query
entry, plus valid lower/upper bounds. Existing PID-reuse controls and the
reviewer's byte-identical controls remain in the affected gate.

At exact repaired source, the complete focused module and reviewer probe gave
**213 passed, zero failed/errors/skips**, in 0.84 seconds: 129 existing tests, 80
new authored cases and four independent controls. `affected.log` and
`affected.xml` preserve that result. The normal Ruff command passed. The reviewed
canonical-byte `checked_tree` function returned the recorded repaired tree, and
the imported helper path points to this worktree.

Both test runs used an inherited process-local Linux network-denial filter and a
Python audit hook. The unit red run additionally refused any process attempt.
The affected run recorded thirteen local launches: nine fixture Git operations,
one authored short pipe-write process, and three calls to an authored fake
BinDiff script. It recorded zero denied audit events. No remote Git operation,
native Windows helper, real BinDiff process, external target binary or network
request was involved. The guard is a test-execution safeguard, not Windows
acceptance evidence or a general sandbox qualification. The original broad
suite was not repeated.

## Preservation and remaining qualification

The reviewer's probe remains byte-identical:
`edc0549b646b3ad714295598951efa8ca19897dcac3e4853d23aa5fe11bc1870`.
Its original two-red/two-positive log/XML are copied without alteration. The
original candidate's sealed archive remains unchanged at SHA-256
`0a51508e9e81ecd8320313f0f8d404dac674401a611afb970aa84ce98db5cda7`.
This new packet does not rewrite the original blocked native artifact or grant
it subsequent acceptance credit.

The packet contains command/environment records, source identities, canonical
source snapshots, original reviewer failures, the tests-first failures, the
passing affected gate, Ruff output and offline audit receipts. The manifest
binds every archived file by size and SHA-256; archive membership, hashes and CRC
were verified after creation.

Root independent re-review is required before integration/publication of this
follow-up. Native Windows execution remains the separate acceptance gate. No
release, tag, deployment, workflow dispatch or remote mutation was performed.
