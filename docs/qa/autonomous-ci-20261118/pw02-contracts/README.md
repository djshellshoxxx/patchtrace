# PW-02 contract and budget mechanics — first candidate slice

Production source: `7084963767d031e08ded1c2c90ca6f4fa9a783ec`, tree
`bf72027ab5831cd1e36de112abdd741dc3dd2a6e`; baseline
`7d2c6662fa789976427b632a7c96dd0d2b365f0e`. The first spec/tests commit is
`e6b86abf`; the additional boundary spec/tests commit is `b39c55da`.
The branch is `codex/pw02-local-packages-20261118` and the worktree is
`/workspace/scratch/c7a9e8d98848/pw02-local-packages`.

## Bounded implementation

Four new pure modules define strict frozen local-package records and ownership,
logical name/encoding/collision admission, a single operation deadline and shared
resource counters, and the Windows AMD64 prerequisite. Eleven generated public
schemas accompany the records. The sole change to an original red-control file
is import ordering in `test_package_platform.py`; its assertions are unchanged.

No production caller, CLI, store, worker, native DLL or Windows API is wired by
this first slice. `PackageDecoder` and capability fields are record contracts;
their authored test values do not represent a native probe. Platform eligibility
does not advertise available extraction. Source signature remains unknown, and
only separately reverified AMD64 full-PE records can pass the pure selector.

## Test-first evidence

| Phase | Exact result | Interpretation |
| --- | --- | --- |
| `red` | 157 failures, 110 passes, 1.47 s | Every failure is the expected missing new API/module before implementation. The positives are existing registry controls, including registration of PW-02. Test bytes map to e6b86abf. |
| `green` | 267 passes, 0.91 s | Initial implementation; exact uncommitted source bytes are retained in `pre-edge-source` and matched against the per-file provenance. |
| `edge-red` | 6 failures, 267 passes, 1.05 s | Additional authored review controls reproduce lost confirmed-byte accounting after cancellation/deadline, unread-header content classification, missing captured JSON admission, and stacked pending writes. Their pre-fix code/test snapshots are retained unchanged. |
| `final` | 273 passes, 0.96 s | Exact committed 70849637 source; all original controls and the six additions pass. No skips/xfails. |

Every test phase installs a Python audit guard denying socket creation/connect/
bind and every subprocess/fork/exec path. All four phases recorded zero attempted
denied operations. Tests use only authored bytes and simulated clocks/cancel
tokens; no library install, advisory request, target launch or native decoder run
occurs. Source imports are pinned to this worktree rather than the shared virtual
environment's older editable checkout. Owned basetemp directories are under the
system temporary directory, outside any Git tree.

One initial authored test import-order Ruff finding and one initial generic-type
syntax finding were corrected without changing assertions or acceptance policy.
Final normal `ruff check src tests tools` and exact schema `--check` both pass;
their raw outputs and command/source records are retained. This does not claim a
clean strict S scan or qualify any unrelated suite.

## Review-sensitive details

Inventory identity binds exact source capture, decoder, mode, limits, parts,
container graph, completion and diagnostics. Member identity includes raw bytes,
encoding, ordinal, parent digest and all ancestors. Completed headers cannot
invent observed content; nested scopes require a reverified matching parent.
Names stay logical and raw bytes are retained; a casefold/NFC collision or either
file/parent-prefix collision refuses before any filesystem destination exists.

Output is reserved before writing and confirmed only from the reported result.
Cancellation/deadline after a completed write records its known byte count before
refusing admission. A failed/short/unknown write retains its full reservation and
cannot restore budget. Allocations can be released by their exact owner after
cancellation; foreign/double completion and free operations refuse. Parent hash
work shares the same deadline/work budget without pretending it is output.

The native worker/stage and KB/CLI/store integration are separate subsequent
slices. Actual Windows FDI, SDK ABI, process containment, held-handle basename
handoff, cleanup and frozen full-PE pair journey remain unverified. These portable
results do not complete PW-02 or authorize release.

The approved design packet is retained separately at
`qa/pw02-local-package-design`; its archive SHA-256 is
`f1682ef246205723226d8b1ef3cf5a3e16cc003162bb98f3377db9302e84b1b4`.
Original hosted55/872, hosted14ef/5ed and other scan/native receipts are unchanged.
