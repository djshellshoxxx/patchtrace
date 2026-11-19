# Directory publication import boundary

Dedicated branch `codex/directory-publication-import-purity-20261118` starts at
root's frozen integration `068513a72e8a1412ce3960d3024c462d68d51376`.
Spec/regressions `ed15187a69d12fc56f1a8184a826d9c4bad58c9a` precede source
`73bd7eadd1fa279cd1f7ea6887029b85e6c55430`, tree
`2630f2e7b3f2454eac16fdf17d14b1444f7677b8`.

The only production change moves `import ctypes` from module scope into the
Linux branch of `_native_move`, after Windows dispatch and unsupported-platform
refusal. It changes no native call, flag, argument, errno, path validation,
reparse admission, publication ownership or cleanup. AST comparison confirms
that removing just the old/new ctypes import nodes makes the whole production
module equal. No `owned_publication.py`, PW02 or other production file changed.

## Why this is required

The original unchanged IR purity test found ctypes loaded by the actual chain
`unified/ir/place.py` -> `ingestion.py` -> `offline_bundle.py` ->
`directory_publication.py`. The same failure was reproduced at the earlier
c7d3f258 baseline during Linux smoke qualification; that original log/XML and
read-only first-import stack are copied unchanged here. The pure modules need
pathname/persistence helpers without eagerly loading native/process/network/Qt
modules. The Linux FFI is now loaded only when an admitted Linux publication
actually needs it. Its absence still fails the operation without fallback.

Six fresh-interpreter controls refuse ctypes/Qt/process/network imports and
exercise direct helper/IR imports, Windows dispatch, unsupported OS, invalid
paths and an actual Linux attempt with unavailable FFI. They check the owned
stage identity/payload and absence of a destination. Windows dispatch is an
authored seam, not native Windows acceptance.

Three existing native test injections now patch their already-imported ctypes
module directly instead of the removed private `publisher.ctypes` alias. Every
existing assertion node is byte-equivalent by AST; no ownership or errno test
was weakened. The original complete `test_unified_packaging.py` is unchanged.

## Actual receipts

| Phase | Exact result |
| --- | --- |
| Spec-first new controls + original purity + publication positives | 7 failed / 36 passed / 1 native Windows junction skip, 1.30 s |
| Initial final-gate command | Usage exit4: nonexistent `tests/test_unified_ir.py`; no tests executed, 0.09 s |
| Corrected actual ten-file affected gate | 442 passed / 1 native Windows junction skip, 4.82 s |
| Required `ruff check src tests tools` at exact source | Passed |

The corrected gate includes actual Linux no-replacement publication, competing
publishers, late foreign destinations, unsupported native operations and error
propagation, real backup/offline-install callers, IR reader/ingest/packaging,
project CLI and persistence security controls. Its one warning is the existing
intentionally duplicate ZIP-entry fixture; the warning and native-only skip
are retained. The initial invalid test-path command is kept as a preflight
failure, not counted as an assertion outcome. No unrelated failure is hidden,
no original probe is rewritten, and overlapping counts are not added together.

No target, engine, network, package install or release is executed. Native
Windows junction/rename behavior remains a platform gate; these portable
results do not certify it. Source/parent ownership assumptions and the original
cooperative-filesystem limitation remain as specified. Root owns independent
review and integration; all commits carry `[no release]`.

Archive: `directory-publication-import-purity-20261118.zip`; 40 members, 90564 bytes. SHA-256 `8e9af84acae6024a48c143bfdb3480a33829b44631ed7e1e075700bc223765c4`.
