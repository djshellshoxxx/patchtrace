# E2 incomplete PE manifest backing — 2026-11-05

Isolated branch `work/pe-parser-security-20261105`, worktree
`/tmp/pt-independent-pe-security-20261105`, base published PR #218
`afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`. Scope: the existing manifest
reader, one precise SPEC-26/SPEC-51 backing amendment and authored-byte tests.
No ingestion, verified reader, persistence, native, unified, KB, shared tracker
or running qualification files changed.

## Verified defect

An authored resource data entry declares a manifest 512 bytes longer than its
file-backed data. The available prefix is a complete XML document containing
assembly identity, `requireAdministrator` and `uiAccess=true`. The prior
resource reader correctly set `complete=False`, but `observe_manifest` still
parsed that prefix and returned identity/security facts with no warnings.
`inspect_metadata` consequently reported `status='ok'`, while the observation
had no digest. Thus XML syntactic completeness hid the unreadable declared
resource tail. Existing partly backed tests used incomplete XML and did not
exercise this case.

Baseline: **4 failed / 1 passed in 2.22 s**, covering UTF-8 and UTF-16 prefixes,
actual PE/resource/metadata composition and refusal before XML parsing; the
fully backed positive control passed. The reproduction uses only authored
bytes through `VerifiedArtifactReader` and existing resource builders. No
target binary or native program was executed.

The specification was amended before changing code. An incomplete manifest
now returns the existing `manifest_xml_invalid` warning, no digest and no
manifest facts before XML parsing. The aggregate correctly becomes `partial`.
Fully backed XML and supported trailing NUL padding retain their behavior;
existing caps, DTD/entity refusal, cancellation and source bytes are preserved.

## Completed validation

`env -u PYTEST_ADDOPTS PYTHONPATH="$PWD/src" QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_pe_parser_security_20261105.py tests/test_pe_manifest.py tests/test_pe_meta_compare.py -k 'not real_launcher'`

**168 passed / 1 deselected in 9.79 s.** The one existing real-launcher test
was explicitly excluded to keep this audit restricted to authored bytes.
Whole-tree `python -m ruff check src tests tools` and `git diff --check` passed.
No model/schema field, warning code, module or dependency was added.

## Limits and next gates

This is a conservative metadata correctness repair, not a Windows loader,
signing/trust, exploitability or real-binary compatibility claim. Independent
review/publication and exact-head integration/full/Windows checks remain
coordinator-owned. PR #205 qualification, existing native builds, worktrees
and logs were not restarted, reused or modified. No broad suite or resource
stress probe was launched.
