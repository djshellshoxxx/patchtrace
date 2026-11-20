# Generation 24 — coordinator adversarial inspection (not independent signoff)

Scope: `cli_index.read_input_file` shared by local CVRF/CSAF CLI import
and investigation import, against main, PR325, PR334 and retained
`work/winbindex-publication-20261105`.

- **Original blocking mode:** an unreadable FIFO with no writer blocks
  before read-budget enforcement; `timeout 0.4s` exited 124 on the
  original `open(path, 'rb')` primitive. This was not a PatchTrace pytest run.
- **Admission:** `O_RDONLY|O_NONBLOCK` plus held-descriptor `fstat`
  refused a FIFO; a directory and symlink-to-directory fail without
  document publication. A symlink to a regular file stays allowed.
- **Descriptor ownership:** if `fdopen` fails before adopting, the
  raw descriptor remains under the finalizer; after adoption, the stream
  owns the descriptor. `SourceError` on nonregular input finalizes the
  descriptor. The original `PT-KBC-LIMIT` sentinel remains unchanged.
- **Unresolved adversarial cases:** concurrent ordinary-file mutation,
  parent-directory path changes, platforms without `O_NONBLOCK`,
  native Windows source mode, unexpected stream close errors, and
  underlying workspace durability are **not** established by these controls.
- **Review limitation:** same-cycle author performed this inspection.
  There is **no independent source-level reviewer signoff** or real
  repository-source pytest/Ruff gate yet.

Do not conflate this path with Winbindex `save_winbindex_record`,
do not infer vendor provenance from these tests, and do not claim the
separate Linux forced-export replacement exposure is closed.
