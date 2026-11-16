# `patchtrace corrections`

List current manual relations with `patchtrace corrections list PROJECT --json`.
Export a reusable document outside the project directory:

```console
patchtrace corrections export PROJECT --out corrections.json --include-review --json
patchtrace corrections import PROJECT corrections.json --dry-run --json
patchtrace corrections import PROJECT corrections.json --json
patchtrace corrections undo PROJECT --json
```

Exports never replace existing different files; choose a new filename. Identical exports leave the destination unchanged. Import requires the exact ordered pair of binary hashes and unambiguous function addresses. It preserves different existing manual corrections and refuses conflicting documents. Finding reviews require the original stored identity and unchanged claim/evidence; independent analyses can share corrections but cannot inherit finding approval by similar text.

Dry runs validate the whole document without saving or repairing interrupted jobs. Imports apply one transaction; repeated imports make no change. Documents and source/candidate snapshots are limited to 16MiB, with 64MiB cumulative planning work. Larger operations refuse without partial application. Cancellation before commit preserves the prior state; interruption after commit may leave the complete imported state. Undo restores the latest active manual correction or the record selected with `--annotation ID`.

Exit codes: 0 success; 2 rejected input; 3 storage or lock failure; 4 no corrections to list/undo; 5 cancelled. `--json` emits one `enrichment-cli/1` envelope.
