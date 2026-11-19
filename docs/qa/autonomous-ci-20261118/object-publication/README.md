# Workspace object publication repair — 2026-11-18

Implementation: `68aa6a5063172a2f46dce48a4373397f3f4ec95e`, on PR #307's
`1418617a80d6057de11f985488cfe6043a7787a2` plus the independently reviewed Windows
sharing repair (`ba4da2d59076b61fd95435ece6321884d517f1bd`, equivalent to `e250f683`).
The evidence checkpoint removes trailing empty lines from the new helper; it does
not change executable behavior. `manifest.json` binds the final source bytes,
receipt payloads, and compressed archive by SHA-256.

## Confirmed defect and correction

The original `WorkspaceStore.write_object` checked its parent and existing object
separately, then called a pathname-based `os.replace`. It could replace damaged or
concurrent evidence, publish bytes from a substituted staging pathname, and remove
a foreign replacement stage during cancellation. It also allowed direct object
writes through a newer-schema read-only store. The original authored regressions
produced **11 failures and 2 passes** before product edits.

The repair extracts the existing winpairs ownership machinery into the stdlib-only
`src/patchtrace/owned_publication.py`. Linux keeps an anonymous source descriptor
and anchored parent. Windows keeps rooted native directory/source handles and
uses the corrected directory sharing modes and a no-replace native rename.
Cleanup closes or discards only the held source. The research wrapper preserves
its existing public seams and never opts into adopting a destination.

Workspace writes verify the supplied raw digest, then reuse an existing regular
object only after a bounded compressed read, bounded single-member decompression,
and exact raw digest/length verification while the file handle remains held.
Existing compressed bytes, inode identity, and timestamps are preserved. A
collision is validated through the same held-parent boundary. A missing object
already referenced by an inventory/support record remains an error. Inventory
reads and writes delegate through the store's shared boundary; the prior separate
path-validation gap is removed. Public persisted schemas and source identities
are unchanged.

Independent review identified two related root ownership cases. Three additional
red regressions proved that a renamed/replaced workspace could redirect object
work while SQLite still owned its original file. Two more red regressions proved
that retargeting an allowed caller root symlink between capture and SQLite open
could split database and object ownership, including a newer-schema reopen.
The store now captures and checks the root identity before/after opening, requires
that identity on held-root walks and final parent revalidation, and uses the
captured resolved root for SQLite, object paths, and orphan discovery. `self.root`
retains the caller-selected path for compatibility.

## Executed verification

All test inputs were authored temporary files or the existing authored repository
fixtures. No target binary, network fetch, or external engine was executed.

| Check | Observed result |
|---|---|
| Expanded publication prerequisite, on Linux | 134 passed; 3 native-Windows tests skipped |
| Focused publication, architecture, and inventory integration | 393 passed; 3 native-Windows tests skipped |
| Entire `tests/test_kbc*.py tests/test_kb_*.py` area | 2,209 passed; 1 skipped; 1 pre-existing fixture-manifest failure |
| Ruff over `src tests tools` | Passed |
| Research command using `python -S` | Passed; no installed desktop package required |
| Whitespace check and receipt archive/hash validation | Passed at evidence checkpoint |

The remaining KB failure is
`tests/test_kbc_fixtures.py::test_manifest_lists_every_fixture_and_nothing_else`:
the starting PR #307 manifest omits `inventory-legacy-tsp.json` and
`inventory-capacity-compat.json`. That separate repair belongs to the root/CVE
integration work. The initial broad run also found the newly required sibling
import declaration; the contract and architecture test now permit exactly the
five public symbols needed by the named store adapter. Pure domain restrictions
remain in force.

The shared virtual environment has an editable installation from another
checkout. Every final pytest command explicitly selected this worktree for both
the pytest process and inherited child processes:

```sh
export PYTHONPATH=/workspace/scratch/c7a9e8d98848/object-publication/src
export QT_QPA_PLATFORM=offscreen
/workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_research_qualification_winpairs.py \
  tests/test_research_qualification_winpairs_integrity.py \
  tests/test_research_qualification_winpairs_publication.py \
  tests/test_owned_publication.py tests/test_kbc_object_publication.py
/workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_kbc*.py tests/test_kb_*.py
/workspace/scratch/3a6632a6e5ff/venv/bin/python -m ruff check src tests tools
python -S -m tools.research_qualification.winpairs --help
```

The provenance receipt records the imported helper/store file paths and Python
3.12.14 interpreter. JUnit and console receipts are retained in `evidence.zip`;
`manifest.json` describes which red runs used intermediate uncommitted trees.
They are regression evidence, not hosted qualification receipts.

## Remaining qualification

`.github/workflows/qa-windows.yml` includes the two new publication modules in
the existing prerequisite, on both Linux and Windows, before the full suite.
Its `pull_request` trigger has no path filter; an updated PR head runs it. Tests
include a native Windows check that existing-object validation denies competing
writes and parent/object renames, alongside the previous native ancestor and
reparse-mutation controls. Portable native-call assertions verify requested access
and status classification; they do not emulate or certify Windows behavior.

The combined candidate still requires full exact-head QA, native Windows
publication execution, and the project's separate Windows package gates. These
changes do not alter cadence or release authorization. No remote ref, release,
tag, deployment, or original frozen receipt was modified by this task.

This boundary does not make filesystem objects and SQLite one atomic transaction.
A verified object may remain unreferenced after a later transaction fails.
External mutation after an operation completes is detected by subsequent bounded
reads; the helper does not promise permanent filesystem immutability.
