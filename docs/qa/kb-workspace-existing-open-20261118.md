# Existing-workspace open: sealed author evidence

Archive: [kb-workspace-existing-open-20261118.zip](kb-workspace-existing-open-20261118.zip); manifest: [kb-workspace-existing-open-20261118.manifest.json](kb-workspace-existing-open-20261118.manifest.json).

- Source: `c470a31acec624410a0412e7c803cc38732235a9`.
- Archive: 216 members (215 payloads plus manifest), 1,039,224 bytes; 168 canonical Git snapshots.
- Archive SHA-256: `e41b28255cf86d3edc8c2dcbd47305cf65288c826e58164f560bb15f960bf13e`.
- Manifest SHA-256: `a099d178a884c6872cb0f013ebad865b816f6d31442d850ee94a2ba208f72458`.
- All payload hashes and inner/outer manifest bytes verified.

Independent review remains required. At sealing, root is specifically probing the final owned-connection assignment; no source or result is relabeled on a hypothesis. Any confirmed finding will receive a separate preserved correction packet.

---

# Existing-workspace open: source and bounded qualification

## Reviewable result

`WorkspaceStore(..., open_mode='existing')` now opens an already initialized
supported v1 database through its **first** SQLite connection in `mode=rw`,
validates that actual connection's base format, and returns without application
schema creation, version stamping or WAL configuration. Ordinary defaults and
ordinary `create=False` initialization of existing version-zero files remain.
Only `src/patchtrace/kbcorrelation/store.py` changes in production. No caller
selects this mode yet; there is no package, CLI/UI or native entry point.

| Stage | Exact commit | Content |
|---|---|---|
| Approved base | `cf5f7301c735c6b6ca1c0d64242804bfb432dfa1` | Integrated original durable design and prior reviewed core/KB source |
| Specification and tests | `f484b54c8203c34816dda017beef6f66809d1613` | §7.3 amendment and 46 explicit-mode/ordinary controls, before implementation |
| Production | `c470a31acec624410a0412e7c803cc38732235a9` | Additive constructor dispatch, actual-connection format admission and owned-connection failure cleanup |
| Separate attributed design correction | `62f0712782b999b63cdb40b1f906526f8fef64f3` | Original independent capture counterexample; retained on the prior design branch, not rewritten or folded into this source chain |

All new commits carry `[no release]`. Root independently reviews and integrates;
there are no remote updates, dispatches, merges or releases in this work.

## Exact behavior and limits

The optional keyword is `open_mode: Literal['normal', 'existing'] = 'normal'`.
An invalid type/value gives fixed nonrecoverable `PT-KBC-INPUT` before path or
connection work. The existing ordinary constructor body, all other preexisting
`WorkspaceStore` methods, and every other production path are unchanged; the
packet's AST/Git proofs record these comparisons.

Existing mode resolves the selected root using the existing root-anchor policy,
then uses `(resolved_root / 'kbc.sqlite3').as_uri() + '?mode=rw'` with `uri=True`.
This preserves literal `?`, `#`, `%`, spaces and Unicode where the platform
permits them, and prevents SQLite from implicitly creating a database after a
pathname disappears. It does not use an early `is_file` result as format
authority. Replacement/removal controls run immediately before the actual real
SQLite connection and preserve both the retained original and the replacement.

The supported-format check requires version 1 and the 13 known base tables.
For each fixed, bound table name, it checks ordinary main-schema table type,
column count, WITHOUT ROWID and STRICT flags, then bounded full `table_xinfo`
rows in column order. Names, declared types, NOT NULL flags, primary-key ordinals
and hidden/generated flags must match the current v1 writer. Generated columns
that `table_info` omits cannot pass this check. Additional unrelated/legitimate
extension tables are permitted. No whole-database integrity scan runs.

This format admission does **not** establish CHECK/UNIQUE/foreign-key expressions,
collation/default expressions, trigger/index policy, every row's integrity,
authenticity or arbitrary namespace exclusion. Existing row, object, revision,
source and saved-scope admission remains necessary. A successfully opened store
is writable for later explicit existing transactions; success grants no package
capture, project attachment, recovery, provenance or migration authority.

Missing or unavailable storage yields fixed `PT-KBC-STORAGE`; zero/v0 or a
contradictory base layout is a nonrecoverable storage refusal. An unknown higher
version is fixed nonrecoverable `PT-KBC-UNSUPPORTED` in this mode, while the
ordinary higher-version read-only behavior is unchanged. After a connection
returns, every refusal or `BaseException` closes the owned connection. Typed
errors and interrupts retain their identity; SQLite errors retain the original
cause under a fixed bounded storage mapping. If close also fails, one fixed
note reports that resources may remain without replacing the primary or
exposing the secondary text/path. No files are deleted or cleanup retried.

The contract concerns application initialization/version/WAL writes. SQLite may
still perform its own hot-journal recovery, locking or shared-memory work in
`mode=rw`. Quiescent fixture byte equality does not establish forensic zero
filesystem writes. There is no new hostile namespace or partial-connect cleanup
guarantee. Native Windows and actual recovery-journal acceptance were not run.
The `?` pathname case is explicitly inapplicable on Windows; the other URI cases
remain portable test inputs. This Linux run used the runtime recorded in
`environment.json`; it is not a Windows qualification.

## Original counterexample remains immutable

The prior independent probe called **ordinary** `WorkspaceStore(create=False)`.
At frozen `195e04af` it produced two failures for zero-byte and foreign v0
initialization, plus healthy-v1 and missing-file positives. Those failures
disproved the earlier durable-design capture assumption. They are not assertions
that this change forces green by altering ordinary defaults.

The exact original probe SHA-256 remains
`823117ef4d6886ceebe747020aece47cc07f4758c7c94217cbdec31394a8e2d3`.
Its complete sealed independent archive remains
`ab2e7ecb8e44f6c78c0f8af76c7bdb6bdf1f93a8ca41c23f20f680d86a49c2af`.
Both are retained byte-for-byte with the original logs, XML, import map and
review under `prior-independent/`. They were not rerun, wrapped or given altered
observations here. New controls call the explicit mode directly and include
four ordinary zero/v0 initialization positives with the keyword omitted or
explicitly `normal`.

## Qualification and failure chronology

| Receipt | Source | Result | Interpretation |
|---|---|---|---|
| `spec-red.*` | `f484b54c` | 44 failed / 2 passed, 0 test errors/skips, 0.74 s | Actual tests completed; post-run import recording then failed on a Qt virtual filename. This invocation has no completed import/exit receipt. |
| `spec-red-pin-harness.log`, `pin-harness-correction.json` | Runner only | Retained original traceback and precise correction | `shibokensupport/feature.py` is a relative virtual third-party origin. The corrected recorder records these names separately; it never exempts project/test/tool origins or real repository files. |
| `spec-red-pinned.*` | `f484b54c` | 44 failed / 2 passed, 0 errors/skips, 0.69 s | Same unchanged tests and source; all failures are the absent keyword API. 52 canonical imports verified, no drift or instrumented network/child attempts. |
| `focused-green.*` | `c470a31a` | 46 passed, 0 errors/skips, 0.53 s | Same committed test bytes, now on the implementation. 52 canonical imports, no drift or instrumented prohibited attempts. |
| `affected-green.*` | `c470a31a` | **344 passed**, 0 errors/skips, **3.46 s** | Bounded current-source gate, including the 46 focused cases. 112 canonical imports, no drift or instrumented prohibited attempts. |
| `ruff.*`, `diff-check.*` | `c470a31a` | Pass | Full `ruff check --no-cache src tests tools`; complete base-to-source whitespace check. |

The final 344 is the affected gate denominator. Earlier focused passes are
overlapping observations, not additional coverage to add to that total.
`affected-selection.json` records every selected file/node and eight excluded
child-process test functions. This in-process gate covers ordinary workspace
transactions, object/index storage, saved-scope revision and source admission,
inventory selection, held-reader/short-read behavior, service operations and
non-child recovery neighbors. It does not claim the hard-kill subprocess or
headless CLI tests ran. The unrelated stale import-policy controls in
`tests/test_kbc_contracts.py` are root-owned and were not changed or included.

Each invocation's command JSON retains exact executable, cwd, environment,
pytest arguments, source/tree and timestamp. JUnit/logs and per-module Git blob
and SHA-256 records are retained. The runner denies instrumented socket
connect/bind/getaddrinfo and child-process events; its allowance for virtual Qt
origins is recorded explicitly. No target binary, compiler, backend or package
payload is executed. Fixtures use ordinary system temporary directories outside
Git. Two transient overlay-space pauses preceded source/seal work; no source or
evidence write was interrupted and no cleanup was performed by this author.

## Review and remaining work

Independent root review/replay is required before integration. The original
durable design and its capture correction remain separately attributed. This
seam is only a prerequisite: strict package contracts/versioning, atomic first
intent, expected project ID, actual side-keyed hashes, association before
sidecars, reader-less recovery refusal, captured/current saved-scope preflight
and bounded committed-project reconciliation remain separate source work.
Native FDI/worker/held-reader lifetime, Windows packaging and actual analyst
journey gates remain open. Stored identity evidence cannot reconstruct a live
reader lease or authorize cleanup.
