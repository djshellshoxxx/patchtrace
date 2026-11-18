# Strict static review: assertions and SQL construction

## Disposition and source

**No validation bypass or SQL-injection defect was confirmed at the 43 selected production boundaries.**
The nine S101 assertions are internal producer/caller invariants or fixed source-table checks. The 34 S608
sites interpolate fixed grammar or generated placeholder lists; imported and caller-controlled values remain
parameters. The per-site classification is **false positive at the reviewed production boundary**. This is a
source-flow disposition, not a statement that these entire modules or the application are secure.

No product source, scanner configuration, inline suppression, rule exclusion, allowlist, or product test changed
for this review. The strict selected scan still exits **1**, reporting all **9 S101 + 34 S608** rows.

| Identity | Exact value |
| --- | --- |
| Review branch | `codex/security-contract-triage-20261118` |
| Source tested | `cffbb6be9b67c8d45393e771ab4f3409af5fe493` |
| Review worktree | `/workspace/scratch/c7a9e8d98848/security-contract-triage` |
| Original strict scanner source | `95bf8f5e71a4704befbf0e79f75ba64afe886cbc` |
| Original strict JSON | 79 findings; 42,088 bytes; SHA-256 `04a73cac7bec53991ac378a8898fab7c15cdad8160be220ad133bf05e3aa8877` |
| Runtime | `/workspace/scratch/3a6632a6e5ff/venv/bin/python`; exact versions retained in `final-context.json` |
| Test imports | Absolute review `src` and `tests` paths in `PYTHONPATH`; `QT_QPA_PLATFORM=offscreen` |

The original raw scanner output is copied byte-for-byte as `strict-original-79.json`. It is not a baseline
acceptance list. The older configured 78-row scan is separate historical evidence: its missing S608 row is the
`WorkspaceStore._dictionary` SELECT, which the strict scan includes despite its existing inline annotation.
That annotation was not edited.

`selected-source-map.json` records every selected row's original diagnostic line, current line, enclosing
function, and both source-file hashes. `dispositions.json` adds the actual input boundary, traced guard/caller,
reason, and relevant external control for **each of the 43 rows**. All original selected lines map to current
statements; none was silently dropped.

### Applicability to the reviewed follow-on candidate

At candidate `36e14051a4d36f5c66df0186f037a4905b01bf05`, **20 of the 21 selected source files are byte-identical**
to the tested worktree. The other file is `pilot/store.py`, which contains the separately reviewed assessment
freshness changes. Its `_holds`, `delete_results`, `_backup`, and `_owner` functions are byte-identical to the
functions reviewed here; only their line numbers move. `candidate36-source-equivalence.json` retains the exact
hashes and locations. This comparison does not describe the 1,012-check run as a test run of that candidate.

## S101: nine assertion sites

Paths below are relative to `src/patchtrace` and line numbers identify the tested source.

| Site | Actual invariant and security disposition |
| --- | --- |
| `callgraph/delta.py:71` | `_old_changes` and `_new_changes` supply a concrete callee label on at least one side in every call to `_change`. Strict `FunctionRecord` models reject `None` in imported callee lists under both modes. The helper assertion narrows a union; it is not the imported-label validator. A direct unsupported private-helper call with both labels `None` is outside this caller proof. |
| `callgraph/minimap_qt.py:51` | `model` refreshes when absent. `refresh` returns early only with an existing model, otherwise assigns the pure builder's `MinimapModel`. An exception does not turn into an admitted empty result when assertions are removed. |
| `enrichment/wil.py:209` | `_scan` retains a gate on a site only when the gate body exists; otherwise it clears the gate. `_qualifying_hunk` calls `_region` only for a retained gate. Empty, unmatched and semicolon bodies remain nonqualifying under `-O`. |
| `kbcorrelation/panel_qt.py:52` | The two five-column lists are fixed source definitions. Imported labels and caller input cannot change their counts. |
| `kbcorrelation/store.py:681` | `_begin` explicitly refuses an absent, stale, or non-verified revision before attach. `_cas` assumes the retained investigation exists; if it is missing, `current.revision` still fails before reduce/append when `assert` is removed. `append_revision` separately checks next revision/parent and performs transactional expected-current comparison. The different exception type for corrupt missing state is not a claim of graceful recovery. |
| `secondary/bindiff_probe.py:146` | Every failure branch of `check_path` returns a failure report; the sole success returns a resolved `Path`. `probe_report` returns the failure before reaching the assertion. |
| `secondary/bindiff_run.py:316` | `execute` returns absent output path/hash only for cancellation or timeout, and the wrapper explicitly raises both before the assertion. Other failed stops and invalid outputs raise inside `execute`. Success follows snapshot hashing, output shape/size checks and preservation; import independently checks schema, pair and file hash. |
| `ui_series.py:334` | Loader success assigns `LoadedSeries`; failure constructs a failed one. Cancel and requery check for a loaded value before displaying it. The assertion is not an evidence or navigation permission gate. |
| `unified/ladder/passes.py:381` | Source-defined pass IDs are unique and their dictionary is built from that fixed tuple. The assertion has no side effects; input IR does not supply these IDs. |

The BinDiff source trace also received an independent read-only check by the inventory agent. The external
probe used an injected runner that returned authored status records and wrote authored SQLite fixtures.
Those controls did not start BinDiff or any target.

## S608: all 34 SQL-construction sites

| Module and current diagnostic lines | Count | Data-to-SQL boundary |
| --- | ---: | --- |
| `diaphora/sqlite_guard.py`: 54, 66 | 2 | `SCHEMA[table]` and `_check` run before SQL; columns come from that fixed schema; row limit is bound. The snapshot has a read-only authorizer. Unknown identifier controls fail before execution. |
| `enrichment/storage.py`: 311, 362 | 2 | Formatting creates question-mark lists only. IDs and kinds are parameters. Retention checks backup ownership and constrains the delete by ID and kind. |
| `kbcorrelation/inventory_store.py`: 227, 259, 335, 340, 343, 345, 348, 379, 492, 521, 525, 533 | 12 | Table names are `docs` and the two fixed inventory/support constants. Public wrappers supply those constants. IDs, hashes, bodies, sizes and pagination values are bound. The budget UNION combines fixed SELECT templates. |
| `kbcorrelation/store.py`: 343, 344, 361 | 3 | Dictionary callers select only `kbs`, `cves`, or `products`; names are bound. The two public lookup methods select fixed `kbs.name=?` or `cves.name=?` grammar and bind caller text. Private helper arguments do not constitute a public arbitrary-SQL interface. |
| `persistence.py`: 644 | 1 | History sequences are bound parameters after a verified retention backup. Only a generated placeholder list is formatted; history sequence is an integer primary key. |
| `pilot/store.py`: 387, 427 | 2 | Backup membership and deletion bind every ID. Deletion also binds the fixed kind and prefix pattern and checks the prefix before backup/deletion. |
| `project_cli.py`: 198 | 1 | The only formatted input is source constant `DERIVED_KIND_LIMIT=64`; no user limit, identifier or predicate is interpolated. |
| `search/segment.py`: 199 | 1 | Internal table names and columns come from fixed mappings; row values go through `executemany` parameters. A nonempty unknown table fails its column lookup before that statement. |
| `search/service.py`: 140, 186, 196, 229, 238 | 5 | Column lists and table callers are fixed. Filter/identity branches generate fixed predicates and question marks; terms, filters, limits and identifiers-as-values are parameters. The query parser independently quotes the FTS language and validates field enums. |
| `unified/ir/ingest.py`: 160 | 1 | The loop selects six fixed table names; tuple width generates marks, and each row is parameterized. |
| `unified/ir/reader.py`: 297 | 1 | Projection comes from fixed `FN_COLUMNS` plus fixed named fields. Stored names/aliases stay row data. |
| `unified/ir/schema.py`: 173 | 1 | Fixed `COLUMNS[table]` and `_ORDER[table]` are looked up before SQL. Unknown identifiers cannot become query grammar. |
| `unified/store.py`: 770, 844 | 2 | Backup membership and deletion generate placeholders and bind IDs/kinds. Deletion explicitly limits requested kinds to `UNIFIED_KINDS` before starting. |
| **Total** | **34** | **No caller/imported value was found to supply SQL grammar at these traced production sites.** |

The earlier provisional priority trace described the inventory `_write_raw` SELECT as removed during the
object-publication repair. That was incorrect: its fixed-table SELECT remains at current line 259. This packet
maps and reviews it explicitly. Its identifier is drawn from `docs` and `_TABLES`; its source SHA is bound.

These dispositions depend on the recorded internal callers and constants. A future caller that supplies
arbitrary table/predicate text would invalidate that site's conclusion. Bound parameters also do not by
themselves prove that every hostile SQLite file, FTS expression, filesystem race or resource-exhaustion case
is safe; those are separate boundaries.

## Independent controls and affected checks

`contract_probe.py` is external to product source and uses explicit conditional failures, so Python optimization
cannot remove the review oracle. The parent `test_contract_external.py` launches each group once normally and
once with `-O`, requires identical outcomes, verifies optimization is actually active, and records the hash of
every imported PatchTrace source file. An audit hook refuses networking, subprocess creation and shell/exec
events inside the probe. No external helper executes inside those sixteen child runs.

| External group | Positive and negative behavior checked |
| --- | --- |
| `assertions_core` | Authored normal/hostile callgraph labels; `None` callee refusal; valid WIL gate versus three bodyless forms; missing-revision attach refusal before project calls; actual SQLite revision CAS; fixed pass identities. |
| `assertions_qt` | Initial/populated/cleared minimap model, five-column mapping, failed series load followed by requery and cancellation, offscreen. |
| `assertions_bindiff` | Four invalid configured paths never reach the injected runner; valid authored probe; cancelled/timeout/missing/malformed/wrong-pair outputs refused; valid authored two-match database admitted. |
| `sql_retention` | SQL-looking IDs round-trip through actual project storage and backups; only the permitted literal rows are deleted; foreign-kind and sentinel rows remain; CLI counts and project identity remain readable. |
| `sql_workspace` | SQL-looking KB/CVE lookup values do not broaden results; dictionary text remains literal; two inventory contexts retain exact raw bytes; unsafe basename and malformed ID/pagination are refused; valid filename and advisory edges survive. |
| `sql_search` | A function name containing `';DROP TABLE doc` is indexed and found as a literal quoted phrase; two SQL-looking word queries reach FTS and return zero results; four invalid syntax/filter cases are refused; the positive remains searchable. |
| `sql_ir` | Authored JSONL names/aliases containing SQL text survive ingest and reader/digest queries; an arbitrary table identifier is refused; the source row remains. |
| `sql_diaphora` | Authored SQL-looking label remains literal; four bad identifier calls are refused; valid counts remain one and original source bytes remain unchanged. |

The final gate combines **24 affected test files and the eight external groups**: **1,012 passed in 41.56s**,
with no skipped tests or expected failures in that run. `affected.context.json` records the complete command,
source and import environment; `affected.log` and `affected.xml` retain the result. The selected tests include
actual SQLite projects, retention/backup/history checks, search parsing/indexing, IR readers, GUI state and
source-pinned CLI children. Existing BinDiff tests use authored fake helper processes, not a real engine.

The configured repository Ruff check (`src tests tools`) passes. The separate strict selected S scan remains
failed with 43 diagnostics. Those are different checks, both retained.

### Preserved harness failures

There is no product red-to-green repair in this slice. The first external run had **2 failures / 6 passes**:
the review harness omitted required `Capability.supports_json` and used nonexistent `CsvInventory.rows`.
After those corrections, an added assertion incorrectly expected the unsafe CSV filename to be admitted;
the parser correctly rejected it (`INVALID_FILENAME`), giving **1 failure / 7 passes**. The final fixture
contains one valid and one refused filename and checks both outcomes. Both earlier harness sources and all
their logs/process receipts are retained under `first-harness/` and `second-harness/`. The first complete
eight-group run is also retained before the FTS control was strengthened and included in the final gate.

## Remaining scope and evidence

This packet covers **43 of 79** original strict rows. The remaining 36 comprise 14 S105, 13 S110, 6 S310, 1 S603,
1 S314 and 1 S108. The manifest encoding/DTD defect and its separate parser repair remain independently retained;
this packet neither replaces that receipt nor counts its tests. URL and subprocess source tracing from the
earlier priority investigation is provisional until its separate disposition and controls are retained.

No release, hosted CI, native matching accuracy, Windows behavior, arbitrary namespace/journal-race immunity,
full hostile-database safety or blanket security qualification is claimed. No target was executed or downloaded,
and frozen corpus/outcomes were not changed. Source remained unchanged during this review; only this QA packet
is committed. Root owns independent review and integration.

The adjacent `security-contract-triage-20261118.manifest.json` enumerates every payload and SHA-256 in
`security-contract-triage-20261118.evidence.zip`. It includes original scanner data, exact per-site dispositions,
current scan command/result, source equivalence, external driver/tests, normal/optimized outputs and source hashes,
harness history, and the affected test/Ruff receipts. Scratch originals are under
`/workspace/scratch/c7a9e8d98848/qa/security-contract-triage`.
