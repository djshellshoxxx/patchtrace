# Scoped inventory recovery — 2026-11-19

## Disposition and source

The bounded PW-01 inventory workflow is recovered on the current foundation.
Focused portable tests and independent actual-service review support the revised
source on the inspected Linux runtime. This is **not release or native-platform
approval**. The full portable run retained one CSV time-budget failure; its exact
single-case rerun passed without a limit change. Strict security diagnostics remain
red, and exact combined-candidate Windows, native and packaging gates remain open.

| Identity | Value |
|---|---|
| Recovery base | `4cdee5a26837802bd90b8b50c11696b039ac9335` |
| Original inventory source | PR #307, `58fc130631f602b6e907bb054d30c21d810551d4` |
| Original slice comparison base | `d8c02caea407f6d323eecd636735849c1eb31a2d` |
| Final runtime/test source reviewed here | `0afd6f5410f8a527d697f79e415b31efcc84407a` |
| Final source tree before this documentation receipt | `cdc99d564293d484e9bf9ecb91857988cc03beb9` |
| Final decision-reader SHA-256 | `c91a6b8bef949259edbf41f498cf5c6244b3067c0b5845c5f9948cd72db5d680` |
| Inspected interpreter | Python 3.12.14; SQLite 3.53.1; PySide6 6.12.0; pytest 9.2.0; Linux x86-64 |

The dedicated inventory interpreter resolves this worktree's `src` first and the
prepared dependency directory second through literal `.pth` entries. It does not
execute nested editable-install `.pth` files from the dependency directory.
`security-inventory-source-proof.json` records an actual `python -I` import from
this candidate, the dependency versions, the exact reader digest and SQLite query
plan. The shared development environment was not changed.

## Scope and preserved dependencies

Runtime changes are confined to 17 files under `src/patchtrace/kbcorrelation`:
CSV contracts/parser, immutable inventory storage, support-link inspection and
explicitly consented retrieval, scoped selection/replay, shared service/CLI/Qt
adapters, and the existing KB store's owned-publication caller. Schema generation,
authored fixtures, focused tests, specification/module indexing and the dedicated
inventory help page accompany those changes. The Windows workflow adds the
shared-publication and KB-publication controls to its existing native boundary step.

The shared `owned_publication.py` helper and its tests remain byte-identical to the
recovery base. Current saved-scope refusal behavior remains intact. The later
`a07fc1cf` inventory fixtures, `fea6d6ef` saved-coverage preflight contract/tests and
`d909ec5b` loaded-index/unreadable-source propagation are included. The distinct
investigation workspace-picker tooltip from `7439549f` and the inventory-inclusive
tooltip regression close the actual `c9a60e36` collision.

The PR #307 held-input, native research/receipt and packaging stacks are excluded.
The unrelated self-test worker-lifecycle slice is also excluded. Historical source
receipts are retained verbatim, including their failed, blocked and native results;
none is promoted to current qualification. No archived script or target binary was
executed during this recovery.

Recovery commit order is retained in `inventory-commit-order.txt` inside the
current evidence archive. GUI's independently authored four actual-service
compatibility controls, original commit `b702d333`, are included as `63efbf2b`.
The separate GUI help29/help67 update `d3d00254` is not part of this source pin;
the integrator applies it separately. The dedicated CLI-linked guide was recovered
unchanged from PR #307 in `35ba1e5c`.

## Confirmed defect and admission repair

The original SQL filter searched for the exact bytes `"op":"inventory-select"`.
Independent actual-service reproduction at `c679e997` reformatted an existing
valid decision with ordinary JSON whitespace. The inventory reader then returned
zero claims while the ordinary decision reader still read the inventory operation.
`components(files=[])` published revision 5 in `NEEDS_FILENAME`, with no hint,
from revision 4 in `COMPONENTS_READY`. Both the original script and result remain
in the archive.

The first repair removed the token filter but applied an 8 KiB cap to all decision
rows. That policy was rejected because valid unrelated `AnalystDecision` records
can exceed 8 KiB through multibyte fields or any number of references. The initial
author characterization also mistakenly used an 8,159-byte fixture and failed its
own size assertion. These failed receipts are preserved; neither is a final pass.
The corrected compatibility controls then produced three failures and two passes
against the rejected reader before the current repair.

The final reader walks each stored decision semantically through the existing
SQLite JSON facility. It projects only bounded decoded keys/scalars and structural
metadata, validates a small header plus one `SourceRef` at a time, and does not add
a general body or reference-count cap. It rejects ambiguous duplicate decoded
keys, escaped duplicate keys, malformed/non-object JSON, unsupported field types,
bad UTF-8, lone surrogates and invalid schema values. Actual inventory operations
still require the original SQL-projected full body to fit 8,192 bytes and pass the
strict full-body and nested-selection contracts.

SQLite can treat a raw NUL as termination and accept a trailing suffix. A separate
raw-NUL guard closes that gap; valid JSON escapes such as `\u0000` retain their
existing schema meaning. Actual-service refusal checks preserve decision bytes,
revision, selected claims and raw inventory evidence. Equivalent pretty/escaped
inventory JSON and valid large unrelated decisions retain the selected hint and
provenance; repeated selection remains idempotent. The 5,000 limit counts inventory
claims, separately from scanned unrelated rows and their references.

### Exact limits of the SQLite qualification

The memory statement is about **bounded Python projection**, not all native
SQLite parsing or sorting allocations. The largest projected scalar is a
4,096-character `SourceRef` pointer, at most 16,384 UTF-8 bytes. Existing SQLite
record/parser limits remain in place; the inspected connection's record limit is
1,000,000,000 bytes. Native SQLite may parse or materialize a whole body internally.
The temporary progress callback is active before execution and removed on every
exit; per-field checks share the existing 60-second cancellation/deadline budget
with source replay. A callback need not preempt the internals of one SQLite JSON
function. This is a cooperative admission budget, not a hard whole-parser memory
or wall-clock guarantee.

The reader consumes the current `json_tree` depth-first traversal, with decisions
ordered by `seq`. On SQLite 3.53.1 the observed plan is a decision scan followed by
the JSON virtual-table scan, without a temporary sorter. Independent actual-route
checks passed with `reverse_unordered_selects` on/off, both tested `temp_store`
settings, references before/after other fields, reversed reference keys and an
escaped operation. These are runtime-specific results. SQLite's [JSON table-valued
function documentation](https://www.sqlite.org/json1.html#the_json_each_and_json_tree_table_valued_functions)
guarantees unique node IDs, not a portable ordering obtained by sorting those IDs.
No `ORDER BY j.id` portability claim is made. Exact other-native/Windows qualification
remains required.

## Recorded results

Times below are the pytest terminal summaries; XML timings can differ slightly.
These runs overlap and are not added into a single unique-test total.

| Source / check | Recorded result | Meaning |
|---|---|---|
| Initial integration tree `3250943c` | 5 failed, 1 passed; 4.37 s | Four saved-scope drift failures plus tooltip collision reproduced before repair. |
| `d840d3cd`, broad portable/adjacent run | 1,189 passed, 1 failed, 1 skipped; 86.19 s | The unchanged 50,001-row CSV control hit its 10-second budget. Windows native publication check skipped on Linux. This run remains failed. |
| `c679e997`, exact unchanged CSV capacity recheck | 1 passed; 9.28 s | Timing-sensitive single-case recheck only; no budget or expectation weakened. |
| `c679e997`, GUI/tooltip/host-adapter set | 132 passed; 47.07 s | Offscreen Qt, worker/stale/selection and adjacent UI controls. |
| `c679e997`, independent focused review | 20 passed; 4.88 s | Scoped GUI, coverage drift, CAS/no-op and publication controls. |
| `eabffe30`, initial semantic admission red controls | 18 failed, 1 passed; 2.53 s | Includes two new callback-API failures against the old signature; not all failures were service-route reproductions. |
| Superseded all-row cap, initial focused check | 66 passed; 2.80 s | Does not establish general-decision compatibility. |
| `35ba1e5c`, superseded cap plus characterization | 154 passed, 1 failed; 5.31 s | Author fixture was 8,159 bytes, below the asserted 8 KiB boundary. |
| `f126c135`, corrected compatibility red controls | 3 failed, 2 passed; 1.87 s | Valid large unrelated decisions blocked by the rejected cap. |
| Revised reader, first focused set | 89 passed; 5.14 s | Before the additional NUL/encoding/reference controls. |
| Final `0afd6f54`, focused admission/selection/service/CLI set | 183 passed; 7.10 s | No skips; final author check. |
| Final `0afd6f54`, independent admission/compatibility set | 48 passed; 2.88 s | Includes four independently authored actual-service compatibility controls. |
| Final `0afd6f54`, independent SQLite ordering probes | 8 actual-route variants passed | Runtime-specific; original pretty-JSON service reproduction also closed. |
| Final source, `ruff check src tests tools` | Passed | General configured lint only. |
| Final source, strict unsuppressed runtime security scan | Failed: 81 findings; base 68 | 13 introduced diagnostic findings; no suppression or waiver. |

Independent disposition: no further introduced source defect was found in the
inspected Linux runtime at `0afd6f54`; this is not approval for all SQLite versions
or native platforms. The final focused tests do not relabel the earlier full run
or any unrun combined-candidate gate as passed.

### Security diagnostic boundary review

The exact scan was:

```text
python -m ruff check src --isolated --select S --ignore-noqa --no-cache --no-respect-gitignore --output-format json
```

The source-multiset comparison retains 68 inherited findings and adds 12 `S608`
findings in `inventory_store.py` plus one `S310` finding in
`sources/inventory_http.py`. The semantic reader adds none. Raw baseline, current
and delta JSON remain in the archive.

The inspected SQL builders interpolate internal constant table/operation names;
public callers supply `INVENTORY_TABLE`, `SUPPORT_TABLE`, or the existing literal
`docs`. Record identities, bodies, sizes and pagination values use bound parameters.
The opener validates exact HTTPS host/path rules and GET, disables proxy inheritance
and automatic redirects, validates every DNS answer before connecting to the same
numeric address, and retains hostname/certificate validation. These are concrete
boundary observations, not a blanket false-positive designation or a green scan.
The unsuppressed security gate remains unresolved.

## Reproduction and evidence

From the pinned source, with the dedicated source-correct interpreter and installed
project development dependencies, the final focused command was:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -B -m pytest -q -p no:cacheprovider \
  tests/test_kbc_inventory_decision_admission.py \
  tests/test_kbc_inventory_decision_compatibility.py \
  tests/test_kbc_inventory_selection.py tests/test_kbc_inventory_source_admission.py \
  tests/test_kbc_inventory_cli.py tests/test_kbc_inventory_service.py \
  --junitxml=security-inventory-semantic-final.xml
```

The independent reviewer reran the first two test files and retained the eight-case
ordering script/result separately. No new full-suite repeat was run for this receipt.

| Archive | Contents | SHA-256 |
|---|---|---|
| `source-evidence.zip` | 56 verbatim historical PW-01 source records/archives; path, source Git blob and byte digests in `source-manifest.json` | `d91fd4389f1f6ece3bc6733a77b5602f0e81cf7852475d336b56ac77d16857ef` |
| `current-evidence.zip` | 55 current raw logs, XML/JSON receipts, independent probes, source/dependency maps and binary-safe candidate/red-source patches; byte digests in `current-manifest.json` | `655cb54a2a624e0a60e2cba518ef78e625556944be7f4d4142358e4b426cf39e` |

Archive member names, CRCs and every recorded member digest were verified after
creation. The exact combined source's Windows/native publication, full QA, Qt
repeat, packaging and strict security outcomes remain the integrator's open gates.
