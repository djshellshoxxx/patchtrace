# `patchtrace search --anchors-from CVE`: wiring the S10 anchor bridge (KBF-05)

Status: draft, developer-ready design. Nothing in sections 4 to 9 is built. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-05. Owner packages: `search/{cli,anchors,service,build}.py`, `search/sources/{advisory,tools,unified}.py`, `intelligence/{anchors,storage,explain}.py`, `kbcorrelation/context.py`. Reads with `docs/specs/program-e/WB1-integration-plan.md` (s5 S10, s8), `docs/specs/workbench/01-search-fts5-rapidfuzz.md`, KBF-04.

## 1. Purpose and non-goals

Purpose: make `patchtrace search PROJECT --anchors-from CVE-ID` answer, for each search anchor derived from a stored advisory, "is this anchor present in the changed code, only elsewhere in the index, absent from a fully indexed project, or unknown because some group is not indexed", without presenting any hit as causation.

Non-goals: ranking functions by anchor hits; a combined anchor score; fetching an advisory (offline only, no consent flag exists on this verb); GUI work (the Search dock gets the same service call later, KBB-05b).

## 2. State of the code (verified on `54fd085`)

- `search/anchors.py` (102 lines) is BUILT and unit-tested with a fake search (`tests/test_search_anchors.py`): `plan_for/plans_for/anchor_coverage/coverage_for`, statuses `changed|indexed-only|none|unknown|not-searchable`, reasons `NO_PLAN`, `UNKNOWN_ABSENCE`.
- `search/cli.py:70` declares `--anchors-from METAVAR CVE-ID`; `cli.py:176-177` raises `PT-SEARCH-CAPABILITY` with the constant `NO_ANCHORS = 'anchor search is not available in this build'`. Test `tests/test_search_cli.py::test_anchors_from_is_a_capability_error_until_s10` pins exit 2 and the code. Real output (run in this review): `error: PT-SEARCH-CAPABILITY: anchor search is not available in this build`.
- `search/sources/advisory.py` (`advisory_specs`), `tools.py`, `unified.py` exist and are tested, but NO production code passes them: `search/cli.py:_run` builds `SearchService(handle, cache, attention=attention, extra_specs=extra_specs)` with `extra_specs=None` (the parameter is a test seam), and `search/qt_panel.py` has no `extra_specs` either (grep: `advisory_specs`, `tool_specs`, `unified_specs` appear only under `search/sources/`). So in production the `adv`, `cve`, `tool`, `ir` groups are absent from coverage.

## 3. Definitions

Anchor, AnchorPlan, AnchorCoverage: as `search/anchors.py`. Changed scope: documents tied to a changed function (`scope:changed`). Indexed scope: every indexed group. Absence is proven only when every group the query could touch is `indexed`.

## 4. Contract

CLI: `patchtrace search PROJECT --anchors-from CVE-YYYY-NNNN [--json] [--no-index-build] [--rebuild] [--cache-dir D] [--limit N]`. `--anchors-from` conflicts with `--query` and `--kind` (exit 2: `--anchors-from takes no --query or --kind`). One `enrichment-cli/1` document.

```json
{"contract": "enrichment-cli/1", "command": "search", "status": "ok|partial|unavailable|stale|failed",
 "result": {
   "contract": "search-anchors/1",
   "cve": "CVE-2099-20001",
   "index_key": "<16 hex>",
   "anchors": [
     {"anchor_id": "<64 hex>", "kind": "module", "label": "module named in the advisory",
      "value": "clfs.sys", "source": "csaf-title", "pointer": "/vulnerabilities/0/title", "quality": "derived",
      "status": "changed|indexed-only|none|unknown|not-searchable",
      "hits": 3, "unindexed": ["ir:newer"], "reason": ""}],
   "summary": {"changed": 1, "indexed-only": 0, "none": 0, "unknown": 1, "not-searchable": 0},
   "coverage": [{"group": "fn", "status": "indexed", "docs": 123, "digest16": "..."}],
   "limitations": ["Anchors are search hints labelled with source and quality; they are never linked to diff results or functions.",
                   "Module and feature names come from advisory text and may describe the product, not this file."]},
 "warnings": []}
```
`search-anchors/1` is NEW, additive (a new result object inside the existing envelope; no persisted contract changes; schema generated to `docs/schemas/search/` by `tools/generate_*_schemas.py` pattern with regenerate-and-compare). `anchors` keep the `AnchorSet` order (kind, value, source, pointer) so equal input gives equal output. There is no per-CVE combined number.

Exit codes (mirror `exit_for`): 0 at least one anchor `changed` or `indexed-only`; 4 no anchor has a hit AND no anchor is `unknown` (complete absence in scope, or nothing searchable; wording "no anchor of CVE was found in the indexed project"); 3 no hit and at least one `unknown` (absence unproven); 2 bad CVE syntax, missing project, `PT-SEARCH-CAPABILITY` (no FTS5), conflicting options; 5 cancelled. `unavailable` status plus exit 4 and text `No stored advisory lists {cve}. Import a CSAF document (intelligence import) or attach a KB context (kb attach).` when no anchors exist at all.

## 5. Algorithm

```
anchors_from(handle, cve):                       # runs on the OWNER thread up to step 3 (project store is owner-thread-only)
  1. cve = normalise_cve(cve)                    # kbcorrelation.ids / intelligence CVE_ID; 24 chars max
  2. enrichment = EnrichmentStore(handle.store)
     csaf = AdvisoryStore(root, enrichment, project.id, project.revision).for_cve(cve)    # (advisories, warnings)
     sets = []
     if csaf.advisories:
         older, newer = project_identities(project.artifacts, root, {}, cancel)
         report = intelligence.explain.build_report(cve, all_advisories, older, newer)    # contains AnchorSet incl. api hints
         sets.append(report.anchors)
     for bundle in kb-context rows whose context.cards contain cve:
         sets.append(AnchorSet(cve, bundle.anchors))        # NEW additive field, section 6
     anchors = merge_sorted_unique(sets)                    # by anchor_id; provenance kept per anchor
  3. if not anchors: unavailable (exit 4) with the text above
  4. specs = default_specs(handle) + production_extra_specs(handle)         # section 7: advisory/tool/unified wired
     service = SearchService(handle, cache_root, attention=..., extra_specs=production_extra_specs)
     if not --no-index-build: service.build()                 # cheap-first, per-group digests, incremental
  5. for each anchor in order:                                 # worker thread allowed from here: only the segment files are read
         plan = plan_for(anchor)                               # quoted phrase, never query syntax
         status = anchor_coverage(plan, service.search)
  6. summary counts; exit code by section 4
```
Rules: (a) the anchor value is always a quoted phrase (`_phrase`), so no advisory character acts as query syntax; (b) kind filter is a UNION of binary-evidence kinds, see section 5.1; (c) changed scope first, then indexed; a miss is `none` only if every group of both runs is `indexed` or `not-applicable`, otherwise `unknown`; (d) nothing is scored, summed or averaged across anchors; (e) no anchor is dropped: an unusable one is `not-searchable` with its reason (value over 400 characters, empty after folding).

### 5.1 Circularity guard (NEW, found by reading; UNVERIFIED by a running repro)

Today `plan_for` filters only `pdb` -> `kind:build` and `string` -> `kind:string`. Once the advisory groups are indexed (section 7), a `module`, `feature`, `component` or `api` anchor derived from advisory TEXT would match the advisory document it came from in the `indexed` scope and report `indexed-only` with `hits >= 1`, a false positive that says nothing about the binary. Fix: `KIND_FILTER` becomes a closed allow-list of binary-evidence kinds for every anchor kind except `string`/`pdb` overrides:

```
BINARY_KINDS = ('function', 'code', 'asm', 'string', 'import', 'export', 'capability', 'rule', 'build')
query_text(anchor) = ' '.join(['kind:' + k for k in kinds_for(anchor.kind)] + [scope] + [phrase])
kinds_for('pdb') = ('build',); kinds_for('string') = ('string',); otherwise BINARY_KINDS
```
(`advisory`, `cve`, `cwe`, `kb`, `note`, `finding` are excluded: they are the analyst's and the vendor's words.) Multiple `kind:` tokens are a union (`parse_query` sorts the set). Red test: a real `SearchService` over a synthetic project with a CSAF advisory whose title names `clfs.sys` and a binary with no such name: expected status `none`, not `indexed-only`.

## 6. Where CVRF-only CVEs get anchors

CSAF anchors come from `AdvisoryStore`. For a CVE known only from a CVRF month the attach path stores a `kb-context` row whose `ContextBundle` has no anchors (verified: no `anchor` token in `kbcorrelation/context.py` or `service.py`). Add (additive, default empty) `ContextBundle.anchors: tuple[Anchor, ...] = ()`, computed at attach from each card's CVRF title with `intelligence.anchors.text_anchors(title, 'cvrf-title', pointer)` where `pointer` is the RFC 6901 pointer of the title field recorded by the parser (`RawVulnerability.at + '/title'`); if the pointer is not available for a card, that card yields no anchors and the bundle records the limitation "no CVRF title pointer" (no anchor without provenance). `context_key` includes a digest of the anchors only if the field is non-empty, so existing rows keep their keys. Schema regenerated with `tools/generate_kbc_schemas.py`.

## 7. Production wiring of the extra groups (precondition of useful `unknown`)

`production_extra_specs(handle) -> BuildRequest -> tuple[SourceSpec, ...]` in `search/wiring.py` (NEW; the only `search` module that imports `intelligence`, `enrichment`, `unified`): GUI/owner thread builds `advisory_specs(AdvisoryStore(...), cve_snapshot_port)`, `tool_specs(...)`, `unified_specs(...)`, each from stored rows only; a missing store returns `skipped(group, kinds, None, 'unavailable', reason)` (never absent). `SearchService(extra_specs=...)` is passed by `search/cli.py` and by `search/qt_panel.py` (the integrator owns `qt_panel` wiring; see gameplan KBB-05b).

## 8. Error codes and exit codes

`PT-SEARCH-QUERY` (2), `PT-SEARCH-CAPABILITY` (2: no FTS5, or conflicting options), `PT-SEARCH-INPUT` (2), `PT-SEARCH-SOURCE` (3), `PT-SEARCH-STALE` (3), `PT-SEARCH-LIMIT` (3), `PT-SEARCH-STORE` (3: cache root inside the project, store failure), `PT-SEARCH-LOCATOR`, `PT-SEARCH-TIMEOUT` (3), `PT-SEARCH-CANCEL` (5). Locked project: exit 2, text `the project is open in another PatchTrace window or process; close the desktop and try again` (BUILT, `LOCKED`).

## 9. Determinism, privacy, security

Same project, same stored advisories, same index digest give the same JSON bytes (sorted keys, ordered anchors). The cache root is never inside a project (`PT-SEARCH-STORE`, tested). Nothing is fetched, uploaded or executed. Advisory text reaches the query only as a quoted phrase after tag stripping and folding; results are rendered as plain text. Recents are not written by this verb.

## 10. Budgets

`--anchors-from` over a 100k-function project with an existing index: under 2 s for 50 anchors (each anchor is at most two `limit=1` searches); index build budgets are the WB1 ones (`tools/bench_search.py`). A single anchor search honours `PT-SEARCH-TIMEOUT`.

## 11. Test plan (red first)

`tests/test_search_cli.py`: replace `test_anchors_from_is_a_capability_error_until_s10` with `test_anchors_from_reports_each_anchor_with_its_coverage` (changed / indexed-only / none / unknown / not-searchable on a synthetic project, golden JSON); `test_anchors_from_rejects_query_and_kind`; `test_anchors_from_without_an_advisory_is_exit_4_with_the_import_hint`; `test_anchors_from_unknown_group_is_exit_3_not_4`; `tests/test_search_anchors_real.py` (circularity: section 5.1, real `SearchService`); `tests/test_search_wiring.py` (production specs include `adv`, `cve`, `tool`, `ir` or an explicit `unavailable` entry; importing `patchtrace.search.anchors` imports no Qt); `tests/test_kbc_context_anchors.py` (CVRF title anchors carry `cvrf-title` source and pointer, none without a pointer). Existing `tests/test_search_*.py` stay green.

## 12. Open questions

Q1 Should module anchors also search `in:name` only for imports/exports? Default no (union is simpler and the guard keeps it honest). Q2 Show anchors in the Search dock now or after the Windows pass? Default after (KBB-05b is separable).

## 13. Acceptance

`python -m patchtrace search P --anchors-from CVE-2099-20001 --json` on the synthetic project returns the contract above; the circularity test is green; the output never contains a banned stem; exit codes per section 4; `tests/test_search_*.py` and `tests/test_intel_anchors.py` green on Linux and Windows.
