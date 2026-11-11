# Binding the K8 adapters, the engine adapter and the KEV link-up to production (KBF-06)

Status: draft, developer-ready design. The adapters exist and are unit-tested; the bindings in sections 4 to 7 are NOT built. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-06. Owner packages: `kbcorrelation/{adapters/*,cli_leads,cli,wiring,context,panel_qt}.py`, `kev/{kb_adapter,service,store,view_model}.py`, `pilot/{collect,sources/kev,sources/tools}.py`, `intelligence/tools/{store,capa_pairs,delta}.py`. Reads with KB plan s4 and K8 row of s9, KEV plan s4-s6, PIL plan s4/s9, KBF-03, KBF-04.

## 1. Purpose and non-goals

Purpose: today the KB correlator and the Leads dock behave as if KEV, tool deltas, search hits and FAB anchors do not exist, even though each has a built, tested adapter. This spec says exactly how each adapter is bound, in which process and thread, and what the user sees when the binding finds nothing.

Non-goals: a new adapter; any change to function ORDER by KEV, search or anchors (forbidden by invariant); network access from an adapter (adapters read stored data only).

## 2. State of the code (verified on `54fd085`)

| Adapter | File | Tests | Bound in production? |
|---|---|---|---|
| KEV lookup for `leads.ExploitationLookup` (`KevExploitation`, `AnchorExploitation`, `FirstAnswer`) | `kbcorrelation/adapters/kev.py` (72 lines) | `tests/test_kb_adapters_k8.py` | NO. `kbcorrelation/cli.py:Context.kev` defaults to `None` -> `NullExploitation` -> chip "KEV: not loaded". `grep -rn "KevExploitation" src` finds only the adapter |
| FAB anchors about a CVE (`cve_facts`) | `adapters/anchors.py` (58) | same | NO (no importer) |
| WB1 hits as corroboration (`search_leads`) | `adapters/search.py` (58) | same | NO |
| Unified rows + attention ranking as `EngineView` (`engine_view`) | `adapters/engine.py` (57) | same | NO. Production `kb leads` and the KB dock use `cli_leads.RealEngine` (stored B1 default-profile ranking + signals via `enrichment.pipeline.load_default`); its docstring says "slice K8 moves them to `adapters/engine.py`" and `tests/test_kbc_contracts.py:376` allow-lists the `enrichment` import for `cli_leads.py` until then |
| KEV for `pilot` | `pilot/sources/kev.py::CatalogKev` | `tests/test_pilot_sources_*` | NO. `pilot/collect.py` always passes `_NoCatalog` and keeps `kev` out of `PilotInputs.kev_snapshot_id` |
| capa/FLOSS/DiE deltas for `pilot` | `pilot/sources/tools.py::ToolDeltas` | `tests/test_pilot_sources_code.py` etc. | NO. `collect.py` builds `tools = _Down(not-run, TOOLS_NOT_READ)` with the fixed reason `stored capa, FLOSS and Detect It Easy results are not read by this command yet` |
| KB window (`pilot/sources/window.py`) from KB | `KbWindowSource` port | - | NO. Contexts carry only the CSAF-derived confounded count |

## 3. Binding rules (apply to every row below)

1. Read-only and offline: a binding reads stored rows/files; it never fetches, runs a tool, or writes.
2. Owner-thread-only project reads (QA-S2-2, KBF-08): the binding is split into `read(owner) -> immutable Snapshot` and `adapt(snapshot) -> view` (worker or any thread). No adapter holds a `ProjectService`.
3. Absent = unknown: no catalog -> `KevFact('no-snapshot')`; no stored tool run -> channel `not-run` with a fixed reason; no search run -> `SearchLeads(complete=False)`. Never `not-listed`, never a counter-vote.
4. Provenance on every row: KEV snapshot id (64 hex) and date added; tool run key (`ToolKey(engine, side)`); search `index_key` and `digest16`; anchor `source` slugs.
5. KEV never changes function order; search hits and anchor counts never become a score; independent-origin counts are shown as counts (`min(hit.components, len(seen_by))`).

## 4. KEV into `kb leads`, the KB dock and the KB context

```
kbcorrelation/wiring.py  (the only module that imports sibling packages)
def default_kev(now=None) -> ExploitationLookup:
    store = kev.store.KevStore(kev.store.default_kev_dir())
    loaded = store.load_current()                      # Loaded | None; a damaged current pointer falls back (INT-1 fixed)
    if loaded is None: return NullExploitation()
    provider = kev.view_model.KevColumnProvider(loaded.catalog, now or utcnow())
    return adapters.kev.KevExploitation(provider)       # KevLookupPort
Context.kev = default_kev() when not injected (tests keep injecting)
```
Staleness wording comes from the KEV provider (`freshness`, `age_days`); `kb leads` prints the catalog age line from `provider.summary_line(cves)` once, above the groups. Groups already sort by (KEV listed, supporting channels, CVE id); keep it.

`context_key` gets the real `kev_snapshot_sha` (`context.py:93` is `None` today) so a context built before a KEV catalog existed is stale-for-reference after one is installed: reason text "KEV catalog {id16} was loaded after this context was prepared" (a new `stale_reasons` string; no new enum). Because `context_key` changes only when a catalog is present, existing rows keep their keys.

`FirstAnswer([KevExploitation(port), AnchorExploitation(fab_anchors)])` is used only when FAB anchors are available; a catalog's `not-listed` outranks silence from the anchors (already coded).

## 5. Engine view: one adapter, two sources

Keep `RealEngine` for the headless `kb leads` (reads the B1 default-profile ranking). Add `adapters/engine.py::engine_view` as the unified source: `UnifiedMatch` rows from `unified.read_model.load` plus the unified attention ranking. Selection rule (deterministic, stated in the output): if a current unified result exists for the exact pair and run it is the engine view and the report says `engine: unified@<result_id16>`; else the stored B1 ranking `engine: ghidriff-b1`; else none (`no-comparison`). The two are NEVER merged or averaged. Move `RealEngine` into `adapters/engine.py` (pure) + `wiring.py` (project reads) so `cli_leads.py` stops importing `enrichment` (remove the allow-list entry in `tests/test_kbc_contracts.py:376` in the same change; that test is the guard).

## 6. Pilot collect: tools and KEV channels (Leads dock)

```
pilot/collect.py::collect(service, enrichment, ..., cancel):                  # still owner thread for the READ phase (KBF-07)
    kev = CatalogKev(snapshot_id, {cve: date_added for listed CVEs in `universe`}) if a KEV catalog is loaded
          else _NoCatalog                                     # state unknown, snapshot None
    runs = intelligence.tools.store.read_runs(enrichment, older_sha, newer_sha)   # stored ToolRun + ToolEvidenceSet, no tool is run
    inputs = [ToolInput(delta=delta.compute(old_set, new_set, ...), runs=(old_run, new_run)) for each engine with both sides]
    tools = ToolDeltas(inputs, candidate_index, older_sha256=..., newer_sha256=...)       # statuses per engine
    # engines with a missing side => ChannelStatus(state='not-run', reason=<fixed text>), never an empty delta
    PilotInputs.kev_snapshot_id = catalog snapshot id or None
    PilotInputs.tool_keys       = sorted ToolKey(engine, side) actually used
```
The fixed reason strings stay (`TOOLS_NOT_READ` is removed only when this slice lands; a grep test pins that it is not in `collect.py` afterwards). A tool run from another pair (hash mismatch) is `PT-TOOL-MISMATCH`/`stale` and yields `not-run`, not an error for the whole run.

## 7. Search hits and FAB anchors as lead chips

`search_leads(SearchResult)` and `cve_facts(anchors)` feed `kbcorrelation/leads.py` as optional ports exactly as the K8 tests show (`complete=False` -> "search incomplete; absence of a hit is unknown"). Binding: the Leads/KB workers receive a prepared `SearchResult` computed by the Search dock service (owner thread builds, worker reads segments) or none. Hits never reorder; they add chips (`anchor`, `code-change` channels) with the original provenance. FAB anchor facts are read through `fabric.store` (`anchor-batch` rows) the same two-step way. Both are optional capabilities: a missing port shows the chip text "not loaded".

## 8. Error codes

Adapters raise nothing for absence. Corrupt stored KEV data: `PT-KEV-STORAGE`/`PT-KEV-FORMAT` mapped to chip "KEV: catalog unreadable" and a warning, exit stays 0/4. Tool store problems: `PT-TOOL-STORE`, `PT-TOOL-STALE`, `PT-TOOL-MISMATCH` -> channel `failed`/`not-run` with the code in `ChannelStatus.reason`, never fatal. KB: `PT-KBC-STORAGE` for the workspace.

## 9. Determinism

Same workspace + same project + same KEV snapshot give byte-equal `kb leads --json` (sorted keys; groups ordered as above). The `engine` source line and `kev` snapshot id are part of the output so a diff explains itself.

## 10. Security and privacy

KEV text is CISA's (CC0) but still untrusted: `vulnerabilityName` etc. are cleaned by `plain_text` before display; no URL from KEV is opened. No consent is needed because nothing is fetched. A KEV entry never names a function.

## 11. Budgets

`default_kev()` loads and indexes a catalog of about 1,500 entries in under 100 ms; `KevColumnProvider.cell` is O(1) after first call; adding the tool and KEV reads to `collect` must not raise the owner-thread read phase above 250 ms on the 5,000-function synthetic project (the heavy PE overview and signal computation move to the worker, KBB-02).

## 12. Test plan (red first)

`tests/test_kbc_kev_binding.py` (a KEV store with the synthetic 2099 catalog installed -> `kb leads --json` shows `listed 2099-02-12` in the group header and row order unchanged vs no catalog; damaged current pointer -> "catalog unreadable", exit 0); `tests/test_kbc_context_kev_key.py` (installing a catalog changes `context_key` and marks the old context stale for reference; no catalog -> key unchanged byte for byte); `tests/test_kbc_engine_selection.py` (unified present -> `engine: unified@...`; absent -> `ghidriff-b1`; swap orientation -> stale); `tests/test_pilot_collect_kev_tools.py` (listed CVE order only; `kev_snapshot_id` recorded; tool store with both sides -> channel available, one side -> `not-run`, other pair -> `stale`; no `TOOLS_NOT_READ` string remains); `tests/test_kbc_adapters_optional.py` (each port missing -> "not loaded" chips, exit code unchanged). Existing: `test_kb_adapters_k8.py`, `test_kev_synergy.py`, `test_kev_kb_integration.py`, `test_kbc_synergy.py`, `test_pilot_synergy.py` must stay green; `test_kbc_contracts.py` import-DAG test enforces that `cli_leads.py` no longer imports `enrichment`.

## 13. Open questions

Q1 Should a stale KEV catalog (older than the KEV freshness policy) still group CVEs KEV-first? Default yes with the age shown (KEV plan). Q2 Do tool deltas count as a Leads channel for the beta, or ship the dock with `not-run` tools? Default bind them (cheap) but keep each engine optional.

## 14. Acceptance

With a KEV catalog installed and a stored capa pair, `kb leads` and `pilot leads` show the KEV group header and the capa channel; with neither installed the output equals today's byte for byte except the new `engine:` line; all tests above green; no listed word from the banned set appears.
