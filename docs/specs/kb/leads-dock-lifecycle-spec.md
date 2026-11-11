# Leads dock lifecycle: states, prepare / rank / publish phases, cancel (KBF-07)

Status: draft, developer-ready design; documents BUILT behaviour of `ui_leads.py` (787 lines) and `pilot/read_model.py` at `54fd085` and the changes needed for beta. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-07. Owner packages: `ui_leads.py`, `pilot/{panel,read_model,collect,service,store}.py`. Reads with PIL plan s8, `docs/specs/gui-framework.md`, KBF-03, KBF-06, KBF-08.

## 1. Purpose and non-goals
Purpose: pin every state of the Leads dock (L0 to L8, including L1b, L3, L4, L7), the three phases of "Prepare leads" and what Cancel really does. Non-goals: new ranking; a second window; modal dialogs.

## 2. States (text is BUILT, `pilot/read_model.py`)
| id | when | text |
|---|---|---|
| L0 | no project | `Open a project to see leads.` |
| L1 | project without a completed run | `No comparison result yet. Run the analysis first; leads are computed from stored results only.` |
| L1b | completed run, no stored leads | `No leads have been prepared for this comparison yet. Use Prepare leads; they are computed from the stored comparison and advisories only.` |
| L2 | preparing | `Preparing leads: {stage} {done}/{total}` or `...: {stage} (no counts available)`; Cancel shown |
| L3 | table shown, nothing missing | the table, first CVE context or code-only |
| L4 | table + banner | `Some evidence was not available: {channels}. Missing evidence is unknown, not a negative result.` |
| L5 | failure | `Leads could not be prepared: {code}: {message}. The stored comparison and earlier leads are unchanged.` Retry, Copy details |
| L6 | stale | `These leads are out of date: {changed}. They are shown for reference only.` |
| L7 | table, no advisory | `No advisory is loaded. Leads use code evidence only and are not matched to a CVE. Import an advisory to rank by fit.` |
| L8 | too many rows | `Too many rows to display ({n}). Narrow the filter.` |
Precedence: L5 > L6 > L4 > L3; L2 only before the first table; L0/L1 replace the content (`read_model.present`). Class vocabulary: fit, review, partial, code, queue. Navigation (Go to function) is enabled only for a lead tied to a current comparison row and never when stale.

Known test weakness: `tests/test_ui_leads.py:752` asserts `state in ('L3','L4','L7')` after an end-to-end prepare on the sample; pin the exact state (the sample has no advisory, so L7 is expected) in KBB-18.

## 3. Phases of Prepare (BUILT flow, `ui_leads.py:prepare/_collect/_ranked`)
1. COLLECT (GUI thread, deferred one turn so the progress line paints): `collect_inputs(service, CancelToken())` -> `pilot.collect.collect`. It reads rows AND does heavy work: bounded PE parse of both artifacts (`_overview`), `GhidriffRows.resolve`, B1 signals (`pipeline.run` in memory if none stored), unified result load, `project_identities`, advisory normalization reads. Stage text `collecting evidence 0/3`.
2. RANK (worker, `tasks.submit('leads.compute', ...)`): `localize(collected, default_config(), token)`; `PilotError` is RETURNED (not raised) so the refusal text reaches the GUI. Stage `ranking 1/3`.
3. PUBLISH (GUI thread): `store.publish(EnrichmentStore, assessment, config, current=store.current_guard(...))`, stage `storing 2/3`, then `reload()` (L3/L4/L7).
Defects (by reading; the end-to-end test passes because the sample is tiny):
- D1: phase 1 runs on the GUI thread, so a large pair freezes the window during PE parse/signals, the progress line cannot update and Cancel cannot be clicked. The `CancelToken()` passed is created inside `_collect` and nothing can set it: `cancel()` only clears `collecting`/`progress` BEFORE `_collect` starts (the zero-delay timer window).
- D2: after Cancel in phase 2 the worker is cancelled via the channel, good (`test_close_while_computing_cancels_and_waits`), but a cancel during phase 3 is impossible and not needed (single transaction).
- D3: `known_inputs` names four `PilotInputs` fields only, so advisory/KEV/KB changes do not mark leads stale (KBF-03).

## 4. Fix: two-phase collect (KBB-02)
```
collect_read(service, enrichment) -> ReadPhase        # OWNER thread, <= 250 ms budget, no PE parse
    project snapshot (artifacts, matches of the run, run id/raw sha), stored signals if current,
    unified result handle/rows, secondary sets, advisory list (AdvisoryStore.advisories()), KEV catalog extract,
    stored tool runs; all frozen plain values
collect_compute(read: ReadPhase, cancel: threading.Event, report) -> Collected    # WORKER
    _overview(older), _overview(newer) via VerifiedArtifactReader (path from read.root, hash checked)
    GhidriffRows.resolve, pe.address_map, signals if missing (pipeline.run on read.project value),
    identities, universe(), contexts
pipeline: read (owner) -> compute (worker, channel 'leads.collect', cancellable, progress 'collecting evidence i/3')
          -> rank (worker, 'leads.compute') -> publish (owner)
```
Rules: a single token per Prepare, `cancel()` cancels both worker channels; each worker step polls the token every 64 work units (`_CHECK_EVERY`) and raises `PT-PILOT-CANCEL`; results of a cancelled or superseded request are dropped (channel generation). The VerifiedArtifactReader runs in the worker, which is allowed because it opens the artifact FILE, not the project database. Publish stays one owner-thread call and is atomic (sidecar directory install + pointer row; `pilot/store.py` fsyncs, H-01 fixed).

Cancel semantics (binding text): cancel before publish -> nothing stored, previous leads unchanged, status line `Preparing leads was cancelled. Earlier leads are unchanged.` (announced politely); cancel after publish started -> not offered. `PT-PILOT-CANCEL` maps to CLI exit 5.

## 5. Contracts
`ReadPhase`, `collect_read`, `collect_compute` are NEW in `pilot/collect.py` (pure + owner-read functions; `collect()` remains as `collect_compute(collect_read(...))` for the CLI so `pilot leads` is unchanged). No persisted contract changes; `PilotInputs` additions (`advisory_facts_ids` etc. already exist) are filled by KBF-06.

## 6. Error codes
`PT-PILOT-NOTFOUND` (no completed run; no named CVE), `PT-PILOT-INPUT` (too many CVEs: `{n} CVEs have stored advisories and a run covers at most {cap}: name up to {cap} with --cve`), `PT-PILOT-LIMIT` (deadline), `PT-PILOT-STORAGE`, `PT-PILOT-INTEGRITY`, `PT-PILOT-CANCEL`. The dock shows `{code}: {message}` for `PilotError` and `{exception_class} stopped the work` for anything else (class only, no text).

## 7. Determinism, privacy, security
Same inputs -> same `result_id` -> byte-equal sidecar. Reviews (pin, dismiss, note) are append-only events outside the result identity; a note is shown as "analyst statement", never a finding. No network, no execution. Clipboard copies go through `ctx.shell.copy_text` of sanitized text.

## 8. Budgets
Owner read phase <= 250 ms (5,000 functions); worker collect + rank for 5,000 pairs x 8 CVEs <= 5 s (`TARGETS`); first paint <= 200 ms; filter 100k rows <= 100 ms; detail <= 50 ms; `data()` calls independent of row count (`test_data_is_called_for_what_is_visible_only`).

## 9. Test plan (red first)
`tests/test_ui_leads_collect_phases.py`: (a) the owner read phase runs on the GUI thread and the compute phase does NOT (thread ids recorded by fakes); (b) a collector that sleeps in compute leaves the GUI event loop responsive (a `QTimer` ticks during Prepare); (c) Cancel during collect yields the cancel text and stores nothing; (d) project switch during collect drops the result; (e) exact end-to-end state for the sample is `L7`. `tests/test_pilot_collect_split.py`: `collect_compute(collect_read(x))` equals the old `collect(x)` field for field on the synthetic project. Existing `tests/test_ui_leads.py`, `tests/test_pilot_*.py` green; 20x gate: `python tools/qt_gate.py --repeat 20 tests/test_ui_leads.py`.

## 10. Open questions
Q1 Keep the zero-delay timer once collect is off-thread? Default drop it. Q2 Offer "Prepare for CVE X only" (`--cve`)? Default CLI only.

## 11. Acceptance
Tests above green on Linux and Windows (`qt-gate (windows-latest, 5)`); a 5,000-function synthetic project keeps the window responsive during Prepare (manual row on the Windows pass); every L-state reachable by a test.
