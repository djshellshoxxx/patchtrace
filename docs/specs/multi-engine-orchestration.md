# SPEC-28: Multi-engine orchestration (Phase C: C0, C1, C2, C5)

Status: developer-ready draft, 2026-10-14. Contract versions `engine-run/1`, `secondary/2` (reads `secondary/1`). Extends SPEC-10 (BinDiff), SPEC-11 (rz-diff), SPEC-27 (calibration). Plan: `../plans/phase-c-multi-engine-plan.md`.

## 1. Outcome

One headless, Qt-free orchestration layer that runs the optional secondary engines (rz-diff now, BinDiff after C3/C4, Ghidriff-baseline as a read-through adapter) against a project's artifact pair with bounded parallelism, cancellation, per-engine deadlines and failure isolation; records every attempt as an auditable `EngineRun`; caches by a content-addressed key; stores exactly one current `SecondaryMatchSet` per engine so `secondary reconcile` can no longer fail on duplicates; and persists alternative matches with source labels. Fixes the verified defect: `assess_reports` raises `ValueError('one report per distinct secondary engine required')` when two stored sets share an engine, and `secondary reconcile` currently loads every non-stale set (entry ids embed `file_sha256`, so each re-run adds a row).

## 2. Non-goals

- No GUI (C6), no BinExport producer or protobuf (C3), no real BinDiff execution (C4), no calibration (C9).
- No averaging or ranking of engine confidences; conflicts stay `contested`; a missing match is unknown, never a negative vote.
- No running Ghidriff from the scheduler: its run path (`backend`/`analysis` modules) is unchanged. `ghidriff-baseline` only adapts the already-stored primary run into the registry for uniform provenance.
- No bundling of rizin/BinDiff; no network access; no auto-install.
- No change to `secondary/1` rows already on disk; no migration pass.

## 3. Module layout

```
src/patchtrace/secondary/
  runs.py        EngineRun, EngineOutcome, cache_key(), argv_digest()           (pure, pydantic, no I/O)
  registry.py    EngineAdapter Protocol, REGISTRY, adapters: ghidriff_baseline / bindiff / rzdiff  (pure + injected runner)
  scheduler.py   run_engines(): bounded pool, cancel fan-out, deadlines          (stdlib threading only)
  store.py       publish_engine_set(), current_sets(), publish_run(), find_cached()  (over EnrichmentStore)
  contracts.py   + AlternativeMatch, secondary/2 fields (append-only, see 4.3)
  rzdiff.py      refactored: probe/run/parse exposed through the adapter; public functions unchanged
src/patchtrace/cli.py  + `secondary run`, reconcile uses store.current_sets()
.github/workflows/live-rizin.yml   (C2)
```
`ui.py` is untouched. Nothing under `secondary/` imports Qt.

## 4. Typed interfaces

Repo convention: strict pydantic v2 models (`_Strict`: `extra='forbid', strict=True, frozen=True`) for anything persisted; frozen dataclasses for in-memory-only results.

### 4.1 Records (`runs.py`, persisted as enrichment kind `engine-run`)
```python
EngineId = Literal['ghidriff-baseline', 'bindiff', 'rz-diff']
Status = Literal['ok', 'failed', 'cancelled', 'unsupported', 'timeout', 'cached']
Orientation = Literal['older->newer']          # only value in v1; a reversed pair is PT-SECONDARY-ORIENTATION

class EngineRun(_Strict):                       # one row per attempt, never updated after write
    contract: Literal['engine-run/1'] = 'engine-run/1'
    run_id: str                                 # domain_id('engine-run', 1, {cache_key, started_utc})
    engine: EngineId
    engine_version: str | None                  # None when unsupported before probe succeeded
    executable_path_sha256: Sha256 | None       # hash of the resolved path string, not the path (no user paths in exports)
    argv_digest: Sha256                         # sha256 of JSON list of argv with input paths replaced by '<older>'/'<newer>'
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Orientation
    cache_key: Sha256
    status: Status
    error_code: str | None                      # PT-SECONDARY-* when status in {failed, unsupported, timeout, cancelled}
    returncode: int | None
    started_utc: str                            # ISO-8601 UTC
    duration_ms: int = Field(ge=0)
    stderr_tail: str = Field(max_length=65_536) # truncated copy of the bounded tail, control chars stripped
    output_sha256: Sha256 | None                # SHA-256 of raw stdout bytes (rz-diff) or imported file (BinDiff)
    match_set_id: str | None                    # entry id of the stored SecondaryMatchSet, when produced
    superseded_by: None = None                  # reserved; never written in v1 (append-only)

@dataclass(frozen=True)
class EngineOutcome:                            # in-memory, returned by the scheduler
    run: EngineRun
    match_set: SecondaryMatchSet | None         # present iff run.status in {'ok', 'cached'}
    error: SecondaryError | None
```
`stderr_tail` in the stored record is 64 KiB (UI/exports); the full 2 MiB tail is only held in memory for the CLI `--verbose` path.

### 4.2 Registry and capability interface (`registry.py`)
```python
@dataclass(frozen=True)
class EngineJob:
    older: Path; newer: Path                    # absolute, inside the project root
    older_sha256: str; newer_sha256: str
    env: Mapping[str, str]; workdir: Path       # private temp dir created by the scheduler
    cancel: threading.Event; deadline_seconds: float
    runner: Callable = run_process              # injected; adapters must call only this to spawn

class EngineAdapter(Protocol):
    id: EngineId
    def probe(self, job_env: Mapping[str, str], cancel: threading.Event) -> Capability: ...
    def argv(self, cap: Capability, job: EngineJob) -> tuple[str, ...]: ...       # pure; used for argv_digest + cache key
    def run(self, cap: Capability, job: EngineJob) -> RawResult: ...              # spawns via job.runner only
    def parse(self, raw: RawResult, cap: Capability, job: EngineJob) -> SecondaryMatchSet: ...  # strict, raises SecondaryError

@dataclass(frozen=True)
class RawResult:
    returncode: int; stdout: bytes | None; stderr_tail: str; file_path: Path | None; reason: str | None

REGISTRY: Mapping[EngineId, EngineAdapter]     # immutable; order = ('rz-diff', 'bindiff', 'ghidriff-baseline') only for display
```
- `rz-diff`: wraps today's `probe`, argv `-C -j -t functions`, `parse_output`. C2 must re-verify flags on the pinned version before they are frozen in `argv()`.
- `bindiff`: `probe` reports `unsupported` (reason `PT-SECONDARY-UNSUPPORTED: BinDiff execution not implemented (C4)`) until C4; `parse` = existing `import_bindiff` (importing a user-supplied `.BinDiff` remains available through `secondary import-bindiff`, and is recorded as an `EngineRun` with `argv_digest` of `["import-bindiff"]`).
- `ghidriff-baseline`: `probe` supported iff the project has a completed run; `run` returns the stored raw output hash; `parse` is not a `SecondaryMatchSet` (Ghidriff matches are primary records), so it yields an `EngineRun` with `match_set_id=None` and is excluded from `reconcile`. Purpose: one provenance table, not a second code path.

### 4.3 Persisted additions (append-only, backward compatible)
1. New enrichment kind `engine-run` (add to `KINDS`; `EnrichmentStore.ensure` already creates tables lazily and backs up before DDL). Older PatchTrace builds read-only-open newer stores per existing `PT-ENRICH-STALE` behaviour and ignore unknown kinds; verify with a test (`test_old_reader_ignores_engine_run_kind`).
2. `SecondaryMatchSet.contract` becomes `Literal['secondary/1', 'secondary/2']`. New optional fields with defaults, only emitted when non-default so v1 JSON round-trips byte-identically:
```python
class AlternativeMatch(_Strict):
    anchor_side: Literal['older', 'newer']
    anchor_address: Address
    candidate: SecondaryMatch                  # same validation as a primary record
    source: Literal['rz-diff', 'bindiff', 'ghidriff-baseline']   # label of the engine that proposed it
    rank: int = Field(ge=1)                    # 1 = engine's own best; engine order, never re-scored
SecondaryMatchSet.alternatives: tuple[AlternativeMatch, ...] = ()
SecondaryMatchSet.run_id: str | None = None    # back-reference to EngineRun
```
3. Stored-set identity: `entry_id` for `secondary/2` = `domain_id('secondary', 2, {'engine', 'older', 'newer'})` (no `file_sha256`), so a re-run/re-import of the same engine on the same pair upserts the same row (existing `ON CONFLICT(id) DO UPDATE`). `secondary/1` rows keep their old ids and are never rewritten.
4. Schemas: regenerate with the repo's schema tool after the model change; commit `docs/schemas/EngineRun.json` and updated `SecondaryMatchSet.json`; CI already fails on schema drift.

## 5. Scheduler (`scheduler.py`)

```python
def run_engines(project: ProjectRef, engines: Sequence[EngineId], *, max_parallel: int = 1,
                per_engine_timeout: Mapping[EngineId, float] | None = None, cancel: threading.Event,
                cache: CacheLookup | None = None, env: Mapping[str, str],
                on_event: Callable[[EngineEvent], None] | None = None,
                registry: Mapping[EngineId, EngineAdapter] = REGISTRY) -> tuple[EngineOutcome, ...]: ...
```
Rules:
- `max_parallel` default 1, allowed 1..2 (values >2 raise `ValueError` -> CLI exit 2). Memory-heavy tools plus a 64 MiB stdout cap make wider fan-out a product decision, not a default.
- Result ordering is deterministic: the tuple is in the caller's `engines` order (de-duplicated, stable), independent of completion order. `on_event` is delivered from workers and may arrive in any order; consumers must not rely on it for ordering.
- One shared `cancel` event is the only cancel channel. The scheduler never creates child events per engine and passes the same object to `run_process`, which already kills the process tree (Windows Job Object via `_windows_process`, `killpg` on POSIX). No new process-spawn code exists in `secondary/`.
- Per-engine deadline: default 1,800 s (rz-diff range 60..86,400 per SPEC-11); applied as `timeout_seconds` to `run_process`; `reason == 'timeout'` -> status `timeout`. Probe has its own 30 s budget outside the deadline. There is no global deadline; cancellation is the global stop.
- Failure isolation: each worker body is wrapped; `SecondaryError`, `OSError`, `RuntimeError('PT-BACKEND: ...')` and any unexpected `Exception` become that engine's `failed` outcome (unexpected -> `PT-SECONDARY-RUN` with exception class name only). Other engines continue. `KeyboardInterrupt`/`SystemExit` set `cancel` and propagate after workers are joined.
- Hard invariant: after `run_engines` returns, no child process created by it is alive (workers are joined; `run_process` already guarantees this on every exit path).

```text
def run_engines(...):
    plan = dedupe(engines); outcomes = {}
    sem = BoundedSemaphore(max_parallel)
    def work(eid):
        with sem:
            if cancel.is_set(): return outcomes[eid] = cancelled(eid)          # not started
            ad = registry[eid]; t0 = monotonic()
            try:
                cap = ad.probe(env, cancel)
                if not cap.supported: return unsupported(eid, cap.reason)
                argv = ad.argv(cap, job); key = cache_key(eid, cap.version, argv_digest(argv), job.older_sha256,
                                                          job.newer_sha256, 'older->newer')
                if cache and (hit := cache.find(key)): return cached(eid, hit)   # re-validates stored set (5.1)
                with TemporaryDirectory('patchtrace-engine-') as wd:
                    raw = ad.run(cap, job_with(wd))
                if raw.reason == 'cancelled': return cancelled(eid)
                if raw.reason == 'timeout':   return timeout(eid, raw)
                ms = ad.parse(raw, cap, job)                                     # strict; may raise
                return ok(eid, ms, raw, t0)
            except SecondaryError as e: return failed(eid, e)
            except Exception as e:      return failed(eid, SecondaryError('PT-SECONDARY-RUN', type(e).__name__))
    with ThreadPoolExecutor(max_parallel, thread_name_prefix='patchtrace-engine') as pool:
        futures = {eid: pool.submit(work, eid) for eid in plan}
    return tuple(futures[e].result() for e in plan)       # plan order == deterministic order
```
Probe and run both execute inside `work`, so a hung probe on engine A never blocks engine B when `max_parallel == 2`. The scheduler itself never writes to the store; `store.py` does, called by the CLI/worker after outcomes return (keeps the scheduler pure and testable).

### 5.1 Cache
`cache_key = sha256(canonical_json([engine, engine_version, argv_digest, older_sha256, newer_sha256, orientation]))`. `argv_digest` hashes the argv with input paths replaced by placeholders and the executable replaced by its basename, so moving a project does not invalidate the cache but flag changes do. Lookup scans stored `EngineRun` rows with `status in {'ok','cached'}` and equal `cache_key`, then loads the referenced `SecondaryMatchSet`, re-validates it with the strict model, checks its `older/newer_sha256` and `file_sha256 == output_sha256`; any mismatch is a miss (never an error). A cache hit writes a new `EngineRun(status='cached')` row and does not rewrite the set. `--no-cache` forces a run. Cache never crosses projects (stores are per-project).

## 6. C5: one current set per engine, alternatives

### 6.1 Supersede on re-import/re-run (`store.py`)
```python
def publish_engine_set(store, guard, current, revision, ms: SecondaryMatchSet) -> Entry   # upsert by v2 id
def current_sets(store, current: Guard | None) -> list[tuple[Entry, SecondaryMatchSet]]    # <=1 per engine
```
```text
publish_engine_set(ms):  # ms.contract == 'secondary/2'; id = f(engine, older, newer)
    entry = store.publish(KIND, guard, current, revision, 'complete', body, ms.entry_id)   # upsert replaces body
    # legacy v1 rows for the same (engine, older, newer) are NOT deleted (append-only history);
    # they are ignored on read by current_sets().
current_sets(store, current):
    rows = [(e, m) for e, m in load_secondary(store, current) if not e.stale]   # newest-first from store
    chosen = {}
    for e, m in rows:                      # first (= newest, by created then id) wins
        key = (m.engine, m.older_sha256, m.newer_sha256)
        chosen.setdefault(key, (e, m))
    # a project has one artifact pair, so key collapses to engine; rows for a different pair are dropped with a warning
    per_engine = {}
    for (engine, o, n), v in chosen.items(): per_engine.setdefault(engine, v)
    return sorted(per_engine.values(), key=lambda v: ENGINE_ORDER[v[1].engine])
```
Tie-break when two rows have identical `created`: higher entry id (lexicographic) wins, deterministic. A stale newest row does not hide a non-stale older one (stale rows are excluded first, per "keep newest non-stale set"). `reconcile` CLI and `assess_reports` callers use `current_sets()` only; `assess_reports` keeps its `ValueError` as a defensive invariant but the CLI converts it to `PT-SECONDARY-RUN`/exit 3 rather than a traceback. Property to hold: for any sequence of publishes/re-imports/re-runs, `reconcile` returns exit 0 or 4, never an uncaught exception.

### 6.2 Alternative matches
When a secondary engine pairs one endpoint with several counterparts (rz-diff one-sided plus partial rows; BinDiff multi-candidate), the adapter's `parse` keeps the engine's highest-similarity candidate (ties: lowest address) as the primary `matches` row and emits the rest as `AlternativeMatch(source=<engine>, rank=2..)`, bounded to 8 per anchor and 50,000 per set (`PT-SECONDARY-LIMIT` beyond). `reconcile` stays read-only: a `Reconciliation` row gains `alternatives: tuple[AlternativeMatch, ...]` (default `()`), and a Ghidriff pairing equal to an alternative reports `disagreement` with note "matches alternative rank N" (never `agreement`). Alternatives are never merged across engines and never scored.

## 7. CLI

```
patchtrace secondary run PROJECT [--engine rz-diff]... [--rz-diff PATH] [--bindiff PATH]
                          [--max-parallel {1,2}] [--timeout SECONDS] [--no-cache] [--json]
```
- `--engine` repeatable; default = every engine whose probe reports supported (`rz-diff` only today). `secondary rzdiff` stays as a thin alias for `secondary run --engine rz-diff` (same flags, same JSON `result` keys; adds `run_id`).
- JSON: one document `enrichment-cli/1` with `result: {runs: [{engine, status, error_code, run_id, cache, duration_ms, matches, alternatives}], reconciliation: {...}}`; `status: partial` when at least one engine ok and at least one failed.
- Exit codes (existing contract): 0 at least one engine produced matches and none failed; 2 invalid argument/environment/unsupported with no engine runnable (`PT-SECONDARY-INPUT|UNSUPPORTED|PAIR|ORIENTATION|FORMAT`); 3 runtime failure (`PT-SECONDARY-RUN|LIMIT`, or all selected engines failed/timed out); 4 every selected engine ran cleanly with zero matches; 5 cancelled (SIGINT/Ctrl+C sets the shared event). Partial success (some ok, some failed) exits 3 with `status: partial` and the ok sets already stored, so scripts cannot mistake it for full success.
- Reconcile: `secondary reconcile` uses `current_sets()`; prints which row superseded which (entry ids) under `--json` `warnings`.

## 8. Error model

Existing codes stay: `PT-SECONDARY-INPUT, -PAIR, -ORIENTATION, -UNSUPPORTED, -RUN, -CANCEL, -LIMIT`. Added (append to `ErrorCode`):
| Code | Meaning | CLI exit |
|---|---|---|
| `PT-SECONDARY-TIMEOUT` | engine exceeded its deadline; process tree killed | 3 |
| `PT-SECONDARY-FORMAT` | output not strict/understood (already used by the CLI mapping, now declared in `ErrorCode`) | 2 |
| `PT-SECONDARY-CACHE` | cached set failed re-validation (internal, converted to a miss; recorded in `warnings`, never fatal) | n/a |
`PT-SECONDARY-CANCEL` -> 5. Messages never echo untrusted stderr; stderr appears only in `EngineRun.stderr_tail`, sanitized (control characters other than `\n\t` replaced) and size-capped.

## 9. Security invariants

1. Target binaries are only read (hashed and passed by path as data to a diff tool); never executed, loaded or installed. Engine executables are user-configured absolute paths (or `shutil.which` results) and are probed with a version flag only.
2. argv lists only (`shell=False`), absolute executable (`run_process` enforces), cwd = private temp directory removed on exit, `stdin=DEVNULL`.
3. Output bounded: stdout 64 MiB, stderr 2 MiB in-memory tail, 64 KiB persisted; sets bounded (`MAX_ROW` 32 MiB, project 128 MiB); alternatives bounded (6.2).
4. No network access and no upload by any adapter or scheduler; the C2 workflow downloads rizin in CI only, never in the product.
5. Every parsed result is strict-validated; hashes in the output must equal the project artifact pair or the result is rejected (`PAIR`/`ORIENTATION`).
6. Env for children is passed explicitly; credentials/provider keys are removed (`env` allow-list: PATH, SYSTEMROOT, TEMP/TMP, HOME/USERPROFILE).
7. A cancelled or failed run never deletes or modifies a previously stored current set.

## 10. Test plan

Fake-executable pattern from `tests/test_secondary_rzdiff.py`: `fake(tmp_path, body)` writes a shebang script (POSIX-only via `posix` mark), `cap()` builds a `Capability`, `artifacts()` writes the old/new files. New file `tests/test_secondary_scheduler.py`:
- `test_sequential_default_runs_one_at_a_time` (fake writes a lockfile; two engines never overlap with `max_parallel=1`).
- `test_parallel_two_overlaps_and_order_is_deterministic` (engine 1 sleeps longer; output tuple order equals request order).
- `test_max_parallel_three_rejected`.
- `test_failure_isolation` (rz-diff crashes with exit 1 and noisy stderr; second fake engine still `ok`; outcome tuple has both).
- `test_timeout_maps_to_timeout_status_and_kills_tree` (fake spawns a grandchild; assert no process alive afterwards).
- `test_cancel_fan_out_stops_all_running_and_marks_unstarted_cancelled`.
- `test_huge_stdout_is_bounded_and_rejected_as_limit` (use a small injected `log_limit`; do not emit 64 MiB, and never use a huge pytest parameter id, per the Windows console stall noted in docs/qa.md).
- `test_stderr_does_not_corrupt_json_document` (stderr noise with success exit; regression for separate streams).
- `test_unsupported_engine_is_outcome_not_exception`.
- `test_unexpected_exception_becomes_failed_run_without_message_echo`.
New `tests/test_secondary_runs.py`: `test_cache_key_changes_with_each_component` (parametrized over engine, version, argv, each hash, orientation), `test_cache_key_stable_when_project_moved`, `test_cache_hit_revalidates_and_misses_on_tampered_set`, `test_engine_run_schema_roundtrip`, `test_secondary_v1_json_roundtrips_unchanged`, `test_old_reader_ignores_engine_run_kind`.
New `tests/test_secondary_store.py` (C5): `test_rerun_same_engine_upserts_single_row`, `test_legacy_v1_duplicates_collapse_to_newest_non_stale`, `test_stale_newest_does_not_hide_valid_older`, `test_reconcile_never_raises_with_duplicate_engines` (hypothesis-free: loop all orderings of 3 publishes), `test_alternatives_persist_with_source_labels`, `test_alternative_equal_to_ghidriff_is_disagreement_not_agreement`, `test_alternative_limits_enforced`.
`tests/test_cli_secondary.py` additions: `test_run_json_partial_exits_3`, `test_run_all_zero_matches_exits_4`, `test_run_cancel_exits_5`, `test_run_unsupported_only_exits_2`, `test_rzdiff_alias_matches_run_output`, `test_reconcile_after_two_reimports_exit_0`.
All tests above are mocked/fake-executable evidence and are labelled as such in `docs/qa.md`; they never substitute for section 11.

## 11. C2: live rz-diff acceptance (CI design)

- Workflow `.github/workflows/live-rizin.yml` modelled on `live-backend.yml`: triggers `workflow_dispatch`, plus push/PR on `src/patchtrace/secondary/**`, `tools/live_rzdiff_check.py`, `tests/fixtures/**`, and the workflow itself. Matrix `os: [ubuntu-latest, windows-latest]`, `timeout-minutes: 20`, `permissions: contents: read`.
- Pinned install: env `RIZIN_VERSION: 0.9.1` (matches SPEC-11 research, tag commit `c3a90e9`) plus per-OS pinned asset URL and expected archive SHA-256 stored in the workflow. Step downloads from the official rizin GitHub release, verifies SHA-256 with `sha256sum`/`Get-FileHash` and fails on mismatch; no `latest`. Bumping the pin is a deliberate PR that must also re-run section 3 flag verification.
- `tools/live_rzdiff_check.py`: probes via the adapter, runs `run_engines(['rz-diff'], max_parallel=1)` on the repo fixture binary pair (the small PE/ELF pair already under `tests/fixtures/`; add one only if none is redistributable), asserts `status == 'ok'`, `len(matches) > 0`, version equals the pin, hashes round-trip into a stored set, and `secondary reconcile` exits 0 afterwards. It also asserts that `rz-diff -C -j -t functions --help` output (or a probe run) accepts each flag, so flag drift fails loudly. Writes `live-rzdiff-<os>.json` {rizin version, archive SHA-256, fixture SHA-256 pair, match count, duration} as a job artifact and step summary.
- Recording: after a green run on `main`, a human or the integration owner adds a dated row to `docs/qa.md` under a heading "Live engine acceptance (not mocked)" with OS, rizin version, archive SHA-256, run URL, match count. Entries are appended by hand from the artifact; the workflow does not push commits. `tasks/todo.md` item "[ ] live BinDiff/rizin runs" is ticked for rizin only after both OS rows exist; BinDiff stays open (`blocked: no licensed install on runner`, recorded explicitly, never skipped silently).
- Separation: tests in section 10 never import or reference the live tool; the live workflow's results are reported in their own QA table and never summed into "tests passed" counts. A Windows failure is recorded as a failure with the log, not retried until green.
- Failure on the pin's JSON schema (0.9.x drift) fails the job; response is a parser change under a new SPEC-11 amendment, not loosening the strict parser.

## 12. Acceptance gates

1. `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools` green; schemas regenerated, no drift.
2. Linux + Windows CI green for every PR; native Ghidriff matrix required for the scheduler PR (touches job behaviour via `run_process` callers).
3. Demonstrated red-to-green: `test_reconcile_never_raises_with_duplicate_engines` fails on current `main`.
4. Reading a project created before this change works unchanged (golden `secondary/1` store fixture) and `secondary reconcile` on it exits as before.
5. Live rizin job green on both OSes and recorded in `docs/qa.md`. If red or unavailable it is listed as an open gate, not hidden.
6. Windows Job Object path exercised by a scheduler test on Windows CI (cancel + timeout with child tree); POSIX-only fake tests have a Windows counterpart using `sys.executable -c` argv, not shebang scripts.

## 13. PR breakdown (cheapest capable tier)

| PR | Scope | Tier |
|---|---|---|
| P0 | This spec + `tasks/todo.md`/modules.md index rows, schema plan (C0) | low-cost (docs); integration owner reviews |
| P1 | `runs.py`, `ErrorCode` additions, schema generation, `test_secondary_runs.py` (pure) | mid-tier |
| P2 | `registry.py` + rz-diff adapter refactor (behavior-preserving) + bindiff/ghidriff stubs | mid-tier |
| P3 | `scheduler.py` + `test_secondary_scheduler.py` (incl. Windows counterparts) | mid-tier (process/cancel semantics) |
| P4 | C5 `store.py`, `secondary/2`, supersede, alternatives, `reconcile` alternatives, tests, regression for the duplicate crash | mid-tier; land before P5 so the crash is fixed first (could be split: P4a supersede only) |
| P5 | CLI `secondary run`, alias, exit-code tests | low-cost with spec in hand (mechanical) |
| P6 | C2 workflow + `tools/live_rzdiff_check.py` + flag verification note | mid-tier for CI debugging; low-cost for fixture and qa.md rows |
Order: P0 -> P1 -> (P2, P4a in parallel; disjoint files) -> P3 -> P4b -> P5; P6 any time after P2. Escalate to top-tier only for a demonstrated process-containment or security-invariant blocker.

## 14. Decisions made (defaults)

- Parallelism default 1, opt-in 2, hard cap 2; revisit after C8 measures memory on real pairs.
- Cache lives in the project store (no global cache): avoids cross-project leakage and path-trust questions.
- `ghidriff-baseline` is provenance-only, not rescheduled.
- v2 set id drops `file_sha256`; history of re-runs is kept in `EngineRun` rows, not in duplicate sets.
- Partial success exits 3 (not 0) with `status: partial`.
- rizin pin 0.9.1 until C2 verifies a newer release.
