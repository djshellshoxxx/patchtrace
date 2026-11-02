# GT12 missing benchmark stages: Linux synthetic evidence

The first acceptance-size runs pass the existing CI allowances on clean source
`1f5f0b808149a30d222a35937667b36a5407bc0d`, based on production checkpoint
`241f445bf3e2e1bc4083aac47ac074b3fd3b795b`. This closes the harness's unmeasured facts/read-model/Qt rows on this
Linux checkpoint. It does not establish full G-U5, largest Tier R, Windows/frozen performance, native engine
performance, or the ultimate integrated source. Earlier ladder/ingest and other gate failures remain unchanged.

| Measurement | Size | Observed | Existing limit applied |
|---|---:|---:|---|
| Facts context plus collection/judgement | 5,000 changed pairs | 3.995 s | 60 s target; 300 s CI allowance: pass |
| Persisted read-model load | 10,000 rows | 0.947 s | Informational; no separate L-35 build-time limit |
| Persisted read-model load | 100,000 rows | 9.330 s | Informational; no separate L-35 build-time limit |
| Qt first paint | 100,000 rows | 14.84 ms | 200 ms target; 1,000 ms CI allowance: pass |
| Qt sort through paint | 100,000 rows | 299.84 ms | Above 150 ms raw target; below unchanged 750 ms CI allowance |
| Qt filter through paint | 100,000 rows | 45.04 ms | 100 ms target; 500 ms CI allowance: pass |

Every Qt operation at both 10k and 100k made exactly 504 `data()` calls for 72 visible cells, below the exact C6
ceiling of 624. Each operation produced a real viewport paint, sorting was checked against function labels and
the selective filter returned exactly 1,000/10,000 rows. No call-count growth occurred between sizes.

Facts use real IR ingest and production context/channel/verdict code over five synthetic mutation families:
comparison literals, signed branches, integer literals, structure-store offsets and changed IAT callees/slots.
Both sides contain 237,000 instructions. All 5,000 pairs have distinct row identities, changed machine bytes,
nonempty deltas, and nonbenign verdicts (1,000 material, 4,000 review); none hit a facts limit. Generation took
6.862 s and ingest 14.389 s, separately from the gated 3.995 s facts operation.

Read/UI fixtures are distinct strict persisted rows and facts, with shuffled Unicode names, five materialities
and three populated source cells per row. They are constructed controls, not captured native engine outputs.
The UI stage prepares the read model before timing the production Qt table. It measures model assignment,
sort and filter through viewport paint, not search debounce, a whole application launch, display-server
latency, scrolling, accessibility or interactive acceptance. Fresh-process peaks include fixture preparation:
facts 506 MiB; read-model 131/954 MiB; Qt 181/1,004 MiB. These new-stage RSS values are informational; the existing
60k-worker and ingest memory gates were not reassigned or relaxed.

The independent reviewer cleared the exact source before the runs: 52 focused tests passed. Separate independent
controls rejected actual Qt sort/filter no-ops and verified timeout replay metadata; strict reports also loaded.
The author's earlier focused run passed 51 tests; the replay-metadata follow-up passed all 12 new-stage tests.
Ruff and patch hygiene passed. No production module, workflow or threshold changed.

Host: Linux 6.18.57 x86-64, CPython 3.12.14, Qt 6.12.0, Fusion/offscreen, nine reported CPUs. Stages ran serially
with one attempt each and no full/performance job alongside them. The coordinator reported a short focused
pytest starting about 12:50 UTC. The Qt stage ran 12:49:34.218–approximately 12:50:04.200 UTC, so its final seconds
may overlap that test. This condition is retained; the sort-target miss is not attributed to contention, and no
acceptance run was retried.

The initial 25-pair harness smoke failed its machine-byte-change check: an IAT fixture changed only the import
label, leaving the call bytes equal. The fixture was corrected to change the slot as well. The original failed
receipt is retained as `gt12-smoke-initial-20261101.json`; it was not a production-engine failure. The subsequent
clean-commit small smoke remains `insufficient-data` and explicitly lists the unrun acceptance sizes.

Evidence: `gt12-{facts,read-model,ui-calls}-20261101.json`, corresponding logs and invocation receipts, and
`gt12-combined-20261101.json`. The combined report recomputes all gates and cross-size checks from the three
unchanged initial reports. `gt12-evidence-20261101.json` records their hashes, source and host conditions.
`gt12-run-stage-20261101.py` preserves the exact serial launcher and refuses to overwrite existing reports.

Reproduction after selecting a stable host (each command serially, choose fresh output paths):

```sh
python -m tools.unified.bench --stages facts --seed 1 --insns 50 --out facts.json
python -m tools.unified.bench --stages read_model --seed 1 --insns 50 --out read-model.json
python -m tools.unified.bench --stages ui_calls --seed 1 --insns 50 --out ui-calls.json
```

Stage-specific defaults select facts 5k and read/UI 10k/100k. All generated reports retain the requested seed and
instruction count, including failures; read/UI do not use the instruction-count parameter. Existing default
CLI stages remain ladder/ingest so this extension does not silently add work to existing workflows.
