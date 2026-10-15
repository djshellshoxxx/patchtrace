# Requirements, acceptance and audit (SPEC-03)

All priorities below are P0 beta gates, unless explicitly P1. Failure must remain visible and previous committed results intact. Rationale: reproducible and trustworthy local investigation.

| Requirement | Acceptance | Modules | Test / milestone |
|---|---|---|---|
| R01 static PE pairs | Select explicit older/newer; copied hashes; reject wrong machine, malformed/changed/oversize input | ingestion | T01 synthetic PE, M1 |
| R02 contracts | 15 requested entities have v1 schemas; future/extra/invalid relations fail | contracts | T02 validation, M1 |
| R03 comparison | Ghidriff output imported and native CLI can produce same normalized result | backend/normalization | T03 fixtures + live fixture, M2 |
| R04 worker lifecycle | UI responsive, timeout and cancel kill children, no partial success | jobs/desktop | T04 child/cancel Windows job, M2 |
| R05 manual review | Added/removed/ambiguous/split/merge representable; correction persisted and invalidates interpretations | service | T05 round trip, M3 |
| R06 code view | Older left/newer right; line alignment uses text; assembly missing explicit; keyboard and search/filter | alignment/desktop | T06 Qt, M3 |
| R07 context | Exact preview bounded; omissions recorded; deterministic digest and scoped evidence | evidence | T07 budgeting/forgery, M4 |
| R08 optional AI | Offline workflow independent; local and remote paths; explicit context preview | providers/desktop | T08 mock + live provider procedures, M4 |
| R09 findings | Strict JSON and citations; support/counterevidence, alternatives, unknowns, review and notes | interpretation/service | T09 malicious/malformed/stale, M4 |
| R10 persistence | Atomic SQLite history, exclusive writer, backup, interrupted run recovery, relocated relative paths | persistence | T10 corruption/lock/roundtrip, M3 |
| R11 exports | Markdown/HTML/JSON deterministic selection; escape HTML; default omit code/raw/private paths | reports | T11 markup/redaction, M5 |
| R12 diagnostics | Backend setup errors actionable; logs/credentials excluded from DB/reports | diagnostics | T12 secret scan, M5 |
| R13 package | Windows x64 desktop ZIP starts on clean Windows; sample works without backend; dependency setup documented | packaging | T13 Windows CI + manual clean install, M6 |
| R14 audit | Full requirement traceability, defect repairs, truthful status and open blockers | all | T14 audit record, M6 |

## Proposed performance targets, not measurements
Reference desktop Windows 11, 4 logical CPUs, 8 GiB RAM, SSD. GUI interactions under 200 ms for 1000 matches, first project load under 3 s for 10 MiB normalized data. Code pane max 200000 characters per side; show truncation rather than freezing. Small/medium/large analysis classes: 1/20/100 MiB PE. Benchmark elapsed time, peak RSS, tool versions/settings, function counts and cancellation latency; no fixed decompilation promise. Worker cancellation target 5 seconds. Context 24000 chars default, raw import maximum 100 MiB. Matching precision/recall and interpretation correctness require held-out labeled real patch corpus; synthetic tests verify integration, cannot establish research accuracy.

## Acceptance fixtures and live procedures
Fixtures cover ordinary bounds fix, identical bytes, relocated address, stripped names, added/removed, manual split/merge/ambiguous and incorrect match corrections. Compiler noise cannot be automatically judged a vulnerability. Add source-built `old/new` Windows benign C fixtures, compare via pinned backend and verify known added bounds check. For live Ollama install a JSON-capable model, preview request, run selected sample, confirm schema+citation handling. For remote supply compatible endpoint and key in session, preview exact context, verify request/response and credential exclusion. No credentials supplied means live checks remain blocked, never passed. Clean Windows: unpack ZIP, launch sample, open/save/export, configure external Python/Ghidriff/Ghidra/Java and compare fixture, cancel and confirm no residual children. User exploratory QA follows package availability.

## Threat model and failure recovery
Malformed files are untrusted inputs; static parsers and external processes can crash. Size/offset/schema limits, owned argv and immutable artifacts limit damage; process isolation is not security sandboxing. Never execute targets/model commands. Prompt injection cannot expand authority or evidence. HTML escaped, no scripts. Secrets remain memory-only; local endpoint loopback, remote HTTPS. Database integrity checked, unknown schema fails, backups preserve immutable files. Disk-full rolls back atomic work. Concurrent-open lock must not be auto-stolen without liveness check. Supply chain: version pins, notices, CI dependency logs; desktop includes Qt licenses, external engines retain their own obligations.

## Unified engine gates (SPEC-31, P1, opt-in; amendment A-19)
The opt-in unified view (setting `unified/enabled`, default off) has its own gates G-U1..G-U8 (`unified-engine/08-evaluation.md` s1). They are P1: they do not gate the beta (the P0 table above) and never block a release of the existing views. The flag stays off, and alpha builds ship with it off, until G-U1..G-U6 pass with the gate-report SHA recorded in `docs/qa.md` (decision U-05). Corpus and bench results come from the dispatch-only workflow `unified-corpus.yml` and are advisory; a gate that cannot run is reported `pending`, `blocked` or `insufficient-data`, never as passed. Status 2026-10-14: the corpus, A/A and mutant scripts, the bench and the gate-report skeleton exist; the gates that need the S3 verdicts are pending.

## Completeness register
Specification package: architecture covers executive summary, assumptions, APIs, integration, privacy, persistence, risks and decisions; modules covers catalog; schemas provide executable contracts/examples; UI covers journeys/controls; research covers sources/reuse/licenses; verification covers requirements, quality, benchmark, traceability, milestone and final audit. Glossary: artifact=input binary; run=immutable analysis attempt; evidence=scoped location; hypothesis=model-proposed explanation; finding=reviewable structured record; stale=result superseded by revision; match=correspondence, never security confidence.

Unverified native backend/provider/clean-machine tests are release gates. Do not quietly reduce scope to mark beta complete. Optional Docker, graph visualization, ELF/ARM/Mach-O, automatic patch acquisition, tool execution, detached panes and chat are deferred. Any essential incomplete requirement remains on tasks/todo.md with evidence needed.
