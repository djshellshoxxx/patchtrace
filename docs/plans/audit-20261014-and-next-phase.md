# Code audit 2026-10-14 and next-phase game plan

Base audited: `main` at `b7e819a`. Four read-only area audits (GUI, core, enrichment, CLI/engines/packaging) plus an external
bug list were triaged; each fixed item has a regression test. Local gate: pytest 1004 passed / 6 skipped, Ruff clean (Linux).
Windows/native CI evidence is recorded on the PR.

## Fixed in this slice
| Area | Defect | Fix |
|---|---|---|
| Reports | `include_code=False` export leaked code via match-override annotation | `_annotation()` keeps only ids/category/reason |
| Reports | Path redaction rewrote exported code/evidence (`a /b; // c:/x`) | `_Verbatim` strings get credential redaction only |
| Reports | Markdown `~`/`:` unescaped | escaped |
| Diagnostics | `Authorization: Token …` secret survived `redact_log` | whole header value redacted |
| Artifact bytes | in-place edit with restored mtime kept "verified" status | POSIX ctime in identity key (Windows residual risk documented) |
| Artifact bytes | FIFO/device could hang open | `O_NONBLOCK` open + regular-file check |
| Raw views | shorter side clamped to last page, diff highlight compared unrelated offsets | page past end shows an explicit message |
| PE overview | import/export reads could cross mapping boundaries; PE32+ thunk high bits masked | contiguous-span reads; reserved bits warn |
| rz-diff | non-string `type`, huge integer similarity escaped `SecondaryError` | validated |
| Acquisition | non-ASCII/huge `Retry-After`/`Content-Length` raised; no total download deadline | ASCII-digit + length guards; 3600 s deadline |
| Persistence/service | lone surrogate JSON, non-canonical run id | rejected with `PT-SCHEMA` |
| N-way | manually overridden edge still produced a second chain through the node | surviving relation identity check |
| CLI | typo launched Qt; unexpected exceptions bypassed exit contract; `--limit -1` | CLI dispatch, exit 3 + JSON, validation |
| Enrichment | `return 01;` crashed whole run; comment-only hunks counted as edits; filter `None` vs `()` cache collision; profile name traversal; `\n` accepted by regex; HTTPException escaped fetch | fixed |
| GUI | Copy after orientation swap used old bytes; failed inspection looped threads; new-project dir-is-file crash; signal jump dead in raw modes; promote errors silent; cancelled ranking mislabelled; stale highlights; recent-project pruning | fixed |
| Tooling | CRLF in Windows `.sha256` sidecar; stale `PatchTrace.spec` | write bytes; removed |

## Deliberately not changed (decision recorded)
- `normalization.ROOT_KEYS` strictness: fail-closed on unknown ghidriff roots is intentional; revisit with a ghidriff version matrix.
- Release job publishes a prerelease per `main` push: kept (user-requested beta flow, marked prerelease). Action is tag-pinned, not SHA-pinned.
- Child environment passthrough (full `os.environ` to Ghidra/Java): an allowlist needs a live Ghidra run to validate; scheduled P1.

## Open backlog (ranked)
P1: enrichment row retention (rows never deleted → 128 MiB cap eventually blocks publishing); WIL status "partial" for one-sided pairings; contextual rerank must require binary evidence; SIZE cast-only and BND added-loop false positives; `_TEMP` over-collapsing real names; env allowlist for children; history table bound; raw output stored twice; provider call cancellation latency; NVD pacing/403 retry; stale CVE snapshot → `partial`; CVSS conflict only across providers; `select_latest` provider loss; spec `validate_location`.
P2: GUI inspection thread teardown/`deleteLater`; hidden overview dialogs; unsaved profile edits; discovery off GUI thread; Setup reject message; note target reset; spec text vs UI (theme/worker settings/export redaction options); `series.save` over corrupt file; `discover_pairs` tolerance; `function_rva` reader identity; offline bundle ratio; derived-cache keys lack algorithm digest; wil gate scan performance; nondeterministic `now`.

## Next phase game plan (Phase C: multi-engine integration), each item = one small PR with spec first
1. **Spec freeze** (`docs/specs/multi-engine-evidence-panel.md`): engine registry contract, `EngineRun{engine,version,args_digest,input_hashes,status,timings}`, disagreement/alternative-match model, no cross-engine probability averaging. Owner: integration.
2. **Scheduler**: bounded parallel engines, per-engine cancel/timeout, failure isolation, cache keys with engine version. Pure module + tests. Uses `run_process(separate_streams=True)`.
3. **rz-diff live acceptance**: install pinned rizin in CI (Linux + Windows), run on the fixture pair, record in `docs/qa.md`.
4. **BinDiff real execution**: runner for `bindiff` CLI + BinExport input handling; protobuf bindings decision (vendor generated code vs `protobuf` dependency; license check) before code.
5. **Evidence panel (GUI)**: source-labelled per-engine matches, disagreement badges, alternative matches; reads reconciliation output only.
6. **Series window + per-hop ranking** (SPEC-09) on the stable N-way core.
7. **Native Windows acceptance** with a representative real binary pair; clean-profile GUI/DPI pass of the beta ZIP (manual gate, tracked separately).
8. Then Phase D/E in order: PE version resources/manifest, offline runtime bundle (separate project), SPEC-28/29/30.
Gates for every PR: focused tests → full pytest → Ruff → Linux + Windows CI → native Ghidriff matrix when backend code changes.
