# 31. Key decisions and trade-offs

The decisions that shape PatchTrace, why they were taken, what they cost, and where they are recorded. Sources: `docs/specs/architecture.md` (DEC-01 to DEC-05), `docs/specs/unified-engine/00-decisions.md` (D-01 to D-36), `docs/plans/spec-decisions-20261014.md`, `docs/specs/non-goals.md` (SPEC-55, N-01 to N-09), `docs/plans/audit-20261014-and-next-phase.md`, `docs/plans/worker-brief.md`. Status words follow those files: a decision is **ratified** only where a source says so; most Program E decisions are integration-owner defaults, reversible before the corresponding PR merged. Previous: [30](30-history-and-process.md). Next: [32](32-how-to-extend.md).

## Product invariants (non-negotiable, `docs/plans/worker-brief.md` section 2)

| Invariant | Why | Cost |
|---|---|---|
| Never execute a target binary; drivers are never loaded or installed | the inputs are the thing under suspicion | no dynamic analysis, no "run it and see" evidence |
| Never upload silently; network only with operation-specific, host-named consent | analysts handle sensitive samples and unreleased patches | more prompts and flags; no auto-update, no telemetry |
| Never fabricate unavailable disassembly or evidence | a made-up listing is worse than a gap | views are sometimes empty ("unavailable") |
| Never show an uncalibrated number as vulnerability confidence | false precision misleads triage | no percentage anywhere; ordinal labels only |
| Never average different engines' scores; keep conflicting evidence | scales differ and agreement can be shared artifact | a `contested` row needs a human |
| Unknown is not a negative vote; shared-origin evidence counts once | absence of evidence is not evidence; two readers of one database are one opinion | fewer "corroborated" rows than a naive count |
| Older/newer orientation is explicit; provenance on everything | silent reversal inverts every conclusion | extra clicks and stale markers on swap |
| Advisory, string and code text are untrusted data | they come from attackers and vendors | everything is escaped, bounded, plain text |
| One main window; new UI is a dock | focus, geometry and teardown rules per window | tabs and docks instead of free windows (N-02) |
| Pure domain and adapters separate from Qt | testability, headless CLI, cheap import | seam code (view models, ports) |
| Persisted contracts change additively only | projects outlive releases | old fields linger; breaking change needs a new version and spec first |
| No GPL/AGPL code copied; Ghidriff (GPL-3.0) stays a separate unmodified process; Microsoft-derived binaries, PDBs and Winbindex labels never committed | licensing and redistribution | external setup burden; no in-process matching fork |

## Architecture decisions (SPEC-01)

| ID | Decision | Reason | Trade-off |
|---|---|---|---|
| DEC-01 | Do not embed Java in the GUI | stability and isolation; Ghidra crashes must not take down the desktop | an external runtime to install (hence discovery, Setup, and the bundle effort) |
| DEC-02 | Use the supported Ghidriff CLI, preserve raw outputs, do not fork matching (reworded by SPEC-31 A-01: never fork Ghidriff, a separate derived engine may match) | GPL boundary and upgrade path | PatchTrace depends on Ghidriff's JSON contract; unknown roots fail closed |
| DEC-03 | A Diffalayze-inspired bounded interpretation flow, with attribution, not its acquisition/execution workflow | reuse the idea, not unvetted code | own implementation of the staging |
| DEC-04 | Ollama on loopback and OpenAI-compatible HTTPS endpoints through the standard library; credentials session-only | smallest surface, no new dependency, no stored secrets | no native Anthropic transport, no remote Ollama, no HTTP, no redirects (N-04) |
| DEC-05 | Preserve all requirements in traceability even if runtime verification is blocked; never call an unverified path complete | honesty about acceptance | gates stay open in `tasks/todo.md` for a long time |

## Storage and data decisions

- **SQLite snapshots plus append-only history, strict pydantic JSON.** Validated whole-document snapshots make ownership checks simple (one validator, [21](21-data-model-and-storage.md)). Cost: snapshot size caps (256 MiB) and bounded history.
- **History is pruned, but "no backup, no deletion"** (SPEC-07h H2): keep the newest 100 rows or 512 MiB, always the newest snapshot of each revision, and only after a re-opened, integrity-checked backup exists. This replaced the earlier "append-only" claim in the docstring.
- **Enrichment as additive tables, `user_version` stays 1**, extension version 1 until a v2-only row is written, so old clients still open new projects. New kinds are a closed, reserved set owned by the integrator.
- **Derived results are separate and stale-able, never overwritten** (D-02, D-07): unified and pilot results are sidecar files plus tiny pointer rows outside `DERIVED_KINDS`, so retention cannot delete them and `ComparisonProject.matches` is never rewritten.
- **Canonical JSON identities with no floats** (SPEC-07 section 3): scores are exact integers; MD index keys are rounded; ordering is explicit. Cost: contract authors must think in integers.
- **Retention**: keep 8 current and 2 stale generations per profile; imported `secondary-matches` never evicted.

## Engine decisions

| Decision | Reason | Trade-off |
|---|---|---|
| Ghidriff primary, unified result **derived** and stored apart (D-02) | AGENTS.md; analysts must be able to trust the baseline | two views to explain; flag `unified/enabled` off in the alpha (U-05) |
| Reconciliation never averages; `contested` is preserved exactly (D-12) with a strength attribute for ordering only | weak engines (rz-diff byte similarity is mostly address noise) must not erase real contests, nor flood the list | a noisy contested list; ordering by strength helps |
| Fusion is union-find over joining dependency tags plus rules, no numeric fusion, no probability (D-11, D-32) | corroboration needs different components *and* different evidence classes; one key computed twice is not two opinions | conservative: many rows stay `tentative` |
| Pass ladder: ordered, uniqueness-gated, fixpoint with neighbour propagation, tier C never auto-accepted (D-09) | BinDiff drill-down semantics with per-pair provenance | slower than greedy; deterministic |
| Port BinDiff v8 ideas with Apache-2.0 attribution (D-21); keep BinDiff itself an optional oracle, never bundled | licence/trademark clarity, parity checks | notices to ship; patent/NOTICE review asked before a release that ships the port (U-01) |
| Diaphora: ideas only, no code, optional import path (D-24); radiff2 dropped as an engine (D-26); QBinDiff solver not built (D-25) | AGPL; rizin already covers the byte-level role; one matching path | a catalogue row but no adapter |
| Extraction first uses the analysed GZFs Ghidriff already writes (D-05) with opt-in `retain_gzf` | avoid hours of re-analysis | disk use about 10 times the binary for small DLLs; transient |
| L2 verdicts by named proof (`UNCH/1`, `COS-*`), scope limited to code plus unwind metadata (D-13, D-35) | an `unchanged` claim must not exceed its evidence | data-only patches are out of verdict scope and the UI says so |
| Cap of 2 parallel engines until Windows memory is measured | OOM risk on real pairs | slower multi-engine runs |
| Hidden capped workers for protobuf, unified and YARA-X | a hostile `.BinExport` or rule scan must not take the app down; a scan holds the GIL | process spawn cost; frozen-aware `worker_argv()` |
| protobuf as a core pinned dependency with upb required (C3) | pure-Python protobuf is about 85 times more memory and 125 times slower on hostile input | build refuses to freeze without upb |
| `.BinExport` size cap 256 MiB; MD5/empty `executable_id` refused unless explicitly overridden and recorded | DoS and identity binding | a confirmation click |

## Calibration and confidence

- **Ordinal only until a validated artifact passes pre-registered gates** (C9, `docs/plans/c9-preregistration-v1.md`): `display_level()` returns `ordinal`. Tier R (open-source, redistributable) trains and tests; Tier W (Windows binaries) stays local. A model can never override `contested`. The target is function *pairing correctness*, never vulnerability.
- **The 55..83 evidence index** is hand-set, opt-in, labelled "triage index, not a probability" (evidence panel decision D1), capped at 83 to avoid false certainty from dependent tools.
- **Verdict names** Agree / Contested / Single engine / Unknown (D2); Ghidriff `quality` and `match_types` shown raw (D3); no confirmation dialog before engine runs, but a live timer and Cancel (D4).
- Open **USER** items: legal position on labels for Microsoft binaries (O1), second annotator (O2), labelling budget (O4).

## Process and release decisions

- **Prerelease on every third counted merge, fail-open gate** (`tools/release_gate.py`): so a broken gate never withholds the Windows alpha. No final release is automatic.
- **Unsigned portable zip**; signing policy SPEC-52 is documented, not applied. A checksum detects corruption, not origin.
- **Cheapest capable model per task; top tier only after a demonstrated blocker**; shared files have single owners; ledgers per instance ([30](30-history-and-process.md)).
- **Environment allow-list for child processes ships behind a green native Windows run**; until then it is opt-in (`restrict_env`, `env_passthrough`, `PATCHTRACE_CHILD_ENV=inherit`), except in bundle mode where it is forced. Cost: default Ghidriff inherits the full environment.
- **Symbol lookups off by default**: `--no-symbols`; online lookup is a Setup opt-in recorded with every run. A PatchTrace-owned Ghidriff launcher for a truly local-only policy is specified (SPEC-53) and not built.
- **Docs-only merges carry `[skip ci]`** and do not count toward a release; the marker anywhere in a message suppresses the build.

## Recorded non-goals (SPEC-55) and what superseded them

| ID | Non-goal | Note |
|---|---|---|
| N-01 | Docker backend | none exists; supported path is desktop plus external runtime or the offline ZIP |
| N-02 | extra top-level windows | the Series window exception has since been converted to a dock (F9); the Files dialog likewise |
| N-03 | whole-program graph viewers, browser canvases, Graphviz execution, NetworkX at runtime | a bounded ego-graph `GraphCanvas` widget exists; the Graph panel is planned |
| N-04 | chat UI; only structured, selection-based AI use | |
| N-05 | light theme: "dark only, no theme setting" | **superseded in code** by F7: View > Theme offers Dark and System and high contrast is automatic; SPEC-55 predates it (see [99](../guide/99-open-doc-questions.md)) |
| N-06 | ELF, ARM64, Mach-O | only x64 PE has a loader, verified Ghidra path and fixtures |
| N-07 | Phase 4 semantic IR and capability-graph semantics (deferred); not the SPEC-31 IR | |
| N-08 | SPEC-12 to SPEC-25 reserved | next free number is taken by a new spec; numbers are never reused |
| N-09 | QB/RD/DA decisions | see engine table above |

## Trade-offs the project accepted knowingly

1. **Honesty over completeness**: features ship with explicit "unavailable" and "planned" states rather than approximations.
2. **External runtime burden over embedding**: Ghidra/Java/Ghidriff stay outside; the answer to the burden is discovery and the bundle, not forking.
3. **Parallel speed over a single narrative**: five instances produced overlapping drafts and numbering collisions; the registry, ledgers and single-owner shared files were the reconciliation mechanism.
4. **Synthetic evidence over hand-waved confidence**: much of the suite uses repo-owned synthetic PEs and recorded tool output; live runs are separate, sometimes blocked, and recorded as such.
5. **Breadth first, acceptance later**: nine manifest panels, KB, KEV wiring and the bundle remain unfinished while the engines and CLI are broad; the roadmap prioritised build/CI correctness and a usable Windows standalone alpha, then the next inspection slices.
