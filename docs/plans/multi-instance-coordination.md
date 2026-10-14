# Multi-instance coordination (owner-approved 2026-10-14; supersedes the 26-worker draft)

Owner instructions (binding): create two more cloud instances (B, C) and spread the remaining work over all three so the project finishes as soon as possible; token-efficient, **cheapest capable model**, **never Fable**; as many workers as needed per instance; merge whenever possible; Windows and Linux builds at every major milestone (prereleases, produced automatically by the `release` job on each code merge to main); put as much of the label training and labelling as possible on the additional instances; **be patient with workers: let them finish their jobs before cancelling them**; check progress every 12 hours until complete; no final (non-prerelease) release without the owner's explicit say; Microsoft-derived data stays on the owner's machine. Plans: `program-e-roadmap.md` (phases, charter, gates), `program-e-research-brief.md` (research format), `phase-d-build-coordination.md` sections 2-3 (frozen seams, builder protocol).

## 1. Instances

| | A (integration owner) | B (feature builder) | C (labels, specs, guide, audits) |
|---|---|---|---|
| Session | `session_01WUziRNgNiy3umAsePrnNZ1` | `session_01CRxHqXZw1qxT3e17yvwgwE` | `session_012UcSEzaTyz5Pp8jj4C78Hj` |
| Branch (push only here) | `claude/clever-clarke-s4nhi6` | `claude/instance-b-features` | `claude/instance-c-research` |
| Orchestrator model | Sonnet | Sonnet | Sonnet |
| Max concurrent workers | 23 (owner order 2026-10-14) | 23 (owner order 2026-10-14) | 12 |

**Instance D (owner order 2026-10-14 ~21:50Z):** branch `claude/instance-d-gui`, up to 23 workers, orchestrator Sonnet; GUI framework F2-F9, Qt panels, feature audits and migration readiness (`program-e-execution-plan.md` section 6.4). Session id: see `ledger-A.md`.

## 2. Rules for every instance

- **Branches and merging.** Push only to your own branch. Open PRs to `main` (draft, ready when green), merge your own PRs (squash, `expectedHeadSha`) as soon as every check is green; then reset your branch to `main` (`git fetch origin main && git checkout -B <branch> origin/main`, force-with-lease only when the remote branch holds merged history only). Before every PR: fetch `main`, merge it into your branch, resolve (append-only docs `docs/modules.md`, `tasks/todo.md`, `docs/qa.md`: keep both sides; `cli.py` `COMMANDS`: union), run the full gate. Docs-only PRs: put `[skip ci]` in the squash commit message so no build or prerelease is produced.
- **Builds.** Every code merge to `main` runs `qa-windows.yml` and its `release` job, which publishes a prerelease `v0.1.0-beta.N` with the Windows zip and the Linux tar.gz (both with sha256). Merge in coherent milestones; never publish a non-prerelease.
- **Models.** Haiku for mechanical work (fixtures, registries, scans, lint), Sonnet for research, specs, frameworks, builds, QA, bug hunts; Opus only after two serious Sonnet attempts failed on one problem, or for a slice a plan flags as hard. **Fable is never used.**
- **Patience.** Never cancel or stop a worker that is making progress; wait for its report. Stop one only when it is demonstrably looping (no new commits and no tool progress for a long time), and say why in the ledger. Do not duplicate a running worker's job.
- **Token discipline.** Keep the orchestrator context small; read plans by section; workers read only what their card names; reports at most 250 words; focused tests while developing, the full suite once per worker before reporting, the full gate twice by the integrator before a PR. Compute-heavy runs (compiling corpora, Ghidra, evaluation) run as background scripts or GitHub Actions matrix jobs, not as agent loops. A container has 4 CPUs: at most 12 workers at once, tests with `-p no:cacheprovider` when parallel.
- **Windows pitfalls checklist** (roadmap section 4) applies to every builder; mocked or synthetic tests are never live evidence.
- **Budget governor.** The weekly limit is shared by the whole account. Before launching a wave read `get_session` (no id) `external_metadata.rate_limit_info`; if `status` is not `allowed` or `allowed_warning`, launch nothing and message A. Do not start Opus workers while the status is `allowed_warning`.
- **Messaging.** `send_message` to a peer for: a plan or framework landed, a PR merged (SHA, one line), a blocker. At most 3 lines; no chatter. Priority `later` unless urgent.
- **Ledgers.** Each instance appends to its own `docs/plans/ledger-<A|B|C>.md` (no shared-file conflicts): item, state, evidence.
- **12-hour check.** Each instance creates its own routine (`create_trigger`, cron `0 */12 * * *`, fires into its own session): verify workers and PRs are progressing, resume the next ledger item, report to the owner only when blocked or at a phase gate. Stop when your tracks are complete and say so to A.
- **Shared files.** `ui.py`, `tooltips.py`, `pyproject.toml`, `cli.py`, `backend.py`: edits only through the owner named below and within the line budgets in the plans; feature panels register through the panel registry (never edit `ui.py` for a panel); optional dependencies are added only by B-0.

## 3. Tracks

**A:** E-1 completion (collect research docs, review, apply amendments; synergy architect writes the anchor-fabric contract); E-2 frameworks (GUI panel registry and shared widgets first: it is the critical path for every panel; anchor fabric second); UE (S0b, S1, S2 running; then S3, S4, S5, S6 gates); PIL (patch-intent localization, CSAF CLI/reports, Leads panel); GitHub Pages site; E-4 integration of audit findings and the milestone builds.

**B:** B-0 dependency enablement (optional extras `rapidfuzz`, `pygments`, `networkx`, `pefile`, `yara-x` only as the plans confirm; `src/patchtrace/optional_deps.py` capability probe with explicit guarded imports so PyInstaller sees them; wheels-only CI probe on windows-latest and ubuntu; PyInstaller hooks; frozen-smoke import lines; `.gitattributes` for new fixtures); then KB (KBC + KPS), WB1, WB3, CAP, DIE, KEV, WB2, YRX, WBQ in the order their plans (`docs/specs/program-e/<ID>-integration-plan.md`) land. Domain, service and CLI slices first; GUI panels after A messages that the panel registry is merged; anchors through an `AnchorSink` Protocol until A's fabric lands.

**C:** (1) **LBL, label training, all of it**: the remaining Tier R work (14-project catalogue recipes from permissively licensed sources, planted-mutation operators, A/A controls, CVE-fix cases), the evaluation harness, a shard runner and a GitHub Actions matrix workflow so Ghidra-dependent runs use CI runners instead of agent tokens (results: aggregate metrics and feature tables of our own synthetic builds only, never Microsoft data), the training run, the honest-scope artifact and its policy gates, the Tier W one-command runner for the owner's machine. Start from `known-answer-corpus.md`, `tier-w-local-corpus.md`, `calibration-corpus-and-model.md`, `tools/calibration/`, `corpus/`; the LBL integration plan lands at `docs/specs/program-e/LBL-integration-plan.md`. (2) **Specs for everything else outstanding**: SPEC-26 D2 (PE version/manifest and Authenticode verification without executing the file), Windows release and signing policy, PatchTrace-owned Ghidriff launcher and symbol policy, report/export contract v2, the E-6 test, performance and beta-scenario plan, an outstanding-specs ledger (qbindiff, radiff2, Diaphora, series window: what exists, what is built, what remains). (3) **GDE, the guided RE teacher**: two research workers (how experts reverse engineer and patch-diff; how to teach and guide inside a tool), then the spec, then a deterministic (not AI-assisted) lesson/hint engine and content built against the existing features and extended as features land; the panel through the registry. (4) **Audits**: ten read-only code/feature auditors on deployed code and bug hunters for K, T, S0a, G and acquisition; findings to `docs/audits/`; fixes go to the owning instance (A: unified, intelligence, ui; B: acquisition, enrichment, tools) unless the module is idle, in which case C fixes it with a red test.

## 4. Interfaces between instances

| Interface | Producer | Consumers | Until it lands |
|---|---|---|---|
| Panel registry and shared widgets | A | B, C | build services and CLI only |
| Anchor fabric (`AnchorSink` and reader) | A | B, C | no-op `AnchorSink` Protocol |
| Optional dependencies | B-0 | A, C | do not add dependencies |
| Calibration artifact and metrics | C | A (Leads ranking), reports | display level stays `ordinal` |
| Guide hooks (charter item 8) | every plan | C | none; C adds hooks late |

## 5. Start-up checklist (B and C)

Read `CLAUDE.md`, `AGENTS.md`, this file, the roadmap and the research brief; start your first tasks; fetch plans as they land with `git fetch origin claude/clever-clarke-s4nhi6` and copy only docs: `git checkout origin/claude/clever-clarke-s4nhi6 -- docs/specs/program-e docs/plans` (never merge A's branch: it carries unmerged code). Create your 12-hour routine. Write your ledger.
