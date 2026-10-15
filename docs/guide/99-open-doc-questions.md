# 99. Open documentation questions

Things this documentation set could not settle from the code and documents at `main` `21a005e` (2026-10-15), things that drifted between older documents and the code, and measurements that were not repeated. Each item says what was checked and who can resolve it. Nothing here is a bug report unless it says so.

## A. Behaviour I could not confirm

| # | Question | What I found | Needed to resolve |
|---|---|---|---|
| A1 | How does a user turn on `unified/enabled` in the GUI? | `ui_unified.py` reads the panel-scoped QSettings key `enabled` under `unified/` (default false) and the tip says "turn on the unified/enabled setting"; `grep unified src/patchtrace/ui.py` finds nothing, and I found no Setup control. The CLI `unified run` does not read the flag | the GUI owner (instance A/D) |
| A2 | (Resolved while writing) The Engines-tab timeout range and parallel range | `secondary/evidence_panel_service.py` sets `TIMEOUT_RANGE = (60, 86_400)` and `PARALLEL_RANGE = (1, 2)`; the GUI matches the CLI | none |
| A3 | Which Windows accessibility gaps listed by the SPEC-45 audit at `fd6cdba` still exist? | the audit (54 unnamed controls, no mnemonics, no localisation) was not re-run after F3 to F9; some may be closed | re-run the AST scan; NVDA/Narrator and DPI acceptance are open anyway |
| A4 | Does `rules propose` work end to end? | `rules/cli.py` says the live `BACKEND` (`PairBackend`) is "set by the code that wires the live evidence stores"; I found no wiring on `main` | confirm with the YRX owner |
| A5 | Is the `kb` verb planned to register from `cli_commands/kb.py`? | `kbcorrelation/cli_index.py` is a dispatcher "for the arguments after `kb index`" and its docstring refers to a `kb` assembler slice that is not on `main`; no `cli_commands/kb.py` | KB integration plan section 8 |
| A6 | Are `ui_pemeta.py` (Build facts tab) and `ui_codetext.py` (token colours) attached anywhere? | no module imports them; ledger D says wiring into the Files panel / `ui.py` seam is open; `inspect_pe` does not call the resource, version-info, manifest or API-delta modules (slice WBQ S5) | WBQ S5 owner |
| A7 | Does `reports.py` include the KEV block? | `kev/report.py` exists; `reports.py` does not import it | KEV K5 owner |
| A8 | What exactly does the GUI offer for `Rank changes` ordering and signal list on a project with no decompiled code? | described from README and code reading; not exercised | a hands-on run |
| A9 | Do the Leads dock and the Unified tab open by default? | `default_visible` is false in both specs; the View menu shows them; first-run visibility on a fresh profile was not observed | a hands-on run |
| A10 | Can the GUI create a series? | no control found (the Series dock only opens a `series.json`); `series create` is CLI only | confirm with SPEC-09b owner |
| A11 | Is the engine-evidence index `55/+20/+8/83` documented with a rationale anywhere? | constants and the "uncalibrated triage aid" wording are in `secondary/evidence.py`; the rationale is presumably in the C6 spec (`multi-engine-evidence-panel.md`) and was not read in full | read the spec |
| A12 | Exact non-GUI fixtures for `pilot` classes (`fit`, `review`, `partial`, `code`, `queue`): what distinguishes `partial` from `review`? | names and CLI filter verified; definitions are in `pilot/contracts.py` / the PIL plan and were not transcribed | read PIL plan section 7 |

## B. Documents that disagree with the code (drift)

| # | Document | Drift |
|---|---|---|
| B1 | `docs/cli-reference.md` | its Conventions section gives `PYTHONPATH=src python -m patchtrace.cli <verb>` as the checkout invocation, which prints nothing (use `python -m patchtrace <verb>`); it also says "Today the registry holds one verb: `panels`" and lists `panels` as the only registry verb; `fabric`, `kev`, `pilot`, `rules` now exist and have no flag tables there. The "Specified but not built" table still lists `kev`, `rules` and `kb` among planned verbs |
| B2 | `docs/specs/non-goals.md` N-05 | "dark only, no theme setting"; View > Theme (Dark, System) and automatic high contrast exist (F7) |
| B3 | `docs/specs/non-goals.md` N-02 | records `SeriesWindow(QMainWindow)` as a known exception; the Series panel is now a dock |
| B4 | `docs/specs/ui.md` last paragraph | still says the GUI framework is "planned, not built by slice GUI-F0"; F3 to F9 are built |
| B5 | `docs/privacy.md` | host table omits the CISA KEV hosts (`raw.githubusercontent.com`, `www.cisa.gov`); it says 27 settings keys (true at `fd6cdba`; panels now add keys under `<panel id>/`, plus `layout/*` and `theme/variant`) |
| B6 | `docs/version-history.md` | stops at `beta.225`; the checkout has tag `beta.243` and later merged PRs without tags |
| B7 | `docs/specs/ui.md` first paragraph | "The palette is fixed; there is no theme setting yet (future work)"; see B2 |
| B8 | `docs/linux.md` | "Verified locally 2026-10-12" only; Ubuntu 22.04/24.04 smoke runs are CI, live Ghidriff from the frozen Linux build still unverified |
| B9 | `docs/specs/REGISTRY.md` / `INDEX.md` | several spec files carry proposed or colliding numbers ("SPEC-28 (proposed number)", "SPEC-39 (proposed; collision)", "SPEC-35 (renamed)"); I cite specs by path where the number is ambiguous |
| B10 | `docs/user-guide.md` | mentions `Project > Download from Microsoft symbol server...` and Rank; does not mention docks, palette or shortcuts added by the GUI framework |
| B11 | `fabric` verb flags | `fabric` takes `--project PATH`; most other verbs take `PROJECT` positionally. Not a bug but an inconsistency that surprises scripts (SPEC-44 section 8 anticipates such cases) |

## C. Measurements not repeated here

- **Test counts.** The sandbox used to write this guide had no `pytest`, so the suite was not run. Counts quoted come from `docs/qa.md` and the ledgers at the stated dates (4,884/4,891 at `beta.225`; 10,068 on the GUI branch). The size of the suite on current `main` is not known to this guide (419 files in `tests/`).
- **`panels list`/`check`** and **every `--help` text** quoted here were run from the checkout (`PYTHONPATH=src python -m patchtrace <verb> --help`, or `patchtrace.cli.main([...])` from Python), so they are current. The exit-code table in [16](16-cli-reference.md) is SPEC-44's and was read at `fd6cdba`; verbs added later follow their module docstrings.
- **`qt_gate`**: no workflow invokes `tools/qt_gate.py`; `docs/qa.md` carries proposed CI text. Whether a job exists on an unmerged branch is unknown.
- **Packaging**: nothing was built or run for this guide. `tools/backend_pin.json` was parsed (one `placeholder`: `python-windows`); I did not check whether the pin-verify results were later recorded on another branch.
- **Acceptance gates** (clean Windows GUI, NVDA/Narrator, DPI, disconnected-machine bundle, live local/remote AI, native `msdelta`, live Ghidriff from the frozen Linux build): all open per `tasks/todo.md`; this guide marks the affected features **unverified**.

## D. Things I deliberately did not document

- Planned panels beyond one-line status (Search, Graph, Strings, Capabilities, Build environment, Rules, KB, KEV, Guide): no code exists to describe. Their plans are under `docs/specs/program-e/` and `docs/specs/workbench/`.
- The guided teacher (GDE / E-5): deferred by the owner; only hooks (`TeachTopic`, `kev/teach.py`) exist.
- Label-training internals (`tools/calibration/`, Tier R catalogue, mutations, evaluation harness): described only at the level of what it means for the shipped product ([22](../internals/22-engines-and-fusion.md)). Source: `docs/specs/known-answer-corpus.md`, `calibration-corpus-and-model.md`, `docs/plans/c9-preregistration-v1.md`.
- Per-detector regular expressions and rule-table rows (`enrichment/signals.py`, `pilot/rules/data.py`): these are code and tests, not documentation.
- GitHub Pages site content (`site/`): dev tooling, not part of the product.

## E. If you extend this documentation

1. Re-run `patchtrace panels list`, `patchtrace --help` and the `--help` of any verb you describe, and cite the file you read.
2. Mark anything not on `main` as **planned**, anything without native acceptance as **unverified**.
3. Prefer a link to the spec over a copy of its contents; keep each file between 80 and 250 lines.
4. Add new unknowns here rather than guessing.

## F. Claims taken from documents, not re-verified in code

These statements appear in the guide because a spec, ledger or QA record says so. I read the source named but did not independently reproduce the fact.

| Claim | Chapter | Source |
|---|---|---|
| Tested backend combination: Python 3.12.10, Ghidra 12.0.4, Temurin Java 25, Ghidriff `4f5d895f...` | [10](10-getting-started.md) | `README.md`, `docs/windows.md`, `docs/qa.md` |
| Bundle pins: JDK 21.0.12.1+1 for the full package versus Java 25 for the verified fixture | [10](10-getting-started.md), [26](../internals/26-packaging-and-bundle.md) | `tools/backend_pin.json` (parsed), `README.md`; the difference is real and unexplained here |
| Settings key count (27 at `fd6cdba`), Windows registry and Linux config paths | [10](10-getting-started.md), [17](17-privacy-and-network.md) | `docs/specs/app-settings.md`, `docs/install.md` |
| Winbindex, symbol-server and CVE endpoint behaviour (rate limits, redirects) | [17](17-privacy-and-network.md) | module docstrings and SPEC-42 section E, which marks several as unverified against primary sources |
| NVD pacing (5 requests per 30 s keyless, 50 with a key) | [24](../internals/24-acquisition-and-enrichment.md) | `enrichment/intelligence.py` docstring |
| Ghidriff `NameParamHash` name shared by two correlators | [14](14-series.md) | `docs/specs/nway.md` |
| Live unified extraction green on Windows (MSVC DLLs) and Linux | [22](../internals/22-engines-and-fusion.md) | `docs/plans/ledger-A.md` |
| `beta.225` package sizes and hashes; test pass counts | [27](../internals/27-testing-and-ci.md), [30](../internals/30-history-and-process.md) | `docs/plans/ledger-A.md`, `docs/version-history.md` |
| Qt abort rows and repeat-gate results | [23](../internals/23-gui-framework.md) | `docs/qa.md` |
| Disk use of retained GZFs (about 10 times the binary for small DLLs) | [31](../internals/31-decisions-and-tradeoffs.md) | `unified-engine/00-decisions.md` U-02, measured on one 3 KB DLL |
| Windows pitfalls checklist | [30](../internals/30-history-and-process.md) | `docs/plans/worker-brief.md`, roadmap section 4 |

## G. Suggested follow-up documentation work

1. Regenerate `docs/cli-reference.md` from the parser including `fabric`, `kev`, `pilot`, `rules` (a small script under `tools/` would stop the drift in B1).
2. Update `docs/privacy.md` (KEV hosts, panel settings keys) and `docs/version-history.md` (after `beta.225`).
3. Amend SPEC-55 N-02 and N-05 and the last paragraph of `docs/specs/ui.md` to match the built GUI framework (B2 to B4, B7).
4. Document the `unified/enabled` setting where users can find it, or add a Setup control (A1).
5. Re-run the SPEC-45 accessibility scan and record which gaps closed (A3).
6. When the `kb`, `kev` and `rules` panels and the zero-download package land, add their user chapters; the chapters marked **planned** here are the placeholders.
