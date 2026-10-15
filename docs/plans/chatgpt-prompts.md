# ChatGPT prompts for the most token-intensive unbuilt parts (copy and paste each block)

How to use: start a NEW ChatGPT conversation per prompt. ChatGPT reads the repository directly (branch claude/instance-d-gui); no attachments needed. ChatGPT cannot verify facts online unless browsing is enabled; every prompt tells it to mark unverifiable facts UNVERIFIED so Claude workers can check them. When ChatGPT stops mid-way, reply with exactly: `continue from the next file, no recap`. Save each returned file at the path in its `=== FILE: <path> ===` header and tell Claude; Claude will integrate and verify.

---

## PROMPT 1 of 5: Qt panel specs for the unbuilt panels

```
ROLE: senior desktop-UI architect and specification writer for PatchTrace, a Windows-first PySide6 (Qt 6.12) application that compares an older and a newer build of a Windows PE binary to find the code a patch changed. One main window; every feature is a dock panel hosted by an existing panel framework.

REPO ACCESS: you can read the GitHub repository djshellshoxxx/patchtrace directly. Read every file below from branch claude/instance-d-gui (NOT main: main lacks the newest docs). If a path is missing, search the repo tree (also docs/research, docs/plans, docs/audits, docs/specs) before assuming it does not exist. FILES TO READ FIRST (read all before writing): docs/specs/program-e/GUI-integration-plan.md; docs/specs/program-e/CAP-integration-plan.md; DIE-integration-plan.md; YRX-integration-plan.md; KEV-integration-plan.md; WB2-integration-plan.md; WB3-integration-plan.md; docs/specs/gui-framework.md; docs/specs/ui.md; docs/modules.md (sections gui/qt, panels); docs/guide/ if present.

FRAMEWORK FACTS YOU MUST USE (exact names): PanelSpec(id,title,factory,area,tabify_with,shortcut,requires,claims,tips,commands,anchors_in,anchors_out,default_visible,...); PanelController hooks (widget, project_changed, selection_changed, busy_changed, capabilities_changed, theme_changed, show_anchor, shutdown); ports (ProjectPort, MutationPort, NavigationPort, ShellPort); TaskRunner with named lanes and CancelToken; StateView states (loading, empty, blocked, error, stale); VirtualTable with ColumnSpec/TableSpec/PreparedTable; CodeDiffView; GraphCanvas; chips; ThemeTokens (dark, system, high contrast, reduced motion); tooltip entries with four lines What/Why/Effect/Source (What <= 160 chars); shortcuts Ctrl+Shift+<letter> (E evidence, U unified, F search, G graph, T strings, A capabilities, B build_env, R rules, K kb, X kev, L leads, H guide); anchors (AnchorRef kinds).

INVARIANTS (every spec must respect): never execute a target binary; never send anything without operation-specific consent and exact preview; never fabricate evidence; never show an uncalibrated number as vulnerability confidence; never average different engines' scores; keep conflicting evidence; unknown is not a negative vote; shared-origin evidence counts once; older/newer orientation explicit; provenance on everything; advisory/string/code text is untrusted (bound, escape, never execute); docks/tabs only, no extra top-level windows; pure models separate from Qt; persisted contracts change additively only; Microsoft binaries/labels never committed; no GPL/AGPL code copied.

TASK: write one implementation-ready spec per panel for: (1) capabilities (CAP-6a/6b), (2) kev (K3), (3) build_env (DIE D5, incl. pre-flight banner), (4) rules (YARA-X R6b), (5) guide (stub only, deferred), (6) graph (deepen WB2 G5/G6), (7) strings (deepen WB3 S7b), (8) search (deepen WB1 S7), (9) any additional panel or card the repo plans imply (list and justify).
EACH SPEC has exactly these sections: 1 Purpose and analyst question. 2 Identity (id, title, area, tab group, shortcut, focus order, default_visible, requires, claims profile). 3 Data contract (pure view-model fields with types and limits; service calls; no Qt). 4 Layout (regions, framework widgets, table columns with header text, widths in em, default sort, filters, empty-cell text). 5 States (table: state, trigger, exact on-screen copy, remedy button, screen-reader announcement). 6 Interactions (every action/button/key/context-menu item with command id, selection and copy behaviour). 7 Navigation (anchors in/out with kinds; stale, ambiguous, missing behaviour). 8 Threads (tasks, lanes, cancellation, progress text, generation handling). 9 Settings (keys under <id>/ with defaults and ranges). 10 Tooltips (EVERY tooltip id with the four lines). 11 Accessibility (accessible name and description for every control, tab order, announcements, high-contrast and reduced-motion behaviour). 12 Performance budgets (numbers). 13 Security/privacy (hostile text, consent flows, exact hosts). 14 Test plan (named tests; manual Windows checks as a separate list). 15 Open questions each with a default.
Then write panels-build-plan.md: dependency order, which pure view-models must exist first (module and function names), missing shared widgets, size S/M/L per panel, risks.

OUTPUT RULES: be exhaustive; do NOT summarise or abbreviate; every tooltip, state and command must be written out in full. Emit each file as `=== FILE: docs/specs/panels/<panel-id>.md ===` followed by its full content. One panel per message; end each message with `NEXT: <panel-id>` and stop; I will reply `continue` until all are done. Use exact identifiers from the repo files; if repo files conflict, state the conflict and pick one with a reason. Do not invent features; put proposals under Open questions. No ': ' inside YAML plain scalars.
```

---

## PROMPT 2 of 5: Label-training corpus: Tier R recipe cards, planted mutations, CVE-fix case candidates

```
ROLE: build-systems engineer and ML-evaluation methodologist producing test-corpus definitions for PatchTrace's label-training pillar (supervised calibration of a function-level patch-localisation ranker, trained ONLY on our own synthetic builds of permissively licensed open-source C projects; never on Microsoft binaries).

REPO ACCESS: you can read the GitHub repository djshellshoxxx/patchtrace directly. Read every file below from branch claude/instance-d-gui (NOT main: main lacks the newest docs). If a path is missing, search the repo tree (also docs/research, docs/plans, docs/audits, docs/specs) before assuming it does not exist. FILES TO READ FIRST: docs/specs/program-e/LBL-integration-plan.md; docs/specs/calibration-corpus-and-model.md; docs/specs/known-answer-corpus.md; docs/specs/tier-w-local-corpus.md; tools/calibration/ (README and the existing catalogue/cards/recipes for the 13 current projects); docs/research/lbl-datasets-and-methods.md if present.

CONTEXT: a "card" is a pair of builds (older, newer) of one project with known changed functions. Release cards compare consecutive releases; CVE-fix cards compare the commit before and after a security fix. Planted-mutation cards inject known edits into a base build. A/A controls compare identical sources built twice (expected zero changes). Recipes are deterministic build instructions (toolchain, flags, MinGW/MSVC/clang options, optimisation levels) so the builds are reproducible in GitHub Actions runners.

TASK: produce (A) 30 NEW project entries beyond the existing 13 (permissive licences only: MIT/BSD/Apache/ISC/Zlib/PD; C or C++ that builds with MinGW-w64 or clang on Linux; avoid projects needing heavy dependencies); for each: name, upstream URL, SPDX licence, why suitable, build system, configure/build commands, expected artefacts (libs/exe), size estimate, known determinism issues. (B) For each project 3 to 6 candidate release pairs and 2 to 5 candidate CVE-fix cases with the CVE id, affected files/functions, fixing commit SHA and parent SHA. YOU CANNOT VERIFY SHAS: mark every SHA, CVE id and function name `UNVERIFIED` unless you are certain, and add a one-line `how_to_verify` (exact git or API command). (C) Planted-mutation operator catalogue: 40 operators (e.g. off-by-one bound change, added length check, swapped condition, changed constant, inserted early return, API-misuse removal, integer-width change, added NULL check, reordered statements, inlined helper, loop-bound change) each with: id, description, C code before/after example, the changed-function label it implies, compile-safety notes, and the nuisance transformations that must NOT count as changes (renames, reordering of independent statements, formatting). (D) Nuisance variants list for recompile-noise controls (compiler version, -O level, /GL vs none, PGO, link order, timestamps) with how each is produced reproducibly. (E) Label schema as JSON Schema (card, function label, provenance, confidence of the label itself, split assignment by project/lineage/time) and a leakage-control protocol (what may never cross train/validation/test) with a worked example. (F) 10 adversarial label-noise scenarios and how the evaluator must treat each.

OUTPUT RULES: exhaustive, no summarising. Emit machine-readable parts as JSON or YAML files, each as `=== FILE: tools/calibration/catalogue/<name>.json ===` (or .yaml, .md) followed by full content. Plain YAML scalars must not contain ': '. One group (A-F) per message, ending with `NEXT: <group>`; I reply `continue`. Mark every uncertain fact UNVERIFIED; never fabricate hashes.
```

---

## PROMPT 3 of 5: Unified-engine gate fixtures and test code

```
ROLE: senior test engineer for a binary-diffing engine. PatchTrace's "unified engine" matches functions between an older and newer PE build through a pass ladder (P00-P19) and fuses independent engines' evidence without averaging scores. It is released only if numeric gates G-U1 to G-U8 pass.

REPO ACCESS: you can read the GitHub repository djshellshoxxx/patchtrace directly. Read every file below from branch claude/instance-d-gui (NOT main: main lacks the newest docs). If a path is missing, search the repo tree (also docs/research, docs/plans, docs/audits, docs/specs) before assuming it does not exist. FILES TO READ FIRST: docs/specs/unified-engine/ (all 00-11 files); docs/plans/unified-engine-plan.md; docs/research/ue-open-questions.md and ue-matching-literature.md if present; src/patchtrace/unified/contracts.py, keys.py, limits.py, read_model.py; tools/unified/ (outcomes.py, live_pairs.py); .github/workflows/unified-live-gates.yml; tests/test_unified_*.py (skim names and fixtures).

TASK: write the complete test and fixture suite for the gates, as Python (3.12, pytest, hypothesis, no network, no execution of target binaries, deterministic, each file under 30 s): (1) a synthetic PE builder library (tests/unified_support/synthetic_pe.py) that emits minimal valid PE32+ files with configurable sections, imports, exports, function bodies from a tiny x86-64 byte assembler (support mov, add, cmp, jcc, call, ret, lea, nop padding, jump tables, thunks); (2) a generator of pairs with KNOWN ground truth: unchanged, moved, renamed, inlined, split, merged, constant-changed, condition-changed, added-check, removed-code; (3) nuisance-variant generators emulating recompile noise (register reallocation, instruction scheduling swaps, basic-block reordering, padding changes, address shifts); (4) for each gate G-U1..G-U7 an evaluator test module that states the gate formula from 08-evaluation.md in a docstring, computes the metric on generated pairs with paired bootstrap confidence intervals, and asserts pass/fail/insufficient-data correctly on known-good and known-bad synthetic engines (include deliberately broken engines that MUST fail the gate); (5) mutation tests for the fusion rules (conflict kept, unknown is not a negative vote, shared-origin counts once, no score averaging) as property tests; (6) golden-file tests for read-model output; (7) a timing harness with budgets.
Think through each gate's statistical power and say how many generated cases are needed.

OUTPUT RULES: exhaustive; write every file in full; no placeholders or "etc."; each as `=== FILE: <path> ===` with full code, one file per message, ending `NEXT: <path>`; I reply `continue`. Use only identifiers that exist in the repo sources; if one is missing, add it to a final file `=== FILE: docs/research/ue-fixture-gaps.md ===` listing what the real code must expose. Keep code ruff-clean (line length 120), type-hinted, `from __future__ import annotations`, pathlib, utf-8 with newline='\n'.
```

---

## PROMPT 4 of 5: KB/CVE correlator and patch-search fixture corpus, adversarial cases, property tests

```
ROLE: senior QA architect for a security-data pipeline. PatchTrace's KB/CVE correlator maps Microsoft KB updates to CVEs and products (MSRC CVRF/CSAF data), resolves old/new binary pairs from Winbindex and update packages, and feeds a patch-search workflow. Everything runs offline-first with explicit consent for network use.

REPO ACCESS: you can read the GitHub repository djshellshoxxx/patchtrace directly. Read every file below from branch claude/instance-d-gui (NOT main: main lacks the newest docs). If a path is missing, search the repo tree (also docs/research, docs/plans, docs/audits, docs/specs) before assuming it does not exist. FILES TO READ FIRST: docs/specs/kb-cve-correlation-and-acquisition.md; docs/specs/kb-patch-search-and-pair-resolution.md; kb-patch-search-source-adapters.md; kb-patch-search-pair-lifecycle.md; kb-patch-search-ui-cli-contract.md; kb-patch-search-qa-and-fixtures.md; kb-patch-search-contract-blueprint.md; docs/specs/program-e/KB-integration-plan.md and KB2-source-facts.md; docs/research/kb-msrc-sources.md and kb-winbindex-packages.md if present; src/patchtrace/kbcorrelation/ (contracts, store, reducer) skim.

TASK: write the full fixture corpus and test code described in kb-patch-search-qa-and-fixtures.md and extend it: (1) 60 SYNTHETIC fixture documents (clearly fake ids, e.g. KB9000001, CVE-2099-xxxx, never real Microsoft data): CVRF v3 and CSAF/VEX documents covering cumulative and checkpoint updates, supersedence chains, many-to-many KB/CVE/product, product-name variants, multiple architectures, withdrawn and re-issued advisories, missing fields, duplicate ids, oversized text, markup/script injection in titles and notes, unicode confusables, BOMs, CRLF, numeric-as-string, huge arrays, deep nesting; (2) Winbindex-style JSON fixtures (hashes, file versions, update ids, missing signatures, conflicting entries); (3) update-package listings (PSFX, MSU, CAB, forward and reverse deltas) as metadata-only fixtures; (4) all 32 adversarial cases and 9 crash-injection points from the spec as concrete pytest modules plus a crash-injection harness (kill/IO-error injection at named points; verify the companion store recovers and is idempotent); (5) property-based tests (hypothesis) for the reducer: order independence, idempotence, supersedence monotonicity, no confirmed CVE edge from monthly co-presence alone, attribution of every edge to a source snapshot; (6) consent and network tests: socket-denial fixtures proving nothing leaves without consent, exact-host allow-list, size and slow-drip limits (fake transport with controllable chunk timing); (7) a performance test plan with budgets for 10k KB/CVE rows and 100k pair candidates.
Use real field names from the repo contracts; where the contracts and specs disagree, list it in `=== FILE: docs/research/kb-fixture-conflicts.md ===`.

OUTPUT RULES: exhaustive; every fixture and test written out in full (JSON for fixtures, Python 3.12 pytest for tests; ruff-clean, type-hinted, pathlib, utf-8 newline='\n', no network, deterministic, files under 30 s each). Emit each as `=== FILE: tests/fixtures/kb/<name>.json` or `tests/test_kb_<name>.py ===` with full content; one group per message, ending `NEXT: <group>`; I reply `continue`. Do not use real vendor data; mark any fact you are unsure of as UNVERIFIED.
```

---

## PROMPT 5 of 5: Full help, documentation and tooltip copy

```
ROLE: senior technical writer and accessibility-minded UX writer for PatchTrace, a Windows-first desktop tool for finding the code a security patch changed by comparing an older and a newer build of a Windows binary. Audience: vulnerability researchers and patch analysts who know reverse engineering but not PatchTrace.

REPO ACCESS: you can read the GitHub repository djshellshoxxx/patchtrace directly. Read every file below from branch claude/instance-d-gui (NOT main: main lacks the newest docs). If a path is missing, search the repo tree (also docs/research, docs/plans, docs/audits, docs/specs) before assuming it does not exist. FILES TO READ FIRST: README.md; docs/guide/ (all files if present); docs/modules.md; docs/specs/ui.md; docs/specs/program-e/GUI-integration-plan.md (sections 8.4-8.9); every docs/specs/panels/*.md if present; src/patchtrace/tooltips.py (read the style: four lines What / Why / Effect / Source); docs/windows.md; docs/qa.md.

TASK: produce, in full: (1) IN-APP HELP: a help system as Markdown topic files under docs/help/ (about 60 topics, each 150-400 words): every panel (evidence, unified, search, graph, strings, capabilities, build_env, rules, kb, kev, leads, series, files, guide), every state message and what to do, every setting, every shortcut table, privacy and consent explained plainly, offline bundle, external tools and how PatchTrace finds them, reading confidence honestly (what is calibrated and what is not), glossary of 150 terms; (2) TOOLTIP COPY: for each panel write the complete tooltip set (every control, column header, button, chip, state) as Python dict literals in the exact style of tooltips.py `'<id>': _e('What (<=160 chars)', 'Why', 'Effect', 'Source')`, ids prefixed by panel id (e.g. `kb.dock`, `kb.action`), at least 25 entries per panel, no probability or vulnerability-claim wording, no word 'safe'; (3) TUTORIALS: 12 step-by-step worked tutorials (each 500-900 words) such as 'Compare two builds of one DLL', 'Find the changed function for a CVE from a KB number', 'Read the Unified result and its provenance', 'Use series to follow a function across three builds', 'Use the offline bundle on an air-gapped machine', 'Export a report'; (4) TROUBLESHOOTING: 80 entries (symptom, cause, fix) across install, bundle, Java/Ghidra, Windows paths, permissions, antivirus, DPI/high contrast, screen readers, slow runs, memory, network consent; (5) MANUAL ACCEPTANCE CHECKLISTS for Windows (DPI 100/150/200 percent, NVDA, Narrator, high-contrast themes, reduced motion, keyboard-only walk of every dock, offline bundle on a disconnected VM): numbered steps with expected results and a pass/fail column; (6) RELEASE NOTES TEMPLATE and a 'Known limitations' page that is honest about unbuilt or uncalibrated features (mark each 'planned' or 'experimental').
Only describe features that appear in the repo files; mark anything else 'planned'. Plain, direct language; no marketing.

OUTPUT RULES: exhaustive; do not abbreviate or say 'and so on'. Emit each file as `=== FILE: <path> ===` with full content; one group or ten topics per message, ending `NEXT: <group>`; I reply `continue`. Mark uncertain statements UNVERIFIED.
```

---

## PROMPT 6: Deferred audit fixes, written straight into the repo (own branch, draft PR)

Different from prompts 1-5: ChatGPT commits to the repository itself. It may only create and push its own branch and open a DRAFT pull request; it must never touch `main` or any `claude/*` branch. CI then runs the tests; nothing here is trusted until CI is green and a Claude worker has reviewed the diff.

```
ROLE: senior Python engineer fixing audited defects in PatchTrace, a Windows-first desktop tool that compares an older and a newer build of a Windows PE binary to find the code a patch changed. You work test-first and you write directly to the GitHub repository djshellshoxxx/patchtrace, which you can read and write.

GIT RULES (hard limits):
1. Base: branch claude/instance-d-gui (NOT main; main lacks the newest code). Create ONE new branch named chatgpt/deferred-audit-fixes-1 from the current head of claude/instance-d-gui.
2. Commit and push ONLY to chatgpt/deferred-audit-fixes-1. Never push, force-push, merge or delete anything on main or on any branch whose name starts with claude/. Never rewrite history. One commit per finding, message: "<finding id>: <what changed>".
3. When done, open a DRAFT pull request from chatgpt/deferred-audit-fixes-1 into claude/instance-d-gui. Do not mark it ready, do not merge it, do not enable auto-merge.
4. If you cannot write to the repo, stop at once and say so; do not paste the code into chat instead.

READ FIRST (branch claude/instance-d-gui): AGENTS.md, CLAUDE.md, docs/plans/worker-brief.md (coding rules and product invariants: follow them exactly), and the six fix reports docs/audits/20261015-fixes-core-series.md, docs/audits/20261015-fixes-acquisition.md, docs/audits/20261015-fixes-secondary.md, docs/audits/20261015-fixes-cli-pe-intel.md, docs/audits/20261015-fixes-gui-ops.md, docs/audits/20261015-fixes-test-hygiene.md. Each ends with a list of DEFERRED findings. The full finding text (file:line, evidence) is in the matching audit file docs/audits/20261015-*.md (not the fixes- files).

TASK: fix as many DEFERRED findings as you can, in this priority order: (1) security findings (ids starting SEC-), (2) acquisition findings (ACQ-12, ACQ-13), (3) core/series, (4) CLI/PE, (5) GUI (GUI-9, 11, 12, 15), (6) test hygiene (TST-4 rest, TST-8). Skip a finding when it needs a decision from the owner, needs network or a real Windows machine, or would change a persisted file format incompatibly (persisted contracts change additively only); list each skipped finding with the reason in the PR description.

FOR EACH FINDING: (a) re-read the cited code and confirm the defect still exists on the branch (if already fixed, say so and skip); (b) write a failing test first, in the matching existing tests/ file or a new tests/test_<area>_<id>.py, hermetic (no network, no Microsoft binaries, no executing target files), deterministic, with short explicit pytest ids; (c) make the smallest correct code change; (d) keep code style, naming, comment density and type hints identical to the surrounding file; pure logic stays separate from Qt; (e) never add a dependency; (f) never edit tests to make them pass unless the test asserted the defect, and then say so in the commit message.

CANNOT RUN CODE: you cannot execute tests. Therefore be conservative: read the called functions and existing tests before editing, trace each new test by hand against your code, and prefer fewer, certain fixes over many guesses. Mark in the PR description which fixes you traced by hand and how.

INVARIANTS (violating one is a defect): never execute a target binary; no network without operation-specific consent; never fabricate evidence; untrusted text is bounded and escaped; older/newer orientation explicit; provenance preserved; one main window; persisted contracts additive only; no GPL/AGPL code copied; Microsoft-derived binaries or labels never committed.

PR DESCRIPTION must contain: table of finding id | status (fixed / already fixed / skipped) | files | test name; the skipped list with reasons; "Not verified" (everything that needs running). Do not claim tests pass.

OUTPUT: after you finish, reply with the PR URL, the branch name, the table, and "NEXT: <first finding you did not reach>" if you stopped early. Stop after at most 15 findings per conversation; I will start a new conversation for the rest.
```

---

## PROMPTS 7-11: prompts 1-5 again, but ChatGPT commits straight to the repo

Each block below is self-contained. Same git rules as PROMPT 6: its own `chatgpt/*` branch, draft PR into `claude/instance-d-gui`, never `main`, never `claude/*`. Only NEW files (no overwrites), only the paths named. Claude reviews the diff, CI decides.

### PROMPT 7: Qt panel specs (direct write)

```
ROLE: senior engineer and technical writer on PatchTrace (Windows-first PySide6 tool that compares an older and a newer build of a Windows PE binary). You can read and write the GitHub repository djshellshoxxx/patchtrace.

TASK DEFINITION: open docs/plans/chatgpt-prompts.md on branch claude/instance-d-gui and read the section "PROMPT 1 of 5" completely (ROLE, REPO ACCESS, FACTS, INVARIANTS, TASK, EACH SPEC/RULES). Do that task exactly as written, with ONE change: ignore its OUTPUT RULES (the "=== FILE ===" blocks and "NEXT:" turns). Instead commit each file straight into the repository.

GIT RULES (hard limits):
1. Base: branch claude/instance-d-gui (NOT main). Create ONE branch named chatgpt/panels-1 from its current head.
2. Commit and push ONLY to chatgpt/panels-1. Never push, force-push, merge or delete on main or on any branch starting with claude/. Never rewrite history. One commit per file or small related group, clear message.
3. Create only NEW files, only under docs/specs/panels/ and docs/plans/panels-build-plan.md. Never overwrite or edit an existing file; if a file you want already exists, write yours with a -2 suffix and say so. Never touch src/, .github/, pyproject.toml or tools/ unless the section names it.
4. When finished, open a DRAFT pull request from chatgpt/panels-1 into claude/instance-d-gui. Do not mark it ready, merge it or enable auto-merge.
5. If you cannot write to the repo, stop at once and say so. Do not paste file contents into chat instead.

QUALITY: you cannot run code. Anything you cannot verify (SHAs, CVE ids, licences, version numbers, field names, URLs) must be marked UNVERIFIED in the file, never invented. Follow docs/plans/worker-brief.md for coding and product-invariant rules. Be exhaustive; do not abbreviate; no placeholders such as "TBD".

PR DESCRIPTION: list every file with one line of purpose, then "Not verified" (everything that needs running or network). Do not claim tests pass.

REPLY at the end with only: PR URL, branch name, file count, and "NEXT: <what you did not reach>" if you stopped early (at most ~25 files per conversation; I will start another conversation for the rest).
```

### PROMPT 8: Tier R corpus: recipe cards, planted mutations, CVE-fix case candidates (direct write)

```
ROLE: senior engineer and technical writer on PatchTrace (Windows-first PySide6 tool that compares an older and a newer build of a Windows PE binary). You can read and write the GitHub repository djshellshoxxx/patchtrace.

TASK DEFINITION: open docs/plans/chatgpt-prompts.md on branch claude/instance-d-gui and read the section "PROMPT 2 of 5" completely (ROLE, REPO ACCESS, FACTS, INVARIANTS, TASK, EACH SPEC/RULES). Do that task exactly as written, with ONE change: ignore its OUTPUT RULES (the "=== FILE ===" blocks and "NEXT:" turns). Instead commit each file straight into the repository.

GIT RULES (hard limits):
1. Base: branch claude/instance-d-gui (NOT main). Create ONE branch named chatgpt/corpus-1 from its current head.
2. Commit and push ONLY to chatgpt/corpus-1. Never push, force-push, merge or delete on main or on any branch starting with claude/. Never rewrite history. One commit per file or small related group, clear message.
3. Create only NEW files, only under the paths PROMPT 2 names (recipe/release catalogue data, corpus/catalog, docs/plans). Never overwrite or edit an existing file; if a file you want already exists, write yours with a -2 suffix and say so. Never touch src/, .github/, pyproject.toml or tools/ unless the section names it.
4. When finished, open a DRAFT pull request from chatgpt/corpus-1 into claude/instance-d-gui. Do not mark it ready, merge it or enable auto-merge.
5. If you cannot write to the repo, stop at once and say so. Do not paste file contents into chat instead.

QUALITY: you cannot run code. Anything you cannot verify (SHAs, CVE ids, licences, version numbers, field names, URLs) must be marked UNVERIFIED in the file, never invented. Follow docs/plans/worker-brief.md for coding and product-invariant rules. Be exhaustive; do not abbreviate; no placeholders such as "TBD".

PR DESCRIPTION: list every file with one line of purpose, then "Not verified" (everything that needs running or network). Do not claim tests pass.

REPLY at the end with only: PR URL, branch name, file count, and "NEXT: <what you did not reach>" if you stopped early (at most ~25 files per conversation; I will start another conversation for the rest).
```

### PROMPT 9: Unified-engine gate fixtures and test code (direct write)

```
ROLE: senior engineer and technical writer on PatchTrace (Windows-first PySide6 tool that compares an older and a newer build of a Windows PE binary). You can read and write the GitHub repository djshellshoxxx/patchtrace.

TASK DEFINITION: open docs/plans/chatgpt-prompts.md on branch claude/instance-d-gui and read the section "PROMPT 3 of 5" completely (ROLE, REPO ACCESS, FACTS, INVARIANTS, TASK, EACH SPEC/RULES). Do that task exactly as written, with ONE change: ignore its OUTPUT RULES (the "=== FILE ===" blocks and "NEXT:" turns). Instead commit each file straight into the repository.

GIT RULES (hard limits):
1. Base: branch claude/instance-d-gui (NOT main). Create ONE branch named chatgpt/unified-fixtures-1 from its current head.
2. Commit and push ONLY to chatgpt/unified-fixtures-1. Never push, force-push, merge or delete on main or on any branch starting with claude/. Never rewrite history. One commit per file or small related group, clear message.
3. Create only NEW files, only under the paths PROMPT 3 names (tests/ and tests/fixtures/ only). Never overwrite or edit an existing file; if a file you want already exists, write yours with a -2 suffix and say so. Never touch src/, .github/, pyproject.toml or tools/ unless the section names it.
4. When finished, open a DRAFT pull request from chatgpt/unified-fixtures-1 into claude/instance-d-gui. Do not mark it ready, merge it or enable auto-merge.
5. If you cannot write to the repo, stop at once and say so. Do not paste file contents into chat instead.

QUALITY: you cannot run code. Anything you cannot verify (SHAs, CVE ids, licences, version numbers, field names, URLs) must be marked UNVERIFIED in the file, never invented. Follow docs/plans/worker-brief.md for coding and product-invariant rules. Be exhaustive; do not abbreviate; no placeholders such as "TBD".

PR DESCRIPTION: list every file with one line of purpose, then "Not verified" (everything that needs running or network). Do not claim tests pass.

REPLY at the end with only: PR URL, branch name, file count, and "NEXT: <what you did not reach>" if you stopped early (at most ~25 files per conversation; I will start another conversation for the rest).
```

### PROMPT 10: KB/CVE correlator and patch-search fixtures, adversarial cases, property tests (direct write)

```
ROLE: senior engineer and technical writer on PatchTrace (Windows-first PySide6 tool that compares an older and a newer build of a Windows PE binary). You can read and write the GitHub repository djshellshoxxx/patchtrace.

TASK DEFINITION: open docs/plans/chatgpt-prompts.md on branch claude/instance-d-gui and read the section "PROMPT 4 of 5" completely (ROLE, REPO ACCESS, FACTS, INVARIANTS, TASK, EACH SPEC/RULES). Do that task exactly as written, with ONE change: ignore its OUTPUT RULES (the "=== FILE ===" blocks and "NEXT:" turns). Instead commit each file straight into the repository.

GIT RULES (hard limits):
1. Base: branch claude/instance-d-gui (NOT main). Create ONE branch named chatgpt/kb-fixtures-1 from its current head.
2. Commit and push ONLY to chatgpt/kb-fixtures-1. Never push, force-push, merge or delete on main or on any branch starting with claude/. Never rewrite history. One commit per file or small related group, clear message.
3. Create only NEW files, only under the paths PROMPT 4 names (tests/ and tests/fixtures/ only). Never overwrite or edit an existing file; if a file you want already exists, write yours with a -2 suffix and say so. Never touch src/, .github/, pyproject.toml or tools/ unless the section names it.
4. When finished, open a DRAFT pull request from chatgpt/kb-fixtures-1 into claude/instance-d-gui. Do not mark it ready, merge it or enable auto-merge.
5. If you cannot write to the repo, stop at once and say so. Do not paste file contents into chat instead.

QUALITY: you cannot run code. Anything you cannot verify (SHAs, CVE ids, licences, version numbers, field names, URLs) must be marked UNVERIFIED in the file, never invented. Follow docs/plans/worker-brief.md for coding and product-invariant rules. Be exhaustive; do not abbreviate; no placeholders such as "TBD".

PR DESCRIPTION: list every file with one line of purpose, then "Not verified" (everything that needs running or network). Do not claim tests pass.

REPLY at the end with only: PR URL, branch name, file count, and "NEXT: <what you did not reach>" if you stopped early (at most ~25 files per conversation; I will start another conversation for the rest).
```

### PROMPT 11: Full help, documentation and tooltip copy (direct write)

```
ROLE: senior engineer and technical writer on PatchTrace (Windows-first PySide6 tool that compares an older and a newer build of a Windows PE binary). You can read and write the GitHub repository djshellshoxxx/patchtrace.

TASK DEFINITION: open docs/plans/chatgpt-prompts.md on branch claude/instance-d-gui and read the section "PROMPT 5 of 5" completely (ROLE, REPO ACCESS, FACTS, INVARIANTS, TASK, EACH SPEC/RULES). Do that task exactly as written, with ONE change: ignore its OUTPUT RULES (the "=== FILE ===" blocks and "NEXT:" turns). Instead commit each file straight into the repository.

GIT RULES (hard limits):
1. Base: branch claude/instance-d-gui (NOT main). Create ONE branch named chatgpt/help-docs-1 from its current head.
2. Commit and push ONLY to chatgpt/help-docs-1. Never push, force-push, merge or delete on main or on any branch starting with claude/. Never rewrite history. One commit per file or small related group, clear message.
3. Create only NEW files, only under docs/guide/ and docs/help/ only; do not edit src/. Never overwrite or edit an existing file; if a file you want already exists, write yours with a -2 suffix and say so. Never touch src/, .github/, pyproject.toml or tools/ unless the section names it.
4. When finished, open a DRAFT pull request from chatgpt/help-docs-1 into claude/instance-d-gui. Do not mark it ready, merge it or enable auto-merge.
5. If you cannot write to the repo, stop at once and say so. Do not paste file contents into chat instead.

QUALITY: you cannot run code. Anything you cannot verify (SHAs, CVE ids, licences, version numbers, field names, URLs) must be marked UNVERIFIED in the file, never invented. Follow docs/plans/worker-brief.md for coding and product-invariant rules. Be exhaustive; do not abbreviate; no placeholders such as "TBD".

PR DESCRIPTION: list every file with one line of purpose, then "Not verified" (everything that needs running or network). Do not claim tests pass.

REPLY at the end with only: PR URL, branch name, file count, and "NEXT: <what you did not reach>" if you stopped early (at most ~25 files per conversation; I will start another conversation for the rest).
```

---

## What to do with the output
0. Prompt 6 needs no copying: ChatGPT pushes its own branch `chatgpt/deferred-audit-fixes-1` and opens a draft PR. Tell Claude when it appears; Claude reviews the diff and lets CI decide.
1. Copy each ChatGPT reply (prompts 1-5) (all messages of one prompt, one after another) into a text file named `promptN-<topic>.md`.
2. Put the file in `docs/inbox/chatgpt/` on branch `claude/instance-d-gui` (GitHub: Add file > Upload files or Create new file), or paste it to Claude in chat.
3. Tell Claude. It runs `python tools/split_chatgpt_output.py docs/inbox/chatgpt/<file> --apply`, then workers lint, verify facts (SHAs, CVE ids, licences, field names) and run the tests before anything is merged.
