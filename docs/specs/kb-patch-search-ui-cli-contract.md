# SPEC-32C: Patch Search GUI, CLI and Public Interface Contract

Status: expanded UI/API developer contract, 2026-10-14. Documentation only.
Related: docs/specs/kb-patch-search-and-pair-resolution.md, kb-patch-search-source-adapters.md, kb-patch-search-pair-lifecycle.md.
UI owner: one integration worker; CLI owner: one integration worker. Do not let multiple agents edit src/patchtrace/ui.py or src/patchtrace/cli.py in parallel.

## 0. Critical design constraints verified against PatchTrace

- src/patchtrace/ui.py has an existing AcquisitionDialog for **filename -> select older/newer -> download** and a Worker(QThread) pattern. Preserve that action and dialog unchanged for current users.
- Verbs are adapter files (GUI plan 8.12): `src/patchtrace/cli_commands/patch.py` registers "patch"; the `cli.py` COMMANDS tuple and HANDLERS map stay unedited, and existing parsing and exit codes are not rewritten.
- Existing --json envelope convention is contract enrichment-cli/1, one JSON document on stdout with diagnostics on stderr. Patch commands return that existing outer envelope and place versioned patch-search/1 objects inside result; do not silently alter the global CLI_CONTRACT version.
- Existing ProjectService and ProjectStore use a single owning SQLite connection; worker thread can compute/fetch but project create/sidecar attach happens on GUI thread or an explicitly separately owned connection if audited.
- Current main window is large. New view and state-management code go into ui_patch_search.py and ui_patch_intelligence.py, plus only a short MainWindow action/callback seam.

## 1. CLI grammar (v1 decision)

All patch commands are offline/cache-only unless the user supplies both an explicit fetch flag and complete provider/host consent. Bare patch search must never fetch.

    patchtrace patch search KB5012345 --scope-file corpus.json --json
    patchtrace patch search KB5012345 --scope-month 2024-08 --snapshot doc.json --json
    patchtrace patch search KB5012345 --scope-month 2024-08 --fetch-metadata --consent-hosts api.msrc.microsoft.com --json
    patchtrace patch variants KB5012345 --session session.json --json
    patchtrace patch components --session session.json --product-id P-CLIENT --json
    patchtrace patch pairs --session session.json --product-id P-CLIENT --file clfs.sys --json
    patchtrace patch fetch --session session.json --pair-id ID --project DIRECTORY --consent-hosts winbindex.m417z.com,msdl.microsoft.com --json
    patchtrace patch attach --session session.json --project DIRECTORY --json
    patchtrace patch explain DIRECTORY --cve CVE-2024-12345 --json

Arguments:
- search KB: required canonical KB input; may include --snapshot repeated; requires an explicit scope for online source search unless a user-selected bounded local corpus exists.
- --scope-month YYYY-MM is repeatable, max 24 unique normalized months in a request; --scope-file is a versioned manifest of permitted source documents, not unchecked arbitrary URL list.
- --fetch-metadata: opt-in; requires exact source origins in --consent-hosts, matched to generated request preview. Even with --fetch-metadata, never download a PE.
- --offline: force local snapshots only even if --fetch-metadata was accidentally supplied; reject contradictory options with invalid-argument status rather than silently choose one.
- variants requires a persisted session or imported output; no hidden fetch.
- components returns known file hints with evidence, asks for manual --file if none.
- pairs resolves expected Winbindex versions; if its cached index is missing, return SOURCE_MISSING and direct the user to separately approved search. A future pairs --fetch-index must preview exact URL and require consent.
- fetch requires immutable plan/session ID, two exact selected candidate SHA-256 hashes, destination and explicitly approved hosts; no automatic Run Comparison.
- attach is needed for a session created via manual project input; refuses mismatched artifacts.
- explain reads existing project and sidecar; strictly local, never fetches providers or launches engines.
- --dry-run is supported for search/fetch/attach planning: no network except explicitly authorized metadata fetch and no project mutation. Prefer a purely local --plan command for zero network ambiguity.
- Successful source KB lookup with no binary hint is still a complete search result; do not return no results merely because download impossible.

Commands above are chosen for implementation and should replace the ambiguous earlier placeholder syntax. If a different syntax is adopted, record a versioned decision with parser golden tests and update all three documents at once.

## 2. CLI output envelope and statuses

Stdout exactly one object in --json mode (one newline), with stable sorted keys and no emitted diagnostics:

    {
      "contract": "enrichment-cli/1",
      "command": "patch search",
      "status": "partial",
      "result": {
        "contract": "patch-search/1",
        "query": {"kb": "KB5012345"},
        "search_scope": {"type": "selected_months", "ids": ["2024-Aug"]},
        "coverage": "partial_in_scope",
        "variants": [],
        "kb_cve_edges": [],
        "sources_inspected": [],
        "unresolved": ["MSRC provider temporarily unavailable"]
      },
      "warnings": ["No complete source coverage"],
      "error": null
    }

For command failure, match existing CLI error envelope (which may have error but result=null) rather than invent a different version. On expected no-result, distinguish in-scope completeness vs source unavailable:
- complete + 0 KB matches: status complete, exit 4.
- complete KB edge resolution but no full binary pair: status complete for search/variants, exit 0; pairs may use 4 with clear blockers.
- one source failed while others valid: status partial, exit 3 only if necessary for automation to treat partial as failure, otherwise exit 0 with partial flag; choose one policy in tests **before** shipping (default proposed exit 3 for incomplete requested source coverage; 0 when query explicitly accepted cached-only partial corpus).
- invalid argument/config: 2.
- runtime/provider failure without useful result: 3.
- cancellation: 5.
No secret keys, SAS query parameters, private file system paths or raw exception traceback in output.

## 3. GUI information architecture and control state

GUI plan section 10 (integrator): the KB wizard stays a modal dialog, a child of the main window; its results go to docks (registry panels), never to a second window.

Entry point:
    File / New:
        New project...
        Download from Microsoft symbol server...   [unchanged]
        Search Microsoft KB / patch...              [new]

Proposed standalone PatchSearchDialog with read-model-driven steps:
  Step 1 - Search query: KB, offline toggle, source scope, select imported advisory and explicit network plan.
  Step 2 - Product: paged table Product Name | Version | Architecture | KB | Source | Release | Conflicts. Exact product ID in details pane.
  Step 3 - Vulnerabilities: CVE | Product status | KB association basis | CWE | Severity context | Source status. Multiple CVEs selectable; default show all associated with chosen product.
  Step 4 - Components: known source filenames if any; otherwise clear "No file names identified by advisory" with manual file input.
  Step 5 - Pair: Older/Newer table, typed versions, SHA-256, product lineage, availability, explicit swap and filter; show boundary type and warnings adjacent to confirmation.
  Step 6 - Acquisition: exact HTTPS origins and file requests, expected bytes, consent, progress, cancel, local import, retry.
  Step 7 - Project: create new project or attach to existing matching two-artifact project, show actual bytes/hash inspection.
  Step 8 - Expected patch motifs: simple advisory-backed explanation shown before Run Comparison; optional post-run evidence panel.

No implicit side effects: changing product deselects CVEs, component hints, pair selection, download plan and open expectation view; cached KB results may be retained. Changing KB invalidates all downstream selections; changing only one file SHA invalidates acquisition plan and run-bound localization.

### 3.1 UI button enablement rules

| Control | Enabled when | Disabled state text |
|---|---|---|
| Search | nonempty canonical KB and valid offline corpus or selected online plan | "Select KB and source scope" |
| Refresh source | connected mode, source plan and consent preview accepted | "Offline mode; no network" |
| Select product | at least one validated source-qualified variant | "No verified product variants in scope" |
| Select component | product selected, source hints exist or manual filename valid | "Enter a filename to continue" |
| Use as older/newer | compatible candidate selected with supported data type | "Not a complete PE candidate" |
| Download pair | exact two different eligible candidates, analyst approved plan, host consent | "Pair selection incomplete" |
| Import pair | selected paths accessible, PE preflight valid | "Choose both complete PE files" |
| Create project | verified files present and destination absent/empty | "Resolve pair blockers" |
| Run comparison | project created, project active and no run already executing | uses existing MainWindow semantics |
| Open finding | current run-bound validated FunctionMatch ID and nonstale triage | "No validated current diff location" |

Use plain text status adjacent to disabled controls; do not convey essential state only via a tooltip.

### 3.2 Window lifecycle and worker concurrency

- Every background job has unique generation and immutable query/session ID. If the user changes KB/product during work, mark earlier result obsolete; never attach to current selection.
- Worker emits bounded progress objects and immutable validated DTOs, not database connections, large untrusted Qt widgets or raw executable content.
- Cancellation calls event.set and disables new actions until worker acknowledgement; closing dialog waits for safe worker termination, consistent with AcquisitionDialog pattern.
- GUI-thread project ownership: call ProjectService.create, quarantine.promote and sidecar append on the connection owner thread. Do not copy metadata into another thread and then call an existing main-thread connection.
- Changing tabs during download must not detach or leak QThread. Window destruction cancels owned workers and cleans owned stage.
- Never display a "completed" download from a 200 response alone; wait for hash+PE and project attach.

### 3.3 Source inspector and notice dialog

Immediately after selecting CVEs (before run), show a nonblocking "What PatchTrace may look for" content pane and optionally one dismissible preview dialog. Store original explanations in the project sidecar and keep them available after dialog dismissal.

For each hypothesis:
    CVE: source-supported ID
    Weakness: CWE if source explicitly states it
    What may change: deterministic versioned motif
    Why relevant: original advisory fact (source/JSON pointer)
    What would strengthen it: concrete source->validation->sink evidence
    What would weaken it: contradictory function identity/product mapping
    Status: hypothetical, not observed / observed candidate / contested
    Limitations: source does not identify target file or function

After comparison, the Patch Intelligence dock shows run identity and pair hashes before any rows. It preserves raw comparison results, lists correlated and unclassified changes, and deep-links only where a current FunctionMatch exists.

### 3.4 Accessibility and tooltip requirements

- Set stable objectName and accessibleName/description for each new focusable control.
- Tab sequence must follow steps; Enter runs the currently enabled primary action; Esc cancels worker or closes idle dialog.
- Explain all network buttons with source/host/why and whether they modify local projects.
- Qt background status announced via accessible status label (polite frequency; no progress spam).
- Native Windows manual acceptance at 100/125/150/200% DPI and keyboard-only, Narrator/NVDA, high contrast; Qt offscreen tests are insufficient for this gate.
- Use QAbstractTableModel (not QTableWidget) to avoid 10K item construction; support pagination/search/filter and stable sort IDs.
- Escape untrusted advisory text and never enable rich text or active links without validation. Open only vetted source URLs on deliberate click.

## 4. State and error copy matrix

| Internal condition | User-visible text | Suggested action |
|---|---|---|
| SCOPE_REQUIRED | "Choose the advisory months or a saved offline corpus to search." | Select scope |
| NO_ASSOCIATION_IN_SCOPE | "No product-specific KB/CVE association found in the sources checked." | Expand scope |
| PARTIAL_SOURCE | "Some requested advisory sources could not be checked; these results may be incomplete." | Retry or use cached data |
| AMBIGUOUS_PRODUCT | "This KB has multiple product variants. Select the product and architecture." | Select variant |
| NO_COMPONENT | "The advisory does not name the changed binary." | Enter filename/import PE |
| EXPLORATORY_PAIR | "The two files are comparable, but which release first fixes this CVE is not established." | Review/continue explicitly |
| DELTA_ONLY | "Only a delta payload was located; a complete binary is required." | Import complete PE |
| HASH_MISMATCH | "Downloaded file does not match the expected hash; no project was created." | Recheck source |
| CONTEXT_PENDING | "The comparison project was created; patch-search context could not be attached." | Retry attachment |
| TRIAGE_STALE | "Patch findings refer to an earlier file pair, run or advisory revision." | Recompute |
| UNKNOWN_FIX | "The observed changes are only possible matches for this CVE." | Review linked diff |

These messages must not claim network success, vendor authenticity or vulnerability verification ahead of evidence.

## 5. UI/CLI end-to-end examples

E1, disconnected:
- Import an official CVRF snapshot file with origin status locally_imported.
- Search KB within declared snapshot corpus; show P1, CVE1.
- Advisory contains no file name => prompt for manual selected component.
- Import two synthetic complete x64 PEs -> verify bytes and create regular PatchTrace project.
- Explain a source-backed hypothesis but no localized evidence yet.
- Run comparison -> display changes from same artifact hashes, "CVE attribution unverified".

E2, connected:
- User chooses month range and consents to source requests.
- MSRC adapter returns variants, product-bound CVE edges.
- User chooses file name, Winbindex index fetch separately consented.
- Select older/newer, review boundary uncertainty, then symbol-server download plan and consent.
- Verify both full PEs against candidate metadata; create project; attach context; no automatic Run Comparison.

E3, blocked:
- A KB maps to an affected product/CVE, but only PSFX deltas exist.
- UI retains valuable advisory facts, shows package fallback or import complete PEs; no false project created.
- CLI exits with no-pair status and machine-readable blockers; not "CVE not found".

## 6. Contract tests

C01: Parser accepts correct patch grammar and invalid options return exit 2.
C02: `cli_commands/patch.py` (adapter, GUI plan 8.12) registers `patch`; COMMANDS, HANDLERS and `_command_name` stay unedited and all existing commands are preserved.
C03: --json prints exactly one document on stdout; stderr only diagnostics.
C04: No network from bare search, variants, components, explain or offline.
C05: Consent flag without exact planned request fails and never fetches.
C06: "no CVEs in searched scope" distinct from provider failure.
C07: UI KB edit invalidates selection and discards late previous-worker result.
C08: Only one project creation event if duplicate worker signals arrive.
C09: UI swap invalidates prior fixed-boundary classification.
C10: New project with no Patch Search sidecar remains fully usable.
C11: Dialog close mid-download cancels safely; no Qt destroyed-object signal errors.
C12: Source metadata malicious HTML remains escaped plain text.
C13: 10k source rows virtualized and deterministic sorted stable IDs.
C14: Keyboard-only navigation and accessible status tested on Windows.
C15: Existing AcquisitionDialog and tooltips tests pass without change.
C16: Deep-link to function disabled if run or identity is stale.
