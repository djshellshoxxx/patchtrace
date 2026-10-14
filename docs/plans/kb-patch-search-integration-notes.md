# SPEC-32 Integration Notes, Engineering Decisions, and Agent Handoff

Status: companion engineering notes, 2026-10-14.
Master spec: docs/specs/kb-patch-search-and-pair-resolution.md
Build guide: docs/plans/kb-patch-search-implementation.md
This change is documentation only. Do not report any of the feature as implemented until verified by code/tests.

## 1. Integration inventory of real repository code

| Existing path | Current purpose | Correct integration | Forbidden shortcut |
|---|---|---|---|
| src/patchtrace/acquisition/contracts.py | Winbindex BuildCandidate and exact paired download records | translate selected candidates into existing DownloadPlan | broaden BuildCandidate to represent speculative CVE associations |
| src/patchtrace/acquisition/winbindex.py | per-filename metadata parse, PE index URL derivation | reuse after analyst/source suggests filename | claim it is a general reverse KB-to-all-files search |
| src/patchtrace/acquisition/transport.py | consented symbol server fetch, metadata, streaming | compose for x64 candidate downloads only | add unrestricted Catalog/MSRC URLs to same download allowlist |
| src/patchtrace/acquisition/quarantine.py | verify, stage and promote binaries | entry for verified pairs | put unknown delta bytes directly in Older/Newer |
| src/patchtrace/acquisition/delta.py | Windows msdelta PA30 reconstruction for exact base | optional separate capability-gated adapter | call it universal MSU/PSFX reconstruction |
| src/patchtrace/enrichment/cve.py | normalized CVE context and contextual ranking | provide CVE read model and source facts | use CVE token overlap as proof of affected function |
| src/patchtrace/enrichment/intelligence.py | NVD and MSRC vulnerability endpoint HTTP requests | copy transport pattern or inject provider adapter | use its one-CVE lookup as a KB search index |
| src/patchtrace/service.py | project lifecycle, artifact identity, revision/SQLite | create ordinary project with exactly two verified files | modify artifacts constraint or call from worker-owned SQLite thread |
| src/patchtrace/ui.py AcquisitionDialog | filename selector and download worker | leave intact; add separate wizard | graft a large KB parser and catalog scraping into this class |
| src/patchtrace/cli.py | existing top-level commands and JSON contract | register "patch" subcommands and delegate | rename "acquire search" and break scripts |
| src/patchtrace/tooltips.py | central tooltip registry | add keys and enumerated coverage | ad-hoc tooltip text scattered across UI |
| src/patchtrace/secondary/* | optional engine runs and evidence UI | read verified, current evidence only | make secondary engines know KB IDs |
| docs/specs/unified-engine/* | planned unified diff and fusion | optional evidence-reader adapter when ready | make SPEC-32 block on unfinished matcher |

Existing code evolution is rapid. This map was checked on 2026-10-14, NOT a stable assertion about future commits. Re-read files when implementation begins.

## 2. Boundary contracts and source of truth

PatchSearch does not own binaries or vulnerability analysis engines. It owns the *selection context* and *relationship evidence*.

Owner map:
- Microsoft advisory parser owns association records and source pointers.
- Product-identity resolver owns "which product/build/arch is this".
- Component-hint provider owns why a given file is proposed.
- SPEC-08 acquisition owns download-plan validations, files and quarantine.
- ProjectService owns actual project artifact creation and SQLite lifecycle.
- Enrichment/CSAF/SPEC-30 own CVE context and patch-intent interpretation.
- Secondary/Unified engine owns function/diff evidence.
- PatchSearch interpretation adapter owns the join and analyst-facing explanation, never a new matching or vulnerability detector by default.

All adapters accept immutable object IDs and resolved hashes; the UI receives a read model. Never pass a QTableWidget item, live mutable QObject, or unchecked external JSON directly to backend logic.

## 3. Official data-source details

### CVRF and MSRC

Microsoft's CVRF API is documented at https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API and the reference PowerShell Get-MsrcCvrfAffectedSoftware function explicitly collects KB remediations of Type 2 per product ID. Use this implementation as a test oracle only, not as code to copy blindly. Check official schema versions and sample data before parser implementation.

CVRF monthly document -> Vulnerability -> Remediations -> ProductID + Type-2 Knowledge Base ID -> ProductTree mapping -> KbCveEdge. A CVRF document usually describes many CVEs; monthly co-presence is irrelevant. Preserve exact source pointer and document revision.

Official Security Update Guide also offers vulnerability details. The existing repo directly fetches CVE details from api.msrc.microsoft.com; that does not mean there is a supported public lookup endpoint that returns all updates for any KB. Plan local indexing of bounded official documents and explicit product selector.

### CSAF and VEX

The separate Microsoft CSAF directory https://msrc.microsoft.com/csaf provides published machine-readable advisories and VEX. The parser and graph belong to SPEC-28; SPEC-32 consumes normalized claims. Interpret product status per OASIS CSAF specification, not as a boolean flag inferred from presence in product_tree. The same product can have differing state among revisions and advisories; do not collapse without trace.

### Microsoft Update Catalog / WUA

The Catalog web service supports KB search interactively and supplies update packages; Microsoft's public documentation does not establish a stable, supported general JSON KB search API. No production adapter may rely solely on undocumented HTML form/POST parsing. An "Open catalog results" button with encoded KB query is acceptable, and manually imported catalog metadata must be source-attributed.

Windows Update Agent IUpdateSearcher supports searching a selected update service for *applicable* updates on the computer, with options including potentially superseded results and online/offline scan. It is not an arbitrary historical full Microsoft Update Catalog mirror, and can be biased by the analyzing host's product and configured server. Keep it optional and label scope. Sources:
- https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher
- https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline
- https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/wsus-and-the-catalog-site

### Winbindex and Microsoft symbol server

Current SPEC-08 stores build indexes from a third-party Winbindex dataset and reconstructs expected Microsoft symbol-server download URLs. Winbindex metadata is keyed by *file name*. KBs in its entry metadata help filter candidates once the binary name is known. It cannot guarantee a unique CVE-bearing file. A SHA-256 match against the third-party index establishes agreement with that index, not independently verified Microsoft authorship.

Available download classifications: direct, candidate SizeOfImage probe, unavailable/update-package only. Pure PA30/PA31 or unsupported formats must remain blocked until reconstructed against the exact base with expected target hash.

### Servicing / PSFX

Per https://learn.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper, newer cumulative updates can package both forward and reverse differentials relative to a release baseline; component servicing hydrates target files. Raw extraction of a CAB can yield delta payloads rather than complete PE images. Do not promise generic automatic recovery from any KB.

Supported upgrade path if later justified:
  known clean baseline image + exact update + verified servicing prerequisites
  -> disposable offline copy A (before) and B (after)
  -> supported Windows servicing in B
  -> copy chosen matching binary from both
  -> identity + hash + signature (if possible) -> PatchTrace pair

Do not run DISM /Online, change host servicing state, or imply that it works for every Windows package.

## 4. Version / pre-post semantics

The "older" and "newer" labels express two bytes for comparison. They do not independently assert "vulnerable" and "fixed".

Maintain three orthogonal attributes:
1. Pair ordering: artifact A release earlier/later and content hashes; exact lineage.
2. Fix boundary: official fixed release/update evidence, inherited cumulative fixes and plausible prior revision mapping.
3. Vulnerability truth: not established automatically by PatchSearch.

Pre-fix and post-fix labeling permitted only when product ID, architecture, release branch and actual patch boundary are reasonably supported. Supersedence can make one KB content part of a later update, and multiple CVEs may be fixed across different modules. Build number alone can be insufficient when unrelated branches/builds share filenames.

If fixed build is known but previous file-version lineage unknown, mark old status unknown. User-selected exploratory pairs are allowed if visible. Never auto-reorder by lexicographic version strings; use typed component tuple/build metadata.

## 5. "What to look for": proposed conservative rule mapping

These are triage hints. The UI must separate advisory-backed CWE from independently observed binary changes. Each rule has version, source CWE(s), positive indicators, negative indicators, and limitations.

| CWE / theme | Hypothetical patch motifs to prioritize | Strong counterexample / limitation |
|---|---|---|
| CWE-787 out-of-bounds write | inserted length/range guard controlling a write; changed allocation-to-copy size relationship; validated index before store | an unrelated check added elsewhere proves nothing |
| CWE-125 out-of-bounds read | adjusted read length, boundary comparisons, cursor/end checks, parse limits | changed import or constant without read linkage is weak |
| CWE-190 integer overflow | checked addition/multiplication, wider intermediate, saturation/rejection before allocation | arithmetic op changes can be compiler or performance updates |
| CWE-416 use-after-free | refcount/lifetime ownership changes; added lock/lease; delayed release; invalidate-after-free guard | allocator-related string names alone are not proof |
| CWE-287 improper authentication | added credential/path validation before protected operation; stricter fail-closed branch | new condition in a same-named function need not enforce access |
| CWE-22 path traversal | path canonicalization, root-bound enforcement, rejection of dot-dot escapes | path string filters may be insufficient by themselves |
| Race/concurrency | atomic ordering/lock coverage, state-check-to-use changes, cancellation safety | mutex added elsewhere unrelated to vulnerable path |

Exact CWE and affected component take priority over broad title matching. If no CWE or precise description, show "insufficient advisory detail for targeted code signature" plus general comparison affordances.

Rule outputs:
- FACT: "MSRC lists CVE-X against KB-Y for selected product Z."
- HYPOTHESIS: "Potential bounds-check or copy-size change to examine."
- OBSERVATION: "Function pair match M shows an added conditional guarding a store." (only if engine supplies validated evidence)
- LIMITATION: "Function identity contested; no data-flow proof of CVE mapping."

Never merge these four sentences into "CVE-X fixed at function M".

## 6. GUI details

Proposed interaction layout:

    MainWindow > New / File
        New project...
        Download from Microsoft symbol server...       [existing]
        Search Microsoft KB / patch...                  [new]

    Patch search wizard:
        [ KB: KB________ ] [Offline | Online with consent] [Search]
        +-----------------------------------------------+
        | Product / architecture / update variant table |
        +-----------------------------------------------+
        | CVEs (sources, affected state, conflicting)   |
        +-----------------------------------------------+
        | Component filename hints + manual text input |
        +-----------------------------------------------+
        | Older vs Newer pair proposals, source status  |
        +-----------------------------------------------+
        | Consent/download | Import PE pair | Create    |
        +-----------------------------------------------+

    Existing project:
        Tabs/Docks: Current comparison | Evidence | Patch intelligence (if attached)

When wizard attaches context: show optional notification dialog "What PatchTrace may look for"; place complete durable list in Patch Intelligence dock so pop-up dismissal doesn't discard information. After analysis finishes: non-modal prompt "Patch intelligence findings available" opening the dock, not a blocking modal interrupt during a long run. A user can review a direct function diff via an action if a valid current match ID exists.

A result row should show exact source provenance on selection, not only tooltip; tooltips explain controls but do not carry essential accuracy limitations. Label absent provider data, incomplete identities and ambiguity in normal text. Keyboard and screen-reader accessibility required.

## 7. Persistence / migrations / stale handling

Preferred schema addition:
  patch_search_sources(snapshot_id PK, provider, digest, schema_rev, retrieval_stamp, verified_state, local_blob_ref)
  patch_search_sessions(session_id PK, parent_project_ref?, revision, query, selected_variant, selected_pair, state, payload_json)
  patch_search_events(event_id PK, session_id, project_revision, action_type, data_digest, occurred_utc)
  patch_search_views(view_id PK, session_id, engine_run, dependency_digest, status, derived_json)

These are DESIGN NAMES; audit existing ProjectStore table naming and migration/version framework first. Avoid storing raw advisory bytes directly in many project databases if a shared content-addressed cache is already available. Treat raw source snapshots as immutable; cap/retain them explicitly and honor licensing constraints. Add schema migration idempotently and test rollback on failure.

Attach session only if project artifact SHA256 exactly matches planned pair and project revision is expected. Run-derived evidence pointer validity is checked on every opening of the dock. Stale condition must be visible: source revision, binary replacement, orientation swap, manual match edit, parser/rule version or completed run change.

Projects without patch sessions must behave byte-for-byte as before. A project missing optional new tables must open normally and lazily migrate only when feature used.

## 8. Quality gates and negative examples

Examples that MUST abstain:
- CVE appears in the same CVRF monthly document as the KB but has no KB Type-2 remediation edge for the chosen product.
- CVE lists KB for Windows Server and the user selected Windows 11.
- Advisory names only "Windows Kernel", no file is identified; do not autoselect ntoskrnl.exe.
- KB has multiple same-number updates for x64/ARM64; do not choose wrong arch.
- Winbindex returns two same-name PE versions from incompatible OS branches.
- Candidate file hash matches index but local Authenticode signature unverified; do not claim trusted Microsoft binary.
- Post-fix binary exists but pre-fix candidate is after the same cumulative fix.
- Only MSU PSFX deltas available, exact baseline unavailable; no standard pair created.
- Analysis returns a generic added bounds check; do not attribute it automatically to every CWE-787 advisory in the KB.
- Ghidriff match conflicts with BinDiff evidence; preserve disputed identity, no high-confidence localization.
- A prior run was for different artifact hashes; no stale evidence links.
- Live source currently fails but valid cached source exists; present stale-source limitation, not false "no associated CVEs".

## 9. Release-gate checklist

[ ] Baseline current main and all active PR ownership reconciled.
[ ] Typed patch-search/1 models and generated schema examples frozen.
[ ] Product-specific CVRF Type-2 KB edge correctness verified on real corpus.
[ ] Offline default and per-host consent with zero hidden fetch confirmed.
[ ] All source data, URLs, file names and JSON pointers boundary-validated.
[ ] Binary pair exact hash/PE/machine/order checks reused from SPEC-08.
[ ] Normal project create and GUI-thread SQLite ownership maintained.
[ ] Malicious source text, redirects, oversized records and malformed packages rejected.
[ ] No unsupported URL scraping or package execution.
[ ] Manual fallback available for every blocked automatic path.
[ ] Expectations and observations rendered distinctly with source pointers.
[ ] No uncalibrated vulnerability probability or automatic proven-fix claim.
[ ] Refresh/swap/match override correctly stales previous localizations.
[ ] CLI offline golden, GUI Qt tests, Windows frozen EXE and real user-accepted live probe.
[ ] Existing acquire, correlate, Ghidriff, multi-engine, N-way and report regressions green.
[ ] Docs/modules.md / tasks/todo.md / docs/qa.md updated by integration owner.
[ ] Data-source licensing and notice scan complete.
[ ] User-facing help documents unsupported OS/format and verification caveats.

## 10. Implementation handoff prompt (copy into coding agent if needed)

    Repository: djshellshoxxx/patchtrace.
    Work from fresh main and review open PRs/branches before creating files.
    Read AGENTS.md, CLAUDE.md and the three SPEC-32 documents:
      docs/specs/kb-patch-search-and-pair-resolution.md
      docs/plans/kb-patch-search-implementation.md
      docs/plans/kb-patch-search-integration-notes.md

    Goal: implement KB->product->CVE->component hint->verified old/new pair
    search as optional module, reusing SPEC-08 acquisition, SPEC-07 enrichment,
    ProjectService, current desktop workers and existing diff engines.
    Start with P0/P1 and a finite approved MVP. Write tests first, then code.
    Do not rewrite Ghidriff/BinDiff/rz-diff/unified engine. Maintain offline
    default, strict consent, immutable provenance and project revision gates.
    Do not equate KB/CVE association, candidate filename, pair identity and
    proven CVE fix. No undocumented Catalog scraping or generic PSFX claims.

    Maintain strict ownership of shared integration files, work on small
    independent feature branches, and merge tested PRs without orphan branches.
    Use the cheapest capable model for each subtask; avoid repetitive broad
    repo reviews by caching one explicit module map. Delegate independent
    parser, contract, adapter and Qt tasks but reserve shared seams for a
    single integrator. Do research from Microsoft, OASIS, original tool docs
    and reproducible code/fixtures before changing a provider contract.
    Run all relevant regressions and Windows packaging checks. Update module
    index, todo and QA evidence when work is actually completed.
    Report only genuine blockers, necessary decisions and final verified state.

## 11. Research references / non-goals

- Official Microsoft Security Updates CVRF API and per-product remediation example:
  https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
  https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfAffectedSoftware.ps1
- Official CSAF directory and standard:
  https://msrc.microsoft.com/csaf
  https://docs.oasis-open.org/csaf/csaf/v2.0/cs01/csaf-v2.0-cs01.html
- Catalog and offline servicing:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/wsus-and-the-catalog-site
  https://learn.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/servicing-the-image-with-windows-updates-sxs
- Windows Update Agent (optional local applicability metadata):
  https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher
- Index and Microsoft-hosted symbol files:
  https://github.com/m417z/winbindex

Do not infer that an automatic offline KB-to-all-changed-binaries map or direct fully hydrated old/new PEs are generally available. SPEC-32 is complete when useful partial results and explicit uncertainty are implemented reliably, not when every scenario is automated.
