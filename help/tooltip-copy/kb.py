"""Proposed KB investigation tooltip copy.

PLANNED: follows the KB integration plan.
The panel declaration was unavailable during review.
End-to-end desktop behavior and packaged availability are UNVERIFIED.

Sources:
- docs/specs/program-e/KB-integration-plan.md, sections 7-8
- src/patchtrace/panel_manifest.py

Local search, network planning, acquisition, project creation, and attachment
are distinct operations with distinct prerequisites.

E0 describes local import, search, planning, and manual pair workflows.
E1 adds consented network synchronization and acquisition.
Entries for E1 must remain unavailable until that implementation exists.

Additional IDs require explicit bindings to documented controls and fields.
A pair grade does not combine byte identity, lineage, and fix-boundary evidence.
An advisory reference does not establish a function-level attribution.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


KB_TOOLTIPS = {
    'kb.dock': _e(
        'Investigate a KB number or CVE ID using retained advisory evidence.',
        'Keep documentary context, candidate files, and comparison leads together.',
        'Shows the investigation without starting network work or analysis.',
        'Local advisory documents, investigation revisions, and linked project records.'),

    'kb.action': _e(
        'Show or hide the KB / CVE investigation panel.',
        'Start or resume an investigation beside the comparison.',
        'Toggles the dock; shortcut Ctrl+Shift+K.',
        'The planned panel command and central manifest.'),

    'kb.lead': _e(
        'Enter the KB number or CVE ID to investigate.',
        'Identify the documentary lookup explicitly.',
        'Validates the identifier; Search reads loaded advisory documents.',
        'Your entered lead and the supported identifier grammar.'),

    'kb.search': _e(
        'Search the local advisory index for the entered lead.',
        'Find recorded associations without an automatic network request.',
        'Creates or updates the investigation lookup and reports its coverage.',
        'Advisory documents already imported or retained on this computer.'),

    'kb.import': _e(
        'Import a supported saved advisory document.',
        'Add local source material to the investigation.',
        'Validates the chosen document without fetching other files.',
        'The selected local CVRF or CSAF document and supported parser dialect.'),

    'kb.plan_network': _e(
        'Prepare an explicit network-search plan.',
        'Inspect requests and limits before deciding whether to retrieve documents.',
        'Lists URLs, hosts, caps, and a plan digest without contacting them.',
        'The selected finite scope and supported source adapter.'),

    'kb.network_scope': _e(
        'Read the finite advisory-document scope for the request plan.',
        'Keep retrieval coverage explicit.',
        'Defines requested months or documents without fetching them.',
        'The selected SearchScope and request-planning rules.'),

    'kb.network_plan': _e(
        'Read every request in the prepared advisory plan.',
        'Check destinations and reasons before approving network use.',
        'Displays the plan without issuing a request.',
        'The prepared request list, host set, limits, and plan digest.'),

    'kb.plan_copy': _e(
        'Copy the displayed request plan.',
        'Retain the exact retrieval instructions for review or another machine.',
        'Writes plain text to the clipboard without fetching documents.',
        'The displayed network plan.'),

    'kb.approve': _e(
        'Approve and execute the exact displayed network plan when E1 is available.',
        'Authorize only the reviewed destinations and requests.',
        'Starts consented retrieval after checking the current plan identity.',
        'The displayed request plan and explicit consent record.'),

    'kb.steps': _e(
        'Move between the six investigation steps.',
        'Keep source search, file selection, and code review distinct.',
        'Changes pages; later steps remain blocked until their prerequisites hold.',
        'The current investigation revision and workflow reducer.'),

    'kb.step.find': _e(
        'Review advisory documents and search coverage.',
        'Check what was actually searched before interpreting results.',
        'Shows the Find page.',
        'Imported source documents and coverage records.'),

    'kb.step.updates': _e(
        'Review product-scoped update associations.',
        'Distinguish remediation references, mentions, and disputes.',
        'Shows the Updates page without selecting a binary pair.',
        'The indexed KB-CVE edges and product scopes.'),

    'kb.step.files': _e(
        'Review component hints or enter a component filename.',
        'Identify a file to investigate when advisories do not name one.',
        'Shows the Files page without assuming every hint changed in the update.',
        'Component hints, their cited basis, and analyst-entered names.'),

    'kb.step.builds': _e(
        'Review or supply the older and newer component builds.',
        'Make pair identity and direction explicit.',
        'Shows local file inputs or available candidate tables.',
        'The selected product, component, and pair-proposal records.'),

    'kb.step.project': _e(
        'Review the selected pair and project-creation request.',
        'Check inputs and destination before creating a comparison project.',
        'Shows the summary or acquisition plan without starting comparison.',
        'The selected pair, available bytes, and project settings.'),

    'kb.step.leads': _e(
        'Review available comparison leads with advisory context.',
        'Inspect evidence after a compatible comparison is available.',
        'Shows retained leads without fetching data or running engines.',
        'The linked project, advisory context, and available analysis results.'),

    'kb.coverage': _e(
        'Read the checked documents, date span, and unreadable sources.',
        'Interpret search results only within their stated coverage.',
        'Displays what was checked and identifies material outside the search.',
        'The investigation Coverage records.'),

    'kb.docs_table': _e(
        'Review the advisory documents available to this investigation.',
        'Inspect source revisions and per-document coverage.',
        'Selection shows retained source information.',
        'The local source-document store and search scope.'),

    'kb.edges_table': _e(
        'Review KB, CVE, and product associations from retained documents.',
        'Keep each relationship attached to its documentary basis.',
        'Selection opens the associated context details.',
        'The indexed KbCveEdge records and source pointers.'),

    'kb.product_filter': _e(
        'Choose the product and architecture relevant to the selected files.',
        'Avoid applying associations from another product scope.',
        'Filters the investigation and records the explicit scope choice.',
        'Retained ProductScope records and source product identifiers.'),

    'kb.relation_filter': _e(
        'Filter associations by their recorded relation type.',
        'Separate remediation records from mentions and analyst assertions.',
        'Changes visible associations without rewriting source claims.',
        'The relation labels on indexed KB-CVE edges.'),

    'kb.text_filter': _e(
        'Filter the displayed update associations by text.',
        'Locate a row within the current product and relation scope.',
        'Changes visible rows without expanding advisory coverage.',
        'The loaded update-table display fields.'),

    'kb.cve_detail': _e(
        'Read the selected advisory context and its limitations.',
        'Inspect documentary statements before relating them to code.',
        'Displays retained context without assigning a changed function to the advisory.',
        'The selected CveCard, source pointers, and context report.'),

    'kb.mentions': _e(
        'Read identifiers mentioned without a remediation association.',
        'Keep textual mentions separate from product-specific update records.',
        'Displays the mention-only group.',
        'Advisory text matches and their source pointers.'),

    'kb.hints_table': _e(
        'Review candidate component filenames and their basis.',
        'Choose what to investigate without treating a hint as an observed file change.',
        'Selection exposes the hint tier, reasons, and cited sources.',
        'ComponentHint records and analyst input.'),

    'kb.file_name': _e(
        'Enter the component basename to investigate.',
        'Supply a filename when the advisory does not identify one.',
        'Validates the name without contacting an index.',
        'Your input and the component-filename validation contract.'),

    'kb.add_file': _e(
        'Add the validated filename to the investigation.',
        'Record an explicit component choice.',
        'Adds an analyst-supplied hint without asserting that the file changed.',
        'The entered basename and current investigation scope.'),

    'kb.builds_older': _e(
        'Review available older-build candidates.',
        'Choose a baseline explicitly rather than accepting the first listed row.',
        'Selection supplies a proposed older endpoint when supported.',
        'Available index BuildRow records and their source identities.'),

    'kb.builds_newer': _e(
        'Review available newer-build candidates.',
        'Choose the later endpoint explicitly.',
        'Selection supplies a proposed newer endpoint when supported.',
        'Available index BuildRow records and their source identities.'),

    'kb.older_file': _e(
        'Choose a local file for the older side.',
        'Use an existing complete component build without downloading it.',
        'Selects a local input for validation and pair review.',
        'The selected local file and its inspected identity.'),

    'kb.newer_file': _e(
        'Choose a local file for the newer side.',
        'Use an existing later component build without downloading it.',
        'Selects a local input for validation and pair review.',
        'The selected local file and its inspected identity.'),

    'kb.older_browse': _e(
        'Browse for the older local binary.',
        'Select the baseline file without typing its path.',
        'Fills the older-file field without creating a project.',
        'The local file selected in the picker.'),

    'kb.newer_browse': _e(
        'Browse for the newer local binary.',
        'Select the later file without typing its path.',
        'Fills the newer-file field without creating a project.',
        'The local file selected in the picker.'),

    'kb.swap': _e(
        'Exchange the proposed older and newer endpoints.',
        'Correct direction before approving the pair.',
        'Updates the proposal and rechecks affected workflow prerequisites.',
        'The selected pair endpoints and investigation state.'),

    'kb.pair_summary': _e(
        'Read the pair grade, update window, and unresolved reasons.',
        'Check identity, lineage, and fix-boundary evidence separately.',
        'Displays the proposal without approving or downloading it.',
        'The PairProposal and its cited index or local-file observations.'),

    'kb.confirm_component': _e(
        'Assert that differently named inputs represent the same component.',
        'Make the required name-mismatch decision explicit.',
        'Records your assertion; it does not establish lineage or a fix boundary.',
        'Your explicit confirmation and selected artifact identities.'),

    'kb.project_name': _e(
        'Enter the name for the comparison project.',
        'Identify the investigation in the project workspace.',
        'Sets the requested title without creating the project.',
        'Your entered project name.'),

    'kb.project_root': _e(
        'Choose the destination for the new comparison project.',
        'Keep the generated project separate from existing work.',
        'Sets a destination subject to the project-creation checks.',
        'Your selected local path and destination policy.'),

    'kb.project_browse': _e(
        'Browse for the new project destination.',
        'Choose a local location without typing its path.',
        'Fills the destination field without writing project data.',
        'The selected directory and project destination rules.'),

    'kb.create': _e(
        'Create a project from the approved complete binary pair.',
        'Prepare the selected inputs for ordinary comparison.',
        'Validates both final files before project creation; analysis remains a separate operation.',
        'The approved pair, final artifact identities, and project settings.'),

    'kb.acquire_plan': _e(
        'Read the exact acquisition requests for the selected pair.',
        'Inspect URLs, expected bytes, and destination before downloading.',
        'Displays the plan without making a network request.',
        'The PairPlan, expected hashes and sizes, and selected endpoints.'),

    'kb.retry_attach': _e(
        'Retry attaching advisory context to the already created project.',
        'Recover context linkage without recreating the binary pair.',
        'Updates the attachment through the supported local workflow.',
        'The existing project and retained investigation revision.'),

    'kb.leads_table': _e(
        'Review available component or function leads.',
        'Inspect the cited channels before assigning meaning to a code change.',
        'Selection opens the retained explanation and provenance.',
        'The linked comparison results and advisory-context adapters.'),

    'kb.group_filter': _e(
        'Choose a CVE group, unattributed leads, or non-applicable context.',
        'Keep separately scoped investigative material distinguishable.',
        'Changes visible lead groups without changing engine output.',
        'The context report and derived lead-group records.'),

    'kb.lead_detail': _e(
        'Read supporting, conflicting, and unknown context for the selected lead.',
        'Check each source before following a code location.',
        'Displays retained explanation without running analysis.',
        'The selected LeadRow and its referenced evidence.'),

    'kb.goto': _e(
        'Open the selected lead at its available current comparison location.',
        'Inspect the code behind the lead.',
        'Checks project revision and run before navigating; stale context does not jump.',
        'The lead navigation reference and current project identities.'),

    'kb.copy': _e(
        'Copy the selected investigation provenance.',
        'Retain source pointers and unresolved checks in research notes.',
        'Writes bounded plain text to the clipboard, up to 16 KiB.',
        'The selected association, pair, context, or lead record.'),

    'kb.refresh': _e(
        'Reload or recompute the local context view from retained records.',
        'Bring displayed investigation material up to date.',
        'Uses local stored inputs without fetching sources or running comparison engines.',
        'The current investigation, linked project, and available derived results.'),

    'kb.stale_banner': _e(
        'Read why this context describes earlier inputs or an advisory revision.',
        'Keep historical context separate from the current comparison.',
        'Shows the reason and disables stale-context navigation.',
        'The ProjectLink and recorded source identities.'),

    'kb.cancel': _e(
        'Request cancellation of the active investigation operation.',
        'Stop work that is no longer needed.',
        'Stops through the operation lifecycle; an in-flight request can delay completion.',
        'The current attempt and its operation-specific cancellation state.'),

    'kb.status': _e(
        'Read investigation progress, coverage, and outcome.',
        'Distinguish pending work from a completed local lookup.',
        'Displays lifecycle feedback without starting another step.',
        'The current investigation revision and operation result.'),

    'kb.retry': _e(
        'Retry the failed investigation step.',
        'Repeat work after addressing its reported cause.',
        'Uses the supported step workflow; network work still requires current consent.',
        'The retained attempt and applicable request plan.'),

    'kb.copy_error': _e(
        'Copy investigation error details.',
        'Preserve the code and available explanation for diagnosis.',
        'Writes plain-text diagnostics to the clipboard.',
        'The retained operation issue and failure record.'),

    # Update-table headers.

    'kb.col.kb': _e(
        'Read the KB identifier associated with this record.',
        'Keep the update reference explicit.',
        'Displays the retained identifier without selecting a binary.',
        'The indexed edge and its source pointer.'),

    'kb.col.cve': _e(
        'Read the CVE identifier associated with this record.',
        'Identify the advisory context for the row.',
        'Displays the reference without attributing a changed function.',
        'The indexed edge and source advisory.'),

    'kb.col.product': _e(
        'Read the product scope attached to this association.',
        'Check applicability before choosing files.',
        'Displays the retained product label and available mapping basis.',
        'Source product identifiers and ProductScope records.'),

    'kb.col.architecture': _e(
        'Read the architecture recorded for the product or build.',
        'Avoid selecting incompatible analysis inputs.',
        'Displays the recorded architecture; binary validation remains separate.',
        'The product scope or inspected binary machine field.'),

    'kb.col.relation': _e(
        'Read how the source connects the update and advisory identifier.',
        'Distinguish remediation, reference, mention, and assertion.',
        'Displays the relation label without strengthening its documentary basis.',
        'The KbCveEdge relation and cited source location.'),

    'kb.col.vendor_build': _e(
        'Read the build number stated by the vendor when available.',
        'Inspect the documentary basis for a proposed update boundary.',
        'Displays the source statement without treating it as downloaded-byte identity.',
        'The retained fixed_build field and source pointer.'),

    'kb.col.source': _e(
        'Read the document and location supporting this association.',
        'Trace the row to retained evidence.',
        'Displays the source reference without contacting its origin.',
        'The SourceDoc identity and SourceRef pointer.'),

    'kb.col.kev': _e(
        'Read CISA KEV membership from the loaded catalog context.',
        'Keep dated catalog information separate from function evidence.',
        'Displays retained catalog status without changing function ranking.',
        'The available local KEV lookup and snapshot identity.'),

    # Component-hint fields.

    'kb.hint.name': _e(
        'Read the candidate component basename.',
        'Identify the file proposed for investigation.',
        'Displays the validated name without asserting a changed file.',
        'The ComponentHint record and cited origin.'),

    'kb.hint.tier': _e(
        'Read the documented source tier for this filename hint.',
        'Inspect how the candidate name entered the investigation.',
        'Displays the tier with its reasons; it is not an accuracy measurement.',
        'The ComponentHint tier and source references.'),

    'kb.hint.changed': _e(
        'Read whether retained evidence states that this file changed in the update.',
        'Distinguish Yes, No, and Unknown.',
        'Displays the supported state without filling a documentary gap.',
        'The hint changed_in_kb field and cited claims.'),

    'kb.hint.basis': _e(
        'Read the sources and reasons behind the filename hint.',
        'Check the candidate before selecting builds.',
        'Displays retained claim references without fetching more data.',
        'The ComponentHint reasons and SourceRef records.'),

    # Build-candidate fields.

    'kb.build.version': _e(
        'Read the version metadata associated with a build candidate.',
        'Distinguish candidate rows before assigning orientation.',
        'Displays retained metadata without proving chronology.',
        'The BuildRow and source index record.'),

    'kb.build.hash': _e(
        'Read the candidate SHA-256 identity.',
        'Check the expected bytes before acquisition or local validation.',
        'Displays the index or local identity without authenticating its publisher.',
        'The index record or inspected local binary.'),

    'kb.build.release': _e(
        'Read the release metadata recorded for this candidate.',
        'Inspect chronology with its source limitations.',
        'Displays the recorded date and release context.',
        'The source BuildRow fields.'),

    'kb.build.availability': _e(
        'Read whether complete bytes are local, directly available, or unavailable.',
        'Check whether a proposed endpoint can become an accepted PE input.',
        'Displays availability without reconstructing a delta payload.',
        'The BinaryRef availability and supported acquisition adapters.'),

    'kb.build.shared': _e(
        'Read other update references associated with these indexed bytes.',
        'Recognize when one build appears in several update records.',
        'Displays the retained sharing context without choosing a fix boundary.',
        'The BuildRow shared_with metadata.'),

    # Documentary relation labels.

    'kb.relation.remediation': _e(
        'The source records a product-specific vendor remediation association.',
        'Distinguish the structured relation from an advisory mention.',
        'Displays the source relation without locating its implementation in code.',
        'The parsed MSRC CVRF record and product-specific pointer.'),

    'kb.relation.association': _e(
        'A retained advisory detail or URL associates this KB with the record.',
        'Keep a vendor reference distinct from a structured remediation field.',
        'Displays Vendor reference with its original source basis.',
        'The CSAF text or support URL and product references.'),

    'kb.relation.mention': _e(
        'The identifier is mentioned in advisory text only.',
        'Avoid treating a textual mention as a remediation association.',
        'Displays Mentioned only.',
        'The advisory text match and source pointer.'),

    'kb.relation.package': _e(
        'The retained package evidence records a containment relationship.',
        'Keep package membership separate from a function-level change.',
        'Displays the supported relation without expanding its meaning.',
        'The package-contains edge and its source reference.'),

    'kb.relation.asserted': _e(
        'This association was entered by the analyst.',
        'Keep analyst input distinguishable from vendor records.',
        'Displays Entered by you with its retained provenance.',
        'The analyst assertion and associated decision record.'),

    'kb.relation.disputed': _e(
        'Retained source statements disagree about this association.',
        'Inspect the conflicting revisions or scope statements.',
        'Displays the dispute without silently selecting a stronger claim.',
        'The edge conflict references and source revisions.'),

    # Coverage states.

    'kb.coverage.complete': _e(
        'All requested documents in the stated nonempty scope were inspected.',
        'Limit the completed-search claim to that exact population.',
        'Displays complete-in-scope coverage, not complete historical coverage.',
        'Requested and inspected document identities with no failed entries.'),

    'kb.coverage.partial': _e(
        'Some requested documents were not successfully inspected.',
        'Keep an incomplete lookup distinct from a complete negative result.',
        'Displays failed or unavailable sources alongside the checked population.',
        'The Coverage requested, inspected, failed, and unfetchable records.'),

    'kb.coverage.stale': _e(
        'The lookup relies on retained coverage marked stale.',
        'Inspect source age and revisions before reusing the result.',
        'Displays the limitation without silently fetching updates.',
        'The coverage snapshot and revision watermark.'),

    'kb.coverage.unknown': _e(
        'The searched source population is not established.',
        'Avoid making an absence claim without a defined scope.',
        'Requests an explicit supported scope.',
        'The investigation scope and coverage validation.'),

    'kb.coverage.not_searched': _e(
        'No advisory documents have been searched for this request.',
        'Distinguish missing work from no matching associations.',
        'Displays Not searched and the next preparation step.',
        'The current investigation and coverage inventory.'),

    # Pair axes and grades.

    'kb.pair.bytes': _e(
        'Read whether both proposed binary endpoints have completed byte checks.',
        'Keep accepted bytes separate from pending metadata candidates.',
        'Displays the recorded byte state.',
        'Final artifact hashes, sizes, format checks, and PairProposal state.'),

    'kb.pair.lineage': _e(
        'Read the proposed relationship between the component builds.',
        'Distinguish index adjacency, branch compatibility, and analyst assertion.',
        'Displays the lineage basis without establishing the fix boundary.',
        'The PairProposal lineage state and cited build records.'),

    'kb.pair.boundary': _e(
        'Read the evidence for the proposed remediation boundary.',
        'Keep source-supported, unresolved, and contradicted boundaries distinct.',
        'Displays the boundary state without attributing a changed function.',
        'The vendor-stated build, selected endpoints, and boundary checks.'),

    'kb.pair.window': _e(
        'Read the updates recorded between the selected builds.',
        'Identify other updates that can explain comparison changes.',
        'Displays the available window and its completeness state.',
        'The PairProposal window and retained update records.'),

    'kb.grade.a': _e(
        'The proposal meets the documented index-adjacent grade rules.',
        'Inspect the strongest available index-based selection basis.',
        'Displays Grade A; bytes can still be pending and the fix boundary can remain unresolved.',
        'Same-version-key predecessor selection and the recorded pair checks.'),

    'kb.grade.b': _e(
        'The proposal uses the documented alternative lineage basis.',
        'Keep asserted or branch-compatible selection limits visible.',
        'Displays Grade B with its byte checks and qualifying reasons.',
        'The pair lineage, update window, and grade policy.'),

    'kb.grade.x': _e(
        'A hard pair-selection block prevents the proposed operation.',
        'Identify the condition requiring a different input or supported confirmation.',
        'Displays Grade X and its reasons.',
        'The pair validation and blocking policy.'),

    # Pair reasons.

    'kb.reason.identical': _e(
        'The two selected files are byte-identical.',
        'Avoid expecting a changed component from identical bytes.',
        'Displays the identical-content reason.',
        'The selected endpoint SHA-256 identities.'),

    'kb.reason.delta_only': _e(
        'Only a delta payload is available for this endpoint.',
        'Identify why a complete PE input is still required.',
        'Blocks use of the payload as a complete binary.',
        'The inspected payload type and acquisition availability.'),

    'kb.reason.architecture': _e(
        'The proposed input does not meet the AMD64 PE requirement.',
        'Keep unsupported architecture outside this comparison contract.',
        'Blocks the incompatible endpoint.',
        'The parsed binary machine field and input policy.'),

    'kb.reason.cross_product': _e(
        'The proposed endpoints belong to different product scopes.',
        'Avoid automatic comparison across incompatible product selection.',
        'Blocks automatic pairing and displays the scope difference.',
        'The two ProductScope identities and pairing rules.'),

    'kb.reason.order_unknown': _e(
        'The retained evidence does not establish release order.',
        'Make older and newer an explicit analyst decision.',
        'Displays the unresolved order and offers the supported orientation choice.',
        'The build metadata and ordering checks.'),

    'kb.reason.digest_mismatch': _e(
        'The acquired file does not match the expected SHA-256.',
        'Prevent unrelated bytes from entering the proposed project.',
        'Rejects the endpoint and does not create the project.',
        'The expected index identity and downloaded-byte hash.'),

    'kb.reason.no_older': _e(
        'No earlier candidate is listed for this component and product.',
        'Identify the missing endpoint without assuming it never existed.',
        'Requests a supported local input or another documented search scope.',
        'The inspected index population and selected product scope.'),

    'kb.reason.no_newer': _e(
        'No later candidate is available in the inspected scope.',
        'Identify the missing endpoint without claiming complete history.',
        'Keeps pair approval unavailable until a supported newer input exists.',
        'The current candidate population and pair prerequisites.'),

    'kb.reason.window_confounded': _e(
        'Other updates occur within the selected build window.',
        'Keep several possible causes of a code difference visible.',
        'Displays the update-window limitation without assigning the change to one KB.',
        'The pair window and available update records.'),

    'kb.reason.server_coverage': _e(
        'The selected file index does not cover the requested Server-only population.',
        'Distinguish source coverage limits from missing historical builds.',
        'Displays the index limitation and retains manual-input options.',
        'The documented index product coverage.'),

    'kb.reason.name_mismatch': _e(
        'The selected files have different basenames.',
        'Require an explicit same-component assertion before continuing.',
        'Blocks the affected step until its supported confirmation is recorded.',
        'The endpoint basenames and component-validation policy.'),

    'kb.reason.index_gap': _e(
        'The inspected index contains a gap relevant to this pair.',
        'Keep incomplete lineage evidence visible.',
        'Displays the gap without treating adjacency as established.',
        'The candidate index records and lineage checks.'),

    # Context and lead fields.

    'kb.context.cwe': _e(
        'Read the retained weakness-class context and its origin.',
        'Distinguish a vendor-stated class from a derived interpretation.',
        'Displays the class with its source basis.',
        'The advisory facts and context-classification record.'),

    'kb.context.hypothesis': _e(
        'Read a rule-derived expected-change hypothesis.',
        'Choose code observations to inspect without treating the hypothesis as evidence.',
        'Displays investigative guidance without executing verification steps.',
        'The retained advisory context and versioned hypothesis rules.'),

    'kb.context.applicability': _e(
        'Read how the advisory context relates to the selected product and builds.',
        'Inspect unsupported, conflicting, or asserted applicability.',
        'Displays the assessment and unresolved checks.',
        'Product-scoped advisory facts and selected binary identities.'),

    'kb.context.unknowns': _e(
        'Read checks that could not be completed for this context.',
        'Keep documentary gaps visible during code review.',
        'Displays unknowns without converting them into negative results.',
        'The ContextReport coverage and limitations.'),

    'kb.lead.group': _e(
        'Read the advisory group associated with this lead.',
        'Keep attributed, unattributed, and non-applicable material separate.',
        'Displays the retained group without changing engine ranking.',
        'The LeadRow group and selected context report.'),

    'kb.lead.channels': _e(
        'Read the separate evidence-channel states for this lead.',
        'Inspect documentary, identity, code, and anchor context individually.',
        'Displays each channel without averaging or scoring their states.',
        'The lead chips and their source references.'),

    'kb.lead.order': _e(
        'Read why the lead appears in its current reading position.',
        'Inspect the ordering basis alongside the cited evidence.',
        'Displays the retained explanation without establishing attribution.',
        'The LeadRow rank_basis and referenced analysis adapters.'),

    # Panel states KB0-KB17.

    'kb.state.no_lead': _e(
        'Enter a KB number or CVE ID to begin the local lookup.',
        'Identify the investigation target explicitly.',
        'Shows entry guidance without searching or fetching.',
        'The current empty lead field.'),

    'kb.state.no_documents': _e(
        'No advisory documents are loaded for this lookup.',
        'Distinguish an unsearched request from no associations.',
        'Offers local import or request planning.',
        'The source-document inventory.'),

    'kb.state.searching': _e(
        'The local advisory index is being searched.',
        'Distinguish pending results from missing associations.',
        'Shows activity and the available cancellation action.',
        'The active local lookup.'),

    'kb.state.found': _e(
        'The lookup found associations within the checked documents.',
        'Read the results alongside their exact coverage.',
        'Displays the checked population and unreadable-document count.',
        'The lookup response and Coverage records.'),

    'kb.state.not_found_complete': _e(
        'The lead was not observed in the completed stated scope.',
        'Keep documentary absence limited to the checked files.',
        'Displays the searched population without claiming complete historical absence.',
        'The completed local lookup and document identities.'),

    'kb.state.not_found_partial': _e(
        'The lead was not observed, but the requested search is incomplete.',
        'Avoid treating failed documents as a complete negative result.',
        'Displays unreadable or missing sources alongside the outcome.',
        'The partial Coverage record.'),

    'kb.state.choose_product': _e(
        'Several product scopes are associated with the lookup.',
        'Choose the product and architecture relevant to the files.',
        'Requires an explicit scope selection before affected later steps.',
        'The indexed product-specific associations.'),

    'kb.state.need_filename': _e(
        'The retained advisory does not identify the component filename.',
        'Avoid inventing an exact binary from general advisory context.',
        'Requests a basename or supported local pair.',
        'The advisory facts and component-hint inventory.'),

    'kb.state.not_applicable': _e(
        'The retained product context does not apply to the selected scope.',
        'Keep other-product associations out of this lead group.',
        'Displays the reason and preserves the documentary record.',
        'The product-scoped advisory facts and applicability checks.'),

    'kb.state.pair_blocked': _e(
        'The proposed pair does not meet a workflow prerequisite.',
        'Inspect the specific reason before creating a project.',
        'Keeps creation unavailable and shows the blocking condition.',
        'The PairProposal and current reducer state.'),

    'kb.state.review_plan': _e(
        'Review the exact acquisition requests before downloading.',
        'Approve destinations, expected bytes, and limits explicitly.',
        'Shows the plan without executing it.',
        'The prepared PairPlan.'),

    'kb.state.acquiring': _e(
        'The approved acquisition operation is running.',
        'Follow the displayed endpoint and received-byte progress.',
        'Retrieves only the approved plan through the supported transport.',
        'The active consented acquisition attempt.'),

    'kb.state.context_pending': _e(
        'The project exists, but advisory attachment has not completed.',
        'Recover context linkage without discarding the created project.',
        'Offers Retry attach while preserving the project.',
        'The ProjectLink context-pending state.'),

    'kb.state.context_attached': _e(
        'Advisory context is attached to the project.',
        'Review vendor statements and unresolved checks beside the comparison.',
        'Enables context review without assigning a function to an advisory.',
        'The attached investigation revision and project link.'),

    'kb.state.stale': _e(
        'This context describes another pair, run, or advisory revision.',
        'Keep historical context distinct from current code.',
        'Retains reference content and disables its navigation.',
        'The attachment identities and stale-reason checks.'),

    'kb.state.error': _e(
        'The investigation step could not complete.',
        'Inspect its error before repeating the operation.',
        'Shows the issue while preserving the last committed investigation state.',
        'The operation issue and retained attempt record.'),

    'kb.state.unsupported': _e(
        'This step is unavailable in the current build or environment.',
        'Keep a missing capability distinct from an empty result.',
        'Displays the restriction while preserving supported metadata and manual routes.',
        'The workflow capability checks.'),

    'kb.state.no_attachment': _e(
        'The open project has no attached advisory investigation.',
        'Keep code-only comparison separate from documentary context.',
        'Offers a local KB or CVE lookup before attachment.',
        'The project attachment inventory.'),

    'kb.state.cancelling': _e(
        'The investigation operation is stopping.',
        'Distinguish a cancellation request from completed shutdown.',
        'Waits for the supported operation boundary before final status.',
        'The active attempt and transport lifecycle.'),

    'kb.state.cancelled': _e(
        'The investigation attempt was cancelled.',
        'Keep interrupted work distinct from a completed lookup or acquisition.',
        'Returns to the previous committed snapshot and records the attempt.',
        'The workflow reducer and cancellation outcome.'),
}


KB_TOOLTIP_TEMPLATES = {
    'kb.row': _e(
        'Investigation association for {identifier}.',
        'Inspect relation, product scope, and source before selecting files.',
        'Select for retained context and coverage.',
        'Relation: {relation}. Product: {product}. Source: {source}. Pointer: {pointer}.'),

    'kb.document': _e(
        'Retained advisory document: {document}.',
        'Inspect revision and inspection status before relying on coverage.',
        'Displays stored source information without contacting its origin.',
        'Digest: {digest}. Revision: {revision}. State: {state}. Origin: {origin}.'),

    'kb.coverage_summary': _e(
        'Coverage of this advisory lookup.',
        'Keep the result bounded by the checked source population.',
        'Reports inspected and failed documents without implying complete history.',
        'Requested: {requested}. Checked: {checked}. Failed: {failed}. Scope: {scope}.'),

    'kb.component': _e(
        'Candidate component: {name}.',
        'Inspect the hint basis before choosing builds.',
        'Selects an investigation candidate without asserting a file change.',
        'Tier: {tier}. Changed in update: {changed}. Basis: {basis}.'),

    'kb.build': _e(
        'Candidate component build.',
        'Check product, identity, and availability before assigning a side.',
        'Selects a proposal endpoint without downloading automatically.',
        'Version: {version}. SHA-256: {sha256}. Product: {product}. Availability: {availability}.'),

    'kb.pair': _e(
        'Proposed older and newer component pair.',
        'Inspect byte identity, lineage, and boundary evidence separately.',
        'Displays the proposal without approving acquisition or comparison.',
        'Grade: {grade}. Bytes: {bytes_state}. Lineage: {lineage}. Boundary: {boundary}.'),

    'kb.request': _e(
        'Request in the displayed network plan.',
        'Check the destination and purpose before approval.',
        'No request runs until the matching current plan is approved.',
        'Method: {method}. URL: {url}. Expected bytes: {size}. Reason: {reason}.'),

    'kb.lead_row': _e(
        'Comparison lead: {subject}.',
        'Inspect the separate channels and limitations before following code.',
        'Selects the lead; navigation requires matching current project identities.',
        'Group: {group}. Basis: {basis}. Run: {run}. State: {state}.'),

    'kb.channel': _e(
        'Investigation channel: {channel}.',
        'Keep support, conflict, and missing evidence distinguishable.',
        'Displays the individual channel state without combining measurements.',
        'State: {state}. Reference: {reference}. Details: {details}.'),

    'kb.reason': _e(
        'Pair-selection reason: {code}.',
        'Inspect the condition before approving the proposed endpoints.',
        'Displays the documented limitation or required explicit decision.',
        'Details: {details}. Basis: {basis}.'),

    'kb.stale_reason': _e(
        'The attached investigation describes earlier inputs.',
        'Identify the changed source before reusing context.',
        'Retains reference content and disables stale navigation.',
        'Recorded input comparison: {reason}.'),
}
