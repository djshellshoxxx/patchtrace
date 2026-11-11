"""Proposed KEV panel tooltip copy.

PLANNED: follows the KEV integration plan.
The panel declaration was unavailable during review.
Implemented behavior, live source compatibility, and packaged availability
are UNVERIFIED.

Sources:
- docs/specs/program-e/KEV-integration-plan.md, sections 7-8
- src/patchtrace/panel_manifest.py

Catalog membership is dated documentary context.
It does not identify affected builds, files, functions, or a code-change purpose.
Catalog retrieval does not send project data or the queried CVE identifiers.

Consent uses an inline page. Source selection does not start a request.
Local import and lookup remain separate from network updates.
The source plan must supply actual URLs and response-size hints at runtime.

Additional IDs require bindings to documented controls, fields, and states.
Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


KEV_TOOLTIPS = {
    'kev.dock': _e(
        'Read dated CISA KEV catalog context for the selected CVE identifiers.',
        'Keep catalog information beside the investigation without assigning it to code.',
        'Shows local context; opening the panel downloads nothing.',
        'The loaded snapshot and lookup metadata; CISA KEV catalog, CC0 1.0.'),

    'kev.action': _e(
        'Show or hide the CISA KEV context panel.',
        'Keep the catalog lookup available during review.',
        'Toggles the dock; shortcut Ctrl+Shift+X.',
        'The planned panel command and central manifest.'),

    'kev.update': _e(
        'Review a request to download a KEV catalog.',
        'Check the exact source and transmission before approving an update.',
        'Opens inline consent; it does not start the download.',
        'The prepared local request plan and selected supported source.'),

    'kev.import': _e(
        'Load a saved KEV JSON catalog from this computer.',
        'Use retained catalog information without a network request.',
        'Validates the chosen file; CSV is not supported by this workflow.',
        'The selected local document; CISA KEV catalog, CC0 1.0.'),

    'kev.changes': _e(
        'Compare the current catalog with the previous retained snapshot.',
        'Inspect additions, removals, and supported field changes.',
        'Shows a read-only comparison when two snapshots are available.',
        'Retained snapshot differences; CISA KEV catalog, CC0 1.0.'),

    'kev.copy': _e(
        'Copy the selected CVE catalog details and provenance.',
        'Retain the exact snapshot context in research notes.',
        'Writes plain text to the clipboard without contacting a source.',
        'The selected lookup and snapshot metadata; CISA KEV catalog, CC0 1.0.'),

    'kev.copy_url': _e(
        'Copy the address of the CISA KEV catalog page.',
        'Retain the reference without opening a browser automatically.',
        'Writes the configured page address to the clipboard only.',
        'The panel source-reference configuration.'),

    'kev.lookup_box': _e(
        'Enter CVE identifiers to look up in the loaded catalog.',
        'Define the local lookup population explicitly.',
        'Validates input for lookup; entering text sends nothing to CISA.',
        'Your entered identifiers and the supported CVE grammar.'),

    'kev.lookup_button': _e(
        'Look up the entered identifiers in the local catalog.',
        'Read membership within a specific retained snapshot.',
        'Performs a local lookup without downloading updates.',
        'The loaded snapshot; CISA KEV catalog, CC0 1.0.'),

    'kev.filter': _e(
        'Choose which KEV lookup states appear in the table.',
        'Separate listed identifiers from unlisted or unavailable lookups.',
        'Changes visible rows without changing function rankings.',
        'The local lookup results; CISA KEV catalog, CC0 1.0.'),

    'kev.filter.all': _e(
        'Show all identifiers in the current lookup population.',
        'Review listed, unlisted, and unresolved states together.',
        'Removes the membership display restriction.',
        'The current local lookup results; CISA KEV catalog, CC0 1.0.'),

    'kev.filter.listed': _e(
        'Show identifiers listed in the loaded catalog.',
        'Focus on recorded catalog entries.',
        'Filters the table without changing comparison evidence.',
        'Membership in the loaded snapshot; CISA KEV catalog, CC0 1.0.'),

    'kev.filter.ransomware_known': _e(
        'Show listed entries whose ransomware-use field is Known.',
        'Inspect that specific CISA-reported field.',
        'Filters rows without changing code rankings or pairing decisions.',
        'The retained ransomware-use field; CISA KEV catalog, CC0 1.0.'),

    'kev.filter.not_listed': _e(
        'Show identifiers absent from the loaded snapshot.',
        'Inspect catalog absence together with snapshot age.',
        'Filters the table without treating absence as a broader negative result.',
        'Membership in the loaded snapshot; CISA KEV catalog, CC0 1.0.'),

    'kev.filter.unavailable': _e(
        'Show lookups lacking a catalog or containing an invalid identifier.',
        'Identify entries that did not receive a usable membership assessment.',
        'Filters unresolved lookup states.',
        'Identifier validation and local catalog availability.'),

    'kev.sort': _e(
        'Choose input order or KEV-listed-first reading order.',
        'Organize the lookup without treating membership as a score.',
        'Changes table order only; function rankings are unaffected.',
        'The local lookup population; CISA KEV catalog, CC0 1.0.'),

    'kev.sort.input': _e(
        'Keep identifiers in their supplied input order.',
        'Preserve the investigation list sequence.',
        'Changes presentation without changing membership results.',
        'The lookup request ordering.'),

    'kev.sort.listed_first': _e(
        'Place listed identifiers before the remaining lookup states.',
        'Read catalog entries first while preserving input order within each group.',
        'Changes reading order without assigning a numeric rank to functions.',
        'The local lookup results; CISA KEV catalog, CC0 1.0.'),

    'kev.table': _e(
        'Read membership, dates, and ransomware-use fields for each identifier.',
        'Inspect catalog facts alongside their snapshot context.',
        'Selection opens details; Enter follows the supported identifier context.',
        'The local lookup results; CISA KEV catalog, CC0 1.0.'),

    'kev.detail': _e(
        'Read retained CISA wording and provenance for the selected identifier.',
        'Check the original fields and their limits before recording a conclusion.',
        'Displays plain text without opening links or running analysis.',
        'The selected entry and snapshot metadata; CISA KEV catalog, CC0 1.0.'),

    'kev.goto': _e(
        'Show the selected identifier in the linked patch-intelligence view.',
        'Continue investigation using available comparison context.',
        'Navigates only when a linked comparison is available.',
        'The selected identifier and current project-context links.'),

    'kev.status': _e(
        'Read catalog version, source, retrieval information, and current operation state.',
        'Identify which snapshot supports the lookup.',
        'Displays local status without starting an update.',
        'Snapshot metadata and lifecycle records; CISA KEV catalog, CC0 1.0.'),

    'kev.freshness': _e(
        'Read catalog age and freshness limitations.',
        'Check whether later catalog changes may be missing.',
        'Displays the age category without fetching a newer catalog.',
        'Release time and the local clock; CISA KEV catalog, CC0 1.0.'),

    'kev.footer': _e(
        'Read the scope limits of KEV context.',
        'Keep CVE-level catalog information separate from code localization.',
        'Displays persistent interpretation and source-attribution guidance.',
        'The panel interpretation contract; CISA KEV catalog, CC0 1.0.'),

    # Inline update consent.

    'kev.consent': _e(
        'Review the exact KEV catalog download request.',
        'Inspect the destination, transmitted fields, and response limit.',
        'Shows an inline approval page without sending the request.',
        'The prepared KevPlan and current source selection.'),

    'kev.source_cisa': _e(
        'Select the supported CISA website source.',
        'Choose the destination before reviewing and approving its request.',
        'Updates the displayed plan without contacting the site.',
        'The configured website-source adapter; live availability is UNVERIFIED.'),

    'kev.source_mirror': _e(
        'Select the supported CISA GitHub-copy source.',
        'Choose the alternative destination explicitly.',
        'Updates the displayed plan without contacting the host.',
        'The configured CISA repository-source adapter.'),

    'kev.consent_request': _e(
        'Read the request method and complete URL.',
        'Check the exact destination covered by approval.',
        'Displays the prepared request without issuing it.',
        'The selected source and current KevPlan.'),

    'kev.consent_sent': _e(
        'Read which request fields leave this computer.',
        'Distinguish catalog retrieval from transmission of investigation data.',
        'Shows the address and fixed headers; project data and CVE queries are not sent.',
        'The operation-specific KEV transport contract.'),

    'kev.consent_received': _e(
        'Read the expected response and enforced size limit.',
        'Inspect retrieval cost before approving the request.',
        'Displays a size hint separately from the 16 MiB maximum.',
        'The request plan response hint and configured transport ceiling.'),

    'kev.consent_download': _e(
        'Approve and send the displayed catalog request.',
        'Authorize this specific retrieval operation.',
        'Downloads the reviewed source and checks it before replacing the current catalog.',
        'The current request plan and operation-specific consent.'),

    'kev.consent_cancel': _e(
        'Close the request review without downloading.',
        'Return to local catalog review.',
        'Cancels the pending approval without contacting the source.',
        'The inline consent state.'),

    'kev.cancel_download': _e(
        'Request cancellation of the active catalog download.',
        'Stop an update that is no longer needed.',
        'Stops through the transport lifecycle without replacing the current snapshot.',
        'The active download operation and cancellation state.'),

    'kev.progress': _e(
        'Read the source host and received-byte progress.',
        'Follow retrieval without assuming the size hint is exact.',
        'Displays operation progress while the catalog is downloaded and checked.',
        'The active transport operation and response-byte count.'),

    'kev.retry': _e(
        'Retry the failed catalog operation through its supported approval path.',
        'Repeat work after addressing the reported cause.',
        'Prepares another attempt; network retrieval requires operation-specific consent.',
        'The retained failure and current request plan.'),

    'kev.copy_error': _e(
        'Copy catalog-operation failure details.',
        'Preserve the code and available explanation for diagnosis.',
        'Writes plain-text diagnostics to the clipboard.',
        'The retained KEV operation error.'),

    'kev.replace_anyway': _e(
        'Explicitly accept a checked catalog containing fewer entries.',
        'Review an unexpected catalog shrink before replacing the current snapshot.',
        'Overrides only the shrink decision; other validation and older-release checks remain.',
        'The checked candidate snapshot and shrink-policy result.'),

    # Column headers.

    'kev.col.cve': _e(
        'Read the identifier used for this catalog lookup.',
        'Keep each membership result attached to its requested record.',
        'Displays the normalized identifier or invalid-input state.',
        'The local lookup request and identifier validation.'),

    'kev.col.membership': _e(
        'Read membership in the loaded KEV snapshot.',
        'Distinguish Listed, Not listed, No catalog, and Invalid ID.',
        'Displays a dated catalog result without assigning it to a function.',
        'The loaded snapshot lookup; CISA KEV catalog, CC0 1.0.'),

    'kev.col.added': _e(
        'Read the date CISA added this entry to the catalog.',
        'Separate catalog addition from activity onset or update release dates.',
        'Displays the retained dateAdded field.',
        'The selected entry; CISA KEV catalog, CC0 1.0.'),

    'kev.col.due': _e(
        'Read the due date stated by CISA for its required action.',
        'Keep the catalog directive date separate from vendor release dates.',
        'Displays the CISA date without determining which obligations apply to you.',
        'The selected entry dueDate field; CISA KEV catalog, CC0 1.0.'),

    'kev.col.ransomware': _e(
        'Read CISA reported ransomware-campaign-use information.',
        'Keep Known and Unknown meanings distinct.',
        'Displays the retained field without converting Unknown to No.',
        'The selected entry ransomware-use field; CISA KEV catalog, CC0 1.0.'),

    # Membership badges and cells.

    'kev.membership.listed': _e(
        'This identifier appears in the loaded KEV snapshot.',
        'Inspect the retained entry and catalog date.',
        'Displays Listed without attributing a build, file, or function.',
        'Membership in the selected snapshot; CISA KEV catalog, CC0 1.0.'),

    'kev.membership.listed_ransomware': _e(
        'This listed entry has ransomware use recorded as Known.',
        'Inspect the specific field together with the catalog provenance.',
        'Displays the combined catalog label without changing function order.',
        'Membership and ransomware-use fields; CISA KEV catalog, CC0 1.0.'),

    'kev.membership.not_listed': _e(
        'This identifier does not appear in the loaded snapshot.',
        'Read catalog absence alongside coverage and age.',
        'Displays Not listed; this is not a conclusion about activity outside the catalog.',
        'Membership in the selected snapshot; CISA KEV catalog, CC0 1.0.'),

    'kev.membership.no_catalog': _e(
        'No usable catalog is loaded for this lookup.',
        'Keep unavailable lookup distinct from Not listed.',
        'Displays No catalog and offers supported loading routes.',
        'The local snapshot inventory and validation state.'),

    'kev.membership.invalid_id': _e(
        'The supplied identifier does not meet the supported CVE grammar.',
        'Correct the input before interpreting membership.',
        'Displays Invalid CVE ID rather than Not listed.',
        'The identifier parser and supported ASCII-digit grammar.'),

    # Ransomware and triage fields.

    'kev.ransomware.known': _e(
        'CISA records ransomware-campaign use as Known for this entry.',
        'Retain the field as a CISA statement rather than a code observation.',
        'Displays Known without identifying involved builds or functions.',
        'The retained entry ransomware-use field; CISA KEV catalog, CC0 1.0.'),

    'kev.ransomware.unknown': _e(
        'CISA records ransomware-campaign use as Unknown for this entry.',
        'Keep lack of confirmation distinct from a negative statement.',
        'Displays Unknown without replacing it with No.',
        'The retained entry ransomware-use field; CISA KEV catalog, CC0 1.0.'),

    'kev.ransomware.absent': _e(
        'This entry does not supply the ransomware-use field.',
        'Distinguish a missing field from an explicit Unknown value.',
        'Displays the missing-field state.',
        'The parsed entry field availability; CISA KEV catalog, CC0 1.0.'),

    'kev.ransomware.unrecognized': _e(
        'The ransomware-use value is outside the recognized vocabulary.',
        'Preserve source drift without guessing the intended meaning.',
        'Displays an unrecognized-value state.',
        'The parsed entry and parser vocabulary; CISA KEV catalog, CC0 1.0.'),

    'kev.triage.yes': _e(
        'CISA records forensic triage as required for this entry.',
        'Keep the directive field separate from local analysis actions.',
        'Displays Yes without starting any investigation command.',
        'The retained forensic-triage field; CISA KEV catalog, CC0 1.0.'),

    'kev.triage.no': _e(
        'CISA records No in the forensic-triage field.',
        'Read the exact directive field without expanding its scope.',
        'Displays No for this field only.',
        'The retained forensic-triage field; CISA KEV catalog, CC0 1.0.'),

    'kev.triage.absent': _e(
        'The catalog entry does not supply the forensic-triage field.',
        'Keep missing data distinct from an explicit No.',
        'Displays the missing-field state.',
        'The parsed entry field availability; CISA KEV catalog, CC0 1.0.'),

    'kev.triage.unrecognized': _e(
        'The forensic-triage value is outside the recognized vocabulary.',
        'Preserve the source limitation without assuming Yes or No.',
        'Displays an unrecognized-value state.',
        'The parsed entry and parser vocabulary; CISA KEV catalog, CC0 1.0.'),

    # Detail fields.

    'kev.detail.identity': _e(
        'Read the selected identifier and its catalog membership.',
        'Confirm which record the detail describes.',
        'Displays the dated lookup result.',
        'The selected lookup and snapshot; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.vendor_product': _e(
        'Read the vendor and product wording supplied by CISA.',
        'Keep catalog labels separate from product-scope matching.',
        'Displays CISA wording without using it to establish KB applicability.',
        'The entry vendor and product fields; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.name': _e(
        'Read the entry name supplied by CISA.',
        'Identify the catalog description being cited.',
        'Displays retained wording as plain text.',
        'The entry name field; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.description': _e(
        'Read the retained CISA short description.',
        'Inspect documentary context without assigning it to the selected code.',
        'Displays bounded plain text.',
        'The entry description field; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.cwes': _e(
        'Read the weakness identifiers listed by CISA.',
        'Keep this list separate from other advisory classifications.',
        'Displays the retained identifiers; they do not alter PatchTrace function ranking.',
        'The entry CWE list; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.required_action': _e(
        'Read the required-action wording retained from CISA.',
        'Inspect the directive text in its source context.',
        'Displays text without executing commands or applying remediation.',
        'The entry requiredAction field; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.notes': _e(
        'Read notes retained from the catalog entry.',
        'Inspect additional documentary references.',
        'Displays plain text; addresses are not opened automatically.',
        'The entry notes field; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.provenance': _e(
        'Read catalog version, release time, retrieval source, and digest.',
        'Retain the exact snapshot behind the lookup.',
        'Displays provenance without updating the catalog.',
        'Snapshot and retrieval metadata; CISA KEV catalog, CC0 1.0.'),

    'kev.detail.scope': _e(
        'Read the limits of CVE-level catalog context.',
        'Avoid using catalog membership as a function-localization result.',
        'Displays the documented scope explanation.',
        'The panel interpretation contract; CISA KEV catalog, CC0 1.0.'),

    # Catalog differences.

    'kev.changes.summary': _e(
        'Read added, changed, and removed entry counts between retained snapshots.',
        'Inspect the catalog difference without treating counts as a score.',
        'Displays the bounded local comparison.',
        'The selected snapshot delta; CISA KEV catalog, CC0 1.0.'),

    'kev.changes.added': _e(
        'This entry appears in the later retained catalog snapshot.',
        'Inspect a catalog addition with its recorded date.',
        'Displays the documentary change without assigning an activity start date.',
        'The two retained snapshots; CISA KEV catalog, CC0 1.0.'),

    'kev.changes.changed': _e(
        'Supported fields differ between the retained entry versions.',
        'Inspect exactly which catalog values changed.',
        'Displays the retained before-and-after fields.',
        'The selected entry delta; CISA KEV catalog, CC0 1.0.'),

    'kev.changes.removed': _e(
        'This identifier is absent from the later retained snapshot.',
        'Inspect a catalog removal without assuming its reason.',
        'Displays the snapshot difference.',
        'The two retained snapshots; CISA KEV catalog, CC0 1.0.'),

    'kev.changes.project_drift': _e(
        'Loaded catalog facts differ from the context recorded with the project.',
        'Keep historical project context distinguishable from the current snapshot.',
        'Displays the changed facts without rewriting the earlier record silently.',
        'Recorded project context and loaded facts; CISA KEV catalog, CC0 1.0.'),

    # Optional KB date context.

    'kev.timeline.before': _e(
        'Catalog addition precedes the established update release date.',
        'Read the two dates without inferring a causal sequence.',
        'Displays the elapsed days and named date basis.',
        'The established KB date and catalog entry date; CISA KEV catalog, CC0 1.0.'),

    'kev.timeline.same_day': _e(
        'Catalog addition and the established update release share a date.',
        'Keep date coincidence separate from a function-level relationship.',
        'Displays the named date basis.',
        'The established KB date and catalog entry date; CISA KEV catalog, CC0 1.0.'),

    'kev.timeline.after': _e(
        'Catalog addition follows the established update release date.',
        'Read the timing without assigning a code-change purpose.',
        'Displays the elapsed days and named date basis.',
        'The established KB date and catalog entry date; CISA KEV catalog, CC0 1.0.'),

    'kev.timeline.unresolved': _e(
        'The update date or required comparison orientation is not established.',
        'Avoid constructing a timing claim from missing context.',
        'Displays the unresolved date relationship.',
        'Available KB metadata and orientation checks.'),

    # Freshness categories.

    'kev.freshness.fresh': _e(
        'The snapshot is within the documented fresh-age threshold.',
        'Read its recency without assuming a live lookup.',
        'Displays the age; later catalog changes can still be absent.',
        'Release time and freshness policy; CISA KEV catalog, CC0 1.0.'),

    'kev.freshness.aging': _e(
        'The snapshot is older than the fresh-age threshold.',
        'Check whether a newer local import or approved update is needed.',
        'Displays the age warning without fetching automatically.',
        'Release time and freshness policy; CISA KEV catalog, CC0 1.0.'),

    'kev.freshness.stale': _e(
        'The snapshot has reached the documented stale-age threshold.',
        'Keep older Not listed results from appearing current.',
        'Displays the stale warning and supported update routes.',
        'Release time and freshness policy; CISA KEV catalog, CC0 1.0.'),

    'kev.freshness.future': _e(
        'The catalog release time is later than this computer clock.',
        'Check clock and source metadata before interpreting freshness.',
        'Displays the time inconsistency as UNVERIFIED.',
        'Catalog release time and the local clock; CISA KEV catalog, CC0 1.0.'),

    'kev.freshness.unknown': _e(
        'The lookup has no usable freshness assessment.',
        'Keep an unavailable age distinct from a recent snapshot.',
        'Displays Unknown freshness.',
        'The available lookup and snapshot metadata.'),

    # Panel and operation states.

    'kev.state.no_catalog': _e(
        'No usable KEV catalog is loaded.',
        'Distinguish unavailable lookup from an unlisted identifier.',
        'Offers local import or a separately approved update.',
        'The local snapshot inventory and validation state.'),

    'kev.state.consent': _e(
        'A catalog request is awaiting explicit approval.',
        'Review its destination and transmitted fields.',
        'Shows inline consent without contacting the source.',
        'The current KevPlan.'),

    'kev.state.downloading': _e(
        'The approved catalog download is running.',
        'Follow received bytes and the selected host.',
        'Keeps the current snapshot until the candidate passes checks.',
        'The active consented transport operation.'),

    'kev.state.checking': _e(
        'The downloaded or imported catalog is being checked.',
        'Distinguish received bytes from an accepted replacement.',
        'Validates the candidate before changing the current pointer.',
        'The candidate document and parser and validation rules.'),

    'kev.state.ready': _e(
        'A retained catalog is ready for local lookup.',
        'Identify the snapshot supporting the displayed results.',
        'Displays version, release, retrieval, count, and age metadata.',
        'The accepted snapshot metadata; CISA KEV catalog, CC0 1.0.'),

    'kev.state.error': _e(
        'The catalog operation could not complete.',
        'Inspect the reported cause while preserving any usable existing snapshot.',
        'Shows the error and states which catalog remains in use.',
        'The retained operation failure and local snapshot state.'),

    'kev.state.network_blocked': _e(
        'Network updates are disabled in this context.',
        'Identify why download approval is unavailable.',
        'Keeps supported local catalog import available.',
        'The panel network-availability setting.'),

    'kev.state.loading': _e(
        'The panel is reading a retained local catalog.',
        'Distinguish pending loading from no catalog.',
        'Shows local loading feedback without making a network request.',
        'The local snapshot store.'),

    'kev.state.older_candidate': _e(
        'The retrieved catalog is older than the current retained release.',
        'Avoid replacing newer catalog context with an older source copy.',
        'Keeps the newer current snapshot and reports the candidate.',
        'The two release timestamps; CISA KEV catalog, CC0 1.0.'),

    'kev.state.shrink': _e(
        'The checked candidate contains fewer entries than the current catalog.',
        'Review the unexpected reduction before replacement.',
        'Requires the supported explicit shrink decision.',
        'Candidate and current entry counts; CISA KEV catalog, CC0 1.0.'),

    'kev.state.empty_input': _e(
        'No identifiers have been supplied for lookup.',
        'Keep an empty request distinct from no catalog matches.',
        'Requests CVE identifiers or a supported context selection.',
        'The current lookup input.'),

    'kev.state.no_visible_rows': _e(
        'No lookup rows pass the current filter.',
        'Distinguish a filtered table from an empty lookup population.',
        'Requests a broader filter without updating the catalog.',
        'The current lookup results and display options.'),

    'kev.state.cancelled': _e(
        'The catalog operation was cancelled.',
        'Distinguish interrupted retrieval from a completed update.',
        'Retains the previously accepted current snapshot.',
        'The operation cancellation outcome.'),

    'kev.state.recovered_snapshot': _e(
        'A valid retained snapshot was used after a store or pointer problem.',
        'Inspect which catalog now supports the lookup.',
        'Reports the fallback instead of hiding the recovery.',
        'Local snapshot validation and current-pointer recovery.'),

    'kev.state.unsupported_import': _e(
        'The selected document is not a supported KEV JSON catalog.',
        'Choose input with the required catalog metadata.',
        'Rejects the import without replacing the current snapshot.',
        'The import format and required-field checks.'),

    'kev.state.too_many_ids': _e(
        'The requested lookup exceeds the identifier limit.',
        'Keep lookup scope bounded and explicit.',
        'Requests a smaller identifier population.',
        'The parsed input count and configured lookup ceiling.'),
}


KEV_TOOLTIP_TEMPLATES = {
    'kev.cell': _e(
        'KEV lookup for {cve}.',
        'Read membership together with snapshot age and its meaning.',
        'Displays the retained lookup without assigning it to a code location.',
        'State: {state}. Version: {version}. Meaning: {meaning}. CISA KEV catalog, CC0 1.0.'),

    'kev.badge': _e(
        'KEV state: {state}.',
        'Keep catalog membership distinguishable from other investigation evidence.',
        'Displays a text badge without changing function ranking.',
        'Identifier: {cve}. Version: {version}. Meaning: {meaning}. CISA KEV catalog, CC0 1.0.'),

    'kev.column': _e(
        'KEV catalog field: {field}.',
        'Inspect the field definition before interpreting its value.',
        'Displays the source-field meaning without extending its scope.',
        'Meaning: {meaning}. CISA KEV catalog, CC0 1.0.'),

    'kev.row_header': _e(
        'Catalog lookup row for {cve}.',
        'Keep each result attached to its requested identifier.',
        'Selects the row for retained details.',
        'State: {state}. Version: {version}. CISA KEV catalog, CC0 1.0.'),

    'kev.snapshot': _e(
        'Retained KEV catalog snapshot.',
        'Identify the exact source version behind a lookup.',
        'Displays provenance without retrieving a new copy.',
        'Version: {version}. Released: {released}. Retrieved: {retrieved}. Digest: {digest}. CISA KEV catalog, CC0 1.0.'),

    'kev.request': _e(
        'Prepared KEV catalog request.',
        'Check the exact destination before approval.',
        'Runs only after approval of the displayed operation.',
        'Method: {method}. URL: {url}. Limit: {limit}. Plan: {plan}.'),

    'kev.changed_field': _e(
        'Catalog entry field changed between retained snapshots.',
        'Inspect the precise documentary difference.',
        'Displays before and after values without changing historical project context.',
        'Identifier: {cve}. Field: {field}. Before: {before}. After: {after}. CISA KEV catalog, CC0 1.0.'),

    'kev.date_relation': _e(
        'Catalog-addition timing relative to the established update date.',
        'Keep the named date basis visible.',
        'Displays a date comparison without attributing a function change.',
        'Identifier: {cve}. Update: {kb}. Relation: {relation}. Basis: {basis}. CISA KEV catalog, CC0 1.0.'),

    'kev.project_drift': _e(
        'Catalog context changed since the project recorded it.',
        'Distinguish the historical lookup from the loaded snapshot.',
        'Displays the difference without silently rewriting the earlier context.',
        'Identifier: {cve}. Earlier: {before}. Loaded: {after}. CISA KEV catalog, CC0 1.0.'),

    'kev.error': _e(
        'KEV catalog operation failed.',
        'Inspect the cause and which retained snapshot remains available.',
        'Displays diagnostics without accepting the failed candidate.',
        'Code: {code}. Reason: {reason}. Retained catalog: {kept}.'),
}
