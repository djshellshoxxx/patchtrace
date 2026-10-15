"""Proposed Unified panel tooltip copy.

Experimental implementation. Packaged Windows availability is UNVERIFIED.

Sources:
- src/patchtrace/unified/panel.py
- src/patchtrace/unified/registry.py
- src/patchtrace/unified/read_model.py
- src/patchtrace/unified/read_text.py
- src/patchtrace/ui_unified.py

Existing tooltip IDs retain their names. Additional IDs require explicit
bindings to the corresponding existing controls, headers, options, or details.

The Class menu filters evidence classes, such as names or call relations.
Instruction-delta classes are described separately under unified.delta.*.

Registry presence does not establish that a source adapter is implemented.
Diaphora runtime availability is UNVERIFIED.

Dynamic What lines must remain within 160 characters after interpolation.
Use the registered, escaped template path with field-specific length limits.

This module supplies copy only. It does not register entries or change UI behavior.
"""

from patchtrace.tooltips import _e


UNIFIED_TOOLTIPS = {
    'unified.dock': _e(
        'Review derived function pairings and change classifications.',
        'Inspect combined evidence while retaining the primary comparison.',
        'Shows the Unified dock without replacing Ghidriff results.',
        'Stored engine outputs and PatchTrace derivation rules.'),

    'unified.action': _e(
        'Show or hide the Unified panel.',
        'Keep the derived comparison beside the code.',
        'Toggles the dock; shortcut Ctrl+Shift+U.',
        'The application panel registry.'),

    'unified.tab': _e(
        'Open the Unified comparison tab.',
        'Read derived relationships for the current project.',
        'Shows existing content without starting analysis.',
        'The stored Unified result and its read model.'),

    'unified.header': _e(
        'Read the identities and scope of the displayed Unified result.',
        'Confirm which comparison the table describes.',
        'Displays the result header without changing inputs.',
        'The loaded Unified result manifest.'),

    'unified.view_switch': _e(
        'Switch to the Engine evidence tab.',
        'Inspect the separate engine records behind the derived view.',
        'Changes the visible tab without computing a result.',
        'The adjacent Engine evidence panel.'),

    'unified.run': _e(
        'Run Unified analysis for the current project.',
        'Prepare derived pairings and available change facts.',
        'Stores a new result; target binaries are not executed and no network is used.',
        'Stored engine outputs, configured extraction, and Unified rules.'),

    'unified.cancel': _e(
        'Request cancellation of the running Unified analysis.',
        'Stop work that is no longer needed.',
        'Stops the attempt without publishing unfinished output.',
        'The active Unified operation.'),

    'unified.retry': _e(
        'Run Unified analysis again after a failure.',
        'Repeat the operation after addressing its reported cause.',
        'Starts another attempt while retaining earlier results.',
        'The current project inputs and Unified configuration.'),

    'unified.copy_error': _e(
        'Copy the Unified failure details.',
        'Preserve the reported code and message for diagnosis.',
        'Writes plain text to the clipboard.',
        'The retained failure report.'),

    'unified.filter_decision': _e(
        'Choose which pairing decisions appear in the table.',
        'Focus on matched, proposed, conflicting, or one-sided relationships.',
        'Changes visible rows without editing stored decisions.',
        'Pairing decisions in the loaded Unified result.'),

    'unified.filter_change': _e(
        'Choose which change classifications appear in the table.',
        'Focus review on a particular kind of assessment.',
        'Changes visible rows; an explicit classification selection can reveal collapsed rows.',
        'Recorded materiality classifications and display rules.'),

    'unified.filter_class': _e(
        'Filter rows by their supporting evidence classes.',
        'Find relationships supported by names, code structure, calls, or other evidence.',
        'Changes visible rows; this menu does not select instruction-delta classes.',
        'Evidence classes attached to the stored pairing records.'),

    'unified.filter_source': _e(
        'Filter rows by the sources recorded for them.',
        'Inspect where a selected source contributes a record.',
        'Changes visible rows without running or enabling a source.',
        'Source identities in the loaded result and source registry.'),

    'unified.search': _e(
        'Filter function names and hexadecimal addresses.',
        'Locate a function already under review.',
        'Narrows rows after a short pause; 0x is optional.',
        'Loaded function labels and addresses.'),

    'unified.show_hidden': _e(
        'Reveal unchanged and structurally cosmetic rows collapsed by default.',
        'Inspect records retained outside the initial reading list.',
        'Includes eligible collapsed rows subject to the remaining filters.',
        'Recorded classifications and the Unified collapse policy.'),

    'unified.summary': _e(
        'Read displayed counts and the available result summary.',
        'Distinguish filtered rows from the underlying result.',
        'Updates with the current view without changing stored records.',
        'Loaded result counts and active display filters.'),

    'unified.table': _e(
        'Review function pairings, change classifications, and separate source values.',
        'Keep relationship decisions and native measurements distinguishable.',
        'Selection opens details; Enter displays the row in the code panes.',
        'The loaded Unified rows and source metadata.'),

    'unified.detail': _e(
        'Read support, conflict, change facts, limits, and provenance for a row.',
        'Check the evidence behind the displayed labels.',
        'Shows selectable plain text without editing the result.',
        'The selected row and its retained supporting records.'),

    'unified.goto': _e(
        'Show the selected relationship in the main code panes.',
        'Read the functions beside their derived evidence.',
        'Selects its Ghidriff match or displays its retained pair text.',
        'The selected Unified row and available function records.'),

    'unified.correct': _e(
        'Open the correction dialog for the selected primary match.',
        'Record a different relationship with an analyst reason.',
        'Requires a mapped Ghidriff match and an idle project; saving can stale derived results.',
        'The existing match-correction workflow.'),

    'unified.copy': _e(
        'Copy provenance for the selected Unified rows.',
        'Retain the input identities and supporting evidence in notes.',
        'Writes bounded plain text to the clipboard, up to 16 KiB.',
        'Selected rows and the Unified result manifest.'),

    'unified.explain': _e(
        'Preview bounded descriptive context for the selected row.',
        'Inspect what a later explanation could use.',
        'Opens a read-only preview without transmitting it.',
        'The selected row and available retained evidence.'),

    'unified.explain_preview': _e(
        'Read the selected row context prepared for explanation.',
        'Check included observations and limits before any later use.',
        'Displays bounded plain text; opening this preview sends nothing.',
        'The Unified context builder and selected row.'),

    'unified.explain_close': _e(
        'Close the Unified explanation preview.',
        'Return to the comparison after inspecting its context.',
        'Closes the preview without sending a request.',
        'The local explanation-preview dialog.'),

    'unified.stale_banner': _e(
        'Read notices about stale inputs, partial evidence, or missing extraction.',
        'Identify limits affecting the displayed result.',
        'Shows notices; rerun analysis when current derived evidence is required.',
        'Result-manifest checks and extraction availability.'),

    'unified.footer': _e(
        'Read the scope and measurement limits of the Unified view.',
        'Keep rule-based decisions distinct from engine-native values.',
        'Displays persistent interpretation guidance.',
        'Unified rules cover function code and unwind data, not global data contents.'),

    'unified.divider': _e(
        'Adjust the space between the result table and row details.',
        'Allocate reading space to the material being inspected.',
        'Changes the panel layout without changing analysis records.',
        'The Unified panel splitter.'),

    # Fixed columns.

    'unified.col.function': _e(
        'Read the function label and recorded endpoint addresses.',
        'Identify the exact relationship represented by this row.',
        'Selection displays its details; sorting changes reading order.',
        'Retained function references in the Unified row.'),

    'unified.col.decision': _e(
        'Read the rule-based function-pairing decision.',
        'Distinguish accepted relationships from proposals and conflicts.',
        'Displays a text-and-glyph label; sorting changes reading order.',
        'Unified support, contest, and ambiguity rules.'),

    'unified.col.change': _e(
        'Read the change classification and available change summary.',
        'Separate supported code differences from unresolved assessment.',
        'Displays recorded change information; sorting changes reading order.',
        'The selected row classification and associated change facts.'),

    # Source columns and matching Source-menu options.

    'unified.source.ghidriff': _e(
        'Read Ghidriff-native match information.',
        'Inspect the primary engine basis without combining its values with other sources.',
        'Displays retained Ghidriff terms; selecting this source filters rows.',
        'Stored Ghidriff output and its recorded version.'),

    'unified.source.bindiff': _e(
        'Read BinDiff similarity and algorithm information.',
        'Keep the native measurement attached to its producing algorithm.',
        'Displays BinDiff values separately; selecting this source filters rows.',
        'The stored BinDiff result and source metadata.'),

    'unified.source.rz-diff': _e(
        'Read rz-diff byte-similarity information.',
        'Distinguish raw-byte comparison from other evidence.',
        'Displays retained rz-diff values; selecting this source filters rows.',
        'The stored rz-diff result and its native units.'),

    'unified.source.diaphora': _e(
        'Read retained Diaphora category and ratio fields when present.',
        'Keep a registered source distinct from an available adapter.',
        'Displays stored fields only; it does not install or launch Diaphora.',
        'Registered Diaphora metadata; runtime availability is UNVERIFIED.'),

    'unified.source.pt-ladder': _e(
        'Read the PatchTrace matching pass and evidence tier.',
        'Identify which matching rule contributed to the relationship.',
        'Displays retained pass information; selecting this source filters rows.',
        'The PatchTrace ladder output and versioned pass registry.'),

    'unified.source.pt-bytes': _e(
        'Read PatchTrace byte-comparison pass information.',
        'Inspect byte-based support separately from structural sources.',
        'Displays retained pass and tier information.',
        'The PatchTrace byte comparator and recorded configuration.'),

    'unified.source.manual': _e(
        'Read the analyst-correction contribution.',
        'Distinguish an analyst decision from engine-derived support.',
        'Displays retained correction information; selecting this source filters rows.',
        'Manual relationship corrections in the project.'),

    'unified.source.unknown': _e(
        'Read a stored source this application build does not recognize.',
        'Preserve the record without assigning undocumented meaning.',
        'Displays its retained values without additional interpretation.',
        'Source metadata embedded in the loaded result.'),

    # Pairing chips; these meanings also apply to Decision-menu options.

    'unified.decision.matched': _e(
        'Recorded evidence satisfies the Unified matching rule.',
        'Identify a relationship supported by its qualifying rule.',
        'Displays Matched; inspect the rule and supporting records in details.',
        'A unique tier A key, analyst correction, or qualifying independent support.'),

    'unified.decision.tentative': _e(
        'Tier B support lacks the required independent corroboration.',
        'Keep a proposed relationship distinct from Matched.',
        'Displays Tentative; it is not counted as a matched relationship.',
        'The recorded components and evidence classes.'),

    'unified.decision.candidate': _e(
        'Only candidate-tier or weak external support is available.',
        'Identify relationships requiring further evidence.',
        'Displays Candidate without automatic acceptance.',
        'Recorded tier C or weak external evidence.'),

    'unified.decision.contested': _e(
        'A source links an endpoint differently.',
        'Direct attention to incompatible function relationships.',
        'Displays Contested and retains the opposing records.',
        'The stored contest and its referenced evidence.'),

    'unified.decision.ambiguous': _e(
        'Several functions share the available matching evidence.',
        'Avoid selecting a counterpart without a distinguishing basis.',
        'Displays Ambiguous without choosing a single pairing.',
        'The candidate relationships and shared evidence.'),

    'unified.decision.older_only': _e(
        'No recorded source pairs this older function with a newer counterpart.',
        'Keep one-sided coverage distinct from an established removal.',
        'Displays Older only; unavailable evidence remains unknown.',
        'Stored sources covering the older function.'),

    'unified.decision.newer_only': _e(
        'No recorded source pairs this newer function with an older counterpart.',
        'Keep one-sided coverage distinct from an established addition.',
        'Displays Newer only; unavailable evidence remains unknown.',
        'Stored sources covering the newer function.'),

    'unified.decision.unknown': _e(
        'No usable pairing evidence supports this row.',
        'Make the unresolved relationship explicit.',
        'Displays Unknown without selecting a counterpart.',
        'The available records and their usability checks.'),

    # Change chips; these meanings also apply to Change-menu options.

    'unified.change.unchanged': _e(
        'The row meets the recorded unchanged-proof requirements.',
        'Identify the comparison scope within which no change was established.',
        'Displays Unchanged; eligible rows are collapsed by default.',
        'The recorded UNCH/1 proof and its supporting channels.'),

    'unified.change.cosmetic': _e(
        'The row meets a recorded cosmetic-classification rule.',
        'Distinguish supported presentation or structural variation from other differences.',
        'Displays Cosmetic; inspect whether its proof is structural or decompiler-relative.',
        'The recorded COS-* proof and its limitations.'),

    'unified.change.material': _e(
        'A semantic delta has the required supporting comparison channel.',
        'Identify a difference meeting the material-change rules.',
        'Displays Material without assigning a purpose to the change.',
        'Recorded semantic deltas and an anchored second differing channel.'),

    'unified.change.review': _e(
        'The available change evidence requires further inspection.',
        'Keep unresolved assessment visible.',
        'Displays Review without promoting it to another classification.',
        'The recorded change facts and classification rules.'),

    'unified.change.unknown': _e(
        'Available evidence does not establish a change classification.',
        'Separate unavailable assessment from an unchanged result.',
        'Displays Unknown.',
        'The retained channels, missing facts, and recorded limits.'),

    'unified.change.not_applicable': _e(
        'A two-sided change classification does not apply to this row.',
        'Avoid treating a one-sided relationship as a comparison of two bodies.',
        'Displays Not applicable.',
        'The relationship shape and change-classification contract.'),

    # Evidence tiers shown in supporting details.

    'unified.tier.manual': _e(
        'Tier M identifies an analyst correction.',
        'Keep analyst input distinguishable from algorithmic support.',
        'Labels the recorded correction evidence.',
        'The project correction record.'),

    'unified.tier.unique': _e(
        'Tier A identifies qualifying unique-key evidence.',
        'Explain the matching rule supporting this relationship.',
        'Labels the support without expressing an accuracy estimate.',
        'The versioned source-step and matching-pass registry.'),

    'unified.tier.corroborating': _e(
        'Tier B identifies corroborating-key evidence.',
        'Check whether independent components and evidence classes also support the pair.',
        'Labels the support; inspect the component breakdown.',
        'The source-step registry and recorded support components.'),

    'unified.tier.candidate': _e(
        'Tier C identifies candidate evidence.',
        'Keep a proposed association distinct from stronger rule support.',
        'Labels the candidate contribution.',
        'The source-step or matching-pass registry.'),

    'unified.tier.weak_external': _e(
        'Tier W identifies weak external evidence.',
        'Keep a limited external contribution visible without promoting it.',
        'Labels the contribution in the row details.',
        'The registered external source and its recorded step.'),

    # Class-menu options: evidence classes, not instruction-delta classes.

    'unified.class.names': _e(
        'Select rows supported by name-related evidence.',
        'Inspect relationships that depend on symbol or name information.',
        'Filters for evidence class E-NAME.',
        'Recorded name-based evidence atoms.'),

    'unified.class.body': _e(
        'Select rows supported by code-byte or instruction evidence.',
        'Inspect body-based support separately from names and layout.',
        'Filters for evidence class E-BODY.',
        'Recorded byte and instruction comparison atoms.'),

    'unified.class.cfg': _e(
        'Select rows supported by control-flow shape evidence.',
        'Inspect structural matching contributions.',
        'Filters for evidence class E-CFG.',
        'Recorded flow-graph evidence atoms.'),

    'unified.class.calls': _e(
        'Select rows supported by call-relation evidence.',
        'Inspect matching contributions involving callers or callees.',
        'Filters for evidence class E-CALL.',
        'Recorded call-relation evidence atoms.'),

    'unified.class.data': _e(
        'Select rows supported by string or constant evidence.',
        'Inspect data-reference matching contributions.',
        'Filters for evidence class E-DATA.',
        'Recorded string and constant evidence atoms.'),

    'unified.class.decompiler': _e(
        'Select rows supported by decompiler-output evidence.',
        'Identify relationships relying on reconstructed text.',
        'Filters for evidence class E-DECOMP.',
        'Recorded decompiler-based matching atoms.'),

    'unified.class.layout': _e(
        'Select rows supported by layout-position evidence.',
        'Inspect associations that depend on placement.',
        'Filters for evidence class E-LAYOUT.',
        'Recorded layout-based matching atoms.'),

    'unified.class.residual': _e(
        'Select rows supported by residual-voting evidence.',
        'Inspect later matching proposals separately from direct keys.',
        'Filters for evidence class E-RESID.',
        'Recorded residual matching-pass atoms.'),

    'unified.class.manual': _e(
        'Select rows carrying analyst-correction evidence.',
        'Locate relationships affected by recorded analyst input.',
        'Filters for evidence class E-MANUAL.',
        'Project correction records represented as evidence atoms.'),

    'unified.class.unknown': _e(
        'Select rows carrying an unrecognized evidence step.',
        'Locate support whose method this build cannot classify.',
        'Filters for evidence class E-UNKNOWN.',
        'Stored source-step text and the current registry.'),

    # Detail sections.

    'unified.detail.function': _e(
        'Read the older and newer function references.',
        'Confirm the endpoints before interpreting their differences.',
        'Displays retained names, addresses, and relationship identity.',
        'The selected Unified row.'),

    'unified.detail.decision': _e(
        'Read why the row received its pairing decision.',
        'Check the rule behind the label.',
        'Displays the decision explanation without changing it.',
        'Recorded support, tiers, and contest information.'),

    'unified.detail.components': _e(
        'Read supporting evidence grouped by dependency component.',
        'Avoid counting dependent sources as separate corroboration.',
        'Displays the component-to-evidence breakdown.',
        'Recorded evidence families and dependency tags.'),

    'unified.detail.classes': _e(
        'Read the evidence-class breakdown for this relationship.',
        'Check the variety of support as well as its dependency grouping.',
        'Displays classes, contributing sources, and recorded tiers.',
        'Evidence atoms supporting the selected endpoints.'),

    'unified.detail.contest': _e(
        'Read records that support a different endpoint.',
        'Inspect the exact basis of a pairing conflict.',
        'Displays retained contest strength and opposing atoms.',
        'The selected row contest record.'),

    'unified.detail.atoms': _e(
        'Read individual source observations and their matching steps.',
        'Trace a decision back to specific contributions.',
        'Displays recorded source, step, tier, class, and endpoints.',
        'Evidence atoms retained with the Unified row.'),

    'unified.detail.facts': _e(
        'Read change channels, proofs, and individual deltas.',
        'Inspect the observations behind the change classification.',
        'Displays available facts and any omitted-delta count.',
        'The associated change-facts record.'),

    'unified.detail.limits': _e(
        'Read missing channels and limits affecting this row.',
        'Keep incomplete assessment visible beside the conclusion.',
        'Displays the retained limitations as plain text.',
        'The selected row, change facts, and result manifest.'),

    'unified.detail.provenance': _e(
        'Read input identities, source versions, and result provenance.',
        'Retain enough context to distinguish this result from another run.',
        'Displays the available recorded derivation metadata.',
        'The Unified result manifest and registry.'),

    # Channel and source-cell states.

    'unified.channel.equal': _e(
        'This comparison channel reports equality within its defined scope.',
        'Keep a channel result distinct from the overall classification.',
        'Displays Equal for this channel.',
        'The recorded channel assessment.'),

    'unified.channel.differs': _e(
        'This comparison channel reports a difference.',
        'Identify which observation supports further change assessment.',
        'Displays Differs for this channel.',
        'The recorded channel assessment and related deltas.'),

    'unified.channel.unavailable': _e(
        'This comparison channel could not supply an assessment.',
        'Keep missing evidence distinct from equality.',
        'Displays Unavailable without supplying a negative vote.',
        'Recorded extraction and channel-availability information.'),

    'unified.channel.not_applicable': _e(
        'This comparison channel does not apply to the selected record.',
        'Distinguish an inapplicable test from missing output.',
        'Displays Not applicable for this channel.',
        'The channel contract and selected relationship.'),

    'unified.cell.pairs_elsewhere': _e(
        'This source links an endpoint to another function.',
        'Locate the source contribution behind a conflict.',
        'Displays the alternative in its source column and row details.',
        'The stored source relationship.'),

    'unified.cell.no_record': _e(
        'This source has no corresponding record for the row.',
        'Keep absent coverage distinct from disagreement.',
        'Displays the missing-record state.',
        'The source records available in the loaded result.'),

    'unified.cell.not_run': _e(
        'No source output is available from the required operation.',
        'Identify an unavailable contribution without assuming a result.',
        'Displays Not run.',
        'The loaded manifest and source availability.'),

    # Individual change-delta labels retained in row details.

    'unified.delta.constant': _e(
        'Read a recorded constant-value change.',
        'Inspect the operand and context that changed.',
        'Displays the retained old and new values when available.',
        'The delta record, its channel, and endpoint addresses.'),

    'unified.delta.comparison': _e(
        'Read a recorded comparison change.',
        'Inspect a changed comparison operation or related expression.',
        'Displays the retained comparison delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.condition': _e(
        'Read a recorded condition change.',
        'Inspect a difference affecting a conditional expression.',
        'Displays the retained condition delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.callee': _e(
        'Read a recorded callee change.',
        'Inspect which called target differs.',
        'Displays available old and new target information.',
        'The recorded call-target delta and address mapping.'),

    'unified.delta.call_added': _e(
        'Read a call classified as added by the comparison.',
        'Inspect the new call within its recorded scope.',
        'Displays the available call delta without assigning its purpose.',
        'The change-facts record and producing channel.'),

    'unified.delta.call_removed': _e(
        'Read a call classified as removed by the comparison.',
        'Inspect the missing call within its recorded scope.',
        'Displays the available call delta without assigning its purpose.',
        'The change-facts record and producing channel.'),

    'unified.delta.data_ref': _e(
        'Read a recorded data-reference change.',
        'Inspect a difference in referenced data targets.',
        'Displays retained target information and mapping limits.',
        'The recorded delta and data-target mapping.'),

    'unified.delta.struct_offset': _e(
        'Read a recorded structure-offset change.',
        'Inspect a changed memory-access offset.',
        'Displays the available offset delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.cfg': _e(
        'Read a recorded control-flow change.',
        'Inspect a structural difference in the compared functions.',
        'Displays the retained flow-related delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.block_added': _e(
        'Read a block classified as added.',
        'Inspect the scope of the recorded structural addition.',
        'Displays the available block delta and associated classification.',
        'The change-facts record and its proof or channel.'),

    'unified.delta.block_removed': _e(
        'Read a block classified as removed.',
        'Inspect the scope of the recorded structural removal.',
        'Displays the available block delta and associated classification.',
        'The change-facts record and its proof or channel.'),

    'unified.delta.string': _e(
        'Read a recorded string-related change.',
        'Inspect the text observation and its attribution limits.',
        'Displays available string-delta information.',
        'The retained delta and producing comparison channel.'),

    'unified.delta.size_only': _e(
        'Read a change classified as size-only.',
        'Keep this limited observation distinct from a semantic explanation.',
        'Displays the stored classification and its details.',
        'The recorded size-only delta.'),

    'unified.delta.refcount_only': _e(
        'Read a change classified as reference-count-only.',
        'Inspect the exact scope assigned by the classifier.',
        'Displays the retained label and supporting details.',
        'The recorded refcount-only delta.'),

    'unified.delta.address_only': _e(
        'Read a change classified as address-only.',
        'Inspect relocation-related variation and its mapping basis.',
        'Displays the stored address delta.',
        'The recorded delta and applicable address-mapping checks.'),

    'unified.delta.register_only': _e(
        'Read a change classified as register-only.',
        'Inspect register variation separately from other recorded changes.',
        'Displays the retained register-related delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.layout_only': _e(
        'Read a change classified as layout-only.',
        'Inspect structural placement differences and their proof limits.',
        'Displays the retained layout delta.',
        'The change-facts record and applicable structural proof.'),

    'unified.delta.name_only': _e(
        'Read a change classified as name-only.',
        'Separate naming variation from other available observations.',
        'Displays the retained name-related delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.frame': _e(
        'Read a recorded frame-related change.',
        'Inspect frame information without assigning an unsupported cause.',
        'Displays the retained frame delta.',
        'The change-facts record and producing channel.'),

    'unified.delta.eh': _e(
        'Read a recorded exception-handling or unwind-related change.',
        'Inspect supporting runtime-structure differences.',
        'Displays available EH-related facts and limits.',
        'The retained delta and associated comparison channel.'),

    'unified.delta.unknown': _e(
        'Read a delta without an established change class.',
        'Preserve the observation without inventing its meaning.',
        'Displays Unknown with the available details.',
        'The retained delta record.'),

    # Result states and accompanying notices.

    'unified.state.no_project': _e(
        'Open a project before using the Unified comparison.',
        'Associate the view with a specific artifact pair.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'unified.state.no_result': _e(
        'No Unified result has been prepared for this project.',
        'Distinguish missing derived analysis from an empty comparison.',
        'Offers Run unified when its prerequisites hold.',
        'The project stored-result inventory.'),

    'unified.state.loading': _e(
        'The panel is reading a stored Unified result.',
        'Distinguish pending content from missing rows.',
        'Shows loading feedback until preparation completes or fails.',
        'The active result-loading task.'),

    'unified.state.running': _e(
        'Unified analysis is preparing a new result.',
        'Follow the active analysis stage.',
        'Shows progress while the existing committed result is retained.',
        'The active Unified operation.'),

    'unified.state.indeterminate': _e(
        'The current Unified stage has no measured completion total.',
        'Read activity without assuming a completion fraction.',
        'Displays stage text without a numeric progress estimate.',
        'Progress supplied by the active Unified operation.'),

    'unified.state.ready': _e(
        'The Unified result is ready to review.',
        'Identify completion of the current view preparation.',
        'Displays rows subject to active filters and collapse rules.',
        'The loaded result and current display settings.'),

    'unified.state.partial': _e(
        'The result lacks some requested evidence.',
        'Keep incomplete coverage visible during review.',
        'Shows available rows and the reasons for missing evidence.',
        'The result manifest and recorded channel status.'),

    'unified.state.failed': _e(
        'Unified preparation failed.',
        'Identify an unsuccessful attempt rather than an empty result.',
        'Shows the error while retaining earlier and primary comparison results.',
        'The recorded Unified failure.'),

    'unified.state.stale': _e(
        'The stored Unified result describes earlier inputs.',
        'Keep historical classifications distinct from current assessment.',
        'Displays the stale reason; rerun for a current derived result.',
        'Manifest identities compared with current project inputs.'),

    'unified.state.extraction_missing': _e(
        'Ghidra extraction is not configured for instruction-level change facts.',
        'Identify why the result relies on stored engine outputs.',
        'Displays the limitation without fabricating missing instruction detail.',
        'The recorded extraction configuration and result manifest.'),

    'unified.state.too_large': _e(
        'The displayed result would exceed the row ceiling.',
        'Explain why the table requires a narrower selection.',
        'Shows the count and requests narrower filters.',
        'The filtered row count and Unified display limit.'),

    'unified.state.cancelled': _e(
        'The Unified attempt was cancelled.',
        'Distinguish interrupted preparation from a completed result.',
        'Publishes no unfinished result and retains the previous committed one.',
        'The active-operation cancellation outcome.'),

    'unified.state.no_visible_rows': _e(
        'No rows pass the current filters and collapse settings.',
        'Separate a filtered view from an empty underlying result.',
        'Requests broader filters or Show hidden where appropriate.',
        'The loaded rows and current display query.'),

    'unified.state.no_selected_row': _e(
        'Select a Unified row to inspect its details.',
        'Identify the prerequisite for row-specific actions.',
        'Keeps selection-dependent actions unavailable until a row is selected.',
        'The current table selection.'),
}


UNIFIED_TOOLTIP_TEMPLATES = {
    'unified.row': _e(
        'Unified row for {function}.',
        'Inspect pairing {decision} and change classification {change}.',
        'Select the row for retained support and limitations.',
        'Sources: {sources}. Address context: {reason}.'),

    'unified.cell': _e(
        '{source} value: {value}. Unit: {unit}.',
        'Keep this measurement attached to its producing source.',
        'Read the row details for its original meaning and limits.',
        '{provenance}. Details: {reason}.'),

    'unified.badge': _e(
        '{decision}: {meaning}',
        'Interpret the badge as a rule-based pairing label.',
        'Read-only; inspect its supporting evidence.',
        'The retained Unified decision rules; uncalibrated.'),

    'unified.delta': _e(
        'Recorded change class: {kind}.',
        'Inspect the channel and addresses behind this observation.',
        'Shows retained delta details without assigning a purpose.',
        '{provenance}. Details: {reason}.'),

    'unified.component': _e(
        'Supporting component: {component}.',
        'Check which observations share dependency assumptions.',
        'Displays the retained component breakdown.',
        'Sources: {sources}. Classes: {classes}.'),

    'unified.limit': _e(
        'Recorded analysis limit: {limit}.',
        'Identify which part of the assessment is bounded or incomplete.',
        'Displays the limitation without treating missing evidence as agreement.',
        'The row, change facts, or result manifest.'),

    'unified.stale_reason': _e(
        'This result is stale.',
        'Identify the changed input before reusing a classification.',
        'Retains historical content; run Unified again for current inputs.',
        'Recorded input comparison: {reason}.'),
}
