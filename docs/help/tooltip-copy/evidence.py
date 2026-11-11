"""Proposed Engine evidence tooltip copy.

Experimental panel. Packaged Windows availability is UNVERIFIED.

Sources:
- src/patchtrace/ui_evidence.py
- src/patchtrace/ui_engine_setup.py
- src/patchtrace/secondary/evidence_panel.py
- src/patchtrace/secondary/evidence_view.py
- src/patchtrace/secondary/evidence_table.py
- src/patchtrace/tooltips.py

Existing evidence IDs retain their names. Additional IDs describe existing
controls, columns, options, and states but require explicit UI bindings.

The evidence.setup.* IDs provide panel-prefixed copy for the embedded
BinDiff setup. Its current bindings use engine_setup.*; migration is planned.

Templates must use PatchTrace's registered, escaped interpolation path.
This module does not register entries, change bindings, or run operations.
"""

from patchtrace.tooltips import _e


EVIDENCE_TOOLTIPS = {
    'evidence.dock': _e(
        'Compare stored function-pairing evidence from Ghidriff and secondary engines.',
        'Inspect endpoint agreement and conflict beside the code.',
        'Shows a review panel; opening it starts no engine run.',
        'Stored Ghidriff, BinDiff, and rz-diff records.'),

    'evidence.action': _e(
        'Show or hide the Engine evidence panel.',
        'Keep pairing evidence available while reviewing functions.',
        'Toggles the dock; shortcut Ctrl+Shift+E.',
        'The application panel registry.'),

    'evidence.tabs': _e(
        'Switch between Evidence and Engines.',
        'Choose between reviewing stored relationships and configuring engine work.',
        'Changes the visible tab.',
        'The Engine evidence panel.'),

    'evidence.tab.evidence': _e(
        'Open the stored function-pairing evidence view.',
        'Compare each engine against the recorded function relationship.',
        'Shows filters, results, and selected-row details.',
        'The current evidence view model.'),

    'evidence.tab.engines': _e(
        'Open engine status, setup, and run controls.',
        'Check available engines before starting additional analysis.',
        'Shows engine controls; selecting the tab starts no run.',
        'Stored engine status and explicit local checks.'),

    'evidence.filter': _e(
        'Filter rows by pairing verdict or show engine-only records.',
        'Focus review on the relationships relevant to the current question.',
        'Changes visible rows and remembers the selected filter.',
        'Verdicts derived from stored engine relationships.'),

    'evidence.filter.all': _e(
        'Show all primary comparison rows allowed by the other filters.',
        'Review all primary-row verdicts together.',
        'Includes Agree, Contested, Single engine, and Unknown rows.',
        'Stored primary matches and reconciled engine evidence.'),

    'evidence.filter.contested': _e(
        'Show rows with conflicting function endpoints.',
        'Inspect relationships on which engines differ.',
        'Restricts the table to Contested rows.',
        'Address-comparable relationships from stored engines.'),

    'evidence.filter.unknown': _e(
        'Show rows without a usable cross-engine assessment.',
        'Find where evidence cannot establish a pairing verdict.',
        'Restricts the table to Unknown rows.',
        'Evidence availability and address-comparability checks.'),

    'evidence.filter.single_engine': _e(
        'Show rows with only a comparable Ghidriff relationship.',
        'Distinguish a single source from cross-engine agreement.',
        'Restricts the table to Single engine rows.',
        'Stored Ghidriff relationships and secondary coverage.'),

    'evidence.filter.agree': _e(
        'Show rows whose comparable engines select the same endpoints.',
        'Inspect the records supporting endpoint agreement.',
        'Restricts the table to Agree rows.',
        'Reconciled address-comparable engine relationships.'),

    'evidence.filter.engine_only': _e(
        'Show secondary records without a covering Ghidriff match.',
        'Review additional relationships separately from primary matches.',
        'Switches the table to Engine-only records.',
        'Stored secondary match sets and primary coverage checks.'),

    'evidence.search': _e(
        'Filter evidence by function name or hexadecimal address.',
        'Locate a function already under investigation.',
        'Narrows visible rows as you type; 0x is optional.',
        'Names and addresses in loaded evidence rows.'),

    'evidence.hide_agreed': _e(
        'Hide rows where comparable engines select matching endpoints.',
        'Concentrate on unresolved or conflicting relationships.',
        'Applies an additional display filter and remembers the choice.',
        'The loaded pairing verdicts.'),

    'evidence.show_index': _e(
        'Show the uncalibrated triage index in row details.',
        'Expose an optional ordering aid with its limits.',
        'Adds the index to details and copied provenance; off by default.',
        'The stored evidence assessment and its ordering rules.'),

    'evidence.copy': _e(
        'Copy provenance for selected evidence rows.',
        'Retain engine values and input identities in research notes.',
        'Copies plain text, limited to 200 rows and 16 KiB.',
        'Selected rows, engine metadata, and recorded artifact hashes.'),

    'evidence.refresh': _e(
        'Reload and reconcile stored engine evidence.',
        'Update the view after relevant project data changes.',
        'Rebuilds the displayed table in the background without writing results.',
        'Current stored Ghidriff and secondary match sets.'),

    'evidence.table': _e(
        'Review function relationships with a separate column for each engine.',
        'Keep each engine value attached to its own measurement.',
        'Selection shows details; Enter navigates and Ctrl+C copies provenance.',
        'Stored engine outputs and derived pairing verdicts.'),

    'evidence.detail': _e(
        'Read native values, alternatives, limits, and provenance for the selected row.',
        'Check how the displayed relationship was assessed.',
        'Shows selectable plain text without editing the result.',
        'The selected evidence row and its supporting engine records.'),

    'evidence.goto': _e(
        'Open the selected primary match in the navigator.',
        'Inspect the code associated with its pairing evidence.',
        'Changes selection; unavailable for stale or engine-only rows.',
        'The selected row and its recorded Ghidriff match identifier.'),

    'evidence.status': _e(
        'Read the current evidence-view status.',
        'Distinguish loaded results from missing or incomplete work.',
        'Displays status text without changing the project.',
        'The evidence view model and loading lifecycle.'),

    'evidence.loading_progress': _e(
        'Read the evidence-loading activity indicator.',
        'Recognize that the panel is preparing its view.',
        'Shows activity without a measured completion total.',
        'The active evidence-loading operation.'),

    'evidence.engines_summary': _e(
        'Read the participating engines and their recorded states.',
        'Check which sources contributed to the displayed view.',
        'Displays engine availability and related warnings.',
        'Loaded engine metadata and evidence warnings.'),

    'evidence.partial_banner': _e(
        'Read which engine results are missing from this view.',
        'Keep incomplete coverage visible during review.',
        'Explains the missing sources; available rows remain reviewable.',
        'The evidence view model and engine outcomes.'),

    'evidence.stale_banner': _e(
        'Read why this evidence describes earlier project inputs.',
        'Avoid applying historical values to the current pair or run.',
        'Disables row activation; copied provenance identifies stale content.',
        'Recorded artifact, run, and project-revision comparisons.'),

    'evidence.footer': _e(
        'Read the interpretation limits of engine-native measurements.',
        'Keep the panel focused on function correspondence.',
        'Displays a persistent explanation; values retain separate units.',
        'The evidence view model interpretation rules.'),

    'evidence.col.match': _e(
        'Read the function name and older-to-newer address relationship.',
        'Identify the exact endpoints being compared.',
        'Selection opens the row details.',
        'The primary match or a separately listed secondary record.'),

    'evidence.col.verdict': _e(
        'Read the derived endpoint-agreement verdict.',
        'Separate agreement, conflict, and unavailable assessment.',
        'Displays the relationship category; sorting changes reading order.',
        'Reconciliation of address-comparable stored engine records.'),

    'evidence.col.ghidriff': _e(
        'Read Ghidriff match types in their original terms.',
        'Identify the primary engine basis for this relationship.',
        'Displays retained match-type text in its own column.',
        'The stored Ghidriff result.'),

    'evidence.col.bindiff': _e(
        'Read BinDiff similarity and its producing algorithm.',
        'Keep the measurement tied to the algorithm that produced it.',
        'Displays BinDiff-native information without combining engine values.',
        'The stored BinDiff match set.'),

    'evidence.col.rzdiff': _e(
        'Read rz-diff raw-byte similarity.',
        'Distinguish byte comparison from other engine measurements.',
        'Displays the retained value in its own units.',
        'The stored rz-diff match set.'),

    'evidence.chip.agree': _e(
        'Comparable engines select the same endpoints as Ghidriff.',
        'Identify endpoint agreement while retaining shared-source limits.',
        'Displays Agree; inspect the supporting records in details.',
        'Reconciled engine relationships; engines can share analysis artifacts.'),

    'evidence.chip.contested': _e(
        'At least one engine selects a different endpoint.',
        'Flag a relationship requiring identity review.',
        'Displays Contested; inspect alternatives before reading the diff.',
        'Conflicting stored engine relationships.'),

    'evidence.chip.single_engine': _e(
        'Only Ghidriff provides a comparable relationship.',
        'Separate single-source evidence from cross-engine agreement.',
        'Displays Single engine; missing records remain unknown.',
        'Ghidriff output and secondary-engine comparability checks.'),

    'evidence.chip.unknown': _e(
        'The available outputs cannot support a cross-engine assessment.',
        'Make the evidence gap explicit.',
        'Displays Unknown without treating missing output as disagreement.',
        'Evidence availability and comparability checks.'),

    'evidence.chip.engine_only': _e(
        'A secondary relationship has no covering Ghidriff match.',
        'Keep additional engine records visible without inventing a primary link.',
        'Displays Engine-only record in its separate result group.',
        'Secondary relationships and primary match coverage.'),

    'evidence.cell.no_record': _e(
        'This engine has no corresponding record for the row.',
        'Separate absent coverage from a conflicting endpoint.',
        'Displays the missing-record state.',
        'The selected engine match set.'),

    'evidence.cell.not_comparable': _e(
        'This engine record cannot be compared on the required address basis.',
        'Explain why a retained value cannot support reconciliation.',
        'Displays the limitation without assigning agreement or conflict.',
        'The engine record and address-basis checks.'),

    'evidence.cell.pairs_elsewhere': _e(
        'This engine links an endpoint to another function.',
        'Locate the alternative underlying a pairing conflict.',
        'Displays the alternative relationship in the row details.',
        'The selected engine relationship and alternative endpoints.'),

    'evidence.cell.not_run': _e(
        'No usable result from this engine is available for the row.',
        'Distinguish unavailable work from a completed assessment.',
        'Displays the missing-result state.',
        'Stored engine status and available match sets.'),

    'evidence.cell.failed': _e(
        'The engine outcome associated with this cell failed.',
        'Identify a source that needs diagnosis before reuse.',
        'Displays the failure state; inspect the Engines tab for details.',
        'The recorded engine outcome.'),

    'evidence.engine_table': _e(
        'Read engine state, version, details, and input identities.',
        'Check which engine results belong to the current investigation.',
        'Selecting an engine shows its available output below.',
        'Stored engine metadata, probes, and current run status.'),

    'evidence.engine_col.name': _e(
        'Identify the engine associated with this status row.',
        'Keep each outcome attached to its producing tool.',
        'Displays the engine label.',
        'The engine registry and recorded outcome.'),

    'evidence.engine_col.state': _e(
        'Read whether this engine is stored, running, missing, or unavailable.',
        'Determine whether usable evidence exists.',
        'Displays the recorded or active lifecycle state.',
        'Stored engine metadata and the current operation.'),

    'evidence.engine_col.version': _e(
        'Read the available version of the selected engine.',
        'Relate results and compatibility checks to a specific tool version.',
        'Displays recorded version text.',
        'The explicit engine probe or stored result metadata.'),

    'evidence.engine_col.detail': _e(
        'Read the engine outcome or capability explanation.',
        'Understand a failed, cancelled, or unsupported state.',
        'Displays the retained explanatory text.',
        'The engine capability check and recorded outcome.'),

    'evidence.engine_col.hashes': _e(
        'Read the input hashes associated with the engine result.',
        'Check that the result refers to the intended older and newer files.',
        'Displays recorded identities; details retain the available full values.',
        'Engine result metadata and project artifact identities.'),

    'evidence.engine_check': _e(
        'Include this secondary engine in the next requested run.',
        'Choose which additional evidence to compute.',
        'Changes the next-run selection; execution requires Run selected engines.',
        'The probed engine capability and current selection.'),

    'evidence.engine_check.bindiff': _e(
        'Include BinDiff in the next selected-engine run.',
        'Compute relationships from the accepted BinExport pair.',
        'Selects BinDiff after its executable and inputs meet prerequisites.',
        'Explicit BinDiff probing and BinExport validation.'),

    'evidence.engine_check.rzdiff': _e(
        'Include rz-diff in the next selected-engine run.',
        'Add a separate raw-byte comparison result.',
        'Selects rz-diff after its capability check succeeds.',
        'The explicit rz-diff probe and current run configuration.'),

    'evidence.parallel': _e(
        'Choose one or two simultaneous secondary engines.',
        'Balance concurrent work against resource use.',
        'Applies to the next run.',
        'The secondary-engine scheduler configuration.'),

    'evidence.timeout': _e(
        'Set the per-engine limit from 60 to 86400 seconds.',
        'Bound the duration of an additional engine attempt.',
        'Applies to the next run; a timed-out attempt publishes no result.',
        'The secondary-engine run configuration.'),

    'evidence.probe': _e(
        'Explicitly check installed secondary-engine capabilities.',
        'Find whether the configured tools meet the run requirements.',
        'Runs the supported tool checks without analyzing target inputs.',
        'The configured external tool executables.'),

    'evidence.run': _e(
        'Run the selected supported secondary engines.',
        'Add separate function-pairing evidence for the current artifacts.',
        'Runs local tools; completed results can be retained if another fails.',
        'Project-owned artifacts, accepted exports, and selected engine options.'),

    'evidence.cancel': _e(
        'Request cancellation of the active secondary-engine run.',
        'Stop additional analysis that is no longer needed.',
        'Stops unfinished engine work; already completed outcomes can remain.',
        'The active scheduler operation and its engine processes.'),

    'evidence.import_bindiff': _e(
        'Import an existing BinDiff result for this artifact pair.',
        'Review a comparison produced outside the current run.',
        'Validates the result and stores an accepted secondary match set.',
        'The selected .BinDiff file and project artifact identities.'),

    'evidence.run_preview': _e(
        'Read the selected engines and inputs for the pending run.',
        'Check what the run action will use before starting.',
        'Displays the current request summary without launching tools.',
        'Selected engine options and recorded input identities.'),

    'evidence.run_status': _e(
        'Read the current secondary-engine operation status.',
        'Follow probing, execution, cancellation, and completion.',
        'Displays lifecycle updates without changing the selected options.',
        'The active engine operation and delivered outcomes.'),

    'evidence.run_progress': _e(
        'Read the secondary-engine activity indicator.',
        'Recognize ongoing work when a measured total is unavailable.',
        'Shows activity while the engine operation remains active.',
        'The current secondary-engine job.'),

    'evidence.engine_log': _e(
        'Read the selected engine output tail as plain text.',
        'Inspect diagnostic output for the selected outcome.',
        'Shows at most the retained 200-line tail.',
        'Output captured from the selected engine operation.'),

    'evidence.copy_details': _e(
        'Copy the selected failed or cancelled engine details.',
        'Preserve an actionable record for diagnosis.',
        'Writes available error, version, identity, and output details to the clipboard.',
        'The selected engine outcome and retained log tail.'),

    'evidence.run_note': _e(
        'Read how secondary engines handle the selected input material.',
        'Distinguish analysis-tool execution from target execution.',
        'Displays the local processing explanation.',
        'The documented secondary-engine runner contract.'),

    'evidence.engine_state.baseline': _e(
        'Ghidriff supplies the baseline comparison for this view.',
        'Identify the reference used during secondary reconciliation.',
        'Displays Baseline; this is not a new engine request.',
        'The project completed Ghidriff run.'),

    'evidence.engine_state.ready': _e(
        'A stored result from this engine is available.',
        'Identify retained output that can contribute to the view.',
        'Displays Ready with its recorded version and inputs.',
        'The accepted stored engine match set.'),

    'evidence.engine_state.not_run': _e(
        'This engine has not supplied a usable current result.',
        'Keep missing work separate from endpoint disagreement.',
        'Displays Not run.',
        'The current engine status and available stored sets.'),

    'evidence.engine_state.queued': _e(
        'The engine is waiting for its scheduled run.',
        'Distinguish waiting from active analysis.',
        'Displays Queued until work starts or is cancelled.',
        'The active secondary-engine scheduler.'),

    'evidence.engine_state.running': _e(
        'The selected engine is currently running.',
        'Identify which tool is consuming analysis time.',
        'Displays Running while the attempt remains active.',
        'The active engine operation.'),

    'evidence.engine_state.failed': _e(
        'The engine attempt ended without an accepted result.',
        'Direct diagnosis to the failed source.',
        'Displays Failed; select the row to inspect available details.',
        'The recorded engine failure outcome.'),

    'evidence.engine_state.cancelled': _e(
        'The engine attempt was cancelled.',
        'Distinguish interrupted work from a completed comparison.',
        'Displays Cancelled without treating unfinished output as a result.',
        'The engine cancellation outcome.'),

    'evidence.engine_state.unsupported': _e(
        'This engine configuration does not meet the current requirements.',
        'Identify a setup or compatibility limit before starting.',
        'Displays Unsupported with the available reason.',
        'The explicit capability check or recorded engine status.'),

    'evidence.engine_state.stale': _e(
        'This stored engine result describes earlier inputs.',
        'Keep historical output distinct from current evidence.',
        'Displays Stale and retains the recorded identities.',
        'Stored engine metadata compared with current project inputs.'),

    'evidence.state.no_project': _e(
        'Open a project before reviewing engine evidence.',
        'Associate the panel with a specific binary pair.',
        'Shows the prerequisite message without starting work.',
        'The current project availability.'),

    'evidence.state.no_engines': _e(
        'No secondary results are available for cross-engine comparison.',
        'Explain why Ghidriff is the only comparable source.',
        'Offers the Engines setup route; missing output is not disagreement.',
        'The loaded secondary-engine inventory.'),

    'evidence.state.loading': _e(
        'The panel is loading its first evidence view.',
        'Distinguish pending content from an empty comparison.',
        'Shows loading activity until a result or error arrives.',
        'The current evidence-loading task.'),

    'evidence.state.refreshing': _e(
        'The panel is rebuilding its view from stored results.',
        'Identify a pending update to already displayed evidence.',
        'Retains lifecycle feedback while the refresh runs.',
        'The active evidence refresh task.'),

    'evidence.state.ready': _e(
        'The current evidence view is ready to inspect.',
        'Identify completion of the view preparation.',
        'Enables the applicable review controls.',
        'The completed evidence-loading result.'),

    'evidence.state.partial': _e(
        'Some engines did not supply usable results.',
        'Preserve the distinction between incomplete coverage and conflict.',
        'Shows available evidence and identifies missing sources.',
        'Loaded engine outcomes and evidence coverage.'),

    'evidence.state.failed': _e(
        'The evidence view could not be assembled.',
        'Identify a failed preparation rather than an empty result.',
        'Shows an error and leaves stored Ghidriff results unchanged.',
        'The evidence-loading failure.'),

    'evidence.state.stale': _e(
        'The displayed evidence belongs to earlier project inputs.',
        'Keep historical values from being read as current.',
        'Retains reference content and disables row activation until refreshed.',
        'Artifact, run, and project-revision checks.'),

    'evidence.state.unsupported': _e(
        'The available configuration cannot provide this evidence view.',
        'Expose the capability limit that blocks assessment.',
        'Shows the reason and the available setup route.',
        'The evidence capability assessment.'),

    'evidence.state.too_large': _e(
        'The result exceeds the displayed-row limit.',
        'Explain why the full table is not shown.',
        'Requests a narrower filter instead of displaying an unbounded table.',
        'The evidence row count and display ceiling.'),

    'evidence.state.retry': _e(
        'Retry loading the Engine evidence view.',
        'Repeat preparation after addressing the reported failure.',
        'Starts another view-load attempt without running comparison engines.',
        'Current stored comparison and secondary results.'),

    'evidence.state.copy': _e(
        'Copy the Engine evidence loading error details.',
        'Preserve the failure information for diagnosis.',
        'Writes the available diagnostic text to the clipboard.',
        'The current evidence-view error report.'),

    'evidence.state.setup': _e(
        'Open the Engines tab from the evidence state message.',
        'Reach setup controls when secondary results are unavailable.',
        'Changes the visible tab without starting an engine.',
        'The Engine evidence panel navigation.'),

    # Panel-prefixed copy for the existing embedded BinDiff setup.
    # Planned binding migration from the current engine_setup.* IDs.

    'evidence.setup.toggle': _e(
        'Show or hide the embedded BinDiff setup.',
        'Reach executable and export checks from the Engines tab.',
        'Changes the section visibility and remembers that preference.',
        'The embedded BinDiff setup panel.'),

    'evidence.setup.section': _e(
        'Configure BinDiff and the older and newer BinExport inputs.',
        'Collect the prerequisites for a BinDiff run.',
        'Enables selection only after the executable and inputs pass checks.',
        'The chosen executable, exports, and project artifact identities.'),

    'evidence.setup.bindiff_path': _e(
        'Choose the exact BinDiff executable by absolute path.',
        'Make the program used by explicit checks unambiguous.',
        'Changing the path clears its checked state; a successful probe remembers it.',
        'Your selected path and local installation suggestions; PATH is not searched.'),

    'evidence.setup.bindiff_browse': _e(
        'Browse for the BinDiff executable.',
        'Select an installed program without typing its path.',
        'Fills the executable field without running the program.',
        'The local file selected in the picker.'),

    'evidence.setup.bindiff_probe': _e(
        'Explicitly check the chosen BinDiff version and required options.',
        'Determine whether the executable supports the requested integration.',
        'Runs version and help checks in a private working directory.',
        'The selected executable and PatchTrace capability requirements.'),

    'evidence.setup.probe_status': _e(
        'Read the outcome of the explicit BinDiff probe.',
        'Distinguish a selected path from a checked executable.',
        'Displays compatibility and version information.',
        'The completed BinDiff capability probe.'),

    'evidence.setup.older_binexport': _e(
        'Choose the BinExport produced from the older project artifact.',
        'Keep BinDiff primary input aligned with comparison direction.',
        'Changing the path clears prior validation and unbound acceptance.',
        'Your selected older export and the project older-artifact identity.'),

    'evidence.setup.older_browse': _e(
        'Browse for the older BinExport file.',
        'Select the intended older-side export.',
        'Fills the path field; validation remains a separate action.',
        'The local export selected in the picker.'),

    'evidence.setup.newer_binexport': _e(
        'Choose the BinExport produced from the newer project artifact.',
        'Keep BinDiff secondary input aligned with comparison direction.',
        'Changing the path clears prior validation and unbound acceptance.',
        'Your selected newer export and the project newer-artifact identity.'),

    'evidence.setup.newer_browse': _e(
        'Browse for the newer BinExport file.',
        'Select the intended newer-side export.',
        'Fills the path field; validation remains a separate action.',
        'The local export selected in the picker.'),

    'evidence.setup.accept_unbound': _e(
        'Assert that exports without usable SHA-256 identities belong to this pair.',
        'Support exporters whose identifiers cannot establish artifact binding.',
        'Records your assertion for validation and the next run; conflicting SHA-256 is refused.',
        'Your explicit assertion; it resets when relevant inputs change.'),

    'evidence.setup.unbound_warning': _e(
        'Read the limits of accepting exports without SHA-256 binding.',
        'Keep an analyst assertion distinct from a matching artifact identity.',
        'Displays the explanation without accepting any export.',
        'The BinExport identity-validation rules.'),

    'evidence.setup.validate': _e(
        'Validate both selected exports against the project pair.',
        'Catch malformed, foreign, swapped, or oversized exports before a run.',
        'Runs isolated bounded checks and reports the accepted binding basis.',
        'Selected BinExport bytes and recorded project artifact identities.'),

    'evidence.setup.validation_status': _e(
        'Read the current BinExport validation outcome.',
        'Check whether both inputs are eligible for the next run.',
        'Displays counts, architecture, binding, or rejection information.',
        'The isolated export checks and pair-binding assessment.'),

    'evidence.setup.cancel_validation': _e(
        'Stop the active BinExport validation.',
        'End a check that is no longer needed.',
        'Stops the checker and leaves the selected inputs unvalidated.',
        'The active isolated validation operation.'),

    'evidence.setup.show_details': _e(
        'Show or hide technical setup details.',
        'Inspect exact codes and identities behind the summary.',
        'Changes the read-only details area visibility.',
        'BinDiff probing and BinExport validation records.'),

    'evidence.setup.details': _e(
        'Read setup codes, failure categories, and checked hashes.',
        'Retain precise diagnostic values when reporting a setup problem.',
        'Shows selectable plain text without launching another check.',
        'The recorded probe and validation outcomes.'),
}


EVIDENCE_TOOLTIP_TEMPLATES = {
    'evidence.row': _e(
        'Engine evidence for {function}.',
        'Review the {verdict} relationship and its available sources.',
        'Select the row to inspect its details.',
        'Engines: {engines}. Address context: {reason}.'),

    'evidence.cell': _e(
        '{engine} value: {value}. Unit: {unit}.',
        'Keep this measurement attached to its producing engine.',
        'Read the selected-row details for limitations.',
        '{provenance}. Details: {reason}.'),

    'evidence.badge': _e(
        '{verdict}: {meaning}',
        'Interpret the label as a function-pairing assessment.',
        'Read-only; inspect supporting endpoints before drawing a conclusion.',
        'Reconciled engine records. Reason: {reason}.'),

    'evidence.engine_row': _e(
        '{engine} state: {state}.',
        'Inspect the recorded availability and outcome.',
        'Select the row to read its available output.',
        'Input hashes: {hashes}. Details: {detail}.'),
}
