"""Proposed Capabilities panel tooltip copy.

PLANNED: follows the CAP integration plan.
The panel declaration was unavailable during review.
Implemented behavior and packaged Windows availability are UNVERIFIED.

Sources:
- docs/specs/program-e/CAP-integration-plan.md, sections 7-8
- src/patchtrace/panel_manifest.py

Additional IDs require explicit bindings to documented controls and fields.
The central manifest determines final dock placement.

Capability recognition, function identity, and code-change purpose remain separate.
Counts describe recognized changes, not assessed defects.
Moved labels identify candidates rather than established relocation.

Download facts must come from the selected release pin at runtime.
This copy does not hard-code a current download URL, size, or digest.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


CAPABILITIES_TOOLTIPS = {
    'capabilities.dock': _e(
        'Compare behaviors recognized by capa in the older and newer files.',
        'Inspect recognition changes beside the function comparison.',
        'Shows stored results without automatically running capa.',
        'Stored capa evidence, coverage, and recorded function pairings.'),

    'capabilities.action': _e(
        'Show or hide the Capabilities panel.',
        'Keep recognized-behavior context beside the code.',
        'Toggles the dock; shortcut Ctrl+Shift+A.',
        'The planned panel command and central manifest.'),

    'capabilities.tabs': _e(
        'Switch between Changes and Setup and run.',
        'Separate review of stored results from explicit tool execution.',
        'Changes the visible tab without starting capa.',
        'The Capabilities panel layout.'),

    'capabilities.tab.changes': _e(
        'Open the capability-change review.',
        'Inspect paired recognition results and their limits.',
        'Shows filters, grouped rows, and selected-row details.',
        'The derived capa-pairs result.'),

    'capabilities.tab.setup': _e(
        'Open capa configuration and run controls.',
        'Review the executable and options before requesting analysis.',
        'Shows setup controls without probing or running automatically.',
        'The configured tool candidate and requested run options.'),

    'capabilities.filter': _e(
        'Choose which capability-change classes to display.',
        'Focus on gained, lost, moved, unchanged, or unassessed recognition.',
        'Filters visible rows without changing stored evidence.',
        'The derived capability-change records.'),

    'capabilities.filter.changes': _e(
        'Show gained, lost, and moved recognition changes.',
        'Start with the documented default review population.',
        'Restricts the table to the selected change classes.',
        'Comparable capability records and delta rules.'),

    'capabilities.filter.gained': _e(
        'Show recognition classified as gained.',
        'Inspect where the newer side has qualifying recognition.',
        'Filters to Gained rows within the recorded evaluation coverage.',
        'Per-side presence and function-evaluation records.'),

    'capabilities.filter.lost': _e(
        'Show recognition classified as lost.',
        'Inspect where the older side has qualifying recognition.',
        'Filters to Lost rows within the recorded evaluation coverage.',
        'Per-side presence and function-evaluation records.'),

    'capabilities.filter.moved': _e(
        'Show candidate recognition moves between function groups.',
        'Investigate whether a behavior shifted rather than appeared or disappeared.',
        'Filters to Moved candidates.',
        'Matching rule-and-scope gains and losses in different eligible groups.'),

    'capabilities.filter.unchanged': _e(
        'Show recognition retained on both compared sides.',
        'Inspect shared capability recognition without assuming identical code.',
        'Requests unchanged rows as well as their retained count.',
        'Comparable per-side capability evidence.'),

    'capabilities.filter.not_compared': _e(
        'Show observations without a usable cross-side comparison.',
        'Keep incomplete evaluation visible.',
        'Filters to Not compared rows.',
        'Function coverage, side availability, and comparability checks.'),

    'capabilities.filter.all': _e(
        'Show all supported capability-change classes.',
        'Review the available population together.',
        'Includes eligible classes subject to the remaining display filters.',
        'The derived capability result and display query.'),

    'capabilities.group_by': _e(
        'Choose how capability rows are grouped.',
        'Organize review by namespace, function pair, or emitted taxonomy label.',
        'Changes presentation without changing recognition or comparison results.',
        'Stored namespaces, function groups, and capa-emitted labels.'),

    'capabilities.group.namespace': _e(
        'Group by the first two capability-namespace components.',
        'Read related rule families together.',
        'Changes grouping; namespace is the default.',
        'The namespaces emitted with capa rule results.'),

    'capabilities.group.function': _e(
        'Group by the recorded function pair.',
        'Read recognized changes alongside their code relationship.',
        'Changes grouping without correcting any function match.',
        'The current function-group mapping.'),

    'capabilities.group.attack': _e(
        'Group by ATT&CK tactic labels emitted by capa.',
        'Browse the supplied taxonomy without treating it as an intent assessment.',
        'Changes grouping using available emitted labels.',
        'Taxonomy labels retained from capa output.'),

    'capabilities.group.mbc': _e(
        'Group by MBC objective labels emitted by capa.',
        'Browse the supplied classification as rule metadata.',
        'Changes grouping without changing code interpretation.',
        'Taxonomy labels retained from capa output.'),

    'capabilities.group.none': _e(
        'Show eligible capability rows without group headings.',
        'Read the selected population as one list.',
        'Changes presentation without changing the underlying result.',
        'The current filtered capability rows.'),

    'capabilities.search': _e(
        'Filter capabilities by rule, namespace, or function text.',
        'Locate a recognition already under investigation.',
        'Narrows visible rows without rerunning capa.',
        'The loaded row labels and recorded function names.'),

    'capabilities.show_noise': _e(
        'Include detection differences in the displayed rows.',
        'Inspect recognition changes associated with unchanged function pairs.',
        'Reveals the labelled observations without presenting them as new code.',
        'Recorded pairing categories and detection-difference flags.'),

    'capabilities.show_unattributed': _e(
        'Include observations not attributed to a function pair.',
        'Keep file-level or unresolved recognition available for review.',
        'Shows separate unattributed observations without inventing a function link.',
        'Stored attribution states and their reasons.'),

    'capabilities.show_library': _e(
        'Include building-block rule observations.',
        'Inspect supporting rule recognition normally omitted from the main view.',
        'Changes visible rule kinds without rerunning capa.',
        'Rule-kind metadata retained with the capability evidence.'),

    'capabilities.table': _e(
        'Read grouped capability recognition across function pairs.',
        'Compare side states before interpreting a change label.',
        'Selection opens details; Enter opens an available function pair.',
        'The derived capa-pairs result and current grouping.'),

    'capabilities.summary': _e(
        'Read change counts and the evaluated-pair coverage.',
        'Distinguish recognized changes from the population actually compared.',
        'Displays gained, lost, moved, unchanged, and not-compared totals.',
        'The capability delta counts and CoverageSummary.'),

    'capabilities.flags': _e(
        'Read tool and build-context cautions affecting this comparison.',
        'Identify conditions that can distort recognition or attribution.',
        'Displays the recorded flags without assigning a cause to each row.',
        'Retained capa and build-context quality flags.'),

    'capabilities.detail': _e(
        'Read the selected change, matched features, cautions, and provenance.',
        'Check the observations behind the recognition label.',
        'Displays selectable plain text without editing the result.',
        'The selected capability row and retained evidence.'),

    'capabilities.goto': _e(
        'Open the selected capability row at its available function pair.',
        'Inspect the code associated with the recognition.',
        'Navigates only when the row supplies a usable match reference.',
        'The selected row match identifier and current project records.'),

    'capabilities.copy': _e(
        'Copy the selected capability change with provenance.',
        'Retain the rule, side states, and source identities in research notes.',
        'Writes bounded plain text to the clipboard, up to 16 KiB.',
        'The selected change and its tool, rule, artifact, and run metadata.'),

    'capabilities.refresh': _e(
        'Re-read saved capa output and rebuild its comparison view.',
        'Recover coverage information or update the derived presentation.',
        'Parses retained output without running capa again.',
        'Stored capa output, current parser, and current pairing records.'),

    'capabilities.retry': _e(
        'Retry assembling the capability comparison.',
        'Repeat preparation after addressing the reported cause.',
        'Rebuilds from available stored results without an automatic tool run.',
        'The current evidence inputs and retained assembly failure.'),

    'capabilities.copy_error': _e(
        'Copy capability-operation error details.',
        'Preserve the reported code and message for diagnosis.',
        'Writes available plain-text diagnostics to the clipboard.',
        'The retained capability failure report.'),

    'capabilities.stale_banner': _e(
        'Read why the displayed capability evidence belongs to earlier inputs.',
        'Keep historical recognition separate from the current pair or setup.',
        'Displays the stale reason and the appropriate refresh or rerun guidance.',
        'Artifact, analysis, executable, rules, and option identity checks.'),

    'capabilities.footer': _e(
        'Read the limits of behavior recognition.',
        'Keep recognized patterns separate from code purpose and intent.',
        'Displays persistent guidance; matching rules do not establish why a change exists.',
        'The capability-comparison interpretation contract.'),

    # Columns.

    'capabilities.col.capability': _e(
        'Read the rule-associated capability name.',
        'Identify which recognition is being compared.',
        'Displays the retained label without interpreting it as a conclusion.',
        'The capa rule identifier and emitted name.'),

    'capabilities.col.older': _e(
        'Read recognition and evaluation state for the older function group.',
        'Check baseline coverage before interpreting a loss or gain.',
        'Displays presence, match count, or the reason evaluation is unavailable.',
        'Older-side capability evidence and function coverage.'),

    'capabilities.col.newer': _e(
        'Read recognition and evaluation state for the newer function group.',
        'Check later-build coverage before interpreting a loss or gain.',
        'Displays presence, match count, or the reason evaluation is unavailable.',
        'Newer-side capability evidence and function coverage.'),

    'capabilities.col.change': _e(
        'Read the derived capability-change label.',
        'Separate recognized differences from unassessed observations.',
        'Displays a word and glyph for the recorded class.',
        'Comparable side states and capability-delta rules.'),

    'capabilities.col.function_pair': _e(
        'Read the older and newer function-group relationship.',
        'Inspect identity and category before assigning meaning to recognition.',
        'Displays retained endpoints without changing their pairing.',
        'The project matches and supported raw pairing records.'),

    # Per-side cell states.

    'capabilities.cell.present': _e(
        'capa reported this capability in the evaluated function group.',
        'Inspect the features that produced the recognition.',
        'Displays Present with the retained match count.',
        'The side capability evidence and associated feature references.'),

    'capabilities.cell.absent': _e(
        'The function group was evaluated without this capability recognition.',
        'Distinguish completed non-recognition from skipped analysis.',
        'Displays Absent within the evaluated rule and function coverage.',
        'FunctionCoverage and the side capability result.'),

    'capabilities.cell.library': _e(
        'capa did not evaluate this function because it was classified as a library routine.',
        'Keep skipped evaluation separate from an absent capability.',
        'Displays Not evaluated with the library reason.',
        'The tool function-coverage classification.'),

    'capabilities.cell.not_found': _e(
        'capa did not recover the function needed for this comparison.',
        'Keep missing function evaluation visible.',
        'Displays Not evaluated rather than Absent.',
        'The project function reference and capa recovery coverage.'),

    'capabilities.cell.no_function': _e(
        'This relationship has no function on the selected side.',
        'Distinguish an added or removed group from a skipped evaluation.',
        'Displays No function.',
        'The recorded relationship category and side membership.'),

    # Change chips.

    'capabilities.change.gained': _e(
        'capa recognizes this rule on the newer side under comparable evaluation.',
        'Inspect the matching features on both sides before explaining the difference.',
        'Displays Gained only when the side-evaluation requirements are met.',
        'Comparable rule identity, function coverage, and presence states.'),

    'capabilities.change.lost': _e(
        'capa recognizes this rule on the older side under comparable evaluation.',
        'Inspect whether the recognized behavior changed or moved.',
        'Displays Lost only when the side-evaluation requirements are met.',
        'Comparable rule identity, function coverage, and presence states.'),

    'capabilities.change.moved': _e(
        'The same rule and scope have eligible gains and losses in different groups.',
        'Investigate a possible move between functions.',
        'Displays Moved as a candidate relationship.',
        'Cross-group capability-delta pairing rules.'),

    'capabilities.change.same': _e(
        'capa recognizes this capability on both compared sides.',
        'Keep shared recognition distinct from identical code.',
        'Displays Same without asserting function-body equality.',
        'Comparable per-side rule observations.'),

    'capabilities.change.not_compared': _e(
        'The available observations do not support a cross-side capability comparison.',
        'Keep missing evaluation distinct from a change.',
        'Displays Not compared.',
        'Coverage, comparability, and function-group checks.'),

    'capabilities.change.detection_difference': _e(
        'Recognition differs within a function pair categorized as unchanged.',
        'Inspect analysis variation before attributing the difference to code.',
        'Displays a detection-difference flag rather than a new-code label.',
        'The function-pair category and per-side capa observations.'),

    # Unattributed observations.

    'capabilities.unattributed.file': _e(
        'This recognition has file scope rather than function-pair attribution.',
        'Keep whole-file context separate from a particular changed function.',
        'Displays the observation without assigning it to a pair.',
        'The rule scope and retained file-level evidence.'),

    'capabilities.unattributed.instruction': _e(
        'This instruction-scope observation lacks supported function attribution.',
        'Inspect the retained location without assuming a containing function.',
        'Displays the unattributed reason.',
        'The emitted scope, location, and attribution checks.'),

    'capabilities.unattributed.basic_block': _e(
        'This basic-block observation lacks the layout needed for function attribution.',
        'Keep incomplete address context visible.',
        'Displays the observation without guessing its function.',
        'The emitted basic-block scope and available layout data.'),

    'capabilities.unattributed.address': _e(
        'The observation address was rejected for attribution.',
        'Avoid assigning a malformed or incompatible location to code.',
        'Displays the rejection reason and available source context.',
        'The recorded address-basis and attribution checks.'),

    # Detail sections.

    'capabilities.detail.change': _e(
        'Read the capability-change explanation.',
        'Understand the side states behind the displayed label.',
        'Displays the fixed explanation without requesting model interpretation.',
        'The selected change record and teaching templates.'),

    'capabilities.detail.where': _e(
        'Read the function group, match identity, and relationship category.',
        'Check where the recognition is attributed.',
        'Displays available endpoints and pairing context.',
        'The selected PairGroup record.'),

    'capabilities.detail.older': _e(
        'Read the older-side recognition details.',
        'Inspect its function coverage and retained matches.',
        'Displays the baseline evidence without rerunning capa.',
        'The older PairCell and source evidence.'),

    'capabilities.detail.newer': _e(
        'Read the newer-side recognition details.',
        'Inspect its function coverage and retained matches.',
        'Displays the later-build evidence without rerunning capa.',
        'The newer PairCell and source evidence.'),

    'capabilities.detail.features': _e(
        'Read the retained features that made capa match.',
        'Check whether the recognized pattern is relevant to the code under review.',
        'Displays up to 16 retained feature references per side with redaction.',
        'Successful rule-feature references kept from capa output.'),

    'capabilities.detail.rule': _e(
        'Read the rule namespace, scope, identity, and kind.',
        'Check that the two sides use comparable recognition rules.',
        'Displays retained metadata and the available rule digest prefix.',
        'The rule evidence and pinned or custom rules identity.'),

    'capabilities.detail.labels': _e(
        'Read ATT&CK or MBC labels emitted with the rule.',
        'Interpret them as rule metadata and optional grouping aids.',
        'Displays retained labels without assigning code intent.',
        'Taxonomy labels present in capa output.'),

    'capabilities.detail.cautions': _e(
        'Read limits affecting recognition or pairing.',
        'Keep skipped functions, build context, and source restrictions visible.',
        'Displays the retained cautions.',
        'The delta flags, coverage summary, and source metadata.'),

    'capabilities.detail.next_steps': _e(
        'Read suggested inspection steps for this recognition state.',
        'Choose a concrete way to compare code and matching features.',
        'Displays fixed guidance without executing a command.',
        'The capability teaching templates.'),

    'capabilities.detail.provenance': _e(
        'Read tool, rules, backend, input, and run identities.',
        'Retain the basis of this capability comparison.',
        'Displays available version and digest information.',
        'The source tool runs, manifests, and comparison records.'),

    # Setup and run.

    'capabilities.path': _e(
        'Select the exact capa executable used for explicit checks and runs.',
        'Identify the installed analysis program.',
        'Changes the candidate path; a successful explicit probe remembers it.',
        'Your selected executable or bounded local installation suggestions.'),

    'capabilities.browse': _e(
        'Browse for the capa executable.',
        'Select an installed program without typing its path.',
        'Fills the executable field without launching it.',
        'The local file chosen in the picker.'),

    'capabilities.probe': _e(
        'Explicitly check the selected capa executable.',
        'Determine its supported version, rules, and capability status.',
        'Runs the documented probe without analyzing the project artifacts.',
        'The selected executable and integration requirements.'),

    'capabilities.probe_status': _e(
        'Read capa version and compatibility status.',
        'Distinguish a selected executable from a checked configuration.',
        'Displays the probe result and pin status.',
        'The explicit capa probe.'),

    'capabilities.pin': _e(
        'Read the release URL, size, and digest from the selected capa pin.',
        'Check manually obtained tool files against the documented release identity.',
        'Displays release facts without downloading anything.',
        'The runtime-selected tool pin metadata.'),

    'capabilities.backend': _e(
        'Choose the supported capa analysis backend.',
        'Make the analysis method explicit before running.',
        'Changes the requested backend; unavailable choices remain explained.',
        'The supported capa backends and explicit dependency checks.'),

    'capabilities.backend.vivisect': _e(
        'Select the vivisect backend for capa.',
        'Use the documented default analysis method.',
        'Sets the next-run backend without starting it.',
        'The capa runner and selected executable capabilities.'),

    'capabilities.backend.ghidra': _e(
        'Select the Ghidra backend when its dependencies meet the requirements.',
        'Use the alternative supported analysis method.',
        'Requires a probed Ghidra directory and compatible Java configuration.',
        'The explicit dependency probes and selected backend requirements.'),

    'capabilities.rules': _e(
        'Read or explicitly choose the rule-set identity for the run.',
        'Keep recognition consistent across the two files.',
        'Uses embedded rules by default; custom rules are an explicit advanced choice.',
        'The executable-embedded rules or selected custom-folder digest.'),

    'capabilities.rules.embedded': _e(
        'Use the rules embedded in the selected capa executable.',
        'Tie default recognition to a recorded executable identity.',
        'Selects the embedded rule set without fetching updates.',
        'The selected executable SHA-256 and embedded-rule label.'),

    'capabilities.rules.custom': _e(
        'Use an explicitly selected custom rules folder.',
        'Make a deliberate alternative rule set reproducible.',
        'Copies rules into run scratch and records their digest; rule text is not reviewed.',
        'The selected folder, tree digest, and capa-major compatibility checks.'),

    'capabilities.timeout': _e(
        'Set the per-file capa time limit from 10 to 86400 seconds.',
        'Bound each requested analysis attempt.',
        'Applies to the next run; the documented default is 1800 seconds per file.',
        'The tool-run request options.'),

    'capabilities.preview': _e(
        'Read the exact capa run request before starting.',
        'Check executable, rules, backend, inputs, and limits.',
        'Displays the request without launching capa.',
        'The prepared tool-run plan and artifact identities.'),

    'capabilities.run': _e(
        'Run capa on the older and newer files after reviewing the request.',
        'Create comparable recognized-behavior evidence.',
        'Starts the selected local tool; targets are not started by Windows and nothing is uploaded.',
        'The reviewed executable, rules, backend, options, and artifact copies.'),

    'capabilities.cancel': _e(
        'Request cancellation of the active capa run.',
        'Stop tool work that is no longer needed.',
        'Stops through the runner lifecycle without accepting cancelled output.',
        'The active capa operation and its child process.'),

    'capabilities.progress': _e(
        'Read the active artifact side and elapsed run progress.',
        'Follow analysis when a completion total is unavailable.',
        'Displays operation activity without inventing a completion fraction.',
        'The tool-run lifecycle and progress messages.'),

    'capabilities.log': _e(
        'Read the bounded capa operation log.',
        'Inspect diagnostics for the current or retained attempt.',
        'Displays plain text with a retained 200-line limit.',
        'The selected tool operation output and status records.'),

    # States C0-C13.

    'capabilities.state.no_project': _e(
        'Open a project before comparing capabilities.',
        'Associate the view with a specific artifact pair.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'capabilities.state.not_configured': _e(
        'capa is not configured for this application.',
        'Identify the separate tool required for capability recognition.',
        'Shows manual setup guidance without downloading the program.',
        'The configured-tool inventory and supported integration baseline.'),

    'capabilities.state.no_results': _e(
        'No capa results are stored for this project pair.',
        'Distinguish missing analysis from completed non-recognition.',
        'Directs you to Setup and run.',
        'The stored tool-evidence inventory.'),

    'capabilities.state.running': _e(
        'capa is analyzing the displayed artifact side.',
        'Follow which part of the pair is being processed.',
        'Displays activity and offers cancellation.',
        'The active tool-run lifecycle.'),

    'capabilities.state.ready': _e(
        'The capability comparison is ready to inspect.',
        'Identify completion of the current view preparation.',
        'Displays rows, summary, and selected details.',
        'The derived comparison and its coverage records.'),

    'capabilities.state.side_incomplete': _e(
        'One artifact side did not finish analysis.',
        'Avoid treating missing output as no recognized capabilities.',
        'Shows the reason without presenting a complete cross-side comparison.',
        'The per-side tool outcomes.'),

    'capabilities.state.assembly_failed': _e(
        'Stored capability results could not be assembled into the view.',
        'Identify a preparation error separately from a tool recognition result.',
        'Shows the error while retaining stored capa results.',
        'The comparison assembly failure.'),

    'capabilities.state.stale': _e(
        'These results describe another pair, setup, or analysis context.',
        'Keep historical recognition distinct from current review.',
        'Retains reference values and explains the required refresh or rerun.',
        'The recorded input and tool identities.'),

    'capabilities.state.pairing_unavailable': _e(
        'No completed comparison supplies usable function pairing.',
        'Keep per-side recognition separate from function-level change claims.',
        'Shows available side totals without assigning changes to function pairs.',
        'The project comparison inventory and tool evidence.'),

    'capabilities.state.no_changes': _e(
        'capa recognizes the same behaviors in the compared functions.',
        'Keep unchanged recognition distinct from identical code.',
        'Displays the outcome within the evaluated rule and function coverage.',
        'The comparable capability records and coverage summary.'),

    'capabilities.state.tool_unusable': _e(
        'The configured capa executable cannot be used.',
        'Identify the probe reason before requesting a run.',
        'Shows the capability failure without starting analysis.',
        'The explicit tool probe result.'),

    'capabilities.state.too_many_rows': _e(
        'The comparison exceeds the supported display population.',
        'Explain why a narrower view is required.',
        'Requests narrower filters instead of building an unbounded table.',
        'The capability row count and display ceiling.'),

    'capabilities.state.truncated': _e(
        'Only part of the reported capability observations was retained.',
        'Keep incomplete coverage visible.',
        'Shows reported and retained counts without implying a complete list.',
        'The parser limits and tool-output coverage record.'),

    'capabilities.state.coverage_refresh': _e(
        'Stored evidence predates the coverage fields required by this panel.',
        'Recover evaluation context before interpreting side absence.',
        'Offers Refresh to re-read saved output without running capa again.',
        'The stored evidence schema and available raw sidecar.'),

    'capabilities.state.cancelled': _e(
        'The capa operation was cancelled.',
        'Distinguish interrupted work from a completed recognition result.',
        'Retains earlier accepted evidence without publishing unfinished output.',
        'The runner cancellation outcome.'),

    'capabilities.state.no_visible_rows': _e(
        'No rows pass the current capability filters.',
        'Distinguish a filtered view from an empty tool result.',
        'Requests broader display options without rerunning analysis.',
        'The loaded comparison and active filter settings.'),

    'capabilities.state.rules_mismatch': _e(
        'The two sides do not use the required identical rule identity.',
        'Prevent different recognition rules from appearing as a code change.',
        'Blocks the incompatible comparison and identifies the rule-set difference.',
        'The per-side rules identities and comparability policy.'),
}


CAPABILITIES_TOOLTIP_TEMPLATES = {
    'capabilities.row': _e(
        'Capability observation: {capability}.',
        'Inspect side evaluation and function pairing before interpreting the change.',
        'Select for matched features, cautions, and provenance.',
        'Change: {change}. Older: {older}. Newer: {newer}. Pair: {pair}.'),

    'capabilities.cell': _e(
        'Capability evaluation for the {side} side.',
        'Distinguish recognition, completed non-recognition, and skipped analysis.',
        'Displays the retained evaluation state.',
        'State: {state}. Matches: {matches}. Reason: {reason}. Origin: {origin}.'),

    'capabilities.group': _e(
        'Capability group: {group}.',
        'Read related rows under the selected grouping scheme.',
        'Expand or collapse the group without changing evidence.',
        'Grouping: {scheme}. Visible rows: {count}.'),

    'capabilities.feature': _e(
        'Retained matching feature: {kind}.',
        'Inspect the observation that contributed to rule recognition.',
        'Displays bounded redacted feature text and an available location.',
        'Value: {value}. Location: {location}. Rule: {rule}. Origin: {origin}.'),

    'capabilities.rule_identity': _e(
        'Rule-set identity used for capability recognition.',
        'Check that both sides used the same recognition basis.',
        'Displays the retained identity without fetching or updating rules.',
        'Label: {label}. Digest: {digest}. Executable: {executable}.'),

    'capabilities.caution': _e(
        'Capability-comparison caution.',
        'Keep a recognition or attribution limitation visible.',
        'Displays the recorded restriction without assigning a cause to the code.',
        'Flag: {flag}. Reason: {reason}. Origin: {origin}.'),

    'capabilities.unattributed': _e(
        'Capability recognition without a usable function-pair link.',
        'Inspect the observation without assigning it to a changed function.',
        'Displays the available scope and attribution reason.',
        'Rule: {rule}. Scope: {scope}. Reason: {reason}. Origin: {origin}.'),

    'capabilities.stale_reason': _e(
        'The capability view describes earlier inputs.',
        'Identify the changed basis before reusing a recognition difference.',
        'Retains reference content and explains the supported update route.',
        'Recorded input comparison: {reason}.'),
}
