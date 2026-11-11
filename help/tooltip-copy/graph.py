"""Proposed Graph panel tooltip copy.

PLANNED: follows the WB2 integration plan.
The panel declaration was unavailable during review.
Implemented behavior and packaged Windows availability are UNVERIFIED.

Sources:
- docs/specs/program-e/WB2-integration-plan.md, sections 6-8
- src/patchtrace/panel_manifest.py

The Across builds view is a later planned addition.
Additional IDs require explicit bindings to documented controls and data fields.
Column IDs describe semantic fields; final header placement requires implementation.

Diagram placement expresses arrangement, not importance or runtime execution.
The Neighbours table must provide the diagram's textual alternative.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


GRAPH_TOOLTIPS = {
    'graph.dock': _e(
        'Explore recorded call relationships and their differences across builds.',
        'Read changed functions in their available caller and callee context.',
        'Shows the Graph panel without running target binaries.',
        'Stored analysis call lists and explicitly available extracted call data.'),

    'graph.action': _e(
        'Show or hide the Graph panel.',
        'Keep call context beside the comparison.',
        'Toggles the dock; shortcut Ctrl+Shift+G.',
        'The planned Graph command and panel registry.'),

    'graph.tabs': _e(
        'Switch between Changes, Neighbours, Tree, and Diagram.',
        'Choose a textual or spatial view of the available call evidence.',
        'Changes the visible view without adding source coverage.',
        'The current graph snapshot and selected function.'),

    'graph.tab.changes': _e(
        'Read call-change summaries for modified function pairs.',
        'Find relationships needing closer inspection.',
        'Shows the change table and its recorded explanations.',
        'Paired stored call lists and call-delta rules.'),

    'graph.tab.neighbours': _e(
        'Read callers and callees in a textual table.',
        'Inspect the diagram information without depending on its graphics.',
        'Shows the bounded neighbourhood for the selected options.',
        'The graph snapshot, focus function, and traversal request.'),

    'graph.tab.tree': _e(
        'Explore call relationships as an expandable tree.',
        'Follow the available neighbourhood one level at a time.',
        'Loads bounded children when expanded, up to the selected depth.',
        'Recorded call edges and traversal limits.'),

    'graph.tab.diagram': _e(
        'Show the selected neighbourhood as a visual diagram.',
        'Inspect the arrangement of retained relationships.',
        'Draws the bounded view; use Neighbours for its textual alternative.',
        'The graph view model and layout result.'),

    'graph.tab.across_builds': _e(
        'Show the later planned call view across a build series.',
        'Compare retained relationships across several ordered builds.',
        'Planned only; availability must not be implied by this entry.',
        'The WB2 evolution design and associated series projects.'),

    'graph.side': _e(
        'Choose older, newer, or both artifact sides.',
        'Keep each call observation tied to its build.',
        'Rebuilds the view within the selected side scope.',
        'The snapshot artifact identities and stored call records.'),

    'graph.side.older': _e(
        'Show eligible call records from the older build.',
        'Inspect baseline relationships.',
        'Restricts the view to the older side.',
        'Older-side stored analysis records.'),

    'graph.side.newer': _e(
        'Show eligible call records from the newer build.',
        'Inspect relationships in the later build.',
        'Restricts the view to the newer side.',
        'Newer-side stored analysis records.'),

    'graph.side.both': _e(
        'Show both builds with their recorded pairing context.',
        'Compare available older and newer relationships.',
        'Includes eligible records from both sides without assuming every node is paired.',
        'Both artifact snapshots and the supported pairing map.'),

    'graph.direction': _e(
        'Choose callers, callees, or both directions.',
        'Control which relationships are explored around the focus function.',
        'Reissues the bounded neighbourhood request.',
        'The selected direction and recorded call edges.'),

    'graph.direction.callers': _e(
        'Explore functions recorded as calling the focus function.',
        'Inspect its observed incoming call context.',
        'Traverses eligible caller relationships within the chosen depth.',
        'Stored incoming call claims and resolution rules.'),

    'graph.direction.callees': _e(
        'Explore functions the focus function is recorded as calling.',
        'Inspect its observed outgoing call context.',
        'Traverses eligible callee relationships within the chosen depth.',
        'Stored outgoing call claims and resolution rules.'),

    'graph.direction.both': _e(
        'Explore recorded callers and callees together.',
        'Read incoming and outgoing context in one bounded view.',
        'Traverses both directions subject to the current limits.',
        'The graph snapshot and selected traversal depth.'),

    'graph.depth': _e(
        'Choose a traversal depth from one to four call steps.',
        'Balance surrounding context against view size.',
        'Rebuilds the neighbourhood within the selected depth and other limits.',
        'The traversal request and recorded graph edges.'),

    'graph.show_unresolved': _e(
        'Choose whether unresolved call targets appear in the view.',
        'Inspect recorded labels that cannot be tied to one function.',
        'Changes visible unresolved records without resolving them.',
        'Stored call labels and name-resolution outcomes.'),

    'graph.changed_only': _e(
        'Choose whether the view focuses on recorded call changes.',
        'Reduce unchanged context when investigating a delta.',
        'Applies the selected display restriction without changing source records.',
        'The call-delta classification and current view options.'),

    'graph.hide_noise': _e(
        'Apply the documented noise-display option.',
        'Control repetitive context while retaining its stated limits.',
        'Changes the view according to the selected option; it does not remove source evidence.',
        'The hub registry, graph flags, and display policy.'),

    'graph.follow': _e(
        'Follow the function selected in the main navigator.',
        'Keep call context aligned with code review.',
        'Updates the graph focus when navigator selection changes; on by default.',
        'The main-window match selection and graph focus state.'),

    'graph.changes_table': _e(
        'Read call-change summaries for compared functions.',
        'Separate mapped endpoint changes from name renumbering.',
        'Selecting a row opens its call evidence and limits.',
        'Stored function pairs, mapped call lists, and change rules.'),

    'graph.table': _e(
        'Read the selected function neighbourhood as text.',
        'Access recorded relationships without relying on the diagram.',
        'Selection opens details; Enter opens an available function.',
        'The bounded neighbourhood view model.'),

    'graph.tree': _e(
        'Expand recorded call relationships around the focus function.',
        'Follow paths without drawing the entire graph.',
        'Creates children on expansion; depth and child-count limits still apply.',
        'The graph snapshot and bounded traversal results.'),

    'graph.tree.more': _e(
        'Read the count of neighbours omitted from this branch.',
        'Recognize that the expanded list is incomplete.',
        'Displays an omission marker rather than inventing missing children.',
        'The branch neighbour count and display ceiling.'),

    'graph.diagram': _e(
        'Inspect the visual call diagram; Neighbours provides the textual alternative.',
        'Use spatial arrangement while retaining another way to read each relationship.',
        'Arrows move focus, Enter opens, and Space selects a node.',
        'The bounded graph view model and layout positions.'),

    'graph.diagram.zoom_in': _e(
        'Increase diagram magnification.',
        'Read labels and relationships at a larger scale.',
        'Changes the viewport scale; keyboard shortcut +.',
        'The current diagram viewport.'),

    'graph.diagram.zoom_out': _e(
        'Decrease diagram magnification.',
        'See more of the current bounded neighbourhood.',
        'Changes the viewport scale; keyboard shortcut -.',
        'The current diagram viewport.'),

    'graph.diagram.fit': _e(
        'Fit the current diagram into its viewport.',
        'Recover an overview after panning or zooming.',
        'Changes the viewport transform; keyboard shortcut 0.',
        'The current diagram scene bounds.'),

    'graph.diagram.paired': _e(
        'Read the older and newer diagram sides with correspondence lines.',
        'Distinguish cross-build pairing from within-build calls.',
        'Displays separate build groups joined by dotted correspondence lines.',
        'The two graph sides and recorded function pairings.'),

    'graph.diagram.arrangement': _e(
        'Read diagram position as arrangement only.',
        'Avoid treating placement or node size as evidence strength.',
        'Displays the layout without assigning importance to spatial position.',
        'The bounded layout algorithm and fixed node presentation.'),

    'graph.minimap': _e(
        'Locate the visible region within the current diagram.',
        'Recover position after panning or zooming.',
        'Shows the overview; the planned M key controls the minimap.',
        'The current diagram scene and viewport bounds.'),

    'graph.detail': _e(
        'Read identity, pairing, call evidence, limits, and provenance.',
        'Check the basis of the selected relationship.',
        'Shows selectable plain text without editing the graph.',
        'The selected node or edge and its retained source claims.'),

    'graph.open': _e(
        'Open the selected function at its supported destination.',
        'Inspect the code behind a recorded call relationship.',
        'Navigates only when the target can be resolved.',
        'The selected node identity and available project function record.'),

    'graph.callsite': _e(
        'Find the callee identifier in available decompiled text.',
        'Inspect surrounding text for the recorded call.',
        'Opens an available text match; it does not establish an instruction call-site address.',
        'The callee label and retained decompiled identifier tokens.'),

    'graph.focus': _e(
        'Make the selected function the graph focus.',
        'Explore its own neighbourhood.',
        'Rebuilds the bounded view and records navigation history; shortcut Ctrl+Enter.',
        'The selected function identity and current traversal options.'),

    'graph.back': _e(
        'Return to the previous graph focus.',
        'Retrace local call exploration.',
        'Restores an available history entry; shortcut Backspace.',
        'The bounded graph-focus history.'),

    'graph.copy': _e(
        'Copy the selected call details and provenance.',
        'Retain a traceable observation in research notes.',
        'Writes the available plain-text details to the clipboard.',
        'The selected graph record and its source references.'),

    'graph.export_dot': _e(
        'Export the supported graph selection as a DOT text file.',
        'Preserve a bounded graph for review in another tool.',
        'Writes escaped graph text through the export workflow; no Graphviz process runs.',
        'The selected graph view and export limits.'),

    'graph.status': _e(
        'Read graph loading, coverage, and error information.',
        'Distinguish missing call evidence from an empty neighbourhood.',
        'Displays current status without changing source records.',
        'The graph request, loading outcome, and coverage model.'),

    'graph.reload': _e(
        'Reload graph evidence after relevant project changes.',
        'Replace a stale view with one built from current records.',
        'Reads retained analysis again without rerunning the binary comparison.',
        'Current project identities and stored call sources.'),

    'graph.cancel': _e(
        'Request cancellation of the active graph operation.',
        'Stop loading or layout work that is no longer needed.',
        'Stops through the supported lifecycle and retains earlier results.',
        'The active graph-load or layout task.'),

    'graph.retry': _e(
        'Retry the failed graph request.',
        'Repeat the operation after addressing the reported cause.',
        'Starts another load or preparation attempt.',
        'The current request and available graph sources.'),

    'graph.copy_error': _e(
        'Copy the graph error details.',
        'Preserve the reported code and message for diagnosis.',
        'Writes available plain-text diagnostic information to the clipboard.',
        'The retained graph failure report.'),

    'graph.footer': _e(
        'Read the coverage limits of the stored call lists.',
        'Keep missing direct, indirect, and unchanged-function coverage explicit.',
        'Displays the source limits beside the view.',
        'Ghidra-derived distinct direct-call lists retained by Ghidriff.'),

    # Changes-table fields.

    'graph.col.function': _e(
        'Identify the function pair associated with this call summary.',
        'Keep the delta attached to the compared endpoints.',
        'Displays the recorded function label and available identity.',
        'The comparison match and associated function records.'),

    'graph.col.meaning': _e(
        'Read the documented explanation of the call-change signal.',
        'Choose an appropriate next inspection step.',
        'Displays rule-based explanatory text without assigning a patch purpose.',
        'The graph-signal identifier and fixed explanation templates.'),

    'graph.col.added': _e(
        'Read the count of calls classified as added.',
        'Distinguish supported call additions from unresolved labels.',
        'Displays the count within the recorded comparison coverage.',
        'Mapped older and newer call lists and call-delta rules.'),

    'graph.col.removed': _e(
        'Read the count of calls classified as removed.',
        'Inspect supported removals without treating missing coverage as removal.',
        'Displays the count within the recorded comparison coverage.',
        'Mapped older and newer call lists and call-delta rules.'),

    'graph.col.api_hints': _e(
        'Read API hints associated with recorded call changes.',
        'Find calls worth inspecting against the stated research context.',
        'Displays hint labels without accepting an advisory-to-function relationship.',
        'Recorded API hints and their rule or advisory references.'),

    'graph.col.direct_callers': _e(
        'Read the available count of distinct direct callers.',
        'Inspect observed incoming context.',
        'Displays a stored-coverage count rather than whole-program reachability.',
        'Distinct caller relationships in the available snapshot.'),

    'graph.col.upstream_types': _e(
        'Read Ghidriff call-related difference types in their native terms.',
        'Keep upstream labels separate from PatchTrace call-delta interpretation.',
        'Displays retained upstream text.',
        'The preserved Ghidriff comparison output.'),

    'graph.col.state': _e(
        'Read whether this call comparison is usable, partial, or unresolved.',
        'Check coverage before interpreting added and removed counts.',
        'Displays the recorded call-delta state.',
        'Source availability, pairing resolution, and comparison checks.'),

    # Neighbour, node, and relationship fields.

    'graph.field.side': _e(
        'Read the build side associated with this graph record.',
        'Keep older and newer observations distinguishable.',
        'Displays the artifact-side label.',
        'The source record artifact identity.'),

    'graph.field.direction': _e(
        'Read whether the selected neighbour is a caller or callee.',
        'Interpret the edge relative to the focus function.',
        'Displays the recorded relationship direction.',
        'The graph edge and selected focus.'),

    'graph.field.pairing': _e(
        'Read the available cross-build pairing for this function.',
        'Check identity before interpreting a call delta.',
        'Displays paired, one-sided, unresolved, or ambiguous status.',
        'The supported function-pair map.'),

    'graph.field.change': _e(
        'Read the call-change classification.',
        'Separate supported additions and removals from unknown coverage.',
        'Displays the text-and-glyph change label.',
        'The call-delta rules and mapped endpoints.'),

    'graph.field.entry_path': _e(
        'Read an observed path from an export or entry point when available.',
        'Inspect retained reachability context within known coverage.',
        'Displays the path or its stated absence and limits.',
        'The bounded traversal over recorded call edges.'),

    # Call-change chips.

    'graph.chip.added': _e(
        'The recorded call relationship is classified as added.',
        'Inspect a supported difference in outgoing calls.',
        'Displays Added within the mapped comparison coverage.',
        'The paired call lists and endpoint-resolution rules.'),

    'graph.chip.removed': _e(
        'The recorded call relationship is classified as removed.',
        'Inspect whether its logic moved, was inlined, or changed.',
        'Displays Removed only where the classification is supported.',
        'The paired call lists and endpoint-resolution rules.'),

    'graph.chip.same': _e(
        'The call endpoints map to the same recorded relationship.',
        'Separate endpoint continuity from apparent name changes.',
        'Displays Same without asserting identical function bodies.',
        'The mapped caller and callee identities.'),

    'graph.chip.not_comparable': _e(
        'Available evidence cannot support a call comparison.',
        'Keep missing or unresolved coverage distinct from a delta.',
        'Displays Not comparable.',
        'The recorded pairing and source-availability checks.'),

    'graph.chip.hub': _e(
        'This relationship is treated as hub context.',
        'Recognize repetitive call plumbing without assigning a cause.',
        'Displays the hub label and its comparison limits.',
        'The hub registry or configured fan-in rule.'),

    # Pairing labels.

    'graph.pairing.paired': _e(
        'A recorded cross-build relationship links this function.',
        'Inspect call differences using the available counterpart.',
        'Displays Paired with its supporting identity.',
        'The current function-pair map.'),

    'graph.pairing.newer_only': _e(
        'The comparison records this function only on the newer side.',
        'Inspect the one-sided function before interpreting its callers.',
        'Displays New in newer build within the stored comparison scope.',
        'The recorded newer-side function category.'),

    'graph.pairing.older_only': _e(
        'The comparison records this function only on the older side.',
        'Inspect the one-sided function and possible moved logic.',
        'Displays Deleted from older build within the stored comparison scope.',
        'The recorded older-side function category.'),

    'graph.pairing.no_data': _e(
        'No usable pairing data resolves this graph node.',
        'Keep identity uncertainty visible.',
        'Displays No pairing data without choosing a counterpart.',
        'The available comparison records and name resolver.'),

    'graph.pairing.ambiguous': _e(
        'Several candidate functions match the available node label.',
        'Avoid opening the first candidate as though identity were established.',
        'Displays ambiguity and the available candidates.',
        'The name-resolution result and candidate identities.'),

    # Signal explanations.

    'graph.signal.new_function_called': _e(
        'A recorded call reaches a function present only in the newer comparison side.',
        'Inspect what the new function checks or does.',
        'Displays the signal and its target reference.',
        'The mapped call delta and newer-side function category.'),

    'graph.signal.api_hint_called': _e(
        'A recorded new call matches an API research hint.',
        'Inspect the call and arguments against the cited hint.',
        'Displays a search aid without assigning the change to an advisory.',
        'The call delta and referenced patch rule or advisory anchor.'),

    'graph.signal.import_called': _e(
        'A recorded new call reaches an import.',
        'Inspect the imported API and its arguments.',
        'Displays the import relationship and any separate new-import flag.',
        'The call delta and available PE import-table comparison.'),

    'graph.signal.call_dropped': _e(
        'A previously recorded call is classified as dropped.',
        'Check whether the associated logic moved or was inlined.',
        'Displays the removed relationship and available target.',
        'The mapped call delta and function categories.'),

    'graph.signal.known_function_called': _e(
        'A new call reaches a function present in both comparison sides.',
        'Compare how this caller now uses the existing function.',
        'Displays the added edge and retained counterpart.',
        'The call delta and cross-build function map.'),

    'graph.signal.fan_in_context': _e(
        'Read how many functions are recorded as direct callers.',
        'Inspect the observed caller population as context.',
        'Displays a count without treating it as an importance measure.',
        'Distinct caller relationships in the graph snapshot.'),

    'graph.signal.hub_only': _e(
        'All classified call differences for this row involve hub targets.',
        'Inspect likely shared plumbing while retaining other possible explanations.',
        'Displays one hub-only summary instead of separate hub signals.',
        'The call deltas and versioned hub classification rules.'),

    'graph.signal.renumber_only': _e(
        'Reported call-label differences map to the same paired callees.',
        'Separate renaming or address renumbering from an endpoint change.',
        'Displays the renumber-only state without an added or removed call signal.',
        'Preserved upstream labels and the cross-build pairing map.'),

    # Detail sections.

    'graph.detail.identity': _e(
        'Read the selected node or relationship identities.',
        'Confirm which artifacts and functions the observation concerns.',
        'Displays the retained endpoint references.',
        'The selected graph record and source claims.'),

    'graph.detail.pairing': _e(
        'Read how the graph resolves the selected function across builds.',
        'Check whether a call delta rests on a usable counterpart.',
        'Displays the pairing basis and unresolved candidates.',
        'The current pair map and name-resolution result.'),

    'graph.detail.evidence': _e(
        'Read the retained call claims behind the selected relationship.',
        'Trace the displayed edge to its source.',
        'Displays recorded caller or callee evidence.',
        'Stored analysis fields and graph claim references.'),

    'graph.detail.limits': _e(
        'Read missing coverage and traversal limits.',
        'Avoid interpreting a partial graph as the complete program.',
        'Displays omissions, unresolved targets, and applied bounds.',
        'The graph snapshot and query completeness record.'),

    'graph.detail.provenance': _e(
        'Read source identities and graph derivation metadata.',
        'Retain the origin of the selected observation.',
        'Displays available hashes, run references, and rule versions.',
        'The graph input snapshot and derivation key.'),

    # States E0-E12; E3 is not separately specified by the plan.

    'graph.state.no_project': _e(
        'Open a project before exploring calls.',
        'Associate the view with a specific comparison.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'graph.state.no_comparison': _e(
        'A completed comparison is required for stored call relationships.',
        'Distinguish missing analysis from an empty call list.',
        'Requests comparison preparation before graph review.',
        'The project completed-run inventory.'),

    'graph.state.loading': _e(
        'The panel is reading recorded call lists.',
        'Distinguish pending preparation from absent relationships.',
        'Shows loading feedback until the request completes.',
        'The active graph-load operation.'),

    'graph.state.function_not_indexed': _e(
        'This function has no call lists in the stored change set.',
        'Explain the missing population before interpreting an empty view.',
        'Displays the coverage limitation instead of an empty success.',
        'The stored function population and available call fields.'),

    'graph.state.no_lists': _e(
        'No caller or callee names are stored for this function.',
        'Keep missing call information distinct from whole-program absence.',
        'Displays the source limitation.',
        'The selected function retained analysis record.'),

    'graph.state.raw_unavailable': _e(
        'Preserved upstream output is missing or fails its recorded hash check.',
        'Identify why unchanged-name pairing cannot be used.',
        'Limits call-change comparison to the supported retained evidence.',
        'The raw-output identity check and available call lists.'),

    'graph.state.truncated': _e(
        'The view omits neighbours beyond a configured limit.',
        'Keep the displayed subset distinct from complete traversal.',
        'Shows displayed and available counts; narrow depth or filters.',
        'The traversal result and applied ceilings.'),

    'graph.state.cancelled': _e(
        'The graph operation was cancelled.',
        'Distinguish interrupted work from a completed empty result.',
        'Retains earlier results without accepting unfinished output.',
        'The operation cancellation outcome.'),

    'graph.state.error': _e(
        'Call evidence could not be read or prepared.',
        'Identify the reported failure before retrying.',
        'Displays the error code and available message.',
        'The graph loading or preparation failure.'),

    'graph.state.stale': _e(
        'This graph view describes earlier project inputs.',
        'Keep historical call relationships separate from current review.',
        'Displays the reason and offers reload.',
        'Graph source identities compared with current project state.'),

    'graph.state.too_large_to_draw': _e(
        'The selected neighbourhood exceeds the diagram limit.',
        'Avoid an unbounded scene while retaining another review route.',
        'Requests a narrower depth or use of the Neighbours table.',
        'The layout node count and diagram ceiling.'),

    'graph.state.instruction_data_missing': _e(
        'Whole-program path analysis lacks the required extracted instruction data.',
        'Identify why only stored-list paths can be shown.',
        'Displays the narrower path scope without inventing missing edges.',
        'The project extraction inventory and graph source coverage.'),

    'graph.state.callsite_missing': _e(
        'No matching callee identifier was found in the retained decompiled text.',
        'Keep unavailable text navigation distinct from absence of a call.',
        'Displays the reason instead of guessing a line.',
        'The selected callee label and available decompiled text.'),

    'graph.state.no_observed_entry_path': _e(
        'No path from an export or entry point was observed in this graph.',
        'Retain the limits of partial stored call coverage.',
        'Reports the traversal outcome without asserting unreachable code.',
        'The bounded path search and available entry information.'),
}


GRAPH_TOOLTIP_TEMPLATES = {
    'graph.row': _e(
        'Recorded call context for {function}.',
        'Inspect side, relationship, and change before opening code.',
        'Select the row to read its details.',
        'Side: {side}. Direction: {direction}. Change: {change}. Origin: {origin}.'),

    'graph.cell': _e(
        'Call-context field: {field}.',
        'Interpret the value within its recorded coverage.',
        'Displays the retained value without extending its meaning.',
        'Value: {value}. Basis: {basis}. Limits: {limits}.'),

    'graph.node': _e(
        'Call-graph node: {name}.',
        'Check the node identity and pairing before following its edges.',
        'Select for details; open only when its target resolves.',
        'Side: {side}. Address: {address}. Pairing: {pairing}.'),

    'graph.edge': _e(
        'Recorded call relationship.',
        'Inspect the endpoints and source before interpreting the connection.',
        'Select for details; this edge does not establish a runtime path.',
        'Caller: {caller}. Callee: {callee}. Side: {side}. Basis: {basis}.'),

    'graph.omitted': _e(
        'Some call-context records are not displayed.',
        'Recognize the bounded scope of the current view.',
        'Reports omissions without treating them as absent relationships.',
        'Shown: {shown}. Available: {total}. Applied limit: {limit}.'),

    'graph.ambiguous': _e(
        'The selected graph target has several candidate identities.',
        'Review candidates rather than choosing by label alone.',
        'Lists available choices without selecting a default counterpart.',
        'Label: {label}. Candidates: {count}. Reason: {reason}.'),

    'graph.path': _e(
        'Observed path through recorded call relationships.',
        'Inspect retained reachability context with its coverage limits.',
        'Displays the bounded path without asserting complete program reachability.',
        'Origin: {origin}. Destination: {destination}. Steps: {hops}. Limits: {limits}.'),

    'graph.signal': _e(
        'Recorded graph signal: {signal}.',
        'Read its explanation and suggested next inspection.',
        'Displays an investigative observation without accepting a new relationship.',
        'Meaning: {meaning}. Next step: {next_step}. Origin: {origin}.'),

    'graph.stale_reason': _e(
        'The call view describes earlier source material.',
        'Identify the changed input before reusing a graph observation.',
        'Retains reference content and offers the supported reload route.',
        'Recorded source comparison: {reason}.'),
}
