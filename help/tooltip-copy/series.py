"""Proposed Series panel tooltip copy.

EXPERIMENTAL: the panel declaration, controller, and read model exist.
Packaged Windows availability and manual accessibility acceptance are UNVERIFIED.

Sources:
- src/patchtrace/nway/panel.py
- src/patchtrace/ui_series.py
- src/patchtrace/nway/view_model.py
- src/patchtrace/nway/pair_access.py
- src/patchtrace/nway/graph.py
- src/patchtrace/tooltips.py

Existing Series tooltip IDs retain their names.
Additional IDs require explicit bindings to existing controls and fields.

Opening and reloading read stored series and pair-project data.
They do not recompute chains or run comparisons.

The read model computes maximum and sum from available hop attention values.
These are display and sorting aids. Missing hop values are excluded, not zeroed.
The Sum is not a calibrated chain assessment.
This wording follows the implementation where older tooltip prose is inconsistent.

Confirmed and Contradicted describe the optional direct-pair check.
Neither label establishes program equivalence across the series.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


SERIES_TOOLTIPS = {
    'series.dock': _e(
        'Follow stored function-chain hypotheses across ordered builds.',
        'Inspect adjacent comparisons without opening every project separately.',
        'Shows one tab per opened series file without changing project data.',
        'The selected series.json files and referenced pair projects.'),

    'series.action': _e(
        'Show or hide the Series panel.',
        'Keep cross-build context beside the current comparison.',
        'Toggles the dock without creating or recomputing a series.',
        'The panel registry and Series controller.'),

    'series.open_file': _e(
        'Choose a series.json file to open.',
        'Review a previously prepared build series.',
        'Reads the file and pair projects; an already open file reuses its tab.',
        'The selected local series manifest and referenced project snapshots.'),

    'series.tabs': _e(
        'Choose an opened series tab.',
        'Keep several retained investigations available in one dock.',
        'Changes the displayed series without recomputing its chains.',
        'The Series controller opened-file list.'),

    'series.close_tab': _e(
        'Close the selected series tab.',
        'Remove its view from the workspace without deleting the investigation.',
        'Stops its loading work and closes the view; stored files remain.',
        'The selected tab and its loading lifecycle.'),

    'series.window': _e(
        'Read the chain hypotheses stored in this series file.',
        'Inspect function continuity alongside individual pair evidence.',
        'Shows retained chain data without writing to the series or pair projects.',
        'The series manifest and read-only pair snapshots.'),

    'series.empty_hint': _e(
        'No series file is currently open.',
        'Identify the file needed before cross-build review.',
        'Offers Open series.json without creating a new series.',
        'The controller opened-tab state.'),

    'series.reload': _e(
        'Read the series file and referenced pair projects again.',
        'Refresh displayed snapshots after stored data changes.',
        'Replaces an active load with a new read; it does not recompute chains.',
        'The current series path and read-only pair readers.'),

    'series.cancel_load': _e(
        'Stop the active series-loading request.',
        'End a read that is no longer needed.',
        'Abandons loading; an earlier loaded view can remain available.',
        'The active SeriesLoadThread cancellation state.'),

    'series.filter_text': _e(
        'Filter chains by function, hexadecimal address, build label, or chain ID.',
        'Locate a function or relationship already under investigation.',
        'Applies a case-insensitive display filter using up to 200 characters.',
        'The loaded chain search fields.'),

    'series.filter_status': _e(
        'Filter chains by Inferred, Confirmed, or Contradicted status.',
        'Separate adjacent-pair hypotheses from direct-pair checks.',
        'Changes visible rows without performing a new direct comparison.',
        'The status retained in each stored chain.'),

    'series.filter_status.all': _e(
        'Show chains with every recorded status.',
        'Review the full eligible status population.',
        'Removes the status restriction while retaining other filters.',
        'The loaded chain records.'),

    'series.filter_event': _e(
        'Filter chains by recorded boundary or text-reversion events.',
        'Locate chains with a specific recorded transition.',
        'Changes visible rows without rebuilding event records.',
        'The ChainEvent records retained in the series.'),

    'series.filter_event.all': _e(
        'Show chains regardless of their recorded events.',
        'Review the eligible population without an event restriction.',
        'Removes the event filter while retaining other filters.',
        'The loaded chain event lists.'),

    'series.only_stale': _e(
        'Show only chains marked stale by the series checks.',
        'Identify stored hypotheses affected by changed pair inputs.',
        'Filters the view; recomputing chains requires the series-creation workflow.',
        'The series staleness result and recorded pair identities.'),

    'series.only_scored': _e(
        'Show only chains with at least one available hop attention value.',
        'Separate scored coverage from chains lacking usable ranking entries.',
        'Filters the table without requiring every hop to have a score.',
        'The pair projects stored default-profile attention rankings.'),

    'series.min_score': _e(
        'Require a highest available hop attention value from 0 to 100.',
        'Focus review using the existing per-pair attention values.',
        'Filters chains by their maximum; zero disables this threshold.',
        'Available attention entries from each pair default-profile ranking.'),

    'series.sort': _e(
        'Order chains by highest hop, hop sum, hop count, name, or chain ID.',
        'Choose a reading order while preserving missing-score distinctions.',
        'Reorders loaded rows; it does not change pair evidence.',
        'The Series view query and retained per-hop attention values.'),

    'series.sort.highest': _e(
        'Order by the maximum available hop attention value.',
        'Locate chains containing a highly ranked individual comparison.',
        'Sorts descending, then by available hop sum; unscored chains follow.',
        'The maximum of retained usable hop scores.'),

    'series.sort.sum': _e(
        'Order by the arithmetic sum of available hop attention values.',
        'Inspect accumulated ranking activity while checking scored-hop coverage.',
        'Sorts descending, then by maximum; missing values are excluded.',
        'The read model sum of usable hop scores; an ordering aid only.'),

    'series.sort.hops': _e(
        'Order by the number of stored adjacent-pair hops.',
        'Find longer chains for cross-build inspection.',
        'Sorts by hop count descending with stable chain-ID tie ordering.',
        'The chain edge count.'),

    'series.sort.name': _e(
        'Order by the displayed chain name.',
        'Locate named chains in a predictable order.',
        'Sorts names case-insensitively with stable chain-ID tie ordering.',
        'The retained function-derived chain titles.'),

    'series.sort.chain_id': _e(
        'Order by the retained chain identifier.',
        'Locate a chain referenced in another record.',
        'Sorts by chain ID without changing its hypothesis status.',
        'The loaded chain identities.'),

    'series.chain_table': _e(
        'Read stored one-to-one chains spanning three or more builds.',
        'Inspect chain status before opening an individual hop.',
        'Selecting a chain fills the hop table.',
        'The series manifest, pair snapshots, and available ranking entries.'),

    'series.hop_table': _e(
        'Read the adjacent comparisons belonging to the selected chain.',
        'Inspect each step independently of the overall hypothesis.',
        'Selecting a usable hop enables its pair-opening action.',
        'Stored chain edges and read-only pair snapshots.'),

    'series.open_pair': _e(
        'Open the selected hop project at its recorded comparison row.',
        'Inspect the code and evidence behind an individual chain step.',
        'Opens the project in the main window; unchanged raw-only hops cannot open a match.',
        'The hop match ID and resolved project path below the series root.'),

    'series.copy_chain': _e(
        'Copy the selected chain and its build references.',
        'Retain the hypothesis, statuses, and per-hop context in notes.',
        'Copies plain text with build ordinals and 12-character artifact-hash prefixes.',
        'The selected chain, loaded build references, and hop records.'),

    'series.banner': _e(
        'Read stale, partial, or truncated-series notices.',
        'Keep pair availability and display limits visible.',
        'Shows the reason without repairing or recomputing the series.',
        'The SeriesView state and source checks.'),

    'series.progress': _e(
        'Read the series-loading activity indicator.',
        'Distinguish a pending read from an empty chain list.',
        'Shows activity without a measured completion total.',
        'The active series-loading task.'),

    'series.message': _e(
        'Read the empty-series or loading-failure explanation.',
        'Choose a supported next step before repeating the operation.',
        'Displays the available message without modifying stored data.',
        'The loaded series outcome and fixed recovery guidance.'),

    'series.divider': _e(
        'Adjust space between the chain list and hop details.',
        'Allocate reading width to the current inspection.',
        'Changes local layout without changing chain records.',
        'The Series tab splitter.'),

    # Chain-table columns.

    'series.col.chain': _e(
        'Read the chain title derived from its retained function references.',
        'Identify the function sequence under review.',
        'Displays the title; selection shows its hops.',
        'The chain nodes and fallback chain identifier.'),

    'series.col.hops': _e(
        'Read the number of adjacent comparisons in the chain.',
        'Check the span represented by the hypothesis.',
        'Displays the stored hop count.',
        'The chain edges.'),

    'series.col.highest': _e(
        'Read the maximum usable attention value among this chain hops.',
        'Identify the highest-ranked individual pair for inspection.',
        'Displays the maximum of available values; no available value remains blank.',
        'Stored default-profile attention entries read from pair projects.'),

    'series.col.sum': _e(
        'Read the arithmetic sum of usable hop attention values.',
        'Inspect this display aid together with missing-hop states.',
        'Adds available values only; it does not assess chain correctness.',
        'The read model sum of retained usable per-hop attention entries.'),

    'series.col.status': _e(
        'Read the stored chain hypothesis status.',
        'Check whether an optional direct pair agreed or conflicted with its endpoint.',
        'Displays Inferred, Confirmed, or Contradicted.',
        'The chain builder and available direct first-to-last comparison.'),

    'series.col.events': _e(
        'Read the event kinds associated with the chain.',
        'Locate boundary changes and repeated code-text observations.',
        'Displays distinct recorded event labels.',
        'The chain event records.'),

    'series.col.stale': _e(
        'Read whether this chain is marked stale.',
        'Keep changed pair inputs visible.',
        'Displays STALE for affected chains without recomputing them.',
        'The series staleness checks and pair identities.'),

    # Hop-table columns.

    'series.hop_col.hop': _e(
        'Read the adjacent-build labels for this step.',
        'Identify which two builds the row compares.',
        'Displays the ordered from-to labels.',
        'The hop ordinals and series build labels.'),

    'series.hop_col.from': _e(
        'Read the older endpoint function for this hop.',
        'Check the starting identity of the adjacent relationship.',
        'Displays its retained name or available address.',
        'The edge older FunctionNode.'),

    'series.hop_col.to': _e(
        'Read the newer endpoint function for this hop.',
        'Check the destination identity of the adjacent relationship.',
        'Displays its retained name or available address.',
        'The edge newer FunctionNode.'),

    'series.hop_col.category': _e(
        'Read the relationship category stored for this hop.',
        'Inspect how the pair engine or analyst represented the transition.',
        'Displays the retained category without changing it.',
        'The chain edge and source comparison relationship.'),

    'series.hop_col.match_types': _e(
        'Read the upstream match-type labels retained for this hop.',
        'Inspect the matching basis of the individual step.',
        'Displays source labels without converting them into a combined measurement.',
        'The chain edge match_types field.'),

    'series.hop_col.ratio': _e(
        'Read the upstream ratio text retained for this hop.',
        'Keep the original measurement separate from attention ranking.',
        'Displays retained text without deriving a chain-level estimate.',
        'The chain edge ratio_text field.'),

    'series.hop_col.score': _e(
        'Read the usable default-profile attention value or its unavailable state.',
        'Inspect ranking coverage for the selected pair.',
        'Displays a stored value without recomputing ranking.',
        'The pair snapshot and matching attention entry.'),

    'series.hop_col.pair_state': _e(
        'Read the current availability and identity state of this pair project.',
        'Check whether the stored hop can be inspected in its project.',
        'Displays the snapshot state and available reason.',
        'The read-only pair-project check.'),

    # Chain status values.

    'series.status.inferred': _e(
        'The chain is assembled from adjacent pair relationships.',
        'Keep transitive correspondence distinguishable from a direct-pair check.',
        'Displays Inferred.',
        'The stored chain builder output.'),

    'series.status.confirmed': _e(
        'The optional direct pair selects the chain final endpoint.',
        'Inspect the extra endpoint check without assuming every intermediate hop is correct.',
        'Displays Confirmed within the recorded pairing scope.',
        'The direct first-to-last relationship and chain endpoint comparison.'),

    'series.status.contradicted': _e(
        'The optional direct pair conflicts with the chain endpoint relationship.',
        'Review the adjacent hops and direct comparison together.',
        'Displays Contradicted without choosing which relationship is correct.',
        'The direct comparison and stored chain endpoint checks.'),

    # Event options and labels.

    'series.event.added': _e(
        'Read a recorded Added event associated with the chain boundary.',
        'Inspect the adjacent relationship where the sequence begins or changes.',
        'Displays the event without reconstructing missing earlier history.',
        'The chain event and originating pair category.'),

    'series.event.removed': _e(
        'Read a recorded Removed event associated with the chain boundary.',
        'Inspect the adjacent relationship where the sequence ends or changes.',
        'Displays the event within the stored series scope.',
        'The chain event and originating pair category.'),

    'series.event.split': _e(
        'Read a recorded split relationship at the chain boundary.',
        'Inspect multiple resulting functions instead of forcing a one-to-one continuation.',
        'Displays the event and retained ordinal.',
        'The boundary pair relationship and chain event.'),

    'series.event.merged': _e(
        'Read a recorded merged relationship at the chain boundary.',
        'Inspect converging function relationships separately.',
        'Displays the event without inventing a one-to-one continuation.',
        'The boundary pair relationship and chain event.'),

    'series.event.ambiguous': _e(
        'Read an unresolved multi-candidate relationship at the chain boundary.',
        'Avoid selecting a continuation without distinguishing evidence.',
        'Displays the event and its retained context.',
        'The boundary pairing and chain-event record.'),

    'series.event.unmatched': _e(
        'Read a recorded unmatched relationship at the chain boundary.',
        'Keep the chain gap distinguishable from a definite removal.',
        'Displays the event without assigning a counterpart.',
        'The source pair relationship and chain event.'),

    'series.event.reverted': _e(
        'A retained code-text observation equals one from an earlier chain build.',
        'Inspect the repeated text without assuming the entire source change was reversed.',
        'Displays Reverted as a recorded text-level event.',
        'The chain builder code-text equality check.'),

    # Attention-value states.

    'series.score.scored': _e(
        'A usable attention entry exists for this hop.',
        'Read the individual pair priority with its own evidence.',
        'Displays the stored default-profile value.',
        'The matching entry in the pair project ranking.'),

    'series.score.unchanged': _e(
        'This hop comes from an unchanged raw relationship.',
        'Keep an unranked unchanged record separate from a numeric zero.',
        'Displays Unchanged rather than an attention value.',
        'The raw-only chain edge and score-state rules.'),

    'series.score.no_ranking': _e(
        'No usable stored default-profile ranking is available for this pair.',
        'Identify missing ranking coverage.',
        'Displays an unavailable score state without treating it as zero.',
        'The read-only pair snapshot and ranking note.'),

    'series.score.pair_unavailable': _e(
        'The pair project could not supply a usable ranking snapshot.',
        'Keep file-access problems separate from low priority.',
        'Displays an unavailable attention value.',
        'The pair reader availability and identity checks.'),

    'series.score.stale_ranking': _e(
        'The retained ranking is stale for the pair project.',
        'Avoid using superseded attention values.',
        'Displays an unavailable score state without rerunning ranking.',
        'The default-profile ranking freshness check.'),

    'series.score.not_ranked': _e(
        'The usable ranking has no entry for this particular relationship.',
        'Distinguish an omitted entry from a numeric zero.',
        'Displays Not ranked.',
        'The stored ranking entries and hop match identifier.'),

    # Pair-project states.

    'series.pair.ok': _e(
        'The pair project matches the recorded series references.',
        'Identify a readable snapshot with the expected identities.',
        'Displays OK without asserting that its function matches are correct.',
        'The project, revision, run, and ordered-artifact checks.'),

    'series.pair.changed': _e(
        'The pair project revision or run changed after series creation.',
        'Keep current project content separate from the stored chain hypothesis.',
        'Displays Changed; the project can still be opened for inspection.',
        'The pair reference compared with its current snapshot.'),

    'series.pair.missing': _e(
        'The referenced pair project is unavailable at its permitted location.',
        'Identify why this hop cannot be inspected through its stored path.',
        'Displays Missing without substituting another project.',
        'The series-relative path and project-file checks.'),

    'series.pair.unreadable': _e(
        'The referenced pair project could not be opened or read.',
        'Keep access or database failure distinct from missing relationships.',
        'Displays Unreadable and the available reason.',
        'The read-only project-opening outcome.'),

    'series.pair.locked': _e(
        'Another PatchTrace instance owns the referenced project lock.',
        'Identify a temporary access restriction.',
        'Displays Locked without stealing the lock or marking the pair stale by that fact alone.',
        'The project writer-lock check.'),

    'series.pair.mismatch': _e(
        'The project does not match the recorded project or ordered artifacts.',
        'Avoid inspecting a different comparison as this chain hop.',
        'Displays Mismatch and blocks normal pair opening.',
        'The project identity and ordered-artifact validation.'),

    'series.pair.no_run': _e(
        'The referenced project has no completed comparison run.',
        'Distinguish missing analysis from an empty result.',
        'Displays No run without starting comparison automatically.',
        'The pair-project completed-run inventory.'),

    # View states and limits.

    'series.state.loading': _e(
        'The series manifest and pair snapshots are being read.',
        'Distinguish pending content from an empty chain list.',
        'Shows activity and temporarily disables the result tables.',
        'The active Series loading task.'),

    'series.state.ready': _e(
        'The available series view is ready to inspect.',
        'Read chains together with their individual statuses.',
        'Displays loaded rows subject to current filters.',
        'The completed read-only loading result.'),

    'series.state.empty': _e(
        'No stored one-to-one chain spans three or more builds.',
        'Keep this series-specific result separate from whole-history absence.',
        'Displays the empty-state explanation.',
        'The chains retained in the loaded series manifest.'),

    'series.state.partial': _e(
        'Some pair projects or hop rankings are unavailable or degraded.',
        'Keep incomplete context visible alongside readable chains.',
        'Displays available rows with the reported pair or ranking issues.',
        'PairHealth records and per-hop score states.'),

    'series.state.stale': _e(
        'Stored chains no longer match the current referenced comparison basis.',
        'Inspect historical hypotheses before recomputing the series.',
        'Displays stale context; Reload alone does not regenerate chains.',
        'The series staleness checks and pair snapshots.'),

    'series.state.failed': _e(
        'The series could not be loaded.',
        'Inspect manifest or storage errors before retrying.',
        'Displays the failure and supported recovery guidance.',
        'The series parser or read-only loading failure.'),

    'series.state.cancelled': _e(
        'The series-loading request was cancelled.',
        'Distinguish an interrupted read from an empty series.',
        'Offers Reload; an earlier loaded view can remain available.',
        'The loading cancellation outcome.'),

    'series.state.truncated': _e(
        'The view shows only the first 5000 matching chains.',
        'Keep the displayed subset distinct from all matching records.',
        'Requests a narrower filter without deleting stored chains.',
        'The query result count and Series display ceiling.'),

    'series.state.no_visible_rows': _e(
        'No loaded chains pass the current filters.',
        'Distinguish a filtered table from a series with no chains.',
        'Requests broader display options without recomputing the series.',
        'The loaded chains and current ViewQuery.'),

    'series.state.no_openable_match': _e(
        'The selected hop has no eligible comparison row to open.',
        'Avoid navigating to a guessed match.',
        'Keeps pair navigation unavailable for unsupported or raw-only hops.',
        'The hop match identifier and pair availability state.'),
}


SERIES_TOOLTIP_TEMPLATES = {
    'series.score_cell': _e(
        'Hop attention state: {state}.',
        'Distinguish a usable ranking entry from missing coverage.',
        'Displays the retained value or reason without recomputing it.',
        'The pair default-profile attention ranking. Reason: {reason}.'),

    'series.pair_state': _e(
        'Pair-project state: {state}.',
        'Check whether the referenced comparison is readable and still matches.',
        'Displays the read-only snapshot outcome.',
        'The last pair-project inspection. Reason: {reason}.'),

    'series.chain_row': _e(
        'Stored chain: {name}.',
        'Inspect hypothesis status and each adjacent comparison.',
        'Select to display its retained hops.',
        'Chain: {chain}. Status: {status}. Hops: {hops}. Stale: {stale}.'),

    'series.hop_row': _e(
        'Adjacent-build chain step.',
        'Check the individual relationship before relying on the sequence.',
        'Select to inspect or open an available source comparison.',
        'From: {older}. To: {newer}. Category: {category}. Pair state: {state}.'),

    'series.tab': _e(
        'Opened series file: {name}.',
        'Distinguish retained investigations in separate tabs.',
        'Shows its loaded view; closing the tab deletes no project data.',
        'Selected local manifest: {path}.'),

    'series.event': _e(
        'Recorded chain event: {event}.',
        'Inspect the event at its specific build boundary.',
        'Displays the stored observation without reconstructing missing history.',
        'Build ordinal: {ordinal}. Details: {details}.'),

    'series.score_coverage': _e(
        'Available attention coverage for this chain.',
        'Read maximum and sum alongside missing-hop information.',
        'Displays coverage counts without creating a chain assessment.',
        'Scored hops: {scored}. Total hops: {total}. Unavailable states: {states}.'),

    'series.stale_reason': _e(
        'The stored chain describes earlier pair inputs.',
        'Identify what changed before reusing the hypothesis.',
        'Retains reference content; chain recomputation is a separate operation.',
        'Recorded comparison changes: {reason}.'),
}
