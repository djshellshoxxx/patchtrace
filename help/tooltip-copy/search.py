"""Proposed Search panel tooltip copy.

PLANNED: this copy follows the WB1 integration plan.
The panel declaration was unavailable during review.
Implemented controls, runtime behavior, and packaged availability are UNVERIFIED.

Sources:
- docs/specs/program-e/WB1-integration-plan.md, sections 6-8
- src/patchtrace/panel_manifest.py

Entries describe documented controls and states, not additional features.
IDs beyond the plan's original list require explicit implementation bindings.

Search Class is not a control in this plan; Kinds selects source populations.
Saved searches retain query plans rather than frozen result sets.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


SEARCH_TOOLTIPS = {
    'search.dock': _e(
        'Search the saved material indexed for the current project.',
        'Find related code, names, strings, and research context in one view.',
        'Shows the Search panel; queries use local project data.',
        'The project search index and its recorded coverage.'),

    'search.action': _e(
        'Show Search and focus its query field.',
        'Start a project-wide lookup from the keyboard.',
        'Opens the dock and selects the query; shortcut Ctrl+Shift+F.',
        'The planned Search command and panel registry.'),

    'search.query': _e(
        'Enter search words, a quoted phrase, or supported filters.',
        'Locate indexed evidence relevant to the investigation.',
        'Typing requests a search after a short pause; Enter requests it immediately.',
        'The parsed query and selected local index populations.'),

    'search.query_clear': _e(
        'Clear the current search text.',
        'Start another query without editing the project.',
        'Empties the field; an empty query does not request all records.',
        'The current query field.'),

    'search.query_hint': _e(
        'Read the supported query examples.',
        'Choose words, phrases, exclusions, or documented filters.',
        'Displays syntax guidance without running an operation.',
        'The Search query grammar.'),

    'search.query_interpretation': _e(
        'Read how Search interpreted the submitted query.',
        'Check prefixes, identity terms, and applied filters.',
        'Displays the parsed interpretation without changing the source records.',
        'The validated query plan.'),

    'search.side': _e(
        'Choose older-side, newer-side, or both-side search coverage.',
        'Control which artifact side contributes results.',
        'Requeries within the selected side scope.',
        'Side identities recorded in the indexed material.'),

    'search.side.both': _e(
        'Search indexed material for both artifact sides.',
        'Compare available references across the selected pair.',
        'Includes eligible older and newer records.',
        'The index side assignments and current query.'),

    'search.side.older': _e(
        'Search indexed material associated with the older artifact.',
        'Focus on the comparison baseline.',
        'Restricts the query to eligible older-side records.',
        'The older artifact identity and index records.'),

    'search.side.newer': _e(
        'Search indexed material associated with the newer artifact.',
        'Focus on the later build.',
        'Restricts the query to eligible newer-side records.',
        'The newer artifact identity and index records.'),

    'search.kinds': _e(
        'Choose which kinds of saved material to search.',
        'Limit the query to useful evidence populations.',
        'Changes requested source groups; unavailable groups remain identified.',
        'The selected kinds and index coverage records.'),

    'search.kind.functions': _e(
        'Include indexed function names and associated function fields.',
        'Locate functions without relying only on the navigator filter.',
        'Adds eligible function records to the requested search kinds.',
        'Stored function records and supported indexed symbol material.'),

    'search.kind.code': _e(
        'Include available indexed code text.',
        'Find expressions and identifiers inside retained representations.',
        'Adds eligible decompiled or extracted instruction text.',
        'Stored analysis text and explicitly available extraction segments.'),

    'search.kind.strings': _e(
        'Include indexed string observations.',
        'Locate text references retained by supported sources.',
        'Adds eligible string records without starting extraction.',
        'Available stored string evidence and its extraction coverage.'),

    'search.kind.imports_exports': _e(
        'Include indexed import and export information.',
        'Find recorded API and symbol references.',
        'Adds eligible import and export records to the query.',
        'Indexed project PE and analysis records.'),

    'search.kind.capabilities_rules': _e(
        'Include indexed capability and rule information.',
        'Locate recognized behaviors and retained rule context.',
        'Adds available records without running capa or testing rules.',
        'Stored capability and rule sources included by the index.'),

    'search.kind.build_facts': _e(
        'Include indexed build-environment facts.',
        'Locate compiler, linker, and packaging context.',
        'Adds available stored build facts without launching a tool.',
        'Indexed header observations and stored tool evidence.'),

    'search.kind.advisories': _e(
        'Include indexed advisory and security-identifier text.',
        'Find relevant statements while retaining their documentary origin.',
        'Adds available advisory records without downloading updates.',
        'Saved advisories, CVE snapshots, and supported context records.'),

    'search.kind.notes_findings': _e(
        'Include indexed analyst notes and interpretation findings.',
        'Find prior research observations and recorded explanations.',
        'Adds available note and finding text to the query.',
        'Saved project annotations and interpretation records.'),

    'search.scope': _e(
        'Choose indexed coverage or the changed-material scope.',
        'Control the population searched before reading results.',
        'Requeries using the selected scope.',
        'The query plan, index populations, and recorded change associations.'),

    'search.scope.indexed': _e(
        'Search the available indexed population.',
        'Use the broadest locally indexed scope selected by the other filters.',
        'Includes eligible indexed records; it does not imply whole-binary coverage.',
        'The index coverage manifest and selected source kinds.'),

    'search.scope.changed': _e(
        'Search records eligible for the changed-material scope.',
        'Focus discovery on material associated with the comparison changes.',
        'Applies the documented changed-scope restriction.',
        'Indexed change associations and the validated query plan.'),

    'search.mode': _e(
        'Choose how Search interprets and matches the query.',
        'Select words, exact text, prefixes, substrings, or similar names.',
        'Requeries using the selected matching mode.',
        'The supported mode definitions and local index capabilities.'),

    'search.mode.auto': _e(
        'Use automatic query interpretation.',
        'Apply the documented grammar without selecting one matching method.',
        'Builds the query plan and reports how terms were interpreted.',
        'The Search query parser and supported index methods.'),

    'search.mode.words': _e(
        'Use word-based matching over indexed text.',
        'Search terms using the documented token and identifier rules.',
        'Requeries in Words mode; inspect the interpreted query.',
        'The word index and index-time identifier splitting.'),

    'search.mode.exact': _e(
        'Use the documented Exact matching mode.',
        'Request exact-text matching rather than a name-similarity suggestion.',
        'Requeries in Exact mode within the selected coverage.',
        'The validated query plan and exact-match implementation.'),

    'search.mode.prefix': _e(
        'Search using the supported prefix-matching rules.',
        'Find indexed terms beginning with the entered text.',
        'Requeries in Prefix mode subject to documented term-length limits.',
        'The parsed prefix query and local index.'),

    'search.mode.substring': _e(
        'Search supported indexed text for a literal substring.',
        'Locate fragments inside a longer name or value.',
        'Requeries in Substring mode within available index support.',
        'The substring index or documented bounded fallback.'),

    'search.mode.similar': _e(
        'Request similar-name suggestions where supported.',
        'Discover possible spellings or related names.',
        'Returns suggestions without accepting a function relationship.',
        'The supported name population and optional RapidFuzz component.'),

    'search.sort': _e(
        'Choose relevance, change, name, or address reading order.',
        'Order the requested result population for the current review.',
        'Reissues the query; sorting is not limited to the loaded page.',
        'The query service and selected sort rules.'),

    'search.sort.relevance': _e(
        'Order results using the documented relevance rules.',
        'Read the reasons a result appears earlier in the list.',
        'Requeries in relevance order; inspect each result explanation.',
        'Search ranking rules and recorded ranking reasons.'),

    'search.sort.change': _e(
        'Order results using recorded change information.',
        'Read comparison-related results in a change-focused order.',
        'Requeries with the change sort.',
        'Indexed change associations and Search ordering rules.'),

    'search.sort.name': _e(
        'Order results by the supported name key.',
        'Locate named records in a predictable reading order.',
        'Requeries with the name sort.',
        'Indexed result names and the query service sort key.'),

    'search.sort.address': _e(
        'Order results by the supported address key.',
        'Read address-bearing records by recorded location.',
        'Requeries with the address sort.',
        'Recorded result locations and the query service sort key.'),

    'search.save': _e(
        'Save the current query plan under a name.',
        'Repeat the same search choices later.',
        'Requests a name of up to 64 characters and saves the plan, not its results.',
        'The current parsed query, scope, kinds, mode, and order.'),

    'search.saved': _e(
        'Open the saved-search menu.',
        'Reuse or remove a retained query plan.',
        'Lists saved searches without restoring a frozen result set.',
        'Saved Search plans associated with the project.'),

    'search.saved_run': _e(
        'Run the selected saved search again.',
        'Apply an earlier query plan to currently available indexed material.',
        'Executes the retained plan and produces current results.',
        'The selected saved plan and current index.'),

    'search.saved_delete': _e(
        'Remove the selected search from the saved-search list.',
        'Retire a query plan that is no longer useful.',
        'Records an append-only removal marker; project evidence is unchanged.',
        'The selected saved-search record.'),

    'search.rebuild': _e(
        'Rebuild the project search index from saved material.',
        'Refresh indexed coverage after relevant data changes.',
        'Starts local indexing without rerunning binary comparison or downloading sources.',
        'Supported saved project records and their current identities.'),

    'search.build': _e(
        'Build the initial search index.',
        'Make supported saved project material searchable.',
        'Starts indexing and reports which populations become available.',
        'The current project saved data and supported index adapters.'),

    'search.update': _e(
        'Update the index after relevant project changes.',
        'Replace stale search coverage with current indexed records.',
        'Starts local index preparation without running comparison engines.',
        'Changed source identities and index coverage metadata.'),

    'search.cancel_index': _e(
        'Request cancellation of index preparation.',
        'Stop indexing work that is no longer needed.',
        'Stops through the supported indexing lifecycle.',
        'The active local index-build operation.'),

    'search.coverage': _e(
        'Inspect which project populations are indexed or unavailable.',
        'Interpret results within the material actually searched.',
        'Opens coverage details without fetching missing sources.',
        'Index segment metadata, source states, and recorded limits.'),

    'search.table': _e(
        'Read search results with side, kind, location, change, and ordering reasons.',
        'Inspect each hit in its comparison context.',
        'Selection opens details; Enter navigates and Ctrl+C copies its reference.',
        'The current query result pages and their provenance.'),

    'search.detail': _e(
        'Read the selected result explanation and limitations.',
        'Check its location, pair context, and reading-order basis.',
        'Displays read-only details without changing analysis records.',
        'The selected search result and referenced project records.'),

    'search.goto': _e(
        'Open the selected result at its supported destination.',
        'Inspect the source material behind the hit.',
        'Checks the locator against the current project before navigation.',
        'The result locator and current project identities.'),

    'search.other_side': _e(
        'Show the available counterpart on the other comparison side.',
        'Inspect the paired context instead of reading one side alone.',
        'Navigates only when the stored relationship supplies a usable counterpart.',
        'The result locator and recorded function relationship.'),

    'search.copy': _e(
        'Copy the selected result reference and provenance.',
        'Retain a traceable search observation in research notes.',
        'Writes the result title, locator, and provenance to the clipboard.',
        'The selected search result.'),

    'search.next': _e(
        'Open the next result in the current list.',
        'Review successive hits from the keyboard.',
        'Moves selection and opens the next result; shortcut F3.',
        'The current result order and available locators.'),

    'search.previous': _e(
        'Open the previous result in the current list.',
        'Return to an earlier hit from the keyboard.',
        'Moves selection and opens the previous result; shortcut Shift+F3.',
        'The current result order and available locators.'),

    'search.suggestions': _e(
        'Read indexed-name suggestions for the query field.',
        'Choose an exact listed function when names are similar.',
        'Selecting a suggestion opens its retained target without running a full search.',
        'The local name index and each suggestion locator.'),

    'search.recent_queries': _e(
        'Read recent queries offered by the empty search field.',
        'Reuse earlier search text without retyping it.',
        'Selecting an entry supplies its query for reuse.',
        'The Search query history described by the panel plan.'),

    'search.status': _e(
        'Read the current query status and coverage summary.',
        'Distinguish completed results from partial or stale coverage.',
        'Displays query feedback without changing source records.',
        'The current search response and index status.'),

    'search.progress': _e(
        'Read the current indexing activity.',
        'Identify the group being prepared and available progress counts.',
        'Displays build progress; completed indexed groups can already be searched.',
        'The active index-build operation.'),

    # Result column headers.

    'search.col.side': _e(
        'Read which artifact side the result belongs to.',
        'Keep older and newer observations distinct.',
        'Displays the indexed side association.',
        'The result source identity.'),

    'search.col.kind': _e(
        'Read the kind of material containing the hit.',
        'Distinguish code, strings, advisories, and other indexed sources.',
        'Displays the result kind.',
        'The indexed record type and source adapter.'),

    'search.col.match': _e(
        'Read the matching result text or label.',
        'Identify the words or name that led to this hit.',
        'Displays a bounded result representation.',
        'Indexed source text and query-hit information.'),

    'search.col.where': _e(
        'Read the result location.',
        'Check which function or document contains the indexed hit.',
        'Displays the supported locator description.',
        'The result locator and source metadata.'),

    'search.col.change': _e(
        'Read the available comparison-change context.',
        'Distinguish a text hit from its recorded relationship to the diff.',
        'Displays available change information without inferring a cause.',
        'Indexed comparison associations and retained change facts.'),

    'search.col.why': _e(
        'Read why this result appears in the current order.',
        'Inspect the documented basis for its reading position.',
        'Displays the result ranking reasons.',
        'Search ordering rules and per-result reason records.'),

    # Read-only detail sections.

    'search.detail.result': _e(
        'Read the selected hit and its source kind.',
        'Confirm what actually matched the query.',
        'Displays the bounded result content.',
        'The selected search record.'),

    'search.detail.order': _e(
        'Read the reasons for this result reading position.',
        'Separate text relevance from comparison evidence.',
        'Displays the applicable ordering factors.',
        'The query plan and per-result ranking reasons.'),

    'search.detail.pair': _e(
        'Read the available older and newer pairing context.',
        'Inspect a hit in relation to its recorded counterpart.',
        'Displays known pair information without accepting a new relationship.',
        'Stored function matches and supported pair expansion.'),

    'search.detail.changes': _e(
        'Read available change facts associated with the hit.',
        'Check whether the located text relates to recorded code differences.',
        'Displays retained facts without generating new analysis.',
        'The referenced comparison and available derived records.'),

    'search.detail.provenance': _e(
        'Read source identities and index provenance for the hit.',
        'Retain the origin of a search observation.',
        'Displays the recorded source references.',
        'The result locator and index-segment metadata.'),

    'search.detail.limits': _e(
        'Read limits affecting this result and its navigation.',
        'Avoid treating incomplete indexing as complete binary coverage.',
        'Displays missing, stale, or restricted source information.',
        'The result limitations and index coverage.'),

    # Coverage details.

    'search.coverage.group': _e(
        'Identify the indexed source population.',
        'Relate a coverage statement to a specific kind of project material.',
        'Displays the group label.',
        'The index source-group manifest.'),

    'search.coverage.status': _e(
        'Read whether this source group is indexed and usable.',
        'Distinguish completed coverage from missing or failed preparation.',
        'Displays the recorded group state.',
        'The index segment status.'),

    'search.coverage.limits': _e(
        'Read source-group coverage limits.',
        'Check what an empty query result can establish.',
        'Displays recorded omissions and restrictions.',
        'The source adapter and index-build coverage record.'),

    'search.coverage.identity': _e(
        'Read the source and segment identities used for this group.',
        'Check whether the index describes current project data.',
        'Displays recorded digests and source references.',
        'The index coverage and freshness metadata.'),

    # Query and index states.

    'search.state.no_project': _e(
        'Open a project before searching saved material.',
        'Associate the query with a specific investigation.',
        'Displays the missing-project prerequisite.',
        'Current project availability.'),

    'search.state.not_indexed': _e(
        'This project has no usable search index yet.',
        'Distinguish missing preparation from no matches.',
        'Offers Build index without uploading project data.',
        'The local index inventory.'),

    'search.state.building': _e(
        'Search is preparing index groups.',
        'Identify which populations are becoming searchable.',
        'Reports progress while completed groups remain available.',
        'The current index-build operation.'),

    'search.state.empty_query': _e(
        'Enter a query to search the selected indexed populations.',
        'Choose a focused lookup instead of requesting all project records.',
        'Shows syntax guidance without listing every indexed entry.',
        'The empty query field and selected search controls.'),

    'search.state.results': _e(
        'The query returned results within its stated scope.',
        'Inspect the hits alongside coverage and display counts.',
        'Displays available pages in the selected reading order.',
        'The current search response.'),

    'search.state.no_results_complete': _e(
        'No matches were found in the completed requested index coverage.',
        'Keep indexed absence separate from absence in the binary.',
        'Displays an empty result with its searched populations.',
        'The completed query and coverage records.'),

    'search.state.no_results_partial': _e(
        'No hits are available, but requested index coverage is incomplete.',
        'Avoid concluding that the requested material is absent.',
        'Identifies missing groups instead of presenting a complete negative result.',
        'The query response and incomplete index coverage.'),

    'search.state.partial_results': _e(
        'Hits are available from only part of the requested coverage.',
        'Review useful records while retaining the missing-source limits.',
        'Displays available hits and the incomplete coverage statement.',
        'The query response and per-group index status.'),

    'search.state.too_broad': _e(
        'The query exceeds the ranked-match ceiling.',
        'Explain why the displayed subset is not relevance-ranked.',
        'Shows the first 200 in index order; narrow the query to restore ranked search.',
        'A query with more than 20000 matches and the documented fallback policy.'),

    'search.state.display_limit': _e(
        'The view has reached its 5000-row display limit.',
        'Distinguish the visible list from all possible hits.',
        'Requests a narrower query instead of loading additional rows.',
        'The result population and planned display ceiling.'),

    'search.state.stale': _e(
        'The project changed after this index was built.',
        'Keep historical search material distinct from current source records.',
        'Shows reference results and checks navigation against the current project.',
        'Index source identities compared with current project data.'),

    'search.state.unsupported': _e(
        'This build lacks the required SQLite FTS5 capability.',
        'Identify a search dependency limit.',
        'Reports full-text search as unavailable; the navigator filter remains separate.',
        'The local SQLite capability check.'),

    'search.state.similar_unavailable': _e(
        'The Similar mode dependency is unavailable.',
        'Distinguish a missing matcher from no similar names.',
        'Reports the unavailable mode instead of returning an empty success.',
        'The optional RapidFuzz capability check.'),

    'search.state.error': _e(
        'Search could not complete the requested operation.',
        'Identify a failed query or index action.',
        'Shows the error while leaving project source records unchanged.',
        'The query or index-operation failure report.'),

    'search.state.query_error': _e(
        'The entered query does not meet the supported grammar.',
        'Correct the identified syntax without guessing another interpretation.',
        'Shows PT-SEARCH-QUERY guidance for the invalid input.',
        'The validated query parser.'),

    'search.state.instructions_missing': _e(
        'Instruction text is unavailable in the indexed source material.',
        'Explain why assembly searches cannot cover that population.',
        'Shows the coverage limit; an instruction hash is not searchable instruction text.',
        'The retained upstream output and extraction availability.'),

    'search.state.navigation_blocked': _e(
        'The selected result cannot be opened in the current project state.',
        'Keep a stale or unresolved locator from opening an unrelated record.',
        'Displays the navigation reason without selecting a substitute target.',
        'The result locator checked against current project identities.'),

    'search.retry': _e(
        'Retry the failed Search operation.',
        'Repeat the request after addressing the displayed cause.',
        'Starts another supported query or preparation attempt.',
        'The current request and local Search service.'),

    'search.copy_error': _e(
        'Copy the Search error details.',
        'Retain the reported code and message for diagnosis.',
        'Writes the available diagnostic text to the clipboard.',
        'The retained Search failure report.'),
}


SEARCH_TOOLTIP_TEMPLATES = {
    'search.row': _e(
        'Search result: {title}.',
        'Inspect its source kind, comparison context, and reading-order reasons.',
        'Select for details; activate only after checking its location.',
        'Kind: {kind}. Side: {side}. Location: {where}. Reason: {why}.'),

    'search.suggestion': _e(
        'Indexed function suggestion: {name}.',
        'Distinguish similarly named entries using side and address.',
        'Selecting opens this exact retained target without running a full query.',
        'Side: {side}. Address: {address}. Category: {category}.'),

    'search.coverage_row': _e(
        'Search coverage group: {group}.',
        'Check whether this source population supports a complete search.',
        'Read the recorded state and limits before interpreting missing hits.',
        'State: {state}. Identity: {digest}. Limits: {limits}.'),

    'search.saved_row': _e(
        'Saved search: {name}.',
        'Reuse its query choices against currently available indexed material.',
        'Running re-executes the plan; deleting records a removal marker.',
        'Retained query plan: {query}. Scope: {scope}.'),

    'search.rank_reason': _e(
        'Result ordering reason: {reason}.',
        'Check why this hit appears at its current reading position.',
        'Displays an explanation without changing a function relationship.',
        'The current query plan and recorded ranking factors.'),

    'search.missing_group': _e(
        'A requested search group is unavailable.',
        'Keep missing coverage visible beside the query results.',
        'Explains the gap without treating it as absent binary content.',
        'Group: {group}. Recorded reason: {reason}.'),

    'search.stale_reason': _e(
        'The search index describes earlier source material.',
        'Identify what changed before reusing a result.',
        'Retains reference results and offers the supported update route.',
        'Recorded source comparison: {reason}.'),
}
