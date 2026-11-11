"""Proposed Leads panel tooltip copy.

EXPERIMENTAL: panel, controller, read model, and explanation sources exist.
Packaged Windows availability and manual accessibility acceptance are UNVERIFIED.

Sources:
- src/patchtrace/pilot/panel.py
- src/patchtrace/ui_leads.py
- src/patchtrace/pilot/read_model.py
- src/patchtrace/pilot/why.py

Existing tooltip IDs retain their names.
Additional IDs require explicit bindings to existing controls and fields.
Dynamic Pin/Unpin and Dismiss/Restore buttons need matching dynamic copy.

Prepare computes a new derived result from stored evidence.
Refresh reloads stored results.
Neither operation downloads advisories or runs an external analysis tool.

Ranks and ties describe reading order.
Expected-change counts describe recognized conditions within a rule.
Analyst review events do not change the derived lead class.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


LEADS_TOOLTIPS = {
    'leads.dock': _e(
        'Review changed functions in an explainable reading order.',
        'Inspect the evidence behind each lead beside the code.',
        'Shows retained leads without running an external tool.',
        'The stored patch-intent result and analyst review events.'),

    'leads.action': _e(
        'Show or hide the Leads panel.',
        'Keep the investigative queue beside the comparison.',
        'Toggles the dock; shortcut Ctrl+Shift+L.',
        'The panel registry and Leads controller.'),

    'leads.context': _e(
        'Choose an advisory context or code evidence only.',
        'Inspect how the same changed functions relate to different research contexts.',
        'Changes the displayed context without storing a new result.',
        'Contexts retained in the loaded assessment.'),

    'leads.context.code_only': _e(
        'Review leads using code evidence without advisory-fit assessment.',
        'Keep code-change review available when no advisory is loaded.',
        'Shows the code-only context without assigning its leads to a CVE.',
        'The stored assessment code-evidence context.'),

    'leads.prepare': _e(
        'Prepare leads from the current stored comparison and supporting records.',
        'Create a derived reading order with traceable explanations.',
        'Stores a new result from retained inputs; nothing is sent or externally executed.',
        'Stored comparison, advisory, signal, and context records.'),

    'leads.refresh': _e(
        'Reload the stored lead result and review events.',
        'Inspect a retained result prepared or updated elsewhere.',
        'Reads stored records again without recomputing the assessment.',
        'The project lead-result store and append-only review history.'),

    'leads.retry': _e(
        'Retry preparing leads after a failed attempt.',
        'Repeat computation after addressing the reported cause.',
        'Starts the supported preparation path while retaining earlier results.',
        'The current stored evidence and retained failure state.'),

    'leads.copy_details': _e(
        'Copy the lead-preparation error details.',
        'Preserve the reported code and message for diagnosis.',
        'Writes available plain-text diagnostics to the clipboard.',
        'The retained Leads failure report.'),

    'leads.cancel': _e(
        'Request cancellation of lead preparation.',
        'Stop derived computation that is no longer needed.',
        'Stops the active task without publishing unfinished assessment output.',
        'The active Leads preparation lifecycle.'),

    'leads.headline': _e(
        'Read the current lead-preparation or loading status.',
        'Distinguish missing preparation from completed review content.',
        'Displays lifecycle feedback without changing evidence.',
        'The Leads presentation state.'),

    'leads.banners': _e(
        'Read stale, partial, applicability, and update-window notices.',
        'Keep assessment limits visible before inspecting rank.',
        'Displays the current result and context restrictions.',
        'The stored assessment, current identities, and advisory gates.'),

    'leads.filter_class': _e(
        'Show leads from the selected class.',
        'Focus the queue without changing its derived classifications.',
        'Changes visible rows; it does not recompute the assessment.',
        'The loaded lead classes and current display query.'),

    'leads.filter.all': _e(
        'Show all lead classes in the selected context.',
        'Review the full eligible queue.',
        'Removes the class restriction while retaining other filters.',
        'The loaded assessment and active context.'),

    'leads.filter.fit': _e(
        'Show leads classified as Fits advisory.',
        'Inspect records meeting the documented fit conditions.',
        'Filters the table without establishing code attribution.',
        'The stored lead class and applicable advisory gate.'),

    'leads.filter.review': _e(
        'Show leads classified as Needs review.',
        'Focus on contested or conflicting evidence.',
        'Filters the table without resolving the recorded conflict.',
        'The stored lead class and its explanation.'),

    'leads.filter.partial': _e(
        'Show leads classified as Partial fit.',
        'Inspect incomplete support and applicable assessment caps.',
        'Filters the table without promoting the result.',
        'The stored lead class, required changes, and cap reasons.'),

    'leads.filter.code': _e(
        'Show leads classified as Code change.',
        'Inspect changed code without an advisory-fit conclusion.',
        'Filters the table to the recorded class.',
        'The stored code-evidence lead records.'),

    'leads.filter.queue': _e(
        'Show leads classified as Changed, no fit.',
        'Keep unexplained or unassessed changes available for review.',
        'Filters the table without discarding the other classes.',
        'The stored review-queue records.'),

    'leads.search': _e(
        'Filter leads by function name or address.',
        'Locate a function already under investigation.',
        'Narrows displayed rows without changing stored rank or class.',
        'The loaded function labels and addresses.'),

    'leads.show_dismissed': _e(
        'Include dismissed leads in the displayed queue.',
        'Review or restore an earlier dismissal.',
        'Changes visibility without deleting or rewriting a review event.',
        'Folded analyst review events for the selected context.'),

    'leads.table': _e(
        'Read ranked leads, classes, expected-change counts, and evidence context.',
        'Inspect why each function appears in the queue.',
        'Selection opens details; Enter opens an available function and Space focuses details.',
        'The stored assessment and current review presentation.'),

    'leads.detail': _e(
        'Read why the selected function appears as a lead.',
        'Inspect expected changes, support, counterevidence, unknowns, and alternatives.',
        'Displays a bounded explanation and separately labelled analyst statements.',
        'The selected lead and its referenced observations.'),

    'leads.observations': _e(
        'Read individual observations associated with the selected lead.',
        'Inspect source, role, and evidence basis separately.',
        'Selection exposes retained evidence; activation navigates only when supported.',
        'The lead observation references and stored observation pool.'),

    'leads.goto': _e(
        'Open the selected lead in the main code panes.',
        'Inspect the changed function behind the explanation.',
        'Selects a resolved current comparison row; unavailable mappings remain blocked.',
        'The lead candidate identity and resolved project match.'),

    'leads.copy': _e(
        'Copy the selected lead explanation.',
        'Retain the cited reasoning beside research notes.',
        'Writes plain text to the clipboard, limited to 16 KiB.',
        'The stored lead explanation and current analyst statements.'),

    'leads.pin': _e(
        'Pin the selected lead in the displayed queue.',
        'Keep a function of interest visible before unpinned rows.',
        'Adds a review event; the lead retains its derived class.',
        'The selected candidate, advisory context, and review store.'),

    'leads.unpin': _e(
        'Remove the selected lead pin.',
        'Return it to the normal unpinned presentation.',
        'Adds an Unpin review event without changing the derived rank or class.',
        'The selected lead review history.'),

    'leads.dismiss': _e(
        'Record a reason for dismissing the selected lead.',
        'Remove it from the active view while retaining the decision.',
        'Opens a reason prompt; saving adds a review event without deleting the lead.',
        'The selected candidate, context, and analyst-entered reason.'),

    'leads.restore': _e(
        'Restore the selected dismissed lead.',
        'Bring an earlier review choice back into the active queue.',
        'Adds a Restore event without removing the dismissal history.',
        'The selected lead review history.'),

    'leads.note': _e(
        'Add an analyst statement to the selected lead.',
        'Record an independent observation beside the derived explanation.',
        'Opens a text prompt; saving appends a separately labelled review event.',
        'Your entered text and the selected lead identity.'),

    'leads.dismiss_reason': _e(
        'Enter the reason for dismissing this lead.',
        'Preserve the reasoning behind a queue decision.',
        'Text is appended to the review history when the prompt is accepted.',
        'Your analyst-authored dismissal reason.'),

    'leads.note_text': _e(
        'Enter an analyst statement for this lead.',
        'Keep your judgment distinguishable from the generated explanation.',
        'Text is appended to the review history when the prompt is accepted.',
        'Your analyst-authored statement.'),

    'leads.review_accept': _e(
        'Save the text requested by the current lead-review prompt.',
        'Commit the stated dismissal reason or analyst note.',
        'Appends the applicable review event; the derived lead class is unchanged.',
        'The selected lead and entered review text.'),

    'leads.review_cancel': _e(
        'Close the lead-review prompt without saving.',
        'Return to the queue without adding that review event.',
        'Discards the prompt text without changing the retained lead.',
        'The pending review dialog.'),

    'leads.footer': _e(
        'Read the limits of lead ordering and tied positions.',
        'Keep reading priority separate from a code-attribution conclusion.',
        'Displays persistent guidance; tied leads have equal ordering evidence.',
        'The Leads interpretation contract.'),

    'leads.divider.rows': _e(
        'Adjust space between the lead list and supporting detail views.',
        'Allocate reading space to the current task.',
        'Changes the local layout without editing assessment records.',
        'The Leads vertical splitter.'),

    'leads.divider.evidence': _e(
        'Adjust space between the explanation and observation table.',
        'Read narrative and individual evidence at a useful width.',
        'Changes the local layout without changing the lead.',
        'The Leads detail splitter.'),

    # Main table headers.

    'leads.col.rank': _e(
        'Read the recorded rank or tied rank range.',
        'Interpret the ordering without inventing distinctions within a tie.',
        'Displays the retained position; pins can change presentation order.',
        'The lead rank, tie record, and analyst pin events.'),

    'leads.col.lead': _e(
        'Read the function names and addresses associated with the lead.',
        'Identify the compared endpoints before reading its explanation.',
        'Displays retained endpoint labels.',
        'The lead older and newer function references.'),

    'leads.col.class': _e(
        'Read the derived lead class.',
        'Distinguish fit, incomplete support, conflict, and code-only review.',
        'Displays a word and glyph without changing the classification.',
        'The stored Lead record and class vocabulary.'),

    'leads.col.expected': _e(
        'Read how many expected changes were seen for the displayed hypothesis.',
        'Inspect recognized conditions without treating the count as a score.',
        'Displays the retained met and total counts, or None assessed.',
        'The selected lead hypothesis-fit records.'),

    'leads.col.channels': _e(
        'Read supporting channels and channels whose evidence remains unknown.',
        'Identify what the explanation uses and what it could not assess.',
        'Displays channel names without merging them into a measurement.',
        'The lead observations and assessment channel statuses.'),

    'leads.col.pairing': _e(
        'Read the recorded function-pairing assessment.',
        'Check correspondence before interpreting the lead.',
        'Displays Corroborated, Contested, or Not assessed.',
        'The lead identity state and retained pairing evidence.'),

    'leads.col.flags': _e(
        'Read evidence limits and analyst presentation flags.',
        'Identify text-only support, build context, pins, and review events.',
        'Displays recorded qualifiers without changing the lead class.',
        'The lead caps, evidence depth, and folded review history.'),

    # Observation-table headers.

    'leads.obs_col.standing': _e(
        'Read whether the observation supports, opposes, qualifies, or offers an alternative.',
        'Keep the evidence relationship explicit.',
        'Displays the observation standing within this lead.',
        'The lead support, counter, unknown, and alternative references.'),

    'leads.obs_col.kind': _e(
        'Read the observation type.',
        'Distinguish code signals, calls, strings, and documentary statements.',
        'Displays the retained evidence-kind label.',
        'The observation kind and fixed display vocabulary.'),

    'leads.obs_col.role': _e(
        'Read how the observation contributes to this assessment.',
        'Separate change support, name overlap, conflict, and context.',
        'Displays the recorded role without promoting contextual material.',
        'The observation role field.'),

    'leads.obs_col.basis': _e(
        'Read how the observation is known.',
        'Distinguish file bytes, tool reports, labels, and analyst statements.',
        'Displays the recorded evidence basis.',
        'The observation verification category mapped to plain language.'),

    'leads.obs_col.source': _e(
        'Read the origin categories associated with this observation.',
        'Inspect shared dependencies before counting independent support.',
        'Displays recorded origins without treating every row as a separate source.',
        'The observation origin tags.'),

    'leads.obs_col.detail': _e(
        'Read the bounded observation explanation.',
        'Inspect the specific fact or limitation cited by the lead.',
        'Displays retained plain text without running verification steps.',
        'The observation detail field.'),

    # Lead-class chips.

    'leads.class.fit': _e(
        'The stored lead meets the advisory-fit rule conditions.',
        'Inspect the expected changes and independent support behind the label.',
        'Displays Fits advisory without establishing a function-level attribution.',
        'The retained hypothesis fits, applicability gate, and class rules.'),

    'leads.class.review': _e(
        'Conflicting or contested evidence requires review.',
        'Resolve the recorded disagreement before relying on the lead.',
        'Displays Needs review with the applicable explanation.',
        'Pairing conflict, counterevidence, and advisory gate records.'),

    'leads.class.partial': _e(
        'The stored lead has incomplete support or an applicable assessment cap.',
        'Inspect what prevented a stronger fit classification.',
        'Displays Partial fit with the recorded reasons.',
        'The hypothesis conditions, channel availability, and cap policy.'),

    'leads.class.code': _e(
        'The lead records a code change without advisory-fit assessment.',
        'Keep code review useful when documentary context is absent.',
        'Displays Code change.',
        'The retained code observations and code-only context.'),

    'leads.class.queue': _e(
        'The function remains changed without an established fit.',
        'Preserve unexplained or unassessed work for inspection.',
        'Displays Changed, no fit without treating it as an exclusion.',
        'The retained queue lead and assessment state.'),

    'leads.rank.tie': _e(
        'Several leads share the same ordering evidence.',
        'Review the group without treating internal position as stronger support.',
        'Displays the shared rank range.',
        'The stored tie first, last, and size fields.'),

    # Pairing labels.

    'leads.pairing.corroborated': _e(
        'The retained pairing assessment records corroboration.',
        'Inspect the contributing sources and their shared dependencies.',
        'Displays Corroborated without changing the function relationship.',
        'The assessment identity state and pairing observations.'),

    'leads.pairing.contested': _e(
        'The retained sources contest the function pairing.',
        'Inspect counterpart identities before interpreting a change.',
        'Displays Contested and keeps the opposing observations available.',
        'The assessment identity state and pairing evidence.'),

    'leads.pairing.unassessed': _e(
        'The pairing has no applicable second-engine assessment.',
        'Keep unassessed correspondence distinct from disagreement.',
        'Displays Not assessed.',
        'The available pairing channel and source inventory.'),

    # Channel labels.

    'leads.channel.advisory': _e(
        'Read the advisory channel status.',
        'Check whether documentary context was available to this result.',
        'Displays channel availability without fetching a document.',
        'The assessment advisory-channel record.'),

    'leads.channel.code': _e(
        'Read the code-evidence channel status.',
        'Check the available basis for expected code changes.',
        'Displays channel availability without running analysis.',
        'The assessment code-channel record.'),

    'leads.channel.calls': _e(
        'Read the call-evidence channel status.',
        'Inspect the availability of call-related observations.',
        'Displays channel availability without rebuilding a graph.',
        'The assessment calls-channel record.'),

    'leads.channel.strings': _e(
        'Read the string-evidence channel status.',
        'Inspect whether retained string context was available.',
        'Displays channel availability without starting extraction.',
        'The assessment strings-channel record.'),

    'leads.channel.capa': _e(
        'Read the capa-evidence channel status.',
        'Check whether capability recognition contributed context.',
        'Displays channel availability without running capa.',
        'The assessment capability-channel record.'),

    'leads.channel.build': _e(
        'Read the build-context channel status.',
        'Inspect whether toolchain or packaging context was available.',
        'Displays channel availability without running a detection tool.',
        'The assessment build-channel record.'),

    'leads.channel.pairing': _e(
        'Read the pairing-evidence channel status.',
        'Check whether correspondence received additional assessment.',
        'Displays channel availability without launching another engine.',
        'The assessment pairing-channel record.'),

    # Channel states.

    'leads.channel_state.available': _e(
        'This channel supplied available evidence to the assessment.',
        'Identify a usable source without assuming it supports every lead.',
        'Displays Available; inspect the selected lead observations for its contribution.',
        'The stored ChannelStatus record.'),

    'leads.channel_state.partial': _e(
        'This channel supplied incomplete evidence.',
        'Keep coverage limits visible.',
        'Displays Partial without treating missing observations as negative.',
        'The stored channel outcome and reason.'),

    'leads.channel_state.not_run': _e(
        'This channel did not supply a performed assessment.',
        'Distinguish unperformed work from absent behavior.',
        'Displays Not run.',
        'The stored channel status or missing-channel fallback.'),

    'leads.channel_state.unsupported': _e(
        'This channel was unavailable under the supported configuration.',
        'Identify a capability limit affecting the lead.',
        'Displays Unsupported.',
        'The stored channel status and reason.'),

    'leads.channel_state.failed': _e(
        'This channel failed to provide usable evidence.',
        'Identify which source requires diagnosis.',
        'Displays Failed without converting the failure into counterevidence.',
        'The retained channel failure status.'),

    'leads.channel_state.stale': _e(
        'This channel evidence describes an earlier input basis.',
        'Keep historical observations distinct from current support.',
        'Displays Out of date.',
        'The stored channel status and input checks.'),

    # Observation roles and bases.

    'leads.role.shape': _e(
        'This observation supports an expected change shape.',
        'Inspect the actual code observation behind the rule condition.',
        'Displays the support role without establishing advisory attribution.',
        'The observation role and hypothesis condition.'),

    'leads.role.local': _e(
        'A retained name matches advisory context.',
        'Inspect local identifier overlap without treating wording as code behavior.',
        'Displays the name-match role.',
        'The observation and advisory-name matching rule.'),

    'leads.role.counter': _e(
        'This observation argues against the proposed change interpretation.',
        'Keep opposing evidence visible beside support.',
        'Displays the counterevidence role.',
        'The retained observation and its lead reference.'),

    'leads.role.conflict': _e(
        'This observation conflicts with another assessment input.',
        'Identify a disagreement requiring inspection.',
        'Displays the conflict role without resolving it automatically.',
        'The retained observation and conflict references.'),

    'leads.role.context': _e(
        'This observation supplies context only.',
        'Keep useful background separate from required change evidence.',
        'Displays the contextual role.',
        'The observation role and source restrictions.'),

    'leads.basis.bytes': _e(
        'The observation was read from file bytes.',
        'Distinguish a byte-backed observation from a label or assertion.',
        'Displays the recorded basis without extending its scope.',
        'The observation source reference and artifact identity.'),

    'leads.basis.tool': _e(
        'The observation was reported by an analysis tool.',
        'Keep tool interpretation distinguishable from direct byte reading.',
        'Displays the tool-reported basis.',
        'The retained tool evidence and run identity.'),

    'leads.basis.label': _e(
        'The observation rests on a retained label only.',
        'Recognize the limit of name-based call evidence.',
        'Displays Label only without upgrading its evidence depth.',
        'The observation verification category.'),

    'leads.basis.advisory': _e(
        'The observation is stated by an advisory.',
        'Keep documentary statements separate from binary observations.',
        'Displays the advisory basis.',
        'The retained advisory fact and source pointer.'),

    'leads.basis.hypothesis': _e(
        'The observation represents a rule hypothesis.',
        'Distinguish expected changes from observed changes.',
        'Displays the hypothesis basis without creating code evidence.',
        'The versioned expected-change rule.'),

    'leads.basis.analyst': _e(
        'The observation is an analyst statement.',
        'Keep explicit assumptions distinguishable from source records.',
        'Displays the analyst-authored basis.',
        'The retained assertion or review record.'),

    # Fixed explanation sections.

    'leads.detail.summary': _e(
        'Read the selected lead class and its principal limits.',
        'Check the overall explanation before individual observations.',
        'Displays the stored summary, tie information, and assessment caps.',
        'The selected lead and fixed explanation rules.'),

    'leads.detail.expected': _e(
        'Read expected changes and whether each required condition was seen.',
        'Inspect the rule-specific basis of the advisory-fit label.',
        'Displays conditions and their evidence references.',
        'The retained HypothesisFit and ExpectedChange records.'),

    'leads.detail.independent': _e(
        'Read support grouped by recorded evidence dependencies.',
        'Avoid counting related observations as separate corroboration.',
        'Displays the component breakdown and cited observations.',
        'The stored origins and dependency-component rules.'),

    'leads.detail.against': _e(
        'Read observations opposing the lead interpretation.',
        'Inspect counterevidence before accepting a conclusion.',
        'Displays the retained opposing records.',
        'The lead counterevidence references.'),

    'leads.detail.unknown': _e(
        'Read missing conditions and unavailable evidence.',
        'Keep unresolved checks visible.',
        'Displays unknowns without interpreting them as contradictions.',
        'The lead unknown references and channel statuses.'),

    'leads.detail.alternatives': _e(
        'Read alternative interpretations or related leads.',
        'Inspect other explanations for the recorded changes.',
        'Displays retained alternatives without choosing one automatically.',
        'The assessment alternative references and related lead records.'),

    'leads.detail.pairing': _e(
        'Read correspondence evidence for the compared functions.',
        'Check endpoint identity before relying on a change explanation.',
        'Displays the recorded pairing assessment.',
        'The lead identity state and pairing observations.'),

    'leads.detail.provenance': _e(
        'Read the input and source identities behind this lead.',
        'Retain the derivation basis alongside copied explanations.',
        'Displays available run, artifact, rule, and source references.',
        'The assessment provenance and referenced observations.'),

    'leads.detail.limits': _e(
        'Read the interpretation and coverage limits of this context.',
        'Keep multiple-update and source restrictions visible.',
        'Displays retained limitations without changing the rank.',
        'The selected advisory context and assessment limits.'),

    'leads.detail.analyst': _e(
        'Read analyst statements appended to this lead.',
        'Distinguish independent review from derived explanation text.',
        'Displays the retained statements with their recorded times.',
        'Append-only lead review events.'),

    # Applicability and assessment caps.

    'leads.gate.not_applicable': _e(
        'The retained applicability gate excludes this advisory context.',
        'Inspect why this build pair does not receive leads for the selected advisory.',
        'Shows the gate reason without erasing code-only review.',
        'The advisory applicability and build-order assessment.'),

    'leads.gate.unresolved': _e(
        'The advisory could not be tied to the selected builds.',
        'Keep an unresolved documentary relationship explicit.',
        'Caps the advisory-context lead class at Partial fit.',
        'The applicability gate and its retained source basis.'),

    'leads.gate.conflict': _e(
        'Advisory statements or build ordering conflict.',
        'Inspect the disagreement before using an advisory-fit result.',
        'Caps the advisory-context lead class at Needs review.',
        'The retained applicability conflict.'),

    'leads.gate.asserted': _e(
        'The analyst asserted that this advisory applies to these builds.',
        'Keep an explicit assumption distinct from source-established applicability.',
        'Displays the assertion without converting it into documentary evidence.',
        'The retained analyst applicability statement.'),

    'leads.limit.multiple_cves': _e(
        'Several advisory identifiers share the selected update window.',
        'Look for observations specific to the selected advisory.',
        'Displays the competing-context limit and applicable fit cap.',
        'The context confounding record and locality rules.'),

    'leads.limit.toolchain_text': _e(
        'The toolchain changed and this lead has decompiler-text support only.',
        'Inspect a build-related alternative explanation.',
        'Applies the documented Partial fit cap.',
        'The build-context observation and lead evidence depth.'),

    'leads.limit.label_only': _e(
        'A required condition rests on call labels only.',
        'Inspect stronger code or import evidence before strengthening the fit.',
        'Displays the recorded assessment limit.',
        'The required condition and observation basis.'),

    'leads.limit.text_only': _e(
        'This lead uses decompiler text without typed change facts.',
        'Keep lexical recognition distinct from instruction-backed assessment.',
        'Displays the evidence-depth qualifier and applicable limits.',
        'The lead depth and available change-fact observations.'),

    # Panel states.

    'leads.state.no_project': _e(
        'Open a project before reviewing leads.',
        'Associate the queue with an explicit artifact pair.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'leads.state.no_comparison': _e(
        'A completed comparison is required before preparing leads.',
        'Distinguish missing source analysis from an empty queue.',
        'Requests ordinary comparison preparation first.',
        'The project completed-run inventory.'),

    'leads.state.not_prepared': _e(
        'No lead assessment is stored for this comparison.',
        'Distinguish missing derived work from no qualifying leads.',
        'Offers Prepare leads.',
        'The lead-result store and current comparison identity.'),

    'leads.state.loading': _e(
        'The panel is loading stored leads and review history.',
        'Distinguish pending content from an empty assessment.',
        'Displays loading feedback without computing a new result.',
        'The active stored-result loading task.'),

    'leads.state.preparing': _e(
        'The panel is preparing a new lead assessment.',
        'Follow the current computation stage.',
        'Displays progress and offers cancellation.',
        'The active stored-evidence computation.'),

    'leads.state.indeterminate': _e(
        'The current preparation stage has no measured total.',
        'Read activity without assuming a completion fraction.',
        'Displays stage text without an invented total.',
        'The active preparation progress report.'),

    'leads.state.ready': _e(
        'The stored lead assessment is ready to inspect.',
        'Read the queue with its context and evidence limits.',
        'Displays rows subject to the selected filters.',
        'The loaded assessment and review presentation.'),

    'leads.state.partial': _e(
        'Some evidence channels were unavailable to this assessment.',
        'Keep missing evidence separate from opposing evidence.',
        'Displays usable leads and the unavailable channel states.',
        'The assessment channel records.'),

    'leads.state.failed': _e(
        'Lead preparation could not complete.',
        'Inspect the reported failure before retrying.',
        'Preserves the comparison and earlier stored leads.',
        'The retained preparation error.'),

    'leads.state.stale': _e(
        'These leads describe earlier comparison or context inputs.',
        'Keep historical ordering separate from the current project.',
        'Displays the changed inputs and retains the result for reference.',
        'The stored assessment identities and current input checks.'),

    'leads.state.no_advisory': _e(
        'No advisory context is loaded for this assessment.',
        'Keep code-only review available without inventing documentary fit.',
        'Displays code-evidence leads without matching them to a CVE.',
        'The assessment context inventory.'),

    'leads.state.too_large': _e(
        'The displayed lead population exceeds the row limit.',
        'Keep the review view bounded.',
        'Requests a narrower filter.',
        'The row count and configured display ceiling.'),

    'leads.state.no_visible_rows': _e(
        'No leads pass the current context, class, text, and dismissal filters.',
        'Distinguish a filtered queue from an empty assessment.',
        'Requests broader display options without preparing a new result.',
        'The loaded rows and current query.'),

    'leads.state.no_navigation': _e(
        'The selected lead has no usable current comparison-row mapping.',
        'Avoid navigating to a guessed counterpart.',
        'Keeps Go to function unavailable and reports the reason.',
        'The candidate-to-match resolver and current project identities.'),
}


LEADS_TOOLTIP_TEMPLATES = {
    'leads.chip': _e(
        'Evidence channel state: {state}.',
        'Check whether this source was available to the assessment.',
        'Displays a status; an unperformed channel is not a negative observation.',
        'The retained ChannelStatus record.'),

    'leads.row': _e(
        'Investigative lead: {function}.',
        'Inspect the class, tie, and supporting observations before following code.',
        'Select for the stored explanation.',
        'Context: {context}. Class: {class_name}. Rank: {rank}. Pairing: {pairing}.'),

    'leads.rank': _e(
        'Recorded lead reading position.',
        'Keep ranks and ties separate from evidence-strength estimates.',
        'Displays retained ordering; a pin can change presentation without changing class.',
        'Rank: {rank}. Tie range: {tie}. Context: {context}.'),

    'leads.observation': _e(
        'Lead observation: {kind}.',
        'Inspect standing, role, and source basis separately.',
        'Displays retained evidence; navigation requires an available current reference.',
        'Standing: {standing}. Role: {role}. Basis: {basis}. Source: {source}.'),

    'leads.expected_change': _e(
        'Expected-change condition: {change}.',
        'Check whether the condition was seen, opposed, or left unresolved.',
        'Displays the recorded condition state without creating new evidence.',
        'State: {state}. Required: {required}. Rule: {rule}. Observations: {observations}.'),

    'leads.component': _e(
        'Recorded dependency component.',
        'Check shared origins before counting separate support.',
        'Displays the retained component breakdown.',
        'Component: {component}. Origins: {origins}. Observations: {observations}.'),

    'leads.review_event': _e(
        'Recorded analyst review event.',
        'Keep presentation choices and independent statements traceable.',
        'Displays append-only history without changing the derived class.',
        'Action: {action}. Time: {time}. Statement: {statement}.'),

    'leads.navigation_reason': _e(
        'The selected lead cannot open a current comparison row.',
        'Inspect the identity or availability limit before continuing.',
        'Displays the reason without choosing a substitute function.',
        'Candidate: {candidate}. Recorded reason: {reason}.'),

    'leads.stale_reason': _e(
        'The lead assessment describes earlier inputs.',
        'Identify the changed source before reusing its ordering.',
        'Retains reference content and offers the appropriate preparation route.',
        'Recorded input comparison: {reason}.'),
}
