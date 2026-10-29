"""Proposed Strings panel tooltip copy.

PLANNED: follows the WB3 integration plan.
The panel declaration was unavailable during review.
Implemented behavior and packaged Windows availability are UNVERIFIED.

Sources:
- docs/specs/program-e/WB3-integration-plan.md, sections 6-8
- src/patchtrace/panel_manifest.py

Additional IDs require explicit bindings to the documented controls and fields.
strings.copy.escaped is the proposed semantic ID for escaped-text copying.
Changing an existing binding requires a coordinated registry update.

Extraction-setting changes and display filters must remain separate.
Emulation-derived observations must not use definite addition or removal labels.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


STRINGS_TOOLTIPS = {
    'strings.dock': _e(
        'Compare string observations from the older and newer artifacts.',
        'Inspect text differences alongside extraction coverage and code links.',
        'Shows the Strings panel without starting extraction.',
        'Stored string tables, extraction metadata, and comparison rules.'),

    'strings.action': _e(
        'Show or hide the Strings panel.',
        'Keep string context available beside the code.',
        'Toggles the dock; shortcut Ctrl+Shift+T.',
        'The planned Strings command and panel registry.'),

    'strings.source': _e(
        'Choose the built-in scanner or configured FLOSS source.',
        'Make the extraction method explicit before starting work.',
        'Changes the source selection without launching extraction.',
        'The available scanner adapters and configured tool path.'),

    'strings.source.builtin': _e(
        'Use the built-in plain-string scanner.',
        'Read supported text directly from artifact bytes without external setup.',
        'Selects the built-in source; Scan starts the operation.',
        'The documented ASCII and ASCII-range UTF-16LE scanning semantics.'),

    'strings.source.floss': _e(
        'Use the configured FLOSS extraction source.',
        'Access the supported external extraction methods.',
        'Selects FLOSS; execution remains an explicit action.',
        'The chosen FLOSS executable and supported adapter.'),

    'strings.path': _e(
        'Choose the FLOSS executable used by explicit tool actions.',
        'Identify the installed program before probing or running it.',
        'Sets the candidate path without executing it.',
        'The local executable selected by the analyst.'),

    'strings.browse': _e(
        'Browse for an installed FLOSS executable.',
        'Avoid typing the executable path.',
        'Fills the FLOSS path field without running the program.',
        'The local file selected in the picker.'),

    'strings.probe': _e(
        'Explicitly check the selected FLOSS executable.',
        'Determine whether it meets the supported integration requirements.',
        'Runs the documented tool check without starting target extraction.',
        'The selected executable and FLOSS capability requirements.'),

    'strings.pin_status': _e(
        'Read the selected FLOSS build and pin status.',
        'Relate extraction compatibility to the tested tool build.',
        'Displays the probe result without starting a scan.',
        'The explicit FLOSS probe and configured integration baseline.'),

    'strings.run.builtin': _e(
        'Scan both project artifacts for supported plain strings.',
        'Create a local baseline without FLOSS.',
        'Reads artifact bytes without executing the target files.',
        'Project-owned artifact copies and built-in scan settings.'),

    'strings.run.floss': _e(
        'Run the configured supported FLOSS baseline extraction.',
        'Collect the selected non-emulation string observations.',
        'Starts an external analysis tool; target files are supplied as data.',
        'The selected FLOSS executable, options, and artifact identities.'),

    'strings.run.emulation': _e(
        'Review an optional FLOSS emulation request.',
        'Inspect the operation before collecting emulation-derived strings.',
        'Opens consent with Cancel selected by default; approval starts the request.',
        'The configured FLOSS adapter and emulation request plan.'),

    'strings.emulation.preview': _e(
        'Read the proposed emulation operation and its limitations.',
        'Understand the selected methods, skipped imports, and runtime constraints.',
        'Displays the request before approval.',
        'The emulation options and documented consent text.'),

    'strings.emulation.accept': _e(
        'Approve the displayed FLOSS emulation request.',
        'Authorize the specific operation being reviewed.',
        'Starts tool emulation and records the consent identity.',
        'The displayed request, selected executable, and chosen artifacts.'),

    'strings.emulation.cancel': _e(
        'Close the emulation request without approval.',
        'Return to string review without starting optional emulation.',
        'Closes the consent dialog without launching the request.',
        'The pending emulation consent dialog.'),

    'strings.cancel': _e(
        'Request cancellation of the active string extraction.',
        'Stop extraction work that is no longer needed.',
        'Stops through the supported lifecycle; cancelled work does not replace earlier results.',
        'The active built-in or external extraction operation.'),

    'strings.elapsed': _e(
        'Read the elapsed extraction time and current side.',
        'Follow work that has no measured completion fraction.',
        'Displays operation timing and stage information.',
        'The active extraction lifecycle.'),

    'strings.basis': _e(
        'Read whether the two extraction results can be compared.',
        'Check settings and coverage before interpreting differences.',
        'Displays harmonizations, exclusions, or the blocking reason.',
        'The older and newer StringBasis records.'),

    'strings.basis.minimum': _e(
        'Read the minimum string length used for comparison.',
        'Recognize when shorter observations were excluded from both sides.',
        'Displays the harmonized larger minimum when the scans differ.',
        'The two scan minima and comparison-basis rules.'),

    'strings.basis.types': _e(
        'Read which extraction types are comparable on both sides.',
        'Avoid treating a type extracted on one side only as a change.',
        'Displays the comparable type intersection and excluded types.',
        'Per-side extraction types and stage records.'),

    'strings.basis.semantics': _e(
        'Read the scanner semantics used to interpret the bytes.',
        'Identify method differences that prevent meaningful comparison.',
        'Displays compatible semantics or a blocking mismatch.',
        'The source parts and recorded semantics identifiers.'),

    'strings.rescan': _e(
        'Rescan the older artifact using the newer scan settings.',
        'Repair a documented comparison-basis mismatch.',
        'Starts a supported extraction request using the displayed settings.',
        'The older artifact identity and newer scan configuration.'),

    'strings.reload': _e(
        'Reload stored string observations and comparison state.',
        'Replace a stale display with current retained material.',
        'Reads available records without silently starting external extraction.',
        'Current project identities and stored string data.'),

    # Display filters.

    'strings.filter.change': _e(
        'Choose which string-change labels to display.',
        'Focus on newer-only, older-only, edited, or other recorded states.',
        'Filters the table without changing extraction coverage.',
        'The current StringsDelta records.'),

    'strings.filter.type': _e(
        'Choose which extraction types appear in the table.',
        'Separate plain, language-specific, and emulation-derived observations.',
        'Filters stored rows without starting another extraction.',
        'Recorded per-side extraction types.'),

    'strings.filter.side': _e(
        'Choose which artifact side contributes visible observations.',
        'Keep older and newer text distinguishable.',
        'Filters the displayed records by their retained side information.',
        'The stored artifact-side associations.'),

    'strings.filter.cue': _e(
        'Filter strings by the documented review cues.',
        'Find text patterns relevant to the current inspection.',
        'Narrows the table without treating a cue as a conclusion.',
        'Recorded cue labels and their matching rules.'),

    'strings.filter.minlen': _e(
        'Filter displayed observations by string length.',
        'Reduce short text while preserving the original scan basis.',
        'Changes visible rows; it does not recover strings excluded during extraction.',
        'Retained string lengths and the display filter.'),

    'strings.filter.text': _e(
        'Filter displayed string observations by text.',
        'Locate a value within the loaded inventory.',
        'Narrows visible rows; Ctrl+F focuses this field and Escape clears it.',
        'The retained display text and supported filter rules.'),

    'strings.filter.scope': _e(
        'Choose Differences or All strings.',
        'Switch between change review and the retained inventory.',
        'Changes the displayed population without rescanning artifacts.',
        'The current delta and available per-side string tables.'),

    'strings.filter.scope_differences': _e(
        'Show the recorded string differences.',
        'Start review with changed observations rather than the entire inventory.',
        'Selects the default Differences scope.',
        'Comparable string records and delta classifications.'),

    'strings.filter.scope_all': _e(
        'Show the retained string inventory.',
        'Inspect unchanged text and extraction context.',
        'Selects All strings subject to display limits.',
        'The retained older and newer string tables.'),

    'strings.filter.noise': _e(
        'Hide noise-like observations in the inventory view.',
        'Reduce repetitive inventory text while retaining a visible hidden count.',
        'Changes inventory display only; delta computation and export retain the records.',
        'Recorded noise-like cues and the inventory display policy.'),

    'strings.filter.function': _e(
        'Read the function restriction applied to the string view.',
        'Keep the current function context visible.',
        'Restricts rows using available recorded links without inventing attribution.',
        'The navigator selection and retained StringLink records.'),

    'strings.in_function': _e(
        'Show string observations linked to the selected function.',
        'Inspect available text context from the navigator.',
        'Sets the function restriction and opens the Strings view.',
        'The selected function identity and supported string links.'),

    # Extraction types.

    'strings.type.static': _e(
        'Read strings obtained through supported static byte scanning.',
        'Distinguish directly scanned text from emulation-derived observations.',
        'Displays static observations within the scanner encoding limits.',
        'The built-in or compatible FLOSS static source part.'),

    'strings.type.language': _e(
        'Read strings reported by a supported language-specific extraction stage.',
        'Keep language-dependent coverage visible.',
        'Displays retained language observations; incompatible stages remain not compared.',
        'The FLOSS language stage and recorded executable identity.'),

    'strings.type.stack': _e(
        'Read stack-string observations from optional emulation.',
        'Keep heuristic extraction separate from complete byte-scan coverage.',
        'Displays what the stage found; an absent observation is not a removal.',
        'The FLOSS stack stage and its emulation source part.'),

    'strings.type.tight': _e(
        'Read tight-string observations from optional emulation.',
        'Identify observations obtained through that extraction method.',
        'Displays stage output with its heuristic coverage limits.',
        'The FLOSS tight-string stage and recorded run.'),

    'strings.type.decoded': _e(
        'Read decoded-string observations from optional emulation.',
        'Inspect recovered text while retaining decoder-attribution limits.',
        'Displays stage output without assuming missed values are absent.',
        'The FLOSS decoded-string stage and retained evidence.'),

    # Table and column headers.

    'strings.table': _e(
        'Read string changes with per-side locations, links, cues, and sources.',
        'Inspect each value together with its comparison basis.',
        'Selection opens details; Enter opens an available function or byte location.',
        'The retained string tables and derived delta.'),

    'strings.col.change': _e(
        'Read the recorded string-change state.',
        'Separate comparable differences from unresolved coverage.',
        'Displays a word and glyph for the state.',
        'The delta classification and per-type comparison basis.'),

    'strings.col.string': _e(
        'Read the bounded escaped representation of the string.',
        'Recognize text without interpreting embedded controls.',
        'Displays redacted content when the value is marked secret-like.',
        'The retained string value, display rules, and redaction metadata.'),

    'strings.col.type': _e(
        'Read the extraction type associated with the observation.',
        'Distinguish static coverage from language or emulation methods.',
        'Displays the retained type labels.',
        'The per-side extraction-stage records.'),

    'strings.col.older': _e(
        'Read available older-side presence and location information.',
        'Locate the observation within the baseline artifact.',
        'Displays retained values without guessing missing offsets.',
        'The older string table and its extraction basis.'),

    'strings.col.newer': _e(
        'Read available newer-side presence and location information.',
        'Locate the observation within the later artifact.',
        'Displays retained values without guessing missing offsets.',
        'The newer string table and its extraction basis.'),

    'strings.col.function': _e(
        'Read the available function links and their attribution limits.',
        'Check how the text is associated with code.',
        'Displays recorded links; no link does not mean unused text.',
        'Retained StringLink records and pairing information.'),

    'strings.col.cues': _e(
        'Read review cues assigned to the observation.',
        'Identify text patterns worth inspecting in context.',
        'Displays labels without assigning a purpose to the change.',
        'The documented cue vocabulary and matching rules.'),

    'strings.col.source': _e(
        'Read the extraction source associated with this observation.',
        'Keep each value attached to its producing method.',
        'Displays retained source and lineage information.',
        'The string-basis source parts and extraction provenance.'),

    # Detail views and actions.

    'strings.detail': _e(
        'Read the selected string summary, links, and provenance.',
        'Inspect its change label together with its source limits.',
        'Displays selectable plain text without editing the observation.',
        'The selected string-change record and associated evidence.'),

    'strings.detail.tabs': _e(
        'Switch between Summary, Links, and Provenance.',
        'Choose the aspect of the selected observation to inspect.',
        'Changes the visible read-only detail page.',
        'The selected string record and retained metadata.'),

    'strings.detail.summary': _e(
        'Read the value comparison and its recorded explanations.',
        'Inspect what changed before following a code link.',
        'Shows both values for an Edited row and any comparison limitations.',
        'The selected StringChange record.'),

    'strings.detail.links': _e(
        'Read the available links from this observation to functions or text.',
        'Check attribution strength and ambiguity before navigation.',
        'Displays recorded links without selecting an unsupported target.',
        'The selected StringLink records and their evidence references.'),

    'strings.detail.provenance': _e(
        'Read artifact, tool, settings, and source identities.',
        'Retain the extraction basis alongside the observation.',
        'Displays available hashes, run identifiers, and consent identity.',
        'The older and newer StringBasis source parts.'),

    'strings.detail.lookalike': _e(
        'Read differing code points and Unicode names for a look-alike pair.',
        'Distinguish visually similar text from identical character sequences.',
        'Displays the recorded character differences as plain text.',
        'The paired string values and look-alike comparison record.'),

    'strings.open.function': _e(
        'Open the selected observation at an available function link.',
        'Inspect the code associated with the text.',
        'Selects the recorded match and reveals a line when a supported reference exists.',
        'The selected StringLink and current project function records.'),

    'strings.open.hex': _e(
        'Open a retained string location in the artifact byte view.',
        'Inspect the bytes at an available file offset.',
        'Navigates to the selected side offset; the other pane uses its own same offset.',
        'The retained per-side file offset and project artifact.'),

    'strings.open.hex_older': _e(
        'Open the older-side file offset for this observation.',
        'Inspect the baseline bytes behind a retained location.',
        'Shows the older offset; the newer pane shows that offset in its own file.',
        'The observation older-side file offset.'),

    'strings.open.hex_newer': _e(
        'Open the newer-side file offset for this observation.',
        'Inspect the later-build bytes behind a retained location.',
        'Shows the newer offset; the older pane shows that offset in its own file.',
        'The observation newer-side file offset.'),

    'strings.copy.escaped': _e(
        'Copy escaped single-line text for selected observations.',
        'Retain readable text without pasting raw control characters.',
        'Copies up to 200 rows and 16 KiB; secret-like values remain redacted.',
        'Selected string display values and redaction rules.'),

    'strings.copy.exact': _e(
        'Request exact-text copying for the selected observation.',
        'Use original characters when escaped display is insufficient.',
        'Reviews control characters before copying; secret disclosure is not implied.',
        'The retained value, control-character checks, and redaction policy.'),

    'strings.copy.exact_preview': _e(
        'Review the exact-copy request before accepting control characters.',
        'Inspect the difference between displayed escapes and copied content.',
        'Shows the copy request without changing project evidence.',
        'The selected value and exact-copy checks.'),

    'strings.copy.exact_accept': _e(
        'Approve the displayed exact-copy request.',
        'Confirm the specific text-copy operation.',
        'Copies the reviewed eligible content to the clipboard.',
        'The pending copy request and applicable redaction rules.'),

    'strings.copy.exact_cancel': _e(
        'Close the exact-copy request without copying.',
        'Return to the escaped display.',
        'Closes the confirmation without writing its content to the clipboard.',
        'The pending exact-copy dialog.'),

    'strings.export': _e(
        'Export string observations with their basis and provenance.',
        'Preserve a bounded inventory or comparison outside the panel.',
        'Uses the supported export workflow; output is redacted by default.',
        'The selected export scope, string records, and extraction metadata.'),

    'strings.status': _e(
        'Read extraction coverage and the current string-view status.',
        'Distinguish complete comparison from missing or partial stages.',
        'Displays counts, limits, and operation outcomes.',
        'The extraction bases and current delta result.'),

    # Change chips.

    'strings.change.only_newer': _e(
        'This comparable observation appears only in the newer scan.',
        'Inspect newer-side text within the stated extraction coverage.',
        'Displays Only in newer for supported comparable observations.',
        'The two comparable string inventories and their coverage.'),

    'strings.change.only_older': _e(
        'This comparable observation appears only in the older scan.',
        'Inspect older-side text within the stated extraction coverage.',
        'Displays Only in older for supported comparable observations.',
        'The two comparable string inventories and their coverage.'),

    'strings.change.edited': _e(
        'Two observations are paired as an edited-string candidate.',
        'Inspect both values and the basis for pairing them.',
        'Displays old and new text with explicit change markers.',
        'The documented bounded edit-pairing rules and linked function context.'),

    'strings.change.both': _e(
        'The value occurs in both comparable inventories.',
        'Distinguish retained text from an apparent offset-only change.',
        'Displays In both without asserting identical reference behavior.',
        'The value comparison and per-side locations.'),

    'strings.change.representation': _e(
        'The retained text has a recorded representation change.',
        'Inspect encoding or representation separately from wording.',
        'Displays the recorded representation difference.',
        'The value identity, per-side encodings, and delta rules.'),

    'strings.change.not_compared': _e(
        'This observation lacks a compatible comparison on the other side.',
        'Keep one-sided extraction coverage distinct from a string change.',
        'Displays Not compared.',
        'The per-type comparison basis and extraction-stage status.'),

    'strings.change.indeterminate': _e(
        'Incomplete extraction prevents a definite presence comparison.',
        'Avoid interpreting truncation or failure as addition or removal.',
        'Displays an unresolved state rather than a definite delta.',
        'The affected scan limit, stage failure, or missing-side coverage.'),

    'strings.change.emulation_only_newer': _e(
        'Optional emulation found this observation only on the newer side.',
        'Retain the heuristic extraction limit.',
        'Displays where it was found without declaring its absence from the older file.',
        'The two emulation-stage outcomes and comparison basis.'),

    'strings.change.emulation_only_older': _e(
        'Optional emulation found this observation only on the older side.',
        'Retain the heuristic extraction limit.',
        'Displays where it was found without declaring its absence from the newer file.',
        'The two emulation-stage outcomes and comparison basis.'),

    # Complete documented cue vocabulary.

    'strings.cue.message': _e(
        'This text has a message-like review cue.',
        'Inspect surrounding code for how the text is used.',
        'Displays a cue without establishing runtime use.',
        'The documented message-cue rules.'),

    'strings.cue.format': _e(
        'This text contains a recognized format-string cue.',
        'Inspect specifiers, widths, and the arguments used with the text.',
        'Displays the cue without establishing the effect of a format change.',
        'The format-cue recognizer and retained string value.'),

    'strings.cue.path': _e(
        'This text has a path-like review cue.',
        'Inspect possible file or directory references.',
        'Displays a text-pattern cue without establishing filesystem access.',
        'The path-cue recognizer and retained value.'),

    'strings.cue.registry': _e(
        'This text has a registry-path review cue.',
        'Inspect code that may use the recorded registry reference.',
        'Displays a cue without establishing an executed registry operation.',
        'The registry-cue recognizer and retained value.'),

    'strings.cue.url': _e(
        'This text has a URL-like review cue.',
        'Inspect the address as data before considering its use.',
        'Displays text only; selecting the cue does not contact the address.',
        'The URL-cue recognizer and retained value.'),

    'strings.cue.guid': _e(
        'This text has a GUID-like review cue.',
        'Inspect a recognizable identifier in its code context.',
        'Displays the cue without assigning a component identity.',
        'The GUID-cue recognizer and retained value.'),

    'strings.cue.api_name': _e(
        'This text matches an available import or export name.',
        'Inspect the relation between the text and recorded API metadata.',
        'Displays the match without establishing a call.',
        'The value and available PE import or export names.'),

    'strings.cue.dynamic_api': _e(
        'This text matches the documented dynamic-API cue rules.',
        'Inspect possible runtime API-name use in the surrounding code.',
        'Displays an investigative cue without establishing API resolution or execution.',
        'Available API anchors and cross-side import information.'),

    'strings.cue.dll_name': _e(
        'This text has a DLL-name review cue.',
        'Inspect references to a named library component.',
        'Displays the text-pattern cue without establishing that the library is loaded.',
        'The DLL-name recognizer and retained value.'),

    'strings.cue.pdb_path': _e(
        'This text has a PDB-path review cue.',
        'Inspect build-related text while considering disclosure in copied material.',
        'Displays the cue without establishing access to a symbol file.',
        'The PDB-path recognizer and retained value.'),

    'strings.cue.version': _e(
        'This text has a version-like review cue.',
        'Inspect build or component context without assuming chronology.',
        'Displays the cue without establishing build lineage.',
        'The version-cue recognizer and retained value.'),

    'strings.cue.identifier': _e(
        'This text has an identifier-like review cue.',
        'Inspect a structured name in its recorded context.',
        'Displays the cue without resolving it to a function.',
        'The identifier-cue rules and retained value.'),

    'strings.cue.advisory_text': _e(
        'This text matches a retained advisory-text anchor.',
        'Inspect the matching phrase without assuming a causal relationship.',
        'Displays the anchor connection as context.',
        'The string observation and referenced advisory anchor.'),

    'strings.cue.advisory_api': _e(
        'This text matches an API anchor from advisory context.',
        'Inspect the referenced API in the selected code.',
        'Displays a search connection without assigning the patch to that advisory.',
        'The retained API anchor and string observation.'),

    'strings.cue.lookalike': _e(
        'Different character sequences appear visually similar.',
        'Inspect code points before treating the values as identical.',
        'Displays the cue and available character differences.',
        'The look-alike pairing rules and retained values.'),

    'strings.cue.secret_like': _e(
        'This observation is marked as secret-like text.',
        'Keep the disclosure restriction visible during review.',
        'Uses redacted display and the documented copy, export, and indexing policy.',
        'The secret-kind classification and value hash.'),

    'strings.cue.resource': _e(
        'This observation has a resource-related review cue.',
        'Distinguish resource context from an established function reference.',
        'Displays the cue without inventing code attribution.',
        'The retained region information and resource-cue rules.'),

    'strings.cue.noise_like': _e(
        'This observation is classified as noise-like for reading order.',
        'Reduce repetitive inventory review without deleting evidence.',
        'Displays the cue; optional inventory hiding retains a visible count.',
        'The documented noise-like rules and display policy.'),

    # Basis and extraction states.

    'strings.state.no_project': _e(
        'Open a project before comparing string observations.',
        'Associate extraction with a specific artifact pair.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'strings.state.no_data': _e(
        'No string extraction results are available for this pair.',
        'Distinguish missing preparation from no differences.',
        'Offers the built-in scan without requiring FLOSS.',
        'The project extraction inventory.'),

    'strings.state.running': _e(
        'String extraction is running for the displayed artifact side.',
        'Follow the current stage and elapsed time.',
        'Displays activity and offers cancellation.',
        'The active extraction operation.'),

    'strings.state.ready': _e(
        'Comparable string observations are ready to review.',
        'Read differences alongside their extraction basis.',
        'Displays recorded changes in the documented reading order.',
        'The completed delta and compatible source parts.'),

    'strings.state.no_differences': _e(
        'No differences were found within the comparable scan coverage.',
        'Keep the result bounded by encodings and extraction methods.',
        'Displays the outcome without asserting that all binary text was covered.',
        'The compatible inventories and their declared coverage.'),

    'strings.state.basis_blocked': _e(
        'The scan settings do not support the requested comparison.',
        'Prevent mismatched methods from appearing as text changes.',
        'Shows the reason and supported older-side rescan action.',
        'The older and newer comparison-basis records.'),

    'strings.state.incomplete': _e(
        'A scan limit or stage failure leaves extraction incomplete.',
        'Keep missing observations distinct from additions or removals.',
        'Marks affected comparisons unresolved and shows the limit.',
        'The affected side, type, and stage outcome.'),

    'strings.state.failed': _e(
        'String extraction failed.',
        'Identify the reported cause before repeating work.',
        'Shows the code and message while retaining earlier results.',
        'The extraction failure record.'),

    'strings.state.stale': _e(
        'These observations describe earlier project inputs.',
        'Keep historical string links separate from current code.',
        'Shows the reason; stale records do not navigate into a different context.',
        'Artifact, run, output, and orientation identity checks.'),

    'strings.state.floss_missing': _e(
        'FLOSS is not configured.',
        'Identify the optional dependency for additional extraction types.',
        'Keeps the built-in plain-string scan available.',
        'The configured-tool inventory and FLOSS requirements.'),

    'strings.state.floss_unsupported': _e(
        'The selected FLOSS build is outside the supported integration.',
        'Distinguish tool incompatibility from missing strings.',
        'Shows the reason and tested baseline instead of starting unsupported extraction.',
        'The explicit tool probe and documented FLOSS 3.1.1 baseline.'),

    'strings.state.cancelled': _e(
        'The extraction attempt was cancelled.',
        'Distinguish interrupted work from a completed comparison.',
        'Retains earlier results without saving the cancelled attempt as current output.',
        'The extraction cancellation outcome.'),

    'strings.state.language_not_compared': _e(
        'Language-specific observations cannot be compared under these scan settings.',
        'Keep language-detection differences from appearing as text removal.',
        'Excludes the incompatible stage while preserving comparable static coverage.',
        'The two language-stage bases and compatibility rules.'),

    'strings.state.emulation_not_compared': _e(
        'The emulation source parts do not support a cross-side comparison.',
        'Keep missing or differently approved stages distinct from a change.',
        'Marks the affected emulation observations not compared.',
        'Executable identities, stage presence, and consent digests.'),

    'strings.state.static_none_found': _e(
        'The static stage found no supported strings.',
        'Keep this result limited to the static scan.',
        'Does not mark unperformed emulation stages as completed.',
        'The static stage outcome and per-stage execution record.'),

    'strings.state.no_function_link': _e(
        'No usable function link is available for this observation.',
        'Avoid treating missing attribution as unused text.',
        'Keeps function navigation unavailable; a retained byte offset may still be usable.',
        'The selected observation and its available links.'),

    'strings.state.no_file_offset': _e(
        'No usable file offset is available for the selected side.',
        'Avoid guessing where an emulation-derived value exists on disk.',
        'Keeps byte navigation unavailable for that location.',
        'The retained extraction location fields.'),

    'strings.state.no_visible_rows': _e(
        'No observations pass the current display filters.',
        'Distinguish a filtered inventory from an empty extraction.',
        'Requests broader filters without rerunning extraction.',
        'The loaded records and active display query.'),

    'strings.retry': _e(
        'Retry the failed string operation.',
        'Repeat work after addressing its reported cause.',
        'Starts the supported retry path with the applicable request checks.',
        'The current request and retained failure state.'),

    'strings.copy_error': _e(
        'Copy the string-operation error details.',
        'Preserve the code and message for diagnosis.',
        'Writes available plain-text diagnostics to the clipboard.',
        'The retained extraction or comparison error.'),
}


STRINGS_TOOLTIP_TEMPLATES = {
    'strings.row': _e(
        'String observation: {display}.',
        'Inspect its change, extraction method, and attribution limits.',
        'Select for details before using a code or byte link.',
        'Change: {change}. Type: {type}. Side: {side}. Source: {source}.'),

    'strings.cell': _e(
        'String field: {field}.',
        'Interpret the value within its extraction coverage.',
        'Displays retained data without extending its meaning.',
        'Value: {value}. Basis: {basis}. Limits: {limits}.'),

    'strings.link': _e(
        'Recorded string-to-code link.',
        'Check attribution method and ambiguity before navigation.',
        'Opens a target only when a usable current reference exists.',
        'Tier: {tier}. Function: {function}. Basis: {basis}. Origin: {origin}.'),

    'strings.basis_note': _e(
        'String-comparison basis note.',
        'Read which settings were harmonized or excluded.',
        'Displays the restriction without changing the original scan.',
        'Affected type: {type}. Rule: {rule}. Details: {reason}.'),

    'strings.cue': _e(
        'String review cue: {cue}.',
        'Inspect the text in context before assigning meaning.',
        'Displays the cue explanation and suggested next inspection.',
        'Basis: {basis}. Origin: {origin}.'),

    'strings.offset': _e(
        'Recorded string byte location.',
        'Check side and offset before opening the raw view.',
        'Navigates only to the retained file-backed location.',
        'Side: {side}. File offset: {offset}. Artifact: {artifact}.'),

    'strings.lookalike': _e(
        'The paired values contain different character sequences.',
        'Inspect code points rather than relying on appearance.',
        'Displays the retained character differences.',
        'Older: {older}. Newer: {newer}. Differences: {codepoints}.'),

    'strings.omitted': _e(
        'Some string observations are outside the displayed result.',
        'Keep limits and hidden inventory rows visible.',
        'Reports the omitted population without deleting the records.',
        'Shown: {shown}. Omitted: {omitted}. Reason: {reason}.'),

    'strings.lineage': _e(
        'Recorded origin shared by string observations.',
        'Avoid counting the same extraction basis as separate corroboration.',
        'Displays the source lineage without combining unrelated measurements.',
        'Lineage group: {group}. Source parts: {parts}.'),

    'strings.stale_reason': _e(
        'The string view describes earlier inputs.',
        'Identify what changed before reusing an observation.',
        'Retains reference content and offers the supported reload route.',
        'Recorded source comparison: {reason}.'),
}
