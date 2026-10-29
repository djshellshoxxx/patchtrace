"""Proposed Rules panel tooltip copy.

PLANNED: follows the YRX integration plan.
The panel declaration was unavailable during review.
Implemented controls and packaged Windows availability are UNVERIFIED.

Sources:
- docs/specs/program-e/YRX-integration-plan.md, sections 7-8
- src/patchtrace/panel_manifest.py

Additional IDs require explicit bindings to documented controls and fields.
Proposal, acceptance, testing, and export are separate operations.
The generated rule text is read-only.
Accepted versions and review decisions remain append-only.

A Match cell reports pattern recognition in a scanned file.
A No match cell requires completed evaluation.
Unreadable, cancelled, and timed-out targets remain distinct.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


RULES_TOOLTIPS = {
    'rules.dock': _e(
        'Review proposed detection rules and their recorded tests.',
        'Inspect patterns derived from an explicitly reviewed function pair.',
        'Shows the Rules panel without proposing, testing, or exporting automatically.',
        'Stored rule candidates, decisions, versions, and test records.'),

    'rules.action': _e(
        'Show or hide the Rules panel.',
        'Keep rule review beside the compared code.',
        'Toggles the dock; shortcut Ctrl+Shift+R.',
        'The planned panel command and central manifest.'),

    'rules.pair': _e(
        'Read the function pair selected for rule proposal.',
        'Check identities, orientation, and review status before generating patterns.',
        'Displays the current source pair without accepting it.',
        'The project match, function records, and analyst review.'),

    'rules.propose': _e(
        'Propose rules for the eligible reviewed function pair.',
        'Generate candidates tied to an explicit comparison.',
        'Builds and checks bounded candidates; acceptance and export remain separate.',
        'The accepted pair, available bytes, linked features, and proposal rules.'),

    'rules.cancel': _e(
        'Request cancellation of active rule work.',
        'Stop proposal or testing that is no longer needed.',
        'Stops through the worker lifecycle without replacing saved rule versions.',
        'The active proposal or test operation.'),

    'rules.tabs': _e(
        'Switch between Candidates, Test grid, and Saved rules.',
        'Keep generation, evaluation, and retained versions distinguishable.',
        'Changes the visible page without starting an operation.',
        'The Rules panel layout and loaded records.'),

    'rules.tab.candidates': _e(
        'Open proposed rules and their selected features.',
        'Review generated text and checks before making a decision.',
        'Shows candidates without accepting or exporting them.',
        'Stored candidate records for the selected pair.'),

    'rules.tab.grid': _e(
        'Open the builds-by-rules test grid.',
        'Inspect observed outcomes against recorded expectations.',
        'Shows retained test results without starting another scan.',
        'The selected matrix run and target records.'),

    'rules.tab.saved': _e(
        'Open accepted rule lineages and versions.',
        'Inspect retained rules, test status, and history.',
        'Shows saved records without exporting a file.',
        'Stored RuleVersion and RuleDecision records.'),

    'rules.candidates': _e(
        'Read proposed rules for the selected pair.',
        'Choose a candidate for feature and check review.',
        'Selection updates details; Enter opens the source pair.',
        'The retained candidate list and review decisions.'),

    'rules.features': _e(
        'Read candidate features and their older and newer observations.',
        'Check which patterns and gates contribute to the rule.',
        'Selecting features updates the candidate through the supported revision workflow.',
        'The candidate feature records and their source evidence.'),

    'rules.checks': _e(
        'Read the candidate eligibility and pattern checks.',
        'Inspect measured values before accepting or exporting.',
        'Displays each gate result without combining checks into a score.',
        'The candidate Gate records and engine checks.'),

    'rules.rule_text': _e(
        'Read the generated rule text.',
        'Inspect the exact candidate or version before further action.',
        'Displays read-only text; editing is through supported feature selection.',
        'The retained rule text and its digest.'),

    'rules.copy_text': _e(
        'Copy the displayed stored rule text.',
        'Inspect or retain the generated text elsewhere.',
        'Writes the rule text to the clipboard; shortcut Ctrl+C in the rule context.',
        'The selected candidate or accepted version.'),

    'rules.accept': _e(
        'Review acceptance of the selected candidate.',
        'Record an analyst-labelled rule version.',
        'Opens acceptance; Ctrl+Enter uses the same route.',
        'The selected candidate, current checks, and decision workflow.'),

    'rules.reject': _e(
        'Reject the selected rule candidate.',
        'Record that it should not be accepted in its present form.',
        'Adds a review decision without deleting the candidate.',
        'The selected candidate identity and analyst action.'),

    'rules.defer': _e(
        'Defer the selected rule candidate.',
        'Retain it for later review without accepting it.',
        'Adds a review decision without exporting or deleting anything.',
        'The selected candidate identity and analyst action.'),

    'rules.archive': _e(
        'Archive the selected retained rule through its review workflow.',
        'Retire it from active use while preserving history.',
        'Adds an archive decision without deleting stored versions.',
        'The selected lineage or candidate and recorded decision history.'),

    'rules.open_pair': _e(
        'Open the source function pair for the selected rule.',
        'Compare the code behind the proposed pattern.',
        'Navigates to an available current match or reports its limitation.',
        'The rule source reference and current project records.'),

    'rules.saved': _e(
        'Read accepted lineages, labels, versions, and test status.',
        'Choose a retained rule for testing, export, or history review.',
        'Selection changes the inspected rule version.',
        'Stored rule versions and associated decisions and tests.'),

    'rules.history': _e(
        'Read the selected rule lineage history.',
        'Inspect prior decisions and immutable versions.',
        'Displays retained history without restoring or rewriting a version.',
        'Append-only rule decisions and version relationships.'),

    'rules.status': _e(
        'Read proposal, testing, and error status.',
        'Distinguish active work from retained results.',
        'Displays lifecycle updates without accepting a rule.',
        'The current Rules operation and view model.'),

    'rules.footer': _e(
        'Read the limits of rule-test outcomes.',
        'Keep pattern recognition separate from broader conclusions about a file.',
        'Displays persistent guidance; counts remain raw measurements.',
        'The rule-testing interpretation contract.'),

    # Candidate states.

    'rules.candidate.proposed': _e(
        'This candidate has not been accepted as a rule version.',
        'Keep generation separate from analyst approval.',
        'Displays Proposed with its available checks.',
        'The candidate and associated decision records.'),

    'rules.candidate.accepted': _e(
        'An analyst accepted a version derived from this candidate.',
        'Identify the retained decision and version.',
        'Displays the acceptance state without implying publication.',
        'The RuleDecision and resulting RuleVersion.'),

    'rules.candidate.rejected': _e(
        'An analyst rejected this candidate.',
        'Preserve the recorded review outcome.',
        'Displays Rejected without removing its source record.',
        'The retained rejection decision.'),

    'rules.candidate.deferred': _e(
        'An analyst deferred this candidate.',
        'Identify work awaiting further review.',
        'Displays Deferred without accepting the rule.',
        'The retained deferral decision.'),

    'rules.candidate.needs_review': _e(
        'This candidate requires additional review.',
        'Keep unresolved eligibility or evidence visible.',
        'Displays Needs review with the applicable reasons.',
        'The candidate state, checks, and source limitations.'),

    # Feature-table headers.

    'rules.col.include': _e(
        'Choose whether an eligible feature contributes to this candidate.',
        'Control the proposed rule through its supported features.',
        'Creates a candidate revision and reruns checks; only same-side features are eligible.',
        'The feature side, inclusion state, and candidate-generation rules.'),

    'rules.col.kind': _e(
        'Read the feature type.',
        'Distinguish bytes, strings, imports, and capability context.',
        'Displays the retained feature category.',
        'The selected candidate feature record.'),

    'rules.col.feature': _e(
        'Read the bounded escaped feature representation.',
        'Inspect the pattern or condition being considered.',
        'Displays the feature without interpreting its text as markup.',
        'The candidate feature and serializer.'),

    'rules.col.older': _e(
        'Read the older-side observation for this feature.',
        'Check baseline presence and source coverage.',
        'Displays Present, Absent, or Unknown as supported.',
        'The older artifact evaluation and producing-source status.'),

    'rules.col.newer': _e(
        'Read the newer-side observation for this feature.',
        'Check later-build presence and source coverage.',
        'Displays Present, Absent, or Unknown as supported.',
        'The newer artifact evaluation and producing-source status.'),

    'rules.col.source': _e(
        'Read the source of the candidate feature.',
        'Trace each rule component to its producing evidence.',
        'Displays the retained origin.',
        'The feature source reference and associated run metadata.'),

    'rules.col.where': _e(
        'Read the available feature location.',
        'Inspect the bytes or code associated with the proposed component.',
        'Offers navigation only for a usable retained location.',
        'The feature RVA, file offset, or supported evidence link.'),

    # Feature kinds and side states.

    'rules.feature_kind.bytes': _e(
        'Read a byte window with documented variable fields masked.',
        'Inspect which literal bytes and call pins define the pattern.',
        'Displays the generated window without asserting general build coverage.',
        'The bounded function extent, decoder, masking rules, and pair checks.'),

    'rules.feature_kind.string': _e(
        'Read a string feature checked against the source artifact.',
        'Inspect its exact bytes and code-link basis.',
        'Displays the retained encoding, value identity, and separation result.',
        'The string observation and bytes reread at its recorded location.'),

    'rules.feature_kind.import': _e(
        'Read an import feature or API gate.',
        'Inspect the external symbol condition used by the candidate.',
        'Displays the retained import metadata and inclusion state.',
        'PE imports or supported capa API evidence.'),

    'rules.feature_kind.capability': _e(
        'Read capability metadata associated with the candidate.',
        'Keep recognition context distinct from a direct byte pattern.',
        'Displays the supported metadata or API gates.',
        'Stored capability evidence and proposal rules.'),

    'rules.presence.present': _e(
        'The producing source reports this feature on the selected side.',
        'Inspect the basis before using it in a rule.',
        'Displays Present with the retained evidence.',
        'The completed producing-source observation.'),

    'rules.presence.absent': _e(
        'The producing source completed without this feature on the selected side.',
        'Distinguish evaluated absence from missing source output.',
        'Displays Absent within the source coverage.',
        'The completed producing-source evaluation.'),

    'rules.presence.unknown': _e(
        'The source cannot establish feature presence on this side.',
        'Avoid treating a missing or failed tool as an absent feature.',
        'Displays Unknown.',
        'The producing-source availability and outcome.'),

    # Candidate checks.

    'rules.check.eligibility': _e(
        'Read whether the source pair meets the reviewed-change requirement.',
        'Keep rule generation tied to an explicit analyst-reviewed comparison.',
        'Displays the materiality check or recorded analyst confirmation.',
        'The accepted pair, materiality record, and any explicit confirmation.'),

    'rules.check.length': _e(
        'Read literal-byte length and longest literal run.',
        'Inspect whether the proposed pattern meets the minimum length rules.',
        'Displays the measured values and gate state.',
        'The generated byte pattern and length thresholds.'),

    'rules.check.wildcards': _e(
        'Read how much of the generated byte pattern is masked.',
        'Inspect whether enough literal content remains.',
        'Displays the wildcard measurement and gate state.',
        'The pattern tokens and masking thresholds.'),

    'rules.check.unique': _e(
        'Read how many source-build locations contain the proposed pattern.',
        'Check whether the pattern isolates its intended source location.',
        'Displays the measured source hits and gate state.',
        'The bounded source-build pattern check.'),

    'rules.check.separates': _e(
        'Read whether the candidate separates the selected older and newer files.',
        'Check its behavior on the exact source pair.',
        'Displays pair-specific results without claiming coverage of other builds.',
        'The candidate scan against both anchor artifacts.'),

    'rules.check.compile': _e(
        'Read the YARA-X compilation check.',
        'Identify rejected syntax or disallowed compiler warnings.',
        'Displays the compiler result for the generated text.',
        'The isolated YARA-X compile operation and configured policy.'),

    'rules.check.secret': _e(
        'Read the check for secret-looking string material.',
        'Inspect whether a candidate contains restricted text features.',
        'Displays the gate outcome without revealing redacted values.',
        'The candidate string features and secret-detection policy.'),

    'rules.check.toolchain': _e(
        'Read the source-pair toolchain compatibility check.',
        'Inspect whether build differences limit pattern portability.',
        'Displays the check and any explicit recorded waiver.',
        'Available build-environment context and rule gate policy.'),

    'rules.gate.pass': _e(
        'This check meets its recorded requirement.',
        'Identify a completed gate within its stated scope.',
        'Displays Pass with its measured value.',
        'The individual Gate record.'),

    'rules.gate.fail': _e(
        'This check does not meet its recorded requirement.',
        'Inspect the failure before accepting or exporting.',
        'Displays Fail and the available explanation.',
        'The individual Gate record and threshold.'),

    'rules.gate.unknown': _e(
        'This check lacks enough evidence to establish an outcome.',
        'Keep missing evaluation distinct from passing.',
        'Displays Unknown.',
        'The individual Gate record and source limitation.'),

    'rules.gate.waived': _e(
        'This check has a recorded waiver where the workflow permits one.',
        'Keep an explicit exception distinguishable from a passed check.',
        'Displays Waived without overriding non-waivable requirements.',
        'The gate policy and recorded analyst decision.'),

    # Acceptance dialog.

    'rules.accept.summary': _e(
        'Read what accepting the selected candidate will save.',
        'Keep a project decision separate from publication and export.',
        'Explains that acceptance creates a retained rule version.',
        'The candidate and acceptance workflow.'),

    'rules.accept.label': _e(
        'Enter the required analyst label for this rule.',
        'Identify the retained version in lists and history.',
        'Validates a label from 1 to 120 characters before acceptance.',
        'The RuleDecision label contract.'),

    'rules.accept.cve': _e(
        'Enter an optional CVE reference supplied by the analyst.',
        'Retain investigation context separately from pattern behavior.',
        'Validates identifier syntax without checking that the rule detects that issue.',
        'Your entered reference and the identifier contract.'),

    'rules.accept.kb': _e(
        'Enter an optional KB reference supplied by the analyst.',
        'Retain update context beside the rule decision.',
        'Validates identifier syntax without establishing a fix boundary.',
        'Your entered reference and the identifier contract.'),

    'rules.accept.cwe': _e(
        'Enter an optional CWE reference supplied by the analyst.',
        'Retain the selected weakness-class context.',
        'Validates identifier syntax without assigning meaning to a pattern match.',
        'Your entered reference and the identifier contract.'),

    'rules.accept.note': _e(
        'Enter an optional note explaining the rule decision.',
        'Preserve the reasoning behind acceptance.',
        'Stores the note as analyst-authored context.',
        'Your entered text and the retained RuleDecision.'),

    'rules.accept.confirm': _e(
        'Accept the candidate as a retained project rule version.',
        'Record the labelled decision after reviewing its checks.',
        'Stores an immutable version; no file is published or exported.',
        'The candidate, current gates, and entered acceptance fields.'),

    'rules.accept.cancel': _e(
        'Close acceptance without saving an accepted version.',
        'Return to candidate review.',
        'Closes the dialog without accepting the candidate.',
        'The pending acceptance dialog.'),

    # Test setup and grid.

    'rules.targets': _e(
        'Read the selected files and their test roles.',
        'Check exactly which population the next test will evaluate.',
        'Displays target identities and limits without scanning.',
        'The prepared TargetRef list.'),

    'rules.series': _e(
        'Choose supported builds from a comparison series.',
        'Evaluate the selected rule beyond its two source anchors.',
        'Adds eligible series targets to the test request.',
        'The selected series manifest and available artifact records.'),

    'rules.extra': _e(
        'Choose additional local files for rule testing.',
        'Inspect behavior on explicitly selected examples.',
        'Adds eligible files as Extra targets without assigning expectations automatically.',
        'The selected local files and target-validation rules.'),

    'rules.clean': _e(
        'Choose a local comparison set labelled Clean for the test.',
        'Measure pattern matches in an explicitly chosen control population.',
        'Adds eligible targets; the role label does not classify their contents.',
        'The selected local directory and recorded target roles.'),

    'rules.expectation': _e(
        'Read or set the supported expected test outcome.',
        'Distinguish observed matches from analyst expectations.',
        'Records an expectation without changing the rule or target bytes.',
        'Anchor-direction rules or explicit analyst-supplied expectations.'),

    'rules.test_timeout': _e(
        'Set the per-target timeout from 5 to 300 seconds.',
        'Bound each requested scan.',
        'Applies to the test request; the documented default is 30 seconds.',
        'The rule-testing limits configuration.'),

    'rules.run_test': _e(
        'Test the selected rule versions against the listed targets.',
        'Record observed outcomes within an explicit file population.',
        'Starts bounded worker scans and retains their results and limits.',
        'The rule texts, target identities, engine stamp, and test options.'),

    'rules.grid': _e(
        'Read target files by rule version in the test matrix.',
        'Compare observations with recorded expectations.',
        'Selection opens the available cell details.',
        'The retained MatrixRun and target records.'),

    'rules.grid.filter_role': _e(
        'Filter test rows by target role.',
        'Inspect anchors, series builds, extra examples, or controls separately.',
        'Changes visible rows without rescanning files.',
        'The retained TargetRef role values.'),

    'rules.grid.filter_state': _e(
        'Filter cells or rows by recorded scan outcome.',
        'Focus on matches, incomplete work, or errors.',
        'Changes the displayed test population without altering results.',
        'The retained CellResult states.'),

    'rules.grid.unexpected_only': _e(
        'Show outcomes that differ from a recorded expectation.',
        'Concentrate on test cases needing explanation.',
        'Filters displayed results without inventing expectations for unscored targets.',
        'The observed outcomes and explicit expectation records.'),

    'rules.grid.summary': _e(
        'Read raw match, non-match, unscanned, and unexpected-outcome counts.',
        'Inspect test coverage alongside the observations.',
        'Displays counts separately without combining them into a score.',
        'The selected matrix cells and expectation comparisons.'),

    'rules.grid.detail': _e(
        'Read the selected rule-by-target evaluation.',
        'Inspect the target identity, outcome, offsets, and any failure reason.',
        'Displays retained cell details without rescanning.',
        'The CellResult, TargetRef, and engine stamp.'),

    # Target descriptors.

    'rules.target.ordinal': _e(
        'Read the target position in the retained test population.',
        'Keep test order distinguishable from importance.',
        'Displays the recorded ordinal.',
        'The TargetRef ordering.'),

    'rules.target.label': _e(
        'Read the recorded target label.',
        'Identify the selected test example.',
        'Displays the label without substituting for its hash identity.',
        'The retained TargetRef.'),

    'rules.target.kb': _e(
        'Read the KB context recorded for this target.',
        'Keep update metadata alongside the test observation.',
        'Displays the reference without establishing target applicability.',
        'The retained target metadata.'),

    'rules.target.file_version': _e(
        'Read the file-version metadata recorded for this target.',
        'Distinguish builds using available descriptive information.',
        'Displays the retained field without establishing chronology.',
        'The target file metadata.'),

    'rules.target.role': _e(
        'Read the target role in this test.',
        'Distinguish source anchors from series examples and controls.',
        'Displays the role without classifying the file contents.',
        'The prepared and retained target request.'),

    'rules.target.advisory': _e(
        'Read what retained advisory context states about this target.',
        'Keep documentary assertions separate from rule-test outcomes.',
        'Displays the source statement without treating a match as confirmation.',
        'The target advisory metadata and its recorded origin.'),

    # Test outcomes.

    'rules.cell.match': _e(
        'The completed scan matched this rule on this file.',
        'Inspect the matching pattern and available locations.',
        'Displays Match within the recorded scan configuration.',
        'The retained engine result for this rule and target.'),

    'rules.cell.no_match': _e(
        'The completed scan did not match this rule on this file.',
        'Inspect a completed negative pattern test within its scope.',
        'Displays No match without making broader claims about the file.',
        'The completed engine result and test configuration.'),

    'rules.cell.not_scanned': _e(
        'This target did not receive a usable completed scan.',
        'Keep missing evaluation distinct from No match.',
        'Displays Not scanned with its recorded reason.',
        'The target-validation or worker outcome.'),

    'rules.cell.timeout': _e(
        'The rule evaluation reached its configured time limit.',
        'Recognize that no completed test outcome was established.',
        'Displays Timed out instead of No match.',
        'The worker timeout outcome and test limits.'),

    'rules.cell.error': _e(
        'The rule evaluation ended with an error.',
        'Inspect the reported cause before repeating the test.',
        'Displays Error without interpreting the attempt as a match outcome.',
        'The retained worker failure.'),

    'rules.verdict.expected': _e(
        'The observed outcome agrees with the recorded expectation.',
        'Check a test case against its stated target behavior.',
        'Displays As expected.',
        'The CellResult and target expectation.'),

    'rules.verdict.unexpected_match': _e(
        'The rule matched where the recorded expectation was no match.',
        'Inspect why the pattern also recognizes this target.',
        'Displays Unexpected match without changing the expectation.',
        'The observed Match outcome and retained expectation.'),

    'rules.verdict.unexpected_miss': _e(
        'The completed scan did not match where a match was expected.',
        'Inspect whether the pattern or expectation needs revision.',
        'Displays Unexpected no match.',
        'The completed scan and retained expectation.'),

    'rules.verdict.unscored': _e(
        'No expectation is recorded for this target.',
        'Keep observation separate from an expected-outcome assessment.',
        'Displays No expectation.',
        'The target expectation state.'),

    # Closed Not scanned reasons.

    'rules.not_scanned.too_large': _e(
        'The target exceeds the permitted file-size limit.',
        'Identify a test-coverage limit.',
        'Leaves the target unscanned instead of reporting No match.',
        'The measured target size and configured ceiling.'),

    'rules.not_scanned.unreadable': _e(
        'The target file could not be read.',
        'Identify the file-access failure.',
        'Leaves the target unscanned.',
        'The target-read outcome.'),

    'rules.not_scanned.not_pe': _e(
        'The target does not meet the required PE input check.',
        'Keep unsupported input outside the test population.',
        'Leaves the target unscanned.',
        'The target-format validation.'),

    'rules.not_scanned.changed': _e(
        'The target changed while it was being read.',
        'Prevent an unstable input from receiving a misleading outcome.',
        'Leaves the target unscanned.',
        'The target identity and read-consistency checks.'),

    'rules.not_scanned.cancelled': _e(
        'The target scan was not completed because the run was cancelled.',
        'Distinguish interrupted work from a completed pattern test.',
        'Leaves the target unscanned.',
        'The test-run cancellation outcome.'),

    # Saved versions.

    'rules.saved.version': _e(
        'Read the retained rule version.',
        'Distinguish a new revision from an earlier accepted text.',
        'Displays the immutable version identity and lineage.',
        'The selected RuleVersion record.'),

    'rules.saved.label': _e(
        'Read the analyst label attached to this rule decision.',
        'Identify the retained research context.',
        'Displays analyst-authored text without changing rule behavior.',
        'The acceptance decision.'),

    'rules.saved.tested': _e(
        'Read when and on which population this version was tested.',
        'Keep test coverage attached to the selected rule text.',
        'Displays retained test counts and date.',
        'The associated matrix run and target identities.'),

    'rules.saved.not_tested': _e(
        'No applicable retained test is recorded for this version.',
        'Keep acceptance separate from evaluation.',
        'Displays Not tested.',
        'The selected version and available test records.'),

    'rules.saved.grid_stale': _e(
        'The retained test grid no longer matches the required evaluation basis.',
        'Identify why earlier test outcomes need review.',
        'Displays the stale reason and requests another test.',
        'Rule, target, engine, worker, and limits identities.'),

    # Export dialog.

    'rules.export': _e(
        'Review export of the selected accepted rule version.',
        'Check hard gates and retained test limits before writing a file.',
        'Opens export review; acceptance alone does not create a .yar file.',
        'The selected RuleVersion and export-policy checks.'),

    'rules.export.destination': _e(
        'Choose the local .yar output file.',
        'Make the export location explicit.',
        'Sets the destination before the write action.',
        'Your selected local path and export-path policy.'),

    'rules.export.checks': _e(
        'Read required export checks and informational warnings.',
        'Distinguish blocking failures from reviewable test limitations.',
        'Displays the checklist without writing a file.',
        'Pair separation, compilation, text restrictions, and retained test records.'),

    'rules.include_names': _e(
        'Include available function names in the exported rule metadata.',
        'Choose whether to disclose symbol-derived names.',
        'Adds names only when selected; off by default.',
        'The selected rule source references and retained function names.'),

    'rules.export.with_warnings': _e(
        'Acknowledge the displayed informational export warnings.',
        'Record a deliberate decision about the stated test limits.',
        'Permits only the warnings the export policy allows; hard failures remain blocking.',
        'The current export checklist.'),

    'rules.export.git_tree': _e(
        'Confirm writing the rule inside the selected Git working tree.',
        'Make the repository destination an explicit export decision.',
        'Allows that destination only through the documented path confirmation.',
        'The selected output path and export policy.'),

    'rules.export.origin': _e(
        'Read the origin of pattern material included in this rule.',
        'Keep copied binary-pattern provenance visible before sharing.',
        'Displays the documented source and redistribution notice.',
        'The source artifact references and export header.'),

    'rules.export.confirm': _e(
        'Write the reviewed rule version to the selected local file.',
        'Create the export after required checks and acknowledgements.',
        'Writes the .yar file and records the export; nothing is uploaded.',
        'The selected version, destination, and accepted export checklist.'),

    'rules.export.cancel': _e(
        'Close export review without writing a rule file.',
        'Return to the retained rule and tests.',
        'Closes the dialog without exporting.',
        'The pending export dialog.'),

    # Panel and operation states.

    'rules.stale_banner': _e(
        'Read why the rule or test context describes an earlier analysis basis.',
        'Keep historical evaluation separate from current use.',
        'Displays the reason and requests the applicable retest.',
        'Recorded source, rule, and engine identities.'),

    'rules.retry': _e(
        'Retry the failed rule operation.',
        'Repeat work after addressing the reported cause.',
        'Starts the supported operation without replacing immutable saved versions.',
        'The current request and retained failure state.'),

    'rules.copy_error': _e(
        'Copy the rule-operation error details.',
        'Preserve the code and message for diagnosis.',
        'Writes available plain-text diagnostics to the clipboard.',
        'The retained proposal, test, storage, or export failure.'),

    'rules.state.no_project': _e(
        'Open a project before working with detection rules.',
        'Associate the workflow with an explicit artifact pair.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'rules.state.engine_unavailable': _e(
        'The required rule engine or decoder is unavailable.',
        'Identify why proposal or testing cannot run.',
        'Keeps saved rules readable while reporting the missing capability.',
        'The YARA-X and decoder capability checks.'),

    'rules.state.pair_required': _e(
        'Select a function pair with an accepted analyst review.',
        'Keep proposal tied to reviewed correspondence.',
        'Blocks proposal until the required selection and review exist.',
        'The current match selection and analyst review record.'),

    'rules.state.no_candidates': _e(
        'No candidate has been proposed for this pair.',
        'Distinguish missing generation from failed checks.',
        'Offers Propose rules without generating anything automatically.',
        'The selected pair and candidate inventory.'),

    'rules.state.proposing': _e(
        'The worker is generating and checking rule candidates.',
        'Follow proposal preparation separately from acceptance.',
        'Displays activity and offers cancellation.',
        'The active proposal request.'),

    'rules.state.testing': _e(
        'The worker is testing selected rules against the listed files.',
        'Follow the explicit evaluation population.',
        'Displays progress; unreadable targets remain Not scanned.',
        'The active matrix request and worker outcomes.'),

    'rules.state.no_candidate_passed': _e(
        'No proposed rule met the required checks for this pair.',
        'Inspect the first failing check before changing the proposal.',
        'Shows the failure reason without creating an accepted version.',
        'The candidate gates and available function extents.'),

    'rules.state.stale': _e(
        'The rules or tests describe an earlier analysis or engine basis.',
        'Identify which evaluation needs repeating.',
        'Retains reference records and requests testing before reuse.',
        'The recorded source and evaluation identities.'),

    'rules.state.failed': _e(
        'The requested rule operation could not finish.',
        'Identify the failure separately from a completed negative test.',
        'Shows the error while preserving saved rule versions.',
        'The retained operation failure report.'),

    'rules.state.too_large': _e(
        'The selected target population exceeds file or grid limits.',
        'Keep evaluation bounded and its coverage explicit.',
        'Requests a narrower folder or build selection.',
        'The prepared target count, cell count, and configured ceilings.'),

    'rules.state.extent_missing': _e(
        'No supported function extent is available for a byte-pattern proposal.',
        'Avoid guessing the bytes belonging to a function.',
        'Leaves byte features unavailable instead of inventing a range.',
        'The available exception-directory or extracted-IR extent records.'),

    'rules.state.integrity_failed': _e(
        'A source or retained rule record failed its identity check.',
        'Prevent changed inputs from receiving an unrelated evaluation.',
        'Blocks the affected operation and preserves the reported mismatch.',
        'Artifact, row, sidecar, or rule-text digest checks.'),

    'rules.state.cancelled': _e(
        'The rule operation was cancelled.',
        'Distinguish interrupted work from a completed test population.',
        'Keeps saved versions and records unfinished targets distinctly.',
        'The worker cancellation outcome.'),

    'rules.state.no_visible_rows': _e(
        'No retained rows pass the current test-grid filters.',
        'Distinguish a filtered view from an empty test run.',
        'Requests broader filters without rescanning.',
        'The retained matrix and active display options.'),
}


RULES_TOOLTIP_TEMPLATES = {
    'rules.row': _e(
        'Rule record: {label}.',
        'Inspect its side, version, and review state before acting.',
        'Select for generated text, checks, and history.',
        'Direction: {side}. Version: {version}. State: {state}. Source: {origin}.'),

    'rules.feature': _e(
        'Candidate feature: {kind}.',
        'Inspect source coverage and inclusion before accepting the rule.',
        'Changing an eligible inclusion creates a checked candidate revision.',
        'Side: {side}. Value: {value}. Origin: {origin}. Location: {location}.'),

    'rules.cell': _e(
        'Rule-by-target test outcome.',
        'Read the observed state separately from the expected outcome.',
        'Select for retained offsets, timing, and limits.',
        'Rule: {rule}. Target: {target}. State: {state}. Expectation: {expectation}.'),

    'rules.gate': _e(
        'Rule check: {check}.',
        'Inspect the measured value behind the gate state.',
        'Displays the individual outcome without producing a combined score.',
        'State: {state}. Measured: {measured}. Details: {details}.'),

    'rules.target': _e(
        'Rule-test target: {label}.',
        'Check the role and identity before interpreting a cell.',
        'Displays the retained target metadata.',
        'Role: {role}. SHA-256: {sha256}. Size: {size}. Expectation: {expectation}.'),

    'rules.rule_column': _e(
        'Test results for a retained rule version.',
        'Keep outcomes tied to the exact evaluated rule text.',
        'Displays that version as a matrix column.',
        'Version: {version}. Rule digest: {digest}. Engine: {engine}.'),

    'rules.offset': _e(
        'Retained rule-match location.',
        'Inspect where the tested pattern matched within its recorded coverage.',
        'Displays the stored location without scanning again.',
        'Target: {target}. File offset: {offset}. RVA: {rva}. Rule: {rule}.'),

    'rules.history_event': _e(
        'Recorded rule-history event.',
        'Trace the analyst decision and resulting version.',
        'Displays append-only history without rewriting an earlier record.',
        'Action: {action}. Time: {time}. Version: {version}. Label: {label}.'),

    'rules.export_warning': _e(
        'Rule-export warning: {kind}.',
        'Review the specific limitation before writing the file.',
        'Requires acknowledgement only where the export policy permits it.',
        'Details: {details}. Basis: {basis}.'),

    'rules.stale_reason': _e(
        'The rule evaluation describes an earlier basis.',
        'Identify the changed input before reusing the test result.',
        'Retains historical records and offers the supported retest route.',
        'Recorded input comparison: {reason}.'),
}
