"""Proposed Build environment tooltip copy.

PLANNED: follows the DIE integration plan.
The dock declaration was unavailable during review.
Implemented behavior and packaged Windows availability are UNVERIFIED.

Sources:
- docs/specs/program-e/DIE-integration-plan.md, sections 7-8
- src/patchtrace/panel_manifest.py

The plan starts with a card and later migrates it to a dock.
Ctrl+Shift+B is reserved by the central manifest for the dock.
The initial card has no separate global shortcut.

Additional IDs require bindings to documented controls, fields, and states.
build_env.unified_section supplies panel-prefixed copy for the planned
Build environment section consumed by the Unified view.

Detection signatures identify patterns, not publisher authenticity.
Header fields, derived observations, signature matches, and weak hints
must retain their distinct origins.

Dynamic templates require registered, escaped interpolation.
Bound substituted What-line fields so rendered What text stays within 160 characters.

This module supplies copy only and registers no entries.
"""

from patchtrace.tooltips import _e


BUILD_ENV_TOOLTIPS = {
    'build_env.dock': _e(
        'Read build-environment observations for the older and newer files.',
        'Inspect build context before attributing code differences to source edits.',
        'Shows the planned dock without starting Detect It Easy.',
        'Project artifact checks and retained Detect It Easy observations.'),

    'build_env.action': _e(
        'Show or hide the Build environment dock when available.',
        'Keep build context beside the comparison.',
        'Toggles the planned dock; Ctrl+Shift+B is reserved for this panel.',
        'The central panel manifest and implemented migration state.'),

    'build_env.card': _e(
        'Read compiler, linker, runtime, and packaging observations.',
        'Identify conditions that can affect function comparison.',
        'Displays retained observations without executing either target.',
        'Bounded artifact parsing and available Detect It Easy results.'),

    'build_env.status': _e(
        'Read the build-environment loading and comparison status.',
        'Distinguish completed observations from missing or failed checks.',
        'Displays status without changing the artifacts.',
        'The current build-environment view model.'),

    'build_env.summary': _e(
        'Read the available toolchain-comparison summary.',
        'Check whether the evidence supports a difference or remains unknown.',
        'Displays the recorded outcome with its limits.',
        'Comparable strong observations and toolchain decision rules.'),

    'build_env.table': _e(
        'Compare build facts across the two artifact sides.',
        'Read each value together with its status and basis.',
        'Selection identifies the corresponding technical detail; Ctrl+C copies the row.',
        'The two build fingerprints and their derived field comparison.'),

    'build_env.banner': _e(
        'Read a build-context notice affecting comparison interpretation.',
        'Keep packaging, managed-code, and toolchain limits visible.',
        'Displays the notice without changing a function verdict.',
        'Preflight checks and retained detection results.'),

    'build_env.banner_details': _e(
        'Show the basis and limits of the build-context notice.',
        'Inspect the observations behind its summary.',
        'Opens the available read-only notice details.',
        'The selected PreflightWarning record.'),

    'build_env.banner_dismiss': _e(
        'Dismiss the current notice within its configured scope.',
        'Reduce repeated presentation after reading the explanation.',
        'Changes notice visibility without removing the underlying observation.',
        'The notice record and project or session dismissal state.'),

    'build_env.setup': _e(
        'Open setup for the Detect It Easy console tool.',
        'Configure the optional source of compiler and packaging names.',
        'Opens setup; explicit probing checks version and help without scanning project files.',
        'The configured tool inventory and supported Detect It Easy integration.'),

    'build_env.read_die': _e(
        'Run the configured Detect It Easy analysis on the selected project inputs.',
        'Collect supported build and packaging detections.',
        'Starts the explicit local tool request; target files are not executed.',
        'The selected console executable, database, options, and artifact copies.'),

    'build_env.weak_hints': _e(
        'Read heuristic observations separately from stronger comparison evidence.',
        'Keep weak detections visible without promoting their meaning.',
        'Displays the retained hints and their source labels.',
        'Heuristic detections and bounded PE-layout observations.'),

    'build_env.copy': _e(
        'Copy build-environment details with provenance.',
        'Retain values and their basis alongside research notes.',
        'Writes bounded plain text to the clipboard.',
        'The displayed fingerprints, comparison, notices, and source identities.'),

    'build_env.technical': _e(
        'Show or hide technical build-environment details.',
        'Inspect raw fields and detection metadata behind the summary.',
        'Changes the read-only detail visibility.',
        'Parsed PE facts and retained Detect It Easy metadata.'),

    'build_env.reread': _e(
        'Read build-environment observations again through the supported workflow.',
        'Replace stale context with observations for the current inputs.',
        'Requests the appropriate read operation without modifying target bytes.',
        'Current artifact identities and available configured sources.'),

    'build_env.retry': _e(
        'Retry the failed build-environment operation.',
        'Repeat the request after addressing its reported cause.',
        'Starts another supported read or preparation attempt.',
        'The current request and retained failure state.'),

    'build_env.copy_error': _e(
        'Copy build-environment error details.',
        'Preserve the code and available message for diagnosis.',
        'Writes plain-text diagnostics to the clipboard.',
        'The retained build-environment failure report.'),

    'build_env.group_last': _e(
        'Group eligible build-tagged rows later within their change group.',
        'Adjust reading order when the documented build-context rules apply.',
        'Changes ordering only; no row changes classification or crosses its materiality group.',
        'The same-pair toolchain delta and versioned noise-map rules.'),

    'build_env.unified_section': _e(
        'Read build-context information associated with the Unified row.',
        'Inspect an alternative explanation for eligible code variation.',
        'Displays context without changing the pairing or change verdict.',
        'The same-pair build delta and selected row change classes.'),

    'build_env.timeline': _e(
        'Compare available build facts across the opened series.',
        'Locate adjacent-build changes in toolchain and packaging context.',
        'Displays retained per-build facts without comparing nonadjacent builds.',
        'The series build references and available pair-project fingerprints.'),

    # Table headers.

    'build_env.col.fact': _e(
        'Identify the build field being compared.',
        'Keep each observation attached to its specific meaning.',
        'Displays the documented fact name.',
        'The closed BuildFact key vocabulary.'),

    'build_env.col.older': _e(
        'Read the older artifact value for this fact.',
        'Inspect the baseline observation and its availability.',
        'Displays the retained value without substituting for missing data.',
        'The older BuildFingerprint.'),

    'build_env.col.newer': _e(
        'Read the newer artifact value for this fact.',
        'Inspect the later-build observation and its availability.',
        'Displays the retained value without substituting for missing data.',
        'The newer BuildFingerprint.'),

    'build_env.col.status': _e(
        'Read whether this fact changed, matched, or could not be compared.',
        'Distinguish a supported difference from missing evidence.',
        'Displays the field-level comparison status.',
        'The two observations and build-comparison rules.'),

    'build_env.col.basis': _e(
        'Read the source and evidence basis for this observation.',
        'Separate header values, derived context, signature matches, and heuristics.',
        'Displays the retained origin without strengthening the claim.',
        'The BuildFact source and basis metadata.'),

    # Complete documented BuildFact vocabulary.

    'build_env.fact.compiler': _e(
        'Read the reported compiler identity.',
        'Inspect a possible build-tool difference.',
        'Displays a retained detection rather than proof of the complete build process.',
        'The available compiler observation and its labelled source.'),

    'build_env.fact.compiler_version': _e(
        'Read the reported compiler-version observation.',
        'Check the version detail behind a compiler comparison.',
        'Displays the retained value and basis.',
        'The compiler-version BuildFact and detection metadata.'),

    'build_env.fact.linker': _e(
        'Read the reported linker identity.',
        'Inspect a toolchain component that can affect binary layout.',
        'Displays the retained name with its source.',
        'The linker BuildFact and available detection evidence.'),

    'build_env.fact.linker_field': _e(
        'Read the linker-version field stored in the PE header.',
        'Distinguish an exact header value from a detected tool name.',
        'Displays the field without treating it as complete build provenance.',
        'The PE optional-header linker-version bytes.'),

    'build_env.fact.linker_rich': _e(
        'Read the linker-related Rich-header observation.',
        'Inspect build context separately from the PE linker field.',
        'Displays available parsed Rich data and its limits.',
        'The bounded Rich-header parser and derived observation.'),

    'build_env.fact.build_tool': _e(
        'Read a reported build-tool observation.',
        'Inspect additional toolchain context.',
        'Displays the retained detection without reconstructing the build.',
        'The BuildFact source and tool-detection metadata.'),

    'build_env.fact.runtime_family': _e(
        'Read runtime-family hints derived from imports.',
        'Inspect dependencies that can explain build-context variation.',
        'Displays a recognized family without claiming an exact runtime version.',
        'The closed runtime-family mapping over imported library names.'),

    'build_env.fact.language': _e(
        'Read the reported implementation-language observation.',
        'Identify source-language context that may affect analysis.',
        'Displays the available detection with its basis.',
        'The language BuildFact and retained source metadata.'),

    'build_env.fact.target_os': _e(
        'Read the reported target-operating-system observation.',
        'Inspect the file metadata and detections relevant to its intended environment.',
        'Displays the retained value without establishing deployment compatibility.',
        'The target-OS BuildFact and its labelled source.'),

    'build_env.fact.subsystem': _e(
        'Read the PE subsystem classification.',
        'Inspect the executable environment recorded by the image.',
        'Displays the parsed subsystem field.',
        'The PE optional header.'),

    'build_env.fact.os_version_field': _e(
        'Read the operating-system version fields stored in the PE header.',
        'Inspect recorded metadata without treating it as a tested requirement.',
        'Displays the major and minor field values.',
        'The parsed PE optional-header OS-version fields.'),

    'build_env.fact.subsystem_version_field': _e(
        'Read the subsystem-version fields stored in the PE header.',
        'Keep these metadata values separate from runtime compatibility testing.',
        'Displays the major and minor field values.',
        'The parsed PE optional-header subsystem-version fields.'),

    'build_env.fact.image_version_field': _e(
        'Read the image-version fields stored in the PE header.',
        'Inspect version metadata without assuming build chronology.',
        'Displays the major and minor field values.',
        'The parsed PE optional-header image-version fields.'),

    'build_env.fact.rich_signature': _e(
        'Read the derived Rich-header product-and-build-set digest.',
        'Compare the supported Rich observations without relying on entry counts.',
        'Displays the digest and available checksum status.',
        'Sorted unique Rich product-and-build pairs; counts are excluded.'),

    'build_env.fact.packer': _e(
        'Read reported packer or compressor observations.',
        'Identify packaging that can limit function-level analysis.',
        'Displays detections with their signature or heuristic basis.',
        'Retained Detect It Easy results and separately labelled PE hints.'),

    'build_env.fact.protector': _e(
        'Read reported protector observations.',
        'Inspect conditions that may distort recovered code.',
        'Displays the detection without unpacking or executing the target.',
        'Retained tool detections and their labelled basis.'),

    'build_env.fact.installer': _e(
        'Read installer or self-extracting-container observations.',
        'Check whether the application code may be inside an unanalyzed payload.',
        'Displays packaging context without extracting or launching the payload.',
        'Retained installer detections and preflight checks.'),

    'build_env.fact.obfuscator': _e(
        'Read reported obfuscation-tool observations.',
        'Inspect a potential limitation on recovered functions.',
        'Displays the retained detection and its basis.',
        'The obfuscator BuildFact and source metadata.'),

    'build_env.fact.managed': _e(
        'Read managed-code and native-header observations.',
        'Distinguish managed-only images from images also containing native code.',
        'Displays parsed CLR context without providing managed-code comparison.',
        'The CLR header and related retained observations.'),

    'build_env.fact.gs_cookie': _e(
        'Read the available security-cookie metadata observation.',
        'Inspect recorded build-option context.',
        'Displays the field-level observation without assessing every function use.',
        'The parsed PE load-configuration data.'),

    'build_env.fact.cfg': _e(
        'Read available Control Flow Guard metadata.',
        'Inspect build-option context separately from code-change purpose.',
        'Displays recorded guard fields without assessing every indirect call.',
        'The parsed load configuration and image flags.'),

    'build_env.fact.aslr': _e(
        'Read the image metadata associated with address randomization.',
        'Inspect a build-option difference.',
        'Displays the recorded flags without establishing runtime policy.',
        'The parsed PE DLL-characteristics field.'),

    'build_env.fact.repro': _e(
        'Read the available reproducible-build marker observation.',
        'Inspect recorded build metadata.',
        'Displays the marker without establishing that an independent rebuild matches.',
        'The parsed PE debug-directory information.'),

    'build_env.fact.debug_entry_types': _e(
        'Read the debug-directory entry types present in the image.',
        'Inspect retained debugging and build metadata.',
        'Displays the bounded parsed type list.',
        'The PE debug directory.'),

    'build_env.fact.entropy_exec': _e(
        'Read the available entropy observation for executable sections.',
        'Inspect a packaging hint while retaining its ambiguity.',
        'Displays the value and any sampling limits; entropy alone identifies no packer.',
        'The bounded section analysis and recorded sampling metadata.'),

    'build_env.fact.overlay': _e(
        'Read the available data size and context after the last section.',
        'Identify file material outside the analyzed image sections.',
        'Displays overlay observations without analyzing an embedded payload.',
        'The section layout, file size, and bounded overlay checks.'),

    # Observation bases.

    'build_env.basis.exact_field': _e(
        'This value was read from a defined file field.',
        'Distinguish a stored field from an inferred tool identity.',
        'Displays the parsed value within the parser coverage.',
        'The labelled PE, CLR, load-config, or debug field.'),

    'build_env.basis.derived': _e(
        'This observation was derived from recorded file information.',
        'Inspect the transformation behind the displayed context.',
        'Displays the derived value with its source reference.',
        'The stated derivation rule and parsed inputs.'),

    'build_env.basis.signature': _e(
        'This tool observation matched a detection signature.',
        'Distinguish signature-based recognition from a weak hint.',
        'Displays the reported pattern match without authenticating the publisher.',
        'The selected Detect It Easy executable and signature database.'),

    'build_env.basis.heuristic': _e(
        'This observation is a heuristic hint.',
        'Keep weak recognition separate from qualifying toolchain evidence.',
        'Displays the hint without promoting it to a strong comparison basis.',
        'The labelled heuristic rule or tool result.'),

    'build_env.basis.unknown': _e(
        'No usable basis establishes this observation.',
        'Keep unavailable evidence explicit.',
        'Displays Unknown without substituting a detected identity.',
        'The observation availability and source-status checks.'),

    # Field-comparison states.

    'build_env.change.added': _e(
        'A comparable build observation is present only on the newer side.',
        'Inspect the field difference within its stated basis.',
        'Displays Added without identifying a source-code edit.',
        'The paired BuildFact records and comparison rules.'),

    'build_env.change.removed': _e(
        'A comparable build observation is present only on the older side.',
        'Inspect the field difference within its stated basis.',
        'Displays Removed without identifying a source-code edit.',
        'The paired BuildFact records and comparison rules.'),

    'build_env.change.changed': _e(
        'Comparable values for this build fact differ.',
        'Inspect the specific observation and its origin.',
        'Displays Changed without assigning a cause to function differences.',
        'The two BuildFact records and their compatibility checks.'),

    'build_env.change.unchanged': _e(
        'Comparable values for this build fact are equal.',
        'Recognize agreement within the observed field.',
        'Displays Unchanged without asserting identical build settings.',
        'The paired comparable observations.'),

    'build_env.change.one_sided_unknown': _e(
        'One side lacks the evidence needed for this field comparison.',
        'Avoid reading missing metadata as a definite addition or removal.',
        'Displays an unresolved comparison state.',
        'The per-side observation availability.'),

    # Preflight notices.

    'build_env.notice.packed_signature': _e(
        'A detection signature identifies packing-related content.',
        'Recognize that recovered function results may be incomplete or misleading.',
        'Displays a caution; PatchTrace does not unpack the file.',
        'A supported signature-level packing detection.'),

    'build_env.notice.packed_hint': _e(
        'PE layout or entropy provides a packing-related hint.',
        'Inspect the hint without assuming the file is packed.',
        'Displays the hint with its source and stated limits.',
        'Bounded section-layout or entropy observations.'),

    'build_env.notice.packed_one_side': _e(
        'Packing-related observations differ between the two sides.',
        'Check whether the artifacts provide a meaningful native-code comparison.',
        'Displays the comparison limitation without unpacking either file.',
        'The per-side packing observations and preflight rules.'),

    'build_env.notice.protected': _e(
        'A supported signature reports a protector or obfuscator.',
        'Recognize limits on function recovery and comparison.',
        'Displays a caution without executing or transforming the target.',
        'The retained signature-level detection.'),

    'build_env.notice.managed_only': _e(
        'The image is identified as managed-only code.',
        'Recognize that the native x64 comparison does not cover its managed program.',
        'Displays the input-scope limitation.',
        'The parsed CLR header and IL-only flag.'),

    'build_env.notice.managed_mixed': _e(
        'The image contains managed metadata and a native-code component.',
        'Keep native coverage separate from managed-code analysis.',
        'Displays the notice that only the native part is compared.',
        'The parsed CLR and native-header observations.'),

    'build_env.notice.installer': _e(
        'The file has installer or self-extracting-container observations.',
        'Check whether the intended program is inside an unanalyzed payload.',
        'Displays the packaging limitation without launching the container.',
        'The retained installer detection and preflight basis.'),

    'build_env.notice.overlay': _e(
        'The file contains a substantial overlay after its sections.',
        'Keep unanalyzed trailing data visible in the comparison context.',
        'Displays overlay size and the stated coverage limitation.',
        'The bounded overlay observation and preflight threshold.'),

    'build_env.notice.toolchain': _e(
        'Qualifying observations support a toolchain difference.',
        'Consider build variation when interpreting eligible function changes.',
        'Displays context without assigning every delta to the toolchain.',
        'The paired strong observations and toolchain decision rules.'),

    'build_env.notice.tool_unavailable': _e(
        'Detect It Easy observations are unavailable.',
        'Distinguish PatchTrace header checks from tool-derived names.',
        'Displays which local checks remain available.',
        'The configured-tool status and parsed PE facts.'),

    'build_env.notice.heuristic_only': _e(
        'Only weak tool hints were retained for this notice.',
        'Avoid treating heuristic recognition as qualifying toolchain evidence.',
        'Displays the hints without raising their evidence basis.',
        'The labelled heuristic detections.'),

    'build_env.notice.sources_disagree': _e(
        'Strong source observations disagree about the comparison.',
        'Inspect the conflict before accepting a toolchain-difference label.',
        'Preserves the conflicting bases and leaves unsupported conclusions unresolved.',
        'The independent source observations and comparison rules.'),

    'build_env.notice.stale': _e(
        'The notice was prepared from earlier inputs or tool setup.',
        'Keep historical preflight context separate from current review.',
        'Displays the stale reason and supported update route.',
        'Recorded artifact and tool identities.'),

    # Timeline.

    'build_env.timeline.build': _e(
        'Identify the build associated with this timeline column.',
        'Keep adjacent-build observations in the intended order.',
        'Displays the retained label and build reference.',
        'The opened series manifest and pair projects.'),

    'build_env.timeline.family': _e(
        'Identify the build-fact family represented by this timeline row.',
        'Read toolchain, runtime, packing, managed, or option context separately.',
        'Displays the family label.',
        'The timeline view model and fingerprint fields.'),

    'build_env.timeline.unknown': _e(
        'This build lacks a usable value for the timeline fact.',
        'Keep missing context distinct from a change.',
        'Displays Unknown without filling from another build.',
        'The per-build fingerprint and source availability.'),

    'build_env.timeline.not_run': _e(
        'The required tool observation was not collected for this build.',
        'Distinguish unperformed analysis from an empty detection.',
        'Displays Not run.',
        'The per-build tool-evidence inventory.'),

    'build_env.timeline.tool_mismatch': _e(
        'Adjacent timeline columns use different tool versions.',
        'Avoid interpreting tool changes as build changes.',
        'Displays the version difference instead of a normal comparison.',
        'The per-build tool identities.'),

    'build_env.timeline.hop_tag': _e(
        'This adjacent-build hop has a recorded toolchain-difference note.',
        'Read its attention score with the available build context.',
        'Adds a note without changing the attention score.',
        'The same-hop build delta and retained pair ranking.'),

    # States B0-B9.

    'build_env.state.no_project': _e(
        'Open a project before reading build-environment facts.',
        'Associate observations with a specific artifact pair.',
        'Displays the project prerequisite.',
        'Current project availability.'),

    'build_env.state.reading': _e(
        'Build-environment observations are being prepared.',
        'Follow the active artifact side and available progress.',
        'Displays reading status while work runs.',
        'The current fingerprint or tool-read operation.'),

    'build_env.state.tool_missing': _e(
        'Detect It Easy is not configured.',
        'Identify why tool-derived compiler and packaging names are missing.',
        'Shows available PatchTrace header, Rich, section, and import checks.',
        'Configured-tool availability and bounded PE parsing.'),

    'build_env.state.toolchain_same': _e(
        'No qualifying toolchain difference was detected.',
        'Keep agreement in observed facts distinct from identical build options.',
        'Displays the outcome with its limits.',
        'Comparable strong facts and the toolchain decision policy.'),

    'build_env.state.toolchain_differs': _e(
        'Qualifying strong facts support a toolchain difference.',
        'Consider a build-related explanation for eligible variation.',
        'Displays the summary and applicable row context without hiding records.',
        'The same-pair toolchain comparison and noise map.'),

    'build_env.state.toolchain_unknown': _e(
        'The available facts do not establish a toolchain comparison.',
        'Keep missing or weak evidence separate from a difference.',
        'Displays Unknown and its reason.',
        'Per-side facts and the strong-evidence comparison requirements.'),

    'build_env.state.side_incomplete': _e(
        'Build-environment preparation failed or is incomplete for one side.',
        'Preserve usable information from the other artifact.',
        'Displays the affected side and reason while retaining the other side.',
        'The per-side preparation outcomes.'),

    'build_env.state.stale': _e(
        'The displayed facts belong to another file or tool configuration.',
        'Keep historical observations distinct from current inputs.',
        'Retains reference content and offers Read again.',
        'Recorded fingerprint identities compared with current inputs.'),

    'build_env.state.error': _e(
        'Build-environment preparation could not complete.',
        'Identify the reported cause before retrying.',
        'Shows the error while retaining earlier results.',
        'The build read, store, or preparation failure.'),

    'build_env.state.tool_unsupported': _e(
        'The selected Detect It Easy version is outside the supported integration.',
        'Identify a tool compatibility limit.',
        'Shows the reason while retaining available PatchTrace header checks.',
        'The explicit tool probe and supported version policy.'),
}


BUILD_ENV_TOOLTIP_TEMPLATES = {
    'build_env.row': _e(
        'Build-environment fact: {field}.',
        'Read both values together with their evidence basis.',
        'Select for available technical detail.',
        'Older: {older}. Newer: {newer}. Status: {status}. Basis: {basis}.'),

    'build_env.tag': _e(
        'This row has build-context information.',
        'Inspect whether its recorded change classes can arise from build variation.',
        'The row remains listed and its pairing and change verdict stay unchanged.',
        'Classes: {classes}. Toolchain basis: {basis}. Applicable effect: {effect}.'),

    'build_env.timeline_cell': _e(
        'Build-environment timeline observation.',
        'Check the build, fact, and source before comparing adjacent columns.',
        'Displays retained context without comparing nonadjacent builds.',
        'Build: {build}. Fact: {field}. Value: {value}. Basis: {basis}.'),

    'build_env.notice': _e(
        'Build-context notice: {kind}.',
        'Inspect the source and limits before applying it to function analysis.',
        'Displays the recorded notice without transforming the target.',
        'Side: {side}. Basis: {basis}. Details: {details}.'),

    'build_env.detection': _e(
        'Retained tool detection: {category}.',
        'Keep the reported name and version attached to its detection basis.',
        'Displays bounded text without promoting a heuristic to a signature match.',
        'Name: {name}. Version: {version}. Basis: {basis}. Database: {database}.'),

    'build_env.rich_entry': _e(
        'Parsed Rich-header entry.',
        'Inspect the product, build, and count behind the technical view.',
        'Displays a retained header entry without identifying the complete build process.',
        'Product: {product}. Build: {build}. Count: {count}. Checksum state: {checksum}.'),

    'build_env.limit': _e(
        'A build-environment parsing or display limit was reached.',
        'Keep bounded coverage visible.',
        'Reports the affected observation without inventing omitted values.',
        'Limit: {limit}. Side: {side}. Details: {reason}.'),

    'build_env.stale_reason': _e(
        'The build-environment view describes earlier inputs.',
        'Identify the changed source before reusing the context.',
        'Retains reference content and offers the supported update route.',
        'Recorded input comparison: {reason}.'),
}
