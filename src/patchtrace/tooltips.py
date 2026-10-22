"""Declarative tooltip registry (SPEC-26 requirement A).

Every functional control is keyed by a stable semantic ID, never by visible text or position. The
table itself is pure data; PySide6 is never imported here, so the registry can be validated without a
Qt runtime. The ``apply_*`` helpers only call setter methods on the widget or action they are given.

Static controls use :func:`tooltip`. Dynamic items (detector IDs, recent paths) use
:func:`template`, which strips control characters, caps the length and escapes every interpolated
value so untrusted names can never be interpreted as markup.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass

VALUE_LIMIT = 200
EXEMPT_IDS = frozenset({'action.new', 'action.open'})
_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]')


@dataclass(frozen=True)
class TooltipEntry:
    what: str
    why: str
    effect: str
    source: str = ''
    availability: str = ''

    def lines(self) -> list[str]:
        pairs = [('What', self.what), ('Why', self.why), ('Effect', self.effect),
                 ('Source', self.source), ('Availability', self.availability)]
        return [f'{label}: {text}' for label, text in pairs if text]

    def render(self) -> str:
        """Readable plain text, one 'Label: text' line per field. Not markup."""
        return '\n'.join(self.lines())


def _e(what: str, why: str, effect: str, source: str = '', availability: str = '') -> TooltipEntry:
    return TooltipEntry(what, why, effect, source, availability)


_CODE_SOURCE = (
    'Decompiled code is C-like decompiler output produced by Ghidra via Ghidriff, not original source code. '
    'Assembly is shown only when the upstream Ghidriff result retained it. Metadata comes from the saved '
    'normalized or raw analysis. Blank rows are PatchTrace display alignment only. No text view implies '
    'that bytes were extracted from this function.')


def _code_pane(side: str, other: str) -> TooltipEntry:
    return _e(
        f'Read-only {side} function representation for the selected match, in the mode chosen in the '
        'representation selector.',
        f'Lets you read the {side} side next to the {other} side without altering either.',
        'Nothing changes. Selecting text and copying is safe; edits are not possible.',
        _CODE_SOURCE,
        'Needs a selected function match. Unavailable representations are shown as unavailable, never '
        'reconstructed.')


_DEFAULT_RO = 'The default profile is read-only.'

REGISTRY: dict[str, TooltipEntry] = {
    # ---- main window actions -------------------------------------------------------------------
    'action.new': _e('Create a new comparison project from two PE x64 files.',
                     'Starts a project with explicit older and newer artifacts.',
                     'Opens the New comparison dialog.'),
    'action.open': _e('Open an existing PatchTrace project folder.',
                      'Resume earlier work.', 'Replaces the project shown in the window.'),
    'action.acquire': _e(
        'Search Winbindex metadata and download exact-hash Microsoft binaries for comparison.',
        'Obtains an older and a newer build of a Windows file without hunting for them by hand.',
        'Opens the acquisition dialog. Nothing is contacted until you confirm each request, and a new '
        'project is created from the downloaded files.',
        'Winbindex metadata and the Microsoft symbol server. Availability and signature authenticity are '
        'separate questions.',
        'Disabled while a job is running.'),
    'action.sample': _e(
        'Create a separate synthetic comparison project.',
        'Demonstrates code, evidence and reviews without analyzing actual binaries.',
        'Opens a new sample project; your current project is not modified.',
        'Built-in synthetic fixture data, not real binaries.',
        'Disabled while a job is running.'),
    'action.import_json': _e(
        'Load raw Ghidriff JSON from a comparison of this exact binary pair.',
        'Lets you reuse a comparison produced elsewhere instead of running one here.',
        'PatchTrace validates orientation and artifact identity before committing results; failures keep '
        'the earlier results.',
        'A Ghidriff JSON file you choose.',
        'Needs an open project and no running job.'),
    'action.file_overview': _e(
        'View older/newer names, sizes and saved SHA-256 values immediately.',
        'Gives a quick sanity check of the pair before any slow analysis.',
        'Opens a non-modal, read-only table. No PE headers or signatures are inspected yet.',
        'Metadata recorded in the project when it was created; nothing is read from disk again.',
        'Needs an open project; works without a configured backend.'),
    'action.run_comparison': _e(
        'Run an external Ghidriff/Ghidra static comparison of the project-owned older and newer PE x64 '
        'files.',
        'Produces the function matches and decompiled differences you review.',
        'Starts a background job and opens the file overview first. Results are committed only on '
        'success; earlier results are kept on failure. Neither binary is executed.',
        'Ghidriff and Ghidra output, not live execution.',
        'Needs an open project, no running job, and a configured backend (see Setup).'),
    'action.rank_changes': _e(
        'Apply PatchTrace heuristic signals to changed Ghidriff decompiled code and order functions by '
        'attention score.',
        'Helps decide where to read first.',
        'Adds derived signals and an attention ordering. The score is not vulnerability likelihood.',
        'The saved raw Ghidriff result of the latest completed run and the selected analysis profile.',
        'Needs a completed run with a saved raw result and no running job.'),
    'action.cancel_job': _e(
        'Request cancellation of the active comparison, import or analysis job.',
        'Stops long work you no longer want.',
        'The job stops cooperatively. Previously committed results are retained.',
        availability='Only enabled while a job is running and not already being cancelled.'),
    'action.interpret': _e(
        'Send selected function differences and evidence to the configured AI provider after showing '
        'the exact context.',
        'Gets an optional second opinion on what a change might mean.',
        'Opens a preview. Nothing is transmitted until you accept. AI conclusions are unverified '
        'hypotheses.',
        'Selected matches and their evidence from the saved project.',
        'Needs an open project, one or more selected matches and no running job.'),
    'action.export': _e(
        'Preview and export a report containing analysis provenance, reviews and optionally notes or code.',
        'Produces a shareable record of your analysis.',
        'Opens the export dialog; a file is written only after you review the preview and confirm.',
        'Saved project data.',
        'Needs an open project and no running job.'),
    'action.setup': _e(
        'Configure local Python/Ghidra backends, preferences, the optional offline runtime and analysis '
        'profiles.',
        'Comparison cannot run until its external tools are located.',
        'Opens the setup dialog. Saved paths and preferences apply after Save setup. Nothing is '
        'installed automatically.',
        availability='Disabled while a job is running.'),
    'action.swap_orientation': _e(
        'Exchange the older and newer binaries of the project.',
        'Corrects a project that was created with the files reversed.',
        'Reverses patch direction after confirmation; existing interpretations may become stale.',
        availability='Needs an open project and no running job.'),
    'action.save': _e(
        'Persist the current project snapshot and review state.',
        'Keeps your reviews and notes.',
        'Writes to the project local SQLite history.',
        availability='Needs an open project and no running job.'),
    'action.backup': _e(
        'Create a complete separate backup of the project.',
        'Protects the database, stored binaries and analysis outputs before risky changes.',
        'Copies everything into a folder you choose; the project itself is unchanged.',
        availability='Needs an open project and no running job.'),
    'action.undo_match_correction': _e(
        'Undo the most recent eligible manual function relationship correction.',
        'Reverts a correction made by mistake while keeping its provenance.',
        'Marks the latest non-stale override as undone and restores the earlier relationship.',
        availability='Needs a previous manual correction that is not stale, and no running job.'),
    'action.help': _e(
        'Explain how analysis, external dependencies, projects, findings and reports work.',
        'First-time orientation without leaving the application.',
        'Opens a read-only help window.',
        'Static text shipped with PatchTrace.'),
    'action.next_difference': _e(
        'Move to the next changed region, continuing into the next visible function at the end.',
        'Keyboard route (Alt+Down) for stepping through a patch.',
        'Moves the selection and scrolls both panes; analysis data is unchanged.',
        'Line alignment of the currently displayed function records.',
        'Needs a selected match containing changed regions.'),
    'action.previous_difference': _e(
        'Move to the preceding changed region, continuing into the previous visible function at the start.',
        'Keyboard route (Alt+Up) for stepping back through a patch.',
        'Moves the selection and scrolls both panes; analysis data is unchanged.',
        'Line alignment of the currently displayed function records.',
        'Needs a selected match containing changed regions.'),
    'action.recent_projects': _e(
        'Submenu listing recently opened projects.',
        'Reopen earlier work in one step.',
        'Choosing an entry replaces the project shown in the window.',
        'Paths stored in your local desktop settings.',
        'Disabled when no recent projects exist or while a job is running.'),
    'menu.project': _e('Project menu: create, open, import, export, back up and reorient projects.',
                       'Groups project-level commands.', 'Opens the menu; nothing changes by itself.'),
    'menu.analysis': _e('Analysis menu: run, rank, cancel, interpret and set up analysis.',
                        'Groups analysis commands.', 'Opens the menu; nothing changes by itself.'),
    'menu.help': _e('Help menu: workflow and dependency guidance.', 'Groups help commands.',
                    'Opens the menu; nothing changes by itself.'),
    # ---- navigator ---------------------------------------------------------------------------
    'nav.search': _e(
        'Filter the function list by name or address text, for example CreateFileW or 0x180001000.',
        'Finds one function quickly in a large comparison.',
        'Narrows the visible matches only; no data is changed.',
        'Names and addresses recorded in the saved Ghidriff matches.'),
    'nav.category_filter': _e(
        'Show only matches of one relationship category such as modified, added or removed.',
        'Focuses review on the kind of change you care about.',
        'Narrows the visible list only.',
        'Categories assigned by Ghidriff or by a manual correction.'),
    'nav.review_filter': _e(
        'Show only matches with one analyst review status.',
        'Tracks what you have and have not looked at.',
        'Narrows the visible list only.',
        'Review states saved in this project.'),
    'nav.order': _e(
        'Choose project order or attention-score order for the match list.',
        'Attention scores prioritize research; they do not establish exploitability.',
        'Reorders the visible list only.',
        'Scores come from the Rank changes action.',
        'Attention order is meaningful only after Rank changes has produced scores.'),
    'nav.manual_filter': _e(
        'Show only matches whose function relationship was corrected manually.',
        'Audits your own overrides.', 'Narrows the visible list only.',
        'Manual correction annotations saved in this project.'),
    'nav.finding_filter': _e(
        'Show only matches referenced by at least one finding.',
        'Jumps to functions an interpretation has already discussed.', 'Narrows the visible list only.',
        'Interpretation findings saved in this project.',
        'Empty until an interpretation has been run.'),
    'nav.matches': _e(
        'List of function matches; select one to inspect, or several to interpret together.',
        'It is the main way to choose which function to read.',
        'Selecting shows both sides in the code panes. Multi-selection feeds Interpret selection.',
        'Function matches from the saved Ghidriff comparison.',
        'Empty until a comparison has run, a JSON was imported or the sample was opened.'),
    'nav.signals': _e(
        'Deterministic change signals for the selected match; activate one to jump to its source.',
        'Shows why a function ranked high so you can verify it in code.',
        'Selecting an entry scrolls the code pane to the supporting lines.',
        'Heuristic detectors run over Ghidriff decompiled code. Signals are hints, not findings.',
        'Needs a selected match and a completed Rank changes.'),
    'nav.match_review': _e(
        'Set the analyst review status of the selected match.',
        'Records your progress through the list.',
        'Saves the new status to the project. It does not establish vulnerability validity.',
        availability='Needs a selected match and no running job.'),
    'nav.correct_match': _e(
        'Correct which older and newer function records belong to the selected match.',
        'Fixes wrong pairings made by automatic matching.',
        'Opens a dialog; saving adds a provenance-tracked override and invalidates dependent findings.',
        availability='Needs a selected match and no running job.'),
    # ---- code viewer -------------------------------------------------------------------------
    'viewer.mode': _e(
        'Choose the representation: decompiled C-like text, actual assembly, preserved metadata, or the '
        'original artifact bytes as Hex, Binary or Base64.',
        'Different views answer different questions about the same change.',
        'Redraws both panes. Unavailable representations are not reconstructed. Raw views read exact '
        'on-disk bytes and never encode decompiled text.',
        'Text views: the imported or freshly generated Ghidriff JSON. Raw views: the project-owned artifact '
        'copies, re-verified against their recorded SHA-256.'),
    'viewer.raw_scope': _e(
        'Choose which bytes the Hex, Binary or Base64 view shows: the whole file, or file bytes starting at '
        'the selected function entry point.',
        'Lets you look at the bytes around a changed function or browse the whole artifact.',
        'Redraws both raw panes from page 1 of the chosen scope.',
        'The entry address comes from Ghidriff and is mapped to a file offset through the PE section table. '
        'The function extent is not determined; bytes past the function end are shown as they are on disk.',
        'Only used by raw views. Entry scope is unavailable when the address is virtual-only, ambiguous or '
        'outside the image; no range is guessed.'),
    'viewer.raw_page': _e(
        'Page number within the selected raw byte scope (4,096 bytes per page).',
        'Large files are read in bounded pages instead of all at once.',
        'Reads and redraws the chosen page on both sides at the same logical offset.',
        'Verified artifact bytes.', 'Only used by raw views; the maximum is the longer side\'s page count.'),
    'viewer.raw_goto': _e(
        'Jump to a file offset in the whole-file raw scope. Accepts hexadecimal, for example 0x400 or 400.',
        'Gets to a known offset (section start, overlay, certificate table) quickly.',
        'Switches to Whole file scope and shows the page containing that offset.',
        'Offsets are file offsets, not RVAs or virtual addresses.',
        'Only used by raw views. Offsets past the end of the larger file are rejected.'),
    'viewer.sync_scroll': _e(
        'Synchronize older and newer code-pane vertical scroll positions.',
        'Keeps matched lines level while you read.',
        'Scrolling one pane moves the other. Only the view position is affected.',
        'Pane text comes from the current Ghidriff result, padded with alignment gaps for display.'),
    'nav.previous_hunk': _e(
        'Move to the preceding changed region; at the start of a function, go to the previous visible '
        'function in the filtered list.',
        'Steps through a patch without scrolling by hand. Shortcut: Alt+Up.',
        'Moves the selection and scroll position; data is unchanged.',
        'Line alignment of the displayed Ghidriff function records.',
        'Needs a selected match containing changed regions.'),
    'nav.next_hunk': _e(
        'Move to the next changed region; at the end of a function, go to the next visible function in '
        'the filtered list.',
        'Steps through a patch without scrolling by hand. Shortcut: Alt+Down.',
        'Moves the selection and scroll position; data is unchanged.',
        'Line alignment of the displayed Ghidriff function records.',
        'Needs a selected match containing changed regions.'),
    'viewer.copy_older': _e(
        'Copy the full text of the older code pane to the clipboard.',
        'Lets you paste the older representation into notes or other tools.',
        'Places plain text on the clipboard; the project is unchanged.',
        'Exactly what the older pane shows, including display-only alignment gaps.',
        'Needs a selected match with text shown.'),
    'viewer.copy_newer': _e(
        'Copy the full text of the newer code pane to the clipboard.',
        'Lets you paste the newer representation into notes or other tools.',
        'Places plain text on the clipboard; the project is unchanged.',
        'Exactly what the newer pane shows, including display-only alignment gaps.',
        'Needs a selected match with text shown.'),
    'viewer.older_code': _code_pane('older', 'newer'),
    'viewer.newer_code': _code_pane('newer', 'older'),
    'nav.hunk_list': _e(
        'Jump to a particular inserted, removed or replaced region in the selected function.',
        'Gives a table of contents for the differences.',
        'Scrolls both panes to the chosen region.',
        'Derived from PatchTrace line alignment of the text currently displayed, not source-level line '
        'numbers.',
        'Needs a selected match containing changed regions.'),
    # ---- findings ----------------------------------------------------------------------------
    'findings.search': _e(
        'Search interpretation findings by text, for example integer overflow.',
        'Finds a finding in a long list.', 'Narrows the visible findings only.',
        'Finding summaries saved from earlier interpretations.'),
    'findings.review_filter': _e(
        'Show only findings with one review status.', 'Tracks which findings still need your decision.',
        'Narrows the visible findings only.', 'Review states saved in this project.'),
    'findings.stale_filter': _e(
        'Choose between current findings, stale findings or both.',
        'Stale findings were produced for an analysis that has since changed.',
        'Narrows the visible findings only. Stale findings cannot navigate into a different run.',
        'Staleness flags saved in this project.'),
    'findings.list': _e(
        'List of AI-assisted findings; select one to read its details.',
        'Lets you audit each hypothesis independently.',
        'Selecting shows details and evidence. Model output is an unverified hypothesis.',
        'Interpretation runs saved in this project.',
        'Empty until an interpretation has been run.'),
    'findings.detail': _e(
        'Read-only detail of the selected finding: summary, hypothesis and alternatives.',
        'Keeps model content separate from your own conclusion.',
        'Nothing changes; select text to copy it.',
        'Model output stored with the interpretation run. Treat it as unverified.',
        'Shows a hint until a finding is selected.'),
    'findings.evidence': _e(
        'Evidence records cited by the selected finding; select one to navigate to its code.',
        'Lets you verify claims against the real function text.',
        'Selecting jumps the code panes to the cited lines when the run is still current.',
        'Evidence references resolved against the saved analysis.',
        'Needs a selected finding.'),
    'findings.bookmark': _e(
        'Bookmark the selected evidence record.', 'Marks proof you want to find again.',
        'Adds a bookmark annotation to the project.',
        availability='Needs a selected evidence record and no running job.'),
    'findings.review_status': _e(
        'Set the review status for the selected finding.', 'Records whether you accept the hypothesis.',
        'Applied when you choose Save finding review.',
        availability='Needs a selected finding and no running job.'),
    'findings.conclusion': _e(
        'Type your own conclusion about the selected finding, for example Confirmed: bounds check added.',
        'Keeps analyst judgement separate from model content.',
        'Saved with the review when you choose Save finding review.',
        availability='Needs a selected finding and no running job.'),
    'findings.save_review': _e(
        'Save the review status and conclusion for the selected finding.',
        'Commits your decision.', 'Writes to the project.',
        availability='Needs a selected finding and no running job.'),
    'findings.note_target': _e(
        'Choose whether a new note attaches to the selected match or the selected finding.',
        'Keeps notes next to what they describe.', 'Changes only where Save note will attach the text.',
        availability='Needs an open project and no running job.'),
    'findings.notes': _e(
        'Type an analyst note, free text.', 'Records observations without involving AI.',
        'Saved to the chosen target when you choose Save note.',
        availability='Needs an open project and no running job.'),
    'findings.save_note': _e(
        'Save the typed note to the selected match or finding.', 'Keeps your reasoning with the data.',
        'Adds a note annotation to the project.',
        availability='Needs a selected target matching the note target, and no running job.'),
    'findings.inspect_responses': _e(
        'Inspect the raw responses returned by the interpretation provider.',
        'Lets you audit exactly what the model said.',
        'Opens a read-only window; nothing is sent or changed.',
        'Provider responses stored with each interpretation run.',
        'Needs an interpretation to exist.'),
    'job.log': _e(
        'Read-only log of job progress, warnings and export messages.',
        'Shows why a comparison or import succeeded or failed.',
        'Nothing changes; select text to copy it.',
        'Messages emitted by PatchTrace and the external backend. Capped at 2000 lines.'),
    # ---- New project dialog ----------------------------------------------------------------
    'new_project.name': _e(
        'Name of the new project, for example Patch comparison.', 'Identifies the project in menus.',
        'Used as the project title.', availability='Required.'),
    'new_project.older': _e(
        'Path of the older PE x64 file, for example C:\\samples\\app_1.0.dll. You can drop a file here.',
        'Defines the baseline side of the patch.',
        'The file is copied into the project; the original is preserved and never executed.',
        'Format and architecture are validated on creation.', 'Required; must be an existing file.'),
    'new_project.newer': _e(
        'Path of the newer PE x64 file, for example C:\\samples\\app_1.1.dll. You can drop a file here.',
        'Defines the patched side.',
        'The file is copied into the project; the original is preserved and never executed.',
        'Format and architecture are validated on creation.', 'Required; must be an existing file.'),
    'new_project.root': _e(
        'Folder that will hold the new project, for example D:\\work\\patchtrace-project.',
        'Everything PatchTrace stores for this comparison lives there.',
        'The folder is created and filled on creation.', availability='Must be absent or empty.'),
    'new_project.older_browse': _e(
        'Choose the older PE file in a file picker.', 'Avoids typing a long path.',
        'Fills the older path field.'),
    'new_project.newer_browse': _e(
        'Choose the newer PE file in a file picker.', 'Avoids typing a long path.',
        'Fills the newer path field.'),
    'new_project.root_browse': _e(
        'Choose a parent folder for the new project.', 'Avoids typing a long path.',
        'Fills the project directory field with a new patchtrace-project folder inside it.'),
    'new_project.swap': _e(
        'Exchange the older and newer paths.', 'Fixes a reversed selection before creation.',
        'Swaps the two path fields only; nothing is created yet.'),
    'new_project.accept': _e(
        'Create the project from the entered files.', 'Finishes setup of a new comparison.',
        'Validates the inputs, copies the files and opens the new project.',
        availability='Needs a name, two existing files and an absent or empty folder.'),
    'new_project.cancel': _e(
        'Close this dialog without creating a project.', 'Backs out safely.', 'Nothing is created.'),
    # ---- Acquisition dialog ----------------------------------------------------------------
    'acquire.name': _e(
        'Windows x64 file name to look up, for example clfs.sys.', 'Winbindex is searched by file name.',
        'Used by Search Winbindex; nothing is contacted until you confirm.',
        availability='Disabled while a download or search runs.'),
    'acquire.search': _e(
        'Search Winbindex for builds of the named file.', 'Lists the versions you can compare.',
        'After you confirm the exact host, fills the table with candidate builds.',
        'Winbindex metadata over the network.', 'Needs a file name; disabled while a job runs.'),
    'acquire.table': _e(
        'Candidate builds: version, KB numbers, release date, download availability and SHA-256.',
        'Lets you pick two builds with full knowledge of what they are.',
        'Selecting a row enables Use as older and Use as newer.',
        'Winbindex metadata; authenticity of the files is a separate question.',
        'Empty until a search completes.'),
    'acquire.use_older': _e(
        'Use the selected build as the older side.', 'Orientation must be explicit.',
        'Fills the Older build line below.', availability='Needs a selected row that is downloadable.'),
    'acquire.use_newer': _e(
        'Use the selected build as the newer side.', 'Orientation must be explicit.',
        'Fills the Newer build line below.', availability='Needs a selected row that is downloadable.'),
    'acquire.swap': _e(
        'Exchange the chosen older and newer builds.', 'Fixes a reversed choice.',
        'Swaps the two picks only.', availability='Needs at least one pick.'),
    'acquire.project_name': _e(
        'Name for the project created from the download, for example clfs.sys patch.',
        'Identifies the project afterwards.', 'Used as the project title.'),
    'acquire.root': _e(
        'Folder for the new project, for example D:\\work\\clfs-project.',
        'Downloads are stored inside the project.', 'The folder is created on download.',
        availability='Must be absent or empty.'),
    'acquire.browse': _e(
        'Choose the project folder in a file picker.', 'Avoids typing a long path.',
        'Fills the project directory field.'),
    'acquire.log': _e(
        'Read-only log of search and download steps.', 'Shows exactly which requests were made.',
        'Nothing changes; select text to copy it.', 'Events reported by the acquisition transport.'),
    'acquire.download': _e(
        'Download both builds and create a project.', 'Fetches the exact-hash binaries.',
        'After you confirm each host and URL, files are verified, quarantined and promoted into a new '
        'project.', 'Microsoft symbol server.', 'Needs both an older and a newer build picked.'),
    'acquire.cancel': _e(
        'Cancel the running search or download.', 'Stops network work you no longer want.',
        'The request stops cooperatively; no project is created.',
        availability='Only enabled while a job is running.'),
    'acquire.close': _e(
        'Close this dialog.', 'Leave acquisition.',
        'A running job is cancelled first; nothing else changes.'),
    # ---- Setup dialog ----------------------------------------------------------------------
    'setup.tabs': _e(
        'Switch between backend and desktop settings and analysis profiles.',
        'Keeps related settings together.', 'Changes the visible page only.'),
    'setup.python': _e(
        'Path of the external Python executable that has Ghidriff installed, for example '
        'C:\\ghidriff\\Scripts\\python.exe.',
        'Comparison runs Ghidriff in this separate environment.',
        'Saved with Save setup and used by Run comparison. It is not run until you diagnose or compare.',
        availability='Read-only during offline installation.'),
    'setup.python_browse': _e(
        'Choose the Python executable in a file picker.', 'Avoids typing a long path.',
        'Fills the Python field.'),
    'setup.ghidra_dir': _e(
        'Folder of the unpacked Ghidra installation, for example C:\\tools\\ghidra_11.3.',
        'Ghidriff needs Ghidra for decompilation.', 'Saved with Save setup.',
        availability='Read-only during offline installation.'),
    'setup.ghidra_browse': _e(
        'Choose the Ghidra folder in a file picker.', 'Avoids typing a long path.',
        'Fills the Ghidra directory field.'),
    'setup.java_home': _e(
        'Optional private Java folder, for example C:\\tools\\jdk-21. Leave empty to use the system Java.',
        'Ghidra needs a compatible Java runtime.', 'Saved with Save setup.',
        availability='Optional. Read-only during offline installation.'),
    'setup.java_browse': _e(
        'Choose the Java folder in a file picker.', 'Avoids typing a long path.',
        'Fills the Java directory field.'),
    'setup.restrict_env': _e(
        'Run Ghidra and Java with only an allowlisted set of environment variables.',
        'Keeps credentials and JVM or Python injection variables away from the process that loads binaries.',
        'Saved with Save setup. Off by default until validated on your machine.',
        availability='Experimental. Set PATCHTRACE_CHILD_ENV=inherit to override.'),
    'setup.env_passthrough': _e(
        'Extra environment variable names to keep when the allowlist is on, separated by commas.',
        'Corporate proxy or custom JDK setups may need extra variables.', 'Saved with Save setup.',
        availability='PYTHONPATH, PYTHONHOME, LD_PRELOAD and names ending in _OPTIONS are rejected.'),
    'setup.symbol_downloads': _e(
        'Allow Ghidriff to look up symbols on the Internet.',
        'Symbols improve names but contact a symbol server.',
        'When on, comparison may make network requests. When off, none are made.',
        'Applies to Ghidriff symbol lookups only.'),
    'setup.symbol_local': _e(
        'Name functions from PDB symbol files you already have, without any network access.',
        'Symbols improve names; this keeps every lookup on your machine.',
        'PatchTrace copies only a PDB whose GUID and age match the binary into a private per-run folder and '
        'tells Ghidra to use no symbol servers. Off by default.',
        'Cannot be combined with Internet symbol lookups.'),
    'setup.symbol_dirs': _e(
        'Folders searched for PDB files, separated by semicolons, at most 16.',
        'Only a PDB named in the binary and matching its GUID and age is used; others are skipped.',
        'Saved with Save setup. Folders are searched one level deep by exact file name.',
        availability='Used only when local PDB mode is on.'),
    'setup.timeout': _e(
        'Seconds a comparison may run before it is stopped, a whole number from 10 to 86400.',
        'Prevents a stuck backend from running forever.', 'Saved with Save setup.'),
    'setup.font_size': _e(
        'Code font size in points, a whole number from 8 to 28.', 'Adjusts readability of the code panes.',
        'Applied when you save setup.'),
    'setup.context_budget': _e(
        'Maximum characters of context sent for interpretation, a whole number from 512 to 200000.',
        'Bounds the size and cost of what leaves the machine.',
        'Larger budgets include more records; omitted ones are listed in the preview.'),
    'setup.sync': _e(
        'Default for synchronized code scrolling.', 'Remembers your preferred reading mode.',
        'Applied to the Sync scroll option when you save setup.'),
    'setup.diagnostics': _e(
        'Read-only output of discovery and dependency diagnosis.', 'Explains what is missing.',
        'Nothing changes; select text to copy it.',
        'Results of local checks. No target binary is run.'),
    'setup.find': _e(
        'Look for existing Python and Ghidra installations on this computer.',
        'Saves hunting for paths.', 'Fills empty path fields with what it finds.',
        'Local folders only; no network access.', 'Disabled during offline installation.'),
    'setup.bundle_sha': _e(
        'Optional SHA-256 of the offline ZIP from a trusted source, 64 lowercase hex characters.',
        'Proves the archive matches what the publisher advertises.',
        'Compared with the ZIP before you are asked to install.', availability='Optional.'),
    'setup.install': _e(
        'Install a prebuilt offline backend ZIP.', 'Provides Ghidriff, Ghidra and Java without Internet.',
        'Inspects the ZIP, shows its details and asks before a private per-user installation. Nothing '
        'is executed or downloaded.', 'A ZIP file you choose.', 'Disabled while another operation runs.'),
    'setup.cancel_install': _e(
        'Cancel the running offline installation check.', 'Stops a long extraction.',
        'The operation stops cooperatively.', availability='Only enabled while an installation runs.'),
    'setup.diagnose': _e(
        'Check that Python, Ghidriff, Ghidra and Java are usable.', 'Finds problems before a long run.',
        'Reports results in the output area. Neither target artifact is run.',
        'Local checks of the configured paths.', 'Disabled during offline installation.'),
    'setup.backend.bundle': _e(
        'Shows whether the analysis runtime bundled next to PatchTrace passed its fast file check.',
        'Tells you before a run whether the download was extracted completely.',
        'Read-only; select text to copy it. A problem means you should extract the complete ZIP again.',
        'Compared with backend/manifest.json; no process is started.',
        'Shown only when a bundled runtime is found next to PatchTrace.'),
    'setup.backend.verify': _e(
        'Hash every file of the bundled runtime and compare it with its manifest.',
        'Finds corrupted or incomplete files that the fast check cannot see.',
        'Runs in the background with progress text and changes none of your settings. It proves the '
        'files are intact, not who published them.',
        'Local files only; no network access.', 'Disabled while another operation runs.'),
    'setup.backend.verify_cancel': _e(
        'Stop the running bundle file verification.', 'A full hash of a large bundle can take minutes.',
        'Stops after the current chunk; your settings and the bundle files are unchanged.',
        availability='Only enabled while the verification runs.'),
    'setup.accept': _e(
        'Save the backend, desktop and profile settings.', 'Makes the changes take effect.',
        'Writes preferences to local desktop settings. API keys are never saved.'),
    'setup.cancel': _e(
        'Close setup without saving.', 'Backs out safely.', 'Discards unsaved edits.'),
    # ---- Profiles panel --------------------------------------------------------------------
    'profile.list': _e(
        'List of analysis profiles; select one to view or edit it.',
        'Profiles control which detectors rank changes and how.',
        'Selecting loads the profile into the editor.',
        'Profile files in your profile folder. The default profile is read-only.'),
    'profile.new': _e(
        'Create a new profile from the default settings.', 'Start a custom ranking setup.',
        'Adds a profile you can edit and save.'),
    'profile.duplicate': _e(
        'Copy the selected profile under a new name.', 'Tweak a profile without losing the original.',
        'Adds a copy to the list.', availability='Needs a selected profile.'),
    'profile.delete': _e(
        'Delete the selected profile.', 'Removes one you no longer need.',
        'Asks for confirmation, then removes its file.',
        availability='Needs a selected profile; the default cannot be deleted.'),
    'profile.name': _e(
        'Profile name, up to 64 characters, for example strict-bounds.', 'Identifies the profile in lists.',
        'Used as the profile name when saved.', availability=_DEFAULT_RO),
    'profile.feature_ids': _e(
        'Windows Feature IDs to consider, comma-separated whole numbers from 0 to 4294967295 such as '
        '1234, 5678. Empty means all features.',
        'Restricts the WIL detector to features you care about.',
        'Saved with the profile.', availability=_DEFAULT_RO),
    'profile.symbol_policy': _e(
        'Symbol policy: disabled or online.', 'Controls whether symbol lookups may use the network.',
        'Saved with the profile; online permits network lookups.',
        availability=_DEFAULT_RO),
    'profile.max_age': _e(
        'Maximum age in days of enrichment snapshots, a whole number from 1 to 3650.',
        'Avoids relying on stale advisory data.', 'Saved with the profile.',
        availability=_DEFAULT_RO),
    'profile.cache_dir': _e(
        'Absolute folder for the enrichment cache, for example D:\\patchtrace-cache. Empty means no cache.',
        'A cache avoids repeating downloads.', 'Saved with the profile.',
        availability=_DEFAULT_RO),
    'profile.cache_budget': _e(
        'Cache size limit in GiB, a whole number from 1 to 1024.', 'Stops the cache growing unbounded.',
        'Saved with the profile.', availability=_DEFAULT_RO),
    'profile.save': _e(
        'Save the edited profile.', 'Makes the weights and options available for ranking.',
        'Validates then writes the profile file; errors are shown below.',
        availability=_DEFAULT_RO),
    'profile.provider_nvd': _e(
        'Use NVD as a CVE provider for this profile.', 'Adds advisory context from NVD.',
        'Saved with the profile; network use is still explicit.',
        availability=_DEFAULT_RO),
    'profile.provider_msrc': _e(
        'Use MSRC as a CVE provider for this profile.', 'Adds advisory context from Microsoft.',
        'Saved with the profile; network use is still explicit.',
        availability=_DEFAULT_RO),
    # ---- Interpretation context dialog -------------------------------------------------------
    'context.tabs': _e(
        'Switch between the exact context, the exact system prompt and omitted records.',
        'You can see everything that would be sent.', 'Changes the visible page only.'),
    'context.exact_context': _e(
        'Exact payload that will be sent to the provider.', 'Transmission must be explicit and reviewable.',
        'Read-only; nothing is sent until you choose Send context.',
        'Built from the selected matches and evidence in the saved project.'),
    'context.system_prompt': _e(
        'Exact system prompt that will accompany the context.', 'Shows the instructions given to the model.',
        'Read-only; nothing changes.', 'The prompt shipped with PatchTrace.'),
    'context.omitted': _e(
        'Records left out of the context, with reasons.', 'Shows what the model will not see.',
        'Read-only; nothing changes.', 'Budget and availability decisions made while building the context.'),
    'context.kind': _e(
        'Provider type: ollama (local) or openai (OpenAI-compatible).', 'Selects the protocol used.',
        'Changes which endpoint rules apply; Ollama must use a loopback endpoint.'),
    'context.endpoint': _e(
        'Provider URL, for example http://127.0.0.1:11434 for Ollama or https://api.example.com/v1.',
        'Tells PatchTrace where to send the context.',
        'Used only after you choose Send context. OpenAI-compatible providers require HTTPS.'),
    'context.model': _e(
        'Model name to request, for example llama3 or gpt-4o.', 'Chooses which model answers.',
        'Sent with the request.', availability='Required.'),
    'context.key': _e(
        'API key for the provider. Optional for local Ollama.', 'Authenticates the request.',
        'Kept in memory for this request only and never saved.'),
    'context.accept': _e(
        'Send the exact context shown to the configured provider.', 'This is the explicit consent step.',
        'The context leaves this computer and a response is stored as an unverified hypothesis.',
        availability='Needs a model name and a valid endpoint.'),
    'context.cancel': _e(
        'Close without sending anything.', 'Backs out safely.', 'Nothing is transmitted.'),
    # ---- Correct match dialog ---------------------------------------------------------------
    'correct.older_list': _e(
        'Older function records; tick the ones that belong to this match.',
        'Defines the older side of the corrected relationship.',
        'Applied when you save the correction.', 'Records from the saved comparison.'),
    'correct.newer_list': _e(
        'Newer function records; tick the ones that belong to this match.',
        'Defines the newer side of the corrected relationship.',
        'Applied when you save the correction.', 'Records from the saved comparison.'),
    'correct.category': _e(
        'Relationship category such as modified, added or removed.', 'Describes how the sides relate.',
        'Saved with the correction.'),
    'correct.reason': _e(
        'Analyst reason for the correction, free text such as Same function after inlining.',
        'Provenance for later audit.', 'Stored with the correction.', availability='Required.'),
    'correct.accept': _e(
        'Save the corrected relationship.', 'Applies your override.',
        'Retains provenance and invalidates findings that depended on the old pairing.',
        availability='Needs a reason.'),
    'correct.cancel': _e(
        'Close without changing the match.', 'Backs out safely.', 'Nothing is changed.'),
    # ---- Export dialog ---------------------------------------------------------------------
    'export.format': _e(
        'Report format: md (Markdown), html or json.', 'Choose what suits the reader or tool.',
        'Changes the preview and the file extension.'),
    'export.destination': _e(
        'Output file path, for example D:\\reports\\report.md.', 'Where the report will be written.',
        'The file is written only when you choose Write report.'),
    'export.browse': _e(
        'Choose the output file in a file picker.', 'Avoids typing a long path.',
        'Fills the destination field.'),
    'export.include_code': _e(
        'Include function code in the report.', 'Code is excluded by default to limit what is shared.',
        'Adds decompiled or assembly text from the saved analysis.',
        'Ghidriff output, not original source.'),
    'export.include_notes': _e(
        'Include analyst notes in the report.', 'Shares your reasoning along with results.',
        'Adds saved notes to the report.', 'Notes stored in this project.'),
    'export.selected_only': _e(
        'Restrict the report to the findings currently selected.', 'Produces a focused report.',
        'Excludes other findings.', availability='Needs findings selected in the main window.'),
    'export.preview': _e(
        'Read-only preview of the exact report.', 'You review what will be written.',
        'Nothing changes. Absolute source paths are redacted and raw provider responses excluded.',
        'Generated from saved project data.'),
    'export.accept': _e(
        'Write the report to the chosen destination.', 'Produces the file you previewed.',
        'Creates or overwrites the destination file.', availability='Needs a destination.'),
    'export.cancel': _e(
        'Close without writing a report.', 'Backs out safely.', 'Nothing is written.'),
    # ---- other dialogs ---------------------------------------------------------------------
    'overview.pe_table': _e(
        'Field-by-field comparison of parsed PE headers, sections, imports, exports, overlay and '
        'certificate-table presence for the older and newer artifacts.',
        'Shows structural differences immediately, before or without the Ghidriff analysis backend.',
        'Read-only. Bold rows changed. Nothing is executed and the project is not modified.',
        'Bounded read-only parsing of the verified project artifact copies. COFF timestamps are untrusted. '
        'Certificate presence is not signature validity.',
        'Fields show unavailable when a side cannot be verified or parsed; the reason is in each tooltip.'),
    'overview.table': _e(
        'Recorded file fields for the older and newer artifacts.', 'A fast sanity check before analysis.',
        'Read-only; nothing is executed, parsed or re-read from disk.',
        'Metadata recorded when the project was created. No signature verification is performed.'),
    'dialog.text_view': _e(
        'Read-only text.', 'Presents information without allowing edits.',
        'Select text to copy it; nothing else changes.'),
    'dialog.close': _e(
        'Close this window.', 'Return to the main window.', 'Nothing is changed.'),
    'confirm.yes': _e(
        'Confirm and continue with the action described.', 'The action requires your explicit consent.',
        'The described action proceeds.'),
    'confirm.no': _e(
        'Decline and stop.', 'Leaves things as they are.', 'The described action does not happen.'),
    # ---- Series window (SPEC-09b) ------------------------------------------------------------
    'action.series': _e(
        'Open a read-only tab over a stored series.json of three or more builds of one binary.',
        'Follow one function across several builds and see which hops deserve attention first.',
        'Opens the Series panel with a tab for that series. Nothing is computed, run or written, and pair projects are only read.',
        'The series.json written by `patchtrace series create` and the pair projects next to it.'),
    'series.window': _e(
        'Read-only view of the chain hypotheses stored in one series.json, in the Series panel.',
        'Compares a function across builds without opening each pair project by hand.',
        'Nothing is changed. Chains are labelled hypotheses assembled from independent pairwise results.',
        'series.json (nway/1) and each pair project\'s stored results.'),
    'series.reload': _e(
        'Read series.json and the pair projects again.', 'Picks up pair results changed since the tab opened.',
        'Cancels a load in progress and starts a new read. Nothing is written.',
        availability='Always available.'),
    'series.cancel_load': _e(
        'Stop reading the series.', 'A large series can take several seconds to read.',
        'The load is abandoned and what was shown before stays. Nothing is written.',
        availability='Enabled only while loading.'),
    'series.filter_text': _e(
        'Show only chains whose function names, addresses, build labels or chain ID contain this text.',
        'Narrows a long list to the function you are following.',
        'Filters the table in the window only; case-insensitive, up to 200 characters.'),
    'series.filter_status': _e(
        'Show only chains with this status: inferred, confirmed or contradicted.',
        'Confirmed and contradicted come from an optional direct first-to-last pair; inferred does not.',
        'Filters the table in the window only.'),
    'series.filter_event': _e(
        'Show only chains with this event: added, removed, split, merged, ambiguous, unmatched or reverted.',
        'Events mark where a function appeared, disappeared or changed shape between builds.',
        'Filters the table in the window only.'),
    'series.only_stale': _e(
        'Show only chains passing through a pair project that changed since the series was computed.',
        'Tells you which chains need `patchtrace series create` to be re-run.',
        'Filters the table in the window only.'),
    'series.only_scored': _e(
        'Show only chains with at least one hop that has a stored attention score.',
        'Hides chains that no ranking has covered yet.', 'Filters the table in the window only.'),
    'series.min_score': _e(
        'Show only chains whose highest hop score is at least this value (0 to 100).',
        'Focuses on the hops that research prioritization ranked highest.',
        'Filters the table in the window only; 0 disables the filter and chains without any score are hidden above 0.',
        'Attention score from the pair project\'s stored default-profile ranking (research prioritization, '
        'not exploitability). Not combined across pairs.'),
    'series.sort': _e(
        'Order the chains by highest hop, sum of hops, hop count, name or chain ID.',
        'Puts the most interesting chains first; ties are broken by chain ID so the order is stable.',
        'Reorders the table only. Highest hop and sum of hops are display aids, never a chain-level score.',
        'Attention score from the pair project\'s stored default-profile ranking (research prioritization, '
        'not exploitability). Not combined across pairs.'),
    'series.chain_table': _e(
        'One row per chain hypothesis across three or more builds.',
        'Shows where a function is followed through every adjacent pair and how hot its hops are.',
        'Selecting a row shows its hops. Nothing is changed.',
        'A chain is a labelled hypothesis from independent pairwise results, not a fact. Scores come from '
        'each pair project\'s stored default-profile ranking and are not combined across pairs.'),
    'series.hop_table': _e(
        'One row per hop (adjacent build pair) of the selected chain.',
        'Shows the match category, upstream match types, ratio and attention score of each step.',
        'Selecting a hop enables opening its pair project. Nothing is changed.',
        'Attention score from the pair project\'s stored default-profile ranking (research prioritization, '
        'not exploitability). Not combined across pairs. Ratios are upstream text.'),
    'series.open_pair': _e(
        'Open the pair project of the selected hop at this function.',
        'Lets you read the code difference behind the score.',
        'Asks the main window to open that pair project; the series window itself changes nothing.',
        availability='Needs a selected hop whose pair project is readable. Unchanged hops have no match to open.'),
    'series.copy_chain': _e(
        'Copy the selected chain as plain text.', 'Share or note a chain with its builds and hops.',
        'Puts text with labels, ordinals and the first 12 hex digits of each build hash on the clipboard.',
        availability='Needs a selected chain.'),
    'series.banner': _e(
        'Warnings about the stored series: out-of-date chains, unreadable pairs or a truncated list.',
        'Scores for affected hops are not available and say why.',
        'Nothing is changed; re-run `patchtrace series create` to refresh chains.'),
    # ---- C6 multi-engine evidence panel (docs/specs/multi-engine-evidence-panel.md 7.1) ---------------
    'evidence.dock': _e(
        'Panel comparing function-pairing evidence from several diff engines side by side.',
        'Shows where engines agree or conflict about which functions correspond across builds.',
        'Read-only; opening or closing it changes no project data.',
        'Stored Ghidriff results plus imported or locally run secondary engine results; uncalibrated.',
        'Needs an open project.'),
    'evidence.action': _e(
        'Show or hide the engine evidence panel.',
        'Opens per-engine function-pairing evidence next to the workspace.',
        'Toggles the dock; shortcut Ctrl+Shift+E.', availability='Needs an open project for content.'),
    'evidence.tabs': _e(
        'Switch between the evidence table and the engine run controls.',
        'Keeps reviewing results separate from launching engines.', 'Changes the visible tab only.'),
    'evidence.filter': _e(
        'Show only matches with the chosen engine verdict, or the engine-only records.',
        'Focus review on conflicts first, then unknown and single-engine matches.',
        'Filters the table; remembered for next time.', availability='Needs loaded evidence.'),
    'evidence.search': _e(
        'Find evidence rows by function name or hexadecimal address (0x is optional).',
        'Jump to a function you already care about.', 'Filters the table as you type.',
        availability='Needs loaded evidence.'),
    'evidence.hide_agreed': _e(
        'Hide matches where every comparable engine pairs the same endpoints.',
        'Leaves the rows that need a human decision.', 'Filters the table; remembered for next time.'),
    'evidence.show_index': _e(
        'Also show the uncalibrated triage index in the detail pane.',
        'Some reviewers use it to order work; it is not a measure of correctness.',
        'Adds one line to details and to copied provenance; off by default; remembered.',
        'SPEC-27 placeholder constants; an ordering aid only, not a probability.'),
    'evidence.table': _e(
        'Per-match list of engine verdicts with one column per engine in its own units.',
        'Compare engines without merging their scales; each engine column is that engine alone.',
        'Selecting a row shows details; Enter goes to the match; Ctrl+C copies provenance.',
        'Ghidriff results plus stored BinDiff and rz-diff sets; values are never combined.',
        'Needs loaded evidence.'),
    'evidence.detail': _e(
        'Read-only per-engine native values, alternatives, limitations and provenance of the selected row.',
        'Explains why the verdict was reached and which engine said what.',
        'Plain text you can select and copy; nothing is edited.', availability='Needs a selected row.'),
    'evidence.copy': _e(
        'Copy plain-text provenance of the selected evidence rows to the clipboard.',
        'Paste an auditable record of engine values, versions and artifact hashes into notes or tickets.',
        'Writes text to the clipboard only (capped at 16 KiB and 200 rows).',
        availability='Needs a selected row.'),
    'evidence.goto': _e(
        'Select the same function match in the navigator on the left.',
        'Inspect the code of a contested or unknown match.',
        'Changes the navigator selection; nothing is modified.',
        availability='Needs a selected row; disabled while evidence is stale.'),
    'evidence.refresh': _e(
        'Reload engine evidence from the stored Ghidriff and secondary engine results.',
        'Brings the panel up to date after the project changed.',
        'Recomputes the table on a background thread; nothing is written.',
        availability='Needs an open project.'),
    'evidence.import_bindiff': _e(
        'Import a .BinDiff result file for this older/newer pair.',
        'Adds BinDiff as a second opinion on function pairing.',
        'Validates the file against both artifact hashes and stores it as the BinDiff set.',
        'A file you produced with BinDiff; PatchTrace does not run BinDiff.',
        'Needs an open project with a completed run and no running job.'),
    'evidence.engine_table': _e(
        'State, version and input hashes of each engine for this project.',
        'Shows which engines produced results and why others did not.',
        'Selecting a row shows its output below.'),
    'evidence.engine_check': _e(
        'Include this secondary engine in the next run.',
        'Choose which engines to spend time on.', 'Takes effect when you press Run selected engines.',
        availability='Needs a successful engine probe.'),
    'evidence.parallel': _e(
        'How many engines may run at the same time (1 or 2).',
        'Two in parallel finish sooner but use more memory.', 'Applies to the next run.'),
    'evidence.timeout': _e(
        'Wall-clock limit per engine run, from 60 to 86400 seconds.',
        'Stops an engine that hangs on a large pair.', 'Applies to the next run; a timed-out engine stores nothing.'),
    'evidence.probe': _e(
        'Check which engines are installed and supported.',
        'Engine runs need a supported version (rz-diff 0.9.0 or newer).',
        'Runs only version checks of the tools; nothing is run on the binaries.'),
    'evidence.run': _e(
        'Run the selected engines on the stored artifact copies.',
        'Produces second-opinion function pairings for this pair.',
        'Each engine runs in its own process; finished results are stored even if another engine fails.',
        'External user-installed tools; the binaries are read as data and never executed; nothing is uploaded.',
        'Needs an idle project, a completed Ghidriff run and a supported, selected engine.'),
    'evidence.cancel': _e(
        'Stop the running engines.',
        'Abandon a run that takes too long.', 'Kills the engine processes; partial output is discarded.',
        availability='Needs a running engine job.'),
    'evidence.engine_log': _e(
        'Last lines of the selected engine output, shown as plain text.',
        'Helps diagnose a failed or slow engine.', 'Read-only; at most 200 lines are kept.'),
    'evidence.copy_details': _e(
        'Copy the selected engine failure details to the clipboard.',
        'Report a failed engine with its error code, version, hashes and output tail.',
        'Writes plain text to the clipboard only.',
        availability='Needs a failed or cancelled engine.'),
    'evidence.stale_banner': _e(
        'Explains that the shown evidence describes a different artifact pair, run or revision.',
        'Stale values must not be read as describing the current comparison.',
        'Row activation is disabled until you refresh; copying provenance marks the text STALE.'),
    # ---- track G BinDiff run setup in the Engines tab (multi-engine-evidence-panel.md section 16) ----
    'engine_setup.toggle': _e(
        'Show or hide the BinDiff run setup below the engine controls.',
        'Running BinDiff needs its executable and one .BinExport file per project file; this section collects '
        'and checks them.',
        'Only changes what is shown and is remembered for next time. Nothing runs until you press Probe BinDiff '
        'or Validate .BinExport files.',
        availability='Needs an open project.'),
    'engine_setup.section': _e(
        'BinDiff run setup: the BinDiff executable and the two .BinExport inputs for this project.',
        "BinDiff compares exported function graphs, not the binaries, so both exports must come from exactly "
        "this project's older and newer files.",
        'Once the executable is usable and both exports are accepted, BinDiff can be ticked for Run selected '
        'engines.',
        'Your installed BinDiff 8 and .BinExport files you exported with Ghidra or IDA; nothing is downloaded '
        'or uploaded.',
        'Needs an open project; locked while engines run.'),
    'engine_setup.bindiff_path': _e(
        'Absolute path of the bindiff executable (bindiff.exe on Windows) of an installed BinDiff 8.',
        'PatchTrace never searches PATH for BinDiff; you choose the exact program that will be run.',
        'Changing it marks BinDiff as not checked. The path is remembered after a successful probe. Discovered '
        'installations are offered in the list but never run until you press Probe BinDiff.',
        'Typed or chosen by you; suggestions come from a read-only look at standard install folders.',
        'Needs an open project; locked while engines run.'),
    'engine_setup.bindiff_browse': _e(
        'Pick the bindiff executable with a file dialog.',
        'Saves typing a long installation path by hand.',
        'Fills the executable field; nothing is run.',
        availability='Needs an open project; locked while engines run.'),
    'engine_setup.bindiff_probe': _e(
        'Check that the chosen file is a usable BinDiff 8 or newer.',
        'BinDiff is only run when its version and every command-line option PatchTrace relies on are confirmed.',
        'Runs bindiff --version and bindiff --nologo --help on a background thread, in a private folder with a '
        'minimal environment. It never reads the project files and never opens the BinDiff user interface.',
        'The executable you chose; the version is compared with the BinDiff 8 build PatchTrace was tested with.',
        'Needs an executable path and an open project; locked while engines run.'),
    'engine_setup.older_binexport': _e(
        "Path of the .BinExport exported from this project's older file; BinDiff reads it as the primary.",
        'BinDiff needs one export per side, and the older side is always the primary.',
        'Changing it discards the last validation and the unbound confirmation.',
        'A file you exported with Ghidra (File, Export, Binary BinExport (v2) for BinDiff) or with IDA 9.4 or '
        'newer.',
        'Needs an open project; locked while engines run.'),
    'engine_setup.older_browse': _e(
        'Pick the older .BinExport file with a file dialog.',
        'Choose the export of the older project file without typing its path.',
        'Fills the older field; the file is not read until you validate.',
        availability='Needs an open project; locked while engines run.'),
    'engine_setup.newer_binexport': _e(
        "Path of the .BinExport exported from this project's newer file; BinDiff reads it as the secondary.",
        'BinDiff compares the secondary export against the primary one, so the newer side must be the newer '
        'file.',
        'Changing it discards the last validation and the unbound confirmation.',
        'A file you exported the same way as the older one, with the same Subtract Imagebase choice.',
        'Needs an open project; locked while engines run.'),
    'engine_setup.newer_browse': _e(
        'Pick the newer .BinExport file with a file dialog.',
        'Choose the export of the newer project file without typing its path.',
        'Fills the newer field; the file is not read until you validate.',
        availability='Needs an open project; locked while engines run.'),
    'engine_setup.accept_unbound': _e(
        'Accept .BinExport files whose executable id is not a SHA-256 (an MD5 hash, empty, or another id).',
        'Some exporters write no usable SHA-256 id; without it PatchTrace cannot check which file an export '
        'came from.',
        'Lets validation and the next BinDiff run bind such files on your word, and stores your confirmation '
        'with the result. A SHA-256 id that does not match is still refused. Resets when a path or the project '
        'changes.',
        'Your explicit confirmation; it is never remembered between sessions.',
        'Needs an open project; locked while engines run.'),
    'engine_setup.unbound_warning': _e(
        'Warning about accepting .BinExport files without a SHA-256 executable id.',
        'A wrong file would produce meaningless function pairings that look like real ones.',
        'Read-only text; nothing changes when you read it.'),
    'engine_setup.validate': _e(
        "Check both .BinExport files and confirm they belong to this project's older and newer files.",
        'Catches swapped, foreign, malformed or oversized exports before BinDiff runs.',
        'Reads each file in an isolated, memory- and time-limited checker on a background thread, then checks '
        'the pair. Temporary copies are removed. Shows function counts, architecture and how each file is tied '
        'to the project.',
        'The two files you chose and the SHA-256 values recorded for the project files.',
        'Needs an open project and both paths; locked while engines run.'),
    'engine_setup.cancel_validation': _e(
        'Stop the running .BinExport validation.',
        'Checking a large export can take a while.',
        'Stops the isolated checker; nothing is kept and the files stay unvalidated.',
        availability='Needs a running validation.'),
    'engine_setup.show_details': _e(
        'Show the technical details of the BinDiff probe and the .BinExport validation.',
        'Error codes and reason names help when reporting a problem or looking it up in the specification.',
        'Shows or hides a read-only text area; nothing is run.'),
    'engine_setup.details': _e(
        'Read-only technical details: probe result, error code, failure kind, reason name and checked hashes.',
        'Complements the plain-language status lines with the exact machine values.',
        'Plain text you can select and copy. Output of the external checkers is never shown here.'),
}

# Tooltips for items that depend on untrusted or dynamic values.
TEMPLATES: dict[str, TooltipEntry] = {
    'overview.pe_row': _e(
        'Inspect the recorded PE overview field {field} for both artifacts.',
        'Review a structural or trust difference with its limitations visible.',
        'Read-only display; this does not change the binary or validate an exploit.',
        'Information origin: {provenance}.',
        'Interpretation or availability: {reason}.'),
    'action.recent_project': _e(
        'Open the recent project at {path}.', 'Resume earlier work in one step.',
        'Replaces the project shown in the window.', 'Path stored in local desktop settings.',
        'Disabled while a job is running.'),
    'profile.detector_weight': _e(
        'Ranking weight of detector {detector}, a whole number from 0 to 100.',
        'Higher weights raise the attention score of matching functions.',
        'Saved with the profile.', availability=_DEFAULT_RO),
    'series.score_cell': _e(
        'Attention score state for this hop: {state}.', 'Reason: {reason}.',
        'Read-only display; nothing is recomputed.',
        'Attention score from the pair project\'s stored default-profile ranking (research prioritization, '
        'not exploitability). Not combined across pairs.'),
    'series.pair_state': _e(
        'Pair project state: {state}.', 'Reason: {reason}.',
        'Read-only display; the pair project is only read and never written.',
        'Observed when this window last read the pair project.'),
    'profile.detector_enabled': _e(
        'Turn detector {detector} on or off for this profile.', 'Lets you drop signals you do not trust.',
        'Saved with the profile; disabled detectors do not contribute to ranking.',
        availability=_DEFAULT_RO),
    'evidence.row': _e(
        'Engine evidence for {function}.', 'Review {verdict} and per-engine native values.',
        'Read-only.', 'Engines: {engines}.', 'Addresses: {reason}.'),
    'evidence.cell': _e(
        '{engine} native value {value} in {unit}.',
        'Different engines use different scales and are never combined.', 'Read-only.',
        '{provenance}.', 'Details: {reason}.'),
    'evidence.badge': _e(
        '{verdict}: {meaning}', 'Verdicts concern function pairing only.', 'Read-only.',
        availability='Reason: {reason}'),
    'evidence.engine_row': _e(
        '{engine} state: {state}.', 'Detail: {detail}.', 'Read-only.', 'Input hashes: {hashes}.'),
}


def tooltip(tip_id: str) -> str:
    """Wrapped, escaped tooltip for a static control. Unknown IDs raise KeyError."""
    return _rich(REGISTRY[tip_id].render())


def plain_description(tip_id: str) -> str:
    """Unwrapped plain text for accessible descriptions and status tips."""
    return REGISTRY[tip_id].render()


def clean_value(value: object) -> str:
    text = _CONTROL.sub('', str(value))
    return text[:VALUE_LIMIT] + ('...' if len(text) > VALUE_LIMIT else '')


def _fill(tip_id: str, values: dict[str, object]) -> TooltipEntry:
    entry = TEMPLATES[tip_id]
    safe = {key: clean_value(value) for key, value in values.items()}

    def fill(text: str) -> str:
        return text.format(**safe) if text else text
    return TooltipEntry(fill(entry.what), fill(entry.why), fill(entry.effect), fill(entry.source),
                        fill(entry.availability))


def template(tip_id: str, **values: object) -> str:
    """Escaped tooltip for a dynamic item. Every value is control-stripped, capped and escaped."""
    return _rich(_fill(tip_id, values).render())


def template_description(tip_id: str, **values: object) -> str:
    return _fill(tip_id, values).render()


def _rich(text: str) -> str:
    """Plain text as sanctioned rich text so Qt wraps long lines. All content is escaped once."""
    return '<p style="white-space:pre-wrap">' + html.escape(text).replace('\n', '<br>') + '</p>'


def apply_tooltip(target, tip_id: str, *, name: str | None = None, accessible: str = 'what', **values: object) -> None:
    """Apply a registry entry to a QWidget or QAction (the work is `gui.tips.apply_tip`).

    Sets toolTip and whatsThis on both, plus statusTip on actions and accessibleDescription on widgets. The description
    is the short What line; pass ``accessible='full'`` for the whole flattened text.
    ``objectName`` is set to ``name`` (default: the ID) only when still empty. Dynamic IDs (those in TEMPLATES)
    take their values as keyword arguments.
    """
    from .gui.tips import apply_tip
    apply_tip(target, tip_id, accessible=accessible, name=name, **values)


def apply_tooltips(owner, mapping: dict[str, str]) -> None:
    """Apply many static entries: ``{attribute_name_on_owner: tip_id}``."""
    for attribute, tip_id in mapping.items():
        apply_tooltip(getattr(owner, attribute), tip_id)
