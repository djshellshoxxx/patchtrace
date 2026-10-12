# PatchTrace

**Compare binaries. Trace fixes. Investigate flaws.**

PatchTrace is a desktop workspace for comparing two Windows x64 binaries and investigating what a patch changed. It combines Ghidriff/Ghidra static analysis with a new paired code viewer, persistent projects, manual function matching, analyst notes, optional AI interpretation, and report exports.

Start with an older and newer version of the same executable, DLL, or driver. Run a comparison or import its Ghidriff JSON, inspect the changed functions, and record your conclusion. AI can suggest the purpose of a fix and possible underlying bugs, with citations back to the supplied code. A function change, matching score, or model assessment does not establish that a vulnerability exists.

## Contents

- [Download and first launch](#download-and-first-launch)
- [Try the sample](#try-the-sample)
- [Install the comparison backend](#install-the-comparison-backend)
- [Compare your own binaries](#compare-your-own-binaries)
- [Workspace and GUI controls](#workspace-and-gui-controls)
- [Correct matches and record your review](#correct-matches-and-record-your-review)
- [Rank changes, feature flags and CVE context](#rank-changes-feature-flags-and-cve-context)
- [Optional AI interpretation](#optional-ai-interpretation)
- [Export and share results](#export-and-share-results)
- [Projects, backups, and data handling](#projects-backups-and-data-handling)
- [How PatchTrace differs from the upstream programs](#how-patchtrace-differs-from-the-upstream-programs)
- [Troubleshooting](#troubleshooting)
- [Development, verification, and architecture](#development-verification-and-architecture)

## Download and first launch

1. Download the Windows x64 ZIP and its `.sha256` file from [Releases](https://github.com/djshellshoxxx/patchtrace/releases). The first published package is [v0.1.0-beta.8](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.8).
2. Extract the **entire ZIP** to a user-writable directory. Keep `PatchTrace.exe`, `_internal`, documentation, and licenses together. Running the executable inside the ZIP or copying only the executable will not work.
3. Launch `PatchTrace.exe`. The desktop includes Python and Qt, so a separate Python installation is unnecessary for opening projects, exploring the sample, reviewing imported comparisons, or exporting reports.
4. Choose **Sample** for a guided first exercise, or **New** to create a comparison project.

The desktop target is Windows 11 x64. The initial input format is PE AMD64, including compatible `.exe`, `.dll`, and `.sys` files. File extensions alone do not determine acceptance: headers and architecture are validated. ARM64, 32-bit x86, ELF, Mach-O, and other formats are outside this beta's supported input contract.

To check the download in PowerShell:

```powershell
Get-FileHash '.\PatchTrace-0.1.0-windows-x64.zip' -Algorithm SHA256
Get-Content '.\PatchTrace-0.1.0-windows-x64.zip.sha256'
```

Compare the hash values. The package is a portable, unsigned beta; no installer or elevation is required. Keep projects in their own directories rather than inside the application directory, so replacing the application does not replace your work.

## Try the sample

The sample requires neither Ghidra nor an AI provider.

1. Click **Sample** and choose a parent directory. PatchTrace creates a new `patchtrace-sample-<timestamp>` project there.
2. Select the modified function in **FUNCTION MATCHES**. Inspect its older and newer code in the center panes and use **Next diff** to reach the changed region.
3. Switch between **Decompiled code**, **Assembly**, and **Metadata** to see the available representations. Missing information is labeled explicitly.
4. Select the sample finding in **FINDINGS & ANALYST REVIEW**. Read its explanation, unknowns, and supporting evidence. Select an evidence entry to navigate to the corresponding code.
5. Add a note, choose a finding review status, enter your own conclusion, and click **Save finding review**.
6. Choose **Export**, inspect the preview, and write a Markdown, HTML, or JSON report.
7. Close and reopen the project using **Open** and its project directory.

This is an authored, synthetic bounds-check example with a curated finding. Its presence does not mean a live model has run or a real binary has been analyzed. Each use of Sample creates a separate persistent project; it does not overwrite an existing comparison.

## Install the comparison backend

**Run comparison** requires a separate analysis environment. Ghidra, Java, Ghidriff, and local AI models are not bundled or downloaded automatically. Docker is not required by PatchTrace's supported desktop workflow.

The native fixture passed with Python 3.12.10, Ghidra 12.0.4, Temurin Java 25, and Ghidriff revision `4f5d895fcbb1eacd65efd81145922c15bb7e741d`. This is the tested combination, rather than a claim that every newer or older combination works.

### Fully offline backend ZIP (optional)

The desktop now supports **Setup → Install offline backend ZIP…**. Select a preassembled, licensed, compatible PatchTrace offline runtime ZIP from local storage, optionally supply its independently trusted SHA-256, review the installer confirmation, and install without downloads, elevation, or changes to global Python/Java settings. Installed Python, Ghidra, and private JDK paths automatically populate Setup after success. Use **Diagnose dependencies** and **Save setup** before running a real comparison. Installation is atomic; cancelled or invalid packages do not replace existing runtimes.

**Availability:** an official complete prebuilt runtime bundle has **not yet been produced or validated**. The ZIP consumer and producer work on synthetic fixtures, but the actual relocatable Python/Ghidriff/Ghidra/JDK payload and disconnected Windows acceptance are still release gates. Without an approved complete bundle, use the manual installation described below. See [offline runtime guide](docs/offline-backend.md) and [installer specification](docs/specs/offline-backend-installer.md).

### Windows setup

1. Install Python 3.12 with the Windows `py` launcher and install Git with `git` available on PATH. Git is needed for the pinned source installation below.
2. Install a compatible JDK. The verified fixture used Temurin Java 25. Configure `JAVA_HOME` to its installation directory and make its `bin` directory available on PATH. Check `java -version` in a new PowerShell window.
3. Download [Ghidra 12.0.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.0.4_build) and unpack the release archive. Select the actual `ghidra_12.0.4_PUBLIC` installation directory, containing `Ghidra`, `support`, and its application files, rather than the ZIP or its parent directory. The release ZIP name includes a date; the unpacked installation directory does not.
4. Create a dedicated Python environment and install the inspected Ghidriff revision:

```powershell
py -3.12 -m venv "$env:LOCALAPPDATA\PatchTrace-backend"
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m pip install --upgrade pip
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m pip install "ghidriff @ git+https://github.com/clearbluejar/ghidriff.git@4f5d895fcbb1eacd65efd81145922c15bb7e741d"
```

5. Check the backend from PowerShell, replacing the Ghidra path with your actual installation:

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_12.0.4_PUBLIC'
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m ghidriff --help
```

6. Restart PatchTrace after changing system Java settings so it inherits the new environment. Click **Setup**. PatchTrace now checks common local installation locations and prefills Python and Ghidra paths only when exactly one candidate of each type is found. Use **Find existing installations** to rescan, or Browse if more than one is found. Detection does not install or run other programs. Then verify the fields:

| Setup field | Value or purpose |
|---|---|
| External Python executable | The full path to `PatchTrace-backend\Scripts\python.exe`; never `PatchTrace.exe`. |
| Ghidra installation directory | The unpacked Ghidra root, for example `C:\Tools\ghidra_12.0.4_PUBLIC`. |
| Comparison timeout (seconds) | Default 3,600; increase for a large comparison if necessary. Allowed range: 10–86,400. |
| Code font size (points) | Default 11; allowed range: 8–28. |
| Interpretation context budget (characters) | Default 24,000; controls evidence selection for AI context, not a provider's token limit. |
| Synchronize code scrolling | Initial preference for the paired code panes. |

7. **Ghidriff symbol-server lookups** are disabled by default to avoid automatic online symbol retrieval. Check **Allow Ghidriff symbol-server lookups (may access the Internet)** only when intentionally enabling this Ghidriff feature. Disabling it can reduce function names and matching information; it is not a whole-system network isolation mechanism. This choice is recorded with every analysis run.

8. Click **Diagnose dependencies**, read the results, then **Save setup**. Diagnosis checks paths, installed backend versions, and Java availability. A successful diagnosis is not a full native comparison test or proof of JDK compatibility.

The GUI passes its configured Ghidra directory to the backend. The temporary `GHIDRA_INSTALL_DIR` assignment above is for the command-line check; it does not permanently configure future shells. See [Windows setup](docs/windows.md) for the packaging and clean-machine test procedure.

## Compare your own binaries

### Create a project

1. Click **New** or press **Ctrl+N**.
2. Enter a project name.
3. Choose the **Older PE x64** and **Newer PE x64** files explicitly. You can browse or drop a local file into its corresponding field. PatchTrace does not infer chronological order from filenames or dates.
4. Choose an absent or empty **New project directory**. The directory picker proposes a `patchtrace-project` child; edit the path if you want a different name.
5. Use **Swap older and newer** in the dialog if the inputs are reversed, then **Create project**.

Creation validates the files, computes their hashes, and stores project-owned copies. It preserves the originals. Target binaries and drivers are statically analyzed; PatchTrace does not launch them, load them as drivers, or install them.

### Run a native comparison

1. Configure the backend in Setup.
2. Click **Run comparison** or press **F5**.
3. Follow the job status, elapsed time, and diagnostic log at the bottom. Progress may be indeterminate because the backend does not always supply a measurable total.
4. When the job completes, select a function match and inspect the older/newer code. A successful identical comparison can legitimately have no changed functions.

Comparison runs Ghidriff in a supervised external process, then validates and normalizes its JSON. Analysis and import work run in a background worker; the GUI commits successful results to the project. Failed, timed-out, invalid, or cancelled attempts preserve prior committed results and retain diagnostic information. **Cancel job** or **Esc** requests cancellation; wait for the terminal job status before starting another operation.

### Import a comparison made elsewhere

1. Create or open a project for the exact binary pair used by Ghidriff.
2. Choose **Import JSON** and select the raw Ghidriff comparison JSON, typically in its output `json` directory with a `.ghidriff.json` name.
3. Wait for validation and import to complete.

Import requires matching artifact identities and orientation. Renaming a file is not sufficient to make an unrelated comparison belong to your project. HTML/Markdown reports, arbitrary JSON, and a PatchTrace exported report are not interchangeable with the raw Ghidriff import format. Imports made with incompatible upstream output contracts can be rejected; the inspected Ghidriff revision above is the integration baseline.

## Workspace and GUI controls

The resizable workspace has function matches on the left, paired code in the center, findings and analyst review on the right, and job diagnostics below. Drag the pane dividers to allocate space. Window size, splitter positions, code font, scrolling preference, backend paths, and non-secret provider preferences are retained in desktop settings.

### Toolbar, menus, and shortcuts

| Control | Location / shortcut | What it does |
|---|---|---|
| New | Toolbar / Project / Ctrl+N | Creates a project from an explicit older/newer pair. |
| Open | Toolbar / Project / Ctrl+O | Opens the directory containing `project.sqlite3` and its companion files. |
| Sample | Toolbar / Project | Creates and opens the synthetic exercise project. |
| Save | Project / Ctrl+S | Saves the current project snapshot. Review actions also persist through the project service. |
| Import JSON | Toolbar / Project | Imports validated raw Ghidriff output for the current pair. |
| Run comparison | Toolbar / Analysis / F5 | Starts the configured external analysis backend. |
| Cancel job | Toolbar / Analysis / Esc | Requests cancellation of the active background operation. |
| Interpret selection | Toolbar / Analysis / Ctrl+I | Builds a context for selected matches and opens a preview before any AI request. |
| Export | Toolbar / Project / Ctrl+E | Opens report options and exact output preview. |
| Setup | Toolbar / Analysis | Configures analysis paths, timeout, code font, context budget, and scrolling; runs dependency diagnosis. |
| Swap orientation | Project | Reverses an existing project's older/newer sides after confirmation; invalidates prior interpretation context. |
| Back up project… | Project | Creates a new full project backup under a chosen parent directory. |
| Undo latest match correction | Project | Restores the latest eligible manual match override; this is not a general undo for all edits. |
| Recent projects | Project | Reopens a previously used project directory. |
| Workflow and dependencies | Help / F1 | Displays the in-app workflow and dependency guide. |

Controls that require a project, selected match, finding, evidence, or idle worker are enabled only when that prerequisite is present. During a job, operations that could replace or modify its project are restricted.

### Function navigation and paired code

| Control | How to use it |
|---|---|
| Search names or addresses | Type part of a function name or address to narrow the match list. |
| Category filter | Select modified, added, removed, ambiguous, split, merged, unmatched, or unchanged. These describe relationships, not vulnerability severity. The engine output determines which records are available; the list is not necessarily an enumeration of every unchanged function. |
| Review filter | Narrow the list by unreviewed, accepted, rejected, or needs-review. |
| Manual corrections only | Shows relationships you have overridden. |
| Matches with findings only | Shows matches associated with interpretation findings. |
| Function list | Select one match for code review. Use Ctrl or Shift selection for multiple matches to interpret together. Hover a row for run/match-quality details. |
| Match review selector | Changes the current match's analyst review status immediately. |
| Correct match… | Opens exact function selection and relationship correction. |
| Decompiled code / Assembly / Metadata | Chooses the displayed representation for both sides. Unavailable representations are labeled; assembly is never fabricated from an upstream instruction hash. |
| Older / Newer headers | Identify the artifacts; hover for full names, hashes, and sizes. |
| Sync scroll | Synchronizes vertical scrolling between the aligned panes. |
| Previous diff / Next diff | Moves to a changed hunk; shortcuts Alt+Up / Alt+Down. |
| Changed-hunk selector | Jumps directly to a listed insertion, deletion, or replacement region. |
| Copy | Copies that side's representation with project, artifact hash, run, match, and function provenance. |

Alignment inserts visual gaps when line counts differ. Decompiled lines are not original source lines, and an address or equal line number does not prove two functions correspond. Very large text uses a bounded alignment fallback; the strategy is disclosed in the match display tooltip. The viewer caps displayed text at 200,000 characters to remain responsive; the stored record can contain more text.

### Findings and analyst review

Search findings by text and filter by review status or **Current & stale**, **Current only**, and **Stale only**. Select a finding to read its summary, proposed fix purpose/category, hypothesis, model confidence label, preconditions, unknowns, proposed verification, alternatives, and any proposed CWE with rationale.

Select a **Support**, **Counterevidence**, or alternative evidence entry to navigate to its side and exact supplied line range. **Bookmark selected evidence** stores an analyst annotation. Set **Finding review status**, write an independent **Analyst conclusion**, and click **Save finding review**. For a separate note, choose **Note on selected match** or **Note on selected finding**, enter text, and click **Save note**.

**Inspect interpretation responses…** displays retained response text and interpretation attempt status, model, errors, and context digest. It is useful when a provider returned malformed or rejected output. Raw responses are displayed as plain text rather than executed or rendered as active content.

## Correct matches and record your review

Ghidriff proposes function relationships. PatchTrace lets you record a different analyst interpretation without rewriting the original backend output.

1. Select the match to correct and click **Correct match…**.
2. Check the exact existing older and newer function records involved. Matching is confined to the relevant analysis run; a function from another run cannot be reused in the relationship.
3. Choose the relationship and provide a required reason. For **added**, select only newer records; for **removed**, only older records. Use **split** or **merged** with the corresponding multiple-function relationship, or **ambiguous/unmatched** when an association remains unresolved.
4. Click **Save correction**. Other relationships using those functions are adjusted; unused remainders become unmatched. The correction retains its reason and prior relationships for provenance.
5. Use **Project → Undo latest match correction** to restore the latest current eligible override if necessary.

Review status belongs to your decision: **unreviewed** means no decision, **accepted** means you accept the match or finding, **rejected** records disagreement, and **needs-review** marks unresolved work. Match review and finding review are separate. Accepting a match does not automatically accept a finding, and accepting a model finding does not independently validate its conclusion.

A new comparison/import, manual relationship correction, correction undo, or orientation swap can invalidate prior interpretations and mark findings/annotations **stale**. Historical material is retained with its original context; stale citations are not redirected into a different current run. Reinterpret the current selection when you need a current hypothesis.

## Rank changes, feature flags and CVE context

After a comparison, **Analysis → Rank changes** (**Ctrl+R**) runs deterministic detectors over the changed hunks of each 1:1 match and orders the list by an integer *attention* score. Change the order back with the ordering selector above the function list. Each ranked row shows `[score]`; `[ — ]` means the evidence a detector needed (for example decompiled code on both sides) was unavailable, which is not the same as "nothing changed". **CHANGE SIGNALS** lists the detector, confidence and exact lines for the selected match; select one to highlight those lines.

| Detector | Weight | What it looks for in decompiled text |
|---|---:|---|
| BND | 30 | New bound comparison whose variable is used as an index, pointer offset or copy/alloc size nearby |
| INT | 22 | Comparison strictness or cast change on the same operands |
| OVF | 28 | New overflow guard or checked-arithmetic call feeding a size |
| VAL | 20 | New probe/validation call, or a newly checked return value |
| ERR | 12 | New predicate-controlled early error return |
| SIZE | 24 | Changed size argument at the same call position |
| WIL | 12 | Changed code enclosed by a `Feature_<id>` gate that was introduced, removed or changed |
| SCRUB | 34 | Zeroing/masking of an object before it is copied out |

Signals on the same edited hunk count as one group: score = `(min(80, Σ groups) × 100 + 40) // 80`, where each group adds its strongest adjusted weight plus a quarter of the second (≤ 40). Confidence multipliers are strong 100 %, moderate 70 %, weak 35 %. The arithmetic is exact integer math (SPEC-07 §6). Detectors work on decompiled text without typed IR, so they are deliberately conservative and their known false-positive/negative classes are documented in the source. **An attention score prioritizes research; it is not a vulnerability verdict, exploitability estimate or CVE match.** Results are stored in the project and marked stale after a new run or manual match correction.

Exports include the same ranking values when a current ranking exists.

### Command line

The same executable runs headless commands without opening the desktop (no Qt is loaded):

```text
PatchTrace rank PROJECT_DIR [--json] [--limit N] [--weights weights.json] [--disable DETECTOR] [--dry-run] [--cache-dir DIR]
PatchTrace flags PROJECT_DIR [--feature-id N]... [--json]
PatchTrace correlate PROJECT_DIR --cve CVE-YYYY-NNNN [--snapshot saved.json] [--json]
PatchTrace correlate PROJECT_DIR --cve CVE-YYYY-NNNN --fetch --consent-providers nvd,msrc [--api-key-env NVD_KEY] [--save-snapshot out.json]
PatchTrace cache {status,verify,prune} --cache-dir DIR [--target-bytes N] [--json]
```

`--json` prints exactly one JSON document on stdout; progress and warnings go to stderr. Exit codes: 0 success, 2 invalid arguments/configuration/environment, 3 runtime failure, 4 legitimate no results, 5 cancelled. A weights file is a JSON object of whole-number weights 0–100 for the detector IDs above.

`flags` lists WIL `Feature_<id>` transitions. Enclosure is a lexical heuristic (no control-flow graph); adjacent references are context only and never score.

`correlate` reorders by CVE context without changing base scores. It works offline from a saved snapshot. **`--fetch` contacts NVD and/or MSRC only with matching `--consent-providers`, and sends only the CVE ID** (plus an NVD API key header if you name an environment variable holding it). No binary, code, path or note leaves the machine. The exact request URLs are printed to stderr first. Context contributions (identifier overlap, CWE aligned with an existing moderate/strong signal, feature ID, product module) are capped at +30 and each cites the binary evidence it relies on; descriptions never prove code behavior.

The optional global cache (`--cache-dir`) stores derived detector results keyed by content hashes; a hit returns identical results. It never stores analyst notes and can be deleted at any time.

## Optional AI interpretation

Comparison, manual review, notes, backups, and exports work without AI. Interpretation operates on the selected match records and bounded supplied context; it does not inspect arbitrary files or autonomously investigate the rest of your machine.

### Choose a provider

| Provider choice | Setup and endpoint |
|---|---|
| `ollama` | Install and run Ollama separately, obtain a model, and enter its exact installed model name. Default endpoint: `http://127.0.0.1:11434`. PatchTrace accepts loopback hosts only for this provider and calls `/api/chat`. |
| `openai` | Use an HTTPS OpenAI-compatible Chat Completions service. Enter its base URL, for example `https://api.openai.com/v1`, exact model name, and required API key. PatchTrace calls `/chat/completions` and requests JSON output. This label describes the protocol; compatibility with every service/model is not guaranteed. |

A full endpoint ending in `/api/chat` or `/chat/completions` is also accepted. Native Anthropic Messages API, remote Ollama hosts, HTTP remote endpoints, endpoint redirects, and environment-proxy forwarding are not supported by the current transports. A local model does not need a PatchTrace API key. For remote providers, enter the key in the preview dialog; credentials are kept in memory for that request and never saved in desktop settings or project records. Provider/model/endpoint preferences are retained, so check them before each send.

### Preview, send, and review

1. Select one or more function matches in the left list, then **Interpret selection** or **Ctrl+I**.
2. Read **Exact context**, **Exact system prompt**, and **Omitted / unavailable**. The preview shows selected match count, evidence records, digest, and an approximate token estimate. Supplied material can include related functions when uniquely resolvable; omitted or unavailable context is disclosed.
3. Enter the provider, endpoint, model, and optional API key. Use Setup's character budget to adjust context size, then reopen the preview to regenerate it. Character count/token estimate is not a guarantee that a model's context window will fit.
4. Click **Send context** to issue the request. Cancelling the preview sends nothing. Sending to a remote endpoint transmits the displayed context and system prompt to that service.
5. Review returned findings, click their evidence, examine counterevidence and alternatives, and record your independent conclusion.

Responses must satisfy PatchTrace's structured schema and cite evidence belonging to the selected context and appropriate match. Invalid/unknown citations or malformed output produce a failed attempt with retained response information rather than accepted findings. Valid schema and citations establish traceability, not factual correctness. Verification suggestions are text for the analyst; PatchTrace never executes model-suggested commands.

Cancellation is cooperative. An active network read can remain blocked until its 120-second timeout, and cancellation cannot recall context already transmitted. Live local/remote provider acceptance remains an open beta check; mocked transport and validation tests have passed.

## Export and share results

1. Choose **Export** or **Ctrl+E**.
2. Select `md` (Markdown), `html`, or `json` and the destination file.
3. Decide whether to **Include function code**. It is off by default. **Include analyst notes** is on by default.
4. To limit the finding section, select findings in the right list before opening Export and enable **Only selected findings**. This scopes findings, not a complete anonymization of project/comparison metadata.
5. Read the exact preview, then click **Write report**.

Reports are built from persisted project data and include relevant comparison/finding provenance and review information. Absolute source paths are redacted; raw provider responses, API keys, and complete context payloads are excluded. HTML reports are self-contained and use escaped content with no scripts. Export is not a full project backup or an importable raw Ghidriff comparison. Inspect notes and optional code for information you do not intend to share.

## Projects, backups, and data handling

Each project owns a SQLite snapshot/history database (`project.sqlite3`), copied inputs, raw comparison output, and run data. Hashes connect artifacts, functions, contexts, and evidence to their recorded origin. Retained interpretation context and raw responses can contain decompiled code even if your exported report excludes code. Project storage is local and is not encrypted by PatchTrace.

Review actions, corrections, notes, and completed result imports are persisted through the project service. Use **Save** for an explicit snapshot and **Open** to reopen the project directory. The application uses a writer lock to prevent concurrent editing of the same project; close it in the other instance before reopening. Do not manually remove a live project's lock or edit immutable input/run files to bypass validation.

**Project → Back up project…** creates a complete new copy, including a SQLite backup and companion files, under a chosen parent. The destination must be new and outside the current project. Use this operation rather than copying only the database. Before a future schema migration, retain a full backup. Versioned record schemas are strict; unsupported future versions fail clearly rather than silently discarding fields.

Backend processes are supervised with a Windows Job Object or POSIX process group. Logs and output sizes are bounded, and failed output is quarantined. This lifecycle management is not an operating-system sandbox. External runtimes perform the disassembly/decompilation; neither target binary is deliberately executed by PatchTrace.

## How PatchTrace differs from the upstream programs

The two original projects are [Ghidriff](https://github.com/clearbluejar/ghidriff) and [Diffalayze](https://github.com/SySS-Research/diffalayze). **PatchTrace is a new application integrating Ghidriff's CLI and drawing on Diffalayze's workflow ideas. It is not a merged fork of their source trees.** Its desktop, project/evidence contracts, review service, provider transports, and report rendering are new PatchTrace modules. The pinned Ghidriff engine is installed separately; its matching algorithms are not rewritten by the GUI.

The comparison below refers to the inspected upstream revisions, not claims about all subsequent upstream releases:

- Ghidriff: `4f5d895fcbb1eacd65efd81145922c15bb7e741d`.
- Diffalayze: `7cab0aae254432f7786d8a450b400f5cc4433865`.

| Area | Original programs at inspected revisions | PatchTrace implementation |
|---|---|---|
| Core comparison | Ghidriff uses Ghidra/PyGhidra for function matching and static diff output. Diffalayze orchestrates Ghidriff in Docker. | Retains Ghidriff as the external engine; adds supervised Windows process handling, configured runtimes, output validation, and normalization. Docker is unnecessary for the supported path. |
| User interface | Ghidriff is a CLI with JSON/Markdown output and optional side-by-side HTML. Diffalayze is a CLI orchestration/LLM toolkit. Ghidriff already provides side-by-side output. | Adds a native Qt desktop combining function search/filtering, paired read-only views, changed-hunk navigation, findings, clickable evidence, notes, setup, and export preview in one persistent workspace. |
| Inputs and scope | Ghidriff handles formats Ghidra supports. Diffalayze's target scripts can fetch binaries and automate target workflows. | Initial input contract is analyst-selected local PE AMD64 pairs with explicit orientation, validation, hashing, and stored copies. Automatic Winbindex downloads, target polling, and broad format support are not carried over. |
| Storage and provenance | Ghidriff writes comparison artifacts; Diffalayze archives timestamped runs. | Adds SQLite snapshots/history, writer locking, full project backups, versioned records, immutable raw artifacts, and artifact/run/function/context/evidence identities. |
| Function review | Ghidriff supplies engine match evidence and diff categories. | Adds separate analyst review states, exact manual relationship correction, split/merge handling, required correction reasons, and undo of the latest eligible correction. Corrections do not train or modify the upstream engine. |
| AI workflow | Diffalayze's documented stages are per-document analysis, final synthesis, and severity evaluation using its prompts/Pocketflow pipeline. | Implements a separate bounded, selection-based structured interpretation path with exact payload/prompt preview, evidence validation, alternatives, unknowns, and analyst conclusions. The original three-stage batch pipeline is not imported wholesale. |
| AI providers | Diffalayze includes Ollama, OpenAI, and native Anthropic helpers. | Currently offers loopback Ollama and HTTPS OpenAI-compatible Chat Completions, with request-only credentials. Native Anthropic transport is not implemented. |
| Automated actions | Diffalayze can invoke a custom command when a severity threshold is met. | No severity-triggered shell commands or model-directed execution. Review and verification recommendations remain analyst-controlled text. |
| Reports | Ghidriff creates diff reports; Diffalayze creates LLM analysis reports and structured evaluations. | Adds previewed JSON/Markdown/self-contained HTML exports, code/notes options, selected finding scope, path redaction, and explicit review/provenance information. |
| Desktop distribution | Upstream projects provide their own runtime/CLI installation workflows. | Adds a Windows standalone GUI ZIP with Python/Qt, curated desktop plugins, notices, inventory, checksum, and frozen startup validation. Analysis runtimes remain separate. |

The new GUI controls listed above belong to PatchTrace. They do not add menus to Ghidra, change Ghidriff's HTML viewer, or port Diffalayze's original command-line flags into an identical graphical interface.

Ghidriff remains GPL-3.0; Diffalayze is MIT-licensed. PatchTrace's new application code is MIT-licensed, with dependency/upstream notices kept separately. An external-process integration does not relicense either upstream project. See [reuse matrix](docs/reuse-matrix.md), [upstream research](docs/research.md), [notices](docs/notices.md), and the [package audit](docs/package-audit.md) for exact source boundaries and attribution. Research documents include planning-time assessments; the current implementation and QA records describe what has since been built and verified.

## Troubleshooting

| Symptom | Check / next step |
|---|---|
| Executable does not start | Extract the complete ZIP and preserve `_internal`; check that you downloaded the x64 package for the supported desktop target. |
| Unsupported input | Check that both files are real PE AMD64 binaries, not x86/ARM64, archives, shortcuts, or text with a renamed extension. |
| Project creation refuses the destination | Choose an absent/empty directory; use Open for an existing project. |
| Project is locked | Close it in the other PatchTrace instance, then retry. Check folder permissions if no other instance owns it. |
| Diagnose cannot find Ghidriff/PyGhidra | Select the dedicated backend `python.exe` and install its dependencies in that environment, rather than the GUI or another interpreter. |
| Ghidra or Java failure | Select the unpacked Ghidra root, check `java -version`/`JAVA_HOME`, restart PatchTrace after environment changes, and inspect the job log. A path check alone does not prove compatible versions. |
| Comparison times out or fails | Read the retained error/log, check runtime compatibility, and adjust the timeout for a large input. Retry starts a new attempt; prior results remain. |
| Import rejected | Use raw Ghidriff JSON generated for the exact pair/orientation and supported contract. Do not substitute a rendered report or an unrelated binary version. |
| Empty function list | Clear search/category/review/manual/finding filters. An identical comparison or output with no changed functions can be legitimate. |
| Assembly unavailable | The imported output may not retain actual instruction text. Switch to decompiled code/metadata; a minimized instruction hash cannot supply assembly. |
| Interpret is disabled | Open a project, select match records, and wait for the active worker to finish. |
| Provider request fails | Check endpoint, exact model, key, loopback/HTTPS rules, and support for JSON Chat Completions or Ollama JSON chat. Inspect retained response/error text. |
| Context too large or heavily omitted | Select fewer matches or adjust the character budget in Setup, regenerate the preview, and review omitted/unavailable entries. |
| Finding is stale / citation will not jump | Its source context predates a project change. Review the retained historical context and generate a new interpretation for current matches. |
| Notes or code missing from a report | Check Include analyst notes / Include function code and finding selection, then regenerate the preview. |

For a reproducible issue, include the application/release version, Windows version, configured backend versions, operation performed, relevant sanitized error/log, and whether the sample reproduces it. Review project data and source code before attaching them to a public issue.

## Development, verification, and architecture

Python 3.12+ is required for development. From the repository root:

```powershell
py -3.12 -m pip install -e '.[dev]'
py -3.12 -m patchtrace
$env:QT_QPA_PLATFORM = 'offscreen'
py -3.12 -m pytest -q
py -3.12 -m ruff check src tests tools
py -3.12 tools/generate_schemas.py
Remove-Item Env:QT_QPA_PLATFORM
```

On Linux, install Qt's required system libraries before launching or running Qt tests. Then use `python -m pip install -e '.[dev]'`, `python -m patchtrace`, and `QT_QPA_PLATFORM=offscreen python -m pytest -q`. Linux offscreen QA does not establish a supported standalone Linux distribution.

Build the Windows package **on Windows**:

```powershell
py -3.12 tools/build_windows.py
```

The builder creates an onedir executable, collects runtime/help/license files, checks required notices and unwanted optional Qt components, records dependency/file inventories, runs the frozen sample self-test, and creates `dist/PatchTrace-0.1.0-windows-x64.zip` plus its checksum. PyInstaller cannot cross-compile the Windows interpreter from Linux.

The published beta passed 93 Windows tests, 91 Linux tests with two Windows-only skips, Ruff, frozen executable startup, a real native Ghidriff known bounds-check fixture, and ZIP checksum/content inspection. These checks verify implementation paths; the single fixture and synthetic sample do not establish general matching accuracy. Live AI-provider acceptance, hands-on clean Windows GUI testing, held-out matching benchmarks, and resource targets remain open. Call-graph visualization, runtime debugging, automatic reproduction, automatic binary acquisition, extra input formats, and the original Diffalayze batch/trigger features are not implemented in this beta.

| Documentation | Purpose |
|---|---|
| [Module index](docs/modules.md) | Module responsibilities, boundaries, dependencies, and test seams. |
| [Architecture](docs/specs/architecture.md) | Runtime, project, ingestion, process, and alignment contracts. |
| [Schemas](docs/specs/schemas.md) | Versioned record contracts and generated schema/example links. |
| [UI specification](docs/specs/ui.md) | Desktop workflow specification; this README follows the implemented controls. |
| [Specification completeness audit](docs/specs/completeness-audit.md) | Coverage and explicit beta boundaries. |
| [QA record](docs/qa.md) | Repaired audit defects, test evidence, and unresolved acceptance checks. |
| [Package audit](docs/package-audit.md) | Frozen runtime contents and dependency notice evidence. |
| [Delivery tracker](tasks/todo.md) | Implemented milestones and remaining live acceptance. |

UI code stays separate from ingestion, backend lifecycle, persistence, evidence, providers, and reporting. See [AGENTS.md](AGENTS.md) for contributor rules. When adding a substantial module, update the module index and applicable specification before implementing it.
