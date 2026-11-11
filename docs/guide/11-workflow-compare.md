# 11. The compare workflow

How to open or create a project, run a comparison (or import one), and read the results. Setup is in [10](10-getting-started.md); evidence and engines are in [12](12-evidence-and-engines.md); panels and shortcuts are in [13](13-panels-and-layout.md).

## Concepts you need first

A **pair** is an older and a newer build of the same PE file. You choose which is which. PatchTrace never infers order from names or dates, and **Swap orientation** is an explicit action that marks earlier interpretations stale. A **match** relates function(s) in the older build to function(s) in the newer one with a category: `modified`, `added`, `removed`, `ambiguous`, `split`, `merged`, `unmatched` or `unchanged` (`models.FunctionMatch`). These describe correspondence, not severity. Definitions: [19](19-glossary.md).

## Open or create a project

| Action | Control | What happens |
|---|---|---|
| New | **New**, Ctrl+N | Wizard: project name, **Older PE x64**, **Newer PE x64**, an absent or empty destination directory. **Swap older and newer** fixes reversed inputs before creation. |
| Open | **Open**, Ctrl+O | Choose the folder that holds `project.sqlite3`. |
| Sample | **Sample** | Creates a new synthetic project (see [10](10-getting-started.md)). |
| Recent projects | Project > Recent projects | Reopens a stored path (paths only are remembered). |
| Download builds | Project > Download from Microsoft symbol server... | Consented acquisition by file name; see below. |

Creation (`ProjectService.create`) validates both files as PE AMD64, hashes them, and stores **read-only, content-addressed copies** as `artifacts/<sha256>.bin`. Originals are untouched. The project directory holds `project.sqlite3`, `artifacts/`, `runs/`, `exports/` and a `.patchtrace.lock` file. One writer at a time: a second instance gets `PT-STORAGE: project is locked by another writer`. If creation fails, no project is published (the copy is staged, then published without replacing).

Acquisition (**built**) lists Winbindex x64 candidates by file name, then downloads two builds you pick, checks size and SHA-256 against Winbindex, holds them in quarantine (headers only, never executed), and creates the two-artifact project. Each host needs your consent; see [17](17-privacy-and-network.md). Headless equivalent: `patchtrace acquire search|fetch` ([16](16-cli-reference.md)). PA30/PA31 delta reconstruction uses the system `msdelta.dll` on Windows only (`acquisition/delta.py`); its native acceptance is open.

## Run a comparison

1. Configure the backend in **Setup** ([10](10-getting-started.md)). **Run comparison** needs a pair, a valid backend and an idle job.
2. Click **Run comparison** or press **F5**. Ghidriff runs as a supervised child process (`jobs.run_process`: absolute executable, no shell, allow-listed environment, timeout, bounded output; Job Object on Windows, process group on POSIX).
3. Watch the job line, elapsed time and the diagnostics log at the bottom. Progress is often indeterminate because the backend gives no totals.
4. **Cancel job** or **Esc** requests cancellation. Wait for the terminal status before starting something else.
5. On success the raw Ghidriff JSON is stored under `runs/<run_id>/`, normalized (`normalization.normalize_ghidriff`) and committed as a new project revision. A failed, timed-out, invalid or cancelled attempt keeps all earlier committed results and a redacted log tail.

The Ghidriff symbol-server lookup is **off** by default (PatchTrace passes `--no-symbols`). The choice is recorded with each run. An identical pair legitimately yields no changed functions.

Optional raw-output cache: a profile with `cache_dir` reuses a previous raw Ghidriff output for identical inputs (SPEC-07 section 13).

### Import a comparison made elsewhere

Create or open a project for the exact pair, click **Import JSON**, choose the raw Ghidriff JSON (usually `*.ghidriff.json`). Import requires matching artifact identities and orientation. HTML, Markdown, arbitrary JSON and PatchTrace's own exports are not accepted. The importer is strict: unknown top-level roots fail closed (`normalization.ROOT_KEYS`).

## Read the results

The window has function matches on the left, paired code in the middle, findings and review on the right, and the job log below. More docks (Engine evidence, Unified, Leads, Files, Series) attach around it ([13](13-panels-and-layout.md)).

**Function matches.** Search by name or address; filter by category and by review state (unreviewed, accepted, rejected, needs-review); toggle manual corrections only and matches with findings only. Ctrl or Shift selects several matches for interpretation.

**Order by attention.** **Rank changes** (Ctrl+R) computes the deterministic `attention/1` score (integer 0 to 100) from eight lexical detectors over the changed decompiled text: BND (bounds check), INT (comparison/cast), OVF (overflow guard), VAL (validation), ERR (early error return), SIZE (size argument), WIL (feature-flag gate), SCRUB (zeroing before copy-out). Choose **Attention score (research priority)** in the order box. Detectors without evidence show `[ — ]`, which means unknown, not zero. Attention is a reading order: it is not exploitability, not a CVE match and not vulnerability confidence. AI output never enters it. Details: [22](../internals/22-engines-and-fusion.md), [concepts](../concepts.md).

**Code panes.** Older left, newer right. The mode box offers Decompiled code, Assembly, Metadata, and raw Hex, Binary and Base64 of the verified original bytes (scope: whole file, or from the function entry; page size 4096 bytes by default, 16 to 65,536). Missing text is labelled, never invented; assembly is not fabricated from an instruction hash. Alignment inserts explicit gaps. Equal line numbers or addresses do not prove two functions correspond. Display is capped at 200,000 characters per side. **Sync scroll**, **Previous diff** / **Next diff** (Alt+Up / Alt+Down), a hunk selector, and **Copy** (copies with project, hash, run, match and function provenance).

**Signals.** The signals list shows the detector hits for the selected match, grouped so one edit is not counted twice.

**Findings and review.** Findings come from optional AI interpretation (Ctrl+I) or the sample. Each lists hypothesis, preconditions, unknowns, alternatives and supporting or counter evidence; an evidence entry jumps to its exact line range. Set the finding review status, write your own conclusion, **Save finding review**. Match review and finding review are independent. A finding is **stale** when the project changed after it was made (for example a match correction or swap); stale evidence shows its raw immutable context and does not jump into current code.

**Correct a wrong pairing.** Select the match, **Correct match...**, pick the exact existing older/newer function records of that run, a relationship and a required reason. The original engine output is preserved; **Project > Undo latest match correction** restores the latest eligible override.

**Optional AI interpretation (Ctrl+I).** Builds the exact context first and opens a preview with the provider, endpoint, model, character budget (default 24,000) and a session-only credential field. Nothing is sent until you press **Send**; Cancel sends nothing. Providers: Ollama on loopback, or an HTTPS OpenAI-compatible endpoint. A response becomes a finding only after strict validation of its citations. See [17](17-privacy-and-network.md), [24](../internals/24-acquisition-and-enrichment.md).

## Export, back up, swap

- **Export** (Ctrl+E): Markdown, HTML (self-contained, escaped, no scripts) or JSON, after an exact preview. Options: include function code (default off), include analyst notes (default on), only selected findings. Absolute source paths, provider responses, keys and full context payloads are excluded. An export is not a backup.
- **Project > Back up project...** writes a full verified copy to a new directory (SQLite backup API plus `artifacts`, `runs`, `exports`, `kb`, `intelligence`). The destination must be new and outside the project.
- **Swap orientation** reverses the sides after confirmation and invalidates prior interpretation context.
- **Save** (Ctrl+S) saves the snapshot; review actions already persist through the service.

## Analysis profiles

A **profile** (`profile/1`, `enrichment/profiles.py`) is shared, non-secret analysis configuration stored as one JSON file (at most 64 KiB) per profile in the desktop profiles directory. It has no field that could hold a credential. Manage profiles in **Setup > Profiles**; select one with `--profile NAME|FILE` on `rank`, `flags` and `correlate`, or by the `analysis/profile` setting (default name `default`).

| Field | Meaning |
|---|---|
| `name` | 1 to 64 characters; portable file-stem characters; Windows reserved names (`con`, `nul`, `com1`...) refused |
| `weights`, `enabled` | detector weights (0 to 100) and which detectors run; at least one must be enabled |
| `feature_ids` | optional list of WIL feature IDs (uint32, at most 256) |
| `symbol_policy` | `disabled` (default) or `online`; recorded with each run |
| `cve_providers` | subset of `nvd`, `msrc` |
| `snapshot_max_age_days` | 1 to 3650, default 30 |
| `cache_dir`, `cache_budget_gib` | opt-in raw-output and derived-stage cache; absolute path; budget 1 to 1024 GiB (default 20) |

A profile on the command line cannot be combined with `--weights`, `--disable` or `--feature-id`; explicit options that the profile also defines are rejected rather than silently merged. Reports record the profile used.

## A typical session, end to end

1. **Setup** once (backend paths, **Diagnose dependencies**, **Save setup**).
2. **New** with the older file as *older*; or **Project > Download from Microsoft symbol server...** for a Windows system file, consenting to each host.
3. **Run comparison** (F5). While it runs, open **Files** to see the structural comparison; it does not need the backend.
4. **Rank changes** (Ctrl+R), order by attention, work down the list. Use **Next diff** and the raw modes where decompiled text is missing.
5. Run second opinions if you have them ([12](12-evidence-and-engines.md)); look at **Contested** rows first.
6. Record your own conclusion on each match or finding you care about; correct pairings that are wrong.
7. Optionally import an advisory and look at leads: `intelligence import`, then `pilot leads PROJECT --cve CVE-...` and the Leads dock.
8. **Export** a report with notes (code off unless you need it), and **Back up project...**.

Everything above except steps 2 (download) and the optional AI step runs without a network connection.

## Next steps from the workflow

Second opinions and fusion ([12](12-evidence-and-engines.md)); a stored ordering of candidate functions against an advisory (`pilot leads`, Leads dock; [16](16-cli-reference.md)); several builds in a row ([14](14-series.md)); structure of the files themselves ([15](15-files-and-pe-overview.md)). Remember: a changed function, a matching score or a model assessment does not establish that a vulnerability exists.
