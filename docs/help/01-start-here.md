# Start here

PatchTrace compares an explicitly chosen older and newer Windows binary. Use it to inspect changed functions, examine the evidence behind a proposed relationship, and record your conclusions.

The documented desktop target is Windows 11 x64. The initial input contract accepts PE AMD64 executables, DLLs, and drivers. A filename extension does not establish the file format or architecture. PatchTrace validates the input headers.

Choose your starting point:

| Your starting material | Start with |
| --- | --- |
| No comparison data | [Explore the synthetic **Sample**](03-explore-the-sample.md) |
| Two versions of one binary | [**New**](04-create-a-comparison-project.md), then [**Run comparison**](05-run-a-comparison.md) |
| An existing PatchTrace project | [**Open** its project directory](10-save-reopen-and-back-up.md) |
| Raw Ghidriff JSON for your exact binary pair | Open the corresponding project, then [**Import JSON**](06-import-ghidriff-results.md) |

The desktop package includes its Python and Qt runtime. Running a native comparison requires a separately configured analysis backend. You can explore the sample, review imported results, and export reports without that backend.

PatchTrace performs static analysis. It does not launch either target binary or install a driver input. External analysis tools run as separate processes.

Keep three questions separate: whether functions correspond, what changed, and whether that change supports your research hypothesis. A matching score, attention score, or generated explanation does not answer all three.

After opening a project:

1. Select a row in **FUNCTION MATCHES**, then [read the older and newer code](08-read-paired-code.md). The **modified** category narrows the list to relationships recorded as changed.
2. [Inspect evidence and its provenance](20-follow-evidence-and-check-provenance.md). Tool output is evidence to review, not an analyst conclusion.
3. [Review or correct a match](09-review-and-correct-matches.md), then [save a note or finding review](19-review-findings-and-record-conclusions.md). These tasks work without an AI provider. [Interpretation](18-preview-and-send-interpretation-context.md) is optional and produces hypotheses to check.
4. [Preview and export a report](47-preview-and-export-reports.md), then [reopen or back up the project](10-save-reopen-and-back-up.md).

For keyboard operation, start with [panel and command navigation](49-keyboard-and-command-navigation.md). For a missing backend, timeout, or empty result, use [Troubleshooting](52-troubleshooting.md).

> UNVERIFIED: availability of newer panels in a particular downloadable release must be checked against that release. Repository implementation records do not establish that every recorded feature is packaged.

Sources: `src/patchtrace/ui.py`; `README.md`; `docs/windows.md`.
