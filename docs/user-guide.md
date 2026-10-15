# User guide

Task-oriented. Terms are defined in [concepts.md](concepts.md); setup is in [install.md](install.md); the first run is in [RUN.md](RUN.md). Commands below were checked against `--help` of this build; anything not built yet is marked "planned".

## Compare two builds

1. **New**: choose the older and newer PE x64 file yourself, and a new project folder.
2. **Setup** once: backend Python, Ghidra root, timeout (default 3600 s, range 10 to 86400). **Diagnose dependencies** checks paths and versions. It does not prove a full comparison works.
3. **Run comparison** (F5). Failed, timed-out or cancelled attempts keep earlier results and a log.
4. Filter the function list by name, category (modified, added, removed, ambiguous, split, merged, unmatched, unchanged) or review state.
5. Use **Rank changes** (Ctrl+R) and sort by attention to read the likely security-relevant changes first.

Alternatives: **Import JSON** for a Ghidriff result produced elsewhere for the same pair and orientation; **Project > Download from Microsoft symbol server...** to fetch two builds by file name (consent required, see Privacy); `series create` for 3 to 8 ordered builds, where a chain across builds is a hypothesis unless a direct first-to-last pair confirms it.

If a pairing is wrong, select it and use **Correct match...**, pick the relationship and give a reason. **Project > Undo latest match correction** restores the previous state. A correction can mark earlier findings stale.

## Read evidence

- **Code panes**: older left, newer right, aligned with gaps where line counts differ. Equal line numbers or addresses do not prove two functions correspond. Decompiled lines are not source lines. Display is capped at 200,000 characters per side.
- **Findings**: each shows hypothesis, unknowns, alternatives and supporting or counter evidence. Clicking an evidence entry jumps to the exact line range.
- **Engine evidence dock** (right side): per-match verdict from the engines you ran. `corroborated` means engines agree; `contested` means an engine pairs the same function differently and needs your review; `single-engine` and `insufficient` mean not enough to judge. Missing engines are listed as unknown. Hover any control for its tooltip.
- **Second opinions**: `secondary import-bindiff PROJECT RESULT.BinDiff` stores a genuine BinDiff result; `secondary rzdiff PROJECT` runs rz-diff if installed; `secondary reconcile PROJECT` compares them with Ghidriff. They never change the Ghidriff result.
- **Unified result (experimental)**: `unified run PROJECT`, then `unified show PROJECT` and `unified explain PROJECT --row ROW_ID`. It fuses stored engine outputs into ordinal rows (no numbers, no probabilities) and shows atoms, contests and provenance. `unified status PROJECT` tells you if the result is stale.
- **Static tool evidence**: `intel-tools probe | run | delta` use capa, FLOSS and Detect It Easy on each artifact. They read files and never run them; `delta` compares stored evidence without running any tool.
- **PE overview**: **File overview** shows sections, headers and an Authenticode probe. The probe does not establish trust.

Never read a high score or a corroborated verdict as "this is the vulnerable function".

## KB and CVE context

- **Rank with CVE context**: `correlate PROJECT --cve CVE-YYYY-NNNN --snapshot saved.json` reranks offline from a saved snapshot. The base ranking is unchanged.
- **Fetch (online, consent)**: add `--fetch --consent-providers nvd,msrc --providers nvd,msrc`. Only the CVE ID is sent (plus an NVD key if you name an environment variable with `--api-key-env`). `--save-snapshot out.json` keeps the result for later offline use.
- **Advisories (CSAF)**: `intelligence import PROJECT FILE --cve CVE-...` validates and stores a local CSAF 2.0 file, nothing sent. `intelligence fetch PROJECT --cve CVE-... --consent-hosts msrc.microsoft.com` downloads from MSRC; add `--offline` to read only the cache. `intelligence explain PROJECT --cve CVE-...` is offline and restates vendor claims with explicit unknowns. A file name never maps to a product; use `--older-product` and `--newer-product` to state your own assertion.
- **KB number search** (`patchtrace patch ...` and a Patch Search panel): planned. The specifications exist (`docs/specs/kb-patch-search-ui-cli-contract.md`), but the verb is not in this build.

An advisory says what the vendor claims. It does not show that a function contains or fixes the issue.

## Exports

**Export** (Ctrl+E) writes `md`, `html` or `json` after showing the exact preview.

| Option | Default | Effect |
|---|---|---|
| Include function code | off | Adds decompiled code to the report |
| Include analyst notes | on | Adds your notes |
| Only selected findings | off | Limits the findings section; not an anonymisation of project metadata |

Reports carry provenance and the same ranking values as the app. Absolute source paths are redacted. Raw provider responses, API keys and full context payloads are excluded. HTML is self-contained with escaped content and no scripts. An export is not a backup and cannot be re-imported; use **Back up project...** for that. `intelligence explain --export FILE` writes the advisory report (suffix picks the format).

## Privacy and consent

| Operation | Needs | Sends |
|---|---|---|
| Open, compare, rank, export, review | nothing | nothing |
| Winbindex search and symbol-server download | `--consent-hosts` or the dialog's listed hosts | File name, then build identity in the URL |
| CVE fetch (NVD, MSRC) | `--fetch` and `--consent-providers` | CVE ID (and your NVD key header if named) |
| CSAF fetch | `--consent-hosts msrc.microsoft.com` | CVE-matching index requests |
| AI interpretation | You click **Send context** in the preview | The displayed context and prompt to the endpoint you set |
| Ghidriff symbol-server lookup | Setup checkbox, off by default | Chosen by Ghidra; recorded with every run |

Rules: binaries and project paths are never uploaded; a network call needs its own consent for the exact host; API keys are session-only and not written to settings or reports; no telemetry, analytics, crash reporting or update check was found in the code (SPEC-42 records how this was checked). AI is optional: Ollama on loopback, or an HTTPS OpenAI-compatible endpoint. The preview shows exactly what will be sent and cancelling sends nothing. A single product-wide offline switch does not exist yet (listed as a gap in SPEC-42), but nothing runs online without the consent flags above. Full inventory: [specs/network-egress-privacy.md](specs/network-egress-privacy.md).

## Troubleshooting

| Symptom | Next step |
|---|---|
| App does not start | Extract the whole zip, keep `_internal`. On Linux install the Qt host libraries (see install.md) |
| Unsupported input | Both files must be real PE AMD64; not x86, ARM64, archives or renamed text |
| Destination refused | Choose a new or empty folder, or use Open for an existing project |
| Project locked | Close it in the other instance; check folder permissions |
| Diagnose cannot find Ghidriff | Point Setup at the backend `python.exe`, not `PatchTrace.exe` |
| Ghidra or Java failure | Select the unpacked Ghidra root, check `java -version`, restart PatchTrace after changing Java settings, read the job log |
| Comparison times out | Raise the timeout in Setup; a retry is a new attempt and earlier results stay |
| Import rejected | Use raw Ghidriff JSON for the exact pair and orientation, not a rendered report |
| Empty function list | Clear filters; an identical pair legitimately has no changed functions |
| Rank shows `[ — ]` | A detector lacked needed evidence (for example no decompiled code); that is unknown, not zero |
| Assembly unavailable | The import did not keep instruction text; it is never fabricated |
| Finding is stale | The project changed after it was made; reinterpret the current selection |
| `correlate --fetch` exits 2 | Consent flags missing or provider lists do not match |
| `backend status` reports no bundle | You run a lite package; use external tools or import a backend ZIP |
| Exit code 4 | A legitimate empty result, not a failure |
| Report lacks code or notes | Check the Export options and regenerate the preview |

## FAQ

**Does it run the binaries I give it?** No. Never. Files are read and analysed statically by Ghidra and the tools you configure. Drivers are not loaded or installed.

**Does it upload my files?** No. Only the consented operations above send anything, and none sends binary content.

**Does it work offline?** Yes, by default. Obtain tools and data beforehand (see install.md).

**Does a high attention score mean a vulnerability?** No. It orders your reading. See concepts.md.

**Why is there no confidence percentage?** No calibrated model has passed its pre-registered gates, so showing one would be false precision.

**The engines disagree. Who is right?** Neither is voted down; the row is `contested` for you to review. A one-sided observation is absence of evidence, not disagreement.

**Is the full zero-download package available?** Not yet; see install.md for the state.

**Can it handle ELF, ARM64 or 32-bit?** Not in the supported input contract.

**Where do I report a bug?** On the repository issue tracker. Include version, OS, backend versions, the steps and a sanitised log. Review project data before attaching it.
