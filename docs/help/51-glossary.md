# Glossary

Short meanings of the words used across these help pages. Each meaning describes what the term means in PatchTrace. It is not a claim about the code inside a binary.

| Term | Meaning |
|---|---|
| **Advisory context** | The CVE or KB information you attach to a project. It is vendor or public text, kept separate from binary evidence. |
| **Attention** | An ordering score for reading changed functions first. It is not a probability and not a vulnerability score. |
| **BinDiff** | An external comparison tool. PatchTrace reads a `.BinDiff` result or runs it only when you configure and start it. |
| **Calibration** | A measured mapping from a score to observed accuracy. No calibrated model ships in this build, so no confidence percentage is shown. See [36](36-read-calibration-and-confidence-labels.md). |
| **capa** | An external tool that recognizes capabilities by static rules. A capability label is a rule match, not a runtime observation. |
| **Change class** | The reading label for a matched pair: unchanged, cosmetic, material, review, unknown or not applicable. See [37](37-pairing-and-change-classifications.md). |
| **Consent** | A confirmation shown before a network request. It names the exact hosts or endpoints and sends nothing until you answer Yes. See [17](17-network-use-and-consent.md). |
| **Contested** | An engine selects a different endpoint from the reference match. Keep the alternatives visible. |
| **Decompiled text** | Generated C-like text for a function. It is not the original source. |
| **Detect It Easy** | An external identification tool. Its compiler or packer names are tool observations with limits. |
| **Evidence provenance** | The record of where a value came from: the tool, its version, the run and the artifact. Use `Copy provenance` to keep it. |
| **Engine** | A comparison source: Ghidriff (primary), BinDiff, rz-diff, or a manual import. See [21](21-engine-evidence-panel.md). |
| **FLOSS** | An external string-extraction tool. Its emulation mode needs its own explicit step. |
| **Ghidra** | The reverse-engineering framework that Ghidriff drives. It is an external installation. |
| **Ghidriff** | The primary comparison tool. PatchTrace reads its raw JSON output or runs it through the configured backend. |
| **Interpretation** | An optional AI-written explanation of a bounded context. Its preview shows exactly what would be sent. See [18](18-preview-and-send-interpretation-context.md). |
| **KB** | A Microsoft update identifier (for example `KB5099003`). A KB number names an update context, not a proven CVE fix. |
| **KEV** | CISA's Known Exploited Vulnerabilities catalog. Membership is exploitation context about a CVE, not a property of a function. See [30](30-kev-context-panel.md). |
| **Lead** | A place to look, ranked by stored evidence. A lead does not show that a function contains or fixes a CVE. See [31](31-leads-panel.md). |
| **Match** | A pairing of an older function with a newer one. A match is a correspondence claim, not a proof of identical behaviour. |
| **Newer / Older** | The two sides of a comparison. Order is set by you when you create the project. File names and timestamps do not decide it. |
| **Offline backend ZIP** | A prepared archive of the analysis runtime that you import with **Install offline backend ZIP…**. Importing does not download anything. |
| **Orientation** | Which file is older and which is newer. A swap can make earlier interpretations stale. |
| **Partial** | Some evidence is missing. Missing evidence is unknown, not a negative result. See [39](39-partial-and-missing-evidence.md). |
| **Project** | A folder that holds your two copies of the files, the comparison results, notes and reviews. It is separate from the application. See [10](10-save-reopen-and-back-up.md). |
| **Provenance** | See *Evidence provenance*. |
| **rz-diff** | An external rizin-based comparison. It runs only when you configure and start it. |
| **Run** | One execution of an analysis for a project. Results name the run they came from. |
| **Sample** | The built-in synthetic comparison. It is authored demonstration data, not an engine run. |
| **Series** | An ordered set of builds, compared as adjacent pairs. See [32](32-series-panel.md). |
| **Stale** | A result computed from inputs that have since changed. Use it for reference and refresh before relying on it. See [38](38-stale-results.md). |
| **Unified** | A derived, experimental view that combines stored engine outputs as ordinal labels. The primary Ghidriff result is unchanged. See [22](22-unified-panel.md). |
| **Verdict** | The Engine evidence summary for one function pair: `Agree`, `Contested`, `Single engine`, `Unknown` or `Engine-only record`. See [21](21-engine-evidence-panel.md). |

Sources: `src/patchtrace/panel_manifest.py`, `src/patchtrace/ui.py` (menu and button labels), and the pages linked above.
