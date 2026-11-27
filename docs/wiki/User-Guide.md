# User Guide

The complete walkthrough is the root README and `docs/user-guide.md`. Summary:

1. **Install.** Download the Windows x64 ZIP and its `.sha256` from Releases. Extract the whole ZIP to a
   user-writable folder and keep `PatchTrace.exe` together with `_internal`. Do not run it from inside the ZIP.
2. **Try the sample.** Choose *Sample* for a synthetic guided exercise. It is labelled as a sample and is not real analysis.
3. **Install the comparison backend.** Ghidriff needs Ghidra and Java; the diagnostics screen reports what is missing. See `docs/install.md`.
4. **Compare.** Choose *New*, select the older and newer executable explicitly (order matters), and run the comparison.
5. **Review.** Inspect changed functions, correct manual matches, record reviews and notes.
6. **Rank and context.** Ranking, feature flags and CVE context are shown as signals, not verdicts.
7. **Optional AI.** Local Ollama or an HTTPS OpenAI-compatible endpoint. Credentials are session-only and never saved.
8. **Export.** JSON, Markdown and self-contained HTML reports.

Data handling (projects, backups, what is sent to providers): see `docs/privacy.md`.
