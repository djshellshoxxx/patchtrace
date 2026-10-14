# Report goldens (SPEC-28 K1)

**SYNTHETIC.** Byte-identical expected output of `intelligence explain` exports (`reports.render`), produced from the synthetic sample project (`ProjectService.sample`: older `synthetic_pe(0)`, newer `synthetic_pe(1)`) and the CSAF fixtures in the parent directory. LF line endings only (`.gitattributes`), UTF-8, no byte order mark. They are not live evidence.

| Golden | Input |
|---|---|
| `single.report.json`, `single.report.md` | `synthetic-advisory-rev1.json`, `CVE-2099-10001`: verified file-hash mapping, older affected, newer fixed, explicit CWE-191 |
| `revisions-vex.report.json`, `revisions-vex.report.md` | rev1, rev2 and `synthetic-vex.json`: a superseded revision, a cross-revision and a VEX-versus-advisory contradiction, both kept |
| `hostile.report.json`, `hostile.report.md` | `../injection/hostile-advisory.json`: the Markdown shows every payload as inert text |

Each document is imported with the fixed retrieval stamp `2099-03-0N` (N = import order) and its fixture file name, so the output holds no clock or path.

After a deliberate change (a contract, the lexicon, the rule table, the renderer), regenerate and review the diff:

    PATCHTRACE_UPDATE_GOLDENS=1 python -m pytest tests/test_intel_reports.py

An unexpected difference is a regression or a platform dependence; do not regenerate it away.
