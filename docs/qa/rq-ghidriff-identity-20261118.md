# Ghidriff research ranking integrity — 2026-11-18

Baseline: `1418617a80d6057de11f985488cfe6043a7787a2` (PR #307).
Repair source: `5936896e452789a565e656ab8491620f78c55705`.

## Reproduced behavior

The research Ghidriff adapter discarded unchanged records and newer-side names
before producing its name-only ranking. Authored reports containing an unchanged
`Target` and a different changed `Target` therefore returned the expected name;
the existing scorer awarded a HIT. The corresponding ambiguous no-change report
also received credit. Duplicate JSON keys silently replaced earlier values.
Malformed data on an unused side and unchanged rows could disappear from the
result rather than blocking qualification.

A separate Markdown defect matched a diff subsection against the normalized
function name. The valid reported heading `_Target@8` normalized to `Target`,
but its `_Target@8 Diff` subsection no longer matched. A genuine authored change
therefore produced an empty candidate list. Both stdcall and fastcall controls
reproduced this defect.

These are report interpretation defects. No claim is made that a real native
capture contains any of these authored examples or that a vulnerability fix has
been located.

## Resulting behavior

The parser checks unique JSON object keys, all reported function labels and
known side-relative addresses, counterpart relationships, unchanged records,
one-sided records and raw record counts before returning candidates. Distinct
records cannot share a normalized label or known endpoint. Exactly repeated
canonical records count once. Supplied malformed side/name/address fields and
unused ranking ratios are refused. Name-only legacy rows remain accepted with
their existing unverified limitations.

Markdown validates headings in all four recognized sections. Conflicting labels
are refused; unchanged headings remain excluded from ranking. Diff blocks match
their original reported heading before calling-convention normalization.

Refusal reaches the existing CLI exit 2 with no partial stdout, or scorerun
`BLOCKED: unparseable_report`, excluded from scored cases. Production
normalization, the scorer/case schema, Rizin, tool pins and frozen outcomes are
unchanged. Existing hand-authored JSON and Markdown fixture bytes and rankings
remain unchanged.

## Current-session verification

Runtime: Linux, Python 3.12; pytest 9.2.0. No engine executable, target binary,
native report generation, corpus rescore or network source acquisition ran.

| Invocation | Result | Scope |
|---|---:|---|
| Initial authored identity controls before source repair | 58 failed, 7 passed | Original failure evidence, 65 tests |
| First repaired adapters/scorerun/scoring/parity selection | 176 passed | Intermediate source, before the Markdown decoration repair |
| Markdown decoration controls before repair | 2 failed, 67 deselected | Original two normalization failures |
| Final candidate selection including Rizin and production normalization controls | 308 passed | Candidate files subsequently committed as `5936896e` |
| Exact-source research qualification family plus production normalization controls | 621 passed, 3 skipped | Executed with HEAD `5936896e452789a565e656ab8491620f78c55705`; native Windows checks remain unverified |
| Whole repository Ruff and `git diff --check` | Passed | Current candidate source |

The final 308-test command was:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_research_qualification_ghidriff_identity.py \
  tests/test_research_qualification_adapters.py \
  tests/test_research_qualification_rizin_identity.py \
  tests/test_research_qualification_scorerun.py \
  tests/test_research_qualification_scoring.py \
  tests/test_research_qualification_parity.py \
  tests/test_evalcore_ghidriff_one_to_many.py \
  tests/test_normalization_address_identity.py --tb=short
```

Selections overlap and must not be added. The full source tree's required hosted
gates and an independent review remain integration requirements. Parser tests do
not establish native accuracy or source-to-binary truth. This guard cannot detect
omitted or consistently mislabeled source facts and cannot replace the
production normalizer or a source-pinned native qualification run.
The three skips were two native Windows publication/handle controls and the
optional `psutil` resource-peak measurement check. Resource peaks were therefore
not measured by that check; no skipped result is acceptance.

The exact-source integration command was:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_research_qualification*.py \
  tests/test_evalcore_ghidriff_one_to_many.py \
  tests/test_normalization_address_identity.py --tb=short
```

Original logs and JUnit files are retained in
`rq-ghidriff-identity-20261118/evidence.zip`; `manifest.json` records each input
filename, size and SHA-256 plus the archive digest.
