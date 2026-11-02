# Independent review: #153 card consensus and Type 2 missing Description

No blocking findings within the reviewed bounded slice.

- Source: `7533fe07365524526915c53b71b9cf45fc3e1bae`
- Tree: `0203f768f6ab4f5bc0dab9c4ffb055b8fd739266`
- Parent: `3bd48a710dcec1b471944f439a79b0fc8655921d`
- Clean worktree: `/workspace/scratch/142cb233d750/wt-msrc-findings`

## Scope and reasoning

- Type 2 vendor-fix rows lacking Description receive a resolvable parent-object ROW_SHAPE diagnostic and are skipped. Existing non-fix omissions and malformed-present behavior remain covered.
- The index groups selected active cards by CVE and source kind. Each of title, stated CWE, and severity context survives only when all candidate values agree, including absence; field and group ordering are deterministic.
- Consensus leaves original imported cards, raw objects, edge sets, revision selection, and separate CVRF/CSAF groups intact. KB searches report the conflict while their cards shape stays unchanged.
- The single context change propagates CARD_FACT_CONFLICT into unknowns; withheld CWE cannot supply a selected CWE hypothesis.
- Current native CVRF, XML CVRF, and CSAF card construction does not load applicability or KEV into source cards. Their existing default values therefore are not lost by reconstruction; derived context computes applicability separately.

## Independent validation

- 165 passed in 2.97 seconds.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_kbc_msrc_review_findings.py tests/test_kbc_msrc_provenance.py tests/test_kbc_msrc_cvrf.py tests/test_kbc_index.py tests/test_kbc_context.py tests/test_kbc_service.py`
- Independent constructed-severity control passed: six insertion orders yield identical cards, edges, and warnings; only severity is withheld; an explicit single-file scope retains its fact; original cards and all edges remain unchanged.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/new_review_controls.py consensus`
- Changed source/test Ruff and diff checks passed; exactly six changed files.
  Command: `/workspace/scratch/142cb233d750/venv/bin/python -m ruff check src/patchtrace/kbcorrelation/index.py src/patchtrace/kbcorrelation/context.py src/patchtrace/kbcorrelation/sources/cvrf_msrc.py tests/test_kbc_msrc_review_findings.py; git diff --check HEAD^ HEAD`

## Limits and integration

- The severity control deliberately constructs a supported card value because current importers leave severity unset; it is not a claim that the pinned source fixture contains severity facts.
- This parent does not contain the independently reviewed #118 saved-scope repair. When combining, retain both its bounded index lookup and this conflict-warning propagation line.
- No full suite, native Windows, live vendor fetch, broader advisory-provenance schema, or unrelated #153 acceptance claim.

The sibling JSON binds every changed file and the retained independent control script by SHA-256. No repository source edits, remote mutations, or GitHub approval were performed.
