# Generation 35 — independent source review of generation-34 Strings CSV cases

## Source identity and bounded review

- Reviewed candidate: \`codex/patchtrace-csv-formula-prefix-20261120-g34\` at
  \`599e1ee1bc7bec095b4e6fa28d5cfc25c4d6f7df\`, stacked on PR342
  \`5f34fb57267637b986814ddc81dba11550992fff\`.
- Production source: \`src/patchtrace/strings/export.py\`, blob
  \`3b53c8a42460f55ab1c3d9bf77e966946d168527\`.
- Regression source: \`tests/test_strings_export.py\`, blob
  \`a64d67ccdcedefad4ccbcbb2ec23f4aa7c1162ca\`.
- This independent source inspection found a **test-source encoding defect**.
  The authored generation-34 regression parameter strings use **two backslash
  characters** in Python source for LF, tab and U+FEFF escapes. These evaluate
  as literal backslash-letter strings, not the intended control/BOM characters.
  The production \`_cell\` checks real control/BOM characters, so the fixture
  itself contradicts its expected escaped values.

## Reproduction and repair

A fresh Python 3 standalone stdlib replay of the exact authored parameter
spellings against a source-equivalent \`_cell\` rejected five of ten expected
outputs: \`line-formula\`, \`bom-formula\`, \`space-tab-formula\`,
\`line-control\` and \`tab-control\`. Those are genuine fixture expectation
mismatches in the source listing, **not** results from repository pytest.

A new isolated test-only successor \`codex/patchtrace-csv-fixture-escape-20261120-g35\`
was forked from the exact generation-34 head. The WB3-S6 test-source contract
was clarified first (commit \`f203ae0adbd5370aa0c14e14eaf703897a322f3d\`),
then only the CSV regression fixtures were corrected. This uses single Python
escape introducers for real newline/tab/BOM values and adds three distinguishing
cases: CR-start prose, vertical-tab-prefixed formula, and literal slash-n
nonformula prose. Case IDs were aligned to parameters.

No runtime or JSON/export data policy, publication, redaction, permissions,
native cache or external transmission behavior changed.

A fresh Python stdlib \`csv.writer\` -> \`csv.reader\` control of the source-
equivalent production helper and the 13 corrected case values **passed 13/13**.
The original bad fixture replay **failed five cases out of ten**. These are
hermetic algorithm controls rather than checked-out-source
\`python -m pytest\`, native spreadsheet application evidence or truly
independent source execution. Source-level audit does not establish universal
formula protection across spreadsheet products.

## Qualification and continuation

The connector can fetch and publish exact repository files but the local
runtime cannot resolve github.com to clone, and \`python -m ruff\` is not
installed. Therefore affected repository pytest, required full offscreen
pytest, whole-tree Ruff, native Windows, Qt, packaging and independent
post-fix reviewer signoff remain unverified. Do not describe the fixed source
as accepted or the original generation-34 tests as passing.

At observation PR342 exact head still had Linux QA and one Linux Qt shard
successful, but Windows QA, other Qt, native and live jobs queued. No
overlapping full workflow was started or earlier check attributed to
generation-35. The original SIGKILL and native \`java=unverified\` failures are
preserved without an inferred cause. Both the separate forced-export
publication race and Winbindex raw-input membership blocker remain open.

Next owner: wait for parent PR342's terminal qualification, review actual
new test source and run
\`python -m pytest -q tests/test_strings_export.py\`,
\`python -m ruff check src tests tools\` and required broader checks from a
supported checkout. Request a fresh peer review of the corrected fixture
and original production helper, then create a stacked draft PR only when
safe to avoid duplicated full CI. Keep g34 and earlier heads intact.
