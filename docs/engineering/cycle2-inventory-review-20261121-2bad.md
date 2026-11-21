# Independent inventory review and quoted-field repair

Review performed 20 November 2026, America/Los_Angeles (21 November UTC).

## Source and scope

The independent reviewer started from exact published source
`91618abec4c4f13a27fd5821a25d1500f17601e4` in a separate worktree. This contains
the PR346 large-field recovery, PR347 integration, and the later TSV column,
immutable commit-ID and strict saved-PR-JSON repairs. Those changes had authored
tests and mirrored controls but lacked execution against a complete checkout.

This review imports the actual `tools/branch_inventory.py` and executes the
repository's inventory tests. It covers read-only inventory admission and
publication, not vulnerability analysis, branch semantic equivalence or
permission to merge/delete refs. The reviewer did not change the task ledger,
other workers' branches, workflows or global qualification records.

The additional repair is isolated in commit
`dc1ebfcd02d15bf94a707ee431ec585805a93cdb`, tree
`689c3059b823b4b73d57728e3a0a1794f16a019e`. Its tool blob is
`d1950b12bf83fbc826ae5f913f2bca1226e8e6c3`; SHA-256 is
`5e391021121198659ee899fd6d172c7bd8c7c13aed7f8c055939a8ba7ac1420f`.
The author of this additional repair cannot independently approve it; a fresh
peer review remains the coordinator's integration gate.

## Findings and changes

### Malformed quoted TSV could still replace retained evidence

Python's default CSV reader is permissive about quoted field syntax. A TSV
row containing a complete branch and commit ID but an unterminated quoted
`note` was accepted. Unexpected text following a closing quote was also
accepted. The column-count and object-ID guards therefore did not prevent
these damaged records from reaching Git. A complete CLI reproduction showed
successful generation replacing an existing report from the malformed input.

The contract now explicitly requires complete quoted fields. After the
contract and three regression cases were added, all three failed against the
unchanged tool: two cases reached Git, and the CLI case did not refuse the
input. The implementation change adds only `strict=True` to the existing
`csv.DictReader`. Its existing `csv.Error` translation and `finally` block
then provide input failure and CSV-limit restoration. The CLI keeps the prior
report because publication happens only after successful input processing.

Valid quoted tabs, embedded newlines, doubled quotes, large notes, reordered
columns and additional named fields remain supported. The strict option does
not add branch mutation, change report columns or alter semantic categories.

### The invalid-UTF-8 test did not contain invalid UTF-8

The prior test's bytes contained a backslash followed by the characters `xff`. Those bytes
decode as UTF-8 and instead exercise an invalid JSON escape. The fixture now
contains the actual invalid byte `0xff` and verifies that its UTF-8 decode
fails before invoking the reader. The former invalid-escape input is retained
as a separate malformed-JSON parameter. The existing production Unicode-error
classification already works; no JSON runtime change was needed for this
test correction.

## Actual execution results

| Selection | Exact source boundary | Result |
| --- | --- | --- |
| Existing inventory suites before this repair | Clean `91618abe` | **36 passed**, 3.68 seconds |
| Three new quoting regressions before runtime change | `91618abe` tool, new contract/tests only | **3 failed**, 0.73 seconds |
| Both maintained inventory suites after repair | Files committed as `dc1ebfcd` | **40 passed**, 3.25 seconds |
| Additional independent import/CLI controls | `dc1ebfcd` tool | **11 passed**, no skips |
| Retained 353-row snapshot | Exact PR346 evidence bytes with `dc1ebfcd` reader | All exact branch/tip pairs resolved; byte-identical rendering |

The two maintained files are `tests/test_branch_inventory.py` and
`tests/test_branch_inventory_pr_json_strict_20261120.py`. Their final run used
the repository pytest configuration and conftest. The imported `patchtrace`
module was verified at this worktree's `src/patchtrace/__init__.py`; the tool
tests resolve their module from this worktree's absolute file path. The
shared dependency interpreter was not assumed to resolve isolated subprocess
imports to this worktree. No test in this selection requires that assumption.

The final test invocation was:

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/tmp/patchtrace-2bad-inventory-review/src \
QT_QPA_PLATFORM=offscreen \
/workspace/scratch/2bade0b323c3/qualification-venv/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_branch_inventory.py \
  tests/test_branch_inventory_pr_json_strict_20261120.py \
  --junitxml=/tmp/patchtrace-2bad-inventory-evidence/maintained-fixed.xml
```

### Exact lower-source regression comparisons

For each lower source, the retained Git blob of the tool was materialized in a
temporary directory beside unchanged copies of the final repository test
files. The tests imported that exact tool file. These bounded comparisons used
pytest with its built-in fixtures and no project conftest; they establish the
specific tool regressions, not full lower-checkout qualification. Source/test
hashes, commands, exit codes, logs and JUnit records are retained.

| Baseline tool source | Selection | Observed result |
| --- | --- | --- |
| PR345 `39c38a02` | Large quoted note replay | **1 failed** |
| PR347 `b461ac64` | Column-shape refusal, compatibility and prior output | **7 failed, 1 passed** |
| TSV successor `eaae7e50` | Immutable IDs, tag peeling and canonical compatibility | **6 failed, 1 passed** |
| OID successor `a63a20b2` | Strict JSON, malformed/deep/invalid-byte inputs and read-before-Git | **11 failed, 1 passed** |

Every corresponding final test is included in the 40-case passing selection.
Counts overlap between the maintained selections and the comparisons; they
must not be summed into an aggregate acceptance number.

## Independent compatibility observations

The additional controls import the repaired tool rather than a copied parser
algorithm. Real temporary Git repositories were created with both SHA-1 and
SHA-256 object formats. Each format accepted its canonical commit ID with a
large quoted Unicode note, refused annotated-tag object substitution, refused
a blob object while preserving the previous report, and completed a valid
offline CLI publication with `delete_safe=no`. Other controls verified an
escaped-equivalent duplicate JSON key, a real invalid UTF-8 byte, and refusal
at a reduced metadata byte limit. These are synthetic local repository and
metadata fixtures; no analyzed target binary was executed.

The retained compatibility input is `raw/branch-inventory.tsv` inside
`docs/engineering/evidence/cycle95fe/cycle-95fe-evidence.zip` at PR346 source
`c07774ecf5a3f7337834f95a9a4c51c8ec5fad44`. The input is **2,228,790 bytes**,
contains **353 topic rows**, and has SHA-256
`d82d52544646eb029f38684e2dd3802ffa1596c7eb02d5c11d0ae0b5783aa902`.
All 353 exact commit IDs resolved, CSV limits were restored, and rendering the
parsed retained rows reproduced the original bytes. This is parsing and
serialization compatibility; it does not refresh the branch census or prove
semantic completeness.

## Review disposition and limits

The inherited bounded large-field reader, all-row column/OID syntax checks,
exact resolved-commit comparison, duplicate-key/nonfinite-constant JSON guards,
fixed parser failures and PR-read-before-branch-replay ordering satisfy their
reviewed narrow contracts after the quoted-field repair. Previous output is
preserved for the tested input-failure paths. Valid JSON payloads and valid
snapshot fields retain their values.

This is not a complete schema or provenance attestation for saved GitHub PR
records. The saved dataset's authenticity, completeness and semantic claims
remain external to these parser guards. Canonical-but-invalid object IDs still
need Git lookup to reject them; the pre-Git guarantee applies to the reviewed
syntactic input failures. Existing duplicate-branch rejection is unchanged.

No full suite, hosted CI, Windows/native acceptance or release gate was run or
claimed by this worker. Prior SIGKILLs and failed hosted jobs remain retained.
The coordinator owns whole-tree Ruff, combined-source verification, fresh
review of this additional repair, and qualified publication/integration.

## Retained evidence

The [evidence directory](evidence/cycle2-inventory-20261121-2bad/README.md)
contains a verified 22-member ZIP and a per-member SHA-256 manifest. It retains
the initial passing run, all expected failing baseline runs, the repaired
passing run, source/environment identities, executable comparison/control
scripts and captured-snapshot compatibility receipt. Original log and JUnit
bytes are compressed without modification.
