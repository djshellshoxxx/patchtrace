# Generation 30 independent review: local input admission and fixture corrections

## Result and scope

Independent source review and actual repository tests found no blocking defect
within the reviewed generation 24–29 changes at
`6c8b33b851a22fb16d39b31693922359cd34ad12`. This worker did not author those
changes. The review covers local advisory-file admission, the conservative
older/newer source guards, and the generation 28–29 fixture corrections. It is
not a review of the entire accumulated branch or a main-merge recommendation.

The source was tested in an isolated Git worktree with Python imports rooted in
that worktree's `src` directory. These are production-module tests, not the
standalone algorithm mirrors retained by earlier generations. All network and
binary inputs in the selected tests are synthetic or mocked; no target binary
was executed. Mock transport acceptance does not establish live provider or
external adapter compatibility.

## Source inspection

- `cli_index.read_input_file` opens the selected advisory file once, requests
  `O_NONBLOCK` when available, verifies the held descriptor is regular before
  reading, reads at most the configured cap plus one byte, and transfers
  descriptor ownership to the buffered stream. The input error and byte-limit
  error remain distinct. Symlinks resolving to ordinary files remain supported,
  as required by `31-F-workflow-ui-persistence.md`. This does not authenticate
  the file's identity against concurrent regular-file replacement.
- `KbService.acquire` applies the older uniqueness requirement and newer
  resolver-window membership requirement before `build_plan` or transport.
  `row_for` refuses disagreements within the selected priority tier while
  retaining native-before-copied selection. Identical duplicate mappings remain
  admissible. Strict normalized-mapping equality can conservatively refuse
  equivalent raw claims; exact older predecessor membership is still absent.
- Generation 28's fixture obtains the target from the resolver's selected pair
  before introducing its synthetic disagreement. It therefore checks the
  source the production path actually selects. The integration assertion still
  requires `PT-KBC-INPUT`, no transport calls, and no destination project.
- Generation 29's two changed import blocks bind exactly the same Python names
  as their predecessor. Explicit `ready as ready` fixture registration remains
  present. The change does not alter test assertions, production behavior,
  consent requirements, or performance budgets. Strict scoped Ruff passes.

## Executed verification

The complete commands, versions, source hashes, and JUnit receipt hashes are
recorded in
[`evidence/generation30-independent-input-manifest.json`](evidence/generation30-independent-input-manifest.json).

| Selection | Result | Scope |
| --- | --- | --- |
| Generation 24 advisory admission and generation 25–29 source/fixture tests | **33 passed in 1.82 s** | Regular, directory, symlink, bounded-input, selected-row, duplicate, ambiguity, and refusal behavior |
| Affected offline import, CLI, acquisition binding, and existing independent integration tests | **63 passed in 2.50 s** | Existing import and consent workflows, source binding, state retention, and typed failures |
| Ruff on reviewed production modules and the four generation 24–29 test modules | **Passed** | No suppressed lint rules or modified test gates |

There are 96 distinct selected test cases across the two runs, no failures,
skips, or expected failures. This review did not repeat a full suite while the
source-specific hosted qualification was active. The receipts belong to the
exact source SHA above; a later integration needs its own affected verification.

## Open boundaries

The known Linux forced-export source-name race remains open. Inspection of
`strings.export._replace_linux`, `owned_publication`, and the retained
`linux-force-primitive-assessment-20261119.md` found no compatible repair to
claim. The current operation validates the result after pathname-based rename;
that does not guarantee prior-target preservation in the recorded interval.
This review did not rerun the retained race demonstration, disable `--force`,
change the export contract, or count the existing limitation test as a fix.

Full raw Winbindex index/entry retention, exact older resolver-input membership,
regular-file source substitution, native Windows input/publication behavior,
Qt artifact disposition, cross-platform packaging, and release acceptance are
outside this signoff. Hosted results, empirical accuracy, and live external
tool compatibility are not inferred from the 96 local tests. No new production
repair was justified by this bounded review, so no speculative source change
was made.
