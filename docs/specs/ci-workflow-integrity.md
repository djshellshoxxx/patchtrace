# CI workflow input and smoke integrity

## Immutable remote actions (2026-11-18)

Every remote action or reusable workflow reference under `.github/workflows/`
must name a complete 40-character Git **commit** SHA in its canonical repository.
Local `./` actions and explicit container references remain separate policies.
A movable branch or tag is insufficient. An annotated tag object must be peeled
to its commit before its SHA can be used as a workflow reference.

For the initial repair, resolve the exact existing action ref without changing
its major or minor selection. Preserve the canonical API ref response, any
annotated tag response, the commit and tree identities, retrieval timestamp and
old-ref-to-commit mapping. Bound the retained response set. Already immutable
references remain unchanged. Future version changes require a fresh attributed
review; a comment naming the original tag is explanatory and never executable.

An action-pin-only change must preserve every other workflow byte apart from
those reference values and their explanatory comments. In particular it cannot
change triggers, dispatch inputs, job/step conditions, permissions, secret or
token handling, scripts, matrices, timeouts or artifact/publication behavior.

The existing all-workflow immutable-reference assertion is a required current
regression. Replay its original historical bytes separately and preserve the
initial failure. Verify YAML parsing and neighboring workflow/release policies.
Record an independent before/after comparison of every workflow, including all
unchanged immutable references. Static source controls do not establish hosted
execution or qualify a native package/release.

## Dependency-hash scope

The historical dependency-hash finding is separate from action pinning. The
direct workflow scripts and their installer helpers must first be mapped to
their runtime/build/scanner/backend/site profiles, platform and interpreter
identities, build inputs and transitive dependencies. A future lock design must
cover the complete resolved closure with reviewed artifact hashes. Do not
silence the original audit, add a cosmetic flag, or disable verification merely
to satisfy a textual assertion. Existing backend wheelhouse and scanner
bootstrap guarantees must retain their stated scopes and their prior evidence.
