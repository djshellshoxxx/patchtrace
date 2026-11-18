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

## Corpus engine cache verification (2026-11-18)

The Linux Tier R shard caches only the original Rizin and Ghidra archives under
new archive-specific keys. A cache key or cache-hit result never admits runtime
bytes. Before every extraction, including a hit, validate the configured SHA-256
syntax and verify the complete archive against that pin. Download only when the
archive is absent. A present corrupt archive fails the step; do not silently
reuse an extracted tree or turn that failure into a successful retry.

Refuse a nonregular or symlink archive and a preexisting runtime destination.
Create the runtime directory exclusively after verification, then extract there.
Keep the archive for future cache restores. Preserve the current engine-selection
condition and environment-variable paths. Ghidriff installation and shard
execution remain after successful archive verification/extraction.

Authored Linux shell controls exercise the actual workflow scripts with small
inert archives and a fixed fake downloader, never an engine or a target binary.
They cover cold/warm valid archives, cache corruption, a bad configured digest,
and refusal to reuse a runtime directory. The original CODEX-6 assertion remains
unchanged in the external replay and becomes required in current tests. This is
a cooperative CI workspace boundary; it does not claim resistance to an active
local writer swapping an archive between the hash tool and extractor, nor does
it replace hosted/native engine acceptance.

## Dependency-hash scope

The historical dependency-hash finding is separate from action pinning. The
direct workflow scripts and their installer helpers must first be mapped to
their runtime/build/scanner/backend/site profiles, platform and interpreter
identities, build inputs and transitive dependencies. A future lock design must
cover the complete resolved closure with reviewed artifact hashes. Do not
silence the original audit, add a cosmetic flag, or disable verification merely
to satisfy a textual assertion. Existing backend wheelhouse and scanner
bootstrap guarantees must retain their stated scopes and their prior evidence.
