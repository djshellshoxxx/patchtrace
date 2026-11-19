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

## Linux full frozen CLI smoke (2026-11-18)

After preparing the Linux onedir package and checking its existing resource,
license and inventory prerequisites, run the same `tools/frozen_smoke.py`
harness used by Windows acceptance against the exact staged executable. It
enumerates the current command registry and covers headless help/error paths,
the self-test, owned synthetic project/series paths and existing BinExport,
intelligence and unified packaging controls. No analysis target is executed.

The host interpreter invokes this harness with an argv list, the source checkout
as cwd, the executable as one separate path argument and the existing Qt
environment (offscreen by default). Bound the complete invocation to at most
900 seconds and require a successful exit. A missing CLI, failed check or timeout
must stop before writing any new lite/full archive or digest sidecar. Do not
replace this with one command's help output, suppress an individual failure, or
create a second command registry. Full backend/disconnected acceptance and the
existing unpacked Linux platform smokes retain their independent scopes.

Behavioral tests drive the builder's actual pre-archive path using inert owned
files and a recorded subprocess seam; no PyInstaller build or executable launch
is inferred from them. The existing real source-CLI smoke verifies the reused
harness separately. Hosted execution of the actual frozen Linux package remains
required before any frozen compatibility claim.

## Authored fixture bytes and Linux inventory spelling (2026-11-19)

Exact-byte source and scanner fixtures must create their declared UTF-8/LF
bytes without host text-newline conversion. This applies to the shared authored
qualification checkout, the reviewed bootstrap/audit requirements fixtures,
and the small authored repositories used to prove publication holds and
untracked-source refusal. Pin `core.autocrlf=false` in each authored repository
before staging its bytes. A caller's normalizing Git defaults cannot silently
change the evidence that the fixture claims to have authored. This requirement
changes fixture construction, never the source or receipt validators: actual
CRLF, changed source bytes, missing inputs and malformed evidence remain subject
to their original refusal rules.

The Linux builder's regular-file inventory is a sorted sequence of relative,
slash-separated names, independent of the host path object's string spelling.
Project each enumerated relative path with its POSIX spelling. Preserve the
same file iteration, regular-file checks, actual Linux names/bytes, unwanted
library refusal, required protobuf extension, exact extractor/launcher bytes,
full frozen smoke and no-archive-on-failure behavior. A Windows-style relative
path model must not stand in for a real Linux frozen build.

Portable controls deliberately apply CRLF text conversion, use an isolated
authored Git configuration with normalization enabled, and return Windows-style
relative path objects while exercising the actual builder with inert files and
its existing injected runner. Preserve the existing hash/identity, same-size
mutation, hold, untracked-source, smoke and failure assertions. No skip, xfail,
weakened predicate, scanner invocation, engine or target execution supplies this
repair. Every real child in these controls is a bounded, reviewed operation on
authored local data; no fetch or network access is required.

The original Windows full QA at head `771e5a77`, job `135175350823`, remains a
51-failure result. Its explicit CRLF and path-spelling failures are retained.
The two tiny Git-source size/type failures did not capture their actual working
bytes, blob bytes or effective Git settings; a portable reproduction establishes
fixture reproducibility weakness without claiming those omitted facts for the
historical job. Corrected hosted Windows/full/frozen acceptance remains separate.

## Dependency-hash scope

The historical dependency-hash finding is separate from action pinning. The
direct workflow scripts and their installer helpers must first be mapped to
their runtime/build/scanner/backend/site profiles, platform and interpreter
identities, build inputs and transitive dependencies. A future lock design must
cover the complete resolved closure with reviewed artifact hashes. Do not
silence the original audit, add a cosmetic flag, or disable verification merely
to satisfy a textual assertion. Existing backend wheelhouse and scanner
bootstrap guarantees must retain their stated scopes and their prior evidence.
