# Bounded Windows network diagnostics — portable candidate

This packet qualifies the authored standard-C formatter and existing Python
evidence controls. It does **not** qualify Windows compilation, AppContainer
startup, effective network denial, descendant containment, or native BinDiff.
The original hosted failure is unchanged and remains failed.

## Exact source and ownership

The reused checkout is `/workspace/scratch/c7a9e8d98848/pw02-local-packages`, on
`codex/windows-network-diagnostics-20261118`. The previous clean worker branch
`codex/pw02-worker-contracts-20261118` remains at
`df479203b4e5e878887493e2b21049aa54c1c1ae`. Both the root and worker reviewer
released that checkout before this explicit transition. No extra worktree was
created, and no earlier packet was modified.

| Role | Commit |
| --- | --- |
| Explicit approved baseline | `9f4e1a57dc75de8d34ef9023bea2fb7619690f0b` |
| Specification, module entry, first eight controls | `666ee125f9fee045cb77d0c6021790cb47146a5e` |
| Additional actual stdio-failure budget control | `44654c74ab34305ad3a8be6a10db4f69ec7eeea5` |
| Three-file native diagnostic implementation | `9ca3c078c1e14ba4895a5e10c00234985a0b3fc2` |
| Test-only correction for the specified `win32` spelling | `ace5db8b3f5c300e0afb9f3dffd2978672514545` |

The C bytes at the final tested commit equal production commit `9ca3c078`.
Owned source is limited to `tools/windows_network/common.h`, `probe.c`, and
`launcher.c`; the other authored files are the existing Windows acceptance
specification/module row and `tests/test_windows_network_diagnostics.py`.
There are no Python production, workflow, package, release-policy, capability,
ACL, firewall, or dependency changes in this slice.

## Observed hosted failure, still unresolved

The original source is head
`f3f4492981f2c76c8d461d6a6d3eb1ac682fb996`, preview
`a94495abb6117400c138eaaa0127d260c3010094`, tree
`e49299eabe4cff2304d9dbe15f94c3c79566af44`. Run `44395588057`, job
`135124463954`, artifact `14470410950` reported a green advisory job but an
actual failed pytest/no-network control. The restricted probe emitted only
depth 0, with four loopback errors `10060` and external TCP error `10013`, then
returned `125`. The original C code does not return `125` solely because a
socket case returned an error. A descendant startup/resume/finish failure or
an early child failure remains unresolved. No specific API cause is inferred.

The original ZIP remains at
`qa/hosted-pr316-f3/artifacts/artifact-14470410950.zip`, 194,511 bytes,
SHA-256 `81495184fab2fc88adfbbc5889fd878f5b2a63e663c8b307feeb4fc5c73b316f`.
The separately sealed read-only diagnosis packet remains at
`qa/hosted-pr316-f3/ci-diagnosis/evidence.zip`, 119,520 bytes,
SHA-256 `7364e918b98da11e6898316f3e640a568d2372a67fa658ad33d0adae052114f8`.
Both were rehashed unchanged while preparing this handoff. No downloaded
Windows image was extracted or executed for this implementation.

The baseline C files exactly match the source hashes in that original native
build receipt: common header `74ada1531449c16c323e4771a95141534c3de4611fb85b26557c70bce921b752`,
probe `c5e6e41ebac7cdc379b31b76925d7f548c7ca6b22345a503389e96214d577b69`,
launcher `83f3c2b634851862779112b193ad3440e573586688195210349d9e619a1200c4`.

## What the candidate changes

The native helpers emit fixed `windows-network-diagnostic/1` JSON records to
stderr. Each record has a sequence, fixed stage/kind, owner and subject PID,
error, socket index, and known sent/received byte counts. All numeric fields
are unsigned 32-bit values. No raw path, argv, environment, nonce, SID, token,
or arbitrary exception text enters these diagnostic records. Existing stdout
receipt/case shapes remain the same.

One process attempts at most 16 records, each below 512 bytes. The sixteenth
slot is the `diagnostic-limit` / `truncated` marker; later calls do nothing.
The counter is advanced before formatting or writing, so a failed write does
not enable unlimited retries. Production code never resets the counter.
The three-probe chain and its launcher therefore attempt fewer than 32 KiB
of diagnostics, within the existing command capture and execution bounds.
There is no diagnostic emission inside a successful polling iteration.

Win32 errors are captured before cleanup and logging, then restored. Socket
errors are captured at the failing Winsock boundary; application-authored
timeouts and local validation failures have different kinds. Socket records
show whether failure occurred during connect, send, receive, or their waits,
and preserve known byte counts. Startup, token checks, Job assignment,
resume, child exit, wait and cleanup have distinct fixed stage context.

The existing native API calls and arguments, flags, handle lists, capability
count, Job policy, cleanup attempts, deadlines, and success/refusal/exit
decisions remain. Diagnostic write success is never an acceptance input.
Timeout still cannot count as access denial. A diagnostic record is not a
process identity/cleanup proof, and missing/truncated diagnostics cannot make
an incomplete receipt pass.

## Preserved failing and passing controls

| Run | Exact source | Result | Interpretation |
| --- | --- | --- | --- |
| `red.*` | `666ee125` | 2 failures, 3 missing-formatter errors, 3 positives | Expected absence of the specified diagnostics before C edits. |
| `red-write.*` | `44654c74` | 2 failures, 4 missing-formatter errors, 3 positives | Adds the actual stdio write-failure control before C edits. |
| `final.*` | `9ca3c078` | 327 passed, 2 failed | Test-helper grammar incorrectly rejected the specified literal `win32`; raw formatter output retained. |
| `final-v2.*` | `ace5db8b` | **329 passed, 0 skipped, 1.23 s** | Corrected lexical predicate; exact eight-kind vocabulary assertion retained; C bytes unchanged. |

The final gate consists of nine new diagnostic controls, 209 unchanged Windows
network evidence controls, and 111 registry controls. The final interpreter is
Python 3.12.14 with absolute checkout `src`/root import pins. All 67 imported
project/tool modules match the canonical Git blobs; no source-location drift
or denied socket/child attempt was observed. Twenty approved child invocations
cover the local compiler, the authored formatter, and the existing inspected
local-Git/Python/fake-BinDiff fixtures. These are not native Windows processes.

The C formatter was extracted verbatim from the actual header and compiled
with the existing `/usr/bin/cc` (Debian GCC 14.2.0-19), using
`-std=c11 -Wall -Wextra -Werror`. No Windows API was substituted or simulated.
The maximum-value record was 251 bytes. One thousand calls without resetting
state emitted exactly 16 records totaling 3,152 bytes, ending in the truncation
marker. A valid read-only stdio stream caused real write failures while the
counter still stopped at 16. The vocabulary harness deliberately resets its
test copy of the counter between independent labels; that mode does not
represent production lifetime accounting. Raw output for every formatter
invocation, compiler identity, harness source, and output hashes are retained.

The original refusal controls still reject return code 125, socket timeout,
and a missing descendant despite diagnostic text. This validates evidence
admission, not actual native networking.

Full normal Ruff (`python -m ruff check src tests tools`) and `git diff --check`
passed. `source-boundaries-v2.json` records a static lexical comparison of
native API call arguments/order and existing stdout calls across all three C
files. The initial `source-boundaries.json` classifier counted the formatter's
new X-macro declarations as OS calls; that original mismatch is retained.
The corrected comparison excludes the separately exercised portable formatter
section and explicitly excludes diagnostic last-error/owner reads. This is
review support, not a proof of execution-path equivalence or Windows ABI fit.

## Evidence and limitations

`final-v2.command.json`, `.imports.json`, and `.exit.json` record source,
arguments, source hashes, approved children, and import ownership. The final
runner is captured and hashed in `final-v2-runner.py`. Earlier runner revisions
were not individually hashed at execution; their exact tested source snapshots,
arguments, failure logs/XML, and observed children remain retained. The runner
was extended to retain raw formatter outputs and the final runner hash. The
audit is in the Python parent; compiler descendants are not audit-instrumented.
The only compiled program is the inspected extracted formatter, with no network
or Windows API code.

`manifest.json` hashes every payload and binds each phase's source snapshots
to its exact Git commit. `evidence.zip` contains that manifest and the payloads.
`seal.json` records its size/hash and successful member verification. The
small QA-only Git checkpoint carries this README, manifest, seal and archive.

Windows `/W4 /WX` SDK compilation and actual error-path behavior remain pending.
The next review is independent inspection of the three native files and this
portable evidence. Only a later exact-source hosted run can reveal the failing
native stage/error and re-evaluate the complete probe, lifecycle and actual
restricted BinDiff controls. No workflow dispatch, remote mutation, native
image execution, package install, release or tag was performed here.
