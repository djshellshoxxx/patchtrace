# Windows BinDiff network acceptance candidate

The implementation passes its portable affected gate. **Native Windows
qualification is pending.** The original Windows BinDiff artifact remains
blocked, and this candidate does not authorize a release or merge to main.

## Source and ancestry

| Item | Identity |
|---|---|
| Approved baseline | `7023c3ad0ce727eb9c8b94c082b55ca9779bd6bb` |
| Specification and initial failing controls | `b7b2d53be0d5ad27613cc078b5ced035b76afa59` |
| Implementation candidate | `8800bef2c2ec5b425d6e3e3ea7d4c0033cc07c17` |
| Implementation tree | `24013a4da0c2aa715d7ff546d1933ce4468ec9a1` |
| Branch | `codex/windows-bindiff-network-20261118` |
| Worktree | `/workspace/scratch/c7a9e8d98848/windows-bindiff-network` |

The source checker verified literal tracked bytes at the implementation commit,
including the new helper's membership in that commit. A clean older tree with
untracked acceptance code is refused. Held commits are valid test inputs;
publication retains its separate `[no release]` hold.

The implementation owns the Windows launcher/probe/header, Python acceptance
orchestration and strict receipt validation, the live BinDiff harness/workflow,
focused tests and documentation. Product `src/` and release qualification policy
are unchanged by this slice. Independent source review remains the next gate.

## Mechanism and scope

The proposed native boundary is a new AppContainer profile with zero
capabilities. Every actual native BinDiff version/help/diff launch goes through
the adapter's existing runner seams. The helper starts the child suspended,
verifies its actual token/SID/capability list, places it in a Job Object that
prohibits breakaway and kills descendants on close, and supplies only NUL stdin
and two dedicated pipe handles before resuming it. The helper holds the native
image open without write/delete sharing during execution.

The Windows SDK build and executable hashes are retained. The native BinDiff
size, SHA-256 and reported version must match the existing repository pin.
Access changes apply to newly owned staging/work directories. The original
checkout, installed interpreter/tool trees and host firewall policy are
unchanged. C3 acceptance and Python result import retain their original
production implementation outside the native AppContainer boundary.

Required observations include parent, differently named child and grandchild
tokens; positive TCP/UDP IPv4/IPv6 loopback controls and bounded external TCP;
actual Winsock access-denied outcomes in the AppContainer; positive controls
after cleanup; cancellation, timeout and abrupt-owner-exit lifecycle evidence;
and the pinned native adapter run. Lifecycle receipts include process creation
identities and a post-stop liveness query. A boolean success assertion alone is
refused. PID reuse in separate serial launches is distinguished by creation
identity; simultaneous descendant identities must remain unique.

Linux and Windows retain match-count parity and now compare a complete imported
semantic fingerprint. It includes all match/alternative fields, orientation,
engine version, image-base interpretation and limitations. Separate raw-output
hashes and run IDs are excluded from that semantic comparison and preserved as
execution evidence. Linux's restricted run also uses the real adapter path.

This is the defined native-tool network boundary. General application isolation,
arbitrary broker-mediated behavior and real-driver accuracy remain outside its
claim. All input artifacts in this slice are authored data and are never
executed.

## Verification at the implementation commit

The exact command, absolute source `PYTHONPATH`, interpreter, source SHA/tree,
timing, log and JUnit are in the sealed packet.

| Check | Observed result |
|---|---|
| Twenty affected test files | **624 passed, 6 skipped**, 57.96 seconds reported by pytest |
| Focused new controls within that run | **129 passed** |
| Normal Ruff over `src tests tools` | Passed |
| Canonical source verification | Passed for `8800bef2` / `24013a4d` |
| Real BinDiff test on this host | `blocked`: `PATCHTRACE_BINDIFF` is unset |
| Native helper build command on this host | `blocked`: native Windows is required |

The six skips are Windows-only existing process tests: containment failure,
suspended-child assignment cleanup, Ghidra path-length preflight, failing
kill-tree handle cleanup, rejected injected `.cmd` arguments, and safe `.cmd`
arguments. Their exact JUnit reasons are preserved. The host is Linux x86-64
with Python 3.12.14. No Windows SDK/compiler or Windows cross-compiler is
available. The new C helper has therefore **not been compiled or run against a
Windows SDK here**. Portable controls establish receipt/orchestration behavior,
including an actual short pipe-write exercise and the real adapter with an
authored fake child; they provide no AppContainer, Winsock or native BinDiff
acceptance credit.

The affected set covers the new controls, live harness, BinDiff probe/input/run/
C3/import/golden/resource/pinning paths, secondary scheduler, process lifecycle
and release qualification. No whole-suite rerun was performed for this slice.

## Failures retained during development

The initial immutable specification checkpoint produced 2 wiring failures,
91 missing-implementation import errors and 1 fixture positive. Intermediate
logs preserve controls for access-time false mutation, incomplete short pipe
reads, boolean-only lifecycle claims, repository pin enforcement, exact source
membership, profile ownership, timeout ordering and strict byte capture.

Two intermediate fixture issues are labeled separately: a minimal fake process
result initially lacked `stderr_tail`, and an initial byte-capture test tried
mutating the frozen `ProcessResult`. The latter was corrected with
`dataclasses.replace`, preserving its assertions; the corrected run then exposed
the intended byte-capture/PID-identity failures while the invalid-UTF-8 control
already passed. A separate raw failure records the implementation's incorrect
`stdout_bytes` attribute; it now uses the actual `log_bytes` process API.

Those intermediate candidates were uncommitted. Their raw logs/XML identify the
observed failures but are not attributed to an invented immutable source SHA.
The complete initial test source and final source are included from their actual
Git commits. `test-receipt-index.json` records each preserved run's counts.

## Original native evidence and remaining gates

The packet includes an unchanged copy of artifact **14438536883**, its API
metadata and original job log. The original ZIP is **6,490 bytes**, CRC-clean,
SHA-256 `01a48208cb6f024f65ad76d35134d6b76623d6c966141baec2fb92212b64816e`.
Workflow run **44319417801**, job **134854104769**, reports PR head
`d8c02caea407f6d323eecd636735849c1eb31a2d`. It contains six passed subchecks and
`no_network: blocked`; overall status is **blocked forever for that receipt**.
It is not a canonical release qualification receipt.

Before acceptance, an independently reviewed exact candidate must compile with
the hosted Windows SDK and produce actual token/handle/job, IPv4/IPv6 TCP/UDP,
descendant, lifecycle, ACL/profile cleanup, C3/native-adapter and semantic-parity
receipts. Missing capabilities remain unverified; any incomplete, contradictory
or failed evidence prevents qualification. The workflow retains the existing
advisory policy and records detailed output under the artifact's `network/` and
`network-build/` directories. Publication still needs the existing canonical
source and full gate policy, including unrelated unresolved scans/native gates.

No remote workflow dispatch, release, tag, deployment or main merge occurred in
this workstream. Root retains remote publication/integration ownership.

## Packet

`evidence.zip` contains the raw logs, JUnit, command/environment/source receipts,
source snapshots, primary-reference notes, original native artifact and job log.
`manifest.json` binds every member by size and SHA-256 and records the archive
hash. The archive was reopened, CRC-checked, checked for duplicate names, and
every member's bytes revalidated before this QA checkpoint was committed.
