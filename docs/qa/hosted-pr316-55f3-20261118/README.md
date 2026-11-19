# PR316 hosted receipt review — 2026-11-18

## Disposition

This read-only packet verifies useful native and scanner results for published
PR316, but **does not qualify a release, main merge, or later integration tree**.
The strict static scan failed with 81 unsuppressed diagnostics. At the final
18:50:02 UTC job snapshot, both main QA jobs were still running, all five Qt jobs
were queued, three dependency profiles were queued, several native scenarios
were queued, and the release gate was skipped. Actual source commit metadata
contains the literal `[no release]` hold. No remote mutation, dispatch, rerun,
release, tag, install, scanner rerun, or native executable launch was performed
for this receipt review.

Source ownership is explicit:

| Identity | Value |
| --- | --- |
| Published PR316 head | `55f3d0742f7d4cf32357a42b8b1cc76d85875e71` |
| Published source tree | `11a0c1598764ebd3fd8d3b540377aa52e949f88a` |
| PR merge preview actually checked out by six reviewed jobs | `872947fd8edead1f3269700375c05149fa71e9ef` |
| Preview tree | Same `11a0c1598764ebd3fd8d3b540377aa52e949f88a` |
| Preview parents | Main `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`, then published head `55f3d074…` |
| Main and PR status at final read | Main still `9c411ca3…`; PR316 open and unmerged at `55f3d074…` |
| Local read-only source | Existing detached `full-batch-path-review`, HEAD `55f3d074…` |

The GitHub runs API identifies the PR head, while checkout logs and scanner
contexts identify the merge preview. Both are retained. Equal trees do not make
a PR event canonical release evidence: this source's release guard accepts only
push, workflow_dispatch, and schedule events. The unified workflow is the
exception in this packet: its two jobs actually checked out the published head
under a push event. None of these results transfers to root's later production
source `5bbb9256` or checkpoint `987cfb1b`.

## Reviewed jobs and actual receipt results

All eight reviewed jobs belong to repository `djshellshoxxx/patchtrace`, attempt
1. Workflow paths, run ownership, job identities, checkout SHAs, step outcomes,
artifact IDs, sizes, GitHub SHA-256 digests, and ZIP CRCs were checked. The complete
machine-readable result is `review.json`; decoded job logs and API responses are
retained independently.

| Workflow/scenario | Run / job | Actual checkout | Finding |
| --- | --- | --- | --- |
| Live BinDiff, Ubuntu 22.04 | 44355795341 / 134983436284 | Preview `872947fd…` | Seven native subchecks passed; raw output digest matches |
| Native Ghidriff, Windows seeded store | 44355795281 / 134983435670 | Preview `872947fd…` | Both fixture PDB seeds observed; backend stopped with exit 0; known bounds-check patch accepted |
| Optional dependency probe, Ubuntu | 44355795413 / 134983435605 | Preview `872947fd…` | All three optional packages imported; this is not a Rizin probe |
| Live rz-diff, Ubuntu | 44355795273 / 134983435271 | Preview `872947fd…` | Real pinned Rizin 0.9.1; 30 matches; no recorded errors |
| Dependency runtime, Ubuntu | 44355795241 / 134983435409 | Preview `872947fd…` | Complete recorded 17-distribution closure audited; zero reported vulnerabilities, skips, or fixes |
| Strict static security | 44355795241 / 134983436211 | Preview `872947fd…` | Ruff exit 1 and 81 findings; correctly blocked; one input text receipt omitted from upload |
| Unified extraction, Windows | 44355710739 / 134983127993 | Published `55f3d074…` | Both authored fixture pairs completed; output and fixture identities retained |
| Unified extraction, Linux | 44355710739 / 135015211489 | Published `55f3d074…` | Same Windows-built DLL bytes; two explicit L6 passes and all four side digests equal across OSes |

### Linux BinDiff

`bindiff.json` is `passed`, `mocked: false`, and records passed probe,
pinned_version, end_to_end, no_network, reversed_refused, cancel_at_first_output,
and timeout_mid_run checks. The authored synthetic 20/21-function pair produced
20 matches. The retained raw BinDiff database hashes to
`7f57af294d61bad93fefbc017f053f68aa5170bf66128ac4eaafc6fe272f056a`, matching the
receipt. The provisioned executable digest also matches the probe and pinned
executable identity.

At this source, the no-network check compares match counts under `unshare -rn`;
it does not retain the later complete semantic-match fingerprint. This is the
defined synthetic Linux check only. It does not qualify the separate unpublished
Windows AppContainer implementation, arbitrary child/broker isolation, or real
driver diff accuracy. The original PR304 Windows artifact remains blocked and
unchanged outside this packet.

Provisioning's `bytes: 110275568` is extracted regular-file bytes, not the
downloaded archive size. The pin specifies a 62,663,460-byte `.deb`; its SHA-256
is `821990e3974a9df6733794370e485486ac276ba5d777a06b4ebe575f092f4dda`.
The provisioning source checks archive integrity separately. This review did
not download that package. The receipt's trust-on-first-use and unverified
upstream-signature caveat is preserved without granting independent publisher
authentication credit.

### Windows Ghidriff seeded store

The log records seeding both `old.pdb` and `new.pdb` in `C:\gout\symbols`, then
PatchTrace's offline analysis and `Known patch accepted: 1 change records`.
The inspected acceptance code requires a completed backend run, normalizes the
result, and checks the changed `read_item` function and its new bounds condition.
The receipt for run `d739f4f6-1851-4e02-bb20-29aaf7587273` reports exit 0,
`process_state: stopped`, `stop_reason: exited`, and about 112.39 seconds. It
records Ghidra 12.0.4, Ghidriff 1.0.0, PyGhidra 3.2.0, Python 3.12.10, and an
explicitly `unverified` JVM version. Raw logs, JSON, matches, markdown, and the
project database are retained in the original ZIP; none was executed.

This job is the Windows `patchtrace-seeded-store` matrix scenario. The clean,
no-adjacent-PDB, raw-cache-hit, and plain-Ghidriff reproduction jobs were queued
at the final read. Their intentionally skipped steps within the seeded-store
job do not establish acceptance of those other scenarios.

### Optional dependency and Rizin probes

The optional-dependency job belongs to `.github/workflows/optional-deps.yml`.
Its final log is `present=rapidfuzz=3.14.6,yara-x=1.21.0,iced-x86=1.21.0
missing=none`. It uploads no artifact and runs no Rizin engine.

The separate live Rizin receipt reports version/pin 0.9.1, required `-C`, `-j`,
and `-t` help flags, `engine_run.status: ok`, null error code, 30 matches, and no
errors on an authored MinGW-built PE pair. The artifact contains the JSON
receipt and its recorded input/output hashes, not the raw engine output. The
Windows live Rizin job remained queued.

### Unified Windows/Linux acceptance at the published head

Both jobs used the same committed extractor script, SHA-256
`3901f3a8c369b3350b98566a46666258f9b2c79a1704f7fcdad2a64c502de49e`.
Windows built the two authored DLL pairs; Linux consumed those exact four DLL
bytes from the Windows artifact. The independently verified side results are:

| Pair / side | Functions | Content digest on both OSes |
| --- | ---: | --- |
| CI / older | 377 | `509c002f2a3cffaba5b2c1aab7e075cab3bbdc91b282aa1572cf9f5060174aa4` |
| CI / newer | 377 | `548088e0b54e2c47b45d3e0b61780884ef9d8dd04d92f53318184eff3fec173d` |
| Probe / older | 383 | `27214932a2dbf4c52443255e49b73c944167447a7b41612f99e9a20eaf7b6ca2` |
| Probe / newer | 383 | `a658ef9f00c21c74bac115a68414f8188206258c051a9c3ea9c484e0d0e65c0c` |

All four sides report Ghidriff-GZF equality with their own analysis on both
OSes, no warnings or unlocated masks, equal h0/h3/h3x/hmx classes, and successful
h3/hm refinement checks. `hm.equal: false` is expected for these fixtures: the
source deliberately omits operand counts from that coarser key and asserts
refinement rather than exact class equality. Linux logs contain two explicit
L6 same-byte cross-OS passes. These are genuine native fixture results, without
claims about real-driver completeness or later source versions.

### Dependency and static scans

The Ubuntu runtime receipts identify CPython 3.12.16 and separately retain the
initial ensurepip 25.0.1 inventories, installation issuer/target metadata, the
hash-pinned pip 26.3 transition, final installed inventories, wheel origins,
process arguments/output hashes, and audit JSON. Both the profile and scanner
transition to pip 26.3 using wheel SHA-256
`f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13`.

The audit covers exactly these 17 installed distributions: annotated-types
0.8.0; iced-x86 1.21.0; pip 26.3; protobuf 7.36.2; pydantic 2.13.5;
pydantic-core 2.46.5; pyside6, pyside6-addons, pyside6-essentials and shiboken6
6.12.0; pyside6-pdf and pyside6-webengine 6.12.0.140; rapidfuzz 3.14.6;
setuptools 84.2.1; typing-extensions 4.16.0; typing-inspection 0.4.5; and
yara-x 1.21.0. The separately proven repository-owned editable distribution is
patchtrace 0.1.0 at the recorded checkout, with search/rules extras selected.
No audit result skipped a distribution, applied a fix, or reported a vulnerability.

The exact-source validator's interpreter, bootstrap, installation, process,
selected dependency, and exact-audit-closure checks were applied to retained
data without rerunning scanners or rewriting host paths. The remote checkout's
filesystem existence cannot be observed locally; that check was run by the
hosted validator. This review verifies the recorded owner URI, canonical source
tree, installation/environment consistency, and full closure without pretending
the remote directory exists here.

The static scanner used pinned Ruff 0.17.5 with `--isolated --select S
--ignore-noqa --no-cache --no-respect-gitignore --output-format json`. Its raw
process receipt records exit 1, no timeout/output limit/error, and empty stderr.
The raw finding JSON SHA-256 is
`046d6b53b64645d44ec648438878382847317ff8a505947d1e3b29660709d485`.

| Rule | Diagnostics |
| --- | ---: |
| S101 | 9 |
| S105 | 14 |
| S108 | 1 |
| S110 | 13 |
| S310 | 6 |
| S314 | 2 |
| S603 | 1 |
| S608 | 35 |
| Total | 81 |

These are unsuppressed scanner diagnostics, not 81 confirmed vulnerabilities.
The failed step and failed verdict remain blocking. They belong to source
55/872, not the later root tree whose separate strict count is 80.

**Confirmed retention omission:** the static upload includes JSON/stdout/stderr
but not `*.txt`, so artifact 14459695622 omits `bootstrap-pip.txt`. The runtime
artifact retains it. The final reviewer records this absence, retains its
initial refusal, verifies the other captured static records, and does not
reconstruct the missing file or credit full static qualification. A future
scoped workflow repair can add `build/security-static/*.txt`; no source change
is made here.

The retained `unaudited.json` explicitly excludes external Ghidra/JDK/Rizin/
BinDiff/NSIS closures, OS and vendored Qt/native code, a separate frozen or
bundle BOM, calibration-dev, scanner-tool dependency auditing, exploitability,
and vulnerabilities absent from the selected advisory service. Other OS and
packaging profiles remain uncredited until their own receipts are reviewed.

## Artifact integrity

Seven small original ZIPs totaling **686,538 bytes** were downloaded. No large
tool package was downloaded. All seven matched API byte counts and SHA-256
digests, and all member CRCs passed. The four authored DLLs in the unified ZIP
were read only to hash them; they were not launched or unpacked as executables.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| 14455712791 | 6,461 | `a65e345bd86553639c596cc038cd26baccf15ec09c6f3bd4f7aed9d5c39349b0` |
| 14458335539 | 96,428 | `dffd9dd7a5007c051afe79a0e5fb4a73e0d2dc6a534432c8d548b6b685377873` |
| 14457495243 | 623 | `0e351b8ffc1646d738d2317db3ecf51f4022b8501b6845b5af413f7a8a9fda2d` |
| 14458535146 | 329,152 | `1f7f3e90e90fa3f5c8867d6d3e53a422887e8cb0803096f9c1891bf7c7cb2111` |
| 14454649231 | 215,905 | `b00dc10e927692d37b3fc283b6937daa5fa7cff822ad7649d82988229ce3ff17` |
| 14458849599 | 2,341 | `0c3f790c50d5f50dcd7b6923479a4070b34e06ceee521b7db4fd494c802ca5f8` |
| 14459695622 | 35,628 | `75edfdea10a0e71dbf252d69e3aab967398b00499222611d0b2d8fcdda4c921c` |

## Review method and retained limits

`review_receipts.py` compares 18 inspected policy/workflow/source files against
their canonical Git blobs at the exact published commit. After those read-only
Git commands, its audit hook refuses subprocess and socket operations; no such
attempt occurred. It checks receipt ownership, recorded critical step outcomes,
artifact integrity, same-byte native outputs, and bounded finite scanner JSON.
Its successful execution is `review-final.log` and `review.json`. The command:

```sh
PYTHONPATH=/workspace/scratch/c7a9e8d98848/full-batch-path-review/src:/workspace/scratch/c7a9e8d98848/full-batch-path-review GIT_ALLOW_PROTOCOL=file GIT_NO_REPLACE_OBJECTS=1 /workspace/scratch/3a6632a6e5ff/venv/bin/python -B qa/hosted-55f3-receipt-review/review_receipts.py
```

This is an evidence read, not a test-suite or native qualification rerun. The
scanner's current 24-hour evidence-age checks were preserved; a much later
rerun may properly reject these now-historical receipts. Existing captures and
source snapshots are never silently overwritten. Original failed reviewer
attempts and helper versions remain with `review-setup-note.md`: an initial
empty API-envelope assumption was corrected using separately captured valid
responses; the second attempt exposed the static text-input omission described
above. Neither was hidden or reclassified as a passing full gate.

All raw API envelopes, exact decoded log strings and their UTF-8 files, original
artifact ZIPs, flat scanner evidence copies, inspected source snapshots, helper
versions, failed/successful reviewer logs, analysis, and this report are sealed
by the adjacent member manifest. Temporary signed download URLs were not
retained. No Git commit was created for this external read-only QA packet; the
parent may archive it without changing any source attribution.
