# PW-02: bounded local CAB/MSU intake

Status: implementation candidate in separate test-first slices. Native Windows
FDI, packaged-worker and frozen user-journey qualification remain pending.
Parent contract: [SPEC-31-D](kb-cve/31-D-acquisition-packages.md). This capability
does not change the symbol-server DownloadPlan or authorize remote retrieval.

## 1. Boundary and ownership

Only explicit local CAB input, including CAB-form MSU containers, is eligible.
The platform boundary requires Windows AMD64 before package reads, staging,
child launch or database mutation. Other systems return PT-ACQ-UNSUPPORTED.
Platform eligibility is not evidence of a usable decoder or native acceptance.
The first slice supplies pure contracts and that prerequisite; it advertises no
working extractor until the supervised native implementation is present.

The later worker uses Cabinet FDI callbacks through the system DLL, the existing
`jobs.run_process` supervisor/Job Object and application-owned handles. It does
not invoke WUSA, DISM, expand-all, a package executable, or a network provider.
Spanning cabinets, unknown encodings, native spill-file requests and unavailable
APIs refuse explicitly. A selected PA30/PA31/PSFX or other delta remains
needs-base/unsupported; extraction cannot turn it into a reconstructed PE.
Signature state remains `signature-unknown`; a CAT entry or index digest does
not authenticate source, product, build, applicability or chronology.

## 2. Strict versioned records and identities

`local-package/1` records are frozen, reject additional fields and coercion, and
carry finite bounded integers. The JSON reader refuses duplicate keys,
nonfinite values, malformed encoding, excessive bytes and unsupported versions.
Serialized IDs are lowercase SHA-256 values with exact length. Canonical IDs use
the existing domain-separated identity utility and preserve raw-name bytes.

| Record | Binding and interpretation |
| --- | --- |
| PackageFileIdentity | Captured Windows volume, nonzero 128-bit file ID, size and last-write FILETIME. A record is evidence data, not proof that the current pathname still names that handle. |
| PackageSource | Exact complete local digest/size, captured identity, redacted basename, inert source claims, signature unknown. Content identity excludes the selected path and timestamps. |
| PackageDecoder | Reported system FDI DLL digest/version, OS version, AMD64 ABI and probe state. Native qualification remains a separate pending gate. |
| PackagePart | Exact parent container digest, ordered ancestor member IDs, one-based ordinal, raw filename bytes/encoding and validated logical path. Member identity includes all those identity fields; duplicate/casefold/path-prefix collisions refuse within one container occurrence. |
| PackageContainer | Container digest/size/ancestry, observed entry count and explicit enumeration completion. Nested container ownership follows the exact verified parent member chain. |
| PackageInventory | Source, decoder, requested mode, captured limits, containers, parts, completion and bounded diagnostics. Inventory digest binds the complete serialized semantic record, including captured ownership and limits. |
| PackageSelection | Exact inventory/source/member/ancestor identities, side, safe expected PE basename and optional externally supplied expected digest. It is not a product or chronology assertion. |
| PackageUsage | Shared reserved/confirmed output, entries, containers, callback count, live/peak allocations, input-hash bytes and elapsed nanoseconds; failed attempts retain their charged budget. |

Per-member compressed size is nullable: CAB folders may share compression across
files. A header-only part has no observed size, observed hash, rehash or machine.
Decoded bytes have an observed hash and actual size equal to the saved declared
size. Reverified bytes additionally have a matching independently reopened hash.
Only a reverified, content-identified AMD64 full PE can pass selection; a filename
hint, decoded-only entry, delta, unsupported architecture or conflicting expected
digest cannot. Native I/O must establish those observations before constructing
the corresponding record; constructing a model alone is not verification.

`complete` means complete enumeration of the requested scope. Header mode has
only the outer scope and no materialized entries. Recursive mode is incomplete
while any recognized nested cabinet has no completed owned container scope.
Every retained part belongs to exactly one declared container occurrence;
ordinal and member IDs are unique there. A child scope must point through its
entire ancestor chain to a reverified CAB/MSU member whose observed digest/size
matches that child. A foreign, disconnected or circular scope is refused.
Completion does not mean every payload has been read or every claim verified.

## 3. Logical names never become host paths

`decode_member_name` accepts bounded bytes and the FDI UTF-8 flag. UTF-8 is strict;
an unflagged name is accepted only when ASCII, without guessing a code page.
The raw bytes remain part of identity. Slash and backslash are logical separators;
validated display preserves Unicode spelling and the collision key uses NFC plus
casefold. Refuse absolute, drive, UNC/device and ADS names; empty/dot/traversal
components; Windows devices including COM/LPT superscript forms; trailing dot or
space; controls/format/surrogate/private/unassigned characters; and illegal
Windows punctuation. Components are at most 255 UTF-16 code units, at most 64
components, and total raw length at most 1,024 bytes. Refuse both duplicate names
and file/directory-prefix collisions in either arrival order. Invalid names are
never echoed unescaped into diagnostics. Selected PE basenames use the existing
acquisition basename policy after ASCII case normalization.

Selected-basename admission checks the original basename for ASCII before any
case conversion. Unicode characters that lowercase to ASCII, including U+212A,
cannot match an ASCII expected basename. This does not change Unicode logical
inventory names or Unicode parent components around an otherwise ASCII basename.

## 4. One operation budget and deadline

All counters and one monotonic absolute deadline belong to the parent operation,
including both pair sides, recursive passes, discarded files and parent hashing.
No worker, new side or nested decoder gets a fresh operation budget. The first
implementation is serial. A later worker grant may only consume remaining budget
and the original deadline; returned consumption cannot restore spent allowance.

| Resource | Hard first-capability ceiling |
| --- | --- |
| Input per container | `2**31 - 1` bytes; conservative FDI signed-long seek limit below D6's 4 GiB outer ceiling |
| Reserved expanded output | 8 GiB across all materialization, including discarded and nested output |
| One emitted entry | 1 GiB and its saved declared size, whichever is lower |
| Observed entries / containers / depth | 50,000 / 256 / 4, shared across passes |
| Per XML / aggregate metadata / serialized JSON | 2 MiB / 32 MiB / 64 MiB |
| Diagnostics / raw member name | 1,000 / 1,024 bytes |
| Live callback allocation / worker process | 512 MiB / 1 GiB |
| Callback count / duration | 2,000,000 / 1,800 seconds |

Callers may lower limits but never raise ceilings; booleans, floats and strings
are not integer budgets. Reservations happen before output or allocation. Output
receipts distinguish reserved bytes from confirmed bytes. Each write reservation
has one owner and can be completed once. Short writes, unknown completion counts,
I/O failure, duplicate completion, foreign tokens, negative counts, expired time
or cancellation permanently fail the operation without refunding prior charges.
A materialized entry closes only with no pending writes and exact declared-byte
completion. Header-skipped entries have no output. Freeing an unknown or already
freed allocation refuses; peak memory remains recorded after a legitimate free.
Clock reversal/invalid clock values refuse. Reading/hash work consumes the same
deadline and work counter; hashing does not manufacture expanded output bytes.

An entry has at most one pending write reservation. If cancellation/deadline is
observed after a write reports its byte count, record those confirmed bytes before
refusing further work; an error must not erase known completed output. The raw
inventory JSON, including otherwise insignificant whitespace, must obey its own
captured JSON limit as well as the caller's limit. Constructed records also obey
that serialization ceiling. Header-only entries cannot claim a content-based
classification even when they omit an observed hash or PE machine.

The output counter bounds bytes exposed to application WRITE callbacks. It does
not claim to observe internal solid-folder prefix/gap decompression. Native work
is additionally bounded by the Job memory cap, parent deadline and cancellation.
Before materialization and during writes, the native stage must enforce at least
twice the conservative outstanding scratch estimate; no short/failed write can
produce an accepted inventory or project.

### 4.1 Portable serial worker grants and receipts

The worker accounting boundary is pure metadata and in-process accounting. It
does not start a worker, open a package, establish native handle identity, qualify
a decoder or admit a project. `local-package-worker/1` records are frozen and
strict, reject additional fields/coercion/nonfinite or duplicate-key JSON, and
have a hard 1 MiB wire ceiling. A grant/receipt also obeys the captured operation's
lower JSON ceiling. The existing package/source/member/inventory models remain
authoritative; worker records do not introduce alternate identities.
Grant and receipt envelopes require their literal contract and integer version
explicitly; an omitted envelope is not silently upgraded to this protocol.

`PackageWorkerBinding` contains exact SHA-256-shaped operation, request and attempt
IDs and the complete captured PackageSource. `PackageWorkerGrant` contains that
binding, a fresh opaque parent nonce, captured PackageLimits, original start and
absolute deadline, issuance time, quiescent cumulative PackageUsage baseline and
a canonical grant digest over those fields. The deadline is exactly the original
start plus captured duration; issuance precedes it. Source size and every baseline
counter obey captured limits. No pending entry/write or live allocation crosses
the parent-to-worker boundary. Grant creation consumes one original callback/work
unit, so empty serial grants cannot evade the work ceiling. The first grant binds
the parent's operation ID; later grants cannot change it. Attempt IDs cannot repeat.
The baseline includes at least that issuance work unit and cannot reserve more
output than its observed entry count times the captured per-entry maximum.

`PackageBudget.issue_worker(binding)` returns the exact parent-owned active grant.
Only one grant may be outstanding. Parent counter mutation while it is outstanding
refuses; clock/cancellation checks and snapshots remain available. A foreign or
copied grant object cannot act as that owner's control token. Nonce and digest
also bind the wire response, including otherwise identical operations. The caller
keeps the exact parent token; parsing a grant does not confer parent authority.

`PackageBudget.from_worker_grant(raw)` strictly parses a bounded grant and derives
the worker budget from its original start/deadline and cumulative baseline. It
does not call the ordinary fresh-budget path or reset any allowance. Its clock
cannot precede issuance. Worker budgets cannot issue another worker grant.

`PackageWorkerReceipt` repeats the exact grant digest and complete binding and
records cumulative usage, its last observed monotonic time, open-entry/pending-
write counts, and complete/failed status. Observation time is not a process-exit
claim. Complete requires zero pending entries/writes/live allocations, equal
reserved/confirmed output, and a nonfailed usage state. Failed requires a failed
usage state and retains known partial counters. `worker_receipt()` produces one
terminal record from a derived worker budget; unfinished work becomes failed.
No further work or second receipt is permitted, except owned allocation cleanup.
In particular, completing or failing an outstanding output token after receipt
emission refuses before changing confirmed bytes, consuming the token or changing
pending-entry counts. The original failure remains the reason. Before a terminal
receipt exists, a completed write still records its known bytes even when the
original cancellation/deadline was already observed; terminal immutability must
not erase that earlier completion evidence.

`reconcile_worker(parent_grant, raw)` validates the entire receipt before changing
counts: exact grant/source/operation/request/attempt, captured resource ceilings,
monotone cumulative counters and peak, original elapsed-time basis, issuance and
parent-observed time bounds. A successful receipt must have observed completion
before the original deadline. Reconciliation is once-only. A validated complete
or failed receipt's known consumption is retained before a later parent cancel/
deadline is surfaced; it cannot erase work already reported as completed. The
parent keeps its own current clock and original deadline for subsequent hashing
or another side, rather than adopting a child's earlier clock observation.
Because issuance requires all earlier entries closed, new output is bounded by
the number of newly reported entries times the captured per-entry maximum.
Reported open entries/writes can refer only to those new entries, including on a
failed receipt. These consistency checks do not prove that native writes occurred.

Malformed, oversized, mismatched, replayed, future-dated or overspent receipts
permanently fail the operation without partial counter mutation. A valid failed
receipt also permanently fails after retaining its known consumption. No later
grant or retry can recover remaining allowance. `abandon_worker(parent_grant)`
does the same for a missing receipt: retain known parent counters and mark worker
consumption unavailable, not zero or a fabricated complete reservation. The
`worker_pending` and sticky `worker_usage_unknown` properties distinguish an
outstanding grant and lost/unusable consumption from known usage. A rejected
replay after an already reconciled grant does not relabel its known usage unknown.

Reported JSON usage is protocol/accounting evidence only. Later native source,
sink, process and full-byte checks remain mandatory before content admission.
Core read-work checkpoint accounting is a separate later seam; it must not
silently redefine hashed-input bytes or consume decompressor output reservations.

## 5. Subsequent native and service slices

Native source and output handles stay anchored with no-reparse and identity
checks. Exclusive opaque files are created only under an owned private stage.
Basename handoff must rename through the held file handle without dropping the
identity locks. Reopen/hash/project-copy admission rechecks the same identity.
Cleanup deletes only owned handles/entries and retains uncertainty; a replaced
foreign path or sibling must survive every error/cancel path.

FDI callback bindings use exact pointer-sized types and the pinned Microsoft SDK
header. Exceptions are retained as failure and cannot escape as successful native
callbacks. COPY_FILE supplies declared output size. CLOSE_FILE_INFO's `cb` is
execution intent, not size; the application closes the output handle exactly
once, also on refusal. First capability refuses execution-marked files, cabinet
continuations and spill requests. No output pathname is supplied by an archive.

The KB package facade will compose with the existing WorkspaceStore and
KbService.import_pair. It captures workspace identity, investigation revision,
ordered advisory sources and finite saved scope before work and revalidates them
before admission. Both selected sides must be ready before project creation.
Metadata uses bounded immutable objects/additive typed tables; package payloads
do not enter the buffered gzip metadata API. A separate idempotent provenance
intent records a retained project if post-commit linking fails; no fake rollback
deletes committed evidence. No worker writes SQLite or creates a project.

### 5.1 Pinned AMD64 decoder ABI and SDK check

The native binding follows Microsoft win32metadata revision
`a40ed3186943620f304649a077b78f8271034736`, files
`generation/WinSDK/RecompiledIdlHeaders/um/fdi.h` and `fdi_fci_types.h`.
DIAMONDAPI is cdecl. Windows LONG/int/BOOL are signed 32-bit; ULONG/UINT are
unsigned 32-bit; USHORT is 16-bit; INT_PTR and pointers are pointer-sized. Native
names remain opaque pointers at this boundary, so ctypes must not implicitly
read an unbounded NUL-terminated string before callback code checks its bound.
The AMD64 declarations use natural packing; the SDK's special 32-bit packing is
not imported into this capability. Validate pointer width and every recorded
structure size/field offset before binding functions. Bind only the required
FDICreate, FDIIsCabinet, FDICopy and FDIDestroy entries; decryption is unsupported.
The ABI module itself performs no DLL loading, package reads or capability claim.

A separate native verification command compiles and executes only the maintained
authored layout/signature probe against the installed Windows SDK. Compile-time
checks cover all callback and required function signatures. Its bounded strict
JSON layout must match the pinned declarations exactly; unknown fields, duplicate
keys, booleans/coercion, or changed offsets refuse. A portable ctypes round trip
is useful regression evidence but is not a Windows SDK or system DLL qualification.
The compiler and probe are supervised with explicit memory, output and time caps.
After each process completes, its actual stdout/stderr totals must still obey
those caps; a fast process may finish before the supervisor polls its limit.
The probe's complete stdout total must equal the retained byte length before
strict receipt parsing, so a valid truncated tail cannot receive native credit.
Missing SDK/compiler is an explicit unavailable gate, never a fabricated pass.
The probe takes no package input and cannot execute a package payload.

Windows CI selects the installed AMD64 Visual C++ tools and SDK, then runs the probe
before the full test suite. Missing build tools or a mismatched layout fails the
Windows job. The step prints its measured receipt to the job log.

### 5.3 Supervised transient Windows handle transfer

`jobs.run_process(..., windows_borrowed_handles=None)` adds an optional in-memory
mapping from explicit child environment names to caller-owned Windows HANDLE
integers. It accepts at most 16 entries. Names match `[A-Z][A-Z0-9_]{0,63}` and
cannot collide, case-insensitively, with the supplied environment or another
binding. Values are distinct nonboolean integers, nonzero, pointer-sized and not
known process/thread/token pseudo handles. Package callers use task-specific
`PATCHTRACE_FDI_*` names. Empty/omitted bindings preserve ordinary callers;
nonempty bindings on other platforms refuse before spawning. Invalid bindings
are reported without echoing names or handle values.

Capture a bounded immutable binding list before launch. The caller retains each
original handle, with its existing access and inheritance flags, until the
supervised call returns. Under the existing Windows spawn lock, validate the
original with `GetHandleInformation`, then use `DuplicateHandle` within the
current process, `DUPLICATE_SAME_ACCESS`, and an inheritable duplicate. Never use
`DUPLICATE_CLOSE_SOURCE`, change original flags, or close a caller-owned handle.
Duplication does not provide independent file offsets or new access rights;
the caller must synchronize access and establish the correct initial access.

Every Windows launch, including one with no borrowed handles, uses
`STARTUPINFOEXW` and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The unique list contains
only the new standard-input NUL handle, standard-output/error pipe write handles,
and approved duplicates. Parent pipe readers, original borrowed handles, Job
handles and other inheritable handles are excluded. Attribute storage is bounded,
kept alive through process creation and destroyed on success or failure. Set
`EXTENDED_STARTUPINFO_PRESENT` with the existing suspended/unicode/no-window
flags and `bInheritHandles=True`. Creating suspended, configuring and assigning
the Job Object, then resuming remains mandatory; no fallback starts an
uncontained child.

The child environment receives each approved duplicate as an unsigned decimal
value under its explicitly supplied name. The input environment is unchanged.
This mapping exists only for that launch; handles are absent from grant, receipt,
provenance, accounting and persisted JSON. A trusted worker consumes the named
value and owns only its inherited duplicate, closing it when finished. Any worker
that starts descendants must remove these transient names and prevent unintended
further inheritance. The parent closes all its temporary duplicates and standard
child ends before releasing the spawn lock, on every setup outcome. Existing
process-tree termination, memory/output/time limits, cancellation and platform
behavior otherwise remain unchanged.

Portable controls may inspect authored pointer values above 32 bits and injected
Win32 success/failure paths; they do not establish native inheritance. Native
Windows controls must prove intended event/file access, exclusion of unrelated
inheritable handles, independent concurrent jobs, preserved original handles and
flags after setup failure or cancellation, and Job assignment before execution.
Linux qualification of those native controls is explicitly blocked.

Primary API contracts: [handle-list attribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[attribute-list lifetime](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist),
[extended startup](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw),
and [handle duplication](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle).

## 6. Verification and completion criteria

Portable authored controls qualify record/identity/name/budget mechanics only.
Native Windows acceptance must build/check SDK ABI sizes and signatures, exercise
real authored CAB and CAB-form MSU fixtures through the actual DLL, record source,
OS/DLL/process identities, and verify write budgets, malformed inputs, cancellation,
cleanup, nesting and held-handle handoff. A frozen Windows CLI journey must import
one authored full-PE pair through existing project admission. Unsupported Linux
behavior is explicit and cannot count as native success. PW-02 remains incomplete
until those receipts and independent source review exist.

Primary references and pinned header proof are retained in the approved design
packet `qa/pw02-local-package-design`; Microsoft documentation:
https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdicreate ,
https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdicopy ,
https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fnfdinotify ,
https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fnwrite .
