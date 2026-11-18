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
https://learn.microsoft.com/en-us/windows/win32/api/fdi/nc-fdi-pfnfdinotify ,
https://learn.microsoft.com/en-us/windows/win32/api/fdi/nc-fdi-pfnwrite .
