# PW-02 local package intake completion

Date: 2026-11-27 (America/Vancouver). Base: reviewed Winbindex/inventory publication
`6e324c1d27075292a1e6f46410c1176b3f0cd5fe`. Audited donor:
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a`.

## Plan and first verified part

The donor contains only portable foundations: package metadata, names, budgets
and worker accounting. It has no native extractor, held source/output stage,
supervised decoder, KB facade or frozen pair journey. Recovering its models alone
must not advertise PW-02 as a working intake capability.

1. Recover the five isolated pure modules, their current strict schemas, helper
   fixtures and eleven focused test modules; retain existing packaged-version
   implementation and tests unchanged.
2. Implement native Windows AMD64 held source/output I/O, verified system FDI ABI
   and decoder binding, with exclusive opaque output and accountable cleanup.
3. Integrate supervised header/recursive decoding, original shared budgets and
   deadline, exact full-byte revalidation and existing KB pair admission.
4. Qualify actual authored native CAB/CAB-form MSU, malformed/expansion/cancel/
   nested/cleanup cases and a frozen Windows full-PE pair journey, then independent
   exact-source review and hosted acceptance.

The spec, module registration and original test controls preceded the foundation
recovery. Baseline: **171 failed / 4 collection errors**, all missing capability
modules or generator. The exact recovered foundation passes **335 tests, no
failures/skips**, in **2.36 seconds**. Schemas were regenerated with the current
Pydantic runtime. Whole-tree Ruff and whitespace checks pass. Original red/green
logs and JUnit are retained under `docs/engineering/evidence/local-package-20261127/`.

The foundation has strict bounded records/identities, logical-name collision
refusal, sticky shared accounting with original monotonic deadline, and once-only
worker grants/receipts. Values that resemble native evidence are authored fixtures;
no Windows I/O, decoder, containment, native ABI or project-admission credit follows
from those tests. Subsequent native/service slices and their qualification remain
incomplete. No live provider or target binary was executed.

## Decoder ABI slice

The Microsoft SDK declarations were checked at immutable win32metadata revision
`a40ed3186943620f304649a077b78f8271034736` (`fdi.h`, `fdi_fci_types.h`). The new ABI
module uses fixed Win32 integer widths, pointer-sized handles, natural AMD64
packing and cdecl callbacks. Name pointers remain opaque until bounded callback
handling; ctypes cannot perform an implicit unlimited string read. All required
entry points are typed only after platform and layout checks. No DLL is loaded
by this module, and it does not advertise an available extractor.

The separately maintained C++ SDK probe checks callback and required entry-point
signatures at compile time and prints only structure sizes/offsets. Its Python
command supervises the authored compiler/probe with process-memory, time and
output caps and verifies bounded strict JSON. It executes no package payload.
A configured Windows AMD64 MSVC/SDK environment is mandatory; this Linux host
cannot qualify that native path.

Baseline **18 failures** established the missing ABI and checker modules. The
portable ctypes callback/64-bit-handle/signed-seek/opaque-name and strict-receipt
controls now pass **18 tests**, no skips, in 0.53 seconds. All package foundations
plus this slice pass **353 tests**, no skips, in 2.32 seconds. Required Ruff
(`src tests tools`) and whitespace checks pass. These are portable regressions;
actual SDK compilation and system DLL/decoder acceptance remain pending.

Primary pinned sources:
- https://github.com/microsoft/win32metadata/blob/a40ed3186943620f304649a077b78f8271034736/generation/WinSDK/RecompiledIdlHeaders/um/fdi.h
- https://github.com/microsoft/win32metadata/blob/a40ed3186943620f304649a077b78f8271034736/generation/WinSDK/RecompiledIdlHeaders/um/fdi_fci_types.h

## Independent ABI/checker review and output-total correction

Independent review of `c88187f2` fetched the exact pinned headers (`fdi.h` blob
`208d9211`, `fdi_fci_types.h` blob `647eef40`) and confirmed all eight callback
and four required entry-point declarations, sizes and offsets. The review found
one checker boundary defect: a quickly completed process could exceed output
limits before the supervisor's polling loop set a reason. A valid retained JSON
tail then incorrectly received credit. Original controls reproduced **2 failures /
4 passes** without running a native compiler, helper, DLL or package.

The checker now verifies final compiler stdout/stderr totals, final probe stdout
cap and exact equality of its full stdout total with retained bytes before parsing.
This remains a checker-local correction; general process supervision is unchanged.
The unchanged independent controls and maintained ABI controls pass 24 tests.
Two further controls cover an under-limit lost prefix and excessive compiler
stderr. The final 26-case corrective lane passes without skips; required Ruff and
whitespace pass. Original red and green receipts and the unchanged independent
controls are retained. Final independent corrective approval remains pending;
actual Windows SDK/DLL/held-I/O/extraction acceptance is still open.
