# R1 defined pilot: independent source and binary review

Reviewer: `/root/truth_audit`, an automated research agent separate from the fixture author and experiment integration owner. This is automated independent review, **not human adjudication**. Review date: 2026-10-30 UTC. No compiled target is executed in this review. Inspection tools only read target files.

## Source version and annotation correction

Reviewed paths: `corpus/ours/r1-pilot/defined/{README.md,suite.json,v1/r1.c,v2/r1.c}`.

| Source | Current SHA-256 | Previously reviewed SHA-256 |
|---|---|---|
| `v1/r1.c` | `5f0468899fbc95fa4026c3c74b0731a5ab412fe017bbddbed00ad7b0d97acb5f` | `70ff6f14b3dc0a69a64cb243e393da9f406f1739a6750c0d42f1cb064cfef158` |
| `v2/r1.c` | `34d8d9f2a1c83c58565ed1885df192c5550e55b9ebb1716d978f8f1c51db27b7` | `62f2eab5866fb7114905af7bd584f784b59980d93ef79bcdef2dab3da4e15c37` |

The corrected declaration is `uint8_t R1_NOINLINE *r1_allocation_size(...)`; the earlier spelling was `uint8_t * R1_NOINLINE r1_allocation_size(...)`. There is exactly one corrected occurrence per file. Reversing only that occurrence **in memory** yields the exact previously reviewed hashes above. This establishes that the source delta consists solely of attribute placement. Function bodies, parameter types, pointer return type and the sixteen source mutation witnesses are unchanged. The existing source parser now includes the corrected declaration header at line 91 in v1 and line 94 in v2. This is a syntactic/provenance check, not a claim about compiler attribute semantics on untested toolchains.

Both C files contain 21 source definitions; the suite contains 22 union identities. The files are self-contained freestanding C11 inputs with no target entry point, external file/network/process activity, or supplied real allocator. All `R1_NOINLINE` definition spans were found by the existing source parser. The suite loads through the existing strict `suite/1` loader.

## Source behavior review

Within the README's common input domain, no undefined behavior was identified in this automated review. This is a bounded code review, not a formal proof over arbitrary platforms or invalid pointer inputs. The specified x64 integer widths, initialized array lengths, valid callback ABI, object lifetime, alignment and no-concurrent-mutation assumptions are part of the result.

The scalar mutations use defined unsigned arithmetic, comparisons, fixed-width bit operations or a defined signed-to-unsigned conversion. Physical array bounds are protected independently of the logical bounds mutations. The loop accesses at most nine initialized bytes under the common domain. Pointer offsets select elements of the stated live array. Both structure fields are initialized, and compile-time offset assertions constrain their layout. NULL validation is an acceptance policy change without a previously undefined dereference. The allocator fixture only calls a valid caller-supplied callback with bounded sizes; the fixture does not allocate or dereference the returned pointer itself.

Each of the sixteen README witnesses was checked algebraically against both source versions. They establish the existence of a defined distinguishing input or callback observation. They do not assert that every input distinguishes versions, that a real vulnerability exists, or that the mutation survives compilation.

Source-level ambiguity identified before examining engine predictions:

* v1 `r1_integer_constant(value)` and `r1_primary(value)` both return `value + 17` modulo 2^32 (decimal `17u` versus hexadecimal `0x11u`). They are mathematically equivalent; lexical or binary equality is a separate question.
* v1 `r1_bounds_added` and v2 `r1_bounds_removed` implement the same physical-capacity-only policy; v1 `r1_bounds_removed` and v2 `r1_bounds_added` implement the same physical-plus-logical policy. The source lineage of the two named functions is authored, but a body-only matcher may prefer the cross-name equivalence.

These cases require explicit ambiguity interpretation in a name-hidden evaluation. Authored source continuity is evidence of lineage, while equal observed bodies can leave the particular lineage mapping non-identifiable from local binary evidence. Do not change labels in response to engine output. Report this subset separately when interpreting 1:1 errors, or use a properly specified alternative/group relation in future structural evaluation.

## Binary configuration and binding

Configuration reviewed: **`msvc-free`, O2, Clang/LLD 18.1.3, x86_64-pc-windows-msvc**, pair `ours-r1-pilot-defined-v1-v2-O2`. This is a Linux-hosted Clang Windows-target build, not a native Microsoft compiler/Windows execution result. Build receipts specify freestanding C11, `/dll /noentry /nodefaultlib`, `/opt:noref /opt:noicf /incremental:no`, debug symbol generation and stripping. The receipt's `cflags` list is empty; **this review does not cover a later `-funwind-tables` observability variant**.

| Artifact | Older SHA-256 | Newer SHA-256 |
|---|---|---|
| Stripped `defined.dll` | `36d607e334544fcf98f81f77f46468e559ac849b01f1fd4f930c0a6ab5192294` | `7b856e5df7916986c3370062990027f4222ae38185006d667a4cd68e365eb5f4` |
| Debug `defined.dll` | `66908cc4642bb149aad74a23d1e641807edb874da008c3b488f5e74fb462b6ea` | `6418f198b730f03c7c1a5c70c395e8fee07637fb98e18c509e5205ee1eafb730` |
| PDB | `d69c89940cb99ef44ceb750a869206ae781978df36f5bca3ed2ae85d373f7473` | `02ce5f3648be28b3e3b56cb5e7f8550a314c503b95bb229a0ebd65c21f6c35d0` |
| Build receipt | `a30d0f685b2d9f196a04f7e0f6c9ae709c3970d85c7aba5b28e199f2e7c792d3` | `15dcb4f875438ef750a9e5444230ade8cb3e3f32773d0fb80ba59304ecbf1a6f` |

Exact label-file SHA-256: `8d103e56c0435346069df53149fe71865267b1e0d547d17246b6371c950644d2`.
Validated label content digest: `24ba952fbde62663524fa3a62033fdf7adfdaadafc8a7f803860a5c171522964`.
Recipe digest for both sides: `7c7b7d39a28c605d990b52c7d2386168f8adfef803a172daa55aaa7b861f6417`.

Every artifact hash above was recomputed from its actual bytes. Each receipt's `inputs.r1.c` matches the independently reviewed current source hash. The debug PE CodeView GUID and Age match the corresponding PDB summary: older `{AF296642-6F6F-9FBA-4C4C-44205044422E}`, Age 1; newer `{251EBE9F-28EC-18FC-4C4C-44205044422E}`, Age 1. The GUID comparison accounts for the PE GUID byte order.

The raw PDB procedure output contains **21 procedures per side**. An independently read procedure table (segment offset and size from `S_GPROC32`, mapped through the actual PE section RVA) exactly matches every present endpoint and extent in the label document. Image bases agree at `0x180000000`. Every reviewed function range is byte-identical between that side's debug and stripped PE. The existing `loaded_view` comparison also confirms equal non-discardable loaded section content/RVAs after masking only the documented debug-directory file-offset fields. Both stripped images have zero COFF symbols, an empty export directory `(0,0)`, and no `r1_` source-function-name prefix in their bytes. These images contain `.text` and `.rdata` but no `.pdata` section. This verifies the labels refer to the code supplied to a hidden-symbol engine; it does not claim that engine can discover every function.

Inspection commands, with actual content-addressed paths under `r1-pilot-store/images/`, were:

```text
/usr/bin/llvm-pdbutil-18 dump --summary --symbols <debug-dir>/defined.pdb
/usr/bin/llvm-readobj-18 --coff-debug-directory <debug-dir>/defined.dll
/usr/bin/llvm-objdump-18 -d --no-show-raw-insn -M intel <debug-dir>/defined.dll
```

`llvm-objdump-18 --version` reports Ubuntu LLVM 18.1.3. The machine-readable review stores hashes of all six inspector outputs, both receipts, full per-function raw-body hashes, source hashes and stable record keys. Inspector output includes local path headings, so a relocated reinspection can change the text-output hash while preserving artifact hashes and instruction evidence.

## Reviewed compiled changes

Raw byte comparisons use exactly the PDB-bound function extents, excluding inter-function alignment padding. All **16 authored changes have different emitted raw bodies**; all **3 unchanged controls and 1 cosmetic control have identical raw bodies**; the 2 authored one-sided interfaces have separate PDB-backed realizations only on their specified side. This was recomputed independently rather than inferred from the label document's `body` field or normalized-body hash.

The following instruction differences were read from the LLVM disassembly and checked against the source intent. RVAs are hexadecimal; sizes are bytes.

| Function | Old RVA/size → new RVA/size | Surviving compiled observation |
|---|---|---|
| `r1_integer_constant` | `1000/4 → 1000/4` | `lea eax,[rcx+0x11]` becomes `+0x1d`; identity caveat below. |
| `r1_comparison` | `1010/17 → 1010/17` | Compare immediate `0xd → 0xe` while retaining unsigned `cmovb`; inclusive source comparison survives via threshold adjustment. |
| `r1_branch_inversion` | `1030/13 → 1030/13` | `cmovne → cmove` after the same bit test and same branch-value calculations. |
| `r1_bounds_added` | `1040/29 → 1040/34` | New `cmp r8d,edx; jae` rejects index >= logical length; physical guards remain. |
| `r1_bounds_removed` | `1060/34 → 1070/29` | That logical comparison/branch disappears; physical guards remain. |
| `r1_pointer_offset` | `1090/16 → 1090/16` | Byte load displacement `[rcx+1] → [rcx+2]`. |
| `r1_array_index` | `10a0/19 → 10a0/21` | New `inc edx` before `and edx,3` and the indexed byte load. |
| `r1_overflow_guard` | `10c0/8 → 10c0/22` | Adds comparison against `0x40000000` and conditional selection of the multiplied value versus `0xffffffff`. |
| `r1_signedness` | `10d0/9 → 10e0/9` | Signed `setl →` unsigned `setb`, with the same comparison immediate 8. |
| `r1_allocation_size` | `10e0/32 → 10f0/32` | Callback request `lea rcx,[4*rcx+8] → +0x10`; indirect tail jump remains. |
| `r1_loop_bound` | `1100/111 → 1110/178` | New code forms `min(count,8)+1` (`inc r9d`) and uses changed unrolled/remainder loops. v1 has a zero-count return before the first load; v2's count-zero path reaches a one-byte remainder load. |
| `r1_call_target` | `1170/31 → 11d0/31` | Jump target loaded from descriptor offset 0 becomes offset 8. Both null-slot checks remain, with changed instruction ordering. |
| `r1_error_handling` | `1190/8 → 11f0/9` | v1 conditionally returns the value or zero; v2 forms a nonzero-status all-ones mask using `neg/sbb` and ORs it with the value. |
| `r1_null_validation` | `11a0/3 → 1200/11` | v1 copies `edx`; v2 forms a NULL-derived all-ones mask using `cmp rcx,1; sbb` and ORs it with the value. No marker dereference. |
| `r1_structure_field` | `11b0/14 → 1210/15` | 32-bit field load `[rcx] → [rcx+4]`, retaining NULL rejection. |
| `r1_security_flag` | `11c0/6 → 1220/6` | OR mask `1 → 5`. This is a fixture policy observation, not a real security finding. |

Controls: `r1_primary` (`11d0/4 → 1230/4`), `r1_secondary` (`11e0/6 → 1240/6`), `r1_unchanged` (`11f0/6 → 1250/6`) and `r1_cosmetic` (`1200/8 → 1260/8`) retain exactly equal raw body bytes across their own source-lineage endpoints. Removed `r1_removed` is at old `1210/6`; added `r1_added` is at new `1270/4`. Their source interfaces and emitted operations differ (`xor 0x39` versus addition `0x67`), and authored provenance declares no rename relationship.

This evidence supports source-intended material changes that survive this compilation, plus the stated unchanged/cosmetic controls. It is not a general equivalence proof, a dynamic test, or evidence about an engine's classification.

## Duplicate bodies and acceptance scope

Actual raw-body equality confirms the ambiguity identified during source review:

| Body SHA-256 | Equal realizations |
|---|---|
| `fa5b7eab57dd503aa341dd700389cb02e61dc21b29c0f2f0161329300ae705bd` | old `r1_integer_constant`, old `r1_primary`, new `r1_primary` (4 bytes each) |
| `91c2bb79fb60c0d032c3792b4fa1fbe1c55fb78cee961c8f3efdbcbfc84c019e` | old `r1_bounds_added`, new `r1_bounds_removed` (29 bytes each) |
| `7996def7ddaf136e19e590c34e42248391d35d39190c86195430a14e53559c9e` | old `r1_bounds_removed`, new `r1_bounds_added` (34 bytes each) |

These are distinct physical RVAs, so they are **not observed ICF aliasing**. `/opt:noicf` is explicit. The cross-name equality is real and cannot be resolved by byte identity alone. No matching-engine output was read or used to decide these groups.

The accompanying `acceptance.json` binds this review to the exact label digest and canonical keys `[file,name,variant,old_rva,new_rva]`. It retains all 22 reviewed identities, identifies the four ambiguous names, and selects **18 records** for strict identity evaluation: **16 same-identity pairs** (13 changed, 2 unchanged, 1 cosmetic) plus 2 authored one-sided records. The four excluded-from-strict-scoring records retain reviewed source/binary evidence, but their intrinsic identity caveat is explicit. Original labels are untouched. Filtering is a transient evaluation view, not relabeling to fit predictions.

No human review, independent rebuild by this reviewer, actual engine accuracy, peak memory, runtime performance, native Windows compatibility, MSVC compatibility, other optimization profile or later unwind-table variant is established here. Those require their own receipts and must not inherit this review's binary acceptance merely from identical source names.

## Separately reviewed MinGW GCC O2 cohort: export names visible

The same automated independent reviewer subsequently inspected the stock **MinGW GCC `13-win32`, O2** artifacts for `research-mingw-gcc-O2-r1-pilot-defined-v1-v2`, without reading matching-engine results. Source files are exactly the current reviewed hashes in the first table. The build receipts retain those hashes and recipe digest `e2406474b56cb867a7379124f7c906305eb009d0ba6c3e7f134d0e0c13fefd02`; the compile configuration is C11, O2, debug information and source/debug path remapping. Stock linking uses `-shared -static-libgcc -Wl,--no-insert-timestamp` with image base `0x180000000`. This is a distinct profile from the earlier freestanding Clang `/noentry /nodefaultlib` build.

| Artifact | Older SHA-256 | Newer SHA-256 |
|---|---|---|
| Stripped `defined.dll` | `c03b76a0e6db62ac35c5f4fa727f38cafdcfb5e7b8544c327b4c9587f8707b58` | `e2bb62115ca712b92bdd2382ec4071a08f37de89eaca0ed2ec07a03476bcec00` |
| Debug `defined.dll` | `82507c9e80aa0493860ca0b56a7400ec67dbda7ae3a32185aa19aaefa5b1b701` | `61d1c3f6444c3066ab5ebb13f9072ed97135fc05ac324016329555f4df1a5d0c` |
| Build receipt | `89dfb0eea80d7ca3f414cf6edea532097beb122872afe036a5a767c94e4dd20b` | `0734e959d5d692588d9a457fcf317d521cb1fce32755f76320a226f956c41633` |

Exact label-file SHA-256: `2c463d1bfd85bbef86b2056e437e46f8b668f91dbb48d058f123393271e504f2`.
Validated label content digest: `9653f54f4e56ab0510be07fdb40ad4f88cf2047002831c79708672b9869599fe`.

Raw `llvm-dwarfdump-18 --debug-info --recurse-depth=1` output independently identifies 21 project subprograms per side with declaration file `./r1.c`. Their actual `DW_AT_low_pc`/`DW_AT_high_pc` ranges exactly match every label extent. The source lines and declared pointer-return type of `r1_allocation_size` also agree with the corrected source. The embedded DWARF is bound by the debug image hash; there is no separate PDB in this profile. Every function's debug/stripped bytes and the normalized loaded-section view agree.

**This cohort exposes source names.** `llvm-readobj-18 --coff-exports` reports exactly 21 `r1_*` exported source-function names per stripped DLL, with the correct per-side RVAs. Stripped COFF symbol count is zero, but stripping does not remove PE export names. The actual engine images contain `.edata`, `.pdata`, `.xdata`, `.CRT`, `.idata` and other MinGW runtime sections. The supplied labels separately report 68 runtime functions, outside the 21 authored project definitions; that runtime count was not independently reclassified by this reviewer. Treat resulting matching measurements as a name-visible/export-visible cohort and never pool them into a name-hidden accuracy claim. Source names remain insufficient as the sole truth basis; the review also checked source construction, debug binding, actual bytes and instructions.

Independent project-range disassembly inspection confirms all 16 mutations survive this compilation and the four controls remain exactly raw-identical at their own source-lineage endpoints:

| Function | Old RVA/size → new RVA/size | Reviewed MinGW GCC observation |
|---|---|---|
| `r1_integer_constant` | `1390/4 → 1390/4` | LEA displacement `0x11 → 0x1d`. |
| `r1_comparison` | `13a0/14 → 13a0/14` | Compare threshold `0xd → 0xe`, followed by the same borrow-derived selection. |
| `r1_branch_inversion` | `13b0/15 → 13b0/15` | Conditional move `cmove → cmovne` after the same mask and branch-value calculations. |
| `r1_bounds_added` | `13c0/38 → 13c0/54` | Adds logical comparison `cmp r8d,edx; setae` to the rejection predicate. |
| `r1_bounds_removed` | `13f0/54 → 1400/38` | Removes the logical comparison while keeping the physical-capacity rejection. |
| `r1_pointer_offset` | `1430/22 → 1430/22` | Byte load displacement `1 → 2`. |
| `r1_array_index` | `1450/22 → 1450/22` | Adds `add edx,1` before the mask and load; alignment padding changes, so size happens to remain equal. |
| `r1_overflow_guard` | `1470/8 → 1470/22` | Adds threshold `0x40000000` and conditional selection of `0xffffffff`. |
| `r1_signedness` | `1480/9 → 1490/9` | Signed `setle →` unsigned `setbe`, both comparing against 7. |
| `r1_allocation_size` | `1490/35 → 14a0/35` | Callback argument displacement `8 → 0x10`; indirect tail jump remains. |
| `r1_loop_bound` | `14c0/68 → 14d0/72` | v1 zero-count early return and index `< limit` loop become an inclusive pointer-end loop that reads one element at count zero. |
| `r1_call_target` | `1510/38 → 1520/38` | Callback destination selected from descriptor offset `0 → 8`, while both slot checks remain. |
| `r1_error_handling` | `1540/8 → 1550/11` | Initial failure result `0 → 0xffffffff`; success conditional move remains. |
| `r1_null_validation` | `1550/3 → 1560/12` | Adds pointer test and conditional value selection versus `0xffffffff`. |
| `r1_structure_field` | `1560/22 → 1570/22` | Load displacement `0 → 4`. |
| `r1_security_flag` | `1580/6 → 1590/6` | OR mask `1 → 5`. |

Controls `r1_primary`, `r1_secondary`, `r1_unchanged` and `r1_cosmetic` have equal raw bodies at their own old/new extents. Removed `r1_removed` is present only at old `15d0/6`; added `r1_added` is present only at new `15e0/4`, consistent with authored source construction and export tables.

The project-only exact-byte scan finds the same three cross-name duplicate groups and no additional names requiring exclusion: the 4-byte add-17 group has hash `fa5b7eab57dd503aa341dd700389cb02e61dc21b29c0f2f0161329300ae705bd`; old bounds-added/new bounds-removed has hash `498b3e99bfa9318b474214a116e87879a7a55166347c31725a9d7ce5fccba12f` (38 bytes); old bounds-removed/new bounds-added has hash `af03715c0d21a2ec5d58309c6ba72161e48b8d3e076480a55cd4828a0d9ee623` (54 bytes). Their RVAs are distinct. Despite names being visible in this cohort, the predetermined conservative four-record ambiguity exclusion is retained, supporting a consistent strict subset rather than adapting selection to matching results.

`acceptance-mingw-gcc-o2.json` binds this review to the exact label digest, source/artifact hashes, inspector-output hashes and stable key partition: **18 accepted records** (13 changed, 2 unchanged, 1 cosmetic, 2 no-counterpart) and **4 ambiguous records**. Its evidence explicitly records the name-visible condition. This extends independent binary review only to the stated MinGW GCC O2 hashes; it establishes neither native-engine success nor name-hidden generalization, target execution, human adjudication, or other configurations.
