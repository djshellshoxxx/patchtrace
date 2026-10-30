# Bounded cJSON 1.7.16 → 1.7.17 source/debug/binary review

Reviewer: Codex `/root/literature`, 2026-10-30. Pair: `cjson-1.7.16-to-1.7.17-O2`.

**Outcome:** accept two source-lineage correspondences with surviving compiled security guards for this exact build; leave the other 111 label records unresolved for this review. The accompanying [cjson-acceptance.json](cjson-acceptance.json) classifies every original record key once and binds the original label content digest. This is a small development selection, not comprehensive ground truth for the release or a locked test.

**Exposure disclosure:** before this review the reviewer had seen the matching engine's two modified RVA pairs while implementing the raw observer. The review is therefore **unblinded**. Source differences, upstream release notes, compiler DWARF ranges, PE bytes and LLVM disassembly independently establish the selected claims; matching predictions were not used as the oracle. No target was executed, and no new matching/decompilation engine run was performed.

## Pins, license and provenance

| Item | Older | Newer |
| --- | --- | --- |
| Upstream release | `v1.7.16` | `v1.7.17` |
| Source commit | `cb8693b058ba302f4829ec6d03f609ac6f848546` | `87d8f0961a01bf09bef98ff89bae9fdec42181ee` |
| Engine DLL SHA-256 | `bed3ef087fd07161a14154d38c683b3f648611114bf9794bf91fba123d6f2d48` | `d3837c837ffff4eb90342b2b9d5d29cd023f72d3858c3a405a015cc180e963b4` |
| Debug DLL SHA-256 | `450c7ac3650a27f3bbc8ff15fe296c813ae7169e6ac71e4cd6f013af353cbdfa` | `9492b937cc3750baa2ab47a397c4a8b4efa423a8427dbf0e71b286bef76016a1` |
| `cJSON.c` SHA-256 | `fdfd427d82fadb395076567edf470c80cebee319e38fd417198508fe11ae56e7` | `de63e951ce3bc9b6938c7635575a6c90c3b364595b0b0f4c5ae8f9c83a43c17d` |
| `cJSON.h` SHA-256 | `c23de3b1227c1edc312be62c21b3324563c8180ddc04a826a412bd34bac13c9d` | `c01a8ca5609bb2c956dd1ae836d5d926ec68153ecebc5a75ea0febc2e076da8d` |

Both locally pinned `LICENSE` files are identical, SHA-256 `a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`, and contain the MIT permission grant with Dave Gamble/cJSON contributor attribution. Retain the copyright and permission notice when redistributing covered source or substantial portions. This review establishes the upstream source license; it does not independently audit the linked MinGW/runtime distribution's full notice obligations.

The local `tier-r-fetch/1` receipts identify the URL `https://github.com/DaveGamble/cJSON.git`, the two commits and release subjects, and mark acquisition verified. This session did not contact upstream or redo Git object verification. It recomputed both DLL hashes, both receipt hashes, all **99 recorded source-input hashes per build**, and source/license hashes. Every recorded input matched the pinned local tree. The sidecar retains these hashes and the fetch-receipt hashes.

Build receipts compile `cJSON.c` and `cJSON_Utils.c` with `x86_64-w64-mingw32-gcc (GCC) 13-win32`, `-O2 -g`, source-path remapping, and no added recipe defines. Linking uses `-shared -static-libgcc`, a fixed image base `0x180000000` and `--no-insert-timestamp`. This is the existing explicit recipe, not a claim to reproduce the upstream CMake build. No native MSVC build or Windows execution is represented.

Original label file SHA-256: `5084235aeaa865266539b3fae608c3ccc09394cbad734c540a517da3933fe6e9`.
Validated label content digest: `3e33941f984951fde5ee28870da9aaad8a7b3e6560a974e6d691ee908e3debe3`.

## Source changes and the security association

Direct textual diff and a separate significant-token comparison of the pinned source definitions agree:

| Source location | Reviewed difference | Interpretation |
| --- | --- | --- |
| `cJSON.c:cJSON_SetValuestring` | Reject NULL `object` before reading its type; reject NULL existing `object->valuestring` before the length/copy path. | Material validation change; the local 1.7.17 changelog associates it with **CVE-2023-50472** and issue #809. |
| `cJSON.c:cJSON_InsertItemInArray` | Reject NULL `newitem`; reject a non-head selected item with NULL `prev` before using that predecessor to splice the list. | Material validation change; the local changelog associates it with **CVE-2023-50471**, #809 and #810. |
| `cJSON.h` | `CJSON_VERSION_PATCH` changes 16 → 17. | Header-induced behavior change in `cJSON_Version`, despite an unchanged function definition. |
| `cJSON.c`, outside definitions | Compile-time source/header compatibility check changes 16 → 17. | Build consistency check, not another emitted function. |
| `tests/misc_tests.c:cjson_functions_should_not_crash_with_null_pointers` | Adds NULL/corrupted-node/string test inputs and restoration/cleanup. | Changed test definition; this translation unit is not linked by the reviewed recipe. Tests were read, not run. |
| `cJSON_Utils.c` | No changed definition tokens. | Does not by itself prove unchanged behavior for callers/dependencies. |

The 1.7.17 changelog dates the release December 26, 2023; its preceding entry dates 1.7.16 July 5, 2023. The reviewed security association is the upstream author's statement plus the actual source guards. No independent affected-version-range, exploitability, severity or CVSS claim is made here. A release-pair label is not a demonstration that every application using the old library is exploitable.

Local source evidence corresponds to these immutable upstream locations: [1.7.17 changelog](https://github.com/DaveGamble/cJSON/blob/87d8f0961a01bf09bef98ff89bae9fdec42181ee/CHANGELOG.md), [old library source](https://github.com/DaveGamble/cJSON/blob/cb8693b058ba302f4829ec6d03f609ac6f848546/cJSON.c), [new library source](https://github.com/DaveGamble/cJSON/blob/87d8f0961a01bf09bef98ff89bae9fdec42181ee/cJSON.c), [new header](https://github.com/DaveGamble/cJSON/blob/87d8f0961a01bf09bef98ff89bae9fdec42181ee/cJSON.h), and [license](https://github.com/DaveGamble/cJSON/blob/87d8f0961a01bf09bef98ff89bae9fdec42181ee/LICENSE). These links identify inspected local content; they were not newly fetched in this review.

## Independent compiled evidence and accepted scope

`llvm-dwarfdump-18 --name=...` was read directly, rather than treating the generated labeler's `check=ok` as acceptance. Each selected name has a unique inspected `DW_TAG_subprogram` with `./cJSON.c`, its declaration line, and concrete low/high PCs. Subtracting the actual PE image base gives:

| Function | Old RVA / size | New RVA / size | Surviving static instruction evidence |
| --- | --- | --- | --- |
| `cJSON_SetValuestring` | `0x2b80 / 174` | `0x2b80 / 190` | Old code reads `[rcx+0x18]` before testing `object`. New code tests `rcx`, branches to NULL return, then reads the type; later it tests the pointer loaded from `[rcx+0x20]` before the `strlen` path. |
| `cJSON_InsertItemInArray` | `0x3ab0 / 190` | `0x3ac0 / 198` | New entry tests `r8` (`newitem`) and branches to false. In the non-head splice path, a comparison of `[rax+8]` against zero branches to false before predecessor-link stores. The corresponding old path has no predecessor-null guard. |

The independently derived ranges match the exact original record keys. Raw body hashes differ across both patch endpoints and are preserved in the sidecar. On each side, every inspected range has identical bytes in debug and stripped DLLs. `loaded_view(debug) == loaded_view(engine)` also holds under the existing PE comparison's documented normalization. These checks bind the compiler's ranges to the actual measured artifacts; they do not prove global semantic equivalence.

This is defensible acceptance of **source lineage plus compiled local security-check changes**. The old implementation can have undefined behavior on the newly rejected NULL/corrupted inputs. Consequently this review does not invent a pair of defined old/new execution outputs, does not execute a crash trigger, and does not claim a formal semantics proof. `cJSON_SetValuestring` still has other caller preconditions, including its incoming `valuestring`; adding two guards does not establish universal input safety.

The sidecar accepts exactly these two records. All 111 others are placed in `ambiguous_keys` as **unaccepted under this bounded review**, not a claim that each is inherently ambiguous. There are no accepted unchanged controls, so this selection cannot estimate negative-change specificity or broad function-retrieval precision. The original labels remain untouched.

## Macro/global dependencies and evaluation limitations

The unchanged definition of `cJSON_Version` uses the changed header macro. Direct disassembly shows its stack argument to `sprintf` changes **`0x10 → 0x11`** at the same RVA `0x24a0`, size 56. This is a concrete counterexample to using unchanged source-span text as unchanged binary truth. The original record already says ambiguous; this review leaves it unaccepted rather than rewriting the source corpus. A future independently reviewed material version-string label would need a new label digest.

For context, `parse_string` has identical inspected source and 780-byte body at RVA `0x1400`, but it is not promoted here: byte equality alone does not establish all called-function, imported-runtime, global-data or hook behavior. The library's allocation hooks, inlined helpers and linked runtime remain dependencies. The reviewed header delta does not change the `cJSON` structure layout, but a header/type-layout or global constant change in a future pair could affect multiple untouched definitions. Transitive behavior must not be reduced to function-body edits.

**Visibility finding:** both stripped DLLs still contain **92 named PE exports**, including both accepted security functions and `cJSON_Version`. Thus this experiment strips debug information while retaining public export names. It is **export-name-visible**, even if a runner labels its debug-symbol setting `hidden`. It cannot substantiate claims about matching those public APIs with all names removed. The sidecar records export counts and the selected public names.

This pair contains one release transition, one compiler configuration and two accepted positive patch functions. Review exposure prevents a blinded-performance claim. No broad detection percentage, engine-independence claim or release acceptance follows from this note.

## Reinspection and sidecar validation

Inspection used the installed LLVM 18 commands over content-addressed `cjson.dll` files:

```text
llvm-dwarfdump-18 --name=cJSON_SetValuestring --name=cJSON_InsertItemInArray \
  --name=parse_string --name=cJSON_Version <debug-image>
llvm-objdump-18 -d --no-show-raw-insn -M intel \
  --start-address=<ImageBase+DWARF-RVA> --stop-address=<DWARF-high-PC> <debug-image>
llvm-readobj-18 --coff-exports <stripped-image>
```

Source input hashes, debug/engine hashes, body hashes, fetch/build receipt hashes and DWARF text hashes are in the sidecar. DWARF output text includes local file headings, so moving the store can change that text hash without changing the binary evidence. `select_truth(original_doc, review)` was run through the existing implementation and validated **2 accepted / 111 unresolved** records; its selected label content digest is `529ff3ab0fb52a2c8857c58e221c6669daa6674a34661c3940663eb6b07bba91`. No target execution or oracle replacement was involved.
