# R1 defined-behavior source pilot

This PatchTrace-authored MIT fixture is a development corpus input for the existing `suite/1` factory. It contains sixteen **candidate source-semantic mutations**, three identical-source controls, one comment/spacing control, one removed function and one added function. Both versions define 21 external functions; the union has 22 identities. The two C files are self-contained freestanding C11, with only `<stddef.h>` and `<stdint.h>`. There is no libc, file/network/process operation, real allocator, executable entry point or copied third-party source.

**Never execute the compiled targets.** Source formulas and distinguishing inputs below are review evidence, not recorded execution results. This is development/validation material, not a held-out test, and it supplies no engine-accuracy claim. The names and `suite.json` truth rows are authored candidate labels. A successful compilation does not establish that a mutation survives optimization or that a function remains separately emitted. The integration owner must bind source/debug/image provenance and independently review machine code before accepting binary labels.

## Defined input domain

Each function is reviewed on the same domain in v1 and v2. There is no old-version undefined behavior used as an expected result.

- Every `uint32_t` input is allowed; addition, multiplication and bitwise operations are unsigned modulo 2^32. There is no signed arithmetic that could overflow, no division by a variable, and no variable shift. `r1_signedness` only compares its `int32_t` argument, then v2 converts it to `uint32_t`; conversion of a negative signed integer to unsigned is defined modulo 2^32.
- A null data/record/descriptor pointer is allowed and rejected before dereference. A non-null pointer must refer to the live, initialized, correctly typed/aligned object or array specified below. No dangling, indeterminate or fabricated pointer is in the domain. No volatile objects, conflicting concurrent writes or data races are in the domain.
- `r1_bounds_added` and `r1_bounds_removed`: non-null `data` refers to at least **16 initialized `uint8_t` elements**. All `logical_length` and `index` values are allowed as scalar inputs; values with length > 16 or index >= 16 are rejected by both versions. A logical length may be smaller than the physical capacity. Both versions are physically memory-safe within this common domain. The mutation changes logical acceptance policy; it is not evidence that the old version performs an unsafe access.
- `r1_pointer_offset` and `r1_array_index`: non-null `data` refers to at least **four initialized bytes**. `index` may have any uint32 value; masking yields 0 through 3 after defined unsigned addition.
- `r1_loop_bound`: non-null `data` refers to at least **nine initialized bytes**, including when count=0. Both versions require this same physical array. The loop limit is min(count,8); v1 reads at most eight bytes and v2 at most nine. No iteration index can overflow. The sum is at most 9*255=2295.
- `r1_structure_field`: non-null `record` refers to one initialized `r1_record`. Layout is unchanged between versions. Compile-time assertions require offsets 0 and 4 for `requested` and `granted`.
- `r1_null_validation`: `marker` may be NULL or a valid pointer to a live uint32 object. Neither version dereferences it. v1 ignores it; v2 rejects NULL as a **policy error**. This is a real added validation branch on a total common domain, not a claim about a formerly unsafe dereference.
- `r1_allocation_size`: `allocate` may be NULL, which is rejected, or a valid callback with the declared ABI. `context` may be NULL or a valid object pointer understood by that callback. If called, the callback must terminate and have defined behavior for the requested size/context; the fixture returns its result without dereferencing it. Both versions reject count > 32, so requested sizes are at most 136 and 144 bytes. No real allocator is supplied or invoked in this task.
- `r1_call_target`: `operations` may be NULL or a pointer to a live initialized `r1_operations`. Each slot may be NULL, causing rejection, or a valid ABI-compatible callback. If called, callbacks must terminate and have defined behavior for the uint32 argument. The documented witness uses `r1_primary` and `r1_secondary`. Callback descriptors/functions may not change concurrently during the call.

`r1.c` uses compile-time assertions for the expected integer representation widths, defined unsigned wrap, signed-to-unsigned conversion, structure member offsets, and a size_t large enough for bounded requests. `R1_NOINLINE` expands to `__declspec(noinline)` for `_MSC_VER`, otherwise `__attribute__((noinline))`. The attribute is placed after the base return type and before any pointer star: `uint8_t R1_NOINLINE *r1_allocation_size(...)`. This placement is checked for host, MinGW and MSVC-target syntax and preserves concrete source definition extents for the existing AST-based checker. This is only an inlining constraint: the normal factory still has to prove each expected function remains emitted and is bound to a debug identity. The default freestanding factory disables identical-code folding and preserves unreferenced functions; altered nuisance/ICF builds may have different identity behavior.

## Precise source-diff and semantic ledger

All sixteen rows below map to `changed` candidate entries in `suite.json`. The row's category is the requested R1 coverage label; `kind` uses the existing suite vocabulary rather than introducing a competing schema. `other` is used for pointer offset, array indexing, callback target and structure field selection. The witness column is mathematical reasoning over the common domain, never a report of running a target.

| Function | Requested category; source edit v1 → v2 | Defined distinguishing input or observation | Why the source change is material |
|---|---|---|---|
| `r1_integer_constant` | Integer constant; `value+17u` → `value+29u` | value=0 yields 17 → 29 | Different uint32 return value; all inputs remain defined |
| `r1_comparison` | Comparison operator; `<13u` → `<=13u` | value=13 yields 0xb2 → 0xa1 | Boundary acceptance changes |
| `r1_branch_inversion` | Branch inversion; `(flags&4u)!=0u` → `==0u`, same branch bodies | flags=0,value=0 yields 0x23 → 0x55 | Existing branch outcomes are reversed; not a cosmetic inversion with swapped bodies |
| `r1_bounds_added` | Added bounds check; insert `if(index>=logical_length) return UINT32_MAX` | initialized data[3]=7, logical_length=3,index=3 yields 7 → UINT32_MAX | New logical-length rejection; physical index is safe in both versions |
| `r1_bounds_removed` | Removed bounds check; delete that same logical check | initialized data[3]=7, logical_length=3,index=3 yields UINT32_MAX → 7 | Logical acceptance widens while physical-capacity guard remains |
| `r1_pointer_offset` | Pointer offset; `data+1u` → `data+2u` | data=[0,7,9,0] yields 7 → 9 | Selects a different element of the same valid array |
| `r1_array_index` | Array indexing; `index&3u` → `(index+1u)&3u` | data=[4,5,6,7],index=0 yields 4 → 5 | Different wrapped ring slot; UINT32_MAX+1 is defined before masking |
| `r1_overflow_guard` | Overflow check; insert `count>UINT32_MAX/4u` rejection before multiply | count=0x40000000 yields 0 → UINT32_MAX | Replaces defined unsigned wrap with an explicit error policy; no signed overflow |
| `r1_signedness` | Signedness; `delta<8` → `(uint32_t)delta<8u` | delta=-1 yields 1 → 0 | Negative input classification changes using defined conversion |
| `r1_allocation_size` | Allocation size; callback request `4*count+8` → `4*count+16` | count=2 passes size16 → size24 to a valid recording callback | The callback argument is observable, even if it returns NULL in both versions; pointer result need not differ |
| `r1_loop_bound` | Loop bound; `index<limit` → `index<=limit` | nine-byte data with data[0]=5,count=0 yields 0 → 5 | Includes one more initialized array element; both loops bounded |
| `r1_call_target` | Call target; `operations->primary(value)` → `operations->secondary(value)` | slots={r1_primary,r1_secondary},value=0 yields 17 → 45 | Calls a different callback. Descriptor-slot offset changes, avoiding sole reliance on a masked direct-call relocation |
| `r1_error_handling` | Error handling; nonzero status returns0 → UINT32_MAX | status=1,value=9 yields 0 → UINT32_MAX | Distinct failure result with same success behavior |
| `r1_null_validation` | NULL validation; ignore marker → reject NULL | marker=NULL,value=7 yields 7 → UINT32_MAX | Adds policy validation without dereferencing marker in either version |
| `r1_structure_field` | Structure field offset; `record->requested` → `record->granted` | valid record{requested=3,granted=9} yields 3 → 9 | Field load changes from offset0 to offset4; layout itself is constant |
| `r1_security_flag` | Security-relevant flag; `flags|1u` → `flags|5u` | flags=0 yields 1 → 5 | Adds fixture-defined mandatory integrity-check bit4; no real product/CVE assertion |

A distinguishing witness establishes existential source behavior difference, not that all inputs produce different values. For example, callback slots may intentionally reference the same function, logical length may cover the selected index, a flag may already be set, or the extra loop element may be zero. The fixture names and descriptions encode intended policy for a synthetic program; there is no claim of discovered vulnerabilities.

## Controls and unmatched identities

| Function | Candidate relationship | Source proof and limitation |
|---|---|---|
| `r1_primary` | unchanged | Exact definition in both versions: value+0x11 modulo 2^32; external helper for call-target witness |
| `r1_secondary` | unchanged | Exact definition in both versions: value XOR0x2d; distinct behavior from primary |
| `r1_unchanged` | unchanged | Exact definition in both versions: rotate-left by5 using shifts5 and27, both less than32 |
| `r1_cosmetic` | cosmetic | Spacing and comment change only; significant token stream and source line count identical. Body equality still requires compiler/artifact review |
| `r1_removed` | removed | Only v1 defines value XOR0x39; no renamed correspondence to `r1_added` |
| `r1_added` | added | Only v2 defines value+0x67 modulo 2^32; behavior differs from removed interface |

The added and removed interfaces deliberately do not have a one-to-one rename relationship. A matcher may propose one from proximity or shape; that proposal must not rewrite the authored lineage. Preservation of unmatched functions is checked against the actual linked artifact and its independently obtained inventory.

## Indistinguishable endpoint identities found in independent source review

Independent review identified deliberate-source identities whose behavior and emitted bodies may be indistinguishable in a symbols-hidden comparison. v1 `r1_integer_constant(value)` and `r1_primary(value)` both compute `value+17u`. The bounds functions also exchange equivalent bodies: v1 `r1_bounds_added` matches v2 `r1_bounds_removed` (physical-capacity check only), and v1 `r1_bounds_removed` matches v2 `r1_bounds_added` (physical plus logical check). At a single endpoint, equal bodies can produce ambiguous candidate groups; across the pair, an engine may prefer a cross-name body match even though authored interface lineage says each named bounds function changed.

These are valid authored source identities, but the bytes alone cannot establish a unique named correspondence when endpoint code and surrounding evidence are indistinguishable. Report these groups separately or exclude them from definitive one-to-one correspondence claims. Do not change their authored labels to agree with future engine predictions, and do not present one arbitrary permutation as empirically unique ground truth. A reviewer must distinguish source lineage from what the symbols-hidden binary actually makes observable. The noinline directive and disabled ICF preserve separate emitted instances; they do not make equal code intrinsically distinguishable.

## Binary promotion and pending evidence

The stripped freestanding DLL has no executable entry point and this source deliberately injects no exported function names or symbol table for the evaluated engine. Merely retaining noinline leaf functions is not proof that a stripped disassembler can discover their starts. A run reporting zero discovered functions is an **observability failure**, not correct omission or successful correspondence. The integration owner may separately derive and record an existing-factory build configuration such as unwind tables that exposes function extents without leaking names. Keep that configuration, its flags, and its source/binary binding explicit. Ground truth may use private debug symbols/PDBs; the measured engine must not receive them or compiler-derived function names. Ordinary MinGW automatic exports would reveal names unless explicitly suppressed and must be reported as a distinct condition if used.

The source ledger is complete before compilation. To promote each candidate, the integration owner must use the existing `tools.calibration.tier_r.factory.run_suite` path, retain exact compiler/version/flags and suite/source digests, inspect debug-derived RVAs independently of evaluated matching, and compare old/new function bytes and instructions. The stripped engine image must be bound to the same code/RVAs as the debug image. For changed functions, investigate surviving memory offsets, immediates, comparisons, callback arguments and control flow rather than treating source text alone as binary truth.

The address-masked body hash is a coarse cross-check. For example, a direct-call target replacement could be masked away despite a semantic change; this pilot uses two callback descriptor slots to make the target selection visible as a load offset, while still requiring review. A compiler can fold equivalent controls or alter code shape; noinline alone is not proof. Any `check=disagree`, missing function, identical emitted changed body, unexpected induced change or uncertain source span remains a finding/ambiguity. Do not edit intended source labels merely to make engine results look correct.

This source-only handoff does not claim function-split/merge/inlining transformation coverage, Windows/MSVC execution, realistic vulnerability exploitability, real-project patch validation, or held-out accuracy. Those are different research strata and must retain their own evidence.

## Source-only validation recorded by author

On 2026-10-30, both source versions passed `/usr/bin/clang-18 -std=c11 -ffreestanding -fsyntax-only -Wall -Wextra -Werror` with exit0 and no diagnostics. This evaluated their static assertions and parsed source without generating or executing a target.

The existing `tools.corpus_check.check_suite` returned **0 findings**, using an explicit `/usr/bin/clang-18` resolver for this invocation because the generic `clang` executable was absent on the worker PATH. No global PATH or tool installation was changed. Strict `contracts.load_suite` accepted **22 truth rows**, and the existing `csrc.Source` locator found **21 definitions in each version**. Token cross-checking confirmed that all 16 changed definitions differ, while the three same controls and one cosmetic definition have identical significant token streams. The ordinary unmodified `python tools/corpus_check.py suite ...` command initially reported `BLOCKED: clang is not installed`; the explicit-path run resolves that tool-discovery limitation for source validation only.

No binary compilation, emitted-code survival, real-engine run or target execution was performed by this source author. The integration owner's separately recorded build/review receipts determine those statuses.


### Windows-target preflight correction

The integration owner's first Windows-target compilation found a real attribute-placement error in the allocator declaration: `uint8_t * R1_NOINLINE r1_allocation_size` placed `__declspec(noinline)` after the pointer star, which the MSVC target rejects. The original host-only syntax check had not exercised the `_MSC_VER` branch. Both source versions now use `uint8_t R1_NOINLINE *r1_allocation_size`, with candidate source semantics otherwise unchanged.

After correction, Clang 18 syntax-only checks of both files passed with `-std=c11 -ffreestanding -fsyntax-only -Wall -Wextra -Werror` under the host target, `--target=x86_64-pc-windows-msvc`, and `--target=x86_64-w64-windows-gnu` (all exit0, no diagnostics). The existing suite checker again returned 0 findings with the explicit Clang18 resolver, the strict contract retained 22 rows, and the source locator retained 21 definitions per version including the allocator. These are source syntax and structural checks; binary builds/engine acceptance remain separate integration evidence.
