# R8-IDENT-02 — source-level identity is not a unique RVA under identical-code folding

**Finding:** confirmed static compiler/linker counterexample.  
**Scope:** linked Windows x64 PE export records; **not** a measured PatchTrace mis-match.  
**Environment:** Clang 17.0.0 `clang-cl`, LLD 17.0.0 `lld-link`, `llvm-objdump -p`; Linux host producing AMD64 Windows COFF and DLL outputs. No target was executed.

## Hypothesis

A one-to-one matcher which assumes one exported source-level function always maps to one distinct entry RVA will fail when the linker folds separate functions with identical machine code. An algorithm may avoid falsely attributing one to the other only by representing the ambiguity explicitly. This distinction matters for matching, patch attribution and training labels.

## Minimal source input

```c
__declspec(dllexport) int first(int x) { return x + 1; }
__declspec(dllexport) int second(int x) { return x + 1; }
```

`icf_pair.c` SHA-256: `337e41a6a5267225f6a1d674e9eb4156c32c7eb7d244f636bbfc44bb4fe76b81`.

Build the same source into a single object, link it twice:

```bash
clang-cl /O2 /Gy /c /Foicf_pair.obj icf_pair.c
lld-link /dll /noentry /nodefaultlib /machine:x64 /opt:icf /Brepro /out:icf_on.dll icf_pair.obj
lld-link /dll /noentry /nodefaultlib /machine:x64 /opt:noicf /Brepro /out:icf_off.dll icf_pair.obj
llvm-objdump -p icf_on.dll
llvm-objdump -p icf_off.dll
```

**Observed export table:**

| Function | Link with `/opt:icf` | Link with `/opt:noicf` |
|---|---|---|
| `first` | RVA `0x1000` | RVA `0x1000` |
| `second` | RVA `0x1000` | RVA `0x1010` |

Both passes used the same source and object. In the folded build, distinct externally named functions share one machine-code entry. The linker's output is valid even though the source-to-entry mapping is no longer injective. No function was renamed or edited between builds.

**Repeatability:** the stdlib probe `tools/research/r8_icf_probe.py` was executed twice under separate temporary working directories and, with `/Brepro`, both runs produced the same export tables and DLL digests:

- `icf_on.dll` SHA-256: `81e4dc0661f031715f8b3f625e813ac80d5540f15a91a77b4d8fddf1e564823e`
- `icf_off.dll` SHA-256: `950b0fac65587bba84dbfc61ee76b6942e9b517b0462a694fdbd77330295ff20`

The probe returns exit 0 and `status=PASS` when aliases exist only with ICF, exit 1 if the test fails, or exit 3 `BLOCKED` if required LLVM tools are absent. It runs the trusted compiler/linker and reads the DLL export table; it never executes the DLL.

## Algorithmic implication

Three different identities coexist:
1. **Source lineage:** `first` and `second` are distinct named definitions.
2. **Linker/code identity:** `/opt:icf` merges them into one code region.
3. **Binary function / RVA identity:** there is one machine-code entry `0x1000` with two symbolic export aliases.

A claim such as `old first ↔ new first` is unsupported by RVA equality alone when one or both sides have aliasing. Mapping the old **one code region** to multiple new regions may be sound as a *group/candidate relationship* without making a unique lineage claim. Similarly, `first` moving to a new RVA does not by itself indicate a patch.

Existing PatchTrace matching may already preserve groups/ambiguity; this experiment **does not show the application currently makes an incorrect match**. It falsifies only the global one-to-one assumption. Do not count two export aliases as two independent evidence points when they share code.

## R1/R2 acceptance packet

- Incorporate both PE variants into Tier R with pinned toolchain, fixture hash, source identity and original export aliases.
- Examine the actual Ghidra function inventory and BinExport/secondary results. Determine whether the extractor emits one region, two overlapping functions, or a multiple-alias record; preserve raw contradictory representations.
- Run old `ICF off` → new `ICF on`, reverse direction, and `ICF on` → same `ICF on` with symbols hidden from matchers but visible to truth labelers.
- Expected: neither forced distinct 1:1 pairs nor false `added/removed`; contested/group or unresolvable identities must retain source-level uncertainty. A/A should not fabricate a change.
- Evaluate G-U3 with **independent lineage units**, not both aliases as separate statistically independent functions. Check cached result identities and all one-sided endpoint coverage.
- Add compiler variants: `/Gy` on/off, `/GL`/LTO, COMDAT aliases, cold splitting and thunks; document when ICF is inapplicable.
- Native Windows/MSVC cross-check pending. No production matcher change without a red end-to-end counterexample and R1/R2 ownership coordination.

## Evidence classification

**RESOLVED—VALIDATED, narrow scope:** static PE export aliasing produced by Clang/LLD ICF vs no-ICF, twice with identical SHA outputs.  
**UNRESOLVED—MORE DATA REQUIRED:** PatchTrace's extraction, matching and verdict behavior, and its error rate on actual folded vendor binaries.
