# R3 experiment E1 and semantic-classification benchmark contract

**Performed:** 2026-10-30. **Scope:** controlled *static object compilation and inspection*, not end-to-end PatchTrace classification. Experiment identifiers here are local E1-A..J, **not** SPEC-31 G-U gate results. No target object or executable was run. Complete object signatures and build commands were recorded locally at the time of experiment; binary outputs are intentionally **not committed**. See reproduction section.

## 1. E1 conditions, source and observed results

Tool versions actually reported:
- GCC `gcc (Debian 14.2.0-19) 14.2.0`.
- Clang `clang version 17.0.0` (`https://github.com/swiftlang/llvm-project.git` revision `10999b6d034fe318f3d56c83bddb6572593a8bb0`); Windows-targeted compiler `--target=x86_64-pc-windows-msvc`.
- GNU `objdump -dr` for instruction bytes and **symbolic relocation entries**.
- Common flags: `-std=c11 -ffunction-sections -fno-inline -c`; `-O0` or `-O2` as recorded. Inputs are freestanding functions with declared but undefined external symbols. The COFF objects have repeated COMDAT sections named `.text`, so sections were identified by **function symbol**, not guessed by `.text.<name>`.

Base functions, representative C (all pure arithmetic functions use `unsigned`):
```c
extern volatile unsigned global_a, global_b;
extern unsigned target_a(unsigned), target_b(unsigned);
__attribute__((noinline)) unsigned boundary(unsigned x) { return x < 16u; }
__attribute__((noinline)) unsigned threshold(unsigned x) { return x + 0x1234u; }
__attribute__((noinline)) unsigned mask(unsigned x) { return x & 0xffu; }
__attribute__((noinline)) unsigned read_global(void) { return global_a; }
__attribute__((noinline)) unsigned call_other(unsigned x) { return target_a(x); }
```
Mutants alter exactly one source occurrence per variant: boundary `<`→`<=`; constant `0x1234`→`0x1235`; mask `0xff`→`0x7f`; external symbol `global_a`→`global_b`; `target_a`→`target_b`. The two external-symbol swaps have **no definite output difference without assumptions** that the globals/callees differ. Therefore the ground-truth claim is **changed reference identity** with *conditional semantic difference*, not universally different behavior.

| E1 ID / target | Comparison | Disassembled instruction bytes equal? | Relocation entries equal? | Byte counts old/new | Instructions old/new | Ground-truth witness / interpretation |
|---|---|---|---|---|---|---|
| A / boundary | GCC O2 base ↔ same object | yes | yes | 9/9 | 4/4 | A/A positive control; does not test build repeatability |
| B / boundary | GCC O0 ↔ GCC O2, same source | **no** | yes | 19/9 | 8/4 | compiler-noise control, same C function semantics within defined domain |
| C / boundary | GCC O2 ↔ Clang O2, same source | **no** | yes | 9/9 | 4/4 | same C function semantics under compatible ABI and defined input, but different instructions |
| D / boundary | GCC O2 `<16` ↔ `<=16` | **no** | yes | 9/9 | 4/4 | material, witness `x=16`; **same size and instruction count** |
| E / threshold | GCC O2 `+0x1234` ↔ `+0x1235` | **no** | yes | 7/7 | 2/2 | material, return differs by 1 modulo 2^32, **same size/count** |
| F / mask | GCC O2 `&0xff` ↔ `&0x7f` | **no** | yes | 5/6 | 2/3 | material, witness `x=0x80` |
| G / read_global | GCC O2 `global_a` ↔ `global_b` | **yes** | **no** | 7/7 | 2/2 | changed referent; conditional value difference |
| H / call_other | GCC O2 `target_a` ↔ `target_b` | **yes** | **no** | 5/5 | 1/1 | changed callee; conditional behavior difference |
| I / read_global | Windows COFF Clang O2 global swap | **yes** | **no** | 7/7 | 2/2 | changed `IMAGE_REL_AMD64_REL32` symbol |
| J / call_other | Windows COFF Clang O2 callee swap | **yes** | **no** | 5/5 | 1/1 | changed `IMAGE_REL_AMD64_REL32` symbol |

Observed relocation labels:
- E1-G: `R_X86_64_PC32 global_a-0x4` vs `R_X86_64_PC32 global_b-0x4`.
- E1-H: `R_X86_64_PLT32 target_a-0x4` vs `R_X86_64_PLT32 target_b-0x4`.
- E1-I/J: `IMAGE_REL_AMD64_REL32` changed to `global_b` or `target_b`.
- The observed byte counts are from hex bytes printed by `objdump -dr`, associated with each symbol's disassembly. They're **not full PE function extents** or proof of semantic equivalence.

**What E1 establishes:** Address references may change while machine instruction bytes remain equal in relocatable objects, and small predicates/constants can change without changing instruction count. **What E1 does not establish:** That PatchTrace misclassifies any case; that linked PE bytes also match; verified data mapping; a false-benign rate, true-positive rate or statistical power. All E1 observations are static disassembly outputs; source witness analysis is mathematical/source-level, not native PatchTrace execution.

## 2. Reproduce E1 without running targets

Create a temporary directory and the five freestanding functions above. Produce the source variants and compile for each:
```sh
gcc -O0 -std=c11 -ffunction-sections -fno-inline -c base.c -o gcc_O0.o
gcc -O2 -std=c11 -ffunction-sections -fno-inline -c base.c -o gcc_O2.o
clang -O2 -std=c11 -ffunction-sections -fno-inline -c base.c -o clang_O2.o
clang --target=x86_64-pc-windows-msvc -O2 -std=c11 -ffunction-sections -fno-inline -c base.c -o coff_O2.obj
objdump -dr gcc_O2.o
objdump -dr coff_O2.obj
```
Repeat for the five variants; compare only disassembled instruction-byte columns *within the same named function*, and independently compare relocation symbol entries. Never treat `objdump -d` as the same thing as dereferencing a loaded PE. Record the C compiler binary hash, version and target triple for repeatability. All static parsing must bound input size, and no target binaries are executed.

For the next **product-level** experiments, drive the already present `tools/unified/mutations/driver.py` + `tools/calibration/tier_r/` and `tools/unified/gates` rather than importing this simple ELF/COFF diagnostic into the formal benchmark corpus. The existing registry has 12 generated mutant classes: `constant`, `comparison`, `bound`, `signedness`, `removed-check`, `callee-swap`, `field-offset`, `added-block`, `global-swap`, `index-swap`, `branch-swap`, `buf-resize`. Two remain **pending** in `classes.PENDING`: `moved-rva-call` and `try-scope` (requires MSVC SEH leg). These are fixture-generator capabilities, not verified success of PatchTrace classification.

## 3. Benchmark dataset schema and separation

Do not create a competing schema; adapt existing Tier R label records and `unified-result/1` rows with a small evaluation join. The analysis unit is a **(artifact pair, ground-truth function correspondence, change class)**; a label for a removed/inlined function must be represented separately from a normal 1:1 function pair.

| Field | Contents / integrity |
|---|---|
| `case_id` | Hash/ID of exact source/variant + build configuration |
| `lineage_id` | Source project and build family; one lineage stays entirely within train/dev/test |
| `old/new` | SHA256, arch, ABI, compiler name/version, flags, linker, optimization/security switches, timestamp |
| `class`, `truth` | No-change / benign layout / changed instruction/target/condition / uncertain; source reference and independent witness |
| `old/new function` | RVA, key, actual symbol or missing, scope, expected call/reference targets |
| `extraction` | Ghidra/Ghidriff/IR producer and options, relocation/import/SEH status, errors |
| `verdict` | L1 pairing status; L2 `ChangeFacts` verdict/proof/deltas/anchors; intermediate C0-C8 channel states |
| `runtime` | Start/end monotonic clock, peak RSS, decompile time, solver timeout, cancel or failure reason |
| `blinding` | Dataset partition and stable split SHA; final held-out test remains read-only until pipeline frozen |

**Critical label discipline:** A mutation that is compiled away or source-level change that yields identical binary behavior is **not** automatically a material positive. Confirm the emitted binary changed at the intended site, with correct target identity; the existing mutation driver already rejects equivalent artifacts for its checked conditions. If proof of material behavior is missing, the label must say “observed binary change, behavioral consequence uncertain,” not “proven vulnerability.”

## 4. Confusion matrix and required metrics

Report absolute denominators before rates. Example template (all cells deliberately **not measured** in this checkpoint):

| Ground truth ↓ / PatchTrace verdict → | unchanged | cosmetic | material | review | unknown | missing/error |
|---|---:|---:|---:|---:|---:|---:|
| Verified unchanged | — | — | — | — | — | — |
| Verified cosmetic transformation | — | — | — | — | — | — |
| Verified material/security mutation | — | — | — | — | — | — |
| Changed reference but behavior uncertain | — | — | — | — | — | — |
| Insufficient ground truth | — | — | — | — | — | — |

For `N_material` verified material pairs:
- **False benign / false unchanged** = `N(material→cosmetic or unchanged)/N_material` with two component counts also published separately.
- **Detection coverage** = `N(material→material or review)/N_material`; separately report `unknown`, `missing`, and unpaired. Do not collapse them to true negatives.
- **Material precision** on eligible adjudicated data = `TP_material/(TP_material + false_material)`; `review` is not a “verified material.”
- **Nuisance rate** on verified benign pairs = `N(benign→material)/N_benign` and `N(benign→review)/N_benign` separately.
- Stratify by mutation class, compiler, O0/O2/LTO, link mode, architecture, exception metadata, and confidence in L1 correspondence.

Show 95% uncertainty intervals; report the proportion of unknown/abstentions and failures. There is no legitimate numeric improvement percentage until **before and after** locked runs using the same distribution and exclusion policy are executed.

## 5. Prioritized next experimental matrix

| Priority | Pair/test | Evidence needed | Acceptance for this slice |
|---|---|---|---|
| P0 | IR+C6-equal + EH-`unavailable` | Isolated verdict unit test, code proof-version bump | `review`, never `cosmetic` |
| P0 | 12 generated mutation classes | Tier R factory + actual PatchTrace unified run | No material case→benign; material vs review separately |
| P0 | E1-G/H/I/J now **linked PE** with controlled A/B global/function definitions | PE image hashes, relocations, Ghidra target resolution, `ChangeFacts.targets` | Changed referent cannot pass `COS-ADDR`/`UNCH` |
| P0 | Pending moved-RVA-call | Two same-sized target definitions with deliberately changed link order and identical caller bytes | Changed actual callee reaches `review`/`material`; never `unchanged` |
| P0 | Pending `__try` scope | Native MSVC exception scope table with static PE parser evidence | `EH-EQ` reports differs or unavailable; never benign by omission |
| P1 | A/A rebuilt compiler/noise conditions | Same source/build, separately linked and no-security-flag mismatch | Measured material/review nuisance; real opt flag reported |
| P1 | Jump table, indirect call, CFG guard and /GS flags | Target/guard metadata and disassembly | Any omitted target produces `review`/`unknown`, no invented equivalence |
| P1 | True block reorder/inverse-predicate/swap controls | Paired CFG and branch polarity | Harmless inversion can be cosmetic only after complete proof |
| P2 | Bounded solver pilot for `boundary/threshold/mask` | Serialized formulas, explicit memory/ABI constraints, witnessed inputs and timeout | Adds testable evidence at measured cost, not automatic benign status |

## 6. Validation log (truthful execution ledger)

| Action | Result | Interpretation |
|---|---|---|
| Read PatchTrace `AGENTS.md`, source and specs | **Performed** on main `a04f5a2` through connected GitHub | File inspection, not execution |
| Compile 6 variants × 5 configurations (GCC/Clang/COFF) | **30 compilation commands succeeded** in isolated environment | Basic source/emission feasibility |
| Parse disassembly/relocations for five functions in each compiled object | **Performed**, E1 table above | Source-level and static output only |
| Run actual PatchTrace `unified run` on these cases | **NOT performed** | E1 must not be reported as semantic accuracy |
| Run `pytest` and `ruff` from PatchTrace checkout | **NOT performed** in the static experiment environment (no local checkout) | CI/current-head verification required |
| Execute G-U1...G-U8 on held-out Windows+Linux PE | **NOT performed** | R3 acceptance **open** |
| Benchmark p95 wall time or peak RSS | **NOT performed** | No runtime claim |
| Use solver/angr/Triton on paired PE | **NOT performed** | Feasibility review only |

The validated distinction is central: **10 static comparisons are not 10 successful PatchTrace classifications**. Preserve this wording in any release report.
