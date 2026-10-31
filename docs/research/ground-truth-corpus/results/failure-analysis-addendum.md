# R1 bounded failure analysis: compiler noise and two materiality abstentions

Reviewer: `/root/truth_audit`, independent automated research agent. Date: 2026-10-30 UTC. Analysis only: no algorithm, threshold, label or test changes; no target execution. Earlier source/binary acceptance was completed before this review of matching results. This addendum does not retroactively tune that acceptance.

## Evidence and scope

The existing unified store reader verified the manifests and read **71 result rows and 71 ChangeFacts records** for each case. Primary raw JSON bytes were rehashed against their recorded run SHA-256 before inspection. The analyzed source domain is the reviewed fixture's live initialized arrays/objects, unsigned arithmetic and valid ABI-compatible callbacks. It does not cover arbitrary invalid pointers, asynchronous unwinding or universal whole-program equivalence.

| Case | Pair/result ID | Receipt SHA-256 | Stored facts-part SHA-256 |
|---|---|---|---|
| Same source, GCC O2 → Clang O2 | `noise-defined-v1-mingw-gcc-O2-mingw-clang-O2`; result `70f6197422a48226` | `ce69183eacf2bcacd2341020b859e14dfda8cc6268a8204e3662b595ce13ce6e` | `3ca40c1b0893c354fd40f5dbc2f34681c78f3e6a93298722a4df9df2b5fa6b76` |
| Reviewed GCC O2 v1 → v2 | `research-mingw-gcc-O2-r1-pilot-defined-v1-v2`; result `d4025ab63fdb0a5c` | `9c1f491418095f2552b1f33009c253e479f295f8e259a3cf03f255b9e765e277` | `732838f00910ab650a66d9b6cfd3159c4f1b8c520598fa0c254b65456cdf7593` |

Receipts are `/workspace/scratch/a55b59b3e326/r1-evidence/pilot-compiler-noise.json` and `pilot-mingw-gcc-o2.json`. The first primary run is `180740a9-e4cc-4469-8b46-5f0a2900c2ba`; the second is `32482391-c4b4-49aa-8e3d-f94abde47097`. Each result's `facts.jsonl.gz` and `rows.jsonl.gz` live under that run's `unified/results/<result-id>/` directory. These hashes identify the inspected snapshots, not a claim that future reruns must preserve wall-time-bearing receipt bytes.

## 1. Same-source compiler control: three false material classifications

The control compares the **same v1 source**, MinGW GCC O2 against MinGW Clang O2. Its label digest is `81fe7c29372134b2ba1efa5f958ee42629e22c71b722089e7dfc02085afaac8c`. The receipt is explicitly `exploratory-candidates`, without a separate accepted-selection review. Across the 21 labeled project functions, unified has 21 explicit source-lineage correspondences, **3 material classifications and 18 review/unknown change outcomes**. The 18 review outcomes are not successful unchanged classifications. Runtime rows account for much of the larger 71-row stored result and must not be mixed into the 21-function denominator.

The three material functions were checked directly against the source and actual GCC/Clang instructions. They preserve the reviewed function's ordinary input/output behavior within the common domain, despite different instruction sequences. This is stronger evidence for these three specific false material classifications than merely asserting same source implies equivalent machine code.

| Function; old/new RVA | Stored classifications and channels | Reviewed semantic interpretation |
|---|---|---|
| `r1_comparison`; `13a0 → 13a0` | Classes `eh,constant,unknown`; C0/C1/C2/C3/C5/C6 differ, C4 equal, C7/C8 unavailable; second channel **C6**; no proof or limits hit | GCC computes `(-(x<13)&-17)+178`, giving 161 for true and 178 for false. Clang selects the same `0xa1/0xb2` values with `cmovb`. The apparent `-0x11 → 0xa1` literal difference is a lowering difference, not a source-policy change. |
| `r1_bounds_removed`; `13f0 → 13f0` | Classes `condition,block-added,eh,cfg,unknown`; C0/C1/C2/C3/C6 differ, C4/C5 equal, C7/C8 unavailable; second channel **C3**; no proof or limits hit | GCC combines rejection predicates using setcc/OR; Clang branches on them separately. Both reject NULL, length >16, physical index >=16 and logical index >=length, then read the same byte. Condition ordering and block partitioning differ. |
| `r1_loop_bound`; `14c0 → 1490` | Classes include condition, struct-offset, block-added, constants, CFG, register-only, unknown and EH; C0/C1/C2/C3/C5/C6 differ, C4 equal, C7/C8 unavailable; second channel **C6**; no proof or limits hit | GCC loops over `min(count,8)` bytes; Clang unrolls the same sum with count-boundary checks. Both return zero at count 0, sum exactly the first min(count,8) bytes otherwise, and return the sentinel for NULL. The unrolled offsets and comparison constants are not new semantic bounds. |

Stored row IDs respectively:

* comparison: `329efcd7f64a08b86be0d18160f23e5a72ec38308634542a2a8bd473ec09ad1e`
* bounds: `ec6435b9f7905b1385f1f5338be8f5c8765ca4c1566315be5bf3a14eb08ee578`
* loop: `960416271223f8c3ede22b6957603f0fd6caecde124d3cc2d74080e7c333724f`

The decompiler also emits different inferred signatures and expression shapes: for comparison, GCC's integer arithmetic form becomes a conditional selection with an inferred `undefined8` result; for the loop, the inferred parameter types and control structure differ. These are recovered representations, not changed source declarations. Actual instructions support the same reviewed return-value semantics. All three facts have EH `differs`: GCC has a plain unwind signature while Clang's relevant leaf view lacks one. That is metadata evidence and blocks some unchanged proofs; it does not by itself establish changed ordinary fixture behavior or explain material promotion without a second anchor.

### Demonstrated store/effect classification defect

A read-only examination of the **actual stored IR** for `r1_bounds_removed` found a concrete evidence-classification defect. `facts/operands.py:is_store` excludes `JMP` in `NON_WRITING`, but does not exclude conditional branches. Its address-operand rule therefore classifies direct Jcc instructions as memory writes when their target operand is `VK_ADDRESS` with a located offset.

For this exact stored newer function, `JNC` at RVA `13f8`, `JZ` at `13fd`, and `JA` at `1402` and `1408` all return **`is_store=True`**, although they are control transfers and perform no memory write. All call flags are false; the function has no call records. Consequently, `holds_effect` returns true for the corresponding conditional-only blocks. The older JNZ/JZ terminators show the same misclassification.

`layout.compare_cfg` annotates unmatched blocks using `holds_effect`; `anchors.anchor_for` permits a block-change C3 anchor when that effect flag is true and block/edge counts differ. The stored bounds result reports C3 as its second channel. This establishes a concrete erroneous effect signal contributing to the available material-promotion path. No policy threshold or label change is needed to demonstrate the defect. A narrowly coordinated future fix should first regress Jcc-not-a-store and this fixture; **no such algorithm fix is part of this addendum**.

Exact affected modules are `src/patchtrace/unified/facts/{operands,layout,anchors,verdict}.py`; decoded record types are in `src/patchtrace/unified/ir/ins.py`. A minimal input copied from the stored newer IR is:

```python
from patchtrace.unified.ir.ins import Insn, Op
from patchtrace.unified.facts.operands import is_store

instruction = Insn(
    rva=0x13f8, raw=bytes.fromhex('7317'), mnem='JNC', flags=2,
    flow='CONDITIONAL_JUMP',
    ops=(Op(vkind=4, optype=8256, value=0x1411, offset=1, length=1, regs=()),),
)
# Observed in the reviewed implementation: is_store(instruction) == True.
# Correct architectural interpretation: conditional control transfer, no memory store.
```

For R2 reproduction, the immutable stored IRs are under the compiler-noise run's `unified/ir/`:

| Side/directory | IR SQLite SHA-256 | Canonical content digest |
|---|---|---|
| GCC older `7471f004fb39774f` | `469cb1f953f77f8b81c09189b3b3dd9537ee49e2b7f87b81454bc6fb8f7857f5` | `7d848edb437ef6f5de8915387aca114e9bb1d02d643a94f49d524f6b935f4118` |
| Clang newer `ee04497b5bfa299c` | `618d8d13fed7bf9af1ef42fc6f0376419d0da8c75e2ad9c757dc7d1bd87bb92a` | `dc5664efa7352a84fe722202454f892956a278dacf0061ebe0b6a172859b80e5` |

The corresponding manifest byte hashes are older `19c3337233fb0c2527936bc96f7639cf050cf35a306a08fed21cd9bcf92cb3a6` and newer `b6126f7461d698ddb6ebbf48ddac242e4eb91ca7180b0dc91158b48b55fc1d21`. Both were opened with verifying `IrReader.open`; the inputs identify function RVA `13f0` on each side and exact instruction RVA `13f8` on the newer side. The original material classification and result-part hashes above must remain preserved if a later R2 fix changes the verdict.

The other two rows show a different limitation: changed machine constants/operators and changed decompiler constants/operators can refer to two compiler lowerings of the same behavior. The MAT-ANCHOR check detects matching forms of representation change; this observation disproves treating those anchors as sufficient proof of semantic change across compilers. The bounded analysis does not propose tuning on these observations or claim to solve general semantic equivalence.

## 2. Reviewed GCC mutation pair: two abstentions despite correct identity

The mutation receipt uses the independently accepted subset: 16 same-identity pairs, including **13 material changes**, with four predetermined ambiguous records counted separately. Unified correctly pairs all 16 accepted pairs. It marks **11/13 material** and leaves **2/13 under review**. This is unconditional material detection `11/13 = 0.84615…`, with two unknown material verdicts and zero material changes incorrectly marked unchanged/cosmetic in this subset. Identity success does not turn those two unknowns into change detection.

### Signedness

`r1_signedness`, old `1480` → new `1490`, row `883abdf0753e56cecac158e9c38bc2a3634181ba572817480e0cd0ee03f0cba5`, is matched but review. Its single semantic delta is C2 `comparison`, **`SETLE AL → SETBE AL`**. C0–C3 differ; C4/C5 are equal; C6 differs; C7/C8 are unavailable; EH is equal; `second_channel=null` and no proof/limits hit.

The persisted decompile part contains `return param_1 < 8;` on both sides. Its parameter type changes from `int` to `uint`. `anchors.anchor_for` checks changed relational/logical operator multisets for comparison/condition anchors. Those operators remain `<`, so a general C6 difference does not satisfy the same-change check. The source and instruction review already established a real signedness effect at input -1 (1 →0). This is a **type/signedness-sensitive anchor coverage limitation**, not a failed correspondence or an unchanged classification.

The persisted mutation result `decomp.jsonl.gz` hash is `c1f883c31d498d37e5000144ec798b444c83faca4e844dd09b47fcf9f4ee62c7`, binding these exact recovered code snippets.

### Indirect callback target

`r1_call_target`, old `1510` → new `1520`, row `cf7179af199d42767705234da4448aa3a374f352eaae70a91e617ed3365878e1`, is matched but review. Its deltas are register-only plus unknown added/removed instructions. The compiled code changes which descriptor slot supplies the indirect jump target: old offset 0 versus new offset 8. Both slot-null checks remain, with changed register assignment and instruction ordering.

C0–C3 differ; C4/C5 are equal; **C6 is unavailable**; C7/C8 are unavailable; EH is equal; `second_channel=null`, no proof/limits hit. The call channel does not resolve the two indirect destination expressions as distinct source callbacks. The operand alignment leaves the changed loads in unknown deltas rather than a recognized semantic target/offset delta. The current on-demand decompile selector considers first semantic constants/comparisons/conditions/structure offsets; this row has no such classified semantic delta and therefore does not receive that fallback. This explains the persisted absence of C6 without asserting an external decompiler failure. The reviewed source callback witness still distinguishes the two versions under the stated callback domain.

## 3. Primary modified output and evidence dependence

For the compiler-noise control, Ghidriff lists **21 project functions as modified**, but the raw `diff_type` histogram is: refcount 21, address 18, code 6, length 6, signature 3. A modified row therefore includes code/metadata/representation changes; it is not a semantic-materiality verdict. The experimental observer correctly records a generic primary change signal rather than pretending it is independent semantic truth. Conversely, absence from modified does not prove unchanged behavior: the signedness and callback mutation rows have explicit address correspondences without a corresponding primary modified row in this receipt.

Ghidriff and unified reuse Ghidra programs, disassembly, function discovery and decompiled text. These channel observations are **not independent engine replications**. C2/C3/C6 are separate representations/filters inside the same analysis lineage, and shared function-boundary or decompiler errors can correlate them. A stored second channel is an implemented decision condition, not statistical independence, a probability, or a semantic proof. No engine scores were averaged in this analysis.

Follow-up scope is now concrete: regress and repair the demonstrated conditional-branch effect classification through the normal coordinated spec/test process; separately evaluate cross-compiler lowering invariance and type/indirect-target coverage on fresh development cases before changing semantic promotion. Preserve these original receipts and report any subsequent corrected run as a new experiment.
