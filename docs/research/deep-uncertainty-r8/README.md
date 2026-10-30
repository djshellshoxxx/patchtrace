# R8 — deep technical uncertainty and adversarial validation

**Research branch:** `research/r8-deep-uncertainty-20261030`  
**Reconciled baseline:** `main` `a04f5a299a8d4afef023261e52e08d14678cf1e7`, 2026-10-30 UTC.  
**Status:** active; provisional research and isolated compiler experiments. **No production acceptance / release claim.**

## Ownership and boundaries

At reconciliation R1 #128 owns ground truth, R2 #131 matching/fusion, R3 #129 semantics/verdicts, R4 #130 provenance/CVE, R5 #132 calibration, R6 #133 integration/release and R7 #134 higher-level binary analysis. R8 does not edit their branches, consume private samples, merge unverified results, enable calibrated probability or broaden a vulnerability attribution. Shared `docs/qa.md` and `tasks/todo.md` have active integration owners; integration-ready proposed entries remain here until coordinated.

Use this workspace to test **false benign claims first**, distinguish source-code inspection from executable experiments, and retain negative findings. Requirements: static inspection only; never execute compiled targets; no redistribution of native Microsoft binaries; record exact tool versions, inputs, outputs, acceptance, and remaining limitations.

## First finding: R8-LIT-01 — numeric literal type erasure

`src/patchtrace/unified/facts/pseudo.py::_number` removes integer `U/L/LL` and floating `f/F` suffixes before creating canonical pseudo-code tokens. It also treats a leading-zero integer token as decimal and collapses large unsuffixed decimal and hexadecimal tokens. This is unsound as *unconditional* C-language normalization: integer literal base/suffix and floating suffix affect literal type; a type difference can alter expression behavior. See [the experiment and proposed correction](01-typed-literal-counterexamples.md).

**Isolated source-equivalent probe, 2026-10-30:** `2147483648`, `2147483648U`, `0x80000000` all became `#2147483648`; `0.1` and `0.1f` both became `f:0.1`. This used the exact `_number` body copied from the baseline; it was **not** a PatchTrace end-to-end run.

**Independent compiled-object evidence:** GCC 14.2 Linux ELF x86-64 `-std=c11 -O2` and Clang 17 Windows x64 COFF `--target=x86_64-w64-windows-gnu -std=c11 -O2` compiled the five independent source functions in `01-typed-literal-counterexamples.md`. Each `.text` was hash-checked with `objcopy/llvm-objcopy --dump-section`; the signed-decimal and unsigned-decimal outputs differ, and the float-suffixed and unsuffixed outputs differ. Only source and text digests, never target binaries, belong in this PR.

**Evidence boundary:** a real Ghidra/Ghidriff decompilation of these exact PE objects and a real PatchTrace verdict are **not available yet**. Do not equate a canonicalizer counterexample with a measured production false-negative rate.

## Research index

- [Prioritized uncertainty register](uncertainty-register.md)
- [Typed literal proof counterexamples, compiler digests, corrective contract](01-typed-literal-counterexamples.md)
- [ICF export-alias identity counterexample](02-icf-function-identity.md)
- [Executable ICF compiler probe](../../../tools/research/r8_icf_probe.py)
- [Experimental scripts and regression tests](../../../tests/test_r8_literal_types.py) (when checked in)
- [R8 follow-up and release gates](uncertainty-register.md#integration-and-release-gates)

## Current decisions

1. **Implemented in R8 branch, not merged:** preserve typed distinctions when literal values can have different C types, correct octal parsing, and increment `canon` channel version to 2. A source-equivalent isolated pytest check passed 5/5 after first reproducing 4 failing cases; full repository pytest remains **pending**.
2. Do not infer equivalence from same tokens without complete target/IR/EH evidence; `COS-PSEUDO` remains a named decompiler-relative statement, not a behavior proof.
3. Preserve existing same-type value normalization, e.g. `0x100` and `256` both have type `int` under the Windows x64 C model.
4. Any normative change to canonicalization must increment the `canon` channel version in `registry.py` to invalidate cached `config_digest`/result keys. Coordinate the nearby active R3 `COS-PSEUDO` version edit.
5. All remaining R8 categories are **open** until explicitly tested; an empty gate is not a passing gate.

## Second measured counterexample: R8-IDENT-02

Clang-cl/LLD 17 compiled the same AMD64 COFF object with exported `first` and `second` definitions. With `/opt:icf`, both names point to RVA `0x1000`. With `/opt:noicf`, `first` is `0x1000`, `second` is `0x1010`. Two independent temporary-directory runs with `/Brepro` produced equal output hashes. The [reproducible compiler-only probe](../../../tools/research/r8_icf_probe.py) returned `status=PASS`; no DLL was executed. This validates source-vs-RVA nonuniqueness, **not a defect in PatchTrace's current matcher**. R1/R2 must test native extractor/matcher behavior before claiming any correction. See [experiment](02-icf-function-identity.md).

## Verification at last R8 checkpoint

- R8 draft PR #135; baseline `a04f5a2`; main production defaults unchanged.
- Portable source-level numeric red/green: isolated baseline 4 failed + 1 passed, amended copy 5 passed; repository-integrated pytest **not run here**.
- Static compiler examples: GCC 14.2 and Clang 17 Win64 COFF differ as expected; ICF export identity: 2/2 separate runs PASS.
- GitHub Actions full QA and native Windows jobs automatically started on the research branch, but exact-head success is **not verified**. Earlier cancelled superseded runs are not pass/fail evidence.
- No source/Ghidra/Microsoft binary executed; no target binary committed or externally uploaded; research code opt-in only.
