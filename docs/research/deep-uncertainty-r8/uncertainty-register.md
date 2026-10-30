# R8 — prioritized uncertainty register (initial checkpoint)

**Source:** baseline `main` `a04f5a299a8d4afef023261e52e08d14678cf1e7` (2026-10-30). R1–R7 changes are open **drafts**, not merged guarantees. A source audit is not a native accuracy measurement.

## Scoring and ordering

Risk is ranked lexicographically by **worst plausible product harm**, then **ease of issuing an apparently conclusive result**, then **observed counterexample**, then **test cost**. Severity uses `critical/high/medium`; likelihood uses `observed in synthetic conditions / plausible / unknown` rather than invented statistical probabilities. Detectability is `low/medium/high` from the user-visible outcome; unknown real-world occurrence is explicitly retained.

| ID | Area / assumption to challenge | Severity; likelihood; detectability | Evidence and contradictions | Exact next experiment / acceptance | State; owner boundary |
|---|---|---|---|---|---|
| R8-LIT-01 | **B/F:** value-normalized C literals are behavior preserving regardless of suffix, radix, or leading zero | **critical**; collision observed in source-equivalent probe, real native rate unknown; **low** | `pseudo._number` loses suffix and decimal/hex base; two compilers emit different `.text`. Real Ghidra pseudocode feasibility unmeasured | Correct canonicalizer conservatively, red/green exact-unit checks, G-U2 changed-negative regression, native Ghidriff sample; zero cosmetic/unchanged on affected samples | **RESOLVED—REVISED at source-level only; native gate OPEN**; R8 owns `facts/pseudo.py`; coordinate R3's nearby proof edits |
| R8-SEM-02 | **B:** equal pseudo code or masked bytes always imply behavior equivalence | critical; plausible; low | R3 #129 has object relocation target counterexamples and EH-availability proof issue, not yet merged | 12 IR+unwind+relocation adversarial cases, run current verdicts on real linked images; zero false benign; abstain if IR incomplete | **OPEN**, R3 owner; R8 only independent counterexamples |
| R8-MATCH-03 | **A:** every source function corresponds to one machine-code range and one target | critical; **ICF alias observed**; low | **R8 native PE ICF counterexample:** two exported source names both RVA 0x1000 with /opt:icf, distinct RVAs 0x1000/0x1010 without; repeatable. PatchTrace matching untested. | Run folded/unfolded pairs with Ghidra/secondary and hidden-label ground truth, verify alias/group/abstention; no forced false 1:1 | **NARROW ICF ASSUMPTION REFUTED; PatchTrace gate OPEN**, R1/R2 ownership |
| R8-FUSE-04 | **C:** two engines in different declared independence components imply independent errors | critical; unknown; low | R2 #131 reports component gating; common underlying bytes, CFG and decompiler features may correlate | Freeze feature-dependency DAG; same-source wrong-match controls; compare B+B false match to A controls with lineage CI | **OPEN**, R2/R5 ownership |
| R8-CAL-05 | **D:** matched-pair confidence can be interpreted numerically across unseen projects/build families | critical; unknown; low | R5 #132 dependence toy demonstrates non-IID danger, not a production failure. R6 says no accepted locked-test report | Independent lineages, no locked-test reuse, out-of-domain project/toolchain shifts, sensitivity and bootstrap cluster intervals | **OPEN**, R5 ownership; probability disabled |
| R8-VULN-06 | **E:** changed function in security KB identifies specific causal CVE | critical; common update membership observed, causality unknown; low | R4 #130 records ambiguity of cumulative KB and package/build supersedence | Multi-CVE update controls; verify source fix to binary and vendor applicability; abstain without causal provenance | **OPEN**, R4 ownership |
| R8-EXTR-07 | **G:** extractors and address bases reconstruct the same function boundaries, targets and EH | high; unknown; medium | Existing adapter/IR checks, Windows native gates and BinDiff provisioning unresolved | Same PE through Ghidra, BinExport, rz-diff; identity of section/ref/target facts; report contradictions, never fabricate | **OPEN**, R2/R3/native gate |
| R8-PERF-08 | **H:** dense ambiguities and large correlated graphs remain bounded without changing correctness | high; unknown; medium | R2 #131 produced synthetic scaling ablations; real Windows 60k/250k frozen gate still open | Dense duplicate-function 1k/10k/60k stress; time/RSS/cancel; invariant results with bounded fallback | **OPEN**, R2/perf owner |
| R8-AI-09 | **I:** AI explanations reliably cite owned evidence and preserve counterexamples | high; unknown; medium | Existing evidence and interpretation schemas enforce citation links; no R7 live model fidelity certification | Prompt-injected symbols, hallucinated CWE, wrong code claims, adversarial omissions and cross-provider tests; no model verdict mutation | **OPEN**, R7/security owner |

## Recorded findings versus untested hypotheses

**Measured:** exact numeric token collision from a source-equivalent `_number` copy; GCC-14.2 and Clang-17 Windows-target COFF assembly differences on minimal source pairs; a cloned code-only red/green unit demonstration (4 failures and 1 passing control, corrected 5/5 passing). A separate native Windows-target PE/COFF linker experiment showed that two distinct exported functions share one RVA under ICF and have distinct RVAs without ICF, confirmed in two independent deterministic runs. These are NOT engine confusion matrices, measured PatchTrace false-cosmetic/mis-match rates, or vulnerability proofs.

**Static fact:** `facts/channels.py` produces S0 C5 and C6 from `Canon.numbers` and `Canon.tokens`. `facts/verdict.py` may emit named `COS-PSEUDO/1` when C4/C5/C6 equal, target checks pass and no blocking deltas exist. Synthetic token collisions could defeat that guard **if** the engine supplies such pseudocode. The actual decompiler path is unmeasured.

**Insufficient:** no cloned repository in the local runtime (GitHub DNS unavailable); no **repository-integrated** `pytest`, Ruff, native Ghidriff or Windows packaging run on full PatchTrace in this session. Only the isolated source-equivalent pytest and compiler/linker probes ran. Pending GitHub Actions are not success.

## Integration and release gates

- R8 regression exact-unit must pass under published branch SHA with `python -m pytest -q tests/test_r8_literal_types.py`.
- Existing `tests/test_unified_facts.py` controls (notably `0x100 == 256`) must remain green.
- All required `QT_QPA_PLATFORM=offscreen python -m pytest -q`, `python -m ruff check src tests tools`, schema drift and Linux+Windows CI need actual results.
- Capture a native decompiler output for the signed/unsigned, decimal/hex and float/double fixtures with provenance/versions and compare actual `C4,C5,C6`, verdict and proof. Do not count a synthetic pseudo string as live evidence.
- Confirm no stale result key reuse: `canon` channel version must increment, while on-wire contracts remain unchanged.
- Coordinate canonical SPEC-31 `05-fusion-and-noise.md`, R3 #129 registry/proof version, and R6 #133 release gates. Any conflicting edits are resolved with both workers' unique work preserved.
- Preserve native compile objects and CI artifacts outside Git; commit no PE/COFF/ELF image. PR remains **draft** until all required checks are green. Leave `unified/enabled` default OFF.

## Handoff order

1. Complete R8-LIT-01 conservative canonicalization and focused regressions; obtain exact CI results.
2. Compare IR/native result for compiled counterexamples with all R3 fixes.
3. Run one bounded ICF function identity stress test, label ambiguity independently, and hand off to R1/R2.
4. Compare engine feature provenance and pairwise dependence without assuming independent errors.
5. Use R5/R4/R7 existing coverage for remaining gates rather than duplicating active experiments.

## R8 checkpoint updates: empirical identity and source correction

- **R8-LIT-01:** Branch implements conservative typed integer/float canonical tokens and octal parsing in `facts/pseudo.py`, updates `registry.CHANNEL_VERSIONS['canon']` to 2, appends SPEC-31 amendment and adds `tests/test_r8_literal_types.py`. Red/green *isolated* pytest demonstrated behavior; full repository tests and actual native decompiler output still OPEN. See `01-typed-literal-counterexamples.md`.
- **R8-IDENT-02:** Compiler/linker probe `tools/research/r8_icf_probe.py` twice returned PASS with byte-identical `/Brepro` DLL hashes across scratch directories. ICF-on export RVAs: first=second=`0x1000`; ICF-off RVAs `0x1000`, `0x1010`. See `02-icf-function-identity.md` and LLVM COFF ICF implementation: https://llvm.googlesource.com/llvm-project/+/cf2e828925dc8c9656e800387820b49be03109d6/lld/COFF/ICF.cpp. This is a **linker property**, not a PatchTrace matcher defect verdict.
- Pending CI runs on superseded PR heads may be cancelled by workflows; cancellations do not establish pass or failure. Verify exact final SHA before acceptance.
