# Actual A/A, compiler variation and structural experiments

Run date: 2026-10-30 UTC. Source: reviewed `corpus/ours/r1-pilot/defined/v1/r1.c`. Scope: one defined-behavior source revision, stock Tier R build profiles, one rebuild control, four successful same-source variation pairs, one preserved initial linker blocker, and one LLVM structural transform through COFF object generation. **No target image was executed and no matching engine was invoked by this experiment worker.** These results establish fixture/build/label infrastructure observations, not matching accuracy.

The separate store is `/workspace/scratch/a55b59b3e326/r1-controls-store`. The integration owner's running matrix store was not touched. The machine-readable companion `controls-and-structure.json` retains tool paths/versions, source hashes, full artifact paths/hashes, existing-schema label paths/digests, full canonical compile/link recipes, and exact blocked outcomes. Generated images, PDBs, IR and COFF objects remain outside the repository. The results files contain metadata only.

## Recorded inputs and toolchain

- Source SHA-256: `5f0468899fbc95fa4026c3c74b0731a5ab412fe017bbddbed00ad7b0d97acb5f`.
- Suite JSON SHA-256: `4a6f4ef6ad1aa12448191d3b16d1beebbc51dea0143168b4894758f4d5a01e13`.
- Clang: Ubuntu Clang 18.1.3 (`/usr/bin/clang-18`).
- MSVC-style linker: Ubuntu LLD 18.1.3 (`/usr/bin/lld-link-18`).
- LLVM inspectors/stripper/PDB tools: LLVM 18.1.3 distribution, exact probe banners in JSON.
- MinGW GCC: x86_64-w64-mingw32-gcc (GCC) 13-win32.
- LLVM opt: Debian LLVM version 18.1.3 (`/usr/bin/opt-18`; full banner in JSON).
- True Microsoft `cl`/`link` profile: **blocked on this POSIX host**. `msvc-free` uses Clang with the Windows MSVC target; it is not a real Microsoft compiler run.

The primary O2 compile tail is:

```text
--target=x86_64-pc-windows-msvc -ffreestanding -mno-stack-arg-probe
-gcodeview -gno-codeview-command-line -ffile-compilation-dir=.
-O2 -g -w -std=c11 -I. -c r1.c -o ../obj/00000.o
```

The canonical link tail is:

```text
/dll /noentry /nodefaultlib /machine:x64 /debug /debug:symtab
/pdb:../out/defined.pdb /pdbaltpath:%_PDB% /pdbsourcepath:/ka-src
/Brepro /opt:noref /opt:noicf /incremental:no /noimplib
/out:../out/defined.dll ../obj/00000.o ../rt/ka_rt.lib
```

No source edits, unwind flags, frame-pointer flags or export-name injection were added. Compiler/source-date/path normalization and the runtime archive follow the existing factory. The complete canonical recipes for each successful build instance are in the JSON receipt; tool executable paths are in its `tools` object.

## A/A rebuild and layout outcome

The actual API call was `F.run_aa(session, base_v1, opt='O2', layout=True)`. The existing factory built variants `aa-a` and `aa-b` independently in separate temporary build directories, parsed both debug inventories, checked both stripped images, and emitted one strict `known-answer-labels/1` document. No factory substitute or fake compiler was used.

| Observation | Result |
|---|---|
| Pair | `aa-defined-v1-O2-rebuild` |
| Source/profile | reviewed v1; stock `msvc-free`, O2 |
| Functions in labels | 21 project functions; 21 same identities, 21 unchanged labels, 21 identical bodies |
| Authored/factory disagreements | 0 |
| Full stripped engine image | byte-identical, 2,048 bytes per build |
| Full debug image | byte-identical |
| PDB | SHA-256-identical |
| Factory reproduction comparison | `byte_identical=true`, `differing_bytes=0`, no differing sections |
| Link-order layout | **not applicable**: one translation unit and no dependencies; factory did not emit reversed/rotated pairs |
| Engine evaluation | not performed by this worker |

The unchanged source identities are construction evidence. Zero disagreements here are not an engine success rate. This suite includes source identities whose endpoint bodies are code-indistinguishable; retain the README's ambiguity groups rather than treating names as recoverable from bytes alone.

| A/A artifact | SHA-256 in both independent builds |
|---|---|
| Stripped engine image | `36d607e334544fcf98f81f77f46468e559ac849b01f1fd4f930c0a6ab5192294` |
| Debug image | `66908cc4642bb149aad74a23d1e641807edb874da008c3b488f5e74fb462b6ea` |
| PDB | `d69c89940cb99ef44ceb750a869206ae781978df36f5bca3ed2ae85d373f7473` |

Label document: `/workspace/scratch/a55b59b3e326/r1-controls-store/labels/aa-defined-v1-O2-rebuild.json`. Its canonical label digest is `1792c140953da1e24c01e697731f3f9d3e5e0065e8358418d3f1fe1aed19e26f`; file-byte SHA-256 is `b03bd0f6d71f3236c1b477093d7160effd46dfb72178479c0e98a61e77bf73e5`. The integration owner can use this existing label path for the next genuine native-engine control. An identical-image backend shortcut must be reported as a shortcut, never as native-engine execution.

## Same-source compiler and optimization variation

`F.run_noise` was called with one explicit variant at a time, allowing the successful configurations and blocked configuration to be preserved independently. All pairs use the same reviewed v1 source. Existing same-source labels are semantic construction labels: a changed machine body under another compiler does not imply a source semantic change. The source's fixed integer widths, unsigned arithmetic and common pointer/callback domains bound the equivalence claim; this is not blanket equivalence for arbitrary C programs.

| Actual requested comparison | Outcome | Project identities/labels | Body observations |
|---|---|---|---|
| Clang MSVC target O0 → O2 | Built and labelled | 21 same, 21 unchanged, zero disagreements | 21 different bodies |
| Clang MSVC target O2 → Os | Built and labelled | 21 same, 21 unchanged, zero disagreements | 20 identical, 1 different |
| Clang MSVC target O2 → MinGW GCC O2 | Built and labelled | 21 same, 21 unchanged, zero disagreements | 10 identical, 11 different |
| MinGW GCC O2 → MinGW Clang O2, initial attempt | **Blocked; no pair emitted** | No label document | Clang link rejected `-fuse-ld=lld` with `invalid linker name in argument '-fuse-ld=lld'` |
| MinGW GCC O2 → MinGW Clang O2, after linker dependency recovery | Built and labelled | 21 same, 21 unchanged, zero disagreements | 10 identical, 11 different |

The initial blocked fourth comparison and exact existing-factory skipped/error text are retained in JSON. The MinGW GCC side was already successfully built and cached; the Clang MinGW side failed at linking. The integration owner then installed the distro generic linker dependency using `apt install lld`, making `/usr/bin/ld.lld` available (Ubuntu LLD 18.1.3, compatible with GNU linkers). Only this one control comparison was retried after that environment change. The retry succeeded with **no source, compiler flags or factory-code changes**, producing its own `noise-retry` receipt entry. The initial failure is preserved rather than overwritten, and the recovery is a dependency repair rather than evidence that the first attempt passed.

The initial phase recorded six successful build instances: two independent A/A O2 builds, O0, another O2 noise variant, Os and MinGW GCC O2. The bounded retry rebuilt GCC O2 (same hashes) and added MinGW Clang O2, giving eight successful build instances and **five unique profile/optimization configurations** overall. Repeated O2 images are intentionally identical, not extra diversity. **Four distinct noise label documents plus the A/A label document** were emitted and reloaded with the strict existing label loader.

The optimization/compiler pairs are also visibility-confounded. Static PE inspection found **zero COFF symbols and zero named exports** in the stripped Clang MSVC-target images, with `.text` and `.rdata` sections and no `.pdata`. The stripped MinGW GCC image has zero COFF symbols but **21 named exports**, the fixture function names, plus `.pdata`/`.xdata` and the usual runtime/import sections. Therefore debug stripping did not hide compiler-derived names in the GCC artifact. The GCC debug inventory also includes 34 runtime functions across the initial Clang/GCC pair's summary, excluded from the 21 project labels. The recovered MinGW Clang stripped image likewise has zero COFF symbols and **21 named exports**, and includes `.pdata`; the GCC/MinGW Clang pair summary counts 68 runtime functions across both sides.

These facts must accompany any later engine results: the MSVC-target image may make function-start discovery unobservable, while the GCC image gives the engine useful names and unwind metadata. This worker did not run an engine to measure discovery counts, did not strip export names, and did not supply private debug symbols to an engine.

| Configuration | Stripped engine SHA-256 | Debug SHA-256 |
|---|---|---|
| msvc-free / O2 | `36d607e334544fcf98f81f77f46468e559ac849b01f1fd4f930c0a6ab5192294` | `66908cc4642bb149aad74a23d1e641807edb874da008c3b488f5e74fb462b6ea` |
| msvc-free / O0 | `b79e088363e9dfa3132313849a4936972e208a6703ce99683dc389ec755049dd` | `ad3f8e58dc37b06d94e9e2895d70274ec710602378f78347a87141e425cdb7b0` |
| msvc-free / Os | `12e45c789c827f8fb317dc6aba2467cf5c3d6f79c1c0a21a4d6aa75ae047fdfc` | `b9b07163121db9b0fe0bb6cf1268836de2c5620b2cf7ed3f66874ded1c43409d` |
| mingw-gcc / O2 | `c03b76a0e6db62ac35c5f4fa727f38cafdcfb5e7b8544c327b4c9587f8707b58` | `82507c9e80aa0493860ca0b56a7400ec67dbda7ae3a32185aa19aaefa5b1b701` |
| mingw-clang / O2 | `f6164cc7eb8bbfc2b56b7176e78f3e2473f838e6f24117dfc1fe11e89ef96203` | `696d8ec0becd77f2f737b9ab1f8b66f7f6fe179494d522e6019269a1d30cb3a7` |

| Same-source label ID | Canonical label digest |
|---|---|
| `noise-defined-v1-msvc-free-O0-msvc-free-O2` | `a49fac036302ab463018d22c76aeb0de5bde43adb9db3ed3ac50be4b1dc9f415` |
| `noise-defined-v1-msvc-free-O2-msvc-free-Os` | `08939af3c162e5dee94f3abe317aa098f8672b32e601a4f75fddf19a0db82445` |
| `noise-defined-v1-msvc-free-O2-mingw-gcc-O2` | `ab00e8abc4f8f62bd7cd67d4ca1e70266d77f281ce69831b5ac87812541355a9` |
| `noise-defined-v1-mingw-gcc-O2-mingw-clang-O2` | `81fe7c29372134b2ba1efa5f958ee42629e22c71b722089e7dfc02085afaac8c` |

## Actual structural transformation

The existing `tools.calibration.mutations.opt_transforms` infrastructure was inspected and used directly. `loop-extract` was chosen because v1 contains the reviewed, physically bounded `r1_loop_bound` loop. The source's explicit noinline annotations were retained. An always-inline experiment would not honestly test inlining of these deliberately noinline functions without changing the experimental conditions.

The source was emitted as Windows-target IR through:

```python
before = O.emit_opt_input(
    F.read_sources(base.root), 'r1.c', tools,
    flags=('--target=x86_64-pc-windows-msvc',),
)
result = O.apply_opt(before, 'loop-extract', tools)
```

The exact canonical emission uses Clang `-S -emit-llvm -O1 -Xclang -disable-llvm-passes -g0 -x c -ffreestanding -Wno-everything -I.` with that target flag. The existing opt pipeline was:

```text
opt-18 -passes=function(mem2reg,loop-simplify),loop-extract -S in.ll -o out.ll
```

Observed result: `status='ok'`, taxonomy N4, **21 IR definitions before and 22 after**. The new internal helper is `r1_loop_bound.extracted`; no existing function was removed. The transformed `r1_loop_bound` contains an actual call to that helper. This is observed outlining of a loop into a new function, not a synthetic claim inferred only from a pass name.

Both IR modules were then compiled, without execution, into Windows x86-64 COFF objects using the existing IR process wrapper:

```text
clang-18 --target=x86_64-pc-windows-msvc -c -O0 -x ir module.ll -o out.obj
llvm-nm-18 --defined-only before.obj
llvm-nm-18 --defined-only after.obj
```

The before object contains the 21 original text symbols. The after object contains those 21 and a local text symbol `r1_loop_bound.extracted` at object offset `0x420`. Thus the new helper survived this O0 object-code generation. The before and after objects are 2,290 and 2,344 bytes respectively. Object offsets are not image RVAs. The opt pipeline also performs mem2reg/loop canonicalization, so other byte differences must not all be attributed specifically to extraction.

| Structural output | SHA-256 |
|---|---|
| before IR module | `96dfd67443fd73110658e2ac7bd1ea606ebe8941db435af4c12490e24fcad5fc` |
| before COFF object | `e302f4805b3f245403e790abfe9745b4abbea34711ed49c04663e2e112d032ef` |
| after IR module | `1c779c07be545a2a478166902aec9625e31ac14ae5932fe98cbe52c75ae0147a` |
| after COFF object | `455df31224214c60de33b1d1ceb10cdaa7dabeacf26420dd40b563e02fbe8d7b` |

The structural observation stops at IR and COFF object evidence. No structural DLL pair, debug-derived relationship document, transformed-function RVAs, one-to-many accepted ground truth, or engine result was manufactured. The existing pass is intended to preserve semantics, but no independent semantic-equivalence proof or dynamic execution was performed here. A later linked structural experiment must preserve the caller/helper relationship and avoid forcing it into a unique one-to-one function match.

## Reproduction through the existing APIs

From the repository with its current source and installed toolchain, use the existing factory and a fresh external store. The experiment calls are:

```python
from pathlib import Path
from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r.toolchain import probe

suite, bases = F.suite_bases(Path('corpus/ours/r1-pilot/defined'))
base = bases['v1']
tools = probe()
session = F.Session(tools, Path('/absolute/path/outside/repository'))
for doc in F.run_aa(session, base, opt='O2', layout=True):
    F.write_doc(session.store, doc)
variants = [
    ('msvc-free', 'O0', 'msvc-free', 'O2'),
    ('msvc-free', 'O2', 'msvc-free', 'Os'),
    ('msvc-free', 'O2', 'mingw-gcc', 'O2'),
    ('mingw-gcc', 'O2', 'mingw-clang', 'O2'),
]
for variant in variants:
    documents, blocked = F.run_noise(session, base, variants=[variant])
    for doc in documents:
        F.write_doc(session.store, doc)
    print(variant, blocked)
```

Use the structural calls shown above to reproduce extraction; the source, exact LLVM version and COFF compile flags are part of that experiment. Check artifact hashes against the receipt, treating different toolchain or source versions as new configurations. The original execution used the venv interpreter and `PYTHONPATH=src:.`; its command and temporary experiment-script digest are preserved in JSON. That temporary wrapper is not a new corpus framework or a committed source dependency.

## Acceptance boundary and next use

A/A has verified exact engine/debug/PDB byte reproducibility for one source revision and configuration. Compiler/optimization variation produced four genuine same-source label pairs, preserving the initial linker blocker and the subsequent explicit dependency-recovery retry. The bounded structural pass produced an actual outlined helper surviving to COFF. True Microsoft compiler testing and independent native matching remain unperformed by this worker. Single-TU link-order variation is inapplicable rather than successful coverage.

The integration owner can now run the genuine baseline against the A/A label path and, separately, the four noise labels. Report actual process launch versus an identical-image shortcut, discovery coverage, name visibility and ambiguous endpoint groups. None of the source-derived same-function labels or zero-disagreement counts here are matching-engine predictions, performance measurements, or held-out accuracy results.
