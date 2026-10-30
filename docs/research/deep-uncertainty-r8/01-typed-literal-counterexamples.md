# R8-LIT-01 — type erasure in canonical pseudo-code

**Finding type:** independently demonstrated source-code normalization defect with statically compiled counterexamples.  
**Priority:** release-blocking for any claim that an equal pseudo-code canonical form is sufficient to label a function benign.  
**Baseline:** `main` `a04f5a299a8d4afef023261e52e08d14678cf1e7`; original file `src/patchtrace/unified/facts/pseudo.py`.  
**Scope of confirmation:** literal normalizer, compiler-produced object `.text` sections. **Not** native Ghidriff/Windows integration, overall false-negative rate, or CVE root-cause.

## 1. Assumption and source-code path

Original `_number(kind, text)` returned `f'#{int(text.rstrip("uUlL"))}'` for decimal tokens and `f'#{int(text.rstrip("uUlL"), 16)}'` for hex tokens; floating tokens stripped `f/F`. The `_TOKEN` tokenizer matches integer suffixes and the `f/F` floating suffix but that information was discarded in `_number`. The same code treated `010` as decimal ten, contrary to C octal syntax.

`facts/channels.py::FactsContext.collect` puts `Canon.tokens` in C6 and normalized `Canon.numbers` in C5. `facts/verdict.py::_pseudo_proof` permits decompiler-relative `COS-PSEUDO/1` when C4/C5/C6 compare equal, no blocking delta or unresolved mapped target exists and the applicable EH condition passes. Thus collapsing type-sensitive numeric tokens **may** remove a reason to abstain. Whether actual Ghidra output ever supplies the exact differing spellings needs native testing.

These sources explain the type distinction:
- GNU C integer constant types: https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Integer-Const-Type.html
- Microsoft C integer syntax (including octal and extensions): https://learn.microsoft.com/en-us/cpp/c-language/c-integer-constants?view=msvc-170
- Microsoft C floating constants: https://learn.microsoft.com/en-us/cpp/c-language/c-floating-point-constants?view=msvc-170

The exact type choice can depend on C dialect and target data model; do not extrapolate compiler-produced bytes to every platform.

## 2. Hostile examples and the exact old collision

| Before | After | Old canonical values | Type/behavioral concern |
|---|---|---|---|
| `2147483648` | `2147483648U` | `#2147483648` / same | signed large constant vs unsigned int |
| `2147483648` | `0x80000000` | `#2147483648` / same | decimal vs hexadecimal unsuffixed type selection |
| `0.1` | `0.1f` | `f:0.1` / same | double vs float precision and operations |
| `010` | `8` | `#10` vs `#8` | **false difference**: octal ten textual value is decimal eight |
| `0x100` | `256` | `#256` / same | correct existing same-value, same-type control |

All are C spelling examples, **not** captured native Ghidra decompilations.

## 3. Compiler code witness: one function per source file

Compile-only fixtures; no object or target function was executed:

```c
// dec_unsigned.c
int probe(int x) { return x < 2147483648U; }
// dec_signed.c
int probe(int x) { return x < 2147483648; }
// hex_unsuffixed.c
int probe(int x) { return x < 0x80000000; }
// float_f.c
float probe(float x) { return x + 0.1f; }
// float_double.c
float probe(float x) { return x + 0.1; }
```

**GCC**: Debian 14.2.0, Linux ELF x86_64, `gcc -std=c11 -O2 -fno-ident -c FILE.c -o FILE.o`, `objcopy --dump-section .text=FILE.text FILE.o`.

**Clang**: 17.0.0, Windows-target COFF x86_64, `clang --target=x86_64-w64-windows-gnu -std=c11 -O2 -c FILE.c -o FILE.obj`, `llvm-objcopy --dump-section .text=FILE.pe-text FILE.obj`.

| Source | `.text` length | GCC `.text` SHA-256 | Clang `.text` SHA-256 |
|---|---:|---|---|
| dec_unsigned | 8 | `2e5789e8b27b7b46e80f324373280a9bef2d5d783dc4487ae87064d9c3c0ec4c` | `443b73f5295088b44379ffc3b01ddbb682ed2c75ca70b8bddf149f7c037b49ce` |
| dec_signed | 6 | `2db31f4e09597946e56e859813bfdad7046d457c32332c3a882654d1e3ffdf67` | `2db31f4e09597946e56e859813bfdad7046d457c32332c3a882654d1e3ffdf67` |
| hex_unsuffixed | 8 | `2e5789e8b27b7b46e80f324373280a9bef2d5d783dc4487ae87064d9c3c0ec4c` | `443b73f5295088b44379ffc3b01ddbb682ed2c75ca70b8bddf149f7c037b49ce` |
| float_f | 9 | `5f1681acb9ca5dd7432e14a3db90701dfa81cde5a9e7d759bab43114c026cb0a` | `5f1681acb9ca5dd7432e14a3db90701dfa81cde5a9e7d759bab43114c026cb0a` |
| float_double | 17 | `c749533e44e095aef994897490d6a12117303a8bbaf16abe387626fab834a0ba` | `c749533e44e095aef994897490d6a12117303a8bbaf16abe387626fab834a0ba` |

The unsuffixed decimal comparison compiled to a constant true result under both configurations; the unsigned and hex comparisons compiled to a non-constant test. For the floating comparison, the suffixed path used a single-precision add, while the unsuffixed path performed double-precision addition and conversions. Object digests are evidence of distinguishable implementation, not general behavior proof. The `-O2` code has relocation records for floating constants outside `.text`; `.text` digest comparison alone is not sufficient for complete binary equivalence.

## 4. Reproducible red/green

An isolated source-equivalent copy of the original exact `_number` ran under Python 3.13.5 and pytest: **4 failed and 1 passed** (four issues above, existing 0x100 == 256 control). The same local tests on the R8 correction copy ran **5 passed in 0.04 s**. This is not `pytest` against a real cloned PatchTrace repository; that checkout was unavailable from the restricted local runtime, where GitHub DNS did not resolve.

The R8 branch contains an integration-shaped pytest module `tests/test_r8_literal_types.py` for GitHub CI. Its true integrated result is **PENDING** until the repository tests and workflow run on the exact head; do not promote the local standalone result to integrated CI success.

## 5. Minimal correction and acceptance

Change `pseudo._number` to:
1. Canonicalize integer suffix order, preserving `u` and length markers rather than discarding them.
2. For unsuffixed values above `INT32_MAX`, retain decimal/octal/hexadecimal radix class because their first representable types can differ.
3. Interpret zero-prefixed digits as octal; invalid octal spelling remains conservative nonnumeric text.
4. Distinguish `f/F` from unsuffixed floating constants; keep the original value-only normalization for safe identical type controls.
5. Bump `CHANNEL_VERSIONS[canon]` from 1 to 2, invalidating result keys that would otherwise carry previous C5/C6 evidence.
6. Preserve `COS-PSEUDO/1` as decompiler-relative only; do not upgrade it into a proof of machine-code equivalence.

**Red/green unit success is not sufficient**. Required native release gate: compile and link valid Windows x64 PE pairs, run actual Ghidra/Ghidriff with pinned versions and settings, save code strings / C4-C6 / relevant IR evidence and verify no changed case gets `unchanged` or `cosmetic` solely from the normalization. Include same-source/alias negative controls. R3's pending EH and register-proof fixes must be reconciled before any integration merge.

## 6. Residual threats and handoff

The scanner also has limited coverage of C exponent-only decimal floating tokens (e.g. `1e3`) and target-specific integer suffixes (`i64`); these are not repaired by R8-LIT-01 and should be kept conservative until lexer tests characterize Ghidra-produced text. C++ literal types can differ further. Decompiler output may lose the original source spelling; no token normalization can recover a distinction already discarded by the extractor. Address-operand matching, EH-EQ, and IR target consistency remain necessary for stronger proof classifications.
