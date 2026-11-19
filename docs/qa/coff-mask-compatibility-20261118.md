# Optional source-checker COFF compatibility — 2026-11-18

## Result and scope

Exact source **`ce093ec56260944869fa28e12c26c79eb1dd4c78`** passes **88 offline
checks**, zero failures/errors/skips, in **0.60 seconds** (0.92 seconds wall).
Full configured Ruff over `src tests tools` and `git diff --check` pass. The
source and test hashes are unchanged across the clean committed-source gate.

The executable repair adds only `?` to `_ASM_SYMBOL`'s existing unquoted-name
character class in `tools/calibration/mutations/engine.py`; one comment explains
the compatibility scope. Quoting, signed decimal addends, the adjacent `(%rip)`
requirement, branch/call target masking and body boundaries remain unchanged.
SPEC-32 and 21 authored controls precede the source change.

This is an **optional dev-only source-checker compatibility repair**. The
injected assembly producer models its input and never runs a compiler or target.
It is not evidence that the exact configured Clang emits unquoted decorated
names. No GUI behavior, frozen corpus, native output, image-level body hashing,
factory integration, schema, acquisition or network behavior changes here.

| Role | Commit |
|---|---|
| Reused clean baseline | `d5d995d6f5c76d4cb2cba7424a997ac9850c6135` |
| Spec and failing controls | `181c13d9ce9a014afbf9b3b97e3e63f58042975e` |
| Source | `ce093ec56260944869fa28e12c26c79eb1dd4c78` |

Branch: `codex/coff-mask-compatibility-20261118`, in the reused
`security-residual-qa` worktree. Its prior branch
`codex/security-residual-triage-20261118` remains at `d5d995d6`. The engine,
contracts, image body hasher, factory, existing mutation tests and SPEC-32 bytes
were verified identical to the peer's baseline
`55f3d0742f7d4cf32357a42b8b1cc76d85875e71`; see `source-comparison.json`.
The separate R2 branch and receipts were left untouched.

## Why the repair is bounded

The old unquoted pattern masked only the suffix following `?`, leaving different
literal-dependent name prefixes in otherwise equal normalized instructions.
`make_masked_body_check` therefore accepted an authored semantic symbol-only
candidate; the optional `apply_case(extra_check=...)` path also accepted it
instead of recording a rejection. The cosmetic equality branch could reject
the same authored equivalence. All are manifestations of the same truncation.

The repaired comparison masks the complete supported COFF-style name, including
its existing optional decimal addend. Tests independently preserve observable
opcode, immediate, register, non-RIP memory offset, base-register and conditional
branch-opcode differences. Plain and quoted names, local RIP labels, branch/call
target normalization and five function-boundary cases remain covered.

Source trace distinguishes this API from the factory: `make_masked_body_check`
is exported for explicit use, while current `tier_r/factory.py` calls
`apply_case` without `extra_check`; there is no non-test caller of the optional
helper in this baseline. This packet does not establish affected frozen labels
or a shipped application failure.

The native-emission assumption was checked against LLVM primary source without
running tools. Its [identifier lexer](https://llvm.org/doxygen/AsmLexer_8h_source.html)
allows `?` within identifiers, while the ordinary
[symbol-name printer](https://llvm.org/doxygen/MCAsmInfo_8cpp_source.html)
requires quoting for characters outside its accepted set. The
[X86 MASM configuration](https://llvm.org/doxygen/X86MCAsmInfo_8cpp_source.html)
explicitly enables leading `?`. These online sources describe syntax handling;
they do not prove the configured compiler emits the authored AT&T/RIP spelling.
The specification and tests retain that distinction.

## Preserved red and green results

| Run | Source | Observed result |
|---|---|---|
| Peer unchanged public probe | `55f3d074` | 1 failed / 3 passed, 0.29 s |
| Independent replay, boundary/API controls and existing pure controls | clean `d5d995d6` | 6 failed / 20 passed, 0.64 s; no setup errors |
| New specification controls | clean `181c13d9`, engine bytes unchanged | 5 failed / 16 passed, 0.43 s |
| Selected unchanged historical controls before repair | clean `181c13d9` | 2 failed / 6 passed / 53 deselected, 0.34 s |
| Exact-source affected gate | clean `ce093ec5` | 88 passed, 0.60 s; zero skips |
| Portable independent source-pin check plus new repository controls | clean `ce093ec5` | 37 passed, 0.74 s |
| Selected unchanged historical controls after repair | clean `ce093ec5` | 2 failed / 6 passed / 53 deselected, 0.29 s; exit 1 retained |

The historical file is unchanged. Before repair, its unquoted case fails body
equivalence; its quoted case fails only the old expected `jmp emit` text. After
repair, **both bodies compare equal**, but both historical cases still expect
`jmp emit` instead of the current `jmp T`. These retained failures are obsolete
branch-normalization expectations, not two remaining compatibility defects.
Current tests assert `jmp T`; no historical assertion was rewritten.

Only explicit pure/authored test nodes were selected from the existing mutation
suite. Native compiler-dependent cases were not run or counted as skipped
passes. The final command, environment, exact imported engine location and
before/after source hashes are in `committed-affected-context.json` and
`committed-affected-exit.json`.

## Receipt ownership and reproduction

Use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, absolute
`PYTHONPATH=<checkout>/src:<checkout>/tests:<checkout>`, and
`QT_QPA_PLATFORM=offscreen`. `run_checks.py` requires a clean checkout, refuses
to replace a receipt label, and verifies the imported engine location. The
separate portable independent control requires
`PATCHTRACE_COFF_REVIEW_ROOT=<checkout>`; only its expected source-root input
differs from the original fixed-path independent control, which is retained
unchanged with its red result. All behavioral assertions are the same.

The peer public probe was copied byte-for-byte into a new directory for each
replay, so its relative observation path never overwrites the peer's originals
or this review's red observations. Original observation hashes remain equal.
Public probe SHA-256:
`2de761cb9e3b57eae2f2a39ebec9c7a540ce3fdc3d8449afbf68407f939be44c`.
Historical file SHA-256:
`719d8466a5269f5b7ef368e00e9bd98d25e67afe9329f83a2d6269d7d0c5d44f`.

The adjacent manifest and ZIP preserve source/test/spec snapshots, exact diffs,
all selected original and current logs/XML/commands, probes and observations.
Raw work receipts remain in `qa/coff-mask-review`; peer originals remain in
`qa/semantic-disposition-batch5`. No remote mutation accompanies this handoff.
