# Independent CODEX-5 command-audit review — final V3

## Verdict

**No remaining review blocker was identified for the bounded CODEX-5 command-audit repair at commit `5b5328ee83ee4990b3311f7ac90e2f5e5f76f800`.** This signoff applies to the reviewed source-only extraction, command-boundary checks, explicit unsupported-syntax errors and current workflow corpus. It does not close broad CODEX-5 package/hash closure or replace the coordinator's combined, hosted, native or full-suite qualification.

| Identity | Exact value |
| --- | --- |
| Final commit | `5b5328ee83ee4990b3311f7ac90e2f5e5f76f800` |
| Final tree | `1e12edd510399fd92da6867cd071394ceb7fc95b` |
| Parent V2 | `4cbe479023067b05b688cd1c1b02994b0228e305` |
| Earlier V1 | `93b053a88e4373d9f5c69cd68f96e1a49305d579` |
| Integration ancestor | `ae69f1e65d7c4564ec5b0e6d7a80119193fabc4e` |
| Recovered donor | `36b58a7d857690a8bf0093bcee1edd5036189b30` |
| Final scanner blob | `ec868e949d5f15db3450d4c25827702a82c39d26` |
| Final test blob | `1e5d374a48c17cd7dcc8b6027d1f58b53d514cac` |
| Final contract blob | `c7da901039834d08803ccc9a768ba1ba3ee97ff8` |

The reviewed worktree was `repair-codex5-command-audit-v3`. The dedicated `codex5-audit-v3-venv` retained its author-installed editable binding. Independent tests asserted both the application's and scanner's actual import paths and the distribution's editable source URL under `python -I`. The worktree was clean before and after verification.

## Independent final results

Receipt paths below use the directory names inside the complete evidence archive.

| Check | Observed result | Receipt |
| --- | --- | --- |
| Maintained new audit, original workflow audit and spec registry | **226 passed, 2 strict CODEX-5 xfailed; 228 distinct cases; zero failures/errors/ordinary skips** | `v3-5b5328ee/maintained.json`, log and JUnit XML |
| Retained extended lexical distinctions | **20 passed, zero failed** | `v3-5b5328ee/extended-shell-controls.json` |
| Original independent YAML defects | **3 of 3 repaired** | `v3-5b5328ee/preservation-and-census.json` |
| Actual conditional Ghidriff install and full current-source census | **21 workflows, 200 run scalars, 42 installers, 41 unprotected** | Same preservation/census receipt and maintained census regression |
| Typed expected-failure separation | Correct ordinary failures for invalid YAML and empty discovery, intended XFAIL for parsed unprotected installs, XPASS(strict) for protected-only input | `v3-5b5328ee/typed-xfail-controls/receipt.json` |
| Ruff on both changed Python paths | Pass | `v3-5b5328ee/lint-dependencies.json` |
| Dedicated-environment dependency consistency | Pass | Same lint/dependency receipt |
| Isolated imports and editable distribution source | Pass | `v3-5b5328ee/binding.json` |

The four expected-failure controls deliberately produce three hard-failure outcomes and one typed expected failure. Those are successful negative controls, not three unresolved product defects. They are kept separate from the maintained passing selection. Counts are not summed across repeated review phases or with the coordinator's larger overlapping selection.

## Why V3 resolves the last finding

The V2 scanner correctly handled the retained comment/quotation cases but silently ignored explicit installers inside input/output process substitution supplied to an output command. V3 changes only `_command_segments`: three lines added and one removed. It recognizes an unquoted process-substitution marker, keeps its existing opaque lexical span intact and applies the already established unsupported-substitution refusal.

The distinction between executable syntax and literal text is preserved:

- Unquoted input/output process substitutions containing installer text raise `WorkflowAuditError`, including multiline forms.
- Single-quoted and double-quoted process-looking output is literal.
- Escaped marker/parenthesis text is literal.
- Real comments cannot introduce executable substitution.
- A completed substitution without installer text does not hide or block a later independent direct install.
- Dollar command substitution remains executable inside double quotes and is refused when it contains matching installer text.

The complete 20-case independent control set now passes. It retains both original false-negative cases, quoted separator/operator output, comment-only matching text, escaped/quoted hash companions, direct/multiline command substitution, process substitution and its literal companions. The authored new 12-case process-substitution regression is also included in the 226 passing maintained tests.

V3 reuses the existing lexical span helper. Every other scanner function/class AST is unchanged from V2. Every existing V2 test definition is unchanged; the correction only adds the new parameterized process-substitution test. No acceptance predicate was removed or weakened.

## YAML, flag and failure boundaries

The reviewed extractor uses the existing development-only PyYAML dependency and reads actual `jobs.*.steps[].run` values. It excludes `defaults.run`, environment keys named `run` and action inputs. Decoded YAML preserves block-header comments, scalar quoting and folded blank-line semantics. Missing dependencies, malformed/duplicate mappings and invalid run shapes fail rather than silently skipping the audit.

The existing syntactic flag rule remains per recognized installer command. Neighboring commands, comments and literal output do not provide protection. The tests retain option-value, option-terminator and explicitly disabled-hash-checking distinctions. This remains a syntactic audit: it does not resolve referenced requirements or verify complete wheel, transitive dependency, runtime-version or remote-wheelhouse provenance.

The added expected-failure mark has `strict=True` and catches only `UnprotectedPipInstalls`. Actual pytest controls, not only decorator inspection, demonstrate that parser/discovery failures remain ordinary failures. The unchanged original CODEX-5 test also retains its strict expected failure. Both remain necessary historical/open-gate records; neither is promoted to a passing closure claim.

## Source and history preservation

All **25 explicitly protected paths** are byte-identical to ae69:

- All 21 workflow files.
- The original CODEX-5 workflow audit test.
- `pyproject.toml`.
- The global task ledger.
- The QA record.

All runtime `src/` files are also unchanged. Relative to ae69, the recovered repair changes exactly eight audit/specification/index/test/tool paths. Workflow events, permissions, Action references, run scripts and deployment/release behavior therefore retain their original bytes.

Only the Pages installer has a qualifying literal boundary flag in the inspected current corpus. The other 41 recognized commands remain unprotected under this audit. CODEX-5 remains open.

The original donor handoff is preserved verbatim as a prefix with clearly identified later appendices. Every original donor JSON field is preserved; V2 and V3 qualification live in separate additive objects. The V2 handoff and evidence are likewise preserved. The three original positive donor test functions, covering 17 cases, retain identical ASTs.

The new contract is registered by its exact path in `docs/specs/REGISTRY.md`. The formerly failing maintained registry selector now passes inside the unchanged registry test module.

## Preserved red-to-green history

| Source | Independent finding | Disposition |
| --- | --- | --- |
| Donor `36b58a7d` | Three valid YAML controls fail; actual conditional Ghidriff installer is omitted; test lint fails | Existing scoped work recovered; original donor claims remain fixture-only |
| V1 `93b053a8` | Original YAML/current-corpus defects repaired; five of nine lexical controls fail; new spec registry selector fails | Blocked; exact source, red controls and ordinary registry failure retained |
| V2 `4cbe4790` | Prior lexical/registry defects repaired; expanded set gives 18 passed/two failed process-substitution cases | Blocked on one remaining unsupported-syntax class; exact red/positive companions retained |
| V3 `5b5328ee` | All 20 retained lexical controls pass; maintained selection gives 226 passed/two strict expected failures | No remaining blocker identified for this bounded repair |

The complete archive includes original donor recovery evidence, V1 and V2 reviews/receipts and the final V3 evidence. Prior failures are not replaced by later passing summaries.

## Full-run limitation

The sole earlier full local attempt started with modified pre-commit working-tree bytes based on ae69, subsequently committed as V1. Its terminal receipt records child exit **-9** after **498.536 seconds**, unchanged source hashes and no aggregate pytest summary. The cause is undetermined. Its original receipt and log are retained under `historical-original-full-attempt/`.

That attempt is not a clean ae69 pass, not V2/V3 qualification and not a successful full-suite result. No second full run was started by this reviewer. The coordinator's separate exact-V3 combined selection is not included in this review's passing total.

## Review boundary

This reviewer did not modify authored source, the author's environment binding, workflows or Git/remote references. Verification used exact source strings, safe YAML parsing, local bounded pytest controls, source/AST/blob comparisons, lint and dependency consistency. No workflow shell command, installer command, native target, deployment or publication was executed by the review.

The signoff is source-specific. Any later runtime/test/tool change requires an appropriate new-source review and validation. Evidence-only integration records should continue to identify the exact tested source and retain the still-open broad CODEX-5 and hosted/native/manual/provenance/accuracy gates.
