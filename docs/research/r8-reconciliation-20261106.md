# R8 research reconciliation, 2026-11-06

Status: historical source preservation; no new implementation, requirement or
release acceptance.

This slice preserves five R8 documents from
[PR #183](https://github.com/djshellshoxxx/patchtrace/pull/183), pinned at
`ed70e6ddac449a42f843f1c60aa878416ab31727`. The comparison baseline is published
continuation `37b771300053e8872febead1fc384fea9126ae90`, tree
`cdbab24d14295b4450cd0d3c744d76734c98a561`. All five paths were absent there.
The [source receipt](r8-reconciliation-20261106-sources.json) records their exact
Git blobs, SHA-256 digests, byte counts, original provenance and dispositions.

The source documents retain their historical dates, statuses, commands and claims.
The [consolidation plan](../plans/branch-merge-plan-20261106.md) and
[earlier research reconciliation](reconciliation-20261105.md) govern this selective
import. It does not settle the remaining #183 research, panel or planning groups,
establish whole-PR equivalence, or authorize deletion of a source branch.

## Preserved documents

| Source under `docs/research/deep-uncertainty-r8/` | Bytes | Historical material |
|---|---:|---|
| [01-typed-literal-counterexamples.md](deep-uncertainty-r8/01-typed-literal-counterexamples.md) | 9,462 | Typed-literal and bounded-token counterexamples, compiler witnesses and proposed corrections. |
| [02-icf-function-identity.md](deep-uncertainty-r8/02-icf-function-identity.md) | 4,988 | Identical-code-folding experiment, source versus machine-code identity, and truth-label limits. |
| [03-integration-handoff-and-release-risk.md](deep-uncertainty-r8/03-integration-handoff-and-release-risk.md) | 12,432 | Cross-branch handoff, proposed experiments and release-gate discussion at the source date. |
| [README.md](deep-uncertainty-r8/README.md) | 5,745 | Research scope, source map and dated validation summary. |
| [uncertainty-register.md](deep-uncertainty-r8/uncertainty-register.md) | 10,012 | Research uncertainties, evidence classes and dated owner questions. |

The five files total **42,639 bytes** and are byte-identical to their PR #183 blobs.
Their original R8 provenance is branch `research/r8-deep-uncertainty-20261030` at
[`12dd4f2b41b468b0eb566bd502219daa821012df`](https://github.com/djshellshoxxx/patchtrace/tree/12dd4f2b41b468b0eb566bd502219daa821012df/docs/research/deep-uncertainty-r8).
The C7 port was `f8a6aa5a177e6ec3290e79f8245bced4be7373ef`, followed by whitespace
cleanup `2ee1d2aaeb1a96e0c08c9597ebf484dc229f6b72`. Four files differ from the
original R8 blobs only in trailing whitespace; `uncertainty-register.md` is already
byte-identical. The receipt distinguishes both revisions instead of attributing
the imported hashes to the original R8 commit.

## Current dispositions at the comparison baseline

| Historical topic | Current overlap and disposition |
|---|---|
| Typed-literal correction and long-token fallback | **The R8 implementation is unported.** Current [pseudo.py](../../src/patchtrace/unified/facts/pseudo.py) is byte-identical to the PR #183 baseline: `_number` still removes integer suffixes, removes a float `f/F` suffix and bounds fallback text to a 40-character prefix. The [registry](../../src/patchtrace/unified/registry.py) and [canonicalization contract](../specs/unified-engine/05-fusion-and-noise.md) retain `canon/1`. R8's claim of implementation describes its own branch. A future correction requires a separate spec/owner decision, coordinated with the existing [FCT-11/A3 address-label question](../audits/20261104-unified-fct.md); this archive changes neither contract nor behavior. |
| ICF and function identity | [Group handling](../../src/patchtrace/unified/ladder/groups.py), [ambiguous group rows](../specs/unified-engine/05-fusion-and-noise.md), [ICF nuisance variants and truth rules](../specs/unified-engine/08-evaluation.md), and [label guidance](../specs/calibration-corpus-and-model.md) already address this area. R8 adds a dated compiler/linker witness and cautions about treating aliases as independent source functions. Its experiment does not establish a current matcher defect, complete ICF coverage, or native acceptance. |
| Register-only COS-PSEUDO blocker | The [current blocker set](../../src/patchtrace/unified/facts/verdict.py) includes `register-only`; [COS-PSEUDO/1](../../src/patchtrace/unified/registry.py) is version 2. [FCT-03](../audits/20261104-unified-fct.md) records the independent repair. R8's old not-merged handoff language is superseded for this behavior and does not describe current ancestry. |
| Handoffs, release risks and uncertainty register | Old active/not-merged labels, owner assignments, isolated test counts, proposed gates and paste-ready QA/todo entries remain historical research. They are not current ownership, reproduced defects, implementation completion or newly accepted requirements. The active specification and release processes retain their own authority. |

These dispositions come from source inspection at the pinned comparison baseline.
No historical compiler experiment, probe, test or target binary was executed for
this reconciliation. Historical success counts are not added to current test
results. Native Windows/package qualification and paid automation remain separate.

## Evidence referenced but not imported

The original R8 commit contains two code files omitted from PR #183 and absent at
the comparison baseline. They remain immutable references:

| Original path | Bytes | Pinned source |
|---|---:|---|
| `tools/research/r8_icf_probe.py` | 3,736 | [Original probe](https://github.com/djshellshoxxx/patchtrace/blob/12dd4f2b41b468b0eb566bd502219daa821012df/tools/research/r8_icf_probe.py) |
| `tests/test_r8_literal_types.py` | 3,555 | [Original literal tests](https://github.com/djshellshoxxx/patchtrace/blob/12dd4f2b41b468b0eb566bd502219daa821012df/tests/test_r8_literal_types.py) |

The source README references the probe twice and the tests once. Those three
relative links remain unresolved locally because changing them would change the
preserved document bytes. The links above and the receipt provide the exact
source locations and hashes. All links among the five imported documents resolve.

The dossier retains textual source snippets, tool versions, digests and reported
compiler/linker observations. This slice does not provide compiled artifacts or
a self-contained reproduction archive. No runtime, probe, test, specification,
registry, QA, task, workflow or packaging file is imported or changed.

## Verification

All five imported files match their source Git objects, SHA-256 digests and lengths;
the original R8 receipts and the two omitted code receipts also match their Git
objects. Strict JSON parsing and receipt consistency checks passed. Across the five
source documents, this wrapper and the research index, 53 relative links resolve;
the three preserved README links to the two omitted code paths are the documented
exceptions. The change is confined to the eight documentary files described here.

The existing help and spec-registry checks cover `docs/help` and `docs/specs`, so
they do not cover this research-only slice. The byte, receipt and link checks above
verify its actual changes. Full application tests and native workflows were not
run for this documentation-only reconciliation.
