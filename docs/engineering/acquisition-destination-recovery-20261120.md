# Protective acquisition destination recovery

This narrow recovery comes from the separately completed continuation branch `codex/patchtrace-acquire-windows-junction-20261120-g32`, exact donor `ae67122c69f05715afa622b7e4050b73ca155967`. It was not present at combined source `ad891694`; that source used acquisition blob `12d64c46`, while the donor uses `222a2077`.

## Recovered behavior

Project-destination admission now refuses final-component symbolic links and Windows junctions. The same admission rule is repeated after verified staging and before the import callback. The initial check remains before staging, existing consent checks are retained, and the second check remains inside the existing cleanup protection so refusal discards staged files. Absent and actual empty directories remain supported.

Only five files were recovered: the acquisition module, its workflow/persistence contract, and three authored protective regression files. Every recovered file matches the donor byte for byte. The donor's shared status, ledger and handoff-index edits were excluded to preserve the integration lineage. The [original branch history bundle](evidence/generation33/parallel-acquisition-history.bundle) preserves its complete 28-commit increment above generation29.

## Independent evidence and limits

Independent defensive review on the exact donor passed **96 cases and skipped one native Windows case**. Eight passing cases are new protective controls; 88 are existing affected cases. Whole-tree Ruff passed. Tests used provided synthetic artifacts, owned temporary directories and fake transport; there was no external network request or execution of analyzed targets. The [review receipt](evidence/generation33/acquire-g32-review.json), [JUnit](evidence/generation33/acquire-g32-defensive-review.xml), and [five-file extraction](evidence/generation33/acquire-g32-minimal.patch.gz) are retained.

The Windows junction test is skipped on Linux, so native Windows behavior remains unqualified. These checks observe only the final path component. They do not anchor parent directories, make publication atomic, prevent all substitutions after the second check, or close the separate Linux forced Strings-export race.

The original author retained bounded filesystem-control evidence in the donor's generation30–32 handoffs. This review does not relabel those controls as a repository-source baseline failure run. Behavioral uniqueness is supported by the exact missing guards in the current source and the independently executed protective regression selection.

Combined-source qualification follows this source checkpoint; predecessor and donor passes alone do not qualify the new integrated candidate.

## Integrated qualification

The extraction is committed as `71b535cc5c1ca0ccc6762831a5d8a137644d14fc`. A combined 26-file selection passes 493 cases with the single native Windows junction skip. Its [receipt](evidence/generation33/combined/receipt.json) records a clean unchanged source; whole-tree Ruff and complete-candidate whitespace checks pass. This remains focused qualification and does not close native or full-suite gates.
