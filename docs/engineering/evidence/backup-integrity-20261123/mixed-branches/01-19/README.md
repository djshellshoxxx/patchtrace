# Historical mixed branches 1–19

The table covers the first 19 of the 37 rows marked `mixed needing manual review` in `docs/engineering/evidence/installer-preferences-20261123/remaining-triage.tsv`, in original order. All 19 remote heads matched the recorded full commit IDs. GitHub metadata confirmed all 13 linked PR heads, including the merge of #146 to the historical #126 branch.

After the keyboard contract cross-check, nine rows describe superseded carriers, records or specific proposals. Four identify equivalent maintained behavior, four retain unproved ordinary changes, one identifies recovered source, and one assigns an exact alternate file to active PR #316. Each decision applies to the named ordinary scope. Specialist research, advisory and native-tool scope was classified by category only.

## Ordinary work still requiring a decision

- Rows 2 and 8 share identical historical table and palette source. PR #176 adds keyboard sorting of the current column and raises the empty-query palette limit to 400. Main and the candidate retain a limit of 50 and lack that table keyboard route. A subsequent contract check resolved the specific proposal. The current GUI specification reserves Alt+Up/Down for difference navigation and keeps the palette bound at 50. Desktop tests confirmed both behaviors on main and on the combined candidate. The general T4/T16 backlog entries do not override the explicit contract. [Current GUI specification](../../../../../specs/gui-framework.md) · [Main control](main.log) · [Candidate control](362.log)
- Row 6 proposes shared hierarchical configuration and source-version reporting. The historical config module has no counterpart at its path on the reviewed heads. The later #320 branch in row 37 has a different build-information module and its own packaging emitter. Coordinate the provenance question with that owner. Equivalence of the configuration interface remains unproved.
- Rows 9 and 10 contain private creation staging and an explicit GUI retry for verified incomplete project directories. Current creation cleanup, background Create and bounded store retry cover some of that behavior. The explicit modal Retry action and cancellable retained-input validation are distinct. Rows 11–14 and 19 carry the same two retry modules as row 10.
- Row 18's alternate immutable-file publication module matches open PR #316 byte-for-byte. Its owner already has the exact source.

## Evidence

Main was `ea16019601486c831941f9bc1a7ba5862a170317`. The application candidate was `256042090462bb0ec14921241edd794c64362587`, tree `a56bd81ec4995267c7589d9509b156b21313e962`. Historical-main conclusions use reachable commits and same-path blobs. A candidate observation makes no claim of a main merge.

The `base` column gives the historical merge base or bases. For rows 9–11, `changed_paths` counts the union against both bases. The witness count is the number of named file comparisons. Function-level conclusions refer only to the specific behaviors described. The source row order, full tips, linked PR numbers, shared retry/table/palette blobs and named main-history file identities were rechecked when the table was saved. No historical automation or donor code ran.
