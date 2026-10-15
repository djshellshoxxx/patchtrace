# Review and correct function relationships

A function relationship is an engine proposal or an analyst correction. Review the relationship independently of any interpretation attached to it.

Use the match review selector to record unreviewed, accepted, rejected, or needs-review. Accepting a relationship records your judgment; it does not automatically accept a finding.

To correct a relationship:

1. Select the match.
2. Choose `Correct match….`
3. Select the exact existing older and newer function records involved.
4. Choose the relationship.
5. Enter the required reason.
6. Select `Save correction.`
7. Inspect the resulting relationships and any stale findings.

For an added function, select newer records only. For a removed function, select older records only. Split and merged relationships involve the corresponding multiple-function selections. Use ambiguous or unmatched when the association remains unresolved.

Corrections operate within the relevant analysis run. They cannot borrow a function record from another run. Other relationships using the selected records are adjusted; unused remainders become unmatched.

The correction preserves its reason and prior relationships rather than rewriting raw backend output.

`Project → Undo latest match correction` restores the latest eligible correction. It is not a general undo for notes, reviews, or every project edit.

A correction, correction undo, new comparison, import, or orientation change can make existing interpretations stale. Retained historical evidence must not silently navigate into unrelated current code.

Sources: `README.md,` “Correct matches and record your review”; `docs/specs/ui.md;` `AGENTS.md.`
