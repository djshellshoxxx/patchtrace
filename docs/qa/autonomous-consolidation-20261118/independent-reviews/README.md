# Independent tooltip and strings-publication review

The inventory worker independently reviewed both changes after the author
implemented them. These results are scoped reviews, not full-suite, Windows or
release acceptance. Exact sources, commands, counts and file hashes are retained
in [review-receipt.json](review-receipt.json).

## Tooltip coverage

Source `010b9e6170b9a882556d11aed0a3186873cd216f` constructs the shipped inventory
dialog in the global registry sweep and inspects its real status and tab widgets.
The existing registry-coverage assertion is unchanged; no ID is exempted.
Independent focused replay passes: **1 passed in 1.80 seconds**.

Two external negative controls clear the actual status and tab tooltips at
construction time. Each run deliberately fails with the matching
`kb.inventory.status: empty tooltip` or `kb.inventory.tabs: empty tooltip`
assertion. The mutation plugin and raw failure logs are retained. Those two
expected failures demonstrate detection; they are not product failures.
No blocking issue was found in the changed test scope.

## Strings publication

Reviewed author candidate is based on main `9c411ca3` and identified by the four
SHA-256 file digests in the receipt. The author/new/export/CLI selection passes
independently: **34 passed in 0.91 seconds**. It overlaps the author selection
and is not an additive unique-test count.

Nine additional controls pass: late symlink and directory destinations remain
unchanged; two simultaneous writers publish exactly one complete winner; forced
replacement of a symlink preserves its referent; unsupported hardlinks fail
without replacement fallback; `fdopen` failure closes its still-owned descriptor;
sync failure preserves an unrelated stage; and the old predictable stage filename
is never reused in either force mode. Raw external results are **9 passed in
0.20 seconds**, with JUnit and source retained.

No blocking issue was found for exclusive unpredictable staging, no-clobber
publication and explicit forced replacement. This change does not establish
resistance to adversarial export-parent or stage-path replacement. That stronger
ownership boundary is a separate implementation/qualification task. Native
Windows and final combined-head gates remain required.
