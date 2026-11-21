# Independent documentation and probe review

Reviewer: fresh child worker `generation10_force_design/syscall_docs`, independent
of the probe author. The reviewer researched primary Linux man-pages and kernel
documentation, then inspected the authored probe and its raw results without
rerunning or editing them.

## Initial review

The production counterexample was valid: import selection was pinned to the
worktree, the source hash matched the committed source, and an actual same-EUID
child changed the staging name before the saved real `os.replace` ran. The
resulting target held foreign bytes before the product refused its receipt.

The reviewer identified one evidence-attribution defect: the original result's
`filesystem` field measured the checkout, while fixtures used temporary
directories elsewhere. It could not establish which filesystem hosted each
experiment. The initial native record, probe log and exact executed probe remain
unchanged; filesystem attribution in that record is superseded.

Additional harness findings were specific and non-product: accept exact expected
errno values instead of any failure; register directory cleanup before opening
O_TMPFILE; ensure a cleanup failure does not skip remaining callbacks; distinguish
the parent's authored intervening publication from the child's initial swap;
and do not treat EUID 1000 as proof of an unprivileged capability set.

## Correction and final review

The final probe records each fixture's filesystem and labels the checkout
filesystem separately. It uses exact expected errno assertions and `ExitStack`
cleanup, identifies the later publication's actor, and records the held write
lease as `F_WRLCK` before and after substitution/publication.

The author replayed the same 14 controls on tmpfs and overlayfs, retaining
`results-final.json` and `results-overlay.json`. Both completed all controls with
zero unavailable-capability outcomes. Their checked operation, outcome, errno
and lease-state fields agree. These are two filesystem replays of the same
controls, not 28 distinct controls.

The reviewer inspected the corrected probe and both final records. Verdict:
**review clear for the bounded conclusions**. The filesystem attribution and
identified harness weaknesses are resolved. No production repair, universal
impossibility result, uninstrumented race frequency, or broader native acceptance
was established. The forced-publication finding remains open.
