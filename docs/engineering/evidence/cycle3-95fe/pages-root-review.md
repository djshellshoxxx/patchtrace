# Pages deployment guard — independent coordinator standards review

Reviewed candidate `e54e4d0afbcdc3916539c62810877faa65842d5e`, tree `ecc943693a310455f1427fff7e3d1abad8f07dd0`, against `6b6fcd3597a604212032ffc453477aeb6edc69ff`. Reviewer is independent of the Pages author. No blocking source finding.

The sole workflow change is a job-level expression. It reads the push-head commit message as expression data, without introducing a shell interpolation, and limits the hold to push events. Manual dispatch retains the prior behavior. `needs: build`, workflow triggers, build/test/artifact commands, permissions and deployment environment remain unchanged. The predicate contains no `always()` or other status override. Existing successful-build dependency behavior is retained.

The source regression pins the complete predicate and build dependency; the existing build-flow control now checks that the hold is absent before the deploy job and that build/tests/upload remain present. The shell-data test is correctly narrowed from forbidding all event references to forbidding event references in run commands: the newly permitted reference is solely in the declarative condition. These are text assertions, not a GitHub expression-engine emulator or deployment receipt.

The specification and site README explain that the actual resulting merge commit must contain `[no deploy]`; a PR title or ancestor marker alone does not control the push. The separately existing `[no release]` marker remains necessary. No changes to global GitHub settings, credentials, publication dependencies or application behavior occur. Root inspected this diff; the author owns executed test receipts, and a separate spec reviewer is reporting independently.
