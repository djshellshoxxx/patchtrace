# Independent technical review of PatchTrace PRs 360 and 361

**Decision at the reviewed heads.** The code and test composition is suitable for the normal integration queue. The release decision remains open. One sentence in the child report overstates what the baseline Qt measurement establishes. Correct that sentence and rebind the hosted evidence to the resulting head.

| Ref | Commit | Full tree | GitHub test merge |
|---|---|---|---|
| Main at review | `ea16019601486c831941f9bc1a7ba5862a170317` | `4a07cd88ded407bef30a8aeb81961e4041822dc2` | |
| Parent PR 360 | `6ffe819e71d48793f8207bd64d7480fbc03e2ef5` | `00b0612e2aa9fef21e2e6f16ce465407ea075c4f` | `8135def48fe3fd1b651928f6c6144e08f047619a` |
| Child PR 361 | `c60f4ecc425294be368009b0711cafb803117cb6` | `512841a6b13d0d66ddde71191a1a9e1f13a90d49` | `5370090dd716e548ba8d82a8240885fd802a7668` |

GitHub’s PR API and an independent Git fetch agree on both heads. Each synthetic merge names the correct base first and PR head second. Each merge tree exactly matches the corresponding complete head tree. Git independently combined `6ffe819e` and `2400d273b976ed98dfcbe4393bdc99925d3b0a46` into tree `48cd859a9079b5e2497f9a729c0042e995ec4a9e`, matching the two-parent application commit `88fcfaf7bd0d2c4047a0a71e357e18e8e9e962a9`. The child’s final commit adds and updates engineering records only.

## Code and publication controls

Reviewed the source differences of both PRs. The parent changes project creation, SQLite paths, backup reopening, Qt recent-project settings and repository inventory matching. Its Windows SMB fixture uses a temporary directory on a loopback share. The child changes one Qt rendering callback and one NSIS registry cleanup operation, along with their tests, help and installation guidance. Its two desktop files match the historical donor's implementation and widened regression. No workflow, site, release gate script or publication marker logic changed in the stack. The Windows smoke continues to run in both the producer and separately downloaded-installer consumer at lines 67 and 140 of the existing Windows QA workflow.

The NSIS change removes the installation-owned `InstallDir` value and the uninstall registration. The smoke creates two named sentinels, invokes the real uninstaller, and checks sibling and nested preferences. It also checks project files and uninstall registration. Source inspection cannot establish Windows registry behavior. Each authored commit in this stack carries both publication opt-outs. An eventual merge message is a separate input and needs the same opt-outs.

## Evidence and finding

Parsed the committed test manifests, JUnit files and console logs. The parent’s affected application selection reports **603 passed in 26 modules**. The combined application selection reports **985 passed, one skipped in 31 modules**, and no failures. The skip identifies the Windows loopback SMB fixture on Linux. The two runs overlap. The child does not claim local Linux qualification of native Windows installation or the disconnected runtime.

Independently replayed the installer manifest, Qt bulk-load regression, SQLite constructor cleanup and project URI tests on a clean checkout whose full tree exactly matches the child head. **54 passed** on Linux/offscreen Qt. `git diff --check` passed for the complete stack.

**Documentation correction.** The UI-02 row of `docs/engineering/desktop-acceptance-20261123.md` says Qt formatted thousands of rows outside the viewport. The measurement counted calls to the controller’s `spans` method. The baseline could call this method for off-window rows and receive no spans. The supported result is 5,780 out-of-window dispatches before the change and zero after it on the tested fixture. The performance records appropriately leave end-user/native latency open.

## Remaining gates

At the hosted snapshot on November 23, both PRs were drafts. PR 360 showed five successful native jobs, seven running Linux/Windows and Qt jobs, and a skipped release gate. PR 361 showed twelve queued jobs and a skipped release gate. The synthetic merge refs had no check runs listed directly. These are point-in-time observations. Confirm job checkout identities and results after each head or base change, especially Windows producer/consumer smoke, SMB and full platform suites. A skipped SMB test leaves native SMB acceptance outstanding. The branch census and scoped tests do not qualify the complete disconnected production runtime, a reproducible installer or the full release.
