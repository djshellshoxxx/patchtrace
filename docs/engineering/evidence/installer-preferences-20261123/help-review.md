# Independent review of reader instructions

Both patches use base `ea16019601486c831941f9bc1a7ba5862a170317`. Review is limited to changed reader instructions and their referenced entry points.

| Change | Review and result |
|---|---|
| Installation and first backup, `18a29e8d05d733f673dfdb6f7861ed9a2ca47528` | Independently inspected the README, install, Windows, and RUN changes against the source at that SHA. The packaging workflow creates the documented canonical ZIP alias and matching digest; the cached release manifest for prerelease v0.1.0-beta.1035 contains both Windows packages, the Linux archive, and all three named sidecars. NSIS uses the current user, LocalAppData, Start menu and HKCU uninstall registration. The build workflow and packaging script agree on release extras, Python 3.12, NSIS 3.13, and compiler override. The portable and installer smoke scripts use RUNNER_TEMP; the installer also exercises the real current-user shortcut and registration. No source mismatch found in the changes. |
| Keyboard navigation, `a20bae8dd83ef77640cd55344190acd734b7e151` | The author verified the ordinary CLI output for `panels list`: 13 built panels, eleven with shortcuts, Files and Series without dedicated shortcuts, and one reserved Guide slot. The independent CI reviewer used a separate exact-commit checkout, confirmed the actual shortcut/title pairs, and ran all 215 help tests successfully in 1.16 seconds. Its receipt is `/tmp/pt-ci/help-recovery.log`. |

On the exact installation-docs source, an independent Linux run executed the three literal commands from the first-backup walkthrough in a new temporary directory. Sample creation, backup and backup information each returned zero. The backup verified its reopened database and hashes; the subsequent info command reported the same project UUID and revision 1. The source CLI help command returned zero. Local Markdown links in all four changed documents resolved.

The review covered repository source, release metadata and Linux execution. This did not exercise native Windows Setup, PowerShell smoke scripts, screen-reader output, or a full offline backend archive. The documentation correctly leaves disconnected runtime acceptance open.
