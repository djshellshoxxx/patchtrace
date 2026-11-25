# Windows desktop acceptance

Source commit `ea16019601486c831941f9bc1a7ba5862a170317` on main. GitHub Actions returned a successful push run for this exact SHA. The reviewer used Linux.

| Gate | Hosted evidence | Result |
|---|---|---|
| Build and test Windows desktop | [Producer 136892880665](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193/job/136892880665) | Repository pytest, Ruff, PyInstaller build, frozen smoke/self-test, portable ZIP outside checkout, NSIS build, install, launch and uninstall passed. |
| Consume downloaded desktop artifacts on a separate Windows runner | [Consumer 136910859852](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193/job/136910859852) | Sidecar checksum verification, extraction and portable launch, installer launch and uninstall passed. |
| Automated Windows Qt | [Qt 136892880761](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193/job/136892880761) | Passed. Manual desktop, accessibility and Windows trust prompts require operator evidence. |
| Artifact delivery | [Main QA 44919714193](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193) | GitHub reports PatchTrace-windows-x64 ID 14715139165, SHA-256 b32c6500cc60270dcbfbbf4d5f8d86d6a1da7da9074ad2ab7f3eacff7e29da3b. Release job skipped. |

The digest is GitHub's value for the outer archive. The hosted consumer checked the inner binaries. The reviewer did not re-download that artifact or repeat Windows execution. These desktop jobs package the lite application. A changed candidate requires checks for its own commit.

The exact-main push job logs also report 24,205 passed, 185 skipped and 3 expected failures on Windows. Linux reported 24,336 passed, 53 skipped and 4 expected failures. The Windows consumer logged inner SHA-256 values AB6E6D5C0A7B4FEED004118EC7AB2294FCDC0E2C1E8131F3AD9157600BF596D1 for the portable ZIP and C7B3FFD7063C5662DE8C0F9D6F3BFB2AA975CA96FFC5E6AB254A07E73015739A for the installer. Time-stamped observations are recorded in hosted-packaging-evidence.json.
