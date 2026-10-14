# WIN: Windows release and code-signing policy (PyInstaller one-folder zip prereleases)

Status: draft policy, written 2026-10-14 (Program E, E-1). Complements `docs/specs/windows-acceptance-and-milestone-builds.md` (release channels, verification, notes template) and `docs/windows.md`. No signing is performed by this document; it fixes what is signed, by whom, and what the project may truthfully say.

Source-access note: `learn.microsoft.com`, `docs.github.com`, `signpath.org`, `azure.microsoft.com` and `www.rfc-editor.org` were not reachable from the research sandbox on 2026-10-14 (egress proxy 403 or DNS failure). Claims about those services are marked `[unverified]` and the owner must re-check them at decision time; they change often. Repository facts were read directly.

## 1. Verdict and scope

Decisions:

1. **Alpha and beta prereleases stay unsigned**, and every release note, README line and the Setup help say so in plain words, including that Windows SmartScreen and antivirus may warn. No wording implies a publisher identity.
2. Integrity without signing: keep the `.sha256` sidecars, add a combined `SHA256SUMS` asset and (owner-approved, workflow-permission permitting) a GitHub build-provenance attestation for the zip. Hashes and attestations prove "this file came from this workflow run", not "this publisher is trusted".
3. A signing path is specified now so it can be switched on later by an owner decision: provider-neutral invariants (section 7), no private key ever on a developer machine, a Claude worker, a pull-request job or in a repository secret as a file.
4. No final (non-prerelease) release, no auto-update, no telemetry, no installer, no elevation. Unchanged from `AGENTS.md` and `docs/windows.md`.

Not built here: purchase of a certificate or enrolment (owner action), SmartScreen reputation management, an MSI/MSIX installer, driver or kernel signing.

## 2. Sources and facts

| claim | source | retrieved | confidence |
|---|---|---|---|
| Windows build is `--onedir --console --hide-console hide-early`, no `--icon`, no `--version-file`, no `--manifest`; archive `PatchTrace-0.1.0-windows-x64.zip` plus `.zip.sha256` (`<sha256>  <name>\n`); `file-inventory.json` and `dependency-versions.json` inside | `tools/build_windows.py` (this repo) | 2026-10-14 | high |
| Release job: `permissions: contents: write`, `softprops/action-gh-release@v2`, `prerelease: true`, tag `v0.1.0-beta.<run_number>` or the pushed `v*` tag, name hard-coded "PatchTrace beta N" | `.github/workflows/qa-windows.yml` (this repo) | 2026-10-14 | high |
| Publishing returned HTTP 403 "Resource not accessible by integration" when a commit changes `.github/workflows/*`; the zip then exists only as an Actions artifact | `docs/plans/claude-autonomous-alpha-handoff-20261013.md` B1; `windows-acceptance-and-milestone-builds.md` 1.1 | 2026-10-14 | high |
| Repo licence MIT, copyright "Circuit Drift Labs" | `LICENSE` (this repo) | 2026-10-14 | high |
| PyInstaller 6.22.3 pinned; bootloader is an executable inside the folder that is the only PatchTrace-built PE | `pyproject.toml` dev extra, `build_windows.py` | 2026-10-14 | high |
| PyInstaller supports `--version-file` and `--manifest` for the built executable | https://pyinstaller.org/en/stable/usage.html | not retrieved (not attempted after proxy failure) | [unverified] |
| Authenticode signatures embed in the PE; a zip cannot carry one, so the zip is protected by hash and attestation, not signature | PE/Authenticode format, see `SPEC26D2-pe-version-authenticode.md` section 2 | not retrievable | [unverified: MS host blocked] |
| Public CAs require code-signing private keys on certified hardware or a managed HSM service since the CA/Browser Forum baseline change of 2023; a PFX in a CI secret is therefore not an option for publicly trusted certificates | https://cabforum.org/working-groups/code-signing/requirements/ | not retrieved | [unverified] |
| SmartScreen reputation is per file hash and publisher certificate, builds gradually, and a signature does not guarantee absence of a warning | Microsoft Defender SmartScreen documentation on learn.microsoft.com | not retrievable | [unverified: MS host blocked] |
| A GitHub OIDC token (`id-token: write`) lets a job authenticate to an external service without a stored secret; artifact attestations use `attestations: write` and `actions/attest-build-provenance`, verified with `gh attestation verify` | https://docs.github.com/en/actions | not retrievable | [unverified] |
| Browser-downloaded files carry a Zone.Identifier (Mark of the Web); Explorer extraction propagates it to extracted files, which is what triggers the SmartScreen prompt on `PatchTrace.exe` | learn.microsoft.com Attachment Manager / Zone.Identifier documentation | not retrievable | [unverified: MS host blocked] |

## 3. Standalone baseline versus PatchTrace value

Standalone baseline: a PyInstaller zip on GitHub Releases is what most small tools ship; users face SmartScreen and guess whether it is safe.

PatchTrace-specific value (this is an RE tool; its users inspect signatures for a living, so honesty is a feature):

- **Dogfood the inspector**: CI runs PatchTrace's own `pe_overview` on `PatchTrace.exe` in the built folder and asserts that the release note's "Signed: yes/no" line equals `certificates.present`. The release cannot claim a signature that is not there, or hide one that is. With SPEC-26 D2 the same step also records signer, digest algorithm and timestamp claim in the notes.
- **Build facts as anchors**: `PatchTrace.exe` carries a version resource (`--version-file`), so a user who opens it in PatchTrace's File overview sees ProductVersion = release tag base and OriginalFilename, which is the same field the KB search and report v2 provenance use.
- **Reproducible evidence**: `file-inventory.json` (every file) is extended with per-file SHA-256 so the release can be diffed against the previous release with PatchTrace itself (old/new build pair of PatchTrace).

## 4. Cross-feature links

| Anchor | Direction | Counterpart | Use |
|---|---|---|---|
| build fact: version resource of `PatchTrace.exe` | emit (build) | SPEC-26 D2 reader | Self-test that the reader reads the project's own release |
| report provenance: PatchTrace version, release tag, zip SHA-256 | emit | RPT2 `tool` block | Exports state which build produced them |
| diagnostics bundle: signed state, SHA-256 of `PatchTrace.exe` | emit | support bundle (future) | Support can tell an unsigned alpha from a signed build |
| release notes `Open gates` | consume | `docs/qa.md`, ledger | Unsigned status is a standing open gate |

## 5. Synergy test

Scenario: build two synthetic frozen folders in CI-free unit form, `release_policy_check.py` run against fixture folders. Case A: folder whose `PatchTrace.exe` fixture has no certificate table and a notes file saying "Unsigned" passes. Case B: same notes but a fixture PE with a synthetic certificate table fails with "notes say unsigned but a signature is present". Case C: notes say "Signed" and no table fails. Case D: notes lack the SmartScreen sentence while unsigned, fails. Each channel alone (hash match, notes grep, PE inspection) misses at least one of B, C, D. Tests: `test_policy_unsigned_notes_match_pe`, `test_policy_signed_claim_without_table_fails`, `test_policy_requires_smartscreen_sentence`.

## 6. Traps and guards

| Trap | Guard |
|---|---|
| Calling an unsigned build "verified" because a hash exists | Fixed wording: "SHA-256 shows the download is intact. It does not show who built it." |
| Self-signed or throwaway certificate used to "get a signature" | Prohibited: it does not build SmartScreen reputation, trains users to ignore trust dialogs, and would read as `untrusted` in PatchTrace's own inspector |
| PFX or token in repository secrets used by fork PRs | Signing job runs only on `push` of an annotated `v*` tag, in a protected GitHub Environment with required reviewer (the owner), never on `pull_request`; no secret file; OIDC-federated or HSM-backed key only |
| Signing changes bytes after the hash was recorded | Order is fixed: build, self-test, sign, re-verify, zip, hash, attest. `file-inventory.json` and sidecars are generated after signing |
| Re-signing third-party DLLs | Never; Qt, Python and VC runtime files keep upstream signatures. Only PatchTrace-built PEs are signed: `PatchTrace.exe` (and any PatchTrace `.pyd` if added). Test lists unexpectedly modified third-party hashes |
| Missing timestamp makes signatures die with the certificate | Signing requires an RFC 3161 SHA-256 timestamp; a signing step without a timestamp fails the job |
| Antivirus false positive on a PyInstaller bootloader | Documented as possible; one-folder (not one-file) already avoids self-extraction behaviour; the owner may submit the exact hash to vendors' false-positive forms manually; PatchTrace never uploads the build to third-party scanners automatically (consent rule) |
| Token cannot publish (403) | Report "build green, release not published" (existing rule); never retry in a loop; Actions artifact remains the distribution |
| Claim of "no warning" | Never promised, even when signed [unverified SmartScreen reputation rules] |
| Release page edited by a worker to add a "signed" badge | Notes are generated by `tools/milestone_notes.py` only, with the policy check as a gate |

## 7. Contracts

### 7.1 Channels and naming (extends windows-acceptance 1.2)

| Channel | Tag | Trigger | Signed | Publish |
|---|---|---|---|---|
| integration | `v0.1.0-beta.<run_number>` | push to `main` | no (v1 policy) | automatic prerelease |
| alpha candidate | `v0.1.0-alpha.<n>` annotated | owner pushes tag | no until owner enables signing | prerelease |
| signed candidate | `v0.1.0-rc.<n>` annotated | owner pushes tag, environment approval | yes, if signing enabled | prerelease only |
| final | none | explicit owner instruction only | n/a | never automatic |

### 7.2 What is signed (when enabled)

Signed: `PatchTrace.exe` only (plus PatchTrace-authored `.pyd` or helper executables if ever added). Not signed: the zip, third-party binaries, `.json`/`.md`. Digest SHA-256, RFC 3161 timestamp SHA-256, dual signing not used.

### 7.3 Key custody

The owner holds the signing account and any hardware token or cloud signing-service identity. CI authenticates by short-lived OIDC federation to the signing service, scoped to this repository, the `release-signing` Environment and tag refs. No agent, worker, local session or pull-request job receives the key or credentials (`AGENTS.md`: credentials are session-only). Compromise procedure: revoke at the CA, rotate, publish a notice in the release notes and `docs/qa.md`, mark affected releases as superseded, never delete history silently.

### 7.4 Provider options (owner decision; all `[unverified]`, re-check eligibility and price)

| Option | Fit | Risk |
|---|---|---|
| Managed cloud signing service from Microsoft (Trusted Signing / Artifact Signing) | OIDC-friendly, no key custody | eligibility by region and organisation age may exclude the owner |
| SignPath Foundation free tier for open source | MIT licence fits; policy-based approvals | project approval and its reputation requirements |
| Commercial OV certificate with cloud HSM | broad availability | cost; HSM integration step |
| Commercial EV certificate with hardware token | historic fast reputation | token on a human machine conflicts with CI signing; Microsoft's SmartScreen treatment of EV has changed [unverified] |
| Self-signed | none | prohibited, see section 6 |

Default recommendation: stay unsigned through the alpha series, apply to the managed-service or SignPath route in parallel (lead time), switch on only after the Windows clean-profile checklist M01-M18 has a recorded pass.

### 7.5 Release record (additions to the notes template)

Lines added to `tools/milestone_notes.py` output: `Signed: no (PatchTrace.exe has no Authenticode signature)` or `Signed: yes - signer <subject CN> - digest sha256 - timestamp claimed <UTC> (claims read by PatchTrace's own inspector, trust not evaluated)`; `SmartScreen: unsigned or low-reputation builds can show "Windows protected your PC". Choose "More info" then "Run anyway" only after checking the SHA-256 above.`; `Provenance: attestation <url or "not generated: <reason>">`; `Assets` list with bytes and SHA-256 per asset (already present); `Supersedes: <tag or none>`.

User verification text (PowerShell): `Get-FileHash .\PatchTrace-0.1.0-windows-x64.zip -Algorithm SHA256`; for signed builds `Get-AuthenticodeSignature .\PatchTrace\PatchTrace.exe | Format-List Status,SignerCertificate`; expected for alpha: `Status : NotSigned`. Error codes for the policy tool: `PT-REL-NOTES-MISMATCH`, `PT-REL-HASH-MISMATCH`, `PT-REL-THIRDPARTY-MODIFIED`, `PT-REL-TIMESTAMP-MISSING`.

### 7.6 Data retention and support

Release assets are never deleted by workers. A superseded release keeps its assets and gains a notes line. No usage telemetry; the future support bundle excludes project content by default.

## 8. CLI and GUI

CLI: `python tools/release_policy_check.py --folder dist/PatchTrace --notes notes.md [--expect unsigned|signed]` exits 0 pass, 2 invalid arguments, 3 policy violation (message carries the `PT-REL-*` code). It uses `patchtrace.pe_overview` (no Qt), prints one JSON object with `--json`.

GUI: the existing Help menu (`ui.py`, `help_menu`) has no About entry today; add "About PatchTrace" (a dialog inside the main window's modal conventions, not a new app window) with three read-only lines: version and tag, "Signed: no (alpha builds are not code-signed)", and the zip SHA-256 recorded at build time in `dependency-versions.json`. Plain text only, copy button. Accessible name `about.build.signed`; tooltip id `about.signed` (WHAT: whether the program file has an Authenticode signature; WHY: to avoid mistaking a hash for a publisher; SOURCE: build record). States: signed "Signed: yes, signer <name> (the signer name is read from the file and is not independently verified here)". No dialog warns about SmartScreen; that is a README and release-notes matter.

## 9. Slice plan

| Slice | Scope | Exclusive files | Depends | Tier | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| WIN-1 | Version resource and manifest for `PatchTrace.exe` (`--version-file`, `--manifest` asInvoker, `longPathAware`) | `tools/windows_version_info.py` (generator), edit `tools/build_windows.py` | none | haiku-sonnet | S | Windows CI: frozen self-test passes; built exe read back by `inspect_pe` shows FileVersion (after SPEC-26 D2-2; before it, `strings`-free byte check of the `VS_FIXEDFILEINFO` magic) | skip manifest |
| WIN-2 | Per-file SHA-256 in `file-inventory.json`; `SHA256SUMS` asset | `tools/build_windows.py` (same owner as WIN-1, single slice owner), tests | WIN-1 | sonnet | S | inventory test, sums verify with `sha256sum -c` | sidecar only |
| WIN-3 | `release_policy_check.py` and notes lines | `tools/release_policy_check.py`, `tools/milestone_notes.py`, tests | WIN-1 | sonnet | M | tests in section 5 | notes lines only |
| WIN-4 | Workflow: policy step, derive release name/body from `github.ref_name`, optional attestation step | `.github/workflows/qa-windows.yml` | WIN-3 | sonnet | S | **expect 403 on publish when the workflow changes in the head commit**: this slice lands alone in its own PR and is verified on the next unrelated push | keep current workflow |
| WIN-5 | Signing job (disabled by `if: vars.SIGNING_ENABLED == 'true'`) | `.github/workflows/sign-windows.yml` (new) | WIN-4, owner decision | sonnet; opus only for the key-custody review | M | dry run with a throwaway local test key on a fixture exe, never a real key; job skipped by default | leave off |
| WIN-6 | About dialog lines | `ui.py` Help menu (shared file: serialize with other `ui.py` edits via the integration owner) | WIN-2 | sonnet | S | offscreen test of the three lines | omit GUI |

## 10. Amendments, test and QA plan

Amendments: `windows-acceptance-and-milestone-builds.md` 1.2 (naming table above) and 4 (notes template: add Signed, SmartScreen, Provenance, Supersedes); `docs/windows.md` last paragraphs: replace "Unsigned beta package" with the exact policy sentence and link here; `docs/modules.md`: add `tools/release_policy_check.py`, `tools/windows_version_info.py`; `README.md`: one-line unsigned notice and verification command; `docs/notices.md`: unchanged. `tests/test_spec_registry.py` excludes program-e (no registry edit until promotion).

Tests (hermetic, no network): `test_policy_*` (section 5); `test_version_info_generator_is_deterministic` (same tag gives same bytes); `test_inventory_hashes_match_files`; `test_thirdparty_unmodified` (hash list of copied notices and DLL names). Windows pitfalls: CRLF in generated JSON (write with `newline='\n'`), zip paths with backslashes (`/` in archive names), short parametrize ids.

Gates only the owner or Windows hardware can close and that are reported separately, never as done: SmartScreen behaviour on a clean Windows 11 profile (M01 plus download-and-extract path, both Edge and curl), Defender real-time scan result of the exact zip, provider eligibility and enrolment, first real signed build verification with `Get-AuthenticodeSignature`, attestation verification with `gh attestation verify` `[unverified]`.

## 11. Open questions (defaults, none blocking)

1. Should docs-only merges to `main` keep publishing betas? Default: no, add a `paths-ignore` for `docs/**` in WIN-4 (owner confirms; open decision already in windows-acceptance 1.1).
2. Which signing provider? Default: apply for a managed or OSS route now, decide after M01-M18 pass.
3. Include the Linux tarball in the attestation? Default yes, same step.
4. Show the Mark-of-the-Web guidance? Default: one README sentence ("if Windows warns, compare the SHA-256 first"), no instruction to disable SmartScreen or add Defender exclusions, ever.
5. Version number: `0.1.0` is hard-coded in six places; WIN-1 introduces one `src/patchtrace/__init__.py` source of truth only if the owner approves editing it (default: generator reads `pyproject.toml`).
