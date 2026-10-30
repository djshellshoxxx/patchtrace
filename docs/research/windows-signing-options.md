# Windows Authenticode signing options for a PyInstaller OSS app

Status: research note, 2026-10-15. Input to SPEC-52 (`docs/specs/windows-release-signing-policy.md`). No code, no purchase, no signing performed.

Access note: `learn.microsoft.com`, `signpath.org` and `msrc.microsoft.com` returned egress 403 or DNS failure from the research sandbox on 2026-10-15 (`curl` CONNECT 403 from the agent proxy). Microsoft and SignPath facts below come from search-result snippets, not from fetched pages, and are tagged `[S]` (snippet only, re-check at decision time). Facts from pages that were fetched are tagged `[F]`. Anything not located in any source is `[U]`.

Retrieval date for all sources: 2026-10-15.

## 1. Options compared

| Option | Cost (USD, public list or reseller, `[S]`) | Eligibility | Effort | Trust effect |
|---|---|---|---|---|
| Azure Artifact Signing (formerly Trusted Signing), public trust | Basic $9.99/month for up to 5,000 signatures; Premium $99.99/month for up to 100,000; $0.005 per extra signature. Source: [Azure product page](https://azure.microsoft.com/en-us/products/artifact-signing) and [quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart), retrieved 2026-10-15 `[S]` | Individual developers: **United States or Canada only**, and the Azure billing account must be type Individual. Organisations: wider country list (quickstart lists e.g. AU, NZ, JP, KR, SG, CH, NO, IL) `[S]`. Identity validation takes "a few business days" `[S]`. Organisation age is not mentioned in any source found `[U]` | Medium: Azure account, Artifact Signing resource, certificate profile, app registration with Signer role, OIDC federated credential for the GitHub environment. Official action: `Azure/artifact-signing-action`, which recommends OIDC and an RFC 3161 timestamp `[F]` ([repo README](https://github.com/Azure/artifact-signing-action), retrieved 2026-10-15) | Publicly trusted; keys in Microsoft-managed HSM, no key custody for the owner. New apps still show SmartScreen warnings until download reputation builds `[S]` |
| SignPath Foundation, OSS programme | Free for eligible OSS `[S]` (official pages say free; one third-party Habr article says it is "no longer free", unverified and conflicting `[U]`) | OSI-approved licence (MIT qualifies), no proprietary code from maintainer, actively maintained, already released in the form to be signed, documented on the download page, project publishes a code signing policy on its home page, build fully automated on GitHub-hosted runners `[S]` ([signpath.org/terms](https://signpath.org/terms), [about.signpath.io OSS](https://about.signpath.io/product/open-source), retrieved 2026-10-15). Foundation can revoke the certificate if rules are broken `[S]` | Medium: upload unsigned artifact, call `signpath/github-action-submit-signing-request` (pin a current tag; docs show `@v1`) with API token, org ID, project slug, policy slug `[S]` ([SignPath GitHub guide](https://about.signpath.io/documentation/trusted-build-systems/github), retrieved 2026-10-15). Application review and project onboarding required | Certificate is issued to **SignPath Foundation** as publisher, not to PatchTrace or Circuit Drift Labs `[S]`. Keys stay in SignPath's HSM `[S]`. Reputation is still per file and builds over time |
| Commercial OV certificate, cloud HSM or token | Sectigo OV roughly $220 to $320/year via resellers; DigiCert OV list $439/year `[S]` ([sslinsights](https://sslinsights.com/digicert-vs-sectigo-code-signing/), [sslinsights 2026](https://sslinsights.com/sectigo-code-signing-certificate-guide/), retrieved 2026-10-15). Cloud OV from one reseller about $116/year on a 3-year term, single source `[U]` | Any verified organisation or individual (individual identity validation exists; details not fetched `[U]`) | Medium to high: CA identity validation, key on HSM or shipped token (since 2023 no exportable PFX), HSM or KeyLocker-style integration in CI | Publicly trusted; reputation builds per file. Organisation or name on the cert is shown to users |
| Commercial EV certificate | Higher than OV; no price found `[U]` | Stricter identity validation (organisation) `[S]` | High: hardware token historically; cloud-HSM variants exist `[U]` | **No longer a SmartScreen shortcut.** Microsoft's documentation says the EV first-download bypass ended in 2024; the Trusted Root Program removed EV code-signing OIDs from August 2024 `[S]` ([Microsoft code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options), snippet, 2026-10-15). One 2025 forum comment disputes timing `[U]` |
| Self-signed / throwaway cert | $0 | none | low | Prohibited by SPEC-52 section 6. Does not build reputation |
| No signing, hash plus attestation (current policy) | $0 | none | low | Integrity only: proves the file came from the workflow run, not who the publisher is |

Certificate validity: the maximum code-signing certificate validity dropped from 39 months to 460 days from 2026-03-01, and DigiCert retired its 2- and 3-year plans `[S]` (sslinsights, retrieved 2026-10-15). Multi-year deals are worth less per year than older quotes suggest.

## 2. Eligibility and rules that matter

- **Key protection (CA/B Forum code signing baseline, in force 2023-06-01)**: OV and EV private keys must be generated and stored on hardware crypto modules at FIPS 140-2 Level 2 or Common Criteria EAL 4+ or equivalent, and marked non-exportable. Certificates are delivered on a token or installed on the customer's HSM `[S]` (AppViewX, GlobalSign support, Sectigo, retrieved 2026-10-15; the CA/B Forum ballot text itself was not fetched `[U]`). Consequence: a PFX in a CI secret is not an option for any publicly trusted certificate. This confirms SPEC-52 section 6.
- **SmartScreen reputation** is per file hash and per publisher certificate. A new build starts from zero, and reputation does not transfer across versions. Certificate renewal can reset reputation `[S]` (community thread, May 2026, AI-generated answer, weak evidence `[U]`). Microsoft advises keeping one certificate as long as possible `[S]`.
- **Warning text** on unknown files: "Windows protected your PC". A signature does not guarantee the warning is absent `[S]`.
- **Escalation for false warnings**: submit the file through Microsoft Security Intelligence; no public reputation threshold or review time exists `[S]` (Microsoft Q&A, retrieved 2026-10-15).

## 3. Antivirus false positives on PyInstaller onedir builds

- Onefile builds self-extract to a temp directory and are the most common heuristic trigger. Onedir avoids self-extraction. Evidence that onedir triggers fewer detections is anecdotal `[U]` (vendor blog, commercial bias).
- Stock PyInstaller bootloaders have been added to some AV signatures. Rebuilding the bootloader from source gives a unique hash and reduces signature hits. PyInstaller documents this mitigation and says it needs a C toolchain on each target platform `[S]` (PyInstaller docs via search snippet; onionshare commit history, older PyInstaller 3.x era, retrieved 2026-10-15). It reduces signature-based detections; heuristics can still fire `[S]`.
- Vendor submission: manual false-positive forms per vendor. Reports say each new version can be re-flagged, so submission is not a one-time fix `[S]` (itch.io comment, retrieved 2026-10-15, anecdotal).
- Signing helps reputation, not AV heuristics directly `[U]`.
- UPX: not verified by any source in this session `[U]`. Packers are a common heuristic trigger; SPEC-52 already excludes packing implicitly, so keep it off.

## 4. Signing in GitHub Actions without exposing keys

- **Azure Artifact Signing**: OIDC federated credential bound to repository and GitHub Environment name. The identity needs the Artifact Signing Certificate Profile Signer role. Workflow needs `id-token: write` and `contents: read` `[S]` (TeamDev and MSYS2 guides; action README). Subject-claim mismatches are the usual failure `[S]`.
- **SignPath**: API token and IDs as repository or environment secrets. Private key never in CI `[S]`. Signing request needs a trusted build: all jobs before the request run on GitHub-hosted agents `[S]`.
- **Commercial CA with cloud HSM**: CA's client tool or KeyLocker-style service; the key stays with the provider. Setup details not verified `[U]`.
- Keep signing in a job gated by a protected GitHub Environment with required reviewer, triggered only by an annotated `v*` tag, never `pull_request`. This matches SPEC-52 section 6.

## 5. Timestamping and verification

- Timestamp with RFC 3161 and SHA-256. In `signtool`, `/td sha256` must come after `/tr`; if it comes first the timestamp uses SHA-1 `[S]` (Microsoft signtool docs snippet, retrieved 2026-10-15).
- Verify on Windows with `Get-AuthenticodeSignature` (check `Status` and `SignerCertificate`) and with `signtool verify /pa /v`. The `signtool verify` details were not located in any source `[U]`.
- Verify on Linux CI with `osslsigncode verify`. Known gap: `osslsigncode` may not show the RFC 3161 chain; `osslsigncode extract-signature` plus `openssl pkcs7` shows the SHA-256 timestamp `[S]` (Tor Project ticket 29614, retrieved 2026-10-15). `signtool` and `osslsigncode` differ on timestamp-expiry checks `[S]`. Use both only if the gap matters.
- Recommended CI check: fail the job if `Status` is not `Valid`, if the timestamp is missing, or if the digest is not SHA-256 (matches SPEC-52 error code `PT-REL-TIMESTAMP-MISSING`).

## 6. SBOM and provenance

- `actions/attest-build-provenance` (v4, wraps `actions/attest`) creates SLSA build provenance in in-toto format for named artifacts. Public repos use the public-good Sigstore instance and are supported on all plans; private repos need GitHub Enterprise Cloud `[F]` ([repo README](https://github.com/actions/attest-build-provenance), retrieved 2026-10-15).
- Required permissions: `id-token: write`, `attestations: write`, `contents: read` `[U]`: the fetched README did not list them; confirm before merging the workflow change.
- Verify with `gh attestation verify <file> --repo <owner>/<repo>` `[S]` (README link, command not tested here).
- SBOM: not researched in depth. SPEC-52 does not require one; a CycloneDX or SPDX SBOM for the frozen folder is a possible later slice `[U]`.
- SLSA level claims: the attestation provides provenance, not a SLSA level by itself `[U]`; SLSA level depends on the build platform's isolation and is not verified here.

## 7. Recommended path for this project

1. **Now (alpha)**: stay unsigned as SPEC-52 says. Keep SHA-256 sidecars and `SHA256SUMS`. Add attestation only after the workflow permission check.
2. **Parallel, owner decision**: apply to SignPath Foundation first. The project fits: MIT licence, GitHub-hosted build, releases exist, and a code signing policy page can be added. Cost is zero if accepted. Trade-off: publisher is SignPath Foundation, not the project. Re-check the free-OSS terms on signpath.org before applying, since the Habr source disagrees.
3. **If SignPath declines or the owner wants the project's own name**: Azure Artifact Signing Basic at $9.99/month if the owner's billing account is type Individual and the owner is in the US or Canada, or an organisation account elsewhere. Cheapest route with no key custody. Otherwise an OV certificate with cloud HSM, about $220 to $440/year.
4. **Do not buy EV for SmartScreen**; it no longer gives an immediate shortcut.
5. Only switch on after the clean-profile checklist (M01 to M18 in SPEC-52) has a recorded pass. Expect SmartScreen warnings for the first builds even when signed.
6. Build the bootloader from source (PyInstaller bootloader build step) as a separate, cheap AV mitigation. Verify the exact steps against the PyInstaller version pinned to 6.22.3 first.

## 8. CI recipe outline (no secrets)

1. Trigger: push of annotated tag `v*` only; job uses GitHub Environment `release-signing` with required reviewer. No `pull_request` trigger.
2. Permissions: `contents: read` by default; `id-token: write` only in the signing job; `attestations: write` only in the attest job.
3. Build: unsigned frozen folder on GitHub-hosted runner, PyInstaller from pinned version, bootloader rebuilt from source if adopted.
4. Self-test: run frozen self-test; run `tools/release_policy_check.py --expect unsigned` on the unsigned folder.
5. Sign: only `PatchTrace.exe` (SPEC-52 section 7.2). Provider step: Azure Artifact Signing action (OIDC) or SignPath submit action (API token from Environment secret). RFC 3161 SHA-256 timestamp.
6. Verify: `Get-AuthenticodeSignature` status `Valid`; timestamp present; digest SHA-256; no third-party DLL hash changed (SPEC-52 `PT-REL-THIRDPARTY-MODIFIED`).
7. Package: zip, then `.sha256`, `SHA256SUMS`, then inventory, in that order (SPEC-52 section 6 order).
8. Attest: `actions/attest-build-provenance` on zip; record URL in notes.
9. Publish: prerelease only (SPEC-52 section 7.1). If the token returns 403, report "build green, release not published", no loop.

## 9. Gotchas

- Signing after hashing invalidates the hash. Order in step 7 is mandatory.
- Timestamp server outage fails the job; do not sign without a timestamp.
- Certificate expiry without timestamp kills signatures; with timestamp they stay valid.
- Re-signing third-party DLLs changes their hashes; never do it.
- SmartScreen reputation resets per build hash; every alpha will warn at first.
- OV and EV private keys cannot be copied off hardware; plan for loss or revocation (SPEC-52 section 7.3).
- SignPath certificate publisher name appears to users; decide before applying.
- Azure Artifact Signing identity follows the billing account type; a mismatched account blocks individuals.
- Certificate renewal can reset reputation; plan renewal dates.
- `osslsigncode verify` may not show RFC 3161 chains; use `extract-signature` plus `openssl pkcs7` when debugging.
- Antivirus: every new build can be re-flagged; re-scan each release and keep hashes.

## 10. Corrections to the policy doc (`docs/specs/windows-release-signing-policy.md`)

Note: the policy file is at `docs/specs/windows-release-signing-policy.md`, not `docs/specs/program-e/WIN-release-signing-policy.md` as named in the task. Its content was read from that path.

1. Section 7.4, Azure row: "eligibility by region and organisation age may exclude the owner" should read: individual developers only in the United States and Canada, with an Individual-type billing account; organisations have a wider country list. Organisation age is not a documented criterion in any source found `[U]`.
2. Section 7.4, Azure row: the product is now named Azure Artifact Signing (Trusted Signing is the former name). Price: $9.99/month Basic `[S]`.
3. Section 7.4, EV row: "Microsoft's SmartScreen treatment of EV has changed [unverified]" is now resolved: the EV first-download bypass ended in 2024 `[S]`. EV gives no immediate SmartScreen advantage.
4. Section 7.4: SignPath row. Add that the publisher on the certificate is SignPath Foundation, and that eligibility requires a published code signing policy and GitHub-hosted build `[S]`.
5. Section 2 table: the CA/B Forum hardware-key claim is now supported by secondary sources `[S]`, still not the ballot text `[U]`.
6. Section 6, antivirus row: "one-folder already avoids self-extraction" is correct, but reduction in false positives from onedir is anecdotal `[U]`. Add the bootloader rebuild mitigation.
7. Section 2 table: the `attestations: write` and `attest-build-provenance` claim is partly supported. The action's README was fetched; the required permission list was not in it `[U]`.
8. Section 7.1 and 9 are consistent with this note; no change.
9. Section 9 WIN-1 mentions `--manifest asInvoker` and `longPathAware`. Not researched here `[U]`.

## 11. Open owner decisions

1. Publisher identity: SignPath Foundation (free, OSS) versus the project or Circuit Drift Labs name (paid, Azure or OV).
2. Eligibility check: is the owner's Azure billing account Individual and in the US or Canada? Decides whether Artifact Signing is open to them.
3. Budget ceiling: $0 (SignPath only) versus about $120 to $440/year (paid).
4. Apply to SignPath now, in parallel with the alpha series, as the policy default suggests?
5. Adopt bootloader rebuild from source as an AV mitigation now (C toolchain on the Windows runner)?
6. Attestation: approve the workflow permission change, which the policy already flags as possibly causing a 403 on publish.
7. Commit to re-scanning each release on VirusTotal and recording results (consent rule for uploads must be confirmed first).
