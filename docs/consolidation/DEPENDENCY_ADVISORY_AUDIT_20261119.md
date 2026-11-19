# PatchTrace dependency advisory review — 2026-11-19 UTC

## Result

**The original Pydantic pin has four upstream advisory matches. The qualified candidate pin, 2.14.2, is outside those four affected ranges. Qt remediation remains unresolved:** installed Qt reports 6.12.0, the version lies in seven assessed native-component advisory ranges, and official PyPI has no PySide6/shiboken6 6.12.1 files at the retrieval time. A downgrade to 6.11.3 does not cover all the findings. These version matches do not demonstrate an exploitable PatchTrace path.

Both PyPI and OSV automated audits completed for both actual installed dependency graphs. Each run represented all 15 packages and returned zero advisories. **That zero is a demonstrated lookup coverage gap:** direct PyPI and OSV API queries also return no findings for Pydantic 2.13.5, although upstream publishes affected ranges containing it. Primary advisory findings remain controlling.

## Exact scope and provenance

- Original source: `f114eb96c392d97ad88ddbbc0bda55c159b92559`; pyproject SHA256 `afb1b89ba00132c09a564a3dc4d4e6db7f4c441b6bb1b558df6786cfd0474ed9`. Original metadata was read from `/workspace/scratch/80dddc5347b2/patchtrace-venv/lib/python3.12/site-packages`.
- Candidate source: the same commit plus the uncommitted Pydantic-only pin change at `/tmp/pt81-test-harness/pyproject.toml`; SHA256 `8c391a0b25e607cf52bb170375a7077c537b298c7fb07c6c2ccad2fda1e1d6d6`. The stable `/tmp/pt81-pydantic-venv/bin/python` supplied actual candidate metadata. The receipt records each selected distribution origin and METADATA hash.
- Roots: runtime `PySide6`, `shiboken6`, `pydantic`, `protobuf`; optional `search` and `rules` roots `rapidfuzz`, `yara-x`, `iced-x86`. Requires-Dist edges and environment markers were evaluated for the observed Linux CPython 3.12.14 environment. No missing distributions or version mismatches were found.
- Dev/build/calibration groups, other platform graphs, native transitive SBOMs, and the auditor’s own graph are excluded. This review does not identify the contents of a final frozen Windows artifact. A later remote commit needs binding to these recorded source/dependency inputs.

| Distribution | Original | Candidate |
|---|---|---|
| annotated-types | 0.8.0 | 0.8.0 |
| iced-x86 | 1.21.0 | 1.21.0 |
| protobuf | 7.36.2 | 7.36.2 |
| pydantic | 2.13.5 | 2.14.2 |
| pydantic-core | 2.46.5 | 2.50.2 |
| pyside6 | 6.12.0 | 6.12.0 |
| pyside6-addons | 6.12.0 | 6.12.0 |
| pyside6-essentials | 6.12.0 | 6.12.0 |
| pyside6-pdf | 6.12.0.140 | 6.12.0.140 |
| pyside6-webengine | 6.12.0.140 | 6.12.0.140 |
| rapidfuzz | 3.14.6 | 3.14.6 |
| shiboken6 | 6.12.0 | 6.12.0 |
| typing-extensions | 4.16.0 | 4.16.0 |
| typing-inspection | 0.4.5 | 0.4.5 |
| yara-x | 1.21.0 | 1.21.0 |

Original requirements SHA256: `7e97b6d59b5c2e6f08919522a73a3e5d9fd0de2a77af6a782752bfd09e644270`.

Candidate requirements SHA256: `b231dda36d95aad4a66fd43b8bda06af102d186990499a7d1f69a5fc48b43d0c`.

## Automated audit receipts

`pip-audit 2.10.1` was installed only in `/tmp/pt81-advisory-venv` (47 MiB; cache below 1 MiB). Each run used the complete pinned graph with `--no-deps --disable-pip`, JSON output, descriptions and aliases, and a 10-second socket timeout. No Qt wheels were downloaded, project dependencies changed, auto-fix used, or advisory IDs suppressed. These flags are supported by the [official usage documentation](https://github.com/pypa/pip-audit#usage).

| Graph | Service | Completed UTC | Exit | Records | Skipped | Returned advisories |
|---|---|---|---:|---:|---:|---:|
| before | pypi | 2026-11-19T12:08:13.411989+00:00 | 0 | 15 | 0 | 0 |
| before | osv | 2026-11-19T12:08:37.116281+00:00 | 0 | 15 | 0 | 0 |
| after | pypi | 2026-11-19T12:14:20.098059+00:00 | 0 | 15 | 0 | 0 |
| after | osv | 2026-11-19T12:14:28.515343+00:00 | 0 | 15 | 0 | 0 |

Raw JSON, stdout/stderr, full commands, exit codes and start/finish times are saved separately as `pip-audit-runtime-{before,after}-{pypi,osv}-20261119.{json,log}` and corresponding `-result.json` files. The result dependency sets were compared with their exact pinned inputs.

Independent HTTP 200 cross-checks at 12:11:41 UTC confirmed an empty `vulnerabilities` array in `https://pypi.org/pypi/pydantic/2.13.5/json` and `{}` from `https://api.osv.dev/v1/query` for ecosystem PyPI, package pydantic, version 2.13.5. Raw responses and hashes are retained in `dependency-advisory-api-crosscheck-20261119.json` and its referenced files. These successful responses are not evidence that the upstream issues do not exist.

## Pydantic upstream findings

All four V2 rows below contain the original 2.13.5 pin. The 2.14.2 candidate clears these specific version ranges; this is a scoped minimum-fix statement, not a claim that 2.14.2 is the latest release. [PyPI also publishes 2.14.3](https://pypi.org/project/pydantic/2.14.3/). Upgrade compatibility evidence is maintained separately in the Pydantic qualification receipts.

| Advisory | Affected range | First fixed | Relevant condition |
|---|---|---|---|
| [GHSA-qpmf-fgh3-ff25](https://github.com/pydantic/pydantic/security/advisories/GHSA-qpmf-fgh3-ff25) | `>=2.13.0, <2.14.2` | 2.14.2 | JSON validation into an extra-allow BaseModel with a constrained __pydantic_extra__ key type. |
| [GHSA-3r8g-cqwr-jr29](https://github.com/pydantic/pydantic/security/advisories/GHSA-3r8g-cqwr-jr29) | `>=2.0, <2.14.2` | 2.14.2 | Aliased TypedDict or dataclass fields with extras allowed; advisory excludes BaseModel. |
| [GHSA-955g-x97g-8mcp](https://github.com/pydantic/pydantic/security/advisories/GHSA-955g-x97g-8mcp) | `>=2.0.0, <2.14.0` | 2.14.0 | Untrusted multi-host URL/DSN validation. |
| [GHSA-gj4f-r7mf-jjxh](https://github.com/pydantic/pydantic/security/advisories/GHSA-gj4f-r7mf-jjxh) | `>=2.10.0, <2.14.0` | 2.14.0 | Untrusted Fraction string with a large exponent. |

The original installation bundles Pydantic V1 compatibility version 1.10.26. Three additional V1 advisories were examined: [GHSA-r49w-vh47-r4hf](https://github.com/pydantic/pydantic/security/advisories/GHSA-r49w-vh47-r4hf), [GHSA-49g6-96jj-f7r9](https://github.com/pydantic/pydantic/security/advisories/GHSA-49g6-96jj-f7r9), and [GHSA-jfv7-ghgv-gx4x](https://github.com/pydantic/pydantic/security/advisories/GHSA-jfv7-ghgv-gx4x). Their version headers and fixed-version narratives have inconsistencies or overlaps, preserved in the JSON record. Their narratives direct V2 users of the compatibility namespace to 2.14.2. No application `pydantic.v1` use was found in the bounded source scan.

## Native Qt findings and available releases

The installed binding and `QtCore.qVersion()` both report 6.12.0. The following are native-component version matches. Component presence in the shipped artifact, indirect use, and actual application exploitability are not established by a package-version audit.

| Advisory / component | Affected versions stated by vendor | Fixed versions stated by vendor |
|---|---|---|
| [CVE-2026-100140](https://www.qt.io/blog/security-advisory-cve-2026-100140) — Qt5Compat / QXmlSimpleReader | 6.0–6.8.9; 6.9.0–6.11.2; 6.12.0 | 6.8.10, 6.11.3, 6.12.1 |
| [CVE-2026-110944](https://www.qt.io/blog/security-advisory-cve-2026-110944) — Qt HTTP Server / QHttpServer | 6.4.0–6.11.2; 6.12.0 | 6.11.3, 6.12.1 |
| [CVE-2026-114366](https://www.qt.io/blog/security-issue-cve-2026-114366) — Qt WebSockets / QWebSocket | 6.6.0–6.8.9; 6.9.0–6.11.2; 6.12.0 | 6.8.10, 6.11.3, 6.12.1 |
| [CVE-2026-105924](https://www.qt.io/blog/security-advisory-cve-2026-105924) — Qt Core / QCborValue | 5.12.0–6.8.9; 6.9.0–6.11.2; 6.12.0 | 6.8.10, 6.11.3, 6.12.1 |
| [CVE-2026-116337](https://www.qt.io/blog/security-issue-cve-2026-116337) — Qt Network | Vendor prose: from Qt 4.5.0 to Qt 6.8.10 or Qt 6.12.1 | 6.8.10, 6.12.1 |
| [CVE-2026-114369](https://www.qt.io/blog/security-advisory-cve-2026-114369) — Qt WebSockets / QWebSocket and QWebSocketServer | 5.15.0–6.8.9; 6.9.0–6.12.0 | 6.8.10, 6.12.1 |
| [CVE-2026-111487](https://wiki.qt.io/List_of_known_vulnerabilities_in_Qt_products) — Qt3D / assimp scene import plugin | 5.9.0–6.8.9; 6.9.0–6.11.2; 6.12.0 | 6.8.10, 6.11.3, 6.12.1 |

CVE-2026-116337 has overlapping affected/fixed endpoints in the vendor prose; the report preserves that ambiguity. Installed 6.12.0 precedes the named 6.12.1 fix. CVE-2026-114369 explicitly includes 6.11.3 in its 6.9.0–6.12.0 affected interval. Therefore 6.11.3 cannot be presented as complete remediation, even though it fixes several other rows. The vendor offers source patches, including backports; those are not equivalent to a published and qualified PySide6 wheel.

Official project JSON was successfully retrieved for [PySide6](https://pypi.org/pypi/PySide6/json) and [shiboken6](https://pypi.org/pypi/shiboken6/json) at 12:07:35 UTC. Both report latest 6.12.0; each has five 6.11.3 wheel files, five 6.12.0 wheel files, and no 6.12.1 files. Filenames, upload times, yanked flags and response hashes are in `qt-pypi-releases-20261119.json`. This confirms a published-wheel availability blocker at this snapshot. It does not rule out another vendor distribution channel. No replacement wheel or custom backport was qualified in this task.

The [official Qt 6.12 downloads index](https://download.qt.io/official_releases/qt/6.12/) also exposes patch records for CVE-2026-120973, CVE-2026-105943 and CVE-2026-105925. Complete advisory ranges and conditions were not established for those records; they remain explicitly unclassified. This bounded review is not a complete native Qt/Chromium/PDF inventory.

Specific tooling fixes are already listed under 6.12.0: [Shiboken PYSIDE-3396](https://doc.qt.io/qtforpython-6/release_notes/shiboken6_release_notes.html), covering doxygen XML external-entity handling, and [PySide PYSIDE-3320](https://doc.qt.io/qtforpython-6/release_notes/pyside6_release_notes.html), covering Windows pyside6-deploy shell handling. These do not clear unrelated Qt native findings.

## Other direct roots

| Root | Retrieved primary record | Assessment |
|---|---|---|
| protobuf 7.36.2 | [GHSA-8qvm-5x2c-j2w7 / CVE-2025-4565](https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-8qvm-5x2c-j2w7) | The pure-Python recursive-message issue has branch fixes 4.25.8, 5.29.5 and 6.31.1. The pin is later than those thresholds; the project additionally requires the upb backend. |
| yara-x 1.21.0 | [GHSA-2jx3-ff3v-j7jj](https://github.com/VirusTotal/yara-x/security/advisories/GHSA-2jx3-ff3v-j7jj) | Rust crate affected through 1.18.0, fixed 1.19.0; Python pin is later by version comparison. Source compiles rule text and does not invoke Rules::deserialize. Embedded Rust transitive versions were not inventoried. |
| iced-x86 1.21.0 | [RUSTSEC-2021-0068](https://rustsec.org/advisories/RUSTSEC-2021-0068.html) | Rust Decoder::new issue affects versions through 1.10.3; patched after 1.10.3. Python pin is later by version comparison; full Rust SBOM coverage is not claimed. |
| rapidfuzz 3.14.6 | Completed PyPI and OSV lookups | Neither service returned an advisory. Manual GitHub advisory-index/API retrieval was unavailable, and no package-specific advisory was successfully retrieved in the manual lookup scope. This is not proof of absence. |

## Reachability and retrieval limits

The source scan covered 900 Python files in `src` and `tools`, with no syntax errors. It found no literal use of the assessed Pydantic V1, constrained-extra-key, multi-host URL/DSN, TypedDict/dataclass, or native Qt network/XML/WebSocket/HTTP/CBOR/Qt3D/Bluetooth entry points; no literal `extra="allow"` configuration was found by AST. The few Fraction references are ordinary tool arithmetic, not model fields. This is a bounded admission scan, not a callgraph or exploitability proof. PyInstaller WebEngine/PDF exclusions are not a complete frozen artifact SBOM.

Failed retrievals are preserved in `dependency-advisory-primary-findings-20261119.json`: RapidFuzz repository/global advisory pages returned DisabledError or URL-inaccessible results; initial PySide6 6.12.1 web lookups were inaccessible but later successful official JSON resolved release availability; an initially guessed Qt CVE-2026-116337 URL was corrected and retrieved. No clean-security conclusion is drawn from unavailable pages, a Snyk no-change status, or zero automated findings.

## Review gate

Bind the eventual published head to the qualified source and dependency metadata, retain Pydantic compatibility and platform receipts, and keep Qt native remediation explicitly open until a supported patched artifact or another evidence-backed disposition is qualified. The current work completes the declared-root lookup and both actual Python-graph audits; it does not complete a native, dev-tool, all-platform, or full security audit.

The companion `dependency-advisory-findings-20261119.json` includes machine-readable findings, primary URLs and web retrieval references, audit commands/results and source bindings. `dependency-advisory-artifact-manifest-20261119.json` hashes the saved evidence set.
