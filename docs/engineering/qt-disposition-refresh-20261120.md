# Native Qt disposition refresh — 2026-11-20

## Decision

**The native Qt release blocker remains open. No verified dependency update or artifact-specific closure is available from this bounded review.** No repository files, pins, installed packages, remote state, or release settings were changed.

The coordinator's integration HEAD observed when recording source identities was `c0108749e8813dfa6165e953b1a2dc2ad736e982`. The JSON companion records hashes of `pyproject.toml`, the release assessment and both preceding Qt evidence records. The checked pins remain PySide6/shiboken6 6.12.0.

## Current package availability

Six public PyPI JSON endpoints returned HTTP 200 at approximately **2026-11-20 15:53:31 UTC**. Their complete-response hashes and relevant platform wheel filenames/digests are retained in the JSON companion.

| Package | Advertised version | Any 6.12.1-family files observed |
| --- | --- | --- |
| [PySide6](https://pypi.org/pypi/PySide6/json) | 6.12.0 | No |
| [shiboken6](https://pypi.org/pypi/shiboken6/json) | 6.12.0 | No |
| [PySide6_Essentials](https://pypi.org/pypi/PySide6_Essentials/json) | 6.12.0 | No |
| [PySide6_Addons](https://pypi.org/pypi/PySide6_Addons/json) | 6.12.0 | No |
| [PySide6_WebEngine](https://pypi.org/pypi/PySide6_WebEngine/json) | 6.12.0.140 | No |
| [PySide6_Pdf](https://pypi.org/pypi/PySide6_Pdf/json) | 6.12.0.140 | No |

The PySide6 and shiboken6 response hashes exactly match the prior November 19 refresh. The [official Qt 6.12 directory](https://download.qt.io/official_releases/qt/6.12/) still lists only the 6.12.0 release directory, alongside vendor patches. The [official PySide download listing](https://download.qt.io/official_releases/QtForPython/pyside6/) likewise shows 6.12.0 and 6.11.3 entries in the retrieved result; it supplies no verified 6.12.1 candidate.

New scheduling evidence explains why a speculative pin change is inappropriate: the [Qt release plan](https://wiki.qt.io/Qt_6.12_Release) lists **November 23, 2026** as the updated 6.12.1 target, with its realized column empty. The [Qt for Python development notes](https://wiki.qt.io/Qt_for_Python_Development_Notes) dated November 19 still describe preparation for 6.12.1. A schedule does not establish publication or wheel availability.

## Retained advisory disposition

The three recently retained official advisories were reread. This is not a new assessment of every historical Qt advisory.

| Official advisory | Current vendor remedy and consequence |
| --- | --- |
| [CVE-2026-114369 — Qt WebSockets](https://www.qt.io/blog/security-advisory-cve-2026-114369) | The stated component range includes 6.12.0. Vendor lists 6.8.10/6.12.1 or source patches as remedies. This does not establish that PatchTrace uses an affected path. |
| [CVE-2026-116337 — Qt Network](https://www.qt.io/blog/security-issue-cve-2026-116337) | Vendor still lists 6.8.10/6.12.1 or patches. Its affected prose overlaps fixed endpoints; preserve that ambiguity. A 6.11.3 downgrade is not established as complete remediation. |
| [CVE-2026-105925 — QXmlSimpleReader](https://www.qt.io/blog/security-advisory-cve-2026-105925) | Component range includes 6.12.0; remedies include 6.8.10/6.11.3/6.12.1 or patches. Fixing this component alone would not settle the other ranges. |

No frozen Windows artifact, native-library inventory, shipped-component SBOM or call-path evidence was produced here. Version matches identify items requiring disposition; they do not prove application reachability. Conversely, absence of a Python import would not prove absence from a frozen artifact or indirect native use. The original seven assessed ranges therefore retain their existing status; this refresh does not mark them safe.

## Next concrete step

After actual vendor publication, recheck the complete compatible PySide6/shiboken6/Essentials/Addons package set and relevant optional modules, then verify their bundled native identities and applicable fix coverage before proposing a pin update. Qualify any candidate on the required Qt, Windows/Linux, packaging and smoke gates. Do not schedule a blind upgrade for the planned date.

An artifact-specific component/reachability disposition or a qualified vendor source-backport build is a separate possible route. Neither was executed or accepted here. No source patches were downloaded/applied, wheels installed, target binaries executed, or vulnerability reproduction attempted.

Evidence: `qt-disposition-refresh.json` contains timestamps, source URLs, package metadata, source hashes and explicit limits; `qt-package-refresh-20261120.json` contains the package-only refresh.
