# CISA KEV context panel

Planned. The KEV plan specifies an exploitation-context dock. Its panel declaration was unavailable during review. Desktop availability and live update support are UNVERIFIED.

The manifest reserves Ctrl+Shift+X. The panel is intended to look up CVE IDs in a locally retained CISA Known Exploited Vulnerabilities catalog.

Import a supported catalog JSON file or review the exact request before downloading an update. **Showing the panel does not authorize a download.**

The planned request preview identifies the destination, headers, response limit, and stored catalog behavior. It states that the catalog request sends no project data or CVE IDs.

Read the catalog version, release time, retrieval source, and freshness alongside each lookup.

| Result | Interpretation |
|---|---|
| `Listed` | The CVE appears in the selected catalog |
| `Not listed` | The CVE does not appear in that snapshot |
| `Unavailable` | No usable catalog supports the lookup |
| `Invalid ID` | The supplied identifier failed validation |

“Not listed” does not establish absence of exploitation. An old catalog may lack later additions. Ransomware use marked unknown must remain unknown.

CISA’s due date is catalog context. Applicability of a remediation obligation to your organization is outside this panel’s determination.

The planned `KEV-listed` first option changes reading order only. It does not alter function rankings, pairing decisions, or evidence strength.

`Copy details` with snapshot provenance when recording a lookup.

Sources: docs/specs/program-e/KEV-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.

next

Worked for 1m 55s

<!-- FORMAT NOTE: The raw text ends with stray UI-capture lines "next" and "Worked for 1m 55s" (likely pasted from a chat transcript). Kept as plain text; confirm and remove if unintended. -->
