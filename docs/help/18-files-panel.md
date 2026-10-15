# Files

Open Project > File overview or View > Files after opening a project. The Files dock is read-only and does not require a comparison backend. It separates metadata recorded at creation from PE fields inspected from project-owned artifact copies.

Begin with names, sizes, hashes, and orientation. The size delta is newer minus older. Identical hashes establish byte identity, not the suitability of a chosen pair for a particular patch investigation.

The PE comparison re-verifies artifact identity before bounded reads. Inspect changed and unavailable rows independently. One side failing to parse must not erase the other side's observations. A timestamp is untrusted metadata; do not use it as a signing date or automatic chronology.

Certificate-table presence is distinct from signature verification. The documented Windows embedded-signature check omits revocation and catalog-signing coverage. Its result must retain those qualifications. It does not establish runtime behavior.

The existing guide identifies resource/version/manifest and Build facts integration work that is not fully attached to this dock. Do not expect every implemented parser module to have a visible row.

If bytes changed after project creation, preserve the failure and investigate the copy rather than bypassing hash verification. See [raw representations](05-code-and-bytes.md).

Source: [Files and PE overview guide](../guide/15-files-and-pe-overview.md). **UNVERIFIED:** Windows trust results, parser integration, concurrent inspection, and packaged display behavior were not run here.
