# Synthetic KB and patch-search fixtures

Everything in this directory is hand-authored synthetic test data. It contains no Microsoft advisory bytes, Winbindex downloads, PE files, update package payloads, or executable data. Identifiers beginning with `KB9000001`, `CVE-2099-`, and `SYN-` are fictional test identifiers.

The corpus manifest selects exactly 60 advisory documents: 20 CVRF-shaped, 20 CSAF-shaped, and 20 VEX-shaped. The CVRF file also contains four supplemental adversarial entries outside that 60-document count. Winbindex and update-package files contain metadata only.

The existing repository uses a synthetic `cvrf-json/0` importer dialect. This fixture label does not claim compatibility with live MSRC CVRF v3. Exact CVRF, CSAF, VEX, Winbindex and package-provider wire schemas remain UNVERIFIED. Hashes, byte lengths and redistribution status are likewise UNVERIFIED because they were not calculated or independently checked.

The corpus spans cumulative and checkpoint updates, supersedence, many-to-many relationships, product and architecture variants, withdrawn/re-issued advisories, malformed and missing data, duplicate identifiers, oversized text and arrays, deep nesting, hostile markup, Unicode confusables, BOM/CRLF metadata, numeric strings, status conflicts, and package/delta metadata. Metadata names describing a format do not prove the repository currently supports its reconstruction.

No test execution or network lookup was performed for this change.
