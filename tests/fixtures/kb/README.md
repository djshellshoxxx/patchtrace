# Synthetic KB and patch-search fixtures

Everything in this directory is hand-authored synthetic test data. It contains no Microsoft advisory bytes, Winbindex downloads, PE files, update package payloads, or executable data. Identifiers beginning with `KB9000001`, `CVE-2099-`, and `SYN-` are fictional test identifiers.

The corpus manifest selects exactly 60 advisory documents: 20 CVRF-shaped, 20 CSAF-shaped, and 20 VEX-shaped. The CVRF file also contains four supplemental adversarial entries outside that 60-document count. Winbindex and update-package files contain metadata only.

The existing repository uses a synthetic `cvrf-json/0` importer dialect. This fixture label does not claim compatibility with live MSRC CVRF v3. Exact CVRF, CSAF, VEX, Winbindex and package-provider wire schemas remain UNVERIFIED. Hashes, byte lengths and redistribution status are likewise UNVERIFIED because they were not calculated or independently checked.

The corpus spans cumulative and checkpoint updates, supersedence, many-to-many relationships, product and architecture variants, withdrawn/re-issued advisories, malformed and missing data, duplicate identifiers, oversized text and arrays, deep nesting, hostile markup, Unicode confusables, BOM/CRLF metadata, numeric strings, status conflicts, and package/delta metadata. Metadata names describing a format do not prove the repository currently supports its reconstruction.

The original author did not execute these fixtures. The 2026-10-30 reconciliation
repairs fixture registration, tests an unknown CVRF remediation type derived from
the known-issue case, retains the intentionally empty CSAF document, and adds
a separate raw Unicode lookalike containing an actual Cyrillic character. The
original double-escaped case remains intact for provenance. Encoding checks now
exercise the importer: BOM is refused by the current contract; CRLF is accepted.

Scenario names are authored labels, not proof of boundary coverage. In particular,
the named oversized/deep and VEX multi-item scenarios are not all large, deeply
nested, or multi-item. CSAF/VEX structural checks do not validate the production
advisory importer. Package/relationship checks validate fixture metadata only;
the crash harness validates an injection protocol, not application recovery.
This corpus is not evidence of live provider compatibility or release acceptance.
