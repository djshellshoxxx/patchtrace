# Authored investigation acceptance fixtures

These strict JSON documents are PatchTrace-authored synthetic metadata, not
Microsoft-derived captures or evidence of actual vulnerabilities. They use
reserved-future synthetic CVE identifiers and no binary payload. Repository MIT
terms apply. `MANIFEST.json` pins exact LF bytes, SHA-256, size, authorship,
creation time, parser dialect and explicit negative obligations. Retrieval and
upstream source fields are absent or null because no source was fetched.

`advisory-v1.json` establishes one documentary product-specific association.
`advisory-v2-missing-product.json` supersedes it in the same synthetic month but
omits the referenced product: the older source remains historical evidence and
cannot fill that missing product proof. `advisory-ambiguous-kb.json` puts two KB
identifiers in one Type 2 sentence, which supports mentions rather than a parsed
remediation. Tests traverse the real importer, WorkspaceStore and service and
verify exact raw-byte retention after reopen. No target file is executed.
