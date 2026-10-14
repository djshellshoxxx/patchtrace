# CSAF fixtures (SPEC-28a/b, track K)

**Every file here is SYNTHETIC.** These files were hand-written for PatchTrace tests on 2026-10-14. They are not live evidence, and no vendor published them. They describe no real vulnerability, product or update.

## Why there are no real Microsoft samples

The Microsoft CSAF directory `https://msrc.microsoft.com/csaf` could not be reached from the authoring sandbox. The egress proxy refused the CONNECT with HTTP 403, both for `/csaf/provider-metadata.json` and for `/.well-known/csaf/provider-metadata.json`. Microsoft's directory layout, file naming and field usage are therefore unverified. Replacing or augmenting these fixtures with small, attributed excerpts of real Microsoft documents is an open live-acceptance item. See `docs/specs/csaf-cve-interpretation-engine.md`, section K.

## How the fixtures avoid looking real

- **CVE IDs:** they use the impossible year 2099 (`CVE-2099-10001`, `CVE-2099-10002`).
- **Publisher:** "PatchTrace Synthetic Fixture Vendor (not Microsoft)", with namespace `https://example.invalid/...`.
- **Products:** they are named "Example OS" and "Example Server", and use PatchTrace-only product IDs (`PT-…`, `VEX-…`).
- **Update names:** they are synthetic (`PT5041585`).
- **Structure:** the shape follows CSAF 2.0 (OASIS Standard, 18 November 2022): vendor, family, name, then version or version range in branches, plus remediations, threats and CVSS. It mirrors what the author expected of a Microsoft advisory. It is not a copy of one.

## Files

| File | Purpose |
|---|---|
| `synthetic-advisory-rev1.json` | `csaf_security_advisory`, tracking ID `PT-SYNTH_CVE-2099-10001`, version 1, with two CVEs in one document. See the notes after this table. |
| `synthetic-advisory-rev2.json` | The same tracking ID, version 2. It was derived from rev1 by script. `PT-101-1` moves from `known_affected` to `known_not_affected`, which is the cross-revision conflict. |
| `synthetic-vex.json` | `csaf_vex` with its own product-ID space and product names identical to the advisory. `VEX-1` is known not affected, which contradicts the advisory's `PT-100-1`. `VEX-2` is known affected, which agrees with `PT-200-1`. |
| `discovery/provider-metadata.json` | Synthetic `provider-metadata.json` at the assumed Microsoft location. It has two directory distributions and one ROLIE feed, which is ignored. |
| `discovery/index-advisories.txt`, `discovery/index-vex.txt` | Synthetic `index.txt` files. They include a decoy (`…-100010`) and lines a client must refuse: path traversal, upper case, absolute URL and a nested path. |

Notes on `synthetic-advisory-rev1.json`:
- **Products:** it has multiple products.
- **CWE:** CVE-2099-10001 has an explicit CWE (191). CVE-2099-10002 has none, and its description says "use-after-free" and "does not allow remote code execution".
- **Document notes:** they contain markup, a bidi override and non-ASCII text.
- **File-hash products:** `PT-800` and `PT-900` carry the SHA-256 of `patchtrace.sample.synthetic_pe(0)` and `synthetic_pe(1)`. Those are the sample project's older and newer artifacts, so the sample project exercises verified-component mappings end to end.

Negative cases are derived in code by the tests, and each one is named there:
- malformed and duplicate-key JSON
- deep, oversized and over-long input
- undefined, duplicate and circular product IDs
- undefined groups
- contradicting statuses
- a revision history out of order
- an unsupported `csaf_version`
- profile violations
