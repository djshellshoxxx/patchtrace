# Advisory report for `CVE-2099-10001`

Contract `intelligence/1`. This report restates advisory claims and PatchTrace rule hypotheses with their sources. It does not show that this CVE is present in, or fixed by, any function or binary. Advisory text is escaped, flattened to one line and shortened here; the JSON export holds the complete text.

## Sources

| Tracking ID | Revision | Category | Doc status | State | Origin | Authenticity | Retrieved | SHA-256 | Publisher | URI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `PT-SYNTH-VEX_CVE-2099-10001` | `1` | `csaf_vex` | `final` | current | `local-import` | `unverified-local-file` | `2099-03-03T00:00:00Z` | `7df4a907937b1e88383cd82273bf551cabb60d5d073ecab291a82660738ff947` | PatchTrace Synthetic Fixture Vendor \(not Microsoft\) | - |
| `PT-SYNTH_CVE-2099-10001` | `1` | `csaf_security_advisory` | `final` | superseded | `local-import` | `unverified-local-file` | `2099-03-01T00:00:00Z` | `f91e5c16ff213ff09990e0e50204f3e17795ba4bee3f0f2ccbad5d5fadd059f0` | PatchTrace Synthetic Fixture Vendor \(not Microsoft\) | - |
| `PT-SYNTH_CVE-2099-10001` | `2` | `csaf_security_advisory` | `final` | current | `local-import` | `unverified-local-file` | `2099-03-02T00:00:00Z` | `dd244d43b3073fcc86260d7abfb66662262c11e8bbbe8d1f226f2e56a815095b` | PatchTrace Synthetic Fixture Vendor \(not Microsoft\) | - |

## Applicability

### Older artifact

- SHA-256: `dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215`
- Identity facts: `verified-bytes`; file version not available; product version not available; PDB not available
- Analyst-asserted product IDs: none
- Product mapping: `candidate`
- Resolution: `affected` (`advisory-claim`); remediation recommended: no
- Why:
  - mapping verified\: PT\-800 in PT\-SYNTH\_CVE\-2099\-10001 r2 \(advisory\-file\-hash\)
  - mapping candidate\: PT\-801 in PT\-SYNTH\_CVE\-2099\-10001 r2 \(relationship\-from\-verified\-component\)
  - mapping verified\: PT\-800 in PT\-SYNTH\_CVE\-2099\-10001 r1 \(advisory\-file\-hash\)
  - mapping candidate\: PT\-801 in PT\-SYNTH\_CVE\-2099\-10001 r1 \(relationship\-from\-verified\-component\)
  - status\: PT\-801 known\_affected in PT\-SYNTH\_CVE\-2099\-10001 r2 at /vulnerabilities/0/product\_status/known\_affected/2
  - superseded status\: PT\-801 known\_affected in PT\-SYNTH\_CVE\-2099\-10001 r1 at /vulnerabilities/0/product\_status/known\_affected/3
- Identity notes:
  - no resource directory
  - no CodeView PDB identity

Product mappings

| Document | Product ID | Product | Tier | Basis | Detail |
| --- | --- | --- | --- | --- | --- |
| `PT-SYNTH_CVE-2099-10001` | `PT-800` | Example netstack\.sys 10\.0\.22621\.3958 \(synthetic build\) | `verified` | `advisory-file-hash` | artifact SHA\-256 equals a file hash in the advisory product identification helper |
| `PT-SYNTH_CVE-2099-10001` | `PT-801` | Example netstack\.sys 10\.0\.22621\.3958 as part of Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037 | `candidate` | `relationship-from-verified-component` | default\_component\_of of Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037; the platform itself is not verified |
| `PT-SYNTH_CVE-2099-10001` | `PT-800` | Example netstack\.sys 10\.0\.22621\.3958 \(synthetic build\) | `verified` | `advisory-file-hash` | artifact SHA\-256 equals a file hash in the advisory product identification helper |
| `PT-SYNTH_CVE-2099-10001` | `PT-801` | Example netstack\.sys 10\.0\.22621\.3958 as part of Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037 | `candidate` | `relationship-from-verified-component` | default\_component\_of of Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037; the platform itself is not verified |

Status evidence

| Document | Revision | Product ID | Product | Status | Pointer | State |
| --- | --- | --- | --- | --- | --- | --- |
| `PT-SYNTH_CVE-2099-10001` | `2` | `PT-801` | Example netstack\.sys 10\.0\.22621\.3958 as part of Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037 | `known_affected` | `/vulnerabilities/0/product_status/known_affected/2` | current |
| `PT-SYNTH_CVE-2099-10001` | `1` | `PT-801` | Example netstack\.sys 10\.0\.22621\.3958 as part of Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037 | `known_affected` | `/vulnerabilities/0/product_status/known_affected/3` | superseded |

### Newer artifact

- SHA-256: `4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168`
- Identity facts: `verified-bytes`; file version not available; product version not available; PDB not available
- Analyst-asserted product IDs: none
- Product mapping: `candidate`
- Resolution: `fixed` (`advisory-claim`); remediation recommended: no
- Why:
  - mapping verified\: PT\-900 in PT\-SYNTH\_CVE\-2099\-10001 r2 \(advisory\-file\-hash\)
  - mapping candidate\: PT\-901 in PT\-SYNTH\_CVE\-2099\-10001 r2 \(relationship\-from\-verified\-component\)
  - mapping verified\: PT\-900 in PT\-SYNTH\_CVE\-2099\-10001 r1 \(advisory\-file\-hash\)
  - mapping candidate\: PT\-901 in PT\-SYNTH\_CVE\-2099\-10001 r1 \(relationship\-from\-verified\-component\)
  - status\: PT\-901 fixed in PT\-SYNTH\_CVE\-2099\-10001 r2 at /vulnerabilities/0/product\_status/fixed/3
  - superseded status\: PT\-901 fixed in PT\-SYNTH\_CVE\-2099\-10001 r1 at /vulnerabilities/0/product\_status/fixed/3
- Identity notes:
  - no resource directory
  - no CodeView PDB identity

Product mappings

| Document | Product ID | Product | Tier | Basis | Detail |
| --- | --- | --- | --- | --- | --- |
| `PT-SYNTH_CVE-2099-10001` | `PT-900` | Example netstack\.sys 10\.0\.22621\.4036 \(synthetic build\) | `verified` | `advisory-file-hash` | artifact SHA\-256 equals a file hash in the advisory product identification helper |
| `PT-SYNTH_CVE-2099-10001` | `PT-901` | Example netstack\.sys 10\.0\.22621\.4036 as part of Example OS 22H2 for x64\-based Systems 10\.0\.22621\.4037 | `candidate` | `relationship-from-verified-component` | default\_component\_of of Example OS 22H2 for x64\-based Systems 10\.0\.22621\.4037; the platform itself is not verified |
| `PT-SYNTH_CVE-2099-10001` | `PT-900` | Example netstack\.sys 10\.0\.22621\.4036 \(synthetic build\) | `verified` | `advisory-file-hash` | artifact SHA\-256 equals a file hash in the advisory product identification helper |
| `PT-SYNTH_CVE-2099-10001` | `PT-901` | Example netstack\.sys 10\.0\.22621\.4036 as part of Example OS 22H2 for x64\-based Systems 10\.0\.22621\.4037 | `candidate` | `relationship-from-verified-component` | default\_component\_of of Example OS 22H2 for x64\-based Systems 10\.0\.22621\.4037; the platform itself is not verified |

Status evidence

| Document | Revision | Product ID | Product | Status | Pointer | State |
| --- | --- | --- | --- | --- | --- | --- |
| `PT-SYNTH_CVE-2099-10001` | `2` | `PT-901` | Example netstack\.sys 10\.0\.22621\.4036 as part of Example OS 22H2 for x64\-based Systems 10\.0\.22621\.4037 | `fixed` | `/vulnerabilities/0/product_status/fixed/3` | current |
| `PT-SYNTH_CVE-2099-10001` | `1` | `PT-901` | Example netstack\.sys 10\.0\.22621\.4036 as part of Example OS 22H2 for x64\-based Systems 10\.0\.22621\.4037 | `fixed` | `/vulnerabilities/0/product_status/fixed/3` | superseded |

### Contradictions

| Kind | Product | Explanation | Claims |
| --- | --- | --- | --- |
| `cross-revision` | Example OS 22H2 for ARM64\-based Systems &lt;10\.0\.22621\.4037 | revision 1 said known\_affected, current revision 2 says known\_not\_affected | PT\-SYNTH\_CVE\-2099\-10001 revision 2\: known\_not\_affected \(PT\-101\-1\); PT\-SYNTH\_CVE\-2099\-10001 revision 1\: known\_affected \(PT\-101\-1\) |
| `vex-vs-advisory` | Example OS 22H2 for x64\-based Systems &lt;10\.0\.22621\.4037 | documents state different status classes for the same product name\: PT\-SYNTH\-VEX\_CVE\-2099\-10001 r1\: known\_not\_affected; PT\-SYNTH\_CVE\-2099\-10001 r2\: known\_affected | PT\-SYNTH\-VEX\_CVE\-2099\-10001 revision 1\: known\_not\_affected \(VEX\-1\); PT\-SYNTH\_CVE\-2099\-10001 revision 2\: known\_affected \(PT\-100\-1\) |

## Advisory facts

### Fact from `PT-SYNTH-VEX_CVE-2099-10001` revision `1` (current)

- Pointer: `/vulnerabilities/0`
- Title: not stated
- CWE stated by the vendor: not stated
- Product status claims: 2 in total (`known_affected`: 1, `known_not_affected`: 1); those tied to the artifacts are listed under Applicability

Notes

| Category | Title | Text | Pointer |
| --- | --- | --- | --- |
| `description` | VEX justification | SYNTHETIC VEX\: the vulnerable reassembly code is not present in the x64 22H2 builds named here\. | `/vulnerabilities/0/notes/0` |

Remediations

| Category | Details | URL | Products | Date | Pointer |
| --- | --- | --- | --- | --- | --- |
| `vendor_fix` | Install synthetic update PT5041160 | - | 1 product(s), 0 group(s) | - | `/vulnerabilities/0/remediations/0` |

Flags

| Label | Products | Pointer |
| --- | --- | --- |
| `vulnerable_code_not_present` | 1 product(s), 0 group(s) | `/vulnerabilities/0/flags/0` |

### Fact from `PT-SYNTH_CVE-2099-10001` revision `1` (superseded)

- Pointer: `/vulnerabilities/0`
- Title: SYNTHETIC Example OS netstack Remote Code Execution Vulnerability
- CWE stated by the vendor: `CWE-191` Integer Underflow \(Wrap or Wraparound\) at `/vulnerabilities/0/cwe`
- Product status claims: 8 in total (`fixed`: 4, `known_affected`: 4); those tied to the artifacts are listed under Applicability

Notes

| Category | Title | Text | Pointer |
| --- | --- | --- | --- |
| `description` | Description | SYNTHETIC\: An integer underflow in the IPv6 fragment reassembly path of netstack\.sys can lead to a heap\-based buffer overflow when the driver processes crafted packets\. | `/vulnerabilities/0/notes/0` |
| `faq` | How could an attacker exploit this vulnerability? | An unauthenticated attacker could repeatedly send IPv6 packets, including specially crafted packets, to a machine\. Systems with IPv6 disabled are not affected\. | `/vulnerabilities/0/notes/1` |
| `general` | Assigning CNA | PatchTrace synthetic fixture | `/vulnerabilities/0/notes/2` |

Remediations

| Category | Details | URL | Products | Date | Pointer |
| --- | --- | --- | --- | --- | --- |
| `vendor_fix` | Install synthetic update PT5041585 | https\://example\.invalid/patchtrace\-synthetic/updates/PT5041585 | 1 product(s), 1 group(s) | `2099-01-10T08:00:00.000Z` | `/vulnerabilities/0/remediations/0` |
| `vendor_fix` | Install synthetic update PT5041160 | https\://example\.invalid/patchtrace\-synthetic/updates/PT5041160 | 1 product(s), 0 group(s) | `2099-01-10T08:00:00.000Z` | `/vulnerabilities/0/remediations/1` |

Threats

| Category | Details | Products | Pointer |
| --- | --- | --- | --- |
| `impact` | Remote Code Execution | 3 product(s), 0 group(s) | `/vulnerabilities/0/threats/0` |
| `exploit_status` | Publicly Disclosed\:No;Exploited\:No;Latest Software Release\:Exploitation More Likely | 0 product(s), 0 group(s) | `/vulnerabilities/0/threats/1` |

Scores (severity context only)

| CVSS | Base score | Severity | Vector | Products | Pointer |
| --- | --- | --- | --- | --- | --- |
| `3.1` | `9.8` | CRITICAL | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 3 product(s) | `/vulnerabilities/0/scores/0/cvss_v3` |

### Fact from `PT-SYNTH_CVE-2099-10001` revision `2` (current)

- Pointer: `/vulnerabilities/0`
- Title: SYNTHETIC Example OS netstack Remote Code Execution Vulnerability
- CWE stated by the vendor: `CWE-191` Integer Underflow \(Wrap or Wraparound\) at `/vulnerabilities/0/cwe`
- Product status claims: 8 in total (`fixed`: 4, `known_affected`: 3, `known_not_affected`: 1); those tied to the artifacts are listed under Applicability

Notes

| Category | Title | Text | Pointer |
| --- | --- | --- | --- |
| `description` | Description | SYNTHETIC\: An integer underflow in the IPv6 fragment reassembly path of netstack\.sys can lead to a heap\-based buffer overflow when the driver processes crafted packets\. | `/vulnerabilities/0/notes/0` |
| `faq` | How could an attacker exploit this vulnerability? | An unauthenticated attacker could repeatedly send IPv6 packets, including specially crafted packets, to a machine\. Systems with IPv6 disabled are not affected\. | `/vulnerabilities/0/notes/1` |
| `general` | Assigning CNA | PatchTrace synthetic fixture | `/vulnerabilities/0/notes/2` |
| `faq` | Why was revision 2 published? | SYNTHETIC\: ARM64\-based systems do not use the affected reassembly path; they are not affected\. | `/vulnerabilities/0/notes/3` |

Remediations

| Category | Details | URL | Products | Date | Pointer |
| --- | --- | --- | --- | --- | --- |
| `vendor_fix` | Install synthetic update PT5041585 | https\://example\.invalid/patchtrace\-synthetic/updates/PT5041585 | 1 product(s), 1 group(s) | `2099-01-10T08:00:00.000Z` | `/vulnerabilities/0/remediations/0` |
| `vendor_fix` | Install synthetic update PT5041160 | https\://example\.invalid/patchtrace\-synthetic/updates/PT5041160 | 1 product(s), 0 group(s) | `2099-01-10T08:00:00.000Z` | `/vulnerabilities/0/remediations/1` |

Threats

| Category | Details | Products | Pointer |
| --- | --- | --- | --- |
| `impact` | Remote Code Execution | 2 product(s), 0 group(s) | `/vulnerabilities/0/threats/0` |
| `exploit_status` | Publicly Disclosed\:No;Exploited\:No;Latest Software Release\:Exploitation More Likely | 0 product(s), 0 group(s) | `/vulnerabilities/0/threats/1` |

Scores (severity context only)

| CVSS | Base score | Severity | Vector | Products | Pointer |
| --- | --- | --- | --- | --- | --- |
| `3.1` | `9.8` | CRITICAL | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 2 product(s) | `/vulnerabilities/0/scores/0/cvss_v3` |

## CWE profile

- Status: `explicit`
- Lexicon: `cwe-lexicon/1` (digest `a56c967518c2`)

Classifications

| CWE | Family | Basis | Confidence | Assessment | Pointers |
| --- | --- | --- | --- | --- | --- |
| `CWE-191` | integer | `explicit-csaf-cwe` | `explicit` | `advisory-claim` | `/vulnerabilities/0/cwe`, `/vulnerabilities/0/notes/0` |
| `CWE-122` | memory\-write | `curated-vocabulary` | `phrase-match` | `rule-hypothesis` | `/vulnerabilities/0/notes/0` |

Effect and primitive phrases (no CWE derived)

| Phrase | Scope | Strength | Pointer | Excerpt |
| --- | --- | --- | --- | --- |
| remote code execution | `effect` | `weak` | `/vulnerabilities/0/threats/0/details` | remote code execution |
| remote code execution | `effect` | `weak` | `/vulnerabilities/0/title` | synthetic example os netstack remote code execution vulnerability |

Disagreements (kept, not resolved)

- explicit CWE\-191 \(integer\) and curated\-vocabulary CWE\-122 \(memory\-write\) differ; both are kept and neither is resolved

## Patch hypotheses

- Rules: `patch-rules/1` (digest `cf3c05fa31e8`); search guidance only, never evidence that a function is vulnerable or fixed

### `CWE-191` (integer) via `R-INTEGER` revision 1

- Basis: `explicit-csaf-cwe`; assessment `rule-hypothesis`
- Expected operations:
  - overflow\-checked arithmetic replaces plain addition, subtraction or multiplication
  - range check before the arithmetic
  - operand type widened
  - subtraction guarded against underflow
- Sources:
  - counts, lengths and offsets from input
- Sinks:
  - allocation size
  - loop bound
  - copy length
  - array index
- Guards:
  - overflow\-checked arithmetic helpers
  - comparison of operands before subtraction
- API names worth searching:
  - RtlULongAdd
  - RtlULongSub
  - RtlULongMult
  - RtlSizeTAdd
  - RtlSizeTMult
  - ULongAdd
  - SizeTMult
  - UIntAdd
- Counterexamples:
  - type change for an unrelated API signature
  - existing check moved or duplicated by refactoring, inlining or compiler reordering
- Observations that would support it:
  - new arithmetic check whose result guards a size, bound or index
- Caveat: Patches need not follow common motifs\: absence of these operations neither refutes the advisory nor the product mapping, and their presence does not establish the weakness in a function\.

### `CWE-122` (memory\-write) via `R-MEMORY-WRITE` revision 1

- Basis: `curated-vocabulary`; assessment `rule-hypothesis`
- Expected operations:
  - new comparison of an index, length or count against the destination capacity before a copy, index or store
  - copy length clamped or recomputed from the destination size
  - allocation size recomputed with checked arithmetic
  - early error return added before the write
- Sources:
  - length, count or offset fields parsed from input
  - sizes supplied by user mode or the network
- Sinks:
  - memory copy into a fixed or computed buffer
  - indexed array store
  - pointer\-arithmetic write
- Guards:
  - bounds check\: index &lt; capacity, offset \+ length &lt;\= size
  - checked arithmetic before the size is used
  - error status returned for oversize input
- API names worth searching:
  - memcpy
  - memmove
  - memcpy\_s
  - RtlCopyMemory
  - RtlMoveMemory
  - RtlSizeTAdd
  - RtlULongMult
  - ExAllocatePool2
  - ExAllocatePoolWithTag
- Counterexamples:
  - check added only for telemetry or logging
  - existing check moved or duplicated by refactoring, inlining or compiler reordering
- Observations that would support it:
  - new or tightened comparison dominating a write in the changed function
  - value flow from the compared quantity to the write size or index
- Observations that would contradict it:
  - the changed function performs no memory writes
  - only constants, strings or logging changed
- Caveat: Patches need not follow common motifs\: absence of these operations neither refutes the advisory nor the product mapping, and their presence does not establish the weakness in a function\.

## Search anchors

| Kind | Value | Source | Quality | Pointer | Label |
| --- | --- | --- | --- | --- | --- |
| `api` | ExAllocatePool2 | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `api` | ExAllocatePoolWithTag | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `api` | RtlCopyMemory | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `api` | RtlMoveMemory | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `api` | RtlSizeTAdd | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | RtlSizeTMult | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | RtlULongAdd | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | RtlULongMult | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | RtlULongSub | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | SizeTMult | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | UIntAdd | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | ULongAdd | `hypothesis-rule` | `rule` | - | API often involved in integer fixes \(R\-INTEGER\) |
| `api` | memcpy | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `api` | memcpy\_s | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `api` | memmove | `hypothesis-rule` | `rule` | - | API often involved in memory\-write fixes \(R\-MEMORY\-WRITE\) |
| `component` | SYNTHETIC Example OS netstack | `csaf-title` | `derived` | `/vulnerabilities/0/title` | component part of a &quot;&lt;component&gt; &lt;impact&gt; Vulnerability&quot; title |
| `feature` | IPv6 | `csaf-note` | `derived` | `/vulnerabilities/0/notes/0` | feature or protocol named in the advisory |
| `feature` | IPv6 | `csaf-note` | `derived` | `/vulnerabilities/0/notes/1` | feature or protocol named in the advisory |
| `module` | netstack\.sys | `csaf-note` | `explicit` | `/vulnerabilities/0/notes/0` | module named in the advisory |
| `module` | netstack\.sys | `csaf-product` | `explicit` | `/product_tree/relationships/0/full_product_name/name` | module named in the advisory |
| `module` | netstack\.sys | `csaf-product` | `explicit` | `/product_tree/relationships/1/full_product_name/name` | module named in the advisory |

## Unknowns

- advisory authenticity is unverified\: a local file was imported and signatures are not checked
- newer artifact\: the product mapping is a candidate, not verified
- older artifact\: the product mapping is a candidate, not verified

## Limitations

- This report restates vendor claims and PatchTrace rule hypotheses with their sources; it does not show that this CVE is present in, or fixed by, any function or binary\.
- Applicability restates vendor claims for products tied to each artifact; it is not a binary verification\.
- File versions are matched to product\_version names by exact equality only; product\_version\_range entries are not evaluated because a Windows file version is not an operating\-system build\.
- CSAF document signatures are not checked; fetched documents are tied to an allowlisted HTTPS host only\.
- CWE profile derived from PT\-SYNTH\_CVE\-2099\-10001 revision 2 \(dd244d43b307\); 2 other stored document\(s\) listing CVE\-2099\-10001 were not used \(superseded, or only compared for disagreements\)
- Hypotheses describe common fix shapes for a weakness class; they are search guidance only\.
- Advisory CWE values and vocabulary matches are claims or interpretations, not binary observations\.
- Anchors are search hints labelled with source and quality; they are never linked to diff results or functions\.
- Module and feature names come from advisory text and may describe the product, not this file\.
