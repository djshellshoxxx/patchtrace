# Patch-intent leads

This report lists changed functions in the order that explainable rules give them. A lead is a place for a person to look; PatchTrace does not claim that a function contains or fixes a CVE.

> Leads are ordered by explainable rules, not by likelihood. A lead does not show that this function contains or fixes any CVE. Tied leads have equal evidence.

- Result: `41669a1dace0da033248a72ea0ef1f4f4eab0b5d47302d0823271a94ae3c467a` (contract `pilot/1`)
- Status: complete
- Older build: `3aa1f3653202a1be3710a508e36065f8c8ae00dc3e8494b8ebe0c1d6ca3d45d1`
- Newer build: `9e1dd2d600fc31153c59a091031336c01c910a224a5f8a8b207e835c1a45ea43`
- Orientation: older to newer
- Computed: `2099-01-01T00:00:00Z`

## Evidence channels

| Channel | State | Note |
| --- | --- | --- |
| Advisory | available | - |
| Code | available | - |
| Calls | partial | Ghidriff call labels only; no import delta |
| Strings | available | - |
| Capa | available | - |
| Build | available | - |
| Pairing | available | - |

Some evidence was not available: Calls. Missing evidence is unknown, not a negative result.

## `CVE-2099-20001`

- Weakness class: stated by the advisory (CWE-122, CWE-787)
- CISA KEV: listed (added 2099-02-10)
- Whether other CVEs are fixed in this build is unknown.
- Leads: fits advisory 2; needs review 2; partial fit 2; code change 0; changed, no fit 3

| # | Function | Addresses | Class | Changes seen | Groups | Pairing | Flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Ipv6pReassembleFragment | older 0x1180, newer 0x11c0 | FITS ADVISORY | 2 of 3 | 2 | corroborated | - |
| 2 | Ipv6pParseOptions | older 0x1280, newer 0x12c0 | FITS ADVISORY | 1 of 3 | 2 | corroborated | - |
| 3 | Ipv6pReassembleFragmentTail | older 0x1400, newer 0x1440 | NEEDS REVIEW | 1 of 3 | 2 | corroborated | text evidence only |
| 4 | Ipv6pFragmentListReassemble | older 0x1300, newer 0x1340 | NEEDS REVIEW | 1 of 3 | 2 | contested | pairing contested |
| 5 | Ipv6pFragmentInit | older 0x1500, newer 0x1540 | PARTIAL FIT | 1 of 3 | 2 | corroborated | text evidence only |
| 6 | Ipv6pFragmentReassemblyStats | older 0x1600, newer 0x1640 | PARTIAL FIT | 0 of 3 | 0 | corroborated | - |
| 7 | Ipv6pDispatch | older 0x1900, newer 0x1940 | CHANGED, NO FIT | 0 of 3 | 0 | corroborated | - |
| 8 | Ipv6pLogFragmentDrop | older 0x1700, newer 0x1740 | CHANGED, NO FIT | 0 of 3 | 0 | corroborated | - |
| 9 | Ipv6pChecksumFragment | older 0x1800, newer 0x1840 | NOT ASSESSED | 0 of 3 | 0 | corroborated | - |

### Why: Ipv6pReassembleFragment (older 0x1180, newer 0x11c0)

**Summary**

- fits advisory; expected changes seen 2 of 3 \(required 1 of 1\); 2 independent groups; evidence depth typed\.

**Expected changes**

- R\-MEMORY\-WRITE revision 1, CWE\-787 as stated by the advisory\.
- Seen\: guard added \(B1 BND, ChangeFacts comparison; go to newer line 14\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Not seen\: size recomputed\.
- Seen\: checked arithmetic \(RtlSizeTAdd call added, label only\)\.
  - Next step\: Check that the size arithmetic now goes through a checked helper and that its failure path returns before the copy\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison, RtlSizeTAdd call added, label only \(same origin, counted once\)\.
- Advisory text\: CISA KEV, CSAF, MSRC, NVD \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Fits advisory for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragment\. Newer\: Ipv6pReassembleFragment\.

**Provenance**

- Evidence\: 4 stated by the advisory, 2 label only, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: listed \(added 2099\-02\-10\)\. KEV only orders CVEs; it says nothing about which function changed\.

### Why: Ipv6pParseOptions (older 0x1280, newer 0x12c0)

**Summary**

- fits advisory; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth typed\.

**Expected changes**

- R\-MEMORY\-WRITE revision 1, CWE\-787 as stated by the advisory\.
- Seen\: guard added \(B1 BND, ChangeFacts comparison; go to newer line 9\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Not seen\: size recomputed\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.
- Advisory text\: CISA KEV, CSAF, MSRC, NVD \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Fits advisory for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pParseOptions\. Newer\: Ipv6pParseOptions\.

**Provenance**

- Evidence\: 4 stated by the advisory, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: listed \(added 2099\-02\-10\)\. KEV only orders CVEs; it says nothing about which function changed\.

### Why: Ipv6pReassembleFragmentTail (older 0x1400, newer 0x1440)

**Summary**

- needs review; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Needs review because a named proof argues against the change that was seen\.

**Expected changes**

- R\-MEMORY\-WRITE revision 1, CWE\-787 as stated by the advisory\.
- Seen\: guard added \(B1 BND; go to newer line 22\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Contradicted\: size recomputed \(a named proof argues against any change\)\.
- Contradicted\: checked arithmetic \(a named proof argues against any change\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.
- Advisory text\: CISA KEV, CSAF, MSRC, NVD \(same origin, counted once\)\.

**Against**

- ChangeFacts cosmetic\: Proof COS\-LAYOUT/1 holds\: the old check was only moved\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Needs review for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragmentTail\. Newer\: Ipv6pReassembleFragmentTail\.

**Provenance**

- Evidence\: 4 stated by the advisory, 1 label only, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: listed \(added 2099\-02\-10\)\. KEV only orders CVEs; it says nothing about which function changed\.

### Why: Ipv6pFragmentListReassemble (older 0x1300, newer 0x1340)

**Summary**

- needs review; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth typed\.
- Needs review because the pairing of the two functions is contested\.

**Expected changes**

- R\-MEMORY\-WRITE revision 1, CWE\-787 as stated by the advisory\.
- Seen\: guard added \(B1 BND, ChangeFacts comparison; go to newer line 17\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Not seen\: size recomputed\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.
- Advisory text\: CISA KEV, CSAF, MSRC, NVD \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Needs review for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is contested between engines\.
- Older\: Ipv6pFragmentListReassemble\. Newer\: Ipv6pFragmentListReassemble\.
- Next step\: Open both functions and decide yourself which pairing is right before relying on this lead\.

**Provenance**

- Evidence\: 4 stated by the advisory, 1 label only, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: listed \(added 2099\-02\-10\)\. KEV only orders CVEs; it says nothing about which function changed\.

### Why: Ipv6pFragmentInit (older 0x1500, newer 0x1540)

**Summary**

- partial fit; expected changes seen 1 of 3 \(required 0 of 1\); 2 independent groups; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Held at partial fit\: a required change was not seen\.

**Expected changes**

- R\-MEMORY\-WRITE revision 1, CWE\-787 as stated by the advisory\.
- Not seen\: guard added\.
- Seen\: size recomputed \(B1 SIZE; go to newer line 6\)\.
  - Next step\: Compare the allocation or copy size in both functions and check that the new size follows from the destination capacity\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 SIZE\.
- Advisory text\: CISA KEV, CSAF, MSRC, NVD \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Partial fit for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pFragmentInit\. Newer\: Ipv6pFragmentInit\.

**Provenance**

- Evidence\: 4 stated by the advisory, 1 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: listed \(added 2099\-02\-10\)\. KEV only orders CVEs; it says nothing about which function changed\.

### Why: Ipv6pFragmentReassemblyStats (older 0x1600, newer 0x1640)

**Summary**

- partial fit; expected changes seen 0 of 3 \(required 0 of 1\); 0 independent groups; evidence depth none\.
- No expected change was seen; the function changed and its name matches the advisory\.

**Expected changes**

- R\-MEMORY\-WRITE revision 1, CWE\-787 as stated by the advisory\.
- Not seen\: guard added\.
- Not seen\: size recomputed\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- None\: no observation meets an expected change\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pFragmentReassemblyStats\. Newer\: Ipv6pFragmentReassemblyStats\.

**Provenance**

- Evidence\: 1 label only, 1 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: listed \(added 2099\-02\-10\)\. KEV only orders CVEs; it says nothing about which function changed\.

## `CVE-2099-20002`

- Weakness class: stated by the advisory (CWE-125)
- CISA KEV: not in the snapshot 6427dbcdeef8; absence says nothing about exploitation
- Whether other CVEs are fixed in this build is unknown.
- Leads: fits advisory 2; needs review 2; partial fit 1; code change 0; changed, no fit 4

| # | Function | Addresses | Class | Changes seen | Groups | Pairing | Flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Ipv6pParseOptions | older 0x1280, newer 0x12c0 | FITS ADVISORY | 1 of 3 | 2 | corroborated | - |
| 2 | Ipv6pReassembleFragment | older 0x1180, newer 0x11c0 | FITS ADVISORY | 1 of 3 | 2 | corroborated | - |
| 3 | Ipv6pReassembleFragmentTail | older 0x1400, newer 0x1440 | NEEDS REVIEW | 1 of 3 | 2 | corroborated | text evidence only |
| 4 | Ipv6pFragmentListReassemble | older 0x1300, newer 0x1340 | NEEDS REVIEW | 1 of 3 | 2 | contested | pairing contested |
| 5 | Ipv6pFragmentInit | older 0x1500, newer 0x1540 | PARTIAL FIT | 1 of 3 | 2 | corroborated | text evidence only |
| 6-7 (tie) | Ipv6pFragmentReassemblyStats | older 0x1600, newer 0x1640 | CHANGED, NO FIT | 0 of 3 | 0 | corroborated | - |
| 6-7 (tie) | Ipv6pDispatch | older 0x1900, newer 0x1940 | CHANGED, NO FIT | 0 of 3 | 0 | corroborated | - |
| 8 | Ipv6pLogFragmentDrop | older 0x1700, newer 0x1740 | CHANGED, NO FIT | 0 of 3 | 0 | corroborated | - |
| 9 | Ipv6pChecksumFragment | older 0x1800, newer 0x1840 | NOT ASSESSED | 0 of 3 | 0 | corroborated | - |

### Why: Ipv6pParseOptions (older 0x1280, newer 0x12c0)

**Summary**

- fits advisory; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth typed\.

**Expected changes**

- R\-MEMORY\-READ revision 1, CWE\-125 as stated by the advisory\.
- Seen\: guard added \(B1 BND, ChangeFacts comparison; go to newer line 9\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Not seen\: size recomputed\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.
- Advisory text\: CSAF\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Fits advisory for CVE\-2099\-20001\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pParseOptions\. Newer\: Ipv6pParseOptions\.

**Provenance**

- Evidence\: 1 stated by the advisory, 1 label only, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: not in the snapshot; absence says nothing about exploitation\.

### Why: Ipv6pReassembleFragment (older 0x1180, newer 0x11c0)

**Summary**

- fits advisory; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth typed\.

**Expected changes**

- R\-MEMORY\-READ revision 1, CWE\-125 as stated by the advisory\.
- Seen\: guard added \(B1 BND, ChangeFacts comparison; go to newer line 14\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Not seen\: size recomputed\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.
- Advisory text\: CSAF\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Fits advisory for CVE\-2099\-20001\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragment\. Newer\: Ipv6pReassembleFragment\.

**Provenance**

- Evidence\: 1 stated by the advisory, 1 label only, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: not in the snapshot; absence says nothing about exploitation\.

### Why: Ipv6pReassembleFragmentTail (older 0x1400, newer 0x1440)

**Summary**

- needs review; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Needs review because a named proof argues against the change that was seen\.

**Expected changes**

- R\-MEMORY\-READ revision 1, CWE\-125 as stated by the advisory\.
- Seen\: guard added \(B1 BND; go to newer line 22\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Contradicted\: size recomputed \(a named proof argues against any change\)\.
- Contradicted\: checked arithmetic \(a named proof argues against any change\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.
- Advisory text\: CSAF\.

**Against**

- ChangeFacts cosmetic\: Proof COS\-LAYOUT/1 holds\: the old check was only moved\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Needs review for CVE\-2099\-20001\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragmentTail\. Newer\: Ipv6pReassembleFragmentTail\.

**Provenance**

- Evidence\: 1 stated by the advisory, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: not in the snapshot; absence says nothing about exploitation\.

### Why: Ipv6pFragmentListReassemble (older 0x1300, newer 0x1340)

**Summary**

- needs review; expected changes seen 1 of 3 \(required 1 of 1\); 2 independent groups; evidence depth typed\.
- Needs review because the pairing of the two functions is contested\.

**Expected changes**

- R\-MEMORY\-READ revision 1, CWE\-125 as stated by the advisory\.
- Seen\: guard added \(B1 BND, ChangeFacts comparison; go to newer line 17\)\.
  - Next step\: Open the newer function and check that the new comparison runs before the copy or index\.
- Not seen\: size recomputed\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.
- Advisory text\: CSAF\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Needs review for CVE\-2099\-20001\.

**Pairing**

- The pairing of the two functions is contested between engines\.
- Older\: Ipv6pFragmentListReassemble\. Newer\: Ipv6pFragmentListReassemble\.
- Next step\: Open both functions and decide yourself which pairing is right before relying on this lead\.

**Provenance**

- Evidence\: 1 stated by the advisory, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: not in the snapshot; absence says nothing about exploitation\.

### Why: Ipv6pFragmentInit (older 0x1500, newer 0x1540)

**Summary**

- partial fit; expected changes seen 1 of 3 \(required 0 of 1\); 2 independent groups; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Held at partial fit\: a required change was not seen\.

**Expected changes**

- R\-MEMORY\-READ revision 1, CWE\-125 as stated by the advisory\.
- Not seen\: guard added\.
- Seen\: size recomputed \(B1 SIZE; go to newer line 6\)\.
  - Next step\: Compare the allocation or copy size in both functions and check that the new size follows from the destination capacity\.
- Unknown\: checked arithmetic \(evidence not complete\: Calls\)\.

**Independent evidence**

- Ghidra\-derived code\: B1 SIZE\.
- Advisory text\: CSAF\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.
- Whether other CVEs are fixed in this build is unknown\.

**Alternatives**

- Partial fit for CVE\-2099\-20001\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pFragmentInit\. Newer\: Ipv6pFragmentInit\.

**Provenance**

- Evidence\: 1 stated by the advisory, 1 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
- CISA KEV\: not in the snapshot; absence says nothing about exploitation\.

## Code evidence only

| # | Function | Addresses | Class | Changes seen | Groups | Pairing | Flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1-2 (tie) | Ipv6pFragmentReassemblyStats | older 0x1600, newer 0x1640 | CODE CHANGE | - | 0 | corroborated | - |
| 1-2 (tie) | Ipv6pDispatch | older 0x1900, newer 0x1940 | CODE CHANGE | - | 0 | corroborated | - |
| 3 | Ipv6pReassembleFragment | older 0x1180, newer 0x11c0 | CODE CHANGE | - | 1 | corroborated | - |
| 4-5 (tie) | Ipv6pFragmentListReassemble | older 0x1300, newer 0x1340 | CODE CHANGE | - | 1 | contested | pairing contested |
| 4-5 (tie) | Ipv6pParseOptions | older 0x1280, newer 0x12c0 | CODE CHANGE | - | 1 | corroborated | - |
| 6 | Ipv6pLogFragmentDrop | older 0x1700, newer 0x1740 | CODE CHANGE | - | 0 | corroborated | - |
| 7-8 (tie) | Ipv6pFragmentInit | older 0x1500, newer 0x1540 | CODE CHANGE | - | 1 | corroborated | text evidence only |
| 7-8 (tie) | Ipv6pReassembleFragmentTail | older 0x1400, newer 0x1440 | CODE CHANGE | - | 1 | corroborated | text evidence only |
| 9 | Ipv6pChecksumFragment | older 0x1800, newer 0x1840 | NOT ASSESSED | - | 0 | corroborated | - |

### Why: Ipv6pFragmentReassemblyStats (older 0x1600, newer 0x1640)

**Summary**

- code change; 0 independent groups; evidence depth none\.
- Positions 1\-2 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- None\: no observation meets an expected change\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- Partial fit for CVE\-2099\-20001\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pFragmentReassemblyStats\. Newer\: Ipv6pFragmentReassemblyStats\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pDispatch (older 0x1900, newer 0x1940)

**Summary**

- code change; 0 independent groups; evidence depth none\.
- Positions 1\-2 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- None\: no observation meets an expected change\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pDispatch\. Newer\: Ipv6pDispatch\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pReassembleFragment (older 0x1180, newer 0x11c0)

**Summary**

- code change; 1 independent group; evidence depth typed\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison, RtlSizeTAdd call added, label only \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- Fits advisory for CVE\-2099\-20001\.
- Fits advisory for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragment\. Newer\: Ipv6pReassembleFragment\.

**Provenance**

- Evidence\: 1 label only, 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pFragmentListReassemble (older 0x1300, newer 0x1340)

**Summary**

- code change; 1 independent group; evidence depth typed\.
- Positions 4\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- Needs review for CVE\-2099\-20001\.
- Needs review for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is contested between engines\.
- Older\: Ipv6pFragmentListReassemble\. Newer\: Ipv6pFragmentListReassemble\.
- Next step\: Open both functions and decide yourself which pairing is right before relying on this lead\.

**Provenance**

- Evidence\: 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pParseOptions (older 0x1280, newer 0x12c0)

**Summary**

- code change; 1 independent group; evidence depth typed\.
- Positions 4\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND, ChangeFacts comparison \(same origin, counted once\)\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- Fits advisory for CVE\-2099\-20001\.
- Fits advisory for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pParseOptions\. Newer\: Ipv6pParseOptions\.

**Provenance**

- Evidence\: 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pLogFragmentDrop (older 0x1700, newer 0x1740)

**Summary**

- code change; 0 independent groups; evidence depth none\.

**Independent evidence**

- None\: no observation meets an expected change\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pLogFragmentDrop\. Newer\: Ipv6pLogFragmentDrop\.

**Provenance**

- Evidence\: 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pFragmentInit (older 0x1500, newer 0x1540)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 7\-8 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 SIZE\.

**Against**

- None\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- Partial fit for CVE\-2099\-20001\.
- Partial fit for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pFragmentInit\. Newer\: Ipv6pFragmentInit\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pReassembleFragmentTail (older 0x1400, newer 0x1440)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 7\-8 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.

**Against**

- ChangeFacts cosmetic\: Proof COS\-LAYOUT/1 holds\: the old check was only moved\.

**Unknown**

- Calls\: partial \(Ghidriff call labels only; no import delta\)\.

**Alternatives**

- Needs review for CVE\-2099\-20001\.
- Needs review for CVE\-2099\-20002\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragmentTail\. Newer\: Ipv6pReassembleFragmentTail\.

**Provenance**

- Evidence\: 2 reported by a tool\.
- Result 41669a1dace0da03; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
