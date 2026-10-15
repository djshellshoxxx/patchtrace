# Patch-intent leads

This report lists changed functions in the order that explainable rules give them. A lead is a place for a person to look; PatchTrace does not claim that a function contains or fixes a CVE.

> Leads are ordered by explainable rules, not by likelihood. A lead does not show that this function contains or fixes any CVE. Tied leads have equal evidence.

- Result: `64b52705a4bcdd382698e9f238342eecbb94b5e5e51f127e9669b27db98c011a` (contract `pilot/1`)
- Status: complete
- Older build: `3aa1f3653202a1be3710a508e36065f8c8ae00dc3e8494b8ebe0c1d6ca3d45d1`
- Newer build: `9e1dd2d600fc31153c59a091031336c01c910a224a5f8a8b207e835c1a45ea43`
- Orientation: older to newer
- Computed: `2099-01-01T00:00:00Z`

## Evidence channels

| Channel | State | Note |
| --- | --- | --- |
| Advisory | not run | no advisory is loaded |
| Code | partial | ChangeFacts were not run |
| Calls | not run | Call labels were not read |
| Strings | not run | FLOSS was not run |
| Capa | not run | capa was not run |
| Build | available | - |
| Pairing | available | - |

Some evidence was not available: Advisory, Code, Calls, Strings, Capa. Missing evidence is unknown, not a negative result.

## Code evidence only

No advisory is loaded. Leads use code evidence only and are not matched to a CVE. Import an advisory to rank by fit.

| # | Function | Addresses | Class | Changes seen | Groups | Pairing | Flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1-5 (tie) | Ipv6pFragmentInit | older 0x1500, newer 0x1540 | CODE CHANGE | - | 1 | corroborated | text evidence only |
| 1-5 (tie) | Ipv6pReassembleFragmentTail | older 0x1400, newer 0x1440 | CODE CHANGE | - | 1 | corroborated | text evidence only |
| 1-5 (tie) | Ipv6pReassembleFragment | older 0x1180, newer 0x11c0 | CODE CHANGE | - | 1 | corroborated | text evidence only |
| 1-5 (tie) | Ipv6pFragmentListReassemble | older 0x1300, newer 0x1340 | CODE CHANGE | - | 1 | contested | text evidence only, pairing contested |
| 1-5 (tie) | Ipv6pParseOptions | older 0x1280, newer 0x12c0 | CODE CHANGE | - | 1 | corroborated | text evidence only |
| 6-8 (tie) | Ipv6pLogFragmentDrop | older 0x1700, newer 0x1740 | NOT ASSESSED | - | 0 | corroborated | - |
| 6-8 (tie) | Ipv6pFragmentReassemblyStats | older 0x1600, newer 0x1640 | NOT ASSESSED | - | 0 | corroborated | - |
| 6-8 (tie) | Ipv6pDispatch | older 0x1900, newer 0x1940 | NOT ASSESSED | - | 0 | corroborated | - |
| 9 | Ipv6pChecksumFragment | older 0x1800, newer 0x1840 | NOT ASSESSED | - | 0 | corroborated | - |

### Why: Ipv6pFragmentInit (older 0x1500, newer 0x1540)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 1\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 SIZE\.

**Against**

- None\.

**Unknown**

- Advisory\: not run \(no advisory is loaded\)\.
- Code\: partial \(ChangeFacts were not run\)\.
- Calls\: not run \(Call labels were not read\)\.
- Strings\: not run \(FLOSS was not run\)\.
- Capa\: not run \(capa was not run\)\.
- Next step\: Run the missing tool, or accept that this lead rests on the other channels only\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pFragmentInit\. Newer\: Ipv6pFragmentInit\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 64b52705a4bcdd38; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pReassembleFragmentTail (older 0x1400, newer 0x1440)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 1\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.

**Against**

- None\.

**Unknown**

- Advisory\: not run \(no advisory is loaded\)\.
- Code\: partial \(ChangeFacts were not run\)\.
- Calls\: not run \(Call labels were not read\)\.
- Strings\: not run \(FLOSS was not run\)\.
- Capa\: not run \(capa was not run\)\.
- Next step\: Run the missing tool, or accept that this lead rests on the other channels only\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragmentTail\. Newer\: Ipv6pReassembleFragmentTail\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 64b52705a4bcdd38; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pReassembleFragment (older 0x1180, newer 0x11c0)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 1\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.

**Against**

- None\.

**Unknown**

- Advisory\: not run \(no advisory is loaded\)\.
- Code\: partial \(ChangeFacts were not run\)\.
- Calls\: not run \(Call labels were not read\)\.
- Strings\: not run \(FLOSS was not run\)\.
- Capa\: not run \(capa was not run\)\.
- Next step\: Run the missing tool, or accept that this lead rests on the other channels only\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pReassembleFragment\. Newer\: Ipv6pReassembleFragment\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 64b52705a4bcdd38; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pFragmentListReassemble (older 0x1300, newer 0x1340)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 1\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.

**Against**

- None\.

**Unknown**

- Advisory\: not run \(no advisory is loaded\)\.
- Code\: partial \(ChangeFacts were not run\)\.
- Calls\: not run \(Call labels were not read\)\.
- Strings\: not run \(FLOSS was not run\)\.
- Capa\: not run \(capa was not run\)\.
- Next step\: Run the missing tool, or accept that this lead rests on the other channels only\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is contested between engines\.
- Older\: Ipv6pFragmentListReassemble\. Newer\: Ipv6pFragmentListReassemble\.
- Next step\: Open both functions and decide yourself which pairing is right before relying on this lead\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 64b52705a4bcdd38; older build 3aa1f3653202, newer build 9e1dd2d600fc\.

### Why: Ipv6pParseOptions (older 0x1280, newer 0x12c0)

**Summary**

- code change; 1 independent group; evidence depth lexical\.
- Text evidence only\: decompiler text, no typed ChangeFacts\.
- Positions 1\-5 are tied\: equal evidence\.
- Next step\: Tied leads have equal evidence; look at each of them\.

**Independent evidence**

- Ghidra\-derived code\: B1 BND\.

**Against**

- None\.

**Unknown**

- Advisory\: not run \(no advisory is loaded\)\.
- Code\: partial \(ChangeFacts were not run\)\.
- Calls\: not run \(Call labels were not read\)\.
- Strings\: not run \(FLOSS was not run\)\.
- Capa\: not run \(capa was not run\)\.
- Next step\: Run the missing tool, or accept that this lead rests on the other channels only\.

**Alternatives**

- None\.

**Pairing**

- The pairing of the two functions is corroborated by more than one engine\.
- Older\: Ipv6pParseOptions\. Newer\: Ipv6pParseOptions\.

**Provenance**

- Evidence\: 1 reported by a tool\.
- Result 64b52705a4bcdd38; older build 3aa1f3653202, newer build 9e1dd2d600fc\.
