# Distinguish pairing from change classification

Experimental: Unified classifications are implemented in the reviewed contracts and panel sources. Packaged availability is UNVERIFIED.

A pairing decision describes the relationship between functions. A change classification describes what the available comparison evidence establishes about their differences. Read both.

The Unified contract includes pairing decisions for matched, tentative, candidate, contested, ambiguous, older-only, newer-only, and unknown records.

Its change classifications are:

| Classification | How to read it |
| --- | --- |
| Unchanged | The comparison satisfies the recorded unchanged-proof rules |
| Cosmetic | Differences satisfy a supported structural-cosmetic proof |
| Material | Required semantic-change and supporting-channel rules are met |
| Review | Available evidence requires further inspection |
| Unknown | The available evidence does not establish a classification |
| Not applicable | This classification does not apply to the relationship |

“Unchanged” is scoped to the recorded comparison and its rules. It does not establish equivalence under every possible execution.

“Material” identifies a supported code difference. It does not identify its purpose or assign it to a CVE.

Change classes can describe constants, comparisons, conditions, callees, calls, data references, structure offsets, control flow, blocks, strings, or presentation-related changes. Inspect the exact class and provenance rather than treating all differences alike.

Older-only and newer-only records lack a two-sided counterpart. **Do not interpret their classification as a comparison of two function bodies.**

If pairing is contested, review the identities before explaining the apparent code change.

Sources: src/patchtrace/unified/contracts.py; src/patchtrace/unified/panel.py; src/patchtrace/unified/read_model.py.
