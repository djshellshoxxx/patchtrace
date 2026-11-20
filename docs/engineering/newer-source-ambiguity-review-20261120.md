# Generation27 coordinator adversarial inspection (NOT independent acceptance)

Reviewed parent PR337 source, current main, gen25 selector, retained Winbindex donor and new contract/tests. The new selected-tier ambiguity guard is reached only after exact SHA/name, KB and version matching, with native records preferred over `other_versions` propagated rows. Native and copied conflicting rows in either input order must refuse. Exact duplicate normalized maps remain admissible, and one native source must still take precedence over a conflicting copied record. Missing target bodies still refuse. The existing older `require_unique` check is preserved.

Open concerns: normalized mapping equality does not prove original raw entry equality; a selected target may have changed between resolver and acquisition index read; duplicate source records can be materially different while normalizing equal; malformed untrusted nested mappings at an injected port boundary are not exhaustively tested; a separate Linux forced export publication race persists. Independent reviewers should challenge equality semantics, provenance binding and no-transport integration using actual checked-out-source tests before any promotion.

Coordinator authorship prevents describing this inspection as independent signoff. Exact head full CI and external/native acceptance remain pending.
