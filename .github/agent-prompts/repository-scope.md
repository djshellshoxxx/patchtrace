# PatchTrace autonomous development scope

Inspect the latest main branch, all open PRs, CI, ownership ledgers and integration branches before selecting work. PatchTrace has active unified-engine, QA, consolidation and API-funded automation efforts. Do not duplicate or modify work owned by active contributors or PRs #170, #171, #174, #176–#185 unless ownership is explicitly reassigned.

Prioritize independently verifiable unowned fixes in binary ingestion and persistence, unified matching and diff, KB→CVE→product→binary→patch correlation, Winbindex pairing, adapters (BinExport2, BinDiff, rz-diff), enrichment ranking, GUI usability, regression tests and release readiness. Verify that a feature is actually missing before implementing it.

Respect native tool availability, offline CI limitations, licensing and fixture provenance. Require test-first development where practical and preserve failure evidence. Produce a focused reviewable diff; the workflow publishes a draft PR. Never merge or deploy from the agent.
