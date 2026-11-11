# WORKSTREAM C - CVE and vulnerability intelligence
Scope: src/patchtrace/intelligence/** (CSAF/CVRF interpretation engine), src/patchtrace/kev/** (CISA KEV),
src/patchtrace/enrichment/** (NVD/MSRC CVE context, cache, storage), src/patchtrace/acquisition/**,
src/patchtrace/netutil.py, providers.py.
Specs: csaf-cve-interpretation-engine.md, kev-exploitation-context.md, enrichment.md, enrichment-hardening-backlog.md,
acquisition.md, network-egress-privacy.md, docs/specs/kb/vendor-feeds-and-source-matrix-spec.md,
docs/specs/kb/advisory-revision-and-snapshot-identity-spec.md, docs/specs/program-e/KEV-integration-plan.md,
KB2-source-facts.md.
Audits/QA: docs/audits/20261014-C-intelligence-enrichment.md, 20261015-acquisition-enrichment.md,
20261015-intelligence-kev-rules-fabric-pilot.md, 20261015-fixes-acquisition.md;
docs/qa/online-source-reliability-20261105.md, kb-source-admission-20261106.md, winbindex-*.md.
Tools: tools/live_nvd_probe.py, live_kev_probe.py, live_kbc_probe.py, make_kev_catalog.py.

Assess each directive item: CVE ingestion; CVE identifier normalization; vulnerability metadata persistence; vendor and
product identification; version and affected-product mapping; CVE-to-KB relationships; KB-to-update relationships;
update-to-binary relationships; source provenance; evidence freshness tracking; confidence and ambiguity reporting; duplicate
and conflicting record handling; incremental refresh; cache management; offline operation; source adapters for NVD, CISA
KEV, MSRC (CVRF/CSAF), vendor publications, Winbindex; respect of documented API requirements (rate limits, API keys,
user-agent); separation of CONFIRMED relationships from INFERRED correlations (find where the code marks inferred
correlations and whether any path can present a speculative CVE match as confirmed).

GitHub read: latest 2 runs on main of live-nvd.yml, live-kev.yml, live-kbc.yml (conclusion, id, date).
Look hard for real defects (malformed advisory parsing, date/timezone handling, dedup keys, cache invalidation, unbounded
growth, identifier normalization edge cases such as lowercase 'cve-', unicode dashes, year/sequence bounds) with file:line;
confirm with a tiny python -c call when cheap.
