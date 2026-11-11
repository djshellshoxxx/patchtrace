# Slice card INT-2 - CVE and KEV records: typed errors, one identifier rule, provenance that never degrades

Evidence and designs: `jq '.actionable_now[] | select(.id=="C-T02" or .id=="C-T05" or .id=="C-T03")' docs/status/inventory/C.json` and the matching
defects `jq '.features[].defects[]? | select(.id|test("C-D0[23467]"))' docs/status/inventory/C.json` (each reproduced offline on main; scripts under
<scratch>/inventory/tmp-C/). Specs: docs/specs/enrichment.md, docs/specs/kev-exploitation-context.md.

Items, one commit each, red test first:

1. C-T02 (C-D02, C-D03) - src/patchtrace/enrichment/cve.py: a CVSS score such as 1e999999 raises decimal.Overflow and an
   out-of-range retrieval time raises OverflowError out of normalize / is_stale; either aborts `patchtrace correlate`
   and discards the VALID responses of other providers and other CVEs. Convert both to the module's typed
   refusal for that one record (the other records survive) - follow how the module already handles malformed fields.
   Tests tests/test_enrichment_cve.py and tests/test_enrichment_review_regressions.py: one bad record among good ones,
   the good ones are still returned and the bad one is reported with its reason.
2. C-T05, contract half (C-D06) - src/patchtrace/enrichment/contracts.py: the stored CveSnapshot.cve_id pattern admits
   non-ASCII digits (open tracker item tasks/todo.md:496 A5). Make it ASCII-only (the CLI already uses
   re.ASCII for the same rule in cli.py:_CVE_ID) and regenerate docs/schemas/enrichment/CveSnapshot.json with
   tools/generate_schemas.py (run from your worktree; `git status` must then show only that schema file changed among
   schemas). Persisted contracts change additively only: prove that every CveSnapshot the existing fixtures and tests
   store still validates, and say explicitly that a stored snapshot with non-ASCII digits (which no ASCII CVE id can
   produce) is refused on read by design. New tests/test_cve_id_normalization.py pins the single rule across the three
   places that validate a CVE id (enrichment contract, cli._cve_id, intelligence CLI) by importing them - do NOT edit
   src/patchtrace/cli.py or src/patchtrace/intelligence/cli.py (other owners); if the three disagree, record the
   disagreement as a strict xfail with the evidence and list the fix under "Integrator asks".
3. C-T03 (C-D04) - src/patchtrace/kev/store.py and kev/service.py: re-importing byte-identical catalog bytes replaces the
   stored snapshot's provenance, erasing the TLS authenticity and consent record of the fetched catalog, and
   `kev fetch` can print a source the store does not hold. Rule (spec sentence first in
   docs/specs/kev-exploitation-context.md): provenance never downgrades - an identical-bytes import keeps the stronger
   existing provenance and reports "already stored" with the STORED metadata; the service always reports what the store
   holds. Tests tests/test_kev_store.py and tests/test_kev_service.py: fetch-provenance then local import of the same
   bytes keeps the fetch record; the reverse order upgrades; the printed source equals the stored one.

## Owned files
src/patchtrace/enrichment/cve.py, src/patchtrace/enrichment/contracts.py, docs/schemas/enrichment/CveSnapshot.json
(regenerated), src/patchtrace/kev/store.py, src/patchtrace/kev/service.py, docs/specs/kev-exploitation-context.md
(one rule sentence - another slice of this session, K4, adds KEV amendment lines to the same file: append yours under
your own dated bullet), docs/specs/enrichment.md (status line for the identifier rule),
tests/test_enrichment_cve.py, tests/test_enrichment_review_regressions.py, tests/test_enrichment_core.py,
tests/test_cve_id_normalization.py (new), tests/test_kev_store.py, tests/test_kev_service.py.
NOT yours: src/patchtrace/cli.py, src/patchtrace/intelligence/** (slice INT-1), src/patchtrace/kev/cli.py,
ui_kev.py, enrichment/storage.py (frozen KINDS), enrichment/cache.py, docs/modules.md and tasks/todo.md (report rows).
