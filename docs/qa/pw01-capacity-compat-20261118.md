# PW-01 published-capacity and retained-page compatibility

## Reviewed source and scope

Source freeze: `0be3b9eb950a2a5a19261fd2f5d2f1fc2eb25b82`, tree
`81ec2835ec0b1a7b87a55cbe7b061d8b4d948878`. Its actual parents are spec-first
`3fee13616a80ecc65eb544e2feb0670f2f2f2df9` (a descendant of retained-page
continuation `c662d00c151e89d9db419c8b40cd9b616e0a4124`) and fresh published
#303 `2b697222b34359bb46adc90aad69fd0a12708601`. The latter preserves prior
#303 `76de3933` and adds the independently reviewed source-admission repair
`94779623`. Final read-only REST refresh still observed #303 at `2b697222`,
base main `9c411ca3`; its update time was 2026-11-18T09:48:50Z.

V1 imports preserve the published default and hard ceiling of 50,000 entries.
V2 source pages have independent strict defaults and ceilings of 5,000 entries,
including inherited retained counters and conflict witnesses. Retention derives
only `max_entries=min(parent.max_entries,5000)`; every other captured budget,
source and retrieval field is preserved. Existing v1 and v2 identities are never
rewritten. The v1 eight-suffix policy, v2-only TSP support, SQL selection-body
guard and incomplete-source selection refusal remain intact.

The incoming admission fix checks the advisory-source snapshot used for
eligibility, including the final transaction and repeated no-op selections.
It is combined with the retained-page guards, not substituted for them.
Three merge conflicts were resolved by retaining the earlier QA section,
combining both capacity specifications, and retaining all SQL-boundary tests;
the incoming test-file change removed trailing blank lines only.

## Regression and independent review

| Check | Observed result |
|---|---|
| New compatibility controls on c662 production source | 12 failed, 6 passed; genuine captured-50,000 record could not replay |
| Resolved shared-50,000 merge, before v2 isolation, uncommitted | 11 failed, 7 passed; wider page budgets accepted and the 5,001-row source had no page 2 |
| Narrow compatibility controls after repair | 18 passed in 5.80 s |
| Fourteen inventory/service/CLI/Qt/schema files | 581 passed in 22.49 s |
| Whole `ruff check src tests tools`, schema `--check`, whitespace | Passed |
| Separate read-only review of frozen 0be3 source | 38 focused plus 6 independently authored controls passed; source approved |

The counts overlap and are not summed. Four authored production-store golden
records cover v1 captured budgets 5,000 and 50,000 and earlier v2 default/lowered
pages with conflicts. The fresh #303 v1 bodies exactly match the prior `76de3933`
captures. The independent reviewer regenerated all four records through their
original exact `2b697222` and `c662d00c` writers and matched every byte/hash.
Parent budgets 1, 2, 5,000 and 50,000, page-two offsets, idempotence, raw/provenance
preservation, strict oversized-page refusal and zero revision changes are covered.

The broad gate used `QT_QPA_PLATFORM=offscreen PYTHONPATH=src
PYTHONDONTWRITEBYTECODE=1` and `/workspace/scratch/3a6632a6e5ff/venv/bin/python
-m pytest -q`, with these exact file arguments:

```text
tests/test_kbc_inventory_capacity_compat.py
tests/test_kbc_inventory_cli.py
tests/test_kbc_inventory_csv.py
tests/test_kbc_inventory_pages.py
tests/test_kbc_inventory_retention_adapters.py
tests/test_kbc_inventory_schemas.py
tests/test_kbc_inventory_selection.py
tests/test_kbc_inventory_service.py
tests/test_kbc_inventory_source_admission.py
tests/test_kbc_inventory_sources.py
tests/test_kbc_inventory_store.py
tests/test_kbc_schemas.py
tests/test_ui_kb_inventory.py
tests/test_ui_kb_inventory_retention.py
```

Exact argv/environment, original stdout, JUnit and gate receipts are retained in
the execution archive below. The independent archive includes its own scripts,
outputs, AST/ancestry checks and original-writer verification.

## Existing real CSV: sequential offline CLI qualification

This is the existing 3,300,683-byte proxy capture, SHA-256
`b327eb5d0f8d7a0d6a9c8c2d1a7af1df134bc2a54c3e0da2eff0fb335547a627`.
It was imported locally as unverified source data. No production fetch, target
binary, symbol or package acquisition, execution, selection or score occurred.

Nine separate, sequential shipped-CLI processes exercised a default v1 import,
AMD64 retention and verified inspection of source pages 1, 2 and 4, a repeated
page-1 request from page 4, and verified inspection of the original v1 import.
Each returned the expected partial status / exit 3 with empty stderr and no
termination signal. The source has rejected/conflicting claims, so partial is
the correct result and is distinct from a failed command.

| Result | Observed value |
|---|---|
| V1 captured budget / retained entries | 50,000 / 37,595 |
| Logical records scanned / rejected data rows | 42,845 / 5,244; not truncated |
| AMD64 source pages 1, 2, 4 | 5,000 / 5,000 / 3,761 retained; capacity 5,000; complete scans |
| Matching / excluded accepted rows | 18,761 / 18,834 |
| Existing v2 inventory and import IDs | Exact matches to the earlier retained-page qualification |
| `aarsvc.dll` contradiction on pages 1 and 4 | Exact witnesses for records 24,355 and 41,380; entries remain conflicted |
| Repeated page 1 from page 4 | Idempotent; no additional import |
| Original v1 serialized body | 30,948,193 bytes; SHA-256 unchanged before/after |
| Original raw object and capture | SHA-256 unchanged before/after |
| Investigation revisions / decisions | 0 / 0 throughout |

Linux `wait4` measured each child's own `ru_maxrss`. The largest observation was
**459,328 KiB (448.56 MiB)** during page-2 retention. Retention from the wider v1
parent took about 5.6-5.9 seconds per process in this run. These are observations,
not enforced memory or performance ceilings. The 16 MiB raw-byte limit,
16,777,216 decoded-character limit, 100,000-record limit, ten-second cooperative
parse deadline, 64 MiB serialized-record/read guard and 8,192-byte selection
guard remain unchanged.

The first external qualification launcher failed before creating a workspace:
it replaced `socket.socket` with a function before CLI imports, breaking the
socket class shape required by SSL initialization (`TypeError: function()
argument 'code' must be code, not str`). Its command returned 3 with error stderr
and no result envelope; the driver failed and did not count it as a partial
success. Original scripts, stderr and receipt are preserved. Only the external
launcher changed to a class-shaped construction denial, then a fresh workspace
completed the nine operations. Production source stayed at `0be3b9eb` throughout.

## Evidence and remaining gates

- [Execution evidence ZIP](pw01-capacity-compat-20261118/execution-evidence.zip): exact raw failures, receipts, outputs, authored golden captures, external CLI drivers and internal SHA-256 manifest. Third-party CSV bytes and the derived workspace are excluded; the input remains identified by its immutable capture hash.
- [Independent review ZIP](pw01-capacity-compat-20261118/independent-review.zip): exact separately sealed review of `0be3b9eb`.
- [Compact manifest and results](pw01-capacity-compat-20261118/manifest.json): archive hashes, source identity and qualification counts.

These local focused and offline-source results do not qualify hosted full-suite,
native Windows, packaging, manual desktop or production DNS/TLS retrieval gates.
They make no L2/L3 accuracy or release-completion claim. Later consolidation
parents and publication remain the integration lead's separate responsibility;
this worker made no remote writes or branch deletions.
