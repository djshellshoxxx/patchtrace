# Ledger B (instance B, feature builder)

| Item | State | Evidence |
|---|---|---|
| B-0 dependency enablement | in PR | extras `workbench`/`rules`, `optional_deps.py`, hook, frozen-smoke line, wheels probe workflow |
| KB K0 contracts | built, merged into branch (162 tests, full suite 2597 passed) | commits 2844797,6fa3e3e; K0f (haiku) then K1 next; K2 waits A-5/A-6 |
| WB1, WB3, CAP, DIE, KEV, WB2, YRX, WBQ | waiting for integration plans from A | |
| C audit findings for B modules | queued after tracks | docs/audits/20261014-C-{tool-adapters,acquisition-gui,intelligence-enrichment}.md on claude/instance-c-research (TA-2 capa delta, transport slow-drip C-01 High, CSAF TypeError, CWE double count) |
| ordering constraint (from A) | note | read 20261014-C-tool-adapters.md TA-1..TA-11 BEFORE CAP/DIE/WB3 runners; acquisition-gui C-01 BEFORE KB K6/K7; fix in owning slice with red tests |
| YRX pins (from A) | note | rules extra: yara-x==1.21.0 + iced-x86 at the plan's version, wheels-only; package yarax/; ship Rust crate licence notices in the Windows build; do it with the YRX slice (pin yara-x==1.21.0 when next touching pyproject) |
