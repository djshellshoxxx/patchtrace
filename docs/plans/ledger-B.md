# Ledger B (instance B, feature builder)

| Item | State | Evidence |
|---|---|---|
| B-0 dependency enablement | MERGED 46dfac1 (PR #44, all checks green, prerelease from main pending verification) | extras `workbench`/`rules`, `optional_deps.py`, hook, frozen-smoke line, wheels probe workflow |
| KB K0 contracts + K0f fixtures | MERGED 46dfac1 (with B-0) | commits 2844797,6fa3e3e; K0f (haiku) then K1 next; K2 waits A-5/A-6 |
| WB1, WB3, CAP, DIE, KEV, WB2, YRX, WBQ | waiting for integration plans from A | |
| C audit findings for B modules | queued after tracks | docs/audits/20261014-C-{tool-adapters,acquisition-gui,intelligence-enrichment}.md on claude/instance-c-research (TA-2 capa delta, transport slow-drip C-01 High, CSAF TypeError, CWE double count) |
| ordering constraint (from A) | note | read 20261014-C-tool-adapters.md TA-1..TA-11 BEFORE CAP/DIE/WB3 runners; acquisition-gui C-01 BEFORE KB K6/K7; fix in owning slice with red tests |
| YRX pins (from A) | note | rules extra: yara-x==1.21.0 + iced-x86 at the plan's version, wheels-only; package yarax/; ship Rust crate licence notices in the Windows build; do it with the YRX slice (pin yara-x==1.21.0 when next touching pyproject) |
| KB K1 | MERGED ea5be5e (PR #47) | commit 04f92ab; note csaf-kb.json fails real CSAF validator, csaf-kb-valid.json added |
| tools-core (TA audit fixes, S1b, TC-R/C/P) + B-0 follow-ups | MERGED ea5be5e (PR #47; Linux+Windows QA, native, live-intel-tools ubuntu+windows green) | pins measured TOFU; diec live blocked here; open: qa.md rows, capa memory_limit_bytes, intel-tools pairs |
| B-0 follow-ups (A build audit of 48f2eed) | DONE in PR #47 | (M) add rapidfuzz (MIT) and yara-x (BSD-3 + Rust crate notices) to licenses/ and dependency-versions.json in tools/build_linux.py:22 and tools/build_windows.py:69; (L) copy_metadata() for rapidfuzz/yara-x in hook-patchtrace.optional_deps.py so self-test shows versions; (L) declare shiboken6==6.12.0 in pyproject (direct import in ui_engine_setup.py, ui_evidence.py) |
