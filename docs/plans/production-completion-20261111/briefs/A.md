# WORKSTREAM A - Binary comparison and matching
Scope: src/patchtrace/unified/** (IR extraction, ladder passes, fusion/arbiter, facts, channels, store, read_model, compute,
worker), src/patchtrace/alignment.py, normalization.py, models.py, service.py (compare/import path), manual matching and
corrections (grep 'correction' in src/patchtrace/unified and service.py).
Specs: docs/specs/unified-engine/01..13 (13-remaining-work-plan.md and 10-amendments.md are the most current),
docs/handoff/unified-engine.md, docs/audits/20261104-unified-*.md, docs/audits/20261015-unified-audit.md.
Tests: tests/test_unified_*.py, tests/unified_support/. Gates G-U1..G-U7: tools/unified/gates_u.py,
docs/specs/unified-engine/08-evaluation.md. Trackers: master-todo U1..U8; `grep -n 'unified\|UE-\|G-U' tasks/todo.md`.

Assess each directive item: (1) binary ingestion and preprocessing (2) function identification and matching (3) known
correctness defects (4) instruction-level differences (5) control-flow-graph comparisons (6) changed / unchanged / added /
removed function classification (7) confidence scoring (8) false-positive and false-negative match detection (9)
identical-input handling (10) reversed-input behaviour (11) stripped binaries (12) missing symbols (13) optimized compiler
outputs (14) different compiler versions (15) architecture-specific behaviour (which architectures are supported at all?)
(16) actionable error reporting (17) regression tests for confirmed defects.
Is the unified engine feature flag ON or OFF by default, and exactly which gates keep it off?
Most of this area is under L1/L2: `actionable_now` only for work clearly outside L1/L2 files (e.g. U3 CLI polish, U5
`unified/columns` setting persistence, U6 IR text reader, ui_unified.py items, U4 hermetic real-pipeline GUI test) and only
after verifying it is still open.
