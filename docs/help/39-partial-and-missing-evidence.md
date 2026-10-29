# Understand partial and missing evidence

A partial result contains usable information alongside missing or incomplete evidence. Read the reason before interpreting an empty cell, absent row, or summary count.

Examples include a failed secondary engine, unavailable extraction channel, unreadable artifact side, incomplete advisory coverage, or a scan stopped at a configured limit.

Keep these states distinct:

| State | Meaning |
| --- | --- |
| Not run | The operation did not evaluate this material |
| Failed | Evaluation was attempted but did not yield a usable result |
| Unsupported | The current tool or environment cannot provide it |
| Unavailable | Required evidence cannot be supplied |
| Completed without a result | Evaluation completed within its stated coverage |

Missing evidence is unknown. It does not count as engine disagreement, absent behavior, or an unsuccessful advisory fit.

Inspect the affected channel or source, then decide whether to configure a missing tool, retry a failed operation, narrow the workload, or continue with explicitly limited coverage.

Do not rerun every tool automatically. The useful next step depends on what evidence your current question requires.

In a two-sided comparison, check whether both sides were evaluated under compatible settings. A complete newer-side scan cannot establish removal from an incomplete older-side scan.

When copying or exporting a partial result, retain its limitations and source identities. A report without those qualifications can suggest broader coverage than the analysis achieved.

Sources: src/patchtrace/gui/state.py; src/patchtrace/secondary/evidence_view.py; src/patchtrace/pilot/read_model.py; relevant Program E integration plans.

<!-- FORMAT NOTE: The Sources line says “relevant Program E integration plans” without naming a specific file. -->
