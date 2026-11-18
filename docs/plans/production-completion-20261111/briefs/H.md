# WORKSTREAM H - Accuracy qualification
Scope: tools/research_qualification/** (cases, scoring, parity, adapters, scorerun, l1_check, sample_size, receipt),
tools/unified/** (gates_u.py, evaluators.py, bench.py, mutations/, corpus/ - L2 lane, read-only), tools/calibration/**,
src/patchtrace/calibration/**, corpus/**, docs/research/accuracy-cases/**,
docs/plans/accuracy-program-handoff-20261107.md, accuracy-validation-plan-20261106.md, c9-preregistration-v1.md,
pilot-preregistration-v1.md, docs/qa/accuracy-program-findings-20261107.md, docs/specs/known-answer-corpus.md,
calibration-corpus-and-model.md, multi-engine-evidence-calibration.md, docs/specs/unified-engine/08-evaluation.md,
docs/handoff/label-training.md (skim headings only).

State precisely:
(a) which accuracy numbers exist today per layer - L1 (advisory join), L2 (open-source pair diff), L3 (real Windows pairs) -
    each with evidence class and where it is recorded, or 'none scored';
(b) per directive benchmark category whether fixtures/cases exist and whether they are runnable offline here: identical
    binaries; small instruction changes; function additions and removals; compiler optimization changes; symbol-stripped
    binaries; reversed comparisons; known patched binaries; known vulnerable binaries; unsupported formats; malformed
    binaries; large binaries; cross-version comparisons;
(c) which tracked metrics have code: matching precision, recall, false positives, false negatives, runtime, memory
    consumption, adapter failures, confidence calibration;
(d) the documented acceptance thresholds (G-U1..G-U7, G-PIL, Tier R, C9) and their current state (pass / fail / blocked /
    not run) with evidence;
(e) what could be measured offline in this sandbox today with pure-Python synthetic IR or checked-in fixtures (name the
    exact command), clearly labelled synthetic.
Run and record (stdlib-only, fast): `cd <main checkout> && python -m tools.research_qualification --help`
and the L1 validator on the checked-in corpus if its usage allows a read-only run (exit 0 ok, 1 differs, 2 blocked).
GitHub read: latest 2 runs on main for corpus-tier-r.yml, unified-corpus.yml, unified-live-gates.yml, diff-and-score.yml,
winbindex-pairs.yml, pilot-eval.yml (conclusion, id, date).
actionable_now: offline-verifiable improvements to the qualification tooling (validators, scoring correctness bugs with
file:line, missing negative tests), never changes to thresholds or expectations.
