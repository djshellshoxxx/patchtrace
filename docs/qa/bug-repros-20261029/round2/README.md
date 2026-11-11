# Round-2 bug repro scripts (issue #105, 2026-10-29)

Standalone scripts that reproduced the round-2 findings posted on issue #105. They are evidence, not tests: each prints
what it observed, and the fixed behaviour is pinned by regression tests under `tests/`.

Run from the repository root with the dev environment (`pip install -e ".[dev,search,rules]"`):

```bash
PYTHONPATH=src python docs/qa/bug-repros-20261029/round2/<script>.py [args]
```

| Prefix | Area | Findings | Regression tests |
| --- | --- | --- | --- |
| `rules_*`, `cg_*`, `fab_fuzz.py` | rules, callgraph | BUG-RULE-1..7, BUG-CG-1..3 | `tests/test_rules_cg_bugfixes_20261029.py` |
| `enr_*` | search, enrichment | S1-S9, E1-E9 | not fixed yet |
| `pilot_*` | pilot, nway, buildenv | N1-N2, P1-P4, B1-B4 | not fixed yet |

Scripts that take arguments: `rules_diff_dos.py N` (instruction count, e.g. 8000), `cg_paths_dos.py K D` (e.g. 200
100000), `enr_r10_corrupt_row.py hash|nostage|listbody`. Some `pilot_*` and `enr_*` scripts write a sample project to
the directory given as their first argument; read the script's top lines first.

Scripts write only to fresh temporary directories (or the directory you pass). Mappings to the exact source lines are in
the #105 comments.
