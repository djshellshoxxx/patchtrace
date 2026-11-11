# Slice card CLI-0 - bring SPEC-44 (CLI umbrella) up to main and record the decisions the new verbs need (docs only)

Evidence: `jq '.actionable_now[] | select(.id=="F-T06")' docs/status/inventory/F.json`, feature rows F-F01, F-F02, F-F21 in the same file, the real
help output of every verb in docs/status/cli-help-main-882d1ca0.txt (106 help pages captured from main 882d1ca0) and the parity matrix
docs/status/gui-cli-parity-matrix.md (sections 1, 3 and 4).

## Why
AGENTS.md: update the specification before changing contracts. docs/specs/cli-umbrella.md (SPEC-44, draft 2026-10-14) still
describes 11 verbs / 36 paths, says cli_commands and export do not exist, and marks project / import / doctor / config as
"not in the alpha". Main has 24 top-level verbs (11 built in, 13 from cli_commands/), 86 visible leaves, one real leaf
help cannot show (`kb index sync`) and three hidden workers.

## Do
1. Rewrite the inventory sections of docs/specs/cli-umbrella.md to describe main as it is (verify every statement against
   the code or the captured help; cite file:line as the existing spec does): the verb list with owner spec per verb, the
   cli_commands registry (a verb is one file exporting COMMAND; adapters stay small; discovery by file; a broken file is
   listed as unavailable and exits 3), the envelope enrichment-cli/1, the exit-code contract 0/2/3/4/5 with the KNOWN
   deviations listed honestly as deviations (parity matrix section 3 item 17 and feature F-F02 enumerate them) rather
   than normalised away, the output formats per verb (text / --json / CSV where it exists), unattended operation (no
   prompt on any path; consent is a flag), the Qt-free import rule and its test.
2. Section 7 ("not in the alpha"): record, dated 2026-11-11, that the owner directive of that date asks for GUI/CLI
   parity (every substantial GUI capability has a CLI equivalent unless impossible or inappropriate) and that the
   following verbs are therefore in scope, each specified in its own file which this session's parallel slices are
   writing - name the files, do not write them: `project` and `compare` (docs/specs/cli-project-compare.md),
   `corrections` and `review` (docs/specs/manual-corrections-exchange.md), `profile`, `doctor`, `runtime`
   (docs/specs/cli-profile-doctor-runtime.md). State the rules those verbs must follow (envelope, exit codes, no Qt, no
   prompt, read-only verbs never write to the project, mutations go through ProjectService only, a help page per verb).
   Keep `interpret` (headless AI interpretation) as an open owner decision: credentials are session-only by policy.
3. Keep section 8 (exit-code decisions pending the owner) intact but add the current list of deviations so the decision
   has the facts in front of it.
4. Do not change any code. Do not edit docs/cli-reference.md, docs/guide/** or docs/help/** (other slices / sessions).

## Owned files
docs/specs/cli-umbrella.md only. Put the row text for docs/specs/REGISTRY.md (status line change for SPEC-44 and three new
rows for the new spec files) under "Integrator asks" - do not edit REGISTRY.md.
There is no red test for a documentation slice; instead put in red_evidence the list of statements in the old spec that
were false on main with the evidence, and in focused_tests the commands you ran to verify the new statements. Run
tests/test_help_docs.py and any test that reads the specs (`grep -rln "cli-umbrella" tests`) and report the result.
