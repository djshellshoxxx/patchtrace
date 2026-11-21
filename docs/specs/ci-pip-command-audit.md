# Workflow pip command audit

## Purpose and dependencies

This additive CODEX-5 audit checks explicit pip-install command boundaries in
workflow source. It does not resolve dependencies, validate artifact hashes,
execute shell scripts, or prove a complete immutable package closure. Existing
CODEX-5 history and the original strict expected-failure test are retained.

Use the existing development dependency PyYAML >=6,<7. Missing PyYAML is a
collection/import error; never substitute a partial YAML parser or skip the
check. Parse errors, ambiguous YAML mappings, unsupported matching shell syntax,
and empty repository discovery must fail independently of missing hash flags.

## YAML boundary

Parse YAML with PyYAML's safe loader and read only actual
`jobs.<job>.steps[].run` string values, in file order. Honor YAML quoting,
comments, indentation, literal/folded blocks and preserved blank-line boundaries.
Ignore `defaults.run`, environment keys named `run`, action inputs and other
metadata. Reject malformed YAML, duplicate mapping keys, invalid jobs/steps/run
shapes and empty run strings. Reusable-workflow jobs may have `uses` without
steps. This is structural validation for the audited boundary, not the entire
GitHub Actions schema.

`run_scalars(source)` returns decoded shell strings. `pip_installs(source)`
returns explicit command records with one-based run ordinal, normalized command
text and pip arguments. `unhashed_installs(source)` preserves the donor API:
list of `(run ordinal, command)` pairs lacking a per-command boundary flag.

## Bounded shell recognition

Use shell-token recognition without evaluating scripts. Support literal direct
`pip[3[.minor]] install` and `python[3[.minor]] -m pip install` invocations,
POSIX executable paths, simple environment assignments, option-free `env`/`sudo`,
and the simple `if`/`elif`/`while`/`until`, `then`/`else`/`do`, and `!` prefixes
used around direct commands. Windows `.exe` names may use the same direct form.
Recognize newline, semicolon, `&&`, `||`, pipe and background separators, shell
comments and backslash/PowerShell-backtick line continuations. Decode YAML
folding before considering shell boundaries.

An echo/printf/Write-Output/Write-Host literal is not an installer. Matching
installer text in unsupported wrappers, command substitutions, grouping,
redirections or dynamic executable expressions is an explicit audit error.
Unbalanced quoting and ambiguous separators are errors. Embedded script bodies
and indirect invocations are outside the proved executable classification;
matching installer text there must not become a successful empty result.
This is intentionally not a general POSIX/PowerShell/cmd parser. Known unsupported
syntax must be fixed in the audit contract and covered before accepting it.

Only literal `--require-hashes` or `--no-index` tokens associated with the same
recognized install qualify as the syntactic boundary. Comments, neighboring
commands and literal output text cannot provide that flag. Tokens after the
`--` option terminator do not qualify; explicitly disabled hash checking does
not qualify as required hashes. Known pip option values cannot supply a flag;
unknown option arity before a possible boundary is an explicit audit error.
No inference is made from environment-supplied
flags, remote wheelhouses or requirements-file contents. A boundary flag alone
never proves artifact or transitive-closure integrity.

## Regression and acceptance

Retain original donor evidence and its incomplete fixture-only qualification.
The repaired audit must cover the independent commented-block, folded blank-line,
env.run and conditional-negation controls, supported positive/negative command
forms, unsupported matching syntax, malformed YAML and missing dependencies.
A positive current-tree census must see 21 workflows, 200 actual run scalars,
42 direct install commands, one Pages command with a boundary flag and 41
unprotected commands at source base ae69f1e65d7c4564ec5b0e6d7a80119193fabc4e.

Any additive strict expected-failure gate must catch only a dedicated exception
for successfully parsed unprotected installs. Parser/shape/dependency errors,
empty discovery and other assertions must remain hard failures. No existing
workflow bytes or original CODEX-5 test are changed by this audit repair.

Verify affected tests, whole-tree Ruff, pip consistency and exact source binding
in a dedicated environment. Full-suite and independent review evidence remain
separate from hosted/native qualification; no main, release, deploy or remote
ref mutation is authorized by this contract.
