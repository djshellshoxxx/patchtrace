# Slice card CLI-B - manual corrections and review state from the command line: `patchtrace corrections` and `patchtrace review`

Evidence and designs: `jq '.actionable_now[] | select(.id=="F-T14")' docs/status/inventory/F.json`, `jq '.features[] | select(.id=="F-F16")' docs/status/inventory/F.json`,
parity matrix docs/status/gui-cli-parity-matrix.md rows 10-14 and section 3 item 9 ("Manual correction import / export": the one required CLI item with
nothing built). Read the binding CLI constraints at the top of docs/plans/production-completion-20261111/cards/CLI-A.md (registry file per verb, adapter of at
most 25 lines, no edit of cli.py, envelope, exit codes, no Qt, no prompt, help page per verb) - they apply here unchanged.

## What exists (read before designing)
ProjectService.correct_match (service.py:337), restore_match_override (379), review_match (313), review_finding (321),
annotate (330); the match-override annotations they write; the desktop flow in ui.py (correct_match about line 2213,
undo about 1899). Main already refuses a manual correction with unresolved members (PR #188) - find that rule and its
test and keep it the single validation path. The unified engine consumes corrections
(`patchtrace unified run PROJECT --sources manual`) and binds them into its result key; you do not touch
src/patchtrace/unified/**, you only go through ProjectService.

## Spec first: docs/specs/manual-corrections-exchange.md (new) - contract `corrections-exchange/1`
A JSON document an analyst can export from one copy of a project and import into another copy of the SAME pair
(or keep under version control): contract name, export time is NOT included (deterministic bytes for the same state),
the identity of the pair it belongs to (older and newer SHA-256 and the orientation at export), and the ordered list of
manual corrections with for each: the functions on each side identified the way the project identifies them (ids as
stored plus address and name so a reader can check them), the correction kind/status the service records, the analyst
note, and the review state of matches and findings if the analyst asks for them (`--include-review`).
Import rules (all in the spec, all tested): strict JSON only (duplicate keys, NaN/Infinity, deep nesting and trailing
data refused - reuse the project's strict JSON reader, do not write a new one); size cap; the pair identity must equal
the target project's (SHA-256 of both sides; a swapped orientation is refused with a message that says so, not silently
mirrored); every member must resolve in the target project (the existing unresolved-member rule); validation of the
WHOLE document happens before the first write; apply is all-or-nothing (if the service cannot do that in one commit,
snapshot and restore, or apply to a candidate and commit once - read how ProjectService._commit works; say exactly what
guarantee you achieved); re-importing the same document is a no-op (idempotent: no duplicate overrides, exit 0, counts
say "already present"); `--dry-run` validates and reports what would change and writes nothing; untrusted text (notes,
names) is bounded and stored inert, and printed through hostile_text.escape_text.

## Verbs
`patchtrace corrections list PROJECT` (text table, --json), `corrections export PROJECT --out FILE [--include-review]`
(refuse to overwrite an existing different file unless --force; write atomically: temp file in the same directory, then
os.replace), `corrections import PROJECT FILE [--dry-run]`, `corrections undo PROJECT [--annotation ID]` (wraps
restore_match_override; default is the latest correction, as the desktop does).
`patchtrace review match PROJECT --match ID --status STATUS`, `review finding PROJECT --finding ID --status STATUS
[--conclusion TEXT]`, `review note PROJECT --target ID --text TEXT [--kind note]` (wrap review_match, review_finding,
annotate; valid statuses come from the models, not from a list you type).
Dispatcher modules src/patchtrace/corrections_cli.py and src/patchtrace/review_cli.py; adapters
src/patchtrace/cli_commands/corrections.py and review.py.

## Help pages (new files; numbers assigned by the orchestrator)
docs/help/79-cli-corrections.md, docs/help/80-cli-review.md, plus one index line each in docs/help/README.md after the
last CLI line.

## Tests (red first; tests/test_corrections_cli.py, tests/test_review_cli.py, new)
Use ProjectService.sample or the fixture projects other tests build. Cover: export -> import into a fresh copy of the
same sample reproduces byte-identical export (round trip); idempotent re-import; dry-run writes nothing (tree hash);
wrong pair refused; swapped orientation refused; unresolved member refused with nothing applied; a document that is
valid for 3 corrections and invalid in the 4th applies none; hostile note text is inert in text output; duplicate-key
and deeply nested JSON refused with exit 2; export refuses to clobber; undo restores the previous state; each review
leaf changes exactly the intended record; envelope/exit-code contract; no-Qt import. After an import, assert the
project's corrections are visible to the consumer the desktop uses (read back through ProjectService).

## Owned files
src/patchtrace/corrections_cli.py, src/patchtrace/review_cli.py, src/patchtrace/cli_commands/corrections.py,
src/patchtrace/cli_commands/review.py (all new), docs/specs/manual-corrections-exchange.md (new),
docs/help/79-cli-corrections.md, docs/help/80-cli-review.md (new), docs/help/README.md (two added index lines),
tests/test_corrections_cli.py, tests/test_review_cli.py (new), docs/schemas files if you add a pydantic model for the
exchange document (put the model in corrections_cli.py or a small src/patchtrace/corrections_exchange.py and wire it
into the schema generator only if the generator is not a frozen/shared file - otherwise put the generator line under
"Integrator asks" and add a test that validates the document against the model directly).
NOT yours: src/patchtrace/service.py, models.py, persistence.py, cli.py, unified/**. If the service lacks something
essential (for example an all-or-nothing batch apply), build the guarantee in your module on top of the public API and
report the gap; if a real defect appears in the service, write a strict xfail test describing it and report it.
