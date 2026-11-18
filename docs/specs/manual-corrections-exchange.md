# Manual corrections and review state from the command line: `corrections-exchange/1`

Status: implemented 2026-11-16 (slice CLI-B, findings F-T14 and F-F16). Evidence class of every test named here: hermetic,
on the synthetic sample project (`ProjectService.sample`). Nothing in this file is live evidence; no analysis engine,
no real Windows binary and no network is involved.

Code: `src/patchtrace/corrections_exchange.py` (contract, export, import plan; no CLI, no Qt),
`src/patchtrace/corrections_cli.py`, `src/patchtrace/review_cli.py` (dispatchers), `src/patchtrace/cli_commands/corrections.py`
and `review.py` (registry adapters). Schema: `docs/schemas/corrections/CorrectionsExchange.json`
(`tools/generate_corrections_schemas.py`). Tests: `tests/test_corrections_cli.py`, `tests/test_review_cli.py`.
Help: `docs/help/79-cli-corrections.md`, `docs/help/80-cli-review.md`.

## 1. Purpose and limits

An analyst corrects function relations in the desktop (`Correct match`). Until this slice those corrections, and the
review state of matches and findings, could not be listed, moved to another copy of the project, kept under version
control or set without the desktop. Two verbs close that gap: `patchtrace corrections` and `patchtrace review`.

Every write goes through `ProjectService` (`correct_match`, `restore_match_override`, `review_match`,
`review_finding`, `annotate`, `save`); nothing here edits the project database or the model records directly, so
the service's rules (one function belongs to one match, category and side rules, staleness of findings and of the
unified result key) stay the single validation path. Never done by either verb: executing a target, any network
request, any prompt (consent and confirmation are flags), any Qt import.

## 2. What a manual correction is in a project

`ProjectService.correct_match(match_id, older_ids, newer_ids, category, reason)` replaces the relation `match_id`
with a relation that has `manual: true`, the chosen functions, the category and the analyst's reason. Every other
relation that held one of the chosen functions loses it; what is left of such a relation becomes an `unmatched`
remainder. The service also appends a `match-override` annotation that holds the replaced relations, and marks every
earlier annotation and every finding stale.

Consequences this contract is built on:

- The effective corrections of a project are its relations with `manual: true`, in stored order. That is what
  `patchtrace unified run PROJECT --sources manual` consumes, what the desktop lists and what this contract exchanges.
- Only the latest correction has an active (not stale) `match-override` annotation, so only the latest correction
  can be restored by `restore_match_override`. This is the service's rule and the desktop's `Undo match correction`
  behaves the same way.
- Function, match and annotation identifiers are random per project. Two projects made from the same two files
  share SHA-256 values and function addresses, never identifiers.

## 3. The document

One JSON object. Written by `corrections export` as UTF-8, ASCII-only (`\uXXXX` escapes, so a bidirectional or
zero-width character in a name or a note is visible in a diff tool), keys sorted, two-space indent, one trailing
newline. No export time, no host name, no path: the same project state gives the same bytes.

| Field | Type | Rule |
|---|---|---|
| `contract` | string | exactly `corrections-exchange/1` |
| `pair.older_sha256`, `pair.newer_sha256` | 64 lower-case hex | SHA-256 of the two input files. The two role-named fields are the orientation at export |
| `corrections` | list, at most 2 000 | the relations with `manual: true`, in stored order |
| `corrections[].category` | string | a `FunctionMatch.category` value (read from the model) |
| `corrections[].note` | string, 1 to 32 767 characters, not blank | the analyst's reason (`FunctionMatch.reason`) |
| `corrections[].older`, `.newer` | list of members, at most 256 each, at least one member in total | the chosen functions per side, in stored order |
| member `address` | string, at most 64 characters; absent when the project stores none | the function's address as stored (hex text) |
| member `name` | string, at most 4 096 characters (longer names are cut at export) | the function's name: a reader's check, never the identity |
| member `id` | string, at most 128 characters, optional | the function identifier as stored in the exporting project: a reader's check, never used to resolve |
| `review` | object, present only with `--include-review` | review state, see below |
| `review.matches[]` | at most 100 000 | every relation whose review state is not `unreviewed`: `older`, `newer` (members), `status` (a `FunctionMatch.review` value) |
| `review.findings[]` | at most 10 000 | every finding whose review state is not `unreviewed` or that has an analyst conclusion: `id` (as stored), `digest`, `summary` (cut at 4 096), `status` (a `Finding.review` value), `conclusion` (at most 32 767) |

Unknown fields, wrong types and values outside these bounds are refused (strict model, `extra: forbid`).

Function identity is (side, address): the side is the list the member stands in, the address is compared as a
number after the same hex parsing the unified engine's manual adapter uses (`unified.addressing.parse_va_text`).
Finding identity requires the exact stored ID and SHA-256 of canonical JSON containing provider, model, prompt version, full interpretation context and full finding (excluding mutable review, analyst conclusion and stale flag).

Not in the document, by design: the replaced relations and the remainders (history, not state), match and
annotation identifiers, timestamps, analyst notes that are not correction reasons, code.

## 4. Import rules

All of them are checked, in this order, before the first write. Any refusal is exit 2, names the rule, and leaves
the project unchanged.

1. The file is a regular file of at most 16 MiB, valid UTF-8 and strict JSON, read with the project's
   `persistence.strict_json`: duplicate keys (NFC-folded), `NaN`, `Infinity`, numbers that overflow, more than 128
   nesting levels, unpaired surrogates and data after the document are refused. `PT-CORR-JSON`.
2. The document validates against the contract model. `PT-CORR-CONTRACT`.
3. Pair identity: both SHA-256 values equal the target project's. If they are equal the other way round the
   refusal says so (`PT-CORR-ORIENTATION`); a correction is never mirrored silently. Any other difference is
   `PT-CORR-PAIR`.
4. Every member resolves: it has an address the parser accepts and exactly one function on that side of the target
   project has that address. A member without an address, with no function or with several is `PT-CORR-MEMBER`
   and refuses the whole document. This is the import side of the rule the unified engine applies when it reads
   corrections (`manual/5`, PR #188: a correction with an unresolved member is dropped as a whole); refusing here
   means an import never stores a correction that the engine would then discard for an address it cannot read.
   A different name at the same address is not a refusal: it is reported as a warning (the first 20, then a count).
5. No function is named twice in the corrections of one document. `PT-CORR-DUPLICATE`.
6. Per correction, in document order, against the state the earlier corrections of the document produce:
   - already present: the project has a `manual` relation with the same older set, the same newer set, the same
     category and the same note. Counted, nothing to do.
   - conflict: one of the members is part of a different `manual` relation. `PT-CORR-CONFLICT`; an import never
     overwrites an analyst's existing correction. Undo or re-correct it first.
   - otherwise the correction is applied with `ProjectService.correct_match`. The relation it replaces is the one
     that holds the first older member (the first newer member when the older list is empty). A refusal by the
     service (for example `split` without exactly one older function) is `PT-CORR-INVALID` with the service's text.
7. Review state, when the document has it, after the corrections: a relation is found by its exact older and newer
   member sets, a finding by its stored ID and complete evidence/context digest. No match
   is `PT-CORR-REVIEW`. A state that already equals the document's is counted as already present; other states are
   set with `review_match` and `review_finding`. States the document does not name are left alone.

Guarantee (all or nothing). The service has no batch operation and commits once per call, so rule 6 and 7 run
against an in-memory candidate: a second `ProjectService` over a copy of the project whose store validates exactly
as `ProjectStore.save` does (`persistence.validate_project`) and writes nothing. Only when the whole document went
through is the result committed, once, with `ProjectService.save()`: one `ProjectStore.save`, one SQLite
transaction. Validation and cancellation before commit leave the previous snapshot intact. A failure after the transaction committed may leave the complete new snapshot present; the open service reloads persisted state rather than falsely claiming rollback. A document invalid at any entry applies none. Planning is bounded by the source-size and aggregate copy-work limits below. Cancellation is checked during review/correction loops and immediately before commit.


Idempotent. Importing the same document again finds every correction and review state already present, writes
nothing (the project revision and the database bytes do not change) and exits 0.

`--dry-run` runs every rule, reports the same counts with `written: false` and writes nothing.

What "writes nothing" and "leaves the project unchanged" mean. Every leaf opens a `ProjectStore` and loads with `recover_interrupted=False`, with no legacy raw cleanup or interrupted-run repair. Read-only leaves, dry runs and refusals change no project file except the advisory lock file, which records the current process. The desktop's recovery policy is unchanged.

What an import reproduces, and what it does not. It reproduces the manual relations: members, category, note, and
with `review` the review states. Exporting the target afterwards gives the same bytes as the imported document when
both projects store the same function identifiers (a copy or a restored backup), and corrections apart from
the `id` reader fields when the target was created independently from the same two files. Finding reviews require a copy with unchanged finding identity and evidence. It does not reproduce
history: a relation that the source project dissolved on the way and did not end up correcting stays as the target
has it, identifiers of the corrected relations are the target's, and after an import of several corrections only
the last one can be undone (section 2).

Untrusted text. Notes, names, summaries and conclusions are data: bounded as in section 3, stored unchanged through
the service (never formatted, interpreted or executed), written to the export as ASCII JSON, and printed in text
output through `hostile_text.escape_text` per field, so a control, bidirectional or line-break character can
neither restyle a terminal nor forge a table row.

## 5. `patchtrace corrections`

| Leaf | Does | Writes |
|---|---|---|
| `corrections list PROJECT [--json]` | the manual relations: category, review state, members, note, and for the latest one the annotation that can be undone | nothing |
| `corrections export PROJECT --out FILE [--include-review] [--json]` | writes the document | `FILE` only |
| `corrections import PROJECT FILE [--dry-run] [--json]` | applies a document under the rules of section 4 | the project, one commit |
| `corrections undo PROJECT [--annotation ID] [--json]` | `restore_match_override`: puts back the relations the correction replaced; default is the latest active correction, as the desktop does | the project |

Export writes atomically: a temporary file in the destination directory, flushed and synced, then an exclusive hard link. An
existing destination with the same bytes is left alone (`written: false`); an existing destination with different
bytes is refused (`PT-CORR-EXISTS`, exit 2) ; a destination that is a directory, or that lies inside
the project directory, is refused (`PT-CORR-OUTPUT`, exit 2). A write failure is exit 3 and leaves a previous file
unchanged. A correction with a member that has no usable address is exported as stored and named in a warning,
because no import will accept it.

JSON results (the `result` of the `enrichment-cli/1` envelope):

- `list`: `pair`, `corrections[]` (`index`, `match_id`, `category`, `review`, `note`, `older`, `newer`,
  `annotation_id`, `undoable`), `superseded_records` (stale `match-override` annotations).
- `export`: `contract`, `path`, `bytes`, `sha256`, `corrections`, `review` (`matches`, `findings` counts, or null),
  `written`.
- `import`: `contract`, `dry_run`, `written`, `corrections` and `review.matches`, `review.findings` (each
  `total`, `new`, `already_present`; `review` null when the document has none), `changes[]` (`index`, `action`
  `apply` or `already-present`, `category`, `older`, `newer` names), `revision` (`before`, `after`).
- `undo`: `annotation_id`, `match_id`, `restored_relations`, `revision`.

Exit codes: 0 done (also: nothing to import because everything is present); 2 invalid arguments, a project that
cannot be opened, every refusal of section 4, `PT-CORR-EXISTS`, `PT-CORR-OUTPUT`, a correction the
service will not restore; 3 storage, lock or write failure; 4 nothing to report (`list` with no manual correction, `undo`
with no active correction); 5 cancelled.

## 6. `patchtrace review`

| Leaf | Wraps | Changes |
|---|---|---|
| `review match PROJECT --match ID --status STATUS [--json]` | `review_match` | the review state of that relation |
| `review finding PROJECT --finding ID --status STATUS [--conclusion TEXT] [--json]` | `review_finding` | the review state of that finding and, when `--conclusion` is given, its analyst conclusion |
| `review note PROJECT --target ID --text TEXT [--kind KIND] [--json]` | `annotate` | appends one annotation |

`STATUS` choices are read from `FunctionMatch.review` and `Finding.review`; `KIND` choices from
`AnalystAnnotation.kind` without the two kinds the service writes itself (`match-override`, `validation`); the
default is `note`. Without `--conclusion` the stored conclusion is kept (the service call would otherwise erase it);
`--conclusion ""` clears it. `--text` must not be blank and both texts are bounded at 32 767 characters. The target
of a note must be an identifier the project owns (the store's rule). None of the three marks anything stale or
changes the project revision.

JSON results: `match`: `match_id`, `status`, `previous`; `finding`: `finding_id`, `status`, `previous`,
`conclusion`; `note`: `annotation_id`, `target_id`, `kind`. Exit codes: 0 done; 2 invalid arguments, unknown
identifier, a project that cannot be opened; 3 storage failure or locked project; 5 cancelled.

## 7. Service gaps recorded by this slice (not changed here)

- No batch apply: `ProjectService` commits once per call. The all-or-nothing guarantee is built in
  `corrections_exchange.py` as described in section 4.
- `review_finding(finding_id, status)` without a conclusion erases the stored conclusion; the CLI passes the stored
  one back.
- Only the latest correction can be restored (every correction marks all earlier annotations stale).

## 8. Open

- Live use on a project analysed by a real engine is UNVERIFIED by this slice.
- No desktop control imports or exports a document yet.

## 2026-11-16 implementation amendments
Read-only operations, dry runs, and refusal paths open `ProjectStore` and call `load(recover_interrupted=False)`; they never repair interrupted runs or perform raw cleanup. Lock contention is exit 3, consistent with project/compare CLI. Exports are immutable create-only publications (synced temporary bytes, exclusive link); existing identical content is a no-op, different content is refused. The unshipped `--force` proposal is withdrawn.
Import plans bind the exact original project state by canonical SHA-256; intervening edits invalidate the plan before any write. Every review target appears at most once; duplicates are refused, including aliases resolving to the same target. Cancellation is checked during all apply loops and immediately before publication. Each import caps original serialized project size at 16MiB and estimated aggregate copy work (serialized bytes times total requested corrections/reviews, minimum 1) at 64MiB, with a typed refusal and no partial application. Exported documents are capped at 16MiB, identical to input size. These are deterministic operational limits, not performance claims.
Finding review exchange requires both exact stored finding ID and a digest of the complete original finding claim/evidence and provider context (excluding mutable review state and conclusion); unmatched identities are refused rather than guessing equivalence across independent analyses. Corrections continue to resolve member addresses only within the exact ordered binary pair.

Candidate saves also charge actual serialized candidate bytes against a cumulative 64MiB budget and refuse any candidate over 16MiB, including growth from correction history.

Export also refuses source snapshots over 16MiB before constructing exchange arrays. Canonical source and output encoding stop at their byte budgets; model serialization still visits the existing in-memory project.
