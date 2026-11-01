# Corpus safeguard reconciliation — November 1, 2026

Scope: read-only comparison of preserved #78/#79/#82/#85 with coordinator source
`241f445bf3e2e1bc4083aac47ac074b3fd3b795b`, followed by one narrow preregistration
claim repair. This is not full GT-05, corpus growth, native accuracy, pre-lock,
single-use final evaluation, or numeric-confidence acceptance. Original author
refs remain intact and their unpublished activity is unknown.

## Preserved work and actual gaps

| Source | Unique work compared with the candidate | Disposition / next executable action |
|---|---|---|
| #78 `2019a37fa65fc37f4758469143c2daadc07e0098` | `tier_r/output_store.py` and `training_artifacts.py` are absent. Current `evaluate_full` computes each normalized output digest but returns only report/deltas; CLI writes the report, not the corresponding normalized training documents. | READY: review and selectively adopt output persistence, verified shard transfer and report retention, with native mutation-boundary acceptance separate. Do not copy its older unified/read-model or mutation source blindly. |
| #79 `9513bc05229dd7a8460fc229d7420154d61498db` and #82 `eaa30013794a9bd0fedc9ec34bbe374d6db0cfc9` | Current planner has `card`, suite A/A/noise and mutation IDs but no `aa-card` or `noise-card`. Actual enumeration: `cards` 83 cases/83 ordinary cards, `noise` 25 suite cases, `full` 908 cases/83 ordinary cards; all have zero recipe A/A/noise IDs. CLI/factory already support card-side base selection. | READY after the overlapping #78 shard integration: reconcile the two competing implementations once, preserve fetch-before-build, both old/new pins and Microsoft refusal. Synthetic planner execution is not native A/A identity evidence. |
| #85 `6ae2c079e6cafa2b7bd5396cac443cd34ba7138a` | Current CLI hashes arbitrary supplied bytes after input loading and sets `preregistered=True`, without QA comparison. Its separate final wrapper is also absent. | Narrow recorded-identity/rehearsal repair READY_FOR_REVIEW in this slice. Declared-final wrapper and lock lifecycle remain READY. Do not import the old whole `train.py`: it predates the current natural-only grouping/hub repair. |

The #85 final wrapper's sign-off test uses approval substrings. As a source-level
review concern, negated prose containing those same substrings can satisfy that
check; this slice neither imports that approval interpretation nor asserts it is
adequate. Final-run integration needs independently reviewed, unambiguous record
semantics, receipt-before-input access, crash/error retention and repeated-call
controls. No final evaluation or real lock was opened or created here.

## Requirement-to-current-behavior map

| Safeguard and source | Current implementation/evidence | Remaining acceptance |
|---|---|---|
| Recipe/source/license identity, SPEC-32 sections 2–3 | `tier_r/fetch.py` restricts HTTPS hosts, verifies commit identity, records license SHA, bounds checkout counts/bytes and uses explicit build recipes. | READY: audit every growth recipe/pin/license register against permitted source bytes. Cache receipts are trusted on reuse; fresh source-byte and provenance/collision behavior require separate adversarial verification. No new license/source claim is made from this inspection. |
| Output persistence and verified transfer, LBL-31/#78 | Missing normalized output store/transfer modules; report contains output SHA without corresponding persisted training document. | READY: selective adoption and actual evaluate → retained output → shard/merge → training chain. |
| Both-side recipe A/A/noise, SPEC-32 section 9/#79/#82 | Suite controls and card-aware factory/CLI exist; recipe controls absent from the planner. | READY: add both-side IDs after shard reconciliation, then real runner case denominators and unchanged-byte outcomes. |
| Pin/build provenance collisions | `manifest.build_manifest` rejects one content hash owned by two lineages; regression passes. Within a project it uses content-keyed `setdefault` for source/build metadata. | READY: establish intended handling of same-byte, distinct pin/recipe provenance and add a regression before any behavior change. Differing metadata is not itself proof of a defect. |
| Lineage/leakage, SPEC-28 section 4 | Manifest cross-role project/PDB/image checks, control-parent lineage checks, identity-role audit, natural-only grouping and separate broad evidence audit exist. Bounded synthetic regression suite passes. | Pre-lock corpus audit and real lineage/vendoring evidence remain READY. Do not split a lineage to improve balance or let excluded authored candidates change natural groups. |
| Preregistration claim, SPEC-28 section 2/LBL-30 | Reproduced false claim and input access before validation; narrow CLI repair below passes. | READY_FOR_REVIEW: independent review, integration and cross-OS checks. QA digest identity alone does not establish pre-lock approval. |
| Single-use final look, SPEC-28 section 2.1 | `run_locked_test` library exclusively creates a SHA-keyed receipt before its callback. The CLI still does not route declared final evaluation through it. | READY: finish reviewed final CLI integration and receipt failure semantics; do not consume a real locked evaluation merely to test it. |
| OOD/shift, SPEC-28 sections 9–10 | Held-out groups leave training, sample floors yield insufficient data, unvalidated Mahalanobis falls back; bounded shift/hardening regressions pass. | Actual predeclared OOD/shift data and stable labels remain outstanding; synthetic tests do not establish population coverage. |
| Guarded promotion, SPEC-28 section 12 | Artifact remains experimental; synthetic/Tier-R claims cannot promote; numeric gates are recomputed from report numbers; forged gates fail in tests. | Numeric promotion remains unavailable. Non-statistical approval/build conditions are not attested by these synthetic checks; no approval or probability claim is produced. |

## Narrow implementation and verification

`prereg_gate.select` validates exact LF protocol bytes against one complete
`C9-PREREG-v1` QA table row containing one lowercase SHA-256. It rejects missing,
ambiguous, malformed, mismatched and invalid-encoding QA records before either
`run` or `shift` opens corpus inputs. Prose examples and substring identifiers do
not count as rows. `--unlocked-prereg` explicitly keeps the report and train key
unlocked while recording the inspected source SHA in the command summary. A
verified protocol cannot label a reduced `--smoke` run as preregistered.

Existing no-protocol behavior, library caller-supplied SHA semantics, natural
grouping, numeric thresholds, frozen protocol bytes and all persisted schemas
remain unchanged. No schema regeneration is needed for these CLI options and a
private Python selection value. No final-look acceptance is inferred.

- Original candidate with the initial 19 regressions: **18 failed, 1 passed** in
  1.83 s. Failures include actual report falsely carrying a draft SHA and access
  to corpus inputs before QA validation. The reproduction injects parsed request
  attributes so it tests old behavior, not rejection of newly added CLI flags.
- Initial repaired subset: **19 passed** in 0.70 s. Three real parser/CLI cases
  were then added, including the explicit rehearsal path with a real constructed
  report and byte-identical unlocked report/key comparison.
- Bounded integration command:

  ```bash
  clear
  QT_QPA_PLATFORM=offscreen python -m pytest -q \
    tests/test_train_prereg_selection.py tests/test_train_pipeline.py \
    tests/test_train_lbl26.py tests/test_train_deferred.py tests/test_train_shift.py \
    tests/test_calibration_hardening.py tests/test_prereg_tools.py \
    tests/test_prereg_constants.py tests/test_tier_r_eval_corpus.py \
    tests/test_calibration_scope.py
  ```

  **255 passed, 1 skipped** in 68.85 s. The skip is explicitly reported as LIVE
  ACCEPTANCE BLOCKED: required clang/lld-link/LLVM inventory tools are not on this
  host's PATH. No native compile or actual engine accuracy is credited.
- `python -m ruff check src tests tools`: **passed** across the repository.
- Environment: own copied interpreter at
  `/workspace/scratch/142cb233d750/venv-corpus/bin/python`, editable installed from
  `/workspace/scratch/142cb233d750/wt-corpus`. An initial attempt before installing
  dev dependencies found pytest absent; no test result was credited to it.

Raw red/green/integration logs and planner evidence have their hashes recorded
in `corpus-safeguards-20261101.json`. Full serial Linux/Windows integration and
independent review are coordinator gates; this worker did not run them or mutate
GitHub, shared ledger, schemas, workflows, receipt-publication helpers or pilot
tools.

### Independent-review follow-up

Reviewer `cancel_fix` reproduced acceptance of a pipe row appearing only inside a fenced Markdown example or HTML comment at `46e1bd2`. Additional negatives also showed indented examples accepted, and an example row could make a real record appear ambiguous. Review regressions: **8 failed, 1 passed, 22 deselected** before repair. The scanner now excludes fenced blocks (including longer fences and non-closing spaced markers), HTML comments and space/tab-indented code. Literal comment syntax inside a fence cannot hide a later visible record. Final preregistration selection/tools/frozen-constants subset: **74 passed** in 0.88 s; full Ruff passes. The earlier 255-pass integration run remains a pre-follow-up record, not silently relabeled as a final-source full run. Independent final review remains pending at commit time.

### Final format-boundary review follow-up

Reviewer `cancel_fix` found remaining false-record contexts at `32603f0`: raw HTML blocks (`pre`, `script`, `style`, including hidden/custom blocks) and a list-nested fence. The bounded record contract now requires column-zero records and conservatively refuses raw HTML outside recognized code/comments or multiline/unclosed inline-code spans. Raw HTML is rejected even when a later valid-looking record exists; this is controlled format refusal, not HTML rendering. Same-line code spans still allow literal path placeholders/HTML, and the actual current `docs/qa.md` prose plus a temporary synthetic record is a passing compatibility control. Multiline/unclosed HTML openers are also rejected.

The new review subset reproduced **15 failed, 11 passed, 25 deselected** at `32603f0`. Final selection/tools/frozen-constants suite: **99 passed** in 1.02 s; full Ruff passes. No heavy run was repeated while the coordinator full-suite slot was reserved. Independent final review is still pending at this commit; earlier results remain preserved with their own source scopes.

### Independent review complete

Reviewer `cancel_fix` cleared production commit `42a3d5dee13ac4ff87436a66f787c6b3b5e093ad`, tree `943a4dccfbdbc3437d0c3598baa4e82374bb0a9b`, with **102 independent checks passed** in 1.40 s (selection/tools/constants plus three early-halt identity/natural-grouping regressions), scoped Ruff and diff hygiene clean. All original false-lock probes were replayed; canonical visible records and explicit unlocked rehearsal behaved correctly. Recorded source hashes matched; frozen protocol, lineage, guards and final-gate library were byte-identical to baseline, and the training pipeline AST was unchanged apart from a docstring. Both reported findings are closed within this narrow scope. This supersedes the pending-review statements above. The review was reported by the independent worker; no real final evaluation or full/native/cross-OS acceptance is inferred. Integration and remaining corpus requirements stay open.
