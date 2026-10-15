# LBL-DATA integration plan: training data path, corpus-growth admission, train.py hardening, pre-lock checklist

Status: proposed, 2026-10-15. Author: handoff worker (documents only). Base: `origin/claude/instance-d-gui` `b853996`; LBL-15 at `origin/claude/instance-c-research` `785998a` (PR #66). Extends `docs/specs/program-e/LBL-integration-plan.md` (cited as LBL s<N>), `docs/plans/lbl-remaining-plan.md` and `docs/plans/c9-preregistration-v1.md` (PREREG s<N>, draft, not locked). Slice ids LBL-30..LBL-34 are new and do not exist in LBL s9. Narrative handoff with commands: `docs/handoff/label-training.md` (cited as HO T-<n>). `[inf]` = inference, not measured.

## 1. Verdict and scope
The Tier R pipeline has all its parts but two seams were never built, and both decide whether the final result is real:
1. **No producer for the training inputs.** `train.py` (PR #66) reads `tier-r-engine-output/1` files (with `known-answer-labels/1`) or `tier-r-feature-rows/1` documents. In the tree, `tier_r/evaluate.py:engine_output_doc` builds the engine-output dict but only its SHA-256 is kept; `shard.py` carries neither (its `sanitize()` rejects lists over 5,000 items and drops table keys, while feature rows run to 200,000 per pair). The pipeline has only run on hand-made synthetic worlds in tests.
2. **`train.py` does not yet implement the LBL-26 "for C" items** (`docs/audits/20261015-lbl26-pre-lock-audit.md` C-1..C-8) and hard-codes `'natural'` for every non-control pair, which conflicts with LBL s7.3 and LBL26-01 for the `authored` stratum.
Also open: corpus size (16 recipe lineages; 41 including 25 authored suite directories), the licence register mismatches (LBL-05 audit), and the lock mechanics (P-1 exists; nothing single-uses the final run).
Out of scope: Tier W code (LBL-20..25, unchanged), GUI (LBL-18), reports and status CLI (LBL-19), the unified adapter (LBL-12). No new persisted contract changes except the additive ones named below.

## 2. Training data path (LBL-31)
- **Files and contracts.** Per pair and engine one file `outputs/<pair_id>.<engine>.json` holding exactly `evaluate.engine_output_doc(out, labels, symbols)` serialised with `common.canonical_json` (contract `tier-r-engine-output/1`, `report_schemas.EngineOutputDoc`). Its SHA-256 (`RS.output_sha256`) must equal the `sha` the evaluator already records per pair in `tier-r-report/1`. Per pair one label document `labels/<pair_id>.json` (`known-answer-labels/1`, open-source function tables only; no image, no byte content). Caps: label doc 64 MiB and 200,000 functions (LBL s7.7), output doc 64 MiB; a run that exceeds a cap records the pair as `failed`, never truncates.
- **Producer.** `tier_r evaluate` gains one option naming the output directory (name chosen in the PR; do not reuse `--out`, which is the report path). `shard.run_shard` collects the files from the shard scratch store into `shard-out/outputs/` and `shard-out/labels/` beside `shard-<i>.json`. `merge` verifies every output file against the aggregate's per-pair SHA and every label file against `labels_digest`; a mismatch fails the merge (exit 1). The shard JSON itself stays aggregate-only.
- **Artifacts.** Workflow uploads `tier-r-outputs-<shard>` (the two directories). Keep the workflow header rule (no images or binaries) and `shard.refuse_microsoft`; add a test that every uploaded file is `.json` and below the cap.
- **Consumer.** `train run --labels <dir> --outputs <dir>` (existing). A new dispatch input `train` (boolean, default false) adds a job after `merge` that downloads the artifacts and runs `train run --smoke` on the result; never on `pull_request` or `schedule`.
- **Acceptance.** Smoke dispatch (`subset=smoke`, `engines=rz-diff`) yields `train-out/report.json` that `train report` verifies; G1 reads `insufficient-data` (far fewer than 30 lineages), G0/G2/G3 `insufficient-data`; second merge gives the same `report_sha256`.
- **Tests (first).** `test_evaluate_writes_engine_outputs_matching_report_sha`, `test_shard_carries_outputs_and_merge_checks_their_sha`, `test_merge_rejects_output_file_with_wrong_sha`, `test_train_reads_outputs_written_by_evaluate`, `test_outputs_artifact_contains_only_capped_json`.
- **Planner (LBL-32).** `case_steps` maps `aa:` and `noise:` ids to `--suite corpus/ours/<name>` and `mutate:` to `--suite`, so recipe lineages get no A/A or noise cases (the CLI `aa` and `noise` accept `--card` and `--side`). Add case ids `aa-card:<card id>:<old|new>` and `noise-card:<card id>:<old|new>`; keep the `_CASE` character classes; test that `refuse_microsoft` still gates them. Recipe-source mutation needs `mutations/engine.py` to accept a recipe base (`factory.BaseSource`); specify that in its own section before building it.

## 3. train.py hardening (LBL-30)
Implement in `tools/calibration/train.py`, each with a red test first (HO T-03 lists names):
- C-1 call `guards.audit_identity_roles(cands, roles, hubs=grouping.hub_identities)` after `identity_groups(..., hub_max_lineages=3)`; non-empty result stops the run, `PT-KA-LEAK`, exit 1. If it fires, roles are assigned per identity group; a group is never split (PREREG 2.4).
- C-2 per-stratum indeterminate share; above 0.05 add a worst-case block (indeterminate read as y = 0) next to the point result (PREREG s3, 6.1).
- C-3 only `natural` rows calibrate, choose tau and form the headline. **Decision D-A** (HO s4): `authored` pairs are adversarial (recommended), shown in their own table. Consequence stated in the report: natural lineages are the recipe lineages.
- C-5 label the G1 precision and interval "dev-selected" in the report (tau chosen on the rows it is then reported on). Nested selection (tau inside outer folds, held-out precision) is a follow-up, opus only after a failed sonnet attempt.
- C-6 halt (report still written, gates `insufficient-data`) for fewer than 30 evaluated lineages, fewer than 12 in a requested locked role, any `audit_manifest` violation.
- C-8 count resamples with an undefined statistic; refuse a headline interval above 5% undefined [proposal; record in the lock commit].
- Preregistration file handling: use `prereg.prereg_sha256` (refuses CR), require equality with the `C9-PREREG-v1` row of `docs/qa.md` unless an explicit "unlocked" option marks the report; replace the plain `hashlib.sha256` in `_prereg_sha`.
- Single use: an explicit option wraps the final run in `run_locked_test(corpus_dir, prereg_sha, evaluate)`. R5 and rehearsals use a throwaway SHA.
- Contract changes: none persisted. New report fields (worst-case block, dev-selected label, undefined share) are additive to `calibration-report/1`; regenerate `docs/schemas/calibration/*` and keep `report_sha256` canonical.

## 4. Corpus-growth admission (LBL-33)
Rules (a candidate that fails any rule is not admitted; there is no "partial"):
1. Language C only (the source locator `csrc.py` is C only). C++ candidates from `origin/chatgpt/corpus-1` (jsoncpp, pugixml, snappy, tinyxml2) stay blocked.
2. Pins are 40-hex commits resolved by `git ls-remote --tags` (peeled), at least 4 consecutive stable tags of one build layout; tagless projects use ancestor commits. Candidate files from `chatgpt/corpus-1` have `source_pin.commit = null` and Git blob ids that are not licence SHA-256 values; they are leads.
3. Licence permissive per `PERMISSIVE_SPDX`, read at each pin, SHA-256 recorded, election noted for dual licences. Licence register row added in the same PR (`docs/plans/calibration-licences.md`).
4. `tier-r-recipe/1` strict, explicit source lists, authored `write` rules for generated headers, no upstream configure, no submodules; dependencies by pin (`depends`).
5. Both layouts updated (`recipes.d` and `recipes.json`; `releases.d` and `releases.json`; CVE cards also in `cves.json`).
6. Build proof: `fetch` and `build-card` for three adjacent pairs, 0 unexplained `disagree`, `aa` byte-identical, recorded in `docs/qa.md`. The tranche test lists the project.
7. CVE cards only with a real CVE id and a fix commit that is one of the pins; never manufactured.
8. Lineage role is computed for information only; recipes are never chosen or dropped because of their role.
Target arithmetic (stated in the lock commit): headline needs at least 30 natural lineages (`MIN_GROUPS_HEADLINE`); a locked-form G1 needs 12 in the locked role (about 48 total at 25%, hash-assigned, today 11 of 41). Reachable pool: 16 existing + 20 C candidates + reserve (libsodium, libssh2, minizip, libuv, libwebp, libarchive; unverified) + plan leads (mpack, tlsf, minIni, libbase64, libb64; unverified). If the pool cannot reach the target the result is `insufficient-data`, stated plainly.

## 5. Pre-lock checklist (LBL-34; PREREG 8.1 made executable)
Owner decisions first (HO s4). Then, in order: LBL-30 and LBL-31 merged; R1 recorded; growth tranches built; vendoring scan applied (`tier_r vendoring --threshold 0.15 --hub-max-lineages 3`); shift declaration in the manifest (`split.shift_test_lineages`; today `manifest.SPLIT` is empty); manifest `verify` and `guard` pass; sample list hashed; `g1` final; preregistration bytes final (Q1-Q5 decided); `.gitattributes` line for the prereg path; lock commit C; `git show C:docs/plans/c9-preregistration-v1.md | sha256sum` equals `python -m tools.calibration.prereg`; `docs/qa.md` row `C9-PREREG-v1` with SHA, C, date, O3 sign-off; `python -m tools.calibration.prereg --qa docs/qa.md` prints MATCH; add the missing test for PREREG 8.5 iii (`test_shift_declaration_matches_manifest`); REGISTRY row.

## 6. Slice plan
| ID | scope and exclusive files | deps | tier | size | acceptance gate | fallback |
|---|---|---|---|---|---|---|
| LBL-30 | `train.py` items in s3, `tests/test_train_lbl26.py` | PR #66 merged | sonnet (opus for nested tau only after a failed sonnet try) | M | every C-n line closed or deferred in writing; tests in s3 green | label G1 dev-selected only |
| LBL-31 | `tier_r/{evaluate,cli,shard}.py`, workflow, tests in s2 | LBL-30 not required; PR #66 for the consumer | sonnet | M-L | s2 acceptance | rows through `--rows` built offline |
| LBL-32 | `tier_r/shard.py` card A/A and noise ids; later `mutations/engine.py` recipe base | LBL-31 (same file, sequential) | sonnet | M | A/A byte-identical for every recipe on a runner | suites only |
| LBL-33 | one PR per recipe: recipe, cards, register row, tranche test, qa.md row | R1; licence fixes | haiku (plain lists) or sonnet (write rules, deps) | S-M each | s4 rule 6 | drop the project |
| LBL-34 | lock commit, qa.md row, `test_shift_declaration_matches_manifest`, manifest shift option | LBL-30, 31, 33, owner | sonnet | S-M | `prereg --qa` MATCH | stay unlocked, report as rehearsal |

## 7. Tests, QA, amendments
- Focused tests per slice as listed; run `PYTHONPATH=src python -m pytest -q -p no:cacheprovider <files>` and `python -m ruff check tools/calibration tests`. Full suite once at the end (`QA and Windows standalone`, job `qa`).
- Runner evidence only from `corpus-tier-r` dispatches (inputs `shards`, `seed`, `engines`, `subset`; a `train` input is added by LBL-31). Record each run in `docs/qa.md` with run id and measured minutes.
- Amend after merge: `docs/specs/calibration-corpus-and-model.md` s20 (outputs/labels artifacts, dev-selected label, worst-case block), `docs/modules.md`, `tasks/todo.md`, `docs/qa.md`, `docs/specs/known-answer-corpus.md` (planner case ids).

## 8. Open questions (defaults apply)
1. Do authored suites count as natural rows? Default: no (adversarial table).
2. Upload `labels/` documents as artifacts (open-source function tables) or rebuild them in the training job from the same pins? Default: upload; the data are not binaries and contain no Microsoft material. Owner may veto.
3. Undefined-resample refusal threshold 5% (proposal). Default: 5%, frozen in the lock commit.
4. Is the nested-tau redesign (C-5) required before the lock? Default: no; label the number dev-selected, because Learn-then-Test already controls the family error and the lock must not wait on a statistics rewrite.
