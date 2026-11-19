# Exact-source release qualification — 2026-11-18

## Outcome and scope

Implementation commit: **0bb63363ed675266ec4572a85ee0c0861aa714b7**.
Branch: codex/release-qualification-20261118.
Base: 9e5a5303da6e9a745e604979932f814de8eca4b0.
This is a follow-on to PR #307, separate from its published
58fc130631f602b6e907bb054d30c21d810551d4 snapshot.

The desktop and backend-bundle publishers now share a read-only qualification
guard. No release, tag, deployment, workflow dispatch, paid service or remote
mutation was performed. Existing raw receipts were preserved. Cadence keeps its
documented fail-open behavior; publication qualification is a separate,
mandatory fail-closed check.

## Confirmed defects and repair

| Confirmed source behavior | Repair |
| --- | --- |
| Desktop publication depended only on QA, Qt, Linux smoke and cadence. | Require exact-source, current-attempt QA/package/Qt/native/unified/import/parser and explicit dependency/security categories. |
| Bundle publication checked build/acceptance results but no global qualification or peeled tag identity. | Require the shared guard plus selected platforms' current bundle prerequisites; peel existing tags to TARGET_SHA. |
| A push-event message condition did not establish the hold on manual/tag/bundle paths. | Read actual checked-out commit metadata and independent API commit metadata. Literal [no release] blocks both publisher profiles. |
| BinDiff success badges can coexist with blocked acceptance. | Check named critical steps plus the owned unmocked status artifact and every required native subcheck. |
| Failed bundle release lookup was treated as absence; upload replaced assets. | Absence needs successful bounded REST enumeration. Refuse asset collisions and remove --clobber. |
| Desktop action defaults allow asset replacement. | Set overwrite_files:false on the already-pinned action, plus unmatched-file failure. |

Only canonical push, workflow_dispatch and schedule runs from the same
repository and exact source commit can supply qualification. A PR run's API
head_sha does not establish that checkout executed canonical release bytes.
The guard selects the latest eligible run, verifies its latest attempt and
actual critical steps, and rechecks run/attempt selection. It never falls back
to an older successful run.

The current publisher may remain in progress while its prerequisite jobs
have completed; other qualifying workflows must be complete and successful.
The publisher must belong to the current run and attempt. Reusable calls whose
API run identity belongs to another workflow cannot stand in for the explicitly
named bundle workflow.

The checkout must have the requested full commit SHA and no tracked changes.
Ownership checks include repository IDs, source SHA, run ID and attempt.
BinDiff artifacts need unique platform names, unexpired metadata, and creation
within the selected job attempt. Only bounded bindiff.json bytes are read from
the ZIP; nothing is extracted or executed. Invalid JSON, pagination, tags,
identities, output persistence or changed evidence block publication.

## Verification

The final affected suite passed **450 tests**, with **3 pre-existing expected
failures**, and no ordinary skips. These are authored metadata, filesystem/git
fixtures and workflow-contract checks. They do not qualify real backends,
Windows packaging, dependency safety or a hosted release.

The unchanged expected failures are test_remote_actions_are_immutable (CODEX-1),
test_pip_downloads_require_hashes (CODEX-5), and
test_corpus_cache_does_not_skip_verification (CODEX-6).

Command, with worktree source explicitly supplied to subprocesses:

~~~bash
PYTHONPATH=/workspace/scratch/c7a9e8d98848/release-qualification/src \
QT_QPA_PLATFORM=offscreen \
/workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_release_qualification.py tests/test_backend_bundle_workflow.py \
  tests/test_release_gate.py tests/test_workflows.py \
  tests/test_workflow_contract_dependencies.py tests/test_codex_pkg_workflows.py \
  tests/test_milestone_notes.py tests/test_verify_release.py
~~~

The normal command **python -m ruff check src tests tools** passes.
The staged diff whitespace check passed before implementation commit.
The exact-source rerun records the commit, interpreter, environment, command,
source hashes and exit status in qualification-command.json.

Three initial workflow regressions failed before the repair. Seven metadata
controls were recorded red before correction; two output-receipt and asset
ambiguity controls were also recorded red before correction. Cases cover
missing/skipped/failed/queued/neutral jobs, critical-step failures, changed
attempts, foreign repositories, PR previews, malformed identities, blocked or
mocked native data, ZIP/JSON/pagination bounds, tag cycles/mismatches, release
collisions, local source drift and commit holds.

An actual invocation of the committed guard exited 1 with
"actual checked-out commit contains [no release]", before API or asset reads.
Its supplied hosted run ID is invocation context, not a claim that this local
commit ran on that job. A separate symbolic HEAD input was also refused;
that raw receipt is retained.

## Exact-head remote snapshot

Read-only REST snapshot at approximately **2026-11-18 14:55 UTC**:

- Main remained 9c411ca3d7b47f950be5f0c6f01b3c54184554c6.
- PR #307 head was 58fc130631f602b6e907bb054d30c21d810551d4.
- Four visible runs were queued: QA PR preview 44327507311, Rizin PR preview
  44327507095, Ghidriff PR preview 44327506922, and canonical Ghidriff push
  44327484648.
- None of those observations qualifies this implementation commit.
- Earlier d8c02caea407f6d323eecd636735849c1eb31a2d and original-PR metadata
  remain historical receipts; no result is carried forward as a current pass.

The connector could read repository, branch, PR, exact-head run and job
metadata. Its URL policy rejected workflow enumeration and Dependabot/
code-scanning endpoints with 400 INVALID_ARGUMENT. This is an interface limit,
not proof that repository security services are disabled. Local gh has no
token: production REST transport was tested hermetically, with no hosted
end-to-end qualification pass.

## Remaining publication blockers

There is no dependency/security workflow in this source tree. The policy
reserves dependency-security.yml jobs dependency-audit and security-scan, but
creates or qualifies neither. Publication therefore remains blocked until a
separately reviewed scanner policy and exact-source execution exist. A job name
alone is not a scanner qualification.

Windows BinDiff's current no_network check explicitly returns blocked because
the implementation uses Linux network namespaces. A real Windows disconnected
control with a positive control is still needed. Green advisory status cannot
replace that evidence. Native synthetic fixtures do not establish real-driver
or CVE accuracy.

Required workflows include path-filtered and manual/scheduled lanes. Missing
exact-source runs need their existing authorized triggers on the chosen
canonical source; the guard never dispatches or polls indefinitely. BinDiff,
optional imports and parser fuzzing are not guaranteed every-main-push gates.
Their absence now holds publication without changing their triggers.

Tag/release checks are point-in-time and cannot lock a GitHub ref against a
later authorized concurrent mutation. Upload still refuses asset replacement.
Qualification also does not establish that publication subsequently completed.

The full combined application suite and native Windows package gates remain
required on the final integrated SHA. This local repair supplies no new native
qualification credit. Pages deployment is separate and was not invoked or
changed.

## Minimal scan policy recommendation

No scanner lane is added in this repair.

1. Use a reviewed, pinned **PyPA pip-audit** release. Inventory dependencies
   actually shipped on each supported platform, preserving the resolved
   inventory and scanner JSON with exact source/build identity. Use strict
   collection behavior; collection/advisory-service errors must block.
   Preserve scanner exits and do not auto-fix dependencies as a publication
   side effect.
2. Preserve an independent static-security result. Ruff's S family is an
   available starting detector, not proof that every security property was
   assessed. Review findings against their actual input boundaries, repair
   confirmed defects, and record reasoned dispositions. Do not suppress a
   finding merely to make the job successful.
3. Review that small scan contract separately, then connect its actual
   critical outcomes and evidence to the reserved policy. Until then, missing
   scan results remain explicit blockers.

The local pre-repair command **python -m ruff check src --select S
--output-format json** exited 1 with **78 untriaged findings**:
S608=33, S105=14, S110=13, S101=9, S310=6, S603=1, S314=1, S108=1.
These are detector findings, not 78 confirmed vulnerabilities. Its original
JSON is unchanged in the evidence bundle. A pass under normal configured Ruff
rules is a different result and is not a clean security scan. pip_audit, Bandit
and Safety were absent from the inspected interpreter; no dependency audit
pass was performed or fabricated.

Primary sources consulted on 2026-11-18:

- [PyPA pip-audit](https://github.com/pypa/pip-audit): dependency auditing and
  --strict collection-failure behavior.
- [Astral Ruff rules](https://docs.astral.sh/ruff/rules/): flake8-bandit security
  rule family.
- [GitHub workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs):
  attempt-scoped jobs and Actions read permission.
- [GitHub tag objects](https://docs.github.com/en/rest/git/tags): annotated tag
  objects versus refs.
- [Pinned action metadata](https://github.com/softprops/action-gh-release/blob/3bb12739c298aeb8a4eeaf626c5b8d85266b0e65/action.yml):
  overwrite_files and fail_on_unmatched_files support.

## Preserved receipts

The evidence ZIP contains original red/green logs and JUnit, raw connector
observations, the original Ruff security JSON, and local refusal receipts.
The manifest records every member's SHA-256, size and source identity.
No prior frozen qualification directory was modified.
