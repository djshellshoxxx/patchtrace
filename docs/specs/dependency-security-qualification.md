# Dependency and static-security qualification

Status: focused candidate, 2026-11-18. This defines real scan execution and
bounded evidence validation; it supplies no clean result or release approval.

## Required jobs and source identity

The dependency-security workflow runs on canonical main/codex pushes and tags,
PRs, and explicit manual runs. Publication still accepts only canonical events
under the shared release guard. Four required dependency jobs are named
dependency-audit (ubuntu-latest, runtime), dependency-audit (ubuntu-latest,
packaging), dependency-audit (windows-latest, runtime), and dependency-audit
(windows-latest, packaging). Each must complete the critical step "Audit installed
dependencies" successfully. The required static job remains security-scan with
critical step "Static security scan". No job or critical step may continue after
failure as if it had passed.

Each receipt binds repository, actual checked-out source SHA/tree, workflow
path, run ID, attempt, platform, Python interpreter/version, and inventory
profile. Local executions are explicitly local and cannot be counted as hosted
acceptance. PR merge-preview results cannot qualify canonical publication.
Preserve initial context and raw receipts on failures.

## Actual installed Python dependency closure

Create a fresh isolated environment per native OS/profile. Runtime installs
the source checkout with production plus search/rules extras. Packaging mirrors
the existing QA/package builder's dev/search/rules installation, including its
test/build tools. This is the actual installed environment for this scan build,
not a claim about a separate frozen executable's complete bill of materials.
Record the exact install command, pip installation report, interpreter identity,
pip check outcome, and full pip inspect JSON. An installation report is evidence
of that resolution; it is not treated as a lock file.

Require all installed distributions, including transitive/bootstrap packages,
to be uniquely represented. Only the one patchtrace distribution may be
classified repository-owned, after its name/version and editable direct origin
are proved to refer to this exact checkout and project metadata. Retain that
entry and proof; never send a same-named unrelated PyPI package as its substitute.
Any other editable/direct dependency, duplicate identity, missing project root,
missing production/selected-extra requirement, unreadable inventory, inconsistent
platform, or broken pip check blocks the audit.

Install build requirements into that observed environment before the editable
source install, with build isolation disabled for this scan build. Thus an
unobserved temporary build environment cannot stand in for the recorded closure.
All non-bootstrap installed distributions must be accounted for by those install
reports; the bootstrap pip identity must match that interpreter's ensurepip.
Currently selected requirements use plain names, exact versions or numeric
version bounds. Refuse an unsupported requirement/marker/version form instead of
guessing whether it is satisfied. Preserve that limitation if project metadata
later gains more expressive requirements.

Generate fully pinned audit requirements from all remaining installed
distributions. Audit that already-resolved closure using pinned pip-audit 2.10.1,
with strict collection, no dependency resolution, pip resolution disabled,
explicit PyPI vulnerability service, bounded request/process time, and JSON
output. No skip-editable, ignored vulnerability, dry run, auto-fix, dependency
upgrade, or successful fallback is allowed. Preserve the raw output even on
nonzero exit or parse failure.

Validation requires an exact name/version match between the full requested
inventory and scanner dependencies, no skips, no missing or duplicate entries,
an empty fixes list, valid bounded finite JSON, and exit zero. Nonzero exit,
network denial, inaccessible advisory data, missing report, collection error,
reported vulnerability, malformed evidence or incomplete coverage remains failed
or unverified, never clean.

## Static security detector

Use pinned Ruff 0.17.5 on application Python source under src with all stable S
rules, isolated configuration, no cache, and inline noqa suppression disabled.
The ignore-noqa switch disables suppression directives; no rule-ignore,
per-file-ignore, baseline acceptance, exit-zero, fix or automatic suppression
operation is permitted. Preserve all raw findings and the actual scanner exit.

A finding remains untriaged until substantive review. No detector finding is
automatically called a confirmed vulnerability. A nonzero scan remains failed;
an empty or fabricated report cannot override its exit status. A zero exit
also requires a present, valid, empty result array and exact scanner/source
context. The prior 78 findings are historical evidence and are not a baseline
allowance or an expected result imposed on new scans.

## Boundaries and artifacts

The receipt validator is stdlib-only. Size, nesting/number validity, collection
counts and process runtime are bounded. Preserve source identities, scanner
versions, full raw installed inventory, raw scanner JSON, command outcomes and
SHA-256 digests. Upload artifacts even when a scan fails; uploading a failed
receipt does not make a job successful. Missing required evidence is an error.

Python package advisories and Ruff rules do not audit external Ghidra/JDK/Rizin/
BinDiff/NSIS code, the operating system, vendored Qt/native libraries, or prove
exploitability. Record these unaudited categories explicitly. Scanner tooling
has its own observed inventory and installation report. Nothing here qualifies
a full backend bundle's native dependency security or a distinct frozen build.

Queries transmit the selected public package names/versions to the explicitly
chosen advisory service. No source bodies, environment secrets or target
binaries are uploaded by this helper. Neither scanner performs automatic
remediation or invokes target binaries. No workflow dispatch, tag, release or
deployment is part of this candidate.

## Tests and remaining qualification

Author workflow/receipt regressions before implementation: exact mandatory
jobs/steps, no continue-on-error or suppression, missing and malformed receipts,
wrong SHA/run/attempt/platform/profile, incomplete dependency coverage,
repository-owned origin proof, duplicate/overflow JSON, scanner failures,
and refusal of fabricated clean results. Authored fixtures are not live scans.

Capture any available actual local scans with their real outcome and source
provenance. Linux evidence does not supply Windows inventory or hosted credit.
Final integrated-source CI and independent review remain required.
