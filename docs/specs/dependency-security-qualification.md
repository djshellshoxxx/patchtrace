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

Identity fields retain their exact JSON types. Verify literal committed source
bytes independently of Git's index flags/replacement objects. Application source
may not gain untracked Python modules or tracked links to external source. Each
command receipt includes its actual argv, bounded duration, start time, exit,
timeout/output-limit state, and raw-output digests. Missing timing or receipts
older than 24 hours cannot supply current qualification; historical evidence
remains available for review without being counted as a current pass.

## Actual installed Python dependency closure

Create a fresh isolated environment per native OS/profile. Runtime installs
the source checkout with production plus search/rules extras. Packaging mirrors
the existing QA/package builder's dev/search/rules installation, including its
test/build tools. This is the actual installed environment for this scan build,
not a claim about a separate frozen executable's complete bill of materials.
Record the exact install command, pip installation report, interpreter identity,
pip check outcome, and full pip inspect JSON. An installation report is evidence
of that resolution; it is not treated as a lock file.

Every directly generated Python subprocess uses the canonical interpreter options
`-I -X utf8` before `-m` or `-c`, including environment preparation, bootstrap,
installer, identity, inspection, check and scanner commands. Explicit UTF-8 mode
keeps Unicode dependency metadata representable on Windows redirected output;
`-I` and the launcher's existing environment filtering remain in force. An
environment-only `PYTHONUTF8`/`PYTHONIOENCODING` setting cannot supply this contract
because isolated Python ignores those variables. Preserve complete raw output
bytes and their digests; do not discard, replace or transliterate metadata to
avoid an encoding error. Exact command-receipt validation includes the UTF-8
option, so missing or altered flags cannot qualify current evidence. Interpreter
UTF-8 mode also governs Python's documented text defaults in those subprocesses.

Cross-check pip's environment against the independently executed interpreter
identity: exact full Python and implementation versions, Python major/minor,
implementation name and display name, native system and machine architecture.
All required fields must be present strings; a partial matching prefix does not
verify a different interpreter. The inspect pip version, installed pip version
and ordinary installation-report pip versions must agree. The original bootstrap
must match ensurepip; an authorized transition separately proves its original
issuer and installed target below. Every installation report preserves the same complete environment
mapping as the final inspection. Missing or contradictory provenance fails even
when the dependency names and versions otherwise appear consistent.

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
reports; the original bootstrap pip identity must match that interpreter's ensurepip.
Currently selected requirements use plain names, exact versions or numeric
version bounds. Refuse an unsupported requirement/marker/version form instead of
guessing whether it is satisfied. Preserve that limitation if project metadata
later gains more expressive requirements. Validate this subset before constructing
or launching installer commands; an unsupported requirement is never forwarded as
an installer option. Malformed interpreter or report shapes produce a recorded
refusal rather than being treated as absent optional provenance.

Generate fully pinned audit requirements from all remaining installed
distributions. Audit that already-resolved closure using pinned pip-audit 2.10.1,
with strict collection, no dependency resolution, pip resolution disabled,
explicit PyPI vulnerability service, bounded request/process time, and JSON
output. No skip-editable, ignored vulnerability, dry run, auto-fix, automatic
dependency upgrade in response to findings, or successful fallback is allowed.
Preserve the raw output even on
nonzero exit or parse failure.

Validation requires an exact name/version match between the full requested
inventory and scanner dependencies, no skips, no missing or duplicate entries,
an empty fixes list, valid bounded finite JSON, and exit zero. Nonzero exit,
network denial, inaccessible advisory data, missing report, collection error,
reported vulnerability, malformed evidence or incomplete coverage remains failed
or unverified, never clean.

## Explicit reviewed bootstrap remediation (2026-11-18 follow-on)

The initial candidate's actual Linux environments contain ensurepip's pip
25.0.1. Retain those failing inventories unchanged. A separate authorized
preparation step pins pip 26.3 in each newly created scanner/product environment;
it does not alter project dependencies or an existing user/shared environment.
This pin is based on official PyPA advisory fixes and pip/PyPI release metadata,
supports Python 3.12, and uses the universal wheel's recorded SHA-256:
`f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13`.

Before any third-party scanner/product installation, retain a separate bootstrap
interpreter identity, full pip inspection and pip-check outcome. Require that
fresh inventory to contain only the observed ensurepip-owned pip, with matching
full native environment and issuer version. A newer/unrecognized bootstrap is
refused rather than silently downgraded or assumed equivalent.

Install only the reviewed pip wheel, with exact version and required hash,
binary-only resolution and no dependencies. Reinstalling the same pin is allowed
in this freshly owned environment so the installation report still records the
actual wheel origin. Preserve the raw process exit/output, installer report and
immediate prepared-environment inspection. The installer report's pip version
is the original issuer; the one installed target is pip 26.3. Require the exact
approved wheel URL/digest, non-yanked requested index distribution, no other
installed target, the same complete native environment, and a prepared inventory
containing exactly the pinned pip. Missing/mismatched/failed transition evidence
blocks all subsequent scanner/product installation.

The final environment must retain the same interpreter/ensurepip identity and
native environment, while its installed/inspection pip and all subsequent
installer-report issuer versions equal 26.3. The final audit still includes pip
and every other non-owned distribution; this transition is not an audit exclusion
or a clean-result waiver. Scanner findings remain blocking.

The lower-level installation validator retains explicit predecessor semantics:
without transition evidence it may validate an unmodified historical ensurepip
environment only when all pip versions match. That API path cannot qualify the
current pipeline: every current profile requires the complete bootstrap command
receipts, pinned requirements, transition report and prepared inventory before
the final inventory/scanner receipts can pass.

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

Both dependency and static artifact uploads retain the raw text input receipts
alongside JSON, stdout and stderr, including `bootstrap-pip.txt` when a scan
fails. The upload patterns must include `*.txt` in each profile's evidence
directory. This retention requirement does not change scanner execution or
acceptance, and cannot repair a missing input in a historical artifact.

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

The 2026-11-18 hosted Windows runtime/packaging receipts retain the original
`pip inspect` CP1252 UnicodeEncodeError unchanged. Portable regression children
may deliberately select CP1252 when the explicit mode is absent; label that as
an authored producer simulation, not a Windows/pip rerun. Keep controls for
Unicode byte preservation, isolation, raw failed output and exact argv refusal.
A corrected hosted Windows inventory/audit remains a separate acceptance gate.
