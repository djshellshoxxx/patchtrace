# CODEX-5: complete installer map and proposed platform lock design

Status: design for root review; no dependency download, install, audit-policy
change or workflow input change is authorized by this document. Source inventory
is frozen at `c7d3f25858cfefbacbd8ea4022b3d13e1e2aed2a`. Action/cache/smoke
follow-ups do not change the Python dependency inputs inventoried here.

The companion [ci-dependency-installer-map-20261118.json](ci-dependency-installer-map-20261118.json) retains every direct script, job,
matrix, profile classification and workflow blob: **41 install script blocks in
20 of 22 workflows**, plus six helper/input boundaries. The two workflows with no
direct pip block are `codex-cloud` and `dependency-security`; the latter invokes
a real installer helper and is explicitly included below. Counts describe
callers, not independently resolved environments or qualification percentages.

## Existing boundaries

| Boundary | Current guarantee | Missing lock scope |
| --- | --- | --- |
| `pyproject.toml` | Exact direct core/optional versions; upper bounds for build/dev dependencies | Resolved transitive artifacts, build backend and OS-specific dependencies |
| QA/packaging jobs | Wheels-only `.[dev,search,rules]` install, pip check and actual tests | No pre-install hash closure; editable build isolation can resolve build requirements |
| Core/dev/optional live and corpus jobs | Core, dev or search/rules selections; some wheels-only | Distinct exact closures must preserve each job's selected extras |
| `tools/site/requirements.txt`, Pages | Segno 1.6.6, Pillow 12.3.0 plus workflow pytest | Pytest/transitives and all wheel hashes |
| Pilot evaluation | Core project plus pytest/hypothesis | The two install steps form one effective environment |
| `tools/dependency_security.py` | Reviewed hash-pinned pip 26.3 bootstrap; complete installed provenance and vulnerability audit | Scanner, build-backend and product dependencies still resolve before their recorded audit; the post-install inventory is not a pre-install lock |
| `tools/build_backend_bundle.py` | Existing platform/any source pins, offline wheel building, per-wheel `--require-hashes`, `--no-index`, `--no-deps`, source-byte comparison | Preserve this pipeline; lock its host build tools separately. It is not a general desktop CI lock |
| `tools/verify_backend_pins.py` | Attributed proposed runtime/source digests; explicit pin review | Workflow's Sigstore 4.5.0 verifier and transitive Python tools are not hash locked |
| Native Ghidriff jobs | Git commit 4f5d895, often PyGhidra 3.0.2 | Commit identity alone is not a complete install artifact/build/transitive lock |
| `diff-and-score` | User-selected Ghidriff version | Arbitrary versions cannot have a pre-reviewed committed closure automatically |
| `winbindex-pairs` | Unversioned advisory Ghidriff install | Needs an explicit reviewed version/profile; current install failure remains advisory |

All direct installer jobs select moving Python `3.12`, not an exact patch. Java
21/25, host/runner packages, apt compiler dependencies and the NSIS host installer
are separate runtime/tool inputs. The Python lock proposal must state these
limits; it cannot claim whole-environment reproducibility from wheel hashes.
The optional `calibration-dev` dependency is declared but no current workflow
installs it. Diagnostic pip strings in the desktop builders, site help and
optional-dependency/doctor UI are not executable installer callers. No general
committed Python lock generator was found. The backend wheelhouse requirement
writer and scanner bootstrap requirement writer are the existing scoped ones.

## Proposed files and identities

Create `tools/ci/lock_inputs.json`, a stdlib-only
`tools/ci/lock_profile.py`, a small `tools/ci/install_profile.py`, and reviewed
`tools/ci/locks/<platform>-cp312-<profile>.txt` plus adjacent provenance JSON.
These are proposed paths, not existing APIs. Keep standard pip requirements
syntax with exact `name==version --hash=sha256:...` rows. Each provenance record
binds the profile's input digest, exact Python patch/implementation/ABI, OS and
architecture, supported wheel tags, resolver/bootstrap version/digest, approved
index, artifact filename/size/URL/SHA256 and complete dependency metadata.

Resolve on actual Linux x86-64 and Windows AMD64 interpreters separately. Select
the exact CPython patch from independently verified official runtime metadata
and existing native qualification evidence before generation; do not silently
take the newest patch or pretend this Linux session proves Windows markers.
Use a compatible reviewed Linux wheel baseline for the supported Ubuntu 22.04
and 24.04 jobs and validate both actual runners. Unsupported platform/interpreter
or a manifest/input drift must refuse before installation. Native acceptance
must record interpreter and runner identities; wheel locking alone does not pin
the hosted image, compiler, Java runtime or apt repositories.

Profiles must remain explicit: app-core; app-extras; qa-core; qa-packaging-extras;
pilot; site-build-test; signature-verify; scanner-static; scanner-audit; backend
build-tools; and the version-specific native Ghidriff/PyGhidra additions. Reuse
identical reviewed lock content by digest where genuinely equal. Do not install
an unrelated superset into every job, because optional dependency presence can
change behavior. The JSON caller map is the denominator for migration.

## Resolution, review and installation

1. Bootstrap a clean native generator environment with the already reviewed pip
   artifact. Preserve its original ensurepip inventory and transition proof.
   Derive profile inputs from the current pyproject/site/scanner/backend inputs;
   fail on unrecognized requirements or an inconsistent input digest.
2. Resolve wheel-only dependencies without installing or executing them. Record
   pip's actual report and fetch only the proposed official artifact URLs into
   a disposable bounded download area. Verify downloaded bytes against the
   proposed metadata, inspect bounded wheel metadata, and construct the complete
   closure. This step needs root-approved generation execution; no such fetch
   has been performed in this task.
3. Review every version/artifact change and its source metadata. Commit the
   platform lock and provenance together. A later installation cannot generate
   or approve its own hashes. Refuse yanked/unexpected-source artifacts and any
   unresolved distribution. A fresh resolution is not automatically trusted.
4. In a new native CI environment, verify the lock/profile/interpreter identity,
   then install the external closure with explicit `--require-hashes` and
   `--only-binary=:all:`. Keep hash enforcement for cache hits too. Require a
   missing or unlisted transitive requirement to fail; never use
   `--no-require-hashes`, downgrade hashes or fall back to an sdist automatically.
5. Install only this checked-out local project separately using `--no-index
   --no-deps --no-build-isolation -e .`, after its locked build backend is already
   present. This is a real network prohibition for a local input, not a flag
   added to satisfy the historical textual probe. Then run pip check and compare
   the complete installed inventory/report against the reviewed closure.
6. Preserve the existing dependency audit and exact-source release gate. Scanner
   execution remains unsuppressed; vulnerability findings and unavailable lanes
   remain failures/blocks. A lock is not a vulnerability-audit waiver.

Ghidriff and mdutils require an explicit source-build subprofile. Preserve the
existing reviewed source tarball digest, build offline with locked build tools,
and reuse the source-byte comparison. Record/review the produced wheel digest
and builder identity before it becomes an installable locked artifact. Do not
replace the approved source with an arbitrary PyPI release, weaken the current
backend license policy, or fold an external engine into the frozen application.

## Decisions needed before expanding implementation

The lock generator/installer and concrete native generation runs need separate
ownership and review. Changes to `tools/dependency_security.py` must be coordinated
with its owner and preserve every existing receipt-validation guarantee.

For `diff-and-score`, retain its version input as a selection among explicitly
reviewed profiles and fail clearly when no matching lock exists, **only if root
approves that input-contract restriction**. Otherwise this route stays openly
unqualified until a compatible explicit-lock input is designed. Similarly,
select the intended pinned version for the currently unversioned advisory
`winbindex-pairs` route before changing it. Do not silently change dispatch
contracts or convert an advisory install result into a native pass.

Migrate standard core/QA/site/scanner routes in a separate reviewable first
implementation, then reviewed native-source profiles. Keep the unchanged
CODEX-5 probe failing until every direct caller it checks is genuinely repaired,
and additionally test helper-generated commands that its textual scan cannot
see. No partial caller count closes the broader historical finding.

## Required controls

Author hermetic controls first for absent/transitive hashes, altered wheel bytes,
foreign URLs, yanked entries, wrong interpreter/platform/profile, stale input
digests, marker/extras closure differences, unlisted build dependencies, cache
tampering and install-side fallback refusal. Check a bounded synthetic complete
closure and genuine local-only project install as positives. Native follow-up
must install each real reviewed closure in clean Linux/Windows environments,
compare reports, run pip check and current dependency/security scans, and retain
both successful and failed receipts. No mocked platform run can qualify a real
Windows lock or external engine.

Primary documentation checked 2026-11-18: pip's
[secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/),
[repeatable installs](https://pip.pypa.io/en/stable/topics/repeatable-installs/),
and [download command](https://pip.pypa.io/en/stable/cli/pip_download/).
The design uses their complete hash-mode and wheel-only constraints, treats
platform wheelhouses separately, and does not use the documented hash-mode
disable switch. Repository caller facts come from the exact JSON/Git snapshots.
