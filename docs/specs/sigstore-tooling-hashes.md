# Sigstore verifier tooling hashes

## Scope and unchanged baseline

This contract protects only the Sigstore installer in
`.github/workflows/backend-bundle.yml`, job `vrfy`. The job runs on
`ubuntu-latest` with CPython 3.12 when `needs.pin.outputs.verify == 'true'`.
The existing `pin_verify` input remains false by default. Selecting Windows
bundle output does not change this Ubuntu tooling job. No Windows, ARM or
other Python-minor closure is claimed.

Preserve Sigstore 4.5.0 and every dependency version resolved by successful
run 38661029764, job 116182091312, source
`bf7e936f358a1eb8ea36d86da8a0189793f17cfa`, on Linux x86-64 CPython 3.12.15.
That actual installer used the same `sigstore==4.5.0` command as the parent.
The later successful verifier run 38661058614 used Sigstore 4.4.0 and is not
this baseline. The complete selected set is:

| Distribution | Version |
|---|---|
| annotated-types | 0.8.0 |
| certifi | 2026.7.22 |
| cffi | 2.1.1 |
| charset-normalizer | 3.5.2 |
| cryptography | 50.0.2 |
| dnspython | 2.9.0 |
| email-validator | 2.3.0 |
| id | 1.6.1 |
| idna | 3.20 |
| markdown-it-py | 4.2.0 |
| mdurl | 0.1.2 |
| platformdirs | 4.13.0 |
| pyasn1 | 0.6.4 |
| pycparser | 3.11 |
| pydantic | 2.14.1 |
| pydantic-core | 2.50.1 |
| pygments | 2.21.0 |
| pyjwt | 2.15.1 |
| pyopenssl | 26.4.0 |
| requests | 2.34.2 |
| rfc3161-client | 1.0.9 |
| rfc8785 | 0.1.4 |
| rich | 15.0.0 |
| securesystemslib | 1.5.1 |
| sigstore | 4.5.0 |
| sigstore-models | 0.0.6 |
| sigstore-rekor-types | 0.0.18 |
| tuf | 7.0.1 |
| typing-extensions | 4.16.0 |
| typing-inspection | 0.4.4 |
| urllib3 | 2.8.0 |

## Complete wheel closure

`tools/requirements-sigstore-ci.lock` contains exactly these 31 distributions,
each pinned by `==` and the SHA-256 of the exact wheel filename observed in
that successful install. Preserve the ordinary dependency resolver. The
workflow uses `--require-hashes --only-binary=:all: -r` with this lock and no
extra unpinned arguments, `--no-deps`, environment/configuration equivalent,
hash bypass or alternative-index shortcut.

The Linux CPython 3.12 closure contains 41 active requirement edges. Propagate
extras: sigstore-rekor-types requires `pydantic[email]`, activating
email-validator, whose dependencies include dnspython and idna. An `extra ==`
marker is not automatically inactive. Sigstore's importlib_resources edge is
inactive on Python 3.12 because it applies below Python 3.11. The lock keeps
pydantic 2.14.1 for this separate tooling environment; do not silently unify it
with the application pin.

Verify actual wheel bytes, size, SHA-256, ZIP integrity and embedded Name,
Version, Requires-Python, Requires-Dist and WHEEL tags against the selected
version-specific official PyPI records. Recheck all active edges from the
embedded metadata for Linux CPython 3.12, including requested extras. Five
selected wheels are native-tagged: cffi, charset-normalizer, cryptography,
pydantic-core and rfc3161-client. The remaining 26 are universal wheels.
Registry metadata or filename tags alone do not establish byte or install
qualification. Pygments 2.21.0 may reuse the reviewed Pages/pilot artifact only
on exact version, filename and SHA-256 equality; it is the sole overlap.

Use the existing small tooling-lock and wheelhouse verification patterns.
The private backend payload builder's `--no-deps`/foreign-target installer is
a separate runtime contract and must not replace this normal-resolver host
install. No new dependency framework or build environment is introduced.

## Unchanged verifier and wider gates

Change only the existing installer run scalar. Preserve its step name, the
workflow triggers/inputs/defaults, planning logic, job condition, permissions,
runner/Python version, timeout, environment, Action pins, verification commands,
identity/issuer/fingerprint inputs, pin artifacts and all other steps. Other
builder/application installers stay separately unprotected. Do not invoke
signing, identity verification, user-artifact verification or credential access
to qualify this dependency-only change.

The parent f086 census is 21 workflows, 203 run scalars, 38 installing jobs,
42 explicit installs, 2 protected and 40 unprotected. Only an actual candidate
scan may record the same totals with 3 protected and 39 unprotected. Preserve
the prior census records and both broad strict CODEX-5 expected failures.
Wider hash closure, hosted qualification, native acceptance and release gates
remain separate.

## Qualification

- Collect source contract tests against the parent's actual installer and
  absent lock before implementation; assertion failures must explain the
  missing boundary/closure, not an import or collection error.
- Verify all 31 selected artifacts and embedded-metadata dependency edges.
  Install the complete lock into a new clean Python 3.12 environment with the
  normal resolver and official index, then require the exact 31 versions and
  a clean `pip check`.
- Use a separate fresh environment for each refusal: wrong Sigstore root hash,
  omitted ordinary transitive entry with the artifact still available, and a
  present email-validator extra-transitive entry whose hash is absent. Require
  the intended hash-mode/pinning refusal; missing artifacts, already-installed
  distributions and resolver suppression are not substitutes.
- Limit direct Sigstore smoke execution to nonnetwork `--help` and `--version`.
  Keep this tooling install evidence separate from source/application tests.
- Run the source/workflow contract and existing verifier unit tests, whole-tree
  Ruff and dependency checks on the frozen candidate. Retain all failures and
  source/environment identities for independent review.

References: [pip hash checking](https://pip.pypa.io/en/stable/topics/secure-installs/),
[command audit](ci-pip-command-audit.md),
[backend wheelhouse contract](program-e/BUNDLE-wheelhouse-and-pyghidra-spec.md),
[historical successful run](https://github.com/djshellshoxxx/PatchTrace/actions/runs/38661029764).
