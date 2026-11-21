# Pages dependency lane — independent standards review

Reviewer: `cycle4_pages_standards`. Reviewed 2026-11-21 UTC.

## Exact source and scope

- Base: `11f51c105bf63946f59373ae605b937c4fee607a`.
- Reviewed Pages head: `305d2d10fafeb4a7c8e566cdd0a3f67cccd97ec1`.
- Complete Pages tree: `9bb0dd33372693c0ccf3836d39c97d7c6afca94f`.
- Read-only checkout: `/workspace/scratch/patchtrace-95fe-c4/pages`.
- Checkout remained clean before and after independent controls.
- Contract `cde11421` precedes regression `f4ed82d8` and implementation `305d2d10`.
- Documentation correction separately reviewed:
  `8c5e77e2c1ad3f6cfa62c2e474f7bcc2f4af1dd5` to
  `36584f8153983d64605dd7f4141e88c9fabfa6ef`.

Reviewed the six-file Pages diff, `AGENTS.md`, relevant site entries in
`docs/modules.md`, the Pages deployment-control specification, and the new
build-isolation/hash specification. This axis covers documented standards,
defensive correctness and the supplied code-smell heuristics; the independent
spec axis remains separate.

## Findings

**Zero blocking findings, zero open documented-standard violations, and zero
actionable code-smell findings.** The change uses existing pip and pytest
mechanisms without introducing a dependency-management framework.

The one nonblocking documentation prerequisite also identified by the spec
reviewer is **closed** by coordinator commit
`36584f8153983d64605dd7f4141e88c9fabfa6ef`. I independently inspected its exact
delta: only `site/README.md` changes, and its three replacement lines explicitly
instruct installation of tested pytest 9.2.0 and state the 8.4 minimum for
`--disable-plugin-autoload`. CI already pins 9.2.0. This is the same prerequisite
note from the spec axis, not a second independent defect.

Primary reference: [pytest plugin loading documentation](https://docs.pytest.org/en/stable/how-to/plugins.html#disabling-plugins-from-autoloading).

## Standards and correctness assessment

`AGENTS.md` requires contracts before implementation, meaningful invariant tests,
preservation of prior failures, and separation of local checks from live
acceptance. The ordered commits, retained original fixture error and four-case
red baseline, complete site selection, and bounded install/refusal receipts
satisfy those requirements in this slice. No schema or application module
changed, so schema regeneration or new module registration is unnecessary.

The install command uses `--require-hashes --only-binary=:all:` with one complete
lock and no extra floating requirement. Dependency resolution remains enabled;
there is no `--no-deps` exception or source-build path. All seven direct/transitive
distributions are pinned and assigned one reviewed wheel digest. The lock's
Linux x86_64/CPython 3.12 scope is explicit, and the portable build-only
Pillow/Segno input retains its original versions.

The pytest command retains the complete `tests/test_site_*.py` selection. Its
fixture/plugin isolation is local to the Pages lane. Application source,
shared `tests/conftest.py`, project configuration, the existing screenshot skip,
and the global CODEX-5 strict expected failure are unchanged. I verified that
the workflow differs from the base by precisely the two intended command
replacements; Action references, event filters, permissions, build/artifact
order, deployment environment and actual-head `[no deploy]` condition remain
intact.

The new source-contract tests enforce unique pinned/hash-bearing entries,
preserved direct versions and the exact bounded command shapes. They are not
treated as artifact-integrity proof: that comes from independently hashed bytes
and actual pip acceptance/refusal evidence. The broader CODEX-5 run-block audit
limitation is not silently fixed or claimed closed here.

## Independent controls performed

The read-only control script read the committed lock and all seven original
version-specific PyPI JSON responses, rehashed every selected wheel, checked
file sizes and non-yanked wheel identities, parsed wheel `METADATA`, and
evaluated dependency markers for CPython 3.12/Linux x86_64 with no extras.

- **Seven of seven** wheel bytes, locked digests, upstream metadata identities
  and sizes agree; selected wheels are compatible with the stated runtime.
- **Four of four** active dependency edges resolve to permitted locked versions.
- All original **244 site-test identities** remain in the final JUnit with
  identical outcomes; four added identities belong to the lock contract file.
  Final author JUnit has **247 passed and one unchanged skip**.
- Eight author receipts name the exact clean reviewed head/tree. The positive
  installation, site selection, build, environment-scope check, pip check and
  Ruff have exit zero. The damaged-hash and missing-dependency controls have exit
  one for the intended failures, verified in their full logs.
- The production workflow has only the intended two command replacements; the
  protected application/fixture/configuration/audit paths are byte-preserved.
- The later prerequisite correction changes only the documented pytest version
  requirement; no runtime or test file changed in that correction.

These are independent metadata, source and recorded-evidence checks, **not new
repository pytest passes**. I did not repeat the full suite or install packages.
The wheel archives were opened as ZIP data; no analyzed target was executed.

## Evidence and acceptance boundaries

- Control script: `/workspace/scratch/patchtrace-95fe-c4/pages-standards-controls.py`.
- Result: `/workspace/scratch/patchtrace-95fe-c4/pages-standards-evidence/controls-result.json`.
- Documentation check: `/workspace/scratch/patchtrace-95fe-c4/pages-standards-evidence/documentation-correction.json`.
- Manifest: `/workspace/scratch/patchtrace-95fe-c4/pages-standards-evidence/manifest.json`.

Actual pip receipts use a verified local wheelhouse with `--no-index`; they do
not establish hosted index resolution. The existing screenshot skip remains
visible because PySide6 is intentionally absent from the site-only environment.
Hosted combined-source QA, Windows/native GUI acceptance, other installation
lanes and the parallel integration owner's findings remain separate. No remote
ref, PR, workflow run, release or deployment was changed by this review.
