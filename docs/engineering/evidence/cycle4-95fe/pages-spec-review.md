# Pages dependency isolation and hashes — independent specification review

Reviewed 2026-11-21 UTC by `cycle4_pages_spec`.

## Frozen source and conclusion

- Baseline: `11f51c105bf63946f59373ae605b937c4fee607a`.
- Reviewed source head: `305d2d10fafeb4a7c8e566cdd0a3f67cccd97ec1`.
- Reviewed complete tree: `9bb0dd33372693c0ccf3836d39c97d7c6afca94f`.
- Documentation correction independently checked: `36584f8153983d64605dd7f4141e88c9fabfa6ef`, against combined parent `8c5e77e2c1ad3f6cfa62c2e474f7bcc2f4af1dd5`.
- Author worktree: `/workspace/scratch/patchtrace-95fe-c4/pages`, clean before and after controls.
- Contract: `docs/specs/pages-build-isolation-and-hashes.md`, plus the existing Pages deployment-control contract, `AGENTS.md`, relevant `docs/modules.md` entries and site instructions.

**Passed: zero remaining blocking or nonblocking specification findings.**
One nonblocking documentation prerequisite was identified and is closed below.
The bounded CI implementation matches its contract. No missing installation dependency,
incorrect hash, changed deployment behavior, assertion weakening, or application-fixture
change was found. The original source remains limited to six specified workflow, lock,
documentation and test files.

## Finding S-PAGES-01 — portable test example omits pytest minimum (P3, closed)

At the reviewed source, `site/README.md` added `--disable-plugin-autoload` to the
portable site-test command, then said only that pytest must be installed. That
command-line flag was introduced in pytest 8.4, while `pyproject.toml` still permits
development environments with `pytest>=8,<10`. An older permitted development
installation therefore could not run the copied command as written.

The coordinator's documentation-only correction `36584f8153983d64605dd7f4141e88c9fabfa6ef`
now directs installing tested **pytest 9.2.0** and states the flag requires **8.4 or newer**.
I inspected the exact parent-to-correction diff: it modifies only this prerequisite
paragraph. The finding is closed. CI already pinned 9.2.0 and was unaffected.

Primary source: [pytest plugin documentation, disabling autoload](https://docs.pytest.org/en/stable/how-to/plugins.html#disabling-plugins-from-autoloading),
retrieved 2026-11-21 UTC, explicitly records introduction in version 8.4.

## Requirement assessment

| Requirement | Review evidence | Disposition |
| --- | --- | --- |
| Exact seven-package Linux x86-64 / CPython 3.12 closure | Independently read every committed requirement and each wheel's METADATA; evaluated active markers and version constraints | Pass: seven distributions, four active dependency edges |
| Retain Pillow 12.3.0 and Segno 1.6.6; pin tested pytest 9.2.0 | Lock pins and unchanged portable input | Pass |
| Reviewed wheel hashes and source provenance | Independently matched all seven SHA-256 values to the retained original version-specific PyPI JSON, actual wheel bytes, sizes, filenames, Name/Version and Requires-Python | Pass |
| Require hashes and binary distributions, without extra unpinned arguments | Exact install command and focused contract tests | Pass; dependency resolution remains enabled |
| Site-only fixture/plugin isolation over the full selection | Exact pytest command retains `tests/test_site_*.py`, adds both specified isolation flags, and leaves shared application fixtures unchanged | Pass |
| Preserve all existing assertions and explicit skip boundary | Existing site workflow test AST equals baseline after substituting only its two intentional expected strings; all other maintained site tests are unchanged | Pass |
| Preserve Action refs, triggers, permissions, artifacts, build and deploy hold | Restoring only the two new command strings recreates the complete original workflow byte-for-byte | Pass |
| Keep ordinary application QA and dependency definitions | `tests/conftest.py`, `pyproject.toml`, portable requirements and all app source are unchanged | Pass |
| Retain original failure and meaningful refusal evidence | Read exact-source receipts and raw logs; clean install passed, wrong Pillow hash and omitted Pluggy lock each refused for the intended reason | Pass; these are author-executed pip controls |
| Scope CODEX-5 honestly | Global expected failure unchanged; lock and specification explicitly limit this to one Linux Pages lane | Pass; broader CODEX-5 remains open |

## Independent controls executed

`pages-spec-controls.py` reads frozen Git objects and retained artifact files only.
It produced `pages-spec-evidence/controls.json` with:

- Seven independently recomputed wheel hashes/sizes and seven exact wheel identities.
- Four active dependency edges checked against the complete pinned closure.
- Python 3.12 compatibility and Pillow's specific Linux x86-64 tags; six universal wheels.
- Exact workflow restoration after only the two intended command substitutions.
- Existing maintained test AST preservation, unchanged application fixtures/configuration
  and portable inputs, and the exact six-file change scope.
- Validation that the damaged-hash control differs only in Pillow's hash, and the
  missing-dependency control only removes Pluggy; original receipts and logs show
  the intended pip refusals on the reviewed clean source.

`pages-spec-evidence/documentation-followup.json` additionally records the exact
documentation correction and confirms all five remaining Pages source/spec/test/lock
blobs are unchanged between the original reviewed head and the corrected integration.

These are independent data/source controls, **not additional repository pytest passes**.
No second broad test suite, dependency installation, artifact download, network dispatch
or publication was performed by this reviewer.

## Boundaries

The author's source-bound site selection reports **247 passed and one existing optional
PySide6 screenshot skip**; its real site build and clean hash-locked installation passed.
These retained results were inspected, not relabeled as independent reviewer runs.

The isolated Pages environment does not establish native GUI, screen-reader or other
platform acceptance. The source review does not execute GitHub's expression engine or
establish hosted Pages acceptance. PR349 integration ownership and its existing merge,
release and deployment holds remain with the coordinator and parallel owner.
