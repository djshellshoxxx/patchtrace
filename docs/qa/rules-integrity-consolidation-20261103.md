# Rules integrity consolidation receipt (2026-11-03 UTC)

This bounded slice preserves the final reviewed #146 rules fixes in the frozen
#163 comparison candidate. It does not change the unfinished proposal backend,
callgraph code, saved-scope behavior, milestone ledger, contracts, dependency
pins, schemas, or shared trackers. Root owns integration, independent review,
remote publication and all PR/issue dispositions.

## Immutable source mapping

- Candidate remote head: `6e82fd70f315b99c6798a42c9061a1424a02933e`.
- Exact local candidate representation / parent:
  `2b6a4965cc4e0e1f3822109d8a13ebf236ff9bb0`, tree
  `2e7cd8e258821f50d776ca3b3a4caef594e2a417`.
- Reviewed final #146 source: `798e11ef345ed7a7a65508a466eaf77ee85ef77c`,
  tree `e29d83a20e9a6d2d3e1a023f51fb30350d88bc73`. Owner reports the
  parent-lane consolidation at `280bf05856eb60f4ddb0d58210616f65a3735816`
  has that same tree; this slice uses the immutable reviewed blob mapping.
- Tested source tree before this receipt was added:
  `8b8254c8fee12b1de6f515760dd7ce3b8f4fb680`. Only this Markdown receipt
  was added after validation. The resulting commit/tree are reported in the
  integration handoff rather than embedded self-referentially here.
- Isolated shared clone: `/tmp/patchtrace-rules-integrity-20261103`, branch
  `codex/rules-integrity-consolidation-20261103`. The frozen parent checkout
  `/tmp/patchtrace-publish-20261102` was read only.

The seven candidate blobs were verified against the pre-lane baselines in
`consolidation-rules-lane-20261102.md`. All seven final files are byte-for-byte
the reviewed #146 blobs below. The historical fetched JSON receipt was decoded
as data, and Git blob SHA-1 was independently recomputed for every blob before
copying it. No network operation or remote mutation was performed.

| Path | Candidate baseline blob | Final reviewed / consolidated blob |
|---|---|---|
| `src/patchtrace/rules/export.py` | `5662bf05ef11d27d6488a063bdc921f7ffd1aba2` | `49d0614cdd18e7df21f3ff95ef4a260f9296cbe8` |
| `src/patchtrace/rules/matrix.py` | `cf60f1e712fe49d0d90c06146e60a2cd3cd0bc60` | `c30d6fbdea224e40d1e60b075020c79a01bd5ec3` |
| `src/patchtrace/rules/store.py` | `fb25a9c48391575cfe35feb94ab951d5af01ad9a` | `0aa5a5fc3d73677d8a3584bfae62e39adcc9e7f0` |
| `tests/test_rules_export.py` | `8a46e460677a413f8825293f705a2f5d018cff49` | `c6eacb28e13ed7db15a30b196daccd67dbb42a45` |
| `tests/test_rules_matrix.py` | `fccffe95c1e05ff3373e5f37391a1872a0944219` | `ffe46b4ea056f1e1dd9a8192390a584624fb1a84` |
| `tests/test_rules_store.py` | `6ce0fa6343985f8dbb0561d5b17b15e702eefb64` | `2a9f7b509f4677e63d922b6a5df26eaeda21e8d1` |
| `docs/specs/yara-x-rule-workflow.md` | `435283d1bb8f3fc0b1ef2d8a11b4544de28364bd` | `4db7a640d441717fbf65b8ef26fcb8fd489adaf4` |

## Behavior preserved

The final workflow specification was applied before production source. Cached
rescoring prefers target/version identity plus matching content hashes, keeps
distinct observations for identical rule text, refuses ambiguous content-only
fallback with `PT-RULE-INTEGRITY` / `cache-identity`, reconstructs requested rule
identities, and validates the final grid. Export reuses the record's basename
validation before creating output. Malformed, invalid UTF-8 and excessively
nested matching-hash sidecars become skipped entries. File hashing checks
regular-file status before and after acquisition and uses nonblocking POSIX
acquisition for a file replaced by a FIFO.

The inherited `rescored` docstring summarizes hash lookup; the final normative
specification and implementation specify the more precise identity-first
policy. This wording was preserved with the reviewed source rather than mixed
with an additional change.

## Validation and provenance

All commands ran in the isolated clone. Python was
`/tmp/patchtrace-isolated-imports-venv-20261102/bin/python` (Python 3.12).
Explicit `PYTHONPATH=/tmp/patchtrace-rules-integrity-20261103/src` resolved
`patchtrace.rules.matrix`, `.export` and `.store` to that clone's corresponding
source files. Installed distribution versions were YARA-X `1.21.0`, iced-x86
`1.21.0`, Pydantic `2.13.5`, pytest `9.2.0` and Ruff `0.17.3`.

Before porting production source, the reviewed tests reproduced six expected
failures on the candidate baseline: reordered saved grids, distinct versions
sharing content, invalid export basename, and three corrupt sidecar cases.
Result: **6 failed, 74 deselected in 1.64s**. The character-device baseline case
was intentionally excluded from this red selection to avoid its formerly
unbounded read; final guards were tested without weakening the regressions.

The green command was:

```sh
PYTHONPATH=/tmp/patchtrace-rules-integrity-20261103/src QT_QPA_PLATFORM=offscreen /tmp/patchtrace-isolated-imports-venv-20261102/bin/python -m pytest -q -p no:cacheprovider tests/test_rules_matrix.py tests/test_rules_export.py tests/test_rules_store.py tests/test_rules_cli.py tests/test_rules_view.py tests/test_rules_contracts.py --tb=short
```

Result: **420 passed in 11.94s**, no skips. This includes the bounded POSIX
FIFO-replacement regression, character-device refusal, deep expectations JSON,
the six reproduced fixes, rules CLI/store/view compatibility and existing
contract/schema-regeneration assertions. Synthetic fixture bytes were read by
the pinned YARA-X rules tests; no compared target was executed.

Repository lint command:

```sh
/tmp/patchtrace-isolated-imports-venv-20261102/bin/python -m ruff check src tests tools
```

Result: **All checks passed!**

Raw local logs and SHA-256:

| Log | SHA-256 |
|---|---|
| `/tmp/patchtrace-rules-integrity-red-20261103.log` | `75fd43476475e29f07bb70dca380031232f993bd5adbe383f8bc9d4743dd94bf` |
| `/tmp/patchtrace-rules-integrity-green-20261103.log` | `12021a43701332dd7df77f2011e421dfb2b19685cddf5045c095e3cc08b5d832` |
| `/tmp/patchtrace-rules-integrity-ruff-20261103.log` | `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18` |

## Limits and integration handoff

Windows named-pipe/device races remain unverified, as the preserved specification
states. This Linux focused validation does not establish Windows, full-suite,
Qt interaction, packaging, release, native comparison-engine, or real-corpus
acceptance. No Ghidriff, BinDiff or rz-diff engine was run. No broad suite,
stress test, tool provisioning, schema change, global runtime change, remote
mutation, target execution, backend wiring, or unrelated closure was performed.
The source-level #146 preservation is now concrete for independent root review;
source-head historical hosted checks are not relabeled as results of this tree.
