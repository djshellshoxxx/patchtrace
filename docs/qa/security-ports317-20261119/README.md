# Independent security ports onto the saved-scope foundation — 2026-11-19

## Result and source

The focused Linux selection passed **608 tests, with 2 native Windows skips, in
187.78 seconds**. Required Ruff over `src tests tools` and `git diff --check`
passed. No blocking finding was confirmed in the inspected security changes.
This is a local source and integration review, not permission to bypass the
remaining hosted platform, native-engine, packaging or security gates.

Foundation: PR #317 `88b0b52281dd314aa72f93819145a73135618bc4`.
Reviewed/tested port source: `2d0fe17de977f2a0d7a346556aa8b8080abea8dd`, tree
`552c6ccc1a9318abd77b61399c3f95337fef493f`. This evidence-only follow-up does not
change that production or test source. The shared interpreter was Python 3.12;
`PYTHONPATH=src` resolved imports from the isolated worktree, not the main checkout.

## Selected source recovery

| Source | Foundation port | Content |
| --- | --- | --- |
| `78adfef0d9b13c841766508a0cbf590b0fdf69cc` | `124e048095524b983a6533dec4d98e87b94717f9` | #311 default child-environment specification and controls |
| `ad90a8c190f1d83450cd5f40b6fbf982705084f8` | `81ed96b067f8a80c814511c8ce8a44e6121d2a84` | #311 default restriction and explicit test opt-outs |
| `dfa4011819131002a24a790a876dfe0868c28b14` | `c5330a1a5ff3771b15d19df8a2f6c04cc076ea85` | #315 parser-level doctype contract and controls |
| `5f31e8adc7e53c5799cb9764f37ed33461529deb` | `0c2636ad9dff07c0f6cae0c3910d9c219833e9c0` | #315 parser callback refusal |
| `d4e5a59f6228134982cc51e9ed5b1cfe77a6b3ec` | `e2b4e347e3cad5c192233a7f734150e94c005c20` | #315 original regression receipts |
| `4fa4c54769765120ee5c7e4cc95660117fccbba6` | `f478b1aed9a6c1a525695e98a23433701f0cc393` | #313 sidecar read-budget contract and controls |
| #307 `58fc130631f602b6e907bb054d30c21d810551d4` | `91175f49476fabba50a45de8da8b5667548cd398` | Unchanged shared ownership module and controls, plus selective-port documentation |
| `8f4a18b5de2af0b7e895d9f363c07c81446ea917` | `88a043490af1f08a074663ee7a7c50681538bcd9` | #313 bounded verified advisory reads |
| `17174d4c609a1d9b7e71fc54fb614b361ffcfce7` | `2d0fe17de977f2a0d7a346556aa8b8080abea8dd` | #313 independent review and original receipts |

The advisory specification/test cherry-pick overlapped the end of
`docs/modules.md`. The resolution keeps the existing saved-scope row and the new
advisory read-budget section; it does not import the unrelated #307 inventory
module block that appeared as patch context. The foundation did not yet contain
`owned_publication.py`. That dependency and `test_owned_publication.py` were
recovered byte-for-byte from the published #307 source before applying #313's
implementation. The module index and CSAF specification describe this narrower
integration. KB workspace and winpairs publication callers were not rewired.

Original source evidence is preserved separately from this replay's result:

- [Primary environment receipts](../primary-environment-20261118/README.md),
  recovered from `09b032f205f4ffa1838bef56007ebdb7a2308420`.
- [Reviewed manifest parser receipts](../manifest-dtd-reviewed-20261118/README.md),
  recovered from `23fbe4a54880319f62f40f3196794f85b6cdaec5`.
- [Shared ownership receipts](../autonomous-ci-20261118/object-publication/README.md),
  recovered from `4b12c5e547bb1abb6a255389a42c159e348581f7`.
- [Advisory read-budget report](../advisory-read-bounds-20261118.md),
  recovered from `a4061979547ef88855fbdb085228a42c3be21603`, together with the
  [independent review](../advisory-read-bounds-independent-20261118.md) already in
  the port chain.

These documents retain their historical source identities, results and blockers.
They are not relabelled as tests of the final combined candidate. Recovery checks
compare their bytes with the source Git blobs and validate the copied archives'
digests and member hashes. Shared `docs/qa.md` and `tasks/todo.md` append-only
history is left to the integrating owner to avoid importing unrelated completion
claims or duplicate history.

## Boundary review

**Child environment.** `BackendConfig` and both absent-setting GUI readers now
agree on restricted inheritance. The existing allowlist is unchanged; automatic
proxy/CA inheritance still follows explicit online symbols. Explicit saved
`False`, direct configuration, validated named passthrough and external-only
inheritance compatibility remain intentional choices. Bundle mode continues to
force restriction. Test fixtures that deliberately exercise unrestricted secret
redaction or a heartbeat request that behavior explicitly, retaining the original
assertions. No settings migration is performed.

**Manifest parser.** The bounded manifest parser rejects parser-recognized
doctypes through the XML builder callback, including encodings and whitespace
that the previous decoded-text screen could misinterpret. The pure-Python
ElementTree fallback also installs its exposed doctype handler. Normal XML
parsing, malformed XML refusal, input bounds and target-file handling are
unchanged; no external entity resolver or network access is introduced.

**Advisory sidecars.** Reads enforce a positive byte cap before content
allocation, use a regular held descriptor and validate the SHA while held.
Normalized sidecars are capped at 64 MiB, raw recovery uses the recorded source
size, and idempotent reuse uses the incoming object's exact size. Oversized
normalized output is rejected before any import sidecar or pointer write. Linux
no-follow opens and post-read identity/change observations reject links and
observed parent/leaf substitution. Windows rooted opens reject reparse processing
and deny write/delete sharing for the evidence handle. Unsupported ownership
primitives fail closed. Valid facts-cache recovery and the existing damaged-cache
repair policy remain. This does not qualify cumulative I/O, parsed-model memory,
broader publication replacement races or selected-root changes before capture.

## Reproduction

From the isolated foundation port worktree, using the project's prepared
interpreter:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_primary_environment_defaults.py tests/test_child_env.py \
  tests/test_backend_bundle_env.py tests/test_network_consent_symbols.py \
  tests/test_network_consent_secrets.py tests/test_unified_extract_runner.py \
  tests/test_advisory_read_bounds.py tests/test_intel_storage.py \
  tests/test_intel_explain.py tests/test_intel_reports.py tests/test_intel_cli.py \
  tests/test_owned_publication.py tests/test_pe_manifest.py \
  tests/test_pe_manifest_dtd_boundary.py \
  tests/test_research_qualification_winpairs_publication.py \
  tests/test_spec_registry.py
python -m ruff check src tests tools
git diff --check
```

The [manifest](manifest.json) binds the [raw receipt archive](evidence.zip), source
hashes, exact commands and environment details. Test totals from overlapping
historical runs must not be summed with this selection.

## Independent adjacent review

The foundation's saved-scope controls had already passed **91 tests in 49.33
seconds** on unmodified `88b0b522`. Review found no blocker in full-index admission
before finite projection, saved coverage coherence, recovery preflight, or
source-sensitive revision identity. This is a scoped foundation recommendation,
not a whole-product correctness claim.

The integrating owner's Windows fixture repair at
`780175c94122e6d8cef06a75932275064ca6f628` was independently inspected. Copies are
opened after held project readers close; authored SQLite writers close before
replacement; source mutation remains the same size; symlink assertions use the
stored target; and C failure fixtures still reach real read-only descriptors.
Namespaced Win32 stubs avoid accidental host CRT interception. The two portable
C harness modules independently passed **57 tests in 30.26 seconds**. These are
Linux-authored fixture controls, not a native Windows run.

The persistence creation repair `d1deefb68704f8fe761c759c580ac152f2a7ad5e`
(integrated as `67cdc0e946ac46bea5e01b608afedc585078f680`) was also inspected.
Regular-file, single-link and bounded-file admission remains; common physical
fields bind descriptor and pathname, while descriptor-to-descriptor and
pathname-to-pathname change-time checks preserve mutation refusal. No scoped
regression was confirmed. The new stat-view controls independently passed
**9 tests in 2.69 seconds**. Native Windows behavior remains a hosted gate.

## Remaining gates

Both skips in the 608-test run are **BLOCKED on this Linux host**: native Windows
sharing/held-handle replacement behavior and native reparse-attribute mutation.
Portable call-level assertions do not replace either test. The default-primary
environment specification also requires actual-candidate Linux and Windows
primary-engine qualification, including raw-cache hits and authored secret/JVM
injection sentinels, before promotion. That qualification was not performed here.

The eventual combined source still needs its full exact-head Linux and Windows
suites, native engines, security checks, frozen package and applicable GUI
acceptance. No target binary was executed, external source acquired, branch
pushed, PR merged, release created, or accuracy claim made by this review.
