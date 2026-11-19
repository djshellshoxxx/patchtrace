# Windows QA fixture portability: exact bytes and Linux inventory names

The bounded repair is source **`81590f936b3f01555720221e55f99ec0611ec4a1`**,
after spec/control commit **`24651bf5d85c42c65cf207991258ce5d3fe4825e`**, on
baseline **`f16d41062a5d558d889ef6a6bda922004e0ac3b4`**. It adds no validator,
native capability, skip, xfail, weakened assertion, dependency upgrade, workflow
change or release action. The original Windows full QA remains failed.

## Changes and responsibility

| Owned path | Concrete change |
|---|---|
| `tests/test_release_qualification.py` | The shared authored checkout writes its declared LF source as exact bytes. Its existing local `core.autocrlf=false` setting remains. |
| `tests/test_release_source_stat.py` | Five new controls model host CRLF text output and replay the original positive/final same-size mutation assertions. |
| `tests/test_dependency_security.py` | The positive evidence fixture writes exact UTF-8 LF bootstrap/audit requirements; its tiny authored source uses binary LF and local `core.autocrlf=false`. Five controls exercise CRLF and isolated true/false global Git normalization. |
| `tests/test_windows_bindiff_network.py` | Only the authored Git fixture construction changes: binary LF and local `core.autocrlf=false`. A new control replays its original untracked-implementation refusal under normalizing host defaults. |
| `tools/build_linux.py` | Exactly one projection changes: `str(p.relative_to(package))` becomes `p.relative_to(package).as_posix()`. |
| `tests/test_linux_frozen_smoke.py` | Nine controls retain real inert file iteration while returning Windows-style relative path objects, covering successful full smoke, exit/timeout and required-resource refusal. |
| CI integrity spec, module index, delivery tracker | Define the exact-byte fixture and slash-separated Linux inventory contract and retain pending native qualification. |

The one tool line belongs to the production Linux builder, not its fixture.
It preserves native Linux inventory spelling/bytes and all iteration, regular
file, unwanted-library, extension, exact extractor/launcher, smoke and archive
conditions. It does not make the Linux builder cross-compile on Windows.

`verify_source_boundary.py` mechanically checks the exact Git delta. The
`source-boundary.json` receipt confirms **144 original assertions and 110
original test identities/decorators**, original context-manager predicates,
unchanged source/receipt validators, unchanged `src` and native C, and exactly
the one authorized tool-line replacement. All existing test signatures are
also rechecked by the retained verifier. This structural verification supplements
the behavioral tests; it is not a native compatibility claim.

## Spec-first and exact-source results

| Retained run | Exact source | Result | Meaning |
|---|---|---|---|
| `red.*` | `24651bf5` | **19 failed, 1 passed**, zero skips/errors | Genuine pre-repair host-newline/Git/inventory reproductions; 42 pinned project/tool imports, no drift or denied attempts. The positive is the already-correct missing-extension refusal. |
| `green.*` | `81590f93` | 19 passed, 1 runner refusal | The corrected fixture reaches the existing local `git cat-file -e` ownership check, which the first audit allowlist omitted. Original output and runner retained; not a product regression or a green gate. |
| `green-v2.*` | `81590f93` | **20 passed**, zero skips/errors | Only that inspected read-only local Git command was added to the recorder allowance; 42 pinned imports, no drift/denied attempts. |
| `affected.*` | `81590f93` | 677 passed, 8 skipped, 1 runner refusal | The adjacent replacement-object negative control requires `git update-ref HEAD <sha>` in its owned temporary repository; the recorder initially omitted it. Original output/runner retained. |
| `affected-v2.*` | `81590f93` | **678 passed, 8 skipped** in 3.09 pytest seconds | Corrected finite recorder admits only that HEAD/full-lowercase-SHA form under owned temp; 69 pinned imports, no drift/denied attempts. |

Every one of the **eight skipped controls requires actual Windows metadata or
native Windows final observations**. Their exact node IDs/reasons are retained
in `test-results.json`; they remain unverified here. No assertion was changed or
platform-skipped to make this repair pass. The normal workflow command
`python -m ruff check src tests tools` and whitespace checks passed.

The exact affected argv is in `affected-v2.command.json`. It selects eight
files: the five owned test files above plus
`test_dependency_security_bootstrap.py`, `test_build_full_variants.py`, and
`test_spec_registry.py`. This is a bounded neighboring gate, not a whole-suite
rerun. No unchanged broad runner was resumed.

## What the portable controls establish

The CRLF model uses actual `Path.write_text(..., newline='\r\n')`; it does not
pretend that Linux is Windows or change file metadata observations. The source
witness proves that the model produces CRLF. Existing same-size/final-change
assertions run unchanged using the real host metadata path. Scanner fixture
tests require the original complete evidence validator to pass only after the
declared requirements are authored as exact bytes.

The tiny Git controls supply a new owned global configuration with
`core.autocrlf=true` or `false` and `core.eol=crlf`, then inspect both actual
working bytes and committed blob bytes. The fixed repository pins its local
normalization before staging. Existing held-commit publication refusal,
canonical-byte ownership, replacement-object, hidden-index and untracked-source
negative controls still execute against the unchanged validators.

The Linux inventory model retains real owned directories/files and regular-file
iteration; it changes only the relative path object's spelling to
`PureWindowsPath`. Complete resource checks and the existing injected smoke
runner must still execute. Missing/changed extractor or launcher, missing upb,
an unwanted Qt library, smoke failure and timeout all refuse before archiving.
No PyInstaller, package executable, engine or target was launched by that model.

## Historical Windows failures stay separate

The original immutable packet is
`qa/hosted-pr316-771e-windows-qa`, source
`771e5a775f5bf60a8d9094232b51dcdbb47d6389`, preview
`ac6632ad6de486ba16343f0eeb4a2b5a446e4ac1`, tree
`ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`, job `135175350823`.
Its archive SHA-256 is
`22d8e0e7acb7014104d3f1c8457b05c5c95ba22e43e532ddbe05536381650d6c`.
`hosted-original-preservation.json` rechecks that original archive and artifact
without changing them. That result remains **51 failures**.

This slice addresses the mechanisms corresponding to eight explicitly
CRLF-sensitive source-stat cases, two exact bootstrap-fixture byte failures,
and five Linux inventory fixture path mismatches. The two historical tiny Git
source-size failures **W22 and W50** did not retain their effective settings and
both byte sequences. `modeled-git-normalization.json` and the raw fixture-byte
receipts distinguish the new controlled reproduction from those unresolved
captured causes. No corrected Windows result is invented or inferred.

Root separately owns formatter W51 diagnostic observations; its original
count/error predicate remains unresolved on Windows. The independent static
review lives in `qa/formatter-predicate-observations/independent-review.md` and
is sealed separately by root. Core creation/replacement/held-input cleanup and
symlink W49 ownership remain assigned to the other reviewer. This branch does
not edit those sources or claim to resolve their failures.

## Finite execution and retention

Each run pins the exact current source, snapshots owned/neighbor files, and
checks every imported project/tool module against its Git blob. Authored fixture
scratch is created under a fresh owned `/tmp` directory outside any Git tree.
After extracting raw byte receipts, only that completed owned scratch is removed.
All old branch heads, hosted packets, source snapshots and failure records remain.

The affected recorder allows local Git operations only inside its owned scratch,
with `GIT_ALLOW_PROTOCOL=file`, and blocks network and unknown child attempts.
Its exact reviewed child list is retained: **392 local Git commands**, **five
fixed stdout/stderr/exit/output-limit Python probes**, **one owned pipe-producer
lifecycle probe**, and **three calls to the byte-verified authored fake BinDiff
script in its fixed `ok` mode**. Those scripts contain no active network or target
execution path. They are authored simulations; parent audit records do not claim
a general sandbox for arbitrary descendant programs or native compatibility.

The two recorder omissions are retained with their respective source and runner
hashes; adding the precise inspected commands does not suppress their original
outcomes. Source-control read attempts for nonexistent exploratory helper paths
are recorded separately in `inspection-notes.json` and carry no test credit.
All publishable evidence is hashed in `manifest.json` and verified in
`evidence.zip`; exact source chain/patches and replay scripts are included.
This packet contains no signed transfer URL or remote mutation receipt.

Root independent source review and a fresh exact-source hosted Windows/full
gate remain the next acceptance boundary. Native PW02 staging remains a separate
approved workstream and supplies no credit to this fixture repair.
