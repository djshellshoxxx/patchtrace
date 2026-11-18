# Autonomous repair and qualification checkpoint — 2026-11-18

## Decision and exact state

Canonical `main` remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`.
PR #304 is open at `d8c02caea407f6d323eecd636735849c1eb31a2d`.
The combined #307 repair source reviewed here is
`9002a1f44c6aebcf2c49b29d631aacf20e7ce9e3`, tree
`9f38ab7cd074469238851aadb19536d1d366d9da`. It preserves the old #307
`1418617a80d6057de11f985488cfe6043a7787a2` and published #304 heads as
actual merge ancestors. This checkpoint is a documentation append to that
source. REST publication records the corresponding commit mapping separately;
qualification must follow the final published head before merging.

No PR has been merged or closed during this checkpoint. All remote branches,
historical failures and frozen research outcomes remain preserved. Every new
integration commit includes `[no release]`. No tag, release or deployment is
created. The candidate is not beta-ready.

## Reviewed repairs

| Scope | Exact implementation source | Result and independent review |
|---|---|---|
| Windows research publication | `e250f683c9f1770639772e33142978f4c3bd0575`; published in #304 | Directory handles share read/write while denying delete; staged sources continue to deny write/delete. Original hosted ERROR_SHARING_VIOLATION failures and authored red controls are retained. Native Windows remains a required gate. |
| Chronology assertions | `1fa724d69cb03bc2796dfa8845f3d99c1c3664ba`; published in #304 | Align the obsolete expectation with the already implemented architecture-scoped partial order; retain both tied variants, ambiguity and direct tied-peer refusal. No production rollback or reduced assertion. |
| Inventory golden manifest and actual tooltip coverage | `27b93eb7a13cde8ccd156a3caa174c4fa8b72d1b`, `010b9e6170b9a882556d11aed0a3186873cd216f` | Register both immutable fixtures and construct the actual inventory dialog in the existing global sweep. Independent mutations of real status/tab tooltips still fail. |
| Owned advisory/inventory objects | `68aa6a5063172a2f46dce48a4373397f3f4ec95e` plus `01d92af145fde5cf776a36803725775cbbc54564` | Reuse one stdlib platform primitive for rooted reads and no-replace publication. Preserve matching compressed bytes; refuse corrupt, replaced, linked, missing referenced or read-only evidence. Independent review reproduced real-root and selected-alias drift; captured root identity and resolved SQLite/object paths now agree. |
| Research Ghidriff ranking identity | `5936896e452789a565e656ab8491620f78c55705` | Validate every supplied side, label, address and ranking field before filtering; reject duplicate keys and conflicting identities; retain valid decorated Markdown changes. Independent parser and actual CLI-child controls passed. This is not native matching accuracy. |

The source author retained red/green receipts for each behavioral repair. Root's
independent storage controls cover concurrent same/different writers, FIFO
refusal, parent replacement during a read, leaf loss after validation without
recreation, unavailable anonymous staging, retargeting at SQLite open, and
multi-member gzip preservation/refusal. The extra Ghidriff controls cover
side-relative address reuse, canonical key-order repeats, all six permutations
of an ambiguous report, one-sided endpoint ownership, duplicate metadata keys,
decorated Markdown and a source-pinned CLI refusal with no partial stdout.

The shared publication helper retains the research wrapper's tested seams;
production KB modules import only the five explicitly authorized stdlib adapter
symbols. Existing schemas, v1/v2 capacity semantics and source identities remain
unchanged. The native Windows existing-object sharing control joins the mandatory
publication prerequisite; no gate or assertion is weakened.

## Executed verification and limitations

| Actual command/scope | Result | Source |
|---|---:|---|
| Combined KB, research, production normalizer, publication and global-tooltip selection | **2,866 passed, 4 skipped in 71.96 s** | Exact combined `9002a1f4` |
| Independent owned-publication controls, repeated on the combined source | **8 passed in 0.36 s** | Exact combined `9002a1f4` |
| Independent research Ghidriff controls including actual CLI child | **8 passed in 0.32 s** | Reviewed parser `5936896e`; the same parser blob is in the combined source |
| Published #304 focused publication/chronology gates | **170 passed, 2 skipped in 1.93 s** | Actual published `d8c02cae` checkout |
| Whole repository Ruff and whitespace | **Passed** | Combined source |
| Local #304 full-suite attempt | **Incomplete, exit 137; no final JUnit** | Preserved raw log; no full-suite pass or cause is inferred |

The four combined skips are native Windows existing-object sharing, native
Windows ancestor/source sharing, native Windows reparse mutation, and optional
`psutil` resource measurement. None is credited as acceptance. The earlier
mistyped focused invocation exited 4 without tests; its log is preserved beside
the corrected result. Selections overlap and must not be summed.

The reused environment has an editable install pointing to an older checkout.
In-process pytest imports were governed by the repository configuration, but an
unpinned child could import the old tree. The combined run and independent child
checks explicitly use the current absolute `PYTHONPATH`. Earlier unpinned receipts
are preserved with this limitation. The Ghidriff author also appended a correctly
pinned **621 passed / 3 skipped** repeat without removing the original evidence.

The combined command was:

```sh
PYTHONPATH=/absolute/path/to/candidate/src QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_kbc*.py tests/test_kb_*.py tests/test_research_qualification*.py \
  tests/test_evalcore_ghidriff_one_to_many.py tests/test_normalization_address_identity.py \
  tests/test_owned_publication.py tests/test_tooltips.py --junitxml=affected.xml --tb=short
python -m ruff check src tests tools
git diff --check
```

## Fresh hosted evidence on #304

The refreshed check snapshot is associated with head `d8c02cae`. Actual source
checkout in the Windows Ghidriff job is merge preview
`f756d7f151857755c993ebeb95f7a27e1487b9d4`; REST confirms its tree is
`ee85c94f12c8c52952ca0ced7b0f481e0ef2d674`, exactly the published head tree,
with recorded parents current main and that head. This is source-tree evidence,
not acceptance of a different implementation.

- Rizin Linux job **134854114336**: pinned 0.9.1, `mocked: false`, status passed,
  30 fixture matches, engine status ok and no reported errors.
- Rizin Windows job **134854114854**: pinned 0.9.1, `mocked: false`, status passed,
  322 fixture matches, engine status ok and no reported errors.
- BinDiff Linux job **134854104185**: one actual live test passed; provision and
  live receipt statuses both passed. Windows BinDiff remains separate.
- Ghidriff clean Windows job **134854121881**: actual primary comparison exited
  zero in 123.531 seconds; the harness accepted the known bounds-check fixture.
  Its raw report contains one modified `read_item` pair with code/length/signature
  changes. The downloaded artifact **14434809753** has SHA-256
  `d2ad8ac8d0a5edc423bee009c53e919e9b3274b40dafec865227d1e70bb57e2e`, matching
  the upload log. The runtime receipt still labels the JVM version unverified.

Full Linux/Windows QA, repeated Qt, the other Ghidriff hypotheses, unified/native
acceptance, optional-wheel checks, packaging and dependency/security qualification
are not completed by these four receipts. The PR-only skipped release-cadence job
is not a release pass. No native fixture receipt rescored a frozen corpus or proves
CVE-fix attribution. All four logs, source proof and the Ghidriff artifact are
retained in the archive.

## Branch audit, separate work and next gates

The original mechanical inventory covers 307 branch tips and 297 PR records at
its timestamp, with merge bases, patch equivalence, file projections and conflicts.
It does not claim exhaustive semantic review of 131 reconciliation candidates.
The later REST refresh covers **all 55 then-open PRs**, including newly created
#308. All 55 review and inline-review-comment collections were empty; independent
review is documented in source-pinned receipts, not inferred from those empty
collections. Each then-current head's check runs are captured. Historical/stale
checks are not present-head approval. No superseded PR is closed before proof in
canonical main.

Separate reviewed or active slices are intentionally kept out of this #307 source:

- Strings publication PR **#308**, published `92a411bf02fc8beb00b7a148e39db2bf68efa061`:
  unique exclusive staging, no-replace non-forced exports, safe cancellation;
  34 focused passes plus nine independent controls. Full/native gates and
  document-level extraction metadata remain open.
- Paired raw-offset desktop source `e4506666edefbbc22419ff97874e3edc599f94e7`:
  independent 183-test affected/headless run and six additional clipboard,
  orientation, revision and late-worker controls pass. A focused follow-on PR,
  combined gates and native/manual UI acceptance remain.
- Saved/recent search source `e705974b0c8a13be0942a172b93bb1cdfa74895f`:
  374 affected tests pass; independent review is pending. Saved rows remain
  project-owned; recent text follows the existing explicitly per-user contract.
- Seven authored failures show pilot assessments can be mislabeled current after
  a manual pair withdrawal or superseding advisory, plus a desktop KEV freshness
  discrepancy. A separate shared CLI/desktop staleness repair is assigned.
- Release publishing lacks mandatory exact-source native/security qualification;
  a fail-closed shared checker is assigned. Existing scans are not fabricated.
- Historical #121's default primary-engine environment inheritance is reproduced
  with dummy values only; a separate environment-isolation repair is pending.
  Primary resource caps and the missing CVRF-to-pilot bridge remain separate.

Next: publish this reviewed #307 chain append-only; qualify actual published heads;
merge #304 into main only when all applicable gates pass, then retarget/requalify
#307. Preserve all branches and use SHA-guarded `[no release]` merges. Continue the
independent analyst, staleness, release and environment slices while external
qualification is pending. L1's 73 PASS/6 FAIL/8 excluded, L2's original MISS/FAIL and
L3's unverified acquisition state remain unchanged.

`manifest.json` hashes the source boundary and every archived receipt. `evidence.zip`
contains the complete raw evidence for this checkpoint.
