# Captured branch technical inventory

This read-only pass expanded all **364 captured live branch heads** against exact
main `fdc2696c23bdbfe7668348f25e3b336ce33039f7` and PR #348
`6b6fcd3597a604212032ffc453477aeb6edc69ff`. All 364 exact commit objects and
their required histories were available locally. There were **zero technical
inventory blockers**. The Git expansion ran from 05:30:47 to 05:31:00 UTC on
21 November 2026; this is separate from the earlier sequential REST capture.

## Publication artifact

Use **`technical-inventory.compact.json.gz`** for repository publication. It is
253,016 bytes and reconstructs the complete JSON inventory without information
loss. Its SHA-256 is
`f92aff6d25907458dee2d39953b17a296c6da9d7a94365119c56c940d6ee3a07`.

The 54,342,477-byte expanded `technical-inventory.json` and its ordinary gzip
are local intermediate representations; publishing those larger copies is
unnecessary. The compact form has 6,483 unique paths, 1,634 unique nonmerge
commit identifiers and 579 unique path/status sets. Repeated identifiers use
dictionary references; path sets use exact singleton indices and inclusive
index ranges. This is lossless encoding, not a sampled inventory.

Expand and validate it with:

```bash
python compact_inventory.py --expand technical-inventory.compact.json.gz --output expanded-inventory.json
```

The decoder verifies the expanded canonical JSON SHA-256:
`5d49e89d30e52b54bf65d42242f025cc448e58776fe361115368fdadc0835561`.
The compact artifact was expanded and compared with the complete original JSON
value before delivery. `summary.json` retains both original and compact hashes.

## Information recorded per branch

- Captured branch name, immutable head, Git tree and parent commits.
- Every merge base with main and PR #348, plus ahead/behind commit counts.
- Head-contained and baseline-contained ancestry flags.
- Unique nonmerge commit IDs relative to PR #348, retaining traversal order.
- Exact changed path/status lists from each merge base and from PR #348.
- Captured matching PR records, with an explicit exact-head-match flag.
- A link to each of the three existing scoped historical dispositions where
  both branch name and immutable head agree.

The capture contains 338 PR records. **337** join a captured live branch name,
and **303** of those joins also match the exact captured branch head. The one
unjoined record is merged **PR #8**, the disposable capability check, whose
`claude/access-test-1791774045` branch is absent from the live capture. Its old
head `48b944fa09c5e1f4946a7f38a4b54e521b4b1eeb` is also unavailable locally.
That missing historical PR head does not affect the complete 364-live-head
inventory. `summary.json` preserves its full normalized captured metadata.

Pure ancestry observations: main contains 129 captured heads; PR #348 contains
163. Forty-seven heads contain main, and four contain PR #348. All 364 share a
merge base with both baselines. These counts are **not semantic dispositions**.

## Classification boundary

No branch was declared duplicate, superseded, mergeable or deletable by this
metadata pass. All records retain `DISCOVERED` and an unset whole-branch
classification. Three exact branches link previously completed **partial**
behavior reviews; their excluded contents remain unreviewed. The other 361
records have no semantic disposition supplied by this pass. That annotation
count does **not** replace the existing authoritative semantic backlog or
invalidate earlier reviews stored elsewhere.

The PR input did not include fork repository identities. Name joins are
therefore accompanied by explicit SHA equality, not an assumption of common
repository ownership. REST pages were captured sequentially, not atomically.

## Method and scope

`build_inventory.py` records its own hash and all three input-file hashes. It
accepts explicit input/output paths for reuse. It invokes only Git object,
ancestry and path-list reads, with optional Git locks disabled, external diffs
and text conversion disabled, rename detection disabled, and at most two Git
subprocesses concurrently. No source, index, branch, remote state, target
binary or native analysis engine was modified or executed. No repository
pytest or native acceptance result is claimed.

Files for publication: this README, `summary.json`, `validation.json`,
`build_inventory.py`, `compact_inventory.py`,
`technical-inventory.compact.json.gz`, and `manifest.json`.
