# CODEX-6: verified original archive caching in Tier R

Date: 2026-11-21 (UTC). This isolated branch starts at PR #348's immutable
head `6b6fcd3597a604212032ffc453477aeb6edc69ff`. See the normative
[known-answer corpus specification](../specs/known-answer-corpus.md),
`AGENTS.md`, [the original audit](../audits/codex-workflows-1.md)
and [the authoritative ledger](task-ledger.json).

## Source defect and narrow repair

The previous Tier R shard workflow cached extracted rizin and Ghidra
directories. On a cache hit the rizin installation was skipped entirely,
and Ghidra installation skipped archive download and digest verification.
The digest in an Actions cache key was not a check of the recovered bytes.

The repair caches `rizin-archive/` and `ghidra-archive/`, containing
the *source archives*, not extracted tool trees. Both install steps run on
every applicable shard, verify their source-pinned SHA-256 archive digests
on cache hits and misses, then remove the destination extracted directory
before unpacking. Missing archives download from the existing pinned URL,
while corrupted cached archives fail at SHA-256 comparison before
extraction; they are not silently replaced. Ghidra/Java remain conditional
on a Ghidriff engine, and Ghidriff's Python installation is unchanged.
No other workflow, tool runtime, corpus output or engine identification
logic changed.

The CODEX-6 test in `tests/test_codex_pkg_workflows.py` was promoted from
strict xfail to a passing source contract. New
`tests/test_corpus_cache_archive_integrity_20261121.py` checks
archive-only cache paths, obligatory pre-extraction digest verification,
clean extraction, pinned archive identity and conditional Ghidra.
Fourteen mutation cases refuse removal of these boundaries. The existing
CODEX-1 and CODEX-5 strict xfails remain unchanged.

## Evidence / qualification

- Connector-fetched workflow blob after patch:
  `c15784337596d03de29a144980312872830b8aa4`.
- Author-side JS source inspection: **14 structural invariants pass**.
- Fourteen mutations of the exact fetched workflow were passed through a
  separate JS implementation of the source contract: **14/14 detected**.
  These are not pytest runs or an independent peer reviewer.
- An isolated **synthetic** shell replay with small fixture archives
  demonstrated both positive checksum+extraction cases and both negative
  cache-hit corruption refusals. No native rizin, Ghidra, owned corpus,
  target binary or live archive was downloaded/executed.
- No complete repository checkout is mounted in this runtime; shell
  GitHub DNS does not resolve. Exact-source pytest, whole-tree Ruff,
  workflow YAML engine validation, hosted Tier R with rizin and Ghidriff,
  separate independent review and peer signoff are **not complete**.
- PR #348 still has an active Windows QA job at last inspection. PR #347
  original QA/Qt/native/package/both Linux smoke passed; PR #345's
  single failed-job retry of external Chocolatey NSIS 503 now completed
  successfully. Those ancestor results do not qualify this new source.

## Follow-up acceptance

On a clean checkout of this exact branch run:
`python -m pytest -q tests/test_corpus_cache_archive_integrity_20261121.py
tests/test_codex_pkg_workflows.py`, followed by
`python -m ruff check src tests tools`, `python -m pip check` and the
offscreen/full suite under a supported runner. Obtain a truly separate
review of archive cache key binding, malformed digest refusal,
cache-hit replay, xz/ZIP extraction and Ghidriff condition. Run
rizin-only and Ghidriff-enabled Tier R shard CI; GitHub Actions PR
path filtering may not run Tier R for a test-only change, so explicit
workflow qualification must be associated with this exact commit.

Do not remove the other security strict xfails, force-push, rebase
another owner, rewrite the PR #348 branch, or delete old donor refs.
No main merge, publication or release is authorized without independent
review and every applicable green current-source check. Historical
181 unmatched/16 patch-equivalent heads, full raw membership,
Windows manual/trust/accessibility and L1/L2/L3 evidence remain open.

### Cache namespace migration review

A second inspection found that keeping the historical cache keys would
restore old *extracted-directory* payloads despite the new `archive/`
path. Actions/cache would regard those keys as hits and never save the
new archive directory. The specification was amended before tests and
workflow code: only `rizin-archive-v1-${{ env.RIZIN_SHA256 }}` and
`ghidra-archive-v1-${{ env.GHIDRA_SHA256 }}` may restore. No fallback to old
keys is configured. Two more negative mutations explicitly refuse reuse of
extracted-cache keys; new workflow blob is
`c15784337596d03de29a144980312872830b8aa4`.
