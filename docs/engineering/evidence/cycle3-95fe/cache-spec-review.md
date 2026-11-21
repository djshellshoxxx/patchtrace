# CODEX-6 independent specification review

Reviewed `/workspace/scratch/patchtrace-95fe-c3/cache-review` at **53e02a478235498563a092d7943c7feaf40adda6**, tree **34acedca0fc524a20a8def6be4b18e909ea2f772**, against PR #348 base **6b6fcd3597a604212032ffc453477aeb6edc69ff**. Read `AGENTS.md`, the relevant `docs/modules.md` Tier R entries, and the known-answer-corpus amendment. Worktree was clean before and after inspection. No source/ref changes, test duplication, native-tool execution, or downloads were performed.

## Blocking findings

**None found in the reviewed implementation.**

- `docs/specs/known-answer-corpus.md:396–407` requires “original immutable tool archives,” verification “including cache hits,” and a “fresh directory.” Workflow lines 92–111 and 120–140 restore archive directories, download only missing archives, validate source-pinned 64-hex digests, hash the same paths later extracted, and perform cleanup only after successful verification. `set -euo pipefail` stops corrupt archives before cleanup. No cache-hit bypass or failure suppression is present.
- The amendment at lines 409–414 requires new archive-specific namespaces without old-key fallbacks. Both cache paths/keys use `*-archive` / `*-archive-v1-${digest}`; no restore-key fallback exists. Rizin remains mandatory and Ghidra/Java remain conditional on Ghidriff. The separate Ghidriff pip install is unchanged and explicitly outside the archive-pin claim.

## Test scope and limitations

The maintained admission test examines each named restore/install step and checks archive binding, verification-before-extraction, cleanup, namespaces, and Ghidriff conditions. The repair supplies the previously incomplete rizin install-step heading; the Ghidra heading was already composed correctly, and both full headings are now stored explicitly. The added `admission_errors(original) == []` precondition prevents the 14 mutation cases from passing because of an unrelated baseline error.

The four Bash fixture cases select the actual workflow scripts and exercise valid/tampered authored xz/ZIP cache hits. Valid cases require stale-tree removal and expected extraction; tampered cases require failure with the stale tree preserved, establishing digest-before-cleanup. Curl is replaced by a refusing shim; the Ghidriff install line alone becomes a no-op. These fixtures do not execute extracted contents.

The admission checker is textual, and the fixture launcher does not exercise Actions-level conditions or cache restore/save semantics. Missing-archive downloads, upstream availability, actual native runtimes, and the external Ghidriff install remain outside this evidence. A hypothetical added `continue-on-error` would require an additional workflow control; no such setting exists now.

Per specification lines 416–421 and `docs/engineering-handoffs/codex6-cache-hit-fixture-20261121.md`, source-specific hosted Tier R verification, including a repeated real cache hit and separate Ghidriff path, remains required. Test/Ruff outcomes are owned by the root reviewer; this report independently inspects their scope without claiming another execution.
