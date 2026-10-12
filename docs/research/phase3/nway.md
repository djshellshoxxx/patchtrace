# N-way comparison: comparing three or more builds of one binary

Research date: 2026-10-12.
Verification labels:
- **[src]**: I read the source or docs at the pinned revision.
- **[run]**: I ran it.
- **[inf]**: inference that I did not verify.

I did not run Ghidriff, because no Ghidra install was available in this container. All Ghidriff findings come from reading source.

## Ghidriff at `4f5d895fcbb1eacd65efd81145922c15bb7e741d`
Repo: https://github.com/clearbluejar/ghidriff. `git describe` gives `v1.0.0-6-g4f5d895`. Licence: GPL-3.0. Depends on `pyghidra>=3.0.0,<4` (setup.cfg).

### Inputs: more than two files, but it only ever diffs pairs [src]
- **Arguments** (`ghidriff/parser.py` L23-34):
  - `old` takes exactly one positional argument (`nargs=1`).
  - `new` takes one or more (`action='append', nargs='+'`), with help text "For multiple new binaries add oldest to newest".
  - `--summary` adds "a summary diff if more than two bins are provided".
  - `--engine` defaults to `VersionTrackingDiff`. The other engines are `SimpleDiff` and `StructuralGraphDiff`.
- **Pairing logic** (`ghidriff/__main__.py` L85-107):
  - All N binaries are imported and analyzed into one Ghidra project.
  - It diffs **adjacent pairs only**: `(p[i], p[i+1])` for i = 0..N-2.
  - With `--summary` and N > 2 it also diffs `(p[0], p[N-1])`. The guard is `binary_paths[1] != binary_paths[-1]`.
  - It does **not** do all-pairs or joint N-way matching.
  - Each pair is an independent `diff_bins(old, new)` call. No match state carries from one pair to the next.
- **Output per pair:** `name = f"{old.name}-{new.name}.ghidriff"`, giving:
  - `<out>/<name>.md`
  - `<out>/json/<name>.json`, the full pdiff
  - `<out>/json/<name>.matches.json`, written by `dump_pdiff_to_path` with `write_matches=True` by default (`ghidra_diff_engine.py` L1966-2030)
  - `<out>/sxs_html/...` with `--sxs`
- **Name collision [inf]:** two inputs with the same basename (e.g. `afd.sys` in different folders) produce colliding output names and Ghidra project entries. PatchTrace should rename inputs (e.g. `afd.10.0.26100.9444.sys`) before invoking.

### Match metadata emitted per pair [src]
- **`matches.json`** (`ghidra_diff_engine.py` L1542-1551) covers **all** matched function pairs, including unchanged ones:
  ```
  { "address_matches": { "<old addr str>": [ ["<new addr str>", [match_type,...]], ... ] },
    "name_matches":    { "<old full name>": [ ["<new full name>", [match_type,...]], ... ] } }
  ```
  - The value is a **list**, so one old function can map to several new ones. Correlators flagged `one_to_many=True` (StructuralGraphHash, BulkBasicBlockMnemonicHash) can produce this.
  - There is **no** score, ratio or confidence per match, only the match-type names.
- **`functions.modified[]`** in the main JSON covers only pairs that needed a deeper diff and showed a difference (L1666-1769). Each entry has:
  - `old` and `new` (enhanced symbol: `name`, `fullname`, `address`, `length`, `sig`, `refcount`, `calling`, `called`, `parent`, `code`, …)
  - `diff` (unified text)
  - `diff_type`, a subset of `code`, `name`, `fullname`, `refcount`, `length`, `sig`, `address`, `calling`, `called`, `parent`
  - `ratio`, `i_ratio`, `m_ratio`, `b_ratio`: difflib `SequenceMatcher` ratios rounded to 2 places, computed on decompiled code without the signature, instructions, mnemonics and basic blocks respectively
  - `match_types`
- **Unchanged matched functions** appear only in `matches.json` and in counts. `syms_need_diff` skips them, so they get no ratios.
- **`stats`:**
  - `match_types` (a Counter of every type) and `first_matches`
  - `matched_funcs_len`, `matched_funcs_no_changes_len`, `unmatched_funcs_len`
  - `match_func_similarity_percent` and `func_match_overall_percent`, which are **strings** like `"97.1234%"` (or float `0.0` if the denominator is 0)
  - plus others
- **Match-type strings** (`version_tracking_diff.py`, `correlators.py`):
  - `SymbolsHash`, `ExternalsName`
  - `ExactBytesFunctionHasher`, `ExactInstructionsFunctionHasher`, `ExactMnemonicsFunctionHasher`
  - `StructuralGraphExactHash`, `StructuralGraphHash`
  - `BulkInstructionHash`, `BulkMnemonicHash`, `BulkBasicBlockMnemonicHash`
  - `NamespaceNameParamHash`, `NameParamHash`. Both `NameParamHasher` and `NameParamRefHasher` use this name (correlators.py L227 and L249), so they cannot be told apart.
  - `SigCallingCalledHasher`, `StringsRefsHasher`, `StrUniqueFuncRefsHasher`, `SwitchSigHasher`
  - `BSIM`, `Implied Match`, `Decomp Match`
  - The list order in each match roughly follows correlator strength, strongest first. `first_match = match_types[0]`.
- **Addresses:** stored as Ghidra address strings with no `0x` prefix. They depend on image base unless `--base-address` is used.

## Ghidra Version Tracking
- **Two programs per session.** A session results from running correlators "against two binaries" (source and destination) [src: Ghidra help `Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html`, master].
- **No N-way session.** The usual workaround is to chain sessions and port markup forward (A→B, then B→C) [inf].
- **Scores:** VT matches carry a similarity score and a confidence score in the GUI and API [inf from Ghidra API knowledge; not re-verified]. Ghidriff does not export them.

## Diaphora
- Version 3.4, at https://github.com/joxeankoret/diaphora @ `de0eb920c1e54649bb3e7c4df5fa058b5c2cdc91`.
- **Licence:** AGPL-3.0, with commercial licences available [src README].
- **IDA only:** it works as an IDA plugin (IDA ≥ 7.4) [src README L15-17]. There is no Ghidra exporter in the repo.
- **Pairwise:** each diff takes one primary and one secondary SQLite export.
- **Results DB schema** (`diaphora.py` L2395-2403):
  - `results(type, line, address, name, address2, name2, ratio, nodes1, nodes2, description)`, unique on `(address, address2)`. `type` is one of `best`, `partial`, `unreliable`, `multimatch`.
  - `unmatched(type, line, address, name)`, where `type` is `primary` or `secondary`.
  - This is per-pair `ratio` metadata that could support transitive reasoning, but it needs IDA.

## BinDiff
- **Pairwise:** one primary and one secondary `.BinExport` (see binexport-bindiff.md).
- **Batch mode:** if `--primary` is a directory, BinDiff runs `BatchDiff` [src: `main_portable.cc` L349-395, L650-659 @ `13c437a`].
  - It builds **all ordered pairs** (i, j) with i ≠ j of the `.BinExport` files in the directory, which is N·(N−1) diffs, with both A→B and B→A.
  - If `--secondary` names a reference file, it diffs only reference→others.
  - Output goes to the directory itself unless `--output_dir` is set.
  - Pairs are diffed with a thread pool and still independent of each other: there is no joint N-way matching.
- The per-pair SQLite file has a `similarity` and `confidence` for each function plus an `algorithm` id, which makes it richer for transitive hypotheses than Ghidriff.

## Pitfalls of chaining A→B→C (largely [inf], standard diffing knowledge)
1. **Non-transitivity.** If A.f↔B.g (ExactBytes) and B.g↔C.h (BSIM), A.f↔C.h is only a hypothesis. Confidence should combine to at most the weakest link. A direct A→C diff (`--summary`) may disagree.
2. **One-to-many fan-out.** Ghidriff's lists can contain several targets per source, so chaining multiplies the candidates. Reject composite chains when any hop is not 1:1.
3. **Missing links.** A function unmatched in B (absent, inlined, or split) breaks the chain even if A and C match directly. Always also run A→C, or at least first→last.
4. **Address keys are not stable identities.** Addresses shift between builds. Chain on the per-pair match tuples, never on address equality across builds.
5. **Name-based hops can mislead.** With PDBs, `SymbolsHash`/`NameParamHash` give confident but possibly wrong links for recycled names (e.g. `<lambda_…>`, `FUN_` names without symbols).
6. **Ratios are not comparable across hops.** difflib ratios exist only for modified pairs. Unchanged pairs carry no ratio (treat as 1.0 only if the match type is Exact*).
7. **Analysis drift.** Each build is analyzed separately, so differing analysis (decompiler timeouts, `--min-func-len`) between runs creates spurious breaks.

## Open questions
- I did not run Ghidriff, so `matches.json` is verified from source only.
- Whether `minimise_pdiff` strips `matches` from the main JSON. I did not trace it, so read `matches.json` instead.

## Implications for PatchTrace contracts
- **Treat Ghidriff as a pairwise engine.** PatchTrace's N-way feature must build its own graph from per-pair outputs:
  - nodes = (build, function address)
  - edges = Ghidriff pairs carrying `match_types` and, where present, `ratio`/`b_ratio`
- **Contract inputs:** `<pair>.matches.json` (all matches) plus `<pair>.json` → `functions.modified` (ratios). A pair missing `matches.json` is an error.
- **Hypotheses:**
  - Only 1:1 hops produce transitive hypotheses.
  - Label each hypothesis "inferred" with the list of hops and their weakest match type.
  - Optionally confirm with a direct first→last diff.
- **Run setup:**
  - Rename inputs to unique basenames before invoking.
  - Invoke as `ghidriff old new1 new2 … [--summary]`, or run explicit pairs separately for control and parallelism.
  - Do not parse `stats.*_percent` as numbers without stripping the `%`.
