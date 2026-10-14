# Audit C: unified engine S0a (SPEC-31 / 02) - 2026-10-14

Scope: `src/patchtrace/unified/{limits,contracts,keys,store}.py` against `docs/specs/unified-engine/02-data-model.md`
(+ README, 00, 10), `docs/schemas/unified/`, `tests/test_unified_{contracts,keys,store}.py`. Base commit `67e5a6c`.
Read-only audit: no `src/` change. Reproductions were run on Linux (Python 3.13, pydantic 2.13) with throw-away
scripts; Windows-specific items are reasoned from the code and marked `[reasoned]`.

Not auditable: `registry.py` does not exist yet (02 s9 item 9 defers it), so there is no registry digest, pass
table or channel/proof version source; `config_digest` takes caller-supplied strings (see F-14). No `fn` line
contract exists for `ir-extract/1` (only header/footer in `SCHEMA_MODELS`), and `hypothesis` is neither installed
in the audit environment nor used by any `test_unified_*` file (see F-20).

Counts: High 1, Medium 9, Low 12, Info 4 (26 findings).

Verified clean (no finding): `extra='forbid'`/`strict`/`frozen` on every model; float, bool and NaN rejected for
every `Count`/`Rva` (python and JSON mode); `UnifiedError` rejects unknown codes and non-slug reasons; schemas
regenerate byte-identically (`tools/generate_schemas.py` into a copy, `diff -r docs/schemas` empty); `Sha256`
pattern rejects a trailing newline; manifest reader rejects duplicate keys, NaN, BOM; lone surrogates rejected by
`_encodable`; `row_id` rejects bool/negative/duplicate rvas; `dump_line` rejects NaN and surrogates; the `.part`
-> `os.replace` publish order with a bounded Windows retry is sound; the package imports no Qt/network/process code.

## High

### F-01 Retention keys on `config_digest` only, so one pair evicts every other pair's results
- `store.py:526-535` (`per_config[pointer.config_digest]`), spec `02-data-model.md:171` and L-32 say
  "newest 3 per `(older, newer, config_digest)`".
- `UnifiedResultPointer` carries no pair identity, and `entries(RESULT_KIND)` returns every run in the project.
- Repro: publish 5 results with the same config and five different `(older, newer)` pairs (sample project,
  `publish_result` each). Result: dirs alive `[False, False, True, True, True]`, pointer rows left 3. The two oldest
  pairs lost their pointer row AND their sidecar directory, through `delete_own` + `_rmtree`.
- Same defect for runs: `store.py:534-535` keeps `RUN_KEEP = 8` `unified-run` rows project-wide, not per pair.
- Impact: silent loss of derived (recomputable) results for unrelated pairs; the backup protects rows, not the
  deleted directories. Fix: add `older_sha256`/`newer_sha256` to the pointer body (additive contract change, spec
  first) and group on `(older, newer, config_digest)`; test with two pairs.

## Medium

### F-02 Part lines are parsed without strict JSON (duplicate keys accepted), against "import only strict JSON"
- `store.py:241` `model.model_validate_json(line)` (manifest uses `strict_json` at `store.py:171`, parts do not).
- Repro: a `rows.jsonl.gz` line `{"decision":"older-only","decision":"matched",...}` with a recomputed manifest
  verifies and `read_rows` returns `matched` (last key wins, first silently dropped). Pydantic JSON mode accepts
  duplicates; `strict_json` in `persistence.py` is the repo's gate and is bypassed here.
- Also applies to `_pointers` (`store.py:364`, `json.dumps(entry.body)` is already lossy) and `read_facts`.

### F-03 `verify_result_dir` proves hashes only; the manifest's counts, rows and facts are never cross-checked
- `store.py:206-234`. `publish_result` (`store.py:304`) trusts it as the sole gate.
- Repro 1: manifest with `counts.decisions.matched=0, unknown=2` (and materiality likewise) over two real `matched`
  rows verifies (`counts.total()` still equals `rows.records`, the only check, `contracts.py` `UnifiedResultManifest._consistent`).
- Repro 2: `rows.jsonl.gz` replaced by `{"garbage":1}\n{"x":2}\n` with matching part hash/bytes/records verifies
  and is publishable; the failure surfaces only later at `read_rows` as `record-invalid`.
- `write_result` does check row ids and facts-to-row linkage (`store.py:137-148`) but a staged directory from the
  worker is untrusted (a different process wrote it): those checks must run in the verifier, plus counts recompute,
  every row/fact validation, `facts.row_id` subset of rows, and `facts.verdict == row.materiality`.

### F-04 `result_id` does not bind the parts; a different payload with the same id is silently dropped
- `keys.result_key_inputs` (`keys.py:60-67`) excludes `parts`; `store.py:311-327` treats an existing valid
  directory with the same `result_id` as the winner and `_rmtree(staged)`.
- A nondeterministic or buggy pass change that keeps `config_digest` still yields a changed result that is discarded
  without any signal (G-U4 "identical manifests across OSes" is unenforced here). [reasoned from code; not run]
- Suggest: compare `manifest_sha256`/parts of staged vs existing and raise `PT-UNIFIED-INTERNAL` on mismatch
  (modulo `created_utc`).

### F-05 Store has no artifact/run ownership validation beyond one guard equality
- `store.py:305-307` compares `guard` to the manifest only. Nothing checks that `older_sha256`/`newer_sha256`
  are the run's artifacts, that `SourceRef.entry_id` rows exist in the run, or that `ghidriff_run_id` belongs to
  `guard.project_id`. AGENTS.md: "validate evidence/artifact/run ownership".
- Repro: five results with invented shas (`'a'*64`..) published against the real sample run id; all accepted.
- `load_result` (`store.py:388-391`) never compares `pointer.relative_dir`'s run with `entry.guard.run_id` or
  `manifest.ghidriff_run_id`; `cached_result` (`store.py:405-413`) ignores staleness (`entry.stale`) and returns
  `state='current'`. Whether the service layer later enforces this is not visible in S0a; the contract should.

### F-06 Run-id path validation: Python `$` newline hole, Windows names, unvalidated `result_id`
- `store.py:57` `_RUN_ID_OK` is a Python `re` with `$`; `store.py:68` checks `len(result_id) != 64` only.
- Repro: `result_relative_dir('r\n', 'a'*64)` returns `runs/r\n/unified/results/aaaaaaaaaaaaaaaa`;
  `result_relative_dir('r', '../' + 'a'*61)` returns `.../results/../aaaaaaaaaaaaa`; non-hex/uppercase ids pass.
  `safe_path` later rejects `..`, but the control-character run id reaches `mkdir`.
- Windows `[reasoned]`: regex also admits `CON`, `NUL`, `aux.txt`, `abc.` (trailing dot is stripped by Win32, so
  `abc.` aliases `abc`), and case aliases (`Abc` vs `abc`). Same alphabet is in `contracts.RunId` and
  `_RELATIVE_DIR`. Reserved device names make `mkdir` fail or open a device. Add a reserved-name, trailing-dot,
  `fullmatch`, and `[0-9a-f]{64}` check, and ideally a guard that `len(root)+len(relative) < 240` (relative path
  alone is up to 166 chars: `runs/<128>/unified/results/<16>`, leaving ~90 for the project root before MAX_PATH).

### F-07 Writer/reader asymmetry: a row longer than `LINE_MAX_BYTES` is written, then fails verification
- `store.py:56` `LINE_MAX_BYTES = 4 MiB` (spec L-05 says 64 MiB per line), `write_part` (`store.py:106-120`) has
  no per-line cap, and `UnifiedMatch.older`/`newer` have no `max_length` (L-01 allows 250,000 functions).
- Repro: one `ambiguous` row with 120,000 older `SideRef`s: `write_part` returns bytes=5,939,763;
  `_lines` raises `PT-UNIFIED-STORE line-too-long`. The result can never be read or verified, and the failure is
  attributed to the store, not the producer. Cap `older`/`newer` (and `hints`) in the contract or check line size
  at write time with `PT-UNIFIED-LIMIT`.

### F-08 Free text carries control and bidi characters (`_text` only checks UTF-8 encodability)
- `contracts.py:37-40`, used by `Atom.step`, `Atom.native`, `Atom.ref`, `SideRef.name`, `Note`, `Delta.old/new`,
  `SourceRef.entry_id`, `Version`, `ExtractRequest.analysis_options`. Spec 02 s1 says `StepId` is "sanitized".
- Repro (all accepted): `step='a\n\x1b[31m'`, `step='a\u202eb'`, `SideRef(name='a\r\nb')`, `entry_id='a\x00b'`.
- `name`, `old`, `new`, `native` are derived from untrusted binaries (symbols, disassembly), and flow to the GUI,
  logs and exports. `stderr_tail` is sanitised (`contracts.py:25`) but nothing else is. Apply one shared
  sanitiser/validator (reject C0/C1 other than none, bidi controls, NUL) to all `_text` fields.

### F-09 `UnifiedRun.stderr_tail` rejects CRLF, so a Windows failure record cannot be built; bidi list incomplete
- `contracts.py:25` pattern `[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]`.
- Repro: `stderr_tail='a\rb'` -> ValidationError. Windows child stderr is `\r\n`; unless every producer normalises
  first (not specified in 02 s9.5), the record that reports the failure is itself rejected. Normalise
  `\r\n` -> `\n` inside the validator or in a documented helper.
- Not covered: `U+200E/200F/061C/200B-200D/FEFF`. Repro: `'a\u200fb\u061cc\ufeff'` is accepted
  (the earlier combined probe failed only because of `\u2066`).

### F-10 `ExtractRequest` accepts hostile paths and unbounded limits
- `contracts.py:495-510` `_no_dot_absolute`, `contracts.py:513-526`.
- Repro (accepted): `'/a/b\n'`, `'/a/b\x00c'` (NUL), `'//a'`, `'/'`; `limits={'l99_whatever': 10**30}`;
  `analysis_options={'a': 'x\n'}`; `mode='decompile'` with no gzf and no `decompile_rvas`.
- Impact: NUL raises `ValueError: embedded null byte` at spawn (crash, not `PT-UNIFIED-INPUT`); newline paths
  break the line-oriented progress/log files; `limits` values beyond 2**63 overflow a JVM/Jython `long` consumer
  and unknown `lNN_` names are never matched to `UnifiedLimits`. Windows `[reasoned]`: trailing dot/space,
  reserved device names and `\\server\share` are not handled (UNC is rejected as "not absolute", which may be
  intended but is undocumented). Also the dot-prefixed-component rule rejects legitimate `C:\Users\me\.cache`.

## Low

### F-11 `Utc` is a regex, not a timestamp
- `contracts.py:26`. Repro (accepted): `2026-13-45T99:99:99Z`, fullwidth digits `２０２６-10-14T00:00:00Z`
  (`\d` is Unicode in pydantic's Rust regex), and both `Z` and `+00:00` spellings of the same instant. `started_utc`
  feeds `unified_run_id` (`keys.py:114-116`), so equal instants get different run ids; NFC does not fold fullwidth.
  Use `[0-9]`, parse with `datetime.fromisoformat`, and require one spelling.

### F-12 `provenance` keys use Python `$` and values are unsanitised
- `contracts.py:24,399-408`. Repro: key `'a\n'` and value `'x\x00y\n'` accepted. The dict is also mutable on a frozen
  model: `run.provenance['x'] = 'y'` succeeds after validation (bypasses the 16-key/256-char cap) and `hash(run)`
  raises `TypeError`. Same for `ExtractRequest.analysis_options/limits`. Use `fullmatch`, `MappingProxyType` or a
  sorted tuple of pairs.

### F-13 `UnifiedRun` status/error-code consistency is partial
- `contracts.py:422-430`: `failed` accepts `PT-UNIFIED-CANCEL/TIMEOUT/UNSUPPORTED`; `partial` accepts any code
  including none. Repro: `status='failed', error_code='PT-UNIFIED-CANCEL'` accepted. Pin `failed` to the non-cancel,
  non-timeout, non-unsupported codes and require a code (or a reason) for `partial`.

### F-14 `config_digest`/`limits_digest` inputs are not validated; limits churn the cache; no golden vectors
- `keys.py:70-76`: arguments are plain `str`/`Mapping`; `config_digest(pass_table_digest='x', registry_digest='',
  limits_digest=None, ...)` succeeds. `channel_versions={'C0': True}` hashes as `true` (differs from `1`).
- `keys.py:26-27` + `limits.py:151` hash `dataclasses.asdict` of ALL 66 fields. Repro: changing
  `l37_progress_poll_ms`, `l32_results_kept` or `l35_first_paint_ms` changes `limits_digest` -> `config_digest` ->
  `result_id`, invalidating every cached result for a UI or retention knob that cannot change content. (Spec says
  "canonical JSON of UnifiedLimits"; the 02 s6 split of content-affecting vs operational limits is only made for
  `ingest_limits_digest`.) Adding a future L-43 field silently re-keys everything without a domain-version bump
  (additive-only versioning, 02 s7, is not met for keys).
- `tests/test_unified_keys.py` has no known-answer vectors (no hex literal appears), so a refactor of
  `canonical_json`/`domain_id`, a pydantic `model_dump` default change or a Python minor version change that alters
  keys passes CI. Golden values from this run for pinning: `limits_digest() = efd5fbb4ea136f813ac3de85779b1b4d7b84a8a99e6bd7a4a7aa697a3b770dd7`,
  `row_id('a'*64,'a'*64,[4096],[4368]) = 6536ebdae6002ac54876bbcf0353952a33aa690d22f6e54d4b526ecf977dde49`.

### F-15 `IrKeyInputs` lacks the consistency rules of `IrProducer`
- `contracts.py:580-591`. Repro: `producer_kind='rizin', mode='gzf'` accepted; `mode='analyze'` with
  `script_sha256=None, analysis_options_digest=None` accepted and `ir_cache_eligible` returns True. Two analyze runs
  with different (but unhashed) options then share one `ir_key`, a cache collision that serves the wrong IR.
  `ir_cache_eligible` (`keys.py:39-41`) also accepts `n/a`, `none`, `?`, `latest` as versions.

### F-16 `ChangeFacts` allows structural-change deltas on unchanged/cosmetic rows
- `contracts.py:227` forbids only `SEMANTIC_CLASSES`. Repro: `verdict='unchanged', proof='UNCH/1'` plus a
  `block-added`, `cfg` or `unknown` delta is accepted, as is a `Delta` with both rvas `None` and
  `deltas_omitted=10**12`. UNCH/1 means C0 (bytes) equal; only COS-LAYOUT may carry block deltas. Tighten per proof.

### F-17 Fallback and backup reuse weaknesses in load_result and backup_once
- `store.py:388-391`: `load_result` takes the first non-stale entry and, if its directory is invalid, returns
  `state='invalid'` without trying older valid pointers (a corrupt newest result hides an intact older one).
- `store.py:450-461` `backup_once` reuses ANY trusted same-project backup, even one taken before the newest results,
  so `delete_own` can remove rows that no backup contains (spec 02 s7.4 asks for a verified backup before deletion).
  `_trusted` (`store.py:58,429-447`) caches in a module-global dict keyed by `(path, size, mtime_ns)`: unbounded,
  not thread-safe, and mtime granularity on FAT/exFAT is 2 s (a replaced file of equal size passes). [reasoned]

### F-18 Newer-contract detection is a prefix match and exists only for the manifest
- `store.py:176-178`: `unified-result/0`, `/abc`, `/` all report "produced by a newer PatchTrace"
  (`PT-UNIFIED-STALE`, repro run). Rows, facts and pointers with a newer `contract` are `record-invalid` /
  skipped instead of `stale` (`store.py:241-243`, `store.py:364-367`), contradicting 02 s7.2 (fail closed, read-only).
  Combined with `extra='forbid'`, any additive optional field in a later patch breaks old readers within the same
  `/1` contract; the freeze policy should state "additive means new `/N`" explicitly.

### F-19 Orphans and temp state
- `store.py:77-83` `tmp-*` staging dirs and `*.part` files leak on a crash (orphan sweep deferred, 02 s9.9);
  `new_staging_dir` is created under the final `results/` parent, so a crashed staging dir sits next to real results
  and is invisible to `apply_unified_retention`. 08 s store row promises "orphan removed by the next publish".
- `_replace` (`store.py:94-103`) retries `PermissionError` only; a Windows sharing violation on directory rename
  can also surface as `OSError(WinError 32/5)` that is not a `PermissionError` subclass in all cases. [reasoned]

### F-20 Property/fuzz and invariants gaps in the test suite
- No `hypothesis` use in `test_unified_*` although `hypothesis>=6.100` is a dev dependency. Missing properties:
  `row_id` invariant under permutation of rva lists; `source_set_digest` invariance under source order and
  duplicates; `manual_digest` order independence with mixed int/text; model JSON round-trip equals identity for
  every `SCHEMA_MODELS` entry; `Counts.of(rows)` totals; `verify_result_dir` rejects any single-byte mutation of
  any part/manifest (bit-flip fuzz); `_lines` on truncated/trailing-garbage gzip.
- Repro of an unflagged tolerance: three zero bytes appended to `facts.jsonl.gz` still verifies (gzip ignores
  trailing zero padding), so on-disk bytes are not covered by any hash (only decompressed content is, by design).
- No negative tests for F-02, F-03, F-05, F-07 above; add them red first.

### F-21 `Budget.tick` and `UnifiedLimits` validation holes
- `limits.py:219-224`: `tick(-100000)` makes `used` negative so the deadline is never checked for that many
  units; `tick(1.5)` is accepted. Latency of cancel is up to 4,096 units (documented), but a hot loop calling
  `tick` with large `n` skips checks after the first.
- `limits.py:134-146` checks only ten orderings. Accepted: `l24_assign_bucket_cap=100000 > l23_bucket_cap=1`,
  `l30_part_bytes == l30_dir_bytes == 1`, `l20_cosine_min_milli=5000` (a cosine above 1.0 can never be met),
  `l21_size_ratio_min_milli == max`, `l03_heap_max_mib=100` (below the 512 MiB `max_heap_mb` floor of
  `ExtractRequest`). `contracts.py` bakes `DEFAULT_LIMITS` at import time (`_L`), so a custom `UnifiedLimits`
  affects only store paths, never contract caps (L-28/L-39/L-41/L-03); that coupling is undocumented.
- `checked_timeout(kind=...)` treats any string except `'extract'` as the worker range (typo-prone).

### F-22 Manual-correction canonicalisation collapses distinct inputs
- `keys.py:99-113`. `16` and `'0x10'` collide (documented); `'0X10'` -> `'0x10'`; but `'0x010'`, `'16'` do not
  fold, so equal addresses can miss the cache. `str(category)` folds `1` and `'1'`. Duplicate addresses in one
  side are kept (`[1,1]` != `[1]`). Only `entry_id` NFC (see F-23) normalises Unicode. Low impact; document or
  parse text addresses.

## Info

### F-23 NFC-equivalent identifiers collide in hashes but not in models
- `enrichment/identity.py` NFC-normalises strings, `contracts.SourceRef.entry_id` does not. Repro:
  `entry_id='\u00e9'` and `'e\u0301'` yield the same `source_set_digest` yet are two distinct `SourceRef`s that both
  pass the manifest's `sorted(set(...))` check; a manifest listing both hashes like a manifest listing one.
  Validate `entry_id`/`name` as NFC in the contract (also fixes F-08 ordering-vs-hash drift).

### F-24 Schemas under-describe the contracts
- `docs/schemas/unified/*.json` regenerate cleanly (no drift), but custom validators (UTF-8 encodability,
  absolute-path rules, `stderr_tail` sanitation, provenance bounds, all cross-field invariants of `UnifiedMatch`,
  `ChangeFacts`, `UnifiedRun`, `ProgramIrManifest`, `ExtractRequest`) are invisible to any non-Python consumer
  (Ghidra-side script, GUI JS). The Jython/PyGhidra extractor must carry its own copy of these rules.

### F-25 Error code table consistency
- `limits.py:15-20`: codes match the 12 listed in 01 s6; exit codes 2/3/5 follow it. `BudgetExhausted` accepts any
  code (not only CANCEL/TIMEOUT), `UnifiedError.message` is truncated at 400 chars with no check that the template
  excludes untrusted text (docstring-only rule). `PT-UNIFIED-STALE` is returned for contract-too-new but also used
  for `read-only-store`, so UI cannot distinguish "newer producer" from "project written by newer client".

### F-26 `.gitattributes` for unified fixtures not yet present
- 02 s7.6 requires `tests/fixtures/unified/*.json|*.jsonl text eol=lf` and `*.bin binary`; no fixtures exist yet and
  `.gitattributes` lacks the lines (only `docs/schemas/**/*.json` covers the schemas). Add them with the first
  fixture so Windows checkouts keep `\n` (the part hashes are of LF-delimited decompressed lines; a CRLF fixture
  on Windows would change `Part.sha256`). Repro on Linux: a CRLF-converted `rows` part (`\r\n`) is accepted by
  `verify_result_dir` and `read_rows` once its manifest is recomputed, so the verifier does not enforce LF framing.

## Windows/cross-platform summary
- CRLF: F-09 (stderr), F-26 (part framing is not enforced), `write_bytes`/`'wb'` used everywhere in store (good).
- Path separators: `safe_path` rejects `\` and `:` in persisted relative paths (good); `ExtractRequest` accepts both
  separators but no UNC/device names (F-10); reserved names and trailing dot not handled (F-06).
- Determinism: keys use ASCII-sorted canonical JSON, NFC strings and no floats (good); no golden vectors (F-14).
- Locks: `_replace` bounded retry (F-19); `_rmtree` uses `onexc` (requires Python >= 3.12, matches `requires-python`).

## Suggested order of fixes
1. F-01, F-03, F-05 (data loss and ownership) with red tests first; spec edit for pointer pair identity.
2. F-02, F-07, F-08, F-06 (strict JSON, line cap, sanitiser, path identity) - small, local.
3. F-14 golden vectors and the limits-digest split before any consumer stores a `result_id`; then F-15, F-09.
4. Property/fuzz tests (F-20) and the remaining Low/Info items.
