# SPEC-31 / 06 Adapters: external engines and stored outputs as evidence sources

Every external result enters the unified engine only as `Atom`s (02 s4) plus groups and limitations, through one adapter per source. Adapters are pure readers of STORED data (they never run tools; engines keep running through the SPEC-28 scheduler, the Ghidriff backend or the DA-01 importer). Owner slice S0b (Ghidriff, secondary, manual); Diaphora adapter: trigger DA-01 D3 merged, owner DA-01 integration owner; BinExport2 producer: C3 is merged, so the trigger is a C3 worker mode `ir-export` (A-18), owner of the S1 follow-up. Tier maps: 05 s1.2.

## 1. Common contract
```python
class SourceAdapter(Protocol):
    id: SourceId
    def available(self, req: UnifiedRequest) -> Availability          # ok | missing(reason) | stale(reason); never raises
    def atoms(self, req: UnifiedRequest, addr: AddressMap, budget: Budget) -> AdapterOutput

@dataclass(frozen=True)
class AdapterOutput:
    atoms: tuple[Atom, ...]; groups: tuple[CorrGroup, ...]
    limitations: tuple[str, ...]            # fixed templates + counts, e.g. 'externals-skipped:312'
    source_ref: SourceRef                   # entry id, file SHA-256, version: goes into result_key (02 s5)

@dataclass(frozen=True)
class SourceSpec:                           # registry row (D-08); adding a source = adapter + one row
    id: SourceId; family: str; display: str; unit_caption: str        # e.g. 'BinDiff', 'similarity / algorithm'
    native_labels: tuple[str, ...]          # labels allowed in Atom.native (<= 4)
    tooltip_id: str                         # tooltips.REGISTRY id 'unified.source.<id>'
    licence_note: str                       # shown in provenance ("external process, GPL-3.0" ...)
```
`AddressMap` (`addressing.py`) per side: `image_base`, `size_of_image` from `pe_overview` (stdlib, verified bytes), `to_rva(value, basis)` with basis `va|rva|auto`; `auto` decides per SET with the same rule as C3's `secondary.binexport_identity.detect_address_basis` (reuse it, do not re-implement): all addresses inside [image_base, image_base + size_of_image) -> VA; all < size_of_image -> RVA; otherwise `not-comparable` for the set plus a limitation (fixes R01 s3 limit 1, where an image-base mismatch silently became "absent"). Ghidriff `EXTERNAL:<hex>` keys never raise: they are skipped and counted (imports are matched by P01 when IR exists; S0 has no import rows) (D-17; same skip rule as nway/graph.py `_is_external`, ce108cd).

## 2. Ghidriff (primary engine; baseline and regression oracle; run as is)

| Aspect | Specification |
|---|---|
| Role | primary result, always present when a completed run exists; oracle for the parity harness (08 s4) |
| Inputs | `FunctionMatch` list of the latest completed run (non-manual rows), raw PDiff JSON re-read from `runs/<run_id>/raw/json/*.ghidriff.json` after SHA-256 == `AnalysisRun.raw_sha256` (pattern of nway/graph.py and series.py), size <= 100 MiB (`backend.JSON_LIMIT`) |
| Address basis | VA text (Ghidra loads at the PE ImageBase; PatchTrace never passes `--base-address`, backend.py:537-542) -> RVA via `AddressMap` |
| Atoms | `modified` -> two-sided atom, tier = strongest `match_types` entry; `matches.address_matches` single target not claimed twice -> 1:1 atom (tier from its type list); one source with several targets or one target claimed by several sources -> `CorrGroup('ghidriff-1n')` (N:M, never cross-multiplied); `added`/`deleted` -> one-sided `W` atoms; `ref` = `FunctionMatch.id` or `raw:<hex>` |
| Taken | pairings, `match_types` (pass provenance), `diff_type` (hints, F4), decompiled `code` (C6), `called`/`calling` (C4n), ratios as native text |
| Not taken | `ratio`, `i_ratio`, `m_ratio`, `b_ratio` as similarity or confidence (degenerate `m_ratio`, rounding, autojunk: R03 s2); `stats.*`; markdown |
| Failure kinds | `raw-missing` (only normalized rows; unchanged pairs absent -> limitation), `raw-hash-mismatch` (refuse raw, limitation), `raw-unparsable` (same), `address-outside-image` (atom dropped, counted), `externals-skipped` (count) |
| Licence | GPL-3.0: external process only; JSON consumed as data; no code read for copying (R03 s6) |

## 3. BinDiff (optional oracle and second opinion; SPEC-29 run or `.BinDiff` import; never bundled)

| Aspect | Specification |
|---|---|
| Inputs | `secondary.store.current_sets()` row with engine `bindiff` (secondary/1 or /2), its `EngineRun` provenance |
| Address basis | `auto` (BinExport from Ghidra writes `offset - addressOffset`, image base subtracted only if chosen, binexport2-support.md s1); `image_base_subtracted` stays recorded |
| Atoms | each `SecondaryMatch` -> two-sided atom; tier from `algorithm` (05 s1.2); rows with `basicblocks = 0` are import/stub matches (R02 s15): tier A only when both ends are imports in the IR, else C; `alternatives` -> extra atoms with `step = '<algorithm> alt-rank-N'`, tier C |
| Taken | algorithm (step), flags -> C8, similarity/confidence text -> `native` |
| Not taken | similarity/confidence for any decision or ranking (evidence-quality index, not probability, R02 s7) |
| Parity role | `.BinDiff` rows and `bindiff --md_index` dumps feed `tools/unified/parity.py` (G-U3) |
| Failure kinds | set stale or for another pair (ignored with limitation, `select_current` semantics), basis `not-comparable` |
| Licence | Apache-2.0 tool run out of process (SPEC-29); our port of its ideas carries attribution (09) |

## 4. rz-diff (weak evidence)

| Aspect | Specification |
|---|---|
| Inputs | current `rz-diff` set (`-C -j -t functions`, rizin 0.9.1 pinned by SPEC-28 C2) |
| Address basis | decimal VA -> RVA via `AddressMap` |
| Atoms | two-sided rows -> tier `W`, `cardinality='non-exclusive'` when the newer endpoint appears in >= 2 rows (0.9.1 keeps the LAST candidate >= 0.5, B is never consumed, R03 s4); one-sided rows -> `W` observations |
| Taken | pairing proposal and `similarity_text` as native text; a `COMPLETE` (1.0) row is shown as a hint, not as C0 (rizin extents differ from Ghidra's) |
| Not taken | similarity as selector, rank or L2 verdict (92 % of correct PARTIAL pairs are pure address noise, R03 s4) |
| Failure kinds | basis not comparable, version other than 0.9.x (`untested-version` limitation; semantics changed on `dev`) |
| Licence | LGPL-3.0-only process (static release also carries GPL-2.0+ plugins, R03 s6); never link `librz` |

## 5. Diaphora (optional, out of process, user-installed; after DA-01 D3)

| Aspect | Specification |
|---|---|
| Inputs | DA-01 kinds `diaphora-matches` (`diaphora/1` sets) produced by DA-01's hardened importer; the unified adapter never opens `.diaphora` SQLite itself |
| Address basis | only rows whose DA-01 address status is `verified-rva`; `external-ea-only`/`ambiguous` -> skipped and counted |
| Atoms | `best` -> B, `partial`/`unreliable` -> C, `multimatch` -> N:M group, unmatched -> W observations; sets with provenance `user-attested` (unverified) produce display-only W atoms flagged `unverified` that neither support nor contest any row (DA-01: "EXCLUDE from ... auto-corroboration until verified"; a misattributed set must not mark every row contested, R-15) |
| Taken | category, heuristic description (as `step`, sanitized), ratio text (native; may exceed 1.0 with the 0.01 bonus) |
| Not taken | ratios for decisions; pseudocode/microcode (C6 stays Ghidra-decompiler based; mixing IR dialects is out of scope) |
| Licence | AGPL-3.0: no code, no SQL, no thresholds copied; ideas only (09) |

## 6. Manual corrections (analyst)
`FunctionMatch` rows with `manual=True` of the project snapshot -> tier-M atoms (1:1) or groups (split/merged/ambiguous categories). Corrections always come from the existing `ProjectService.correct_match` flow (D-29). `manual_digest` (02 s5) makes every correction change `result_key`, so the read model shows U6 "stale: a manual correction changed the inputs".

## 7. IR producers other than Ghidra (03 s1)

| Producer | Mapping into `ir-extract/1` | Limits |
|---|---|---|
| BinExport2 (C3 merged: `accept_binexport` validates in a capped worker but returns only `BinExportSummary` + a snapshot path) | a new C3 worker mode `ir-export` (A-18) maps the validated message inside the worker: `call_graph.vertex` -> functions (THUNK/IMPORTED types -> kind), `flow_graph` -> blocks, `instruction` -> raw bytes + mnemonic, `call_target` -> calls (Ghidra exporter also emits jumps to function entries here, R02 s2), string table refs -> strings; output = `ir-extract/1` JSONL, ingested as usual | no operand masks: `h1..h3` NULL, P05-P07, C1/C2 and every cosmetic proof except COS-PSEUDO unavailable; both sides must come from the same exporter and version (F1) |
| rizin (`aflj`, `afbj`, `pdfj`) | functions, blocks, instruction bytes/opcodes, call and data refs | reachability-bound discovery (`coverage-partial` flag); x86 operand types from `pdfj` are not SLEIGH masks -> `h1..h3` NULL in v1; backup only (B-02) |

## 8. Engines considered and not adapted (why)

| Engine | Decision |
|---|---|
| QBinDiff (Apache-2.0) | ideas only (P19 assignment with rejection); dependency rejected (dense matrices, memory warning above ~10k functions, R04 s1 #11) |
| radiff2 (LGPL) | no adapter (D-26); file-level byte/layout features belong to SPEC-26 |
| Ghidra AutoVT headless | deferred, no slice in v1; trigger: G-U3 shows Ghidriff-only parity is insufficient; owner S6 (R03 s7) |
| PatchDiff2 (GPL-2.0), Turbodiff (GPL-3.0), DarunGrim/binkit | ideas only (R04 s2) |
| neural embeddings (Gemini, Asm2Vec, SAFE, PalmTree, jTrans) | rejected for the core (size, licences, fit: R05 s6) |

## 9. Tests (named)
`test_ghidriff_adapter_maps_modified_unchanged_added_deleted`; `test_ghidriff_one_to_many_becomes_group_not_cross_product`; `test_external_keys_skipped_and_counted`; `test_diaphora_unverified_never_supports_or_contests`; `test_raw_hash_mismatch_drops_raw_with_limitation`; `test_address_basis_auto_va_rva_mixed`; `test_bindiff_algorithm_tier_map_and_basicblocks_zero`; `test_bindiff_alternatives_become_rank_atoms`; `test_rzdiff_shared_newer_endpoint_is_non_exclusive`; `test_rzdiff_similarity_never_read_by_rules` (mutation test: changing every similarity text changes no decision or verdict); `test_diaphora_verified_best_is_tier_b` (with a fake `diaphora-matches` row); `test_manual_correction_changes_result_key`; `test_unknown_source_id_renders_generically`.
