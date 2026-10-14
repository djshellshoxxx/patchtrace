# SPEC-09: N-way build comparison (Phase 3b)

Status: developer-ready contract, 2026-10-12; amendment A-05 (raw `EXTERNAL:<hex>` address_matches entries are skipped and counted in the pair notes) applied in unified-engine slice P2, 2026-10-14. Contract version `nway/1`. Verified facts: `../research/phase3/nway.md` (Ghidriff @ 4f5d895).

## 1. Outcome and invariants

An analyst follows functions across an explicit, ordered list of 3–8 builds of one binary (e.g. RTM → several cumulative updates). PatchTrace builds one ordinary two-artifact project per **adjacent** pair (B1→B2, B2→B3, …), reusing cached directional runs, and a read-only "series" view that links them. The two-artifact project invariant is unchanged. Transitive correspondence is a **labelled hypothesis**, never a fact.

Ghidriff is pairwise: with >2 inputs it diffs adjacent pairs independently (plus first→last with `--summary`), never jointly. PatchTrace therefore runs explicit pairs itself for control, caching and parallelism.

## 2. Records (`nway/contracts.py`)

- `BuildRef`: `ordinal` (0..7), `label` (≤ 64), `artifact_sha256`.
- `Series`: `series_id = domain_id('series', 1, ordered sha256 list)`, `builds` (3–8, unique hashes, analyst order — never inferred from names/dates), `pair_projects` (one path per adjacent pair, each validated to contain exactly that ordered artifact pair).
- `FunctionNode`: `(ordinal, address int|None, name|None)`; `PairEdge`: `(from_node, to_node, category, match_types, ratio_text|None, manual: bool)` taken from the pair project's current matches (manual corrections win over engine matches; one function may have several edges).
- `Chain` (hypothesis): ordered nodes across ≥ 3 builds where every hop is a 1:1 edge; `weakest_match_type`, `hops`, `status: Literal['inferred','confirmed','contradicted']`, `gaps` (ordinals with no edge), `events` (`added`, `removed`, `split`, `merged`, `reverted` — reverted = code text at Bk equals Bi for i < k−1 after a change).
- Series file `series.json` stored next to (not inside) the pair projects, strict JSON, schema `nway/1`.

## 3. Rules

- Edge sources per pair project, in precedence order: (1) manual corrections; (2) normalized matches (modified/added/removed/split/merged/ambiguous/unmatched); (3) engine `matches.address_matches` read from the run's preserved raw Ghidriff JSON after verifying `raw_sha256` — 1:1 entries only (one target, target not claimed by another source), category `unchanged`. Normalized projects contain only changed functions, so (3) is what lets a chain cross a pair where the function did not change. A raw file without `matches` adds no edges and is noted per pair.
- Nodes in the shared build of two adjacent pairs are joined on address when both have one, else on exact (address, name). Addresses are never compared across different builds.

- Only 1:1 hops extend a chain. split/merged/ambiguous/unmatched hops end the chain and are recorded as events; no many-to-many transitivity is inferred.
- A chain is `confirmed` only when a direct first→last pair (optional, analyst-requested) has a 1:1 edge between its endpoints; `contradicted` if that direct pair maps the start elsewhere; otherwise `inferred`.
- Ratios are carried as upstream text (Ghidriff emits them only for modified functions); no new similarity is computed. Two correlators share the name `NameParamHash`; match types are reported verbatim and not used for scoring.
- Enrichment (SPEC-07) runs per pair project unchanged; the series view shows each hop's attention score and lets the analyst open the pair project at that function.
- Changing a pair project (rematch, new run) invalidates chains passing through it (`stale`); recomputation is deterministic.

## 4. Surfaces and limits

CLI `PatchTrace series create --builds F1 F2 F3 … --root DIR [--labels …]` (creates/reuses pair projects; runs comparisons only on explicit `--run`), `series chains SERIES_JSON [--function NAME|--address HEX] [--json]`. GUI: Series window (read-only table of chains with per-hop links). Limits: ≤ 8 builds, ≤ 100,000 nodes per series view, chain extraction O(edges).

## 5. Acceptance

Synthetic three-pair fixtures: straight 1:1 chain; split in the middle ends chain; manual correction overrides engine edge; revert detection; gap handling; confirmation/contradiction with a direct pair; deterministic series_id and order independence of file discovery; stale propagation after a pair rematch. Native: one real three-build series of the known fixture DLL (old → new → new-with-extra-change) on Windows CI.
