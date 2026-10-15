# Anchor fabric (SPEC-48)

Status: partial, 2026-10-14, owner Program E track FAB. Documents the built package `src/patchtrace/fabric/` (FAB-0 core, FAB-1 store, FAB-2 converters, FAB-4 pins) against the research plan `docs/specs/program-e/FAB-integration-plan.md` (the plan holds the research, the cross-plan amendments and the slice cards; this spec is the normative contract). Planned and not built: FAB-3 adoption by `pilot/`, FAB-5 CLI verbs, FAB-6 `related` panel, and the registry data additions of plan s10. Contract name `fabric/1`; stored contracts `fabric-batch/1` and `fabric-pin/1`.

## 1. Scope and non-goals

The fabric is one vocabulary, identity scheme, provenance and shared-origin calculus for **anchors**: typed, keyed, oriented statements that let separate features (UE pairs, capabilities, strings, build facts, advisories, rules) point at the same thing and be joined by key.

Non-goals: ranking, scoring or CWE classification (PIL owns judgment); navigation (GUI); a second store beside the enrichment database; analyst editing of producer output; any Qt, network, subprocess or sqlite code in the pure core (`ports.py` holds Protocols only; the sqlite access is the enrichment store's). Product invariants apply: unknown is not negative, shared-origin evidence counts once, older/newer orientation is explicit, text is untrusted.

## 2. Vocabulary (built)

| Item | Value | Code |
|---|---|---|
| Kinds (10, closed) | `function, string, import, capability, rule, build_fact, advisory_phrase, cve, kb, cwe` | `fabric/contracts.py:28` |
| Sides | `older, newer, both, none` | `contracts.py:30` |
| Roles | `observed, stated, hint` | `contracts.py:31` |
| Producers (13; order picks the display witness) | `core, ue, cap, die, wb3, wbq, wb2, wb1, yrx, kb, kev, pil, analyst` | `contracts.py:33` |
| Roles by kind | function: observed; string, import: observed or hint; capability: observed; rule, build_fact: observed or stated; advisory_phrase, cwe: stated or hint; cve, kb: stated | `contracts.py:39` |
| Resolve statuses | `found, ambiguous, unknown, unsupported` (no `absent`) | `contracts.py:45` |

Key grammar per kind is plan s4 (enforced by `ids.check_anchor`, `fabric/ids.py`). Records are strict, frozen, extra-forbidden Pydantic models: `Ref`, `Witness` (1..8 origins, up to 16 facets), `PairRef`, `Anchor` (1..16 witnesses) in `contracts.py`. New kinds, roles, sides and producers are appended only (additive contract); a reader skips and counts what it does not know.

## 3. Normative requirements

Identity and merge
1. R1. `anchor_id` MUST be `domain_id('fabric-anchor', 1, {kind, key, side, role, subject})`; `witness_id` MUST be `domain_id('fabric-witness', 1, ...)` over all other witness fields; `anchors_digest` MUST be `domain_id('fabric-anchors', 1, ...)` over sorted (anchor_id, sorted witness ids) (`ids.py:63,69,75`). Labels, facets and timestamps MUST NOT enter identity.
2. R2. One fact reported by two producers MUST be one anchor with two witnesses; merge is the union of witnesses by `witness_id`. The project is not part of identity, so a series can reuse anchors across pair projects.
3. R3. `role` MUST be part of identity, so advisory text (`stated`, `hint`) can never read as found evidence. `observed` MUST have a side other than `none`; on one side every witness MUST carry `input_sha256`; `hint` MUST have side `none`; `cve`, `kb`, `cwe` and `advisory_phrase` MUST NOT be `observed`; `function` has no subject.

Provenance and independence
4. R4. Each witness MUST carry origin tags equal to the registry tags of its `source`; an unknown source MUST fail closed with `PT-FAB-ORIGIN` (`origins.check_origins`, `origins.py:141`).
5. R5. Independence MUST be the number of connected components over origin tags (`components`, `independent_count`, `origins.py:53,92`), never the witness count. The UI wording is "2 independent of 3" (planned, FAB-6).
6. R6. The registry digest (`origins.digest`, `origins.py:136`) feeds batch staleness. The fabric adopts or replaces PIL's `pilot/origins.py`; (FAB-3 built: PIL now re-exports the fabric table) until FAB-3 both exist and parity tests pin them (planned adoption).

Publish, read, orientation
7. R7. `AnchorSink.publish` MUST be atomic and MUST first remove every witness of each (producer, batch) present in the call; `retract(project_key, producer, batch)` removes only that batch. A sink MUST NOT remove another producer's witnesses (`ports.py`).
8. R8. `AnchorReader.find` MUST return canonical order (kind, key, side, role, subject, id), page size at most F-09; a `pair:` subject also matches its member `image:` subjects. An empty `find` is not a statement.
9. R9. `resolve` MUST answer `found`, `ambiguous`, `unknown` or `unsupported`, never `absent`; code-side kinds (function, string, import, capability) consider observed anchors only; side older or newer also matches `both`; a null reader answers `unsupported`.
10. R10. A bound project MUST reject a swapped pair with `PT-FAB-ORIENTATION` (reasons `orientation-swapped, pair-mismatch, input-sha-mismatch, subject-sha-mismatch, subject-side-mismatch`, `ids.check_orientation`). In the enrichment store the hashes are bound from the saved snapshot on every call (`store.py`), so the check cannot be skipped.
11. R11. `verify_anchor` MUST recompute `anchor_id`, `witness_id` and the pair row id; a mismatch is `PT-FAB-INTEGRITY`.

Untrusted text
12. R12. Every text field MUST pass `plain_line` (parity with `secondary.evidence_view.sanitize_text`, bidi and control characters removed; `contracts.py:53`). A string anchor is a hash plus a label of at most 200 characters; the producer redacts secret-looking values. `string_key` MUST use NFC plus ASCII lower case, not `casefold` (interpreter-independent).
13. R13. `FabricError` messages MUST be fixed templates; the offending value never appears (`limits.py`).

Store (built, FAB-1)
14. R14. `EnrichmentAnchorStore` MUST persist one enrichment row of kind `anchor-batch` per (project, producer, batch), id `fabric:<producer>:<batch>`, body `FabricBatch` (`fabric-batch/1`, `store.py:56`), schema `docs/schemas/fabric/FabricBatch.json`. A body above 24 MiB MUST be refused `PT-FAB-LIMIT` reason `row-size` (`store.py:59,348`). The kind is not in `DERIVED_KINDS`, so retention never deletes it (`enrichment/storage.py:54`).
15. R15. One store answers for the one project of its database: another key is `PT-FAB-INPUT` reason `foreign-project`; an unsaved project takes no publish (`PT-FAB-STORAGE` reason `project-unsaved`) and reads as empty.
16. R16. The guard is (project id, run `fabric`, raw `''`, `input_digest`); a stale batch (moved guard or changed registry digest) MUST be listed with its flag and its anchors still returned. An anchor that fails validation, `verify_anchor`, holds another batch's witness, or was made for the other orientation MUST be skipped and counted in `BatchStatus.skipped`, never hidden; reading deletes nothing.
17. R17. A publish MUST be checked in full before the first write; rows are then written one transaction each, so repeating the call completes a crash-interrupted publish.

Pins (built, FAB-4)
18. R18. `PinPort` (`pin`, `unpin`, `pins`) MUST stay separate from `AnchorSink`. `EnrichmentPinStore` writes append-only `anchor-pin` events, id `fabric-pin:<uuid>`, body `PinEvent` (`fabric-pin/1`, `fabric/pins.py:48,68`). A pin names the anchor by identity, so it survives batch replacement and retraction; no producer can retract it.
19. R19. The state of an anchor is its event with the highest sequence number; re-pinning with the same note writes nothing; unpinning an unset pin returns False and writes nothing. Notes are at most 2 KiB plain text and are refused, never cut (`PT-FAB-LIMIT` reason `note-size`, `pins.py:160`). `pins()` returns `PinList(pins, skipped)` newest first; a pin from the other orientation is flagged `stale`; an anchor of the other orientation cannot be pinned.

Converters (built, FAB-2)
20. R20. `from_k_anchor` and `from_pilot_anchor` (`fabric/convert.py:125,167`) MUST convert the K `Anchor` and `PilotAnchor` records to fabric anchors under the plan s4 mapping, refusing unmapped input with a typed `PT-FAB-*` error. K stays a search-hint contract; `pdb` verified-bytes becomes an observed `build_fact`.

## 4. Limits and error codes

Limits F-01..F-15 are the defaults of `FabricLimits` (`limits.py`): 20,000 anchors per publish; 200,000 per project; 16 witnesses per anchor; 16 facets per witness; label 200, key 200, facet value 300 characters; 256 RVAs per pair side; 500 page rows; 8 origins per witness; batch name 64; 20 resolve candidates; ref id 256; pointer 4096; tool 64. Counts are enforced by the stores and may be tightened; text and shape caps are fixed by the models.

Error codes and CLI exits (`limits.py`): `PT-FAB-INPUT, KIND, KEY, ORIENTATION, ORIGIN, UNSUPPORTED` exit 2; `LIMIT, STALE, STORAGE, INTEGRITY` exit 3; `NOTFOUND` exit 4; `CANCEL` exit 5. `PT-FAB-NOTFOUND`, `CANCEL` and `UNSUPPORTED` are reserved for FAB-5 and the null reader.

## 5. Planned, not built

- FAB-3 (built 2026-10-14): `pilot/origins.py` and `pilot/ports.py` rebound to the fabric; PIL goldens re-pinned (owner: PIL).
- FAB-5 (no `fabric` module exists in `src/patchtrace/cli.py` or `cli_commands/`): read-only `patchtrace fabric list|show|resolve|stats --project <path>` with `--kind --side --role --subject --limit --json`, envelope `enrichment-cli/1`, Qt-free `fabric/cli.py`, adapter of at most 25 lines. Also listed in `docs/specs/cli-umbrella.md` (SPEC-44).
- FAB-6: one `related` panel through the GUI panel registry (`Ctrl+Shift+J`, tabbed with `leads`), virtualized table, role chips with glyph and text, copy per plan s8; blocked on the GUI panel registry.
- Registry data additions (plan s10): CAP lineage tags, KEV `kev-catalog`, WBQ `pe-self-report`, WB3 `emulation:` and `ir:` groups.
- Absent verdict: not in v1. [proposal] add as an optional `publish` argument once a producer can declare a batch complete.

## 6. Test and acceptance plan

Existing tests (all hermetic, built in code): `tests/test_fabric_contracts.py`, `test_fabric_ids.py`, `test_fabric_origins.py`, `test_fabric_memory.py` (R1-R13), `test_fabric_store.py` with `fabric_store_support.py` (R14-R17, differential against the memory reference), `test_fabric_schemas.py` (regenerate-and-compare of `docs/schemas/fabric/`, generator `tools/generate_fabric_schemas.py`), `test_fabric_pins.py` (R18-R19), `test_fabric_convert.py` (R20), `test_fabric_synergy.py::test_one_api_three_channels_count_independently` (one API seen by three channels: 2 witnesses and 2 components on pair F, 2 and 1 on G, CWE-190 4 witnesses and 1 component, swapped orientation raises `PT-FAB-ORIENTATION`), `test_fabric_plan.py` (the plan's tables equal the code).

Gaps: no test for the FAB-5 verbs or the FAB-6 panel (not built); the plan's measured figures (20,000 anchors: build 2.3 s, publish 0.5 s, 500-row page 71 ms, 11.1 MiB JSON) were measured on Linux only and have no CI gate. Gates only the owner or CI can close, never counted as done: Windows CI run of the fabric tests, frozen-smoke import once a consumer exists, the 100,000-row GUI walk with NVDA and Narrator (GUI M26).

## 7. Open questions (recommended default each)

1. Kind spelling `import` versus `api`: keep `import`.
2. Keep `capa` as PIL's single origin tag until CAP-7 lands, then change in one data PR.
3. One row per (producer, batch) versus per project: keep per batch (bounded rows, cheap replace).
4. `project_key` is the persisted project id: keep.
5. [unverified] Python Unicode-database drift is the reason for avoiding `casefold` (plan cites docs.python.org, unreachable from the sandbox on 2026-10-14); the NFC plus ASCII lower-case rule does not depend on it.
