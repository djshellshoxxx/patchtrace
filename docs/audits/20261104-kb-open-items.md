# KB / CVE correlator open items, survey of 2026-11-04 (WS-D, slice ws-d-kbc)

Base `claude/autonomous-finish-20261104` (cb28e96). Method: every open `- [ ]` line of `tasks/todo.md` that names KB, K-slices, KEV, Winbindex, acquisition or PIL, checked against the code on that base. Classes: DONE (already built), UNBLOCKED (pure, hermetic), FROZEN (needs a frozen file), EXTERNAL (live data or owner).

| todo.md line | Item | Class | Evidence / blocker |
|---|---|---|---|
| 307 | K4a `rank` and `kb leads` | DONE | `kbcorrelation/leads.py` (`build_leads`), `cli_leads.py`; `tests/test_kbc_leads.py`, `tests/test_kbc_synergy.py` |
| 307, 335 | K5 `kb plan` / `kb pairs` | DONE | `kbcorrelation/plan.py`, `pairs.py`, `cli_pairs.py` (`pairs`, `plan`, `import-pair`); `tests/test_kbc_pairs.py`, `tests/test_kbc_pairs_index.py` |
| 350 | `kb index import` of a Winbindex record | DONE | `cli_index._import_winbindex`, `wiring.save_winbindex_record` (strict `parse_rows`, size bound); `tests/test_kbc_index.py`, `tests/test_kbc_e0_e2e.py` |
| 335 | K7 `IndexPort` over workspace records | DONE | `wiring.WorkspaceFileIndex` (`rows_for`) feeds `kb pairs` / `kb plan` through `KbService`. Live heading classes: EXTERNAL |
| 179 | `intelligence explain` withdrawn CVE (C-03) | DONE in this slice | `explain.build_report` now passes the stored supersession flags to `resolve`; test `tests/test_intel_explain.py::test_withdrawn_cve_is_superseded_in_the_explain_report` |
| (gameplan KBB-04) D-02 | CVRF description clipped by characters, limit is bytes | DONE in this slice | `cvrf.clip_bytes`; `tests/test_kbc_text_limit_bytes.py` (json, xml) |
| (gameplan KBB-04) D-03 | unbounded manifest read in `cli_index` | DONE (moved) | no `read_text`/`json.loads` of a manifest remains in `cli_index.py`; manifests live in the sqlite `store.py` |
| 344 | KEV adapter path tests | EXTERNAL (owner) | `tests/test_kbc_kev_wiring.py` removed at the owner's request 2026-10-29; re-add only when the owner agrees (git `6331817`) |
| 347 | KEV on `kb search` edge rows (`service._edge_dict`) | UNBLOCKED | needs a KEV-lane design call in `service.py`; not started, larger than a slice |
| 347, 590 | pilot `collect.py` `NO_CATALOG`; plan item 9 `test_three_lanes_stay_separate_for_cve_2024_38063` | FROZEN-ish | `pilot/**` is another worker's area; the lane test needs the KB view model |
| 139 / 307 | `IntelligenceAdvisory.report_for` (CSAF applicability in the context) | UNBLOCKED | still raises `PT-KBC-UNSUPPORTED`; `AdvisoryStore.applicability` now gives the pure input |
| 220, 253, 307, 326, 341 | `cli.py` `kb` hook, `kb index sync` routing | FROZEN | `src/patchtrace/cli.py` (integrator) |
| 341, 463 | `.gitattributes` lines for kbcorrelation / kev expected JSON and schemas | FROZEN | `.gitattributes` |
| 163 | A-12: `tools/frozen_smoke.py` import of `kbcorrelation`, `live_kbc` marker, tooltip roots | FROZEN | `tools/frozen_smoke.py`, `pyproject.toml`, `tooltips.py` |
| 358 | `kb acquire` CLI verb binding, K7 UI (`ui_kb_online.py`) | FROZEN | `ui.py`, `tooltips.py`, `panel_manifest.py`; `cli_acquire.py` exists |
| 220, 326, 335 | real MSRC CVRF dialect and URL shape, CSAF KB location (L1, L4), S20, Winbindex heading classes | EXTERNAL | live MSRC / Winbindex data; proxy 403 here |
| 128 | Winbindex/msdl access, real PE/PDB parsing | EXTERNAL | owner machine |
| 196 | consented fetch from msrc.microsoft.com, real Microsoft documents | EXTERNAL | live |
| 410, 464, 468 | KEV K6 live gate, canonical CISA URL | EXTERNAL | live |
| 617 | RA-3 slow-drip read in `csaf/transport.py`, `enrichment/intelligence.py`, `acquisition/transport.py` | UNBLOCKED, cross-owner | shared `netutil` helper outside this slice's files |
| 253 | `kb attach --repair` verb; workspace object eviction; `test_kbc_contracts` sqlite exemption | UNBLOCKED (small) | `recovery.repair` exists (`tests/test_kbc_recovery.py`); verb wiring is a CLI change |
| 403-433, 553-555, 666-667 | PIL-A3 / B2 / C1 / C2 wiring (confidence carrier, `status()` port, tools, KEV window) | out of scope | `pilot/**` and `unified/**` owners |
| 94 | C9-3 Tier R recipes, licences | out of scope | other workstream |
| 584 | CI legs not run (Windows, MSVC, frozen EXE) | EXTERNAL | CI |

Closed in this slice: C-03 on the explain path and D-02. Evidence: `tests/test_kbc_*.py tests/test_kb_*.py tests/test_kev_*.py tests/test_intel_*.py` 2565 passed.
