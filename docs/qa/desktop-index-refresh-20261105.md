# Desktop Winbindex metadata preview and refresh — 2026-11-05

Base: coordinator-approved backend integration `92f2ab687790909bde87031ef6557b05d9683adb` plus the candidate snapshot prerequisite `bf3661966785a971f484b6339af81274278d1434`, merged locally as `ccc2f3de`. Isolated worktree `/tmp/pt-independent-metadata-desktop-20261105`, branch `work/desktop-index-refresh-20261105`. The coordinator approved additive internal operations before edits; SPEC-31-F was updated before implementation. No serialized model, schema, transport, parser or publisher changed.

## Working chain

The analyst enters a public component filename, previews the exact third-party Winbindex metadata request, separately consents to that one plan, reviews its saved-byte/source receipt, and explicitly inspects saved-index candidates. Backend orchestration delegates only to the reviewed `sources.winbindex_fetch` build/render/RefreshRequest/refresh seam; the source module retains all URL, strict plan/consent, transport, parse, cache-publication and receipt verification policy. The facade normalizes the explicit basename and sends no project/local-path/hash/KB/CVE context to the provider. UI code holds immutable request values and adds no networking or database behavior.

Monthly MSRC and index metadata plans are held separately and are mutually exclusive. Starting another preview or operation consumes/clears both grants before any worker result can replace the details. Field/product/mode/candidate changes, cancellation and close revoke consent; old-generation callbacks cannot restore it. Refresh delegates its cancellation token to the source module. If cancellation/edit/close occurs after publication starts, completed exact cache bytes remain available while the obsolete receipt cannot populate the current dialog or adopt a candidate/project. The local/manual file controls and measured pair-hash preview remain authoritative.

The details use the existing bounded 64 KiB view: full source-rendered request JSON/headers/caps/host/digest before consent, then raw metadata SHA-256/size, source URL, retrieval/source dates and date basis, saved path, counts/warnings and explicit third-party/TLS limits after refresh. Candidate preview still does not grant download consent or enable project creation.

## Deterministic verification

All responses are existing authored synthetic Winbindex/advisory fixtures through an injected opener. Socket creation/connection/DNS are denied; these checks supply no live compatibility evidence.

- Baseline: 3 failures in 2.38 s; the immutable worker facade lacked the metadata operation/injection seam and no real desktop journey could load it. Raw log `/tmp/pt-independent-metadata-desktop-red.log`.
- Initial integrated selection: 341 passed in 17.24 s; the final selection expands late-publication and malformed-input controls and overlaps it.
- Final exact selection: **351 passed in 18.05 s**, raw log `/tmp/pt-independent-metadata-desktop-final.log`.
- Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=$PWD/src python -m pytest -q tests/test_kb_desktop_index_refresh_20261105.py tests/test_kb_winbindex_refresh_20261105.py tests/test_kb_candidate_journey_20261105.py tests/test_kb_online_investigation_20261105.py tests/test_kb_accessibility_20261105.py tests/test_ui_kb_investigation.py tests/test_kb_investigation_service.py tests/test_kb_binary_only_start.py tests/test_kb_current_project.py tests/test_kbc_contracts.py`.
- Whole-tree `python -m ruff check src tests tools` and `git diff --check` pass. Source binding resolves `/tmp/pt-independent-metadata-desktop-20261105/src/patchtrace/__init__.py`; no shared editable install changed.

Tests cover exact/no-write/no-network preview and privacy; real metadata transport/parser/publication and exact raw receipt; an actual Qt advisory/product → metadata preview → explicit fetch → saved candidate selection/preview journey; absent/wrong-host/wrong-digest/stale-filename consent; both directions of monthly/index plan crossover; 13 field/mode/cancel/other-operation revocations; preview replacement and displayed-plan exclusivity; late successful publication after edit/cancel/close with retained exact raw bytes and no stale adoption; discarded late planning callbacks; invalid component paths/extensions and binary-only refusal. Existing current/manual pair and reopen-hash journeys remain included.

An interim late-publication test initially failed three controls (348 passed) because `TaskRunner.busy()` intentionally excludes cancelled workers and the test asserted before publication finished. The tests now wait for the actual queued completion/drop to be delivered, then assert retained bytes and unchanged dialog state; the publication was already retained. The failed development log `/tmp/pt-independent-metadata-desktop-verified.log` is preserved, and no production cancellation or assertion was weakened.

## Remaining qualification

Full candidate binary acquisition/download/create is a later separate slice; metadata consent never authorizes it. Product-only desktop starts and live/frozen/native Windows, high-DPI, screen-reader and release acceptance remain open. No target binary, driver, model-suggested command, live provider call, broad suite or GUI stress suite ran. Existing PR #205 qualification and pinned-native processes/worktrees/logs were untouched. All results above are scoped deterministic Linux checks, not release/native/provider acceptance.
