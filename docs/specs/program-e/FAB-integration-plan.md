# FAB integration plan: anchor fabric for cross-feature links (Program E, track FAB)

Status: research plan and FAB-0 card, 2026-10-14, base `fd6cdba`. FAB-0 (pure core `src/patchtrace/fabric/` plus `tests/test_fabric_*.py`) is BUILT from this plan and its tables are pinned to the code by `tests/test_fabric_plan.py`. FAB-2 (`fabric/convert.py`, the K and PIL converters, and the s10 registry rows for KEV, WBQ and WB3; CAP's lineage waits for CAP-7) is BUILT on `b4fdd2b` with `tests/test_fabric_convert.py`; FAB-1 and FAB-3..FAB-6 are open. Labels: [S] read from source at the base commit (`path:line`), [D] documentation text, [M] measured here (CPython 3.13.16 on Linux; the tests also pass on 3.12.3 with pydantic 2.13.5), [U] unverified (host blocked from the sandbox). Inputs read: AGENTS.md, CLAUDE.md, both briefs, roadmap s3, section 4 of all 14 `*-integration-plan.md`, GUI s7 and s11, GDE s7.6, `pilot/{ports,origins,keys,contracts}.py`, `intelligence/{contracts,anchors}.py`, `enrichment/{identity,storage}.py`, `unified/{keys,fusion/components}.py`.

## 1. Verdict and scope

- Build `patchtrace.fabric`: one vocabulary, identity, provenance and shared-origin calculus for anchors, plus the two Protocols every plan already assumes in four incompatible shapes: `AnchorSink` (write) and `AnchorReader` (read). FAB-0 is the pure core with in-memory and null implementations; storage, converters, CLI and GUI are later slices.
- An anchor is a typed, keyed, oriented statement (`kind`, `key`, `side`, `role`, optional `subject`) holding 1..16 witnesses (one per producer statement: producer, batch, evidence source, origin tags, label, facets, tool, input hash, ref). Identity = (kind, key, side, role, subject): one fact reported by two producers is ONE anchor with two witnesses; independence is counted over origin tags, never over witnesses.
- Decisions: ten closed kinds spelled as GUI and GDE spell them (`import`, `build_fact`, `advisory_phrase`); GUI-only `match` and `address` stay in `gui/anchors.py`. `role` (`observed`, `stated`, `hint`) is part of identity, so advisory text can never read as found evidence. No `absent` verdict in v1 (the reader says found, ambiguous or unknown). Publish is atomic and replaces per (producer, batch). Orientation is explicit and guarded by input hashes.
- Not building: ranking, scoring or CWE classification (PIL owns judgment), navigation (GUI `NavigationPort`), a second store (`kb-context`, `kev-context`, `patch-intent` rows stay; FAB reads through converters), analyst pins (FAB-4), new dependencies, any Qt, network or sqlite code in the core.

## 2. Sources and facts

Repository rows cite the base commit. `docs.python.org`, `www.rfc-editor.org` and `www.unicode.org` do not resolve from this sandbox.

| Claim | Source | Retrieved | Conf. |
|---|---|---|---|
| Four `AnchorSink` shapes are assumed: PIL `publish(project_key, Sequence[PilotAnchor])`, KB `publish(project_key, anchors)`, GDE `resolve(kind, value, side)`, WB1 `pin(locator, note, provenance)` | `src/patchtrace/pilot/ports.py:48-53`, `KB-integration-plan.md:92`, `GDE-integration-plan.md:152-157`, `WB1-integration-plan.md:85` [S] | 2026-10-14 | high |
| GUI owns a closed 12-kind tuple (adds `match`, `address`), `key` <= 256, `label` <= 200, `side` explicit, and adapts FAB through `AnchorRef.from_fabric`; no `gui/` package exists yet | `GUI-integration-plan.md:104,431`; `ls src/patchtrace` [S] | 2026-10-14 | high |
| FAB owns the anchor record, kinds and keys, the origin registry with `components()`, persistence and staleness; PIL owns judgment; PIL's `origins.py` and `ports.py` are provisional and FAB "adopts or replaces" them | `PIL-integration-plan.md:68-72` [S] | 2026-10-14 | high |
| Three union-finds exist: pilot tags, unified families, calibration `family_dependencies` | `pilot/origins.py:38-74`, `unified/fusion/components.py:30-65`, `calibration/features.py:36-47` [S] | 2026-10-14 | high |
| Origin tags and the source table are PIL's (`D_vendor_text` repeats advisory claims across NVD, MSRC, KEV; `capa` is `D_vivisect`, `capa-ghidra` is `D_ghidra`) | `pilot/origins.py:24-35`; `docs/specs/unified-engine/05-fusion-and-noise.md` s1.1 [S] | 2026-10-14 | high |
| K anchors: kinds module, api, string, feature, component, pdb; quality explicit, derived, rule, verified-bytes; always `search-hint` | `intelligence/contracts.py:544-557`, `intelligence/anchors.py:1-7,44` [S] | 2026-10-14 | high |
| CAP keys `capobs/1`, `apiobs/1` and the `api_key` rule; "FAB dedupes by key `apiobs/1`" | `CAP-integration-plan.md:98,114` [S] | 2026-10-14 | high |
| Candidate identity is `domain_id('unified-row', 1, {older_sha256, newer_sha256, older_rvas, newer_rvas})`; PIL re-derives it and pins it by test | `unified/keys.py:115-122`, `pilot/keys.py:76-82` [S] | 2026-10-14 | high |
| Function ids are `rva:0x<hex>` (`^rva:0x[0-9a-f]{1,16}$`) | `intelligence/tools/common.py:53` [S] | 2026-10-14 | high |
| Enrichment store: one table, `KINDS` frozenset, rows <= 32 MiB, project <= 128 MiB, retention deletes only `DERIVED_KINDS`; `kb-context`, `kev-context`, `patch-intent` already exist | `enrichment/storage.py:37-55,213-249` [S] | 2026-10-14 | high |
| Strict frozen Pydantic 2.13.5 records, JSON-mode revalidation, tuples in canonical order, no floats | `pyproject.toml`; `pilot/contracts.py:1-14` [S] | 2026-10-14 | high |
| At F-01 (20,000 one-witness anchors with facets) building takes 2.3 s, `publish` 0.5 s, a 500-row `find` page 71 ms, `resolve` 14 ms; the JSON is 11.1 MiB (583 bytes per anchor) and revalidates in 0.75 s; re-measure on Windows CI | scratch benchmark, in-memory store [M] | 2026-10-14 | medium |
| PE import names are ASCII, case sensitive, null terminated; ordinal imports use the high bit and a 16-bit ordinal | https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/Debug/pe-format.md (Hint/Name Table, Import Lookup Table) [D] | 2026-10-14 | high |
| Python's Unicode database differs per interpreter (here 15.1.0), so `str.casefold()` is not a stable content key; ASCII lower case plus NFC is | `unicodedata.unidata_version` [M]; https://docs.python.org/3/library/stdtypes.html#str.casefold [U] | 2026-10-14 | medium |
| JSON Pointer syntax used by `Pointer` is the repo pattern `^(/([^/~]|~[01])*)*$` | `pilot/contracts.py:155` [S]; https://www.rfc-editor.org/rfc/rfc6901 [U] | 2026-10-14 | medium |
| `clean_line` and `plain_line` remove exactly what `sanitize_text` removes (plus tab and newline); the `\u` escape form was checked code point by code point | `secondary/evidence_view.py:101-110`, `pilot/contracts.py:93,106,122` [S]; scratch check [M] | 2026-10-14 | high |
| Instance A produces the fabric; B and C use a no-op `AnchorSink` until it lands | `docs/plans/multi-instance-coordination.md:41`; roadmap `:39,49` [S] | 2026-10-14 | high |
| No new dependency: stdlib plus pydantic (MIT), so `pip --only-binary=:all:` is unaffected | `pyproject.toml` [S] | 2026-10-14 | high |

## 3. Standalone baseline versus PatchTrace value

- Standalone, every channel (capa, FLOSS, DiE, advisory text, Ghidriff pairs) lists its own findings with its own ids. Joining them is manual, and one fact appears once per tool.
- Without a fabric the 14 plans keep four `AnchorSink` signatures, three union-finds, K kinds versus the GUI tuple versus the GDE selector, CAP and UE each reporting the same API call, and NVD, MSRC and KEV counting one CWE three times.
- With it. W1: select a changed pair and see capability, API, string, build, rule and CVE rows about it with "2 independent origins from 3 witnesses", then jump to the owning panel. W2: join an advisory hint to observed evidence by key (hint `rtlulongadd`, newer imports it, function F calls it). W3: guide steps resolve to a location through one call. W4: N-way series reuse anchors across pair projects, because identity contains no project. W5: reports print provenance per anchor.

## 4. Cross-feature links

Key grammar and roles (implemented by `ids.check_anchor`; every key is NFC and <= 200 characters). Rules: `observed` needs a side other than `none` and, on one side, `input_sha256` on every witness; `hint` needs side `none`; `stated` may carry any side; `cve`, `kb`, `cwe` and `advisory_phrase` are never `observed`; `function` has no subject.

| Kind | Key | Roles | Emitted by -> consumed by |
|---|---|---|---|
| `function` | `pair:<row_id>` (side both; `Anchor.pair` holds both SHA-256 and the RVA lists and must reproduce `row_id`) or `image:<sha256>:rva:0x<hex>` (an RVA, so at most 2**32-1; side older or newer) | observed | UE, core, WB2, CAP, WB3, YRX -> GUI navigator, PIL, KB leads, GDE, WB1, reports |
| `string` | 64 hex of `string_key` (NFC, ASCII letters lower-cased, UTF-8, SHA-256); exact hash in facet `exact` | observed, hint | WB3, CAP (redacted), K quoted text -> WB3 hits, PIL, YRX |
| `import` | `api_key(name)` (CAP rule: strip to the last `!` or `.`, ASCII lower case, trailing a or w folded when >= 4 remain) or `<dll>!#<n>` for ordinals; spelling in facets `name`, `dll` | observed, hint | CAP, UE call sets, WBQ, WB2, PIL `api_hints` -> PIL, WB2, KB chips, YRX |
| `capability` | capa rule name as reported; namespace, scope, ATT&CK and MBC labels are facets | observed | CAP -> PIL (context), YRX, WB1, WB2 badge, LBL gates |
| `rule` | `patch:R-<ID>@<rev>` or `yara:<12 hex>.v<n>` | observed (a match), stated (the rule) | YRX, KB, PIL -> WB1, WB2 badge, GUI, GDE |
| `build_fact` | `<name>=<value>`, name `[a-z][a-z0-9_]{0,31}`, value <= 160 | observed, stated | DIE (26 names), WBQ, WB3, CAP, K `pdb`, KB build rows -> UE noise, PIL, YRX, DIE |
| `advisory_phrase` | 64 hex of `string_key(excerpt)`; excerpt is the label; pointer in `ref` | stated, hint | KB, PIL -> WB3 hits, WB1, YRX, GDE |
| `cve` | `CVE-YYYY-NNNN+` | stated | KB, PIL, CSAF; a KEV listing is witness facets `kev`, `date_added`, `snapshot` -> KEV, KB, PIL, GUI, GDE |
| `kb` | `KB` + 5 to 9 digits | stated | KB -> KEV, PIL, WB1 |
| `cwe` | `CWE-N` | stated, hint | KB, PIL, CSAF, KEV (display only) -> CAP, YRX, LBL, GDE |

How each plan's assumption maps (the change is applied by the plan's owner, s10):

| Plan | Assumed | Fabric meaning |
|---|---|---|
| PIL | `AnchorSink.publish(project_key, Sequence[PilotAnchor])`, `OriginRegistry`, `Navigator` | same `publish` over fabric `Anchor`; the `OriginRegistry` Protocol is identical (4 members) so `pilot/ports.py` rebinds; `PilotAnchor` becomes a PIL-side converter; `Navigator` is the GUI's, not FAB's |
| KB | `publish(project_key, anchors)`; its s4 table | KB `kb`, CVE `cve`, CWE `cwe`, CVRF text and module names `advisory_phrase` (facet `phrase_kind`), API and string hints role `hint`, `BuildRow` claims `build_fact` stated, pairs `pair:` |
| GDE | `resolve(kind, value, side)` giving found, absent, unknown, unsupported | `AnchorReader.resolve(project_key, ...)`; the guide reads `ambiguous` and `absent` as `unknown`; `unsupported` is the null reader; `location` is `anchor_id` |
| WB1 | hits expose `anchor_kind`, `anchor_key`; `pin(locator, note, provenance)` | kind and key 1:1; pin becomes the separate `PinPort` (FAB-4), so `AnchorSink` never changes |
| GUI | `AnchorRef.from_fabric` | 1:1 on the ten kinds; side `none` becomes None; `label` is the display witness label; a `pair:` key resolves to a match through the UE read model, else `not-found` |
| CAP | `capobs/1`, `apiobs/1`, lineage tags | both keys equal `anchor_id` in information (kind, key, side, subject); CAP imports `api_key` from `fabric.ids`; lineage is witness `origins` |
| DIE, WBQ, WB3 | `BuildFactAnchor`; origin families; `lineage_group` | `build_fact`; families and groups become registry tags (data additions, s10) |
| KEV | lane `exploitation-context`, row `kev-context` | `cve` witnesses with source `kev-catalog`; no new rows; KEV cannot label a function (`function` has no stated role) |
| YRX | K `Anchor.kind` gains `rule` | dropped: K stays a search-hint contract; YRX uses fabric `rule` |
| K `Anchor` | module, api, string, feature, component, pdb | explicit module `advisory_phrase` stated; feature and component `advisory_phrase` hint; string `string` hint; api `import` hint; `pdb` verified-bytes `build_fact` `pdb=<name>` observed |

## 5. Synergy test

`tests/test_fabric_synergy.py::test_one_api_three_channels_count_independently`, synthetic, all in code. Project `P` is bound to older `a*64` and newer `b*64`; pair `F` (older 0x1000, newer 0x1040) and pair `G` (older 0x2000, newer 0x2040) come from UE (source `pairing`). Publishes:
1. CAP via `capa` (vivisect): capability `create process` and import `RtlULongAdd`, observed newer, about `F`. UE call set (`call-label`, Ghidra): the same import about `F`. PE import delta (`pe-import`): the import with no subject. WB3 (`floss`): a string observed newer about the newer `image:` key of `F`.
2. For `G` the import comes from `capa-ghidra` and `call-label`.
3. KB (`advisory-text`): CWE-190 stated; NVD, MSRC and KEV repeat CWE-190; the hint import `RtlULongAdd` with side none.

Expected: `F`'s import anchor has 2 witnesses and 2 independent components; `G`'s has 2 witnesses and 1; the CWE-190 anchor has 4 witnesses and 1 component; `find(kind='import', key='rtlulongadd')` returns exactly 4 anchors in canonical order (observed with no subject, observed about `F`, observed about `G`, then the hint), so the hint meets the observed evidence by key and the independent components over the observed anchors about `F` and `G` are 2 and 1; `find(subject=F)` returns the capability, the function-level import and the string (reached through `PairRef` members) but neither the file-level import nor `G`'s. Controls: the same publishes into a project bound with older and newer swapped raise `PT-FAB-ORIENTATION` and change nothing; for a project where CAP never ran, `resolve('capability', ...)` answers `unknown`; republishing CAP's batch with one anchor removes its other anchors and keeps KB's. Each channel alone gives a pair, a capability or a hint; only the join says "advisory hint met by two independent channels in F and by one in G".

## 6. Traps and guards

| Trap | Guard |
|---|---|
| Same-origin evidence counted twice (capa on Ghidra plus Ghidra call labels; NVD plus MSRC plus KEV CWE) | witnesses carry origin tags; `independent_count` is the number of connected components; `publish` requires tags == registry tags of `source` (`PT-FAB-ORIGIN`); an unknown source fails closed |
| A hint or advisory sentence read as found evidence | `role` is in identity and in the roles-by-kind table; documentary kinds cannot be observed; chips read "observed", "stated", "hint" |
| Missing read as negative | no `absent` status or API; `resolve` returns `unknown`; an empty `find` is not a statement |
| Older and newer swapped | pair anchors carry both SHA-256; one-sided observed anchors carry `input_sha256`; a bound project rejects a mismatch (`PT-FAB-ORIENTATION`); a swapped project has other `anchor_id`s |
| Untrusted text (advisory, strings, capa names) | `plain_line` on every text field, <= 200 or 300 characters, parity with `sanitize_text`; a string is a hash plus a <= 200-character label; the producer redacts secret-looking values |
| `api_key` folding merges two names (it is also not idempotent: a second fold can strip another letter) | the key is join-only and applied once to the name as the tool reports it; the spelling stays in facet `name`; the display witness shows it |
| Key drift across Python versions | `string_key` avoids `casefold`; NFC plus ASCII lower case only; golden digests in the tests |
| Unbounded growth, stale batches | F-01, F-02, F-03 raise `PT-FAB-LIMIT`; publish replaces per (producer, batch); atomic, no partial state |
| A producer forges independence or identity | closed `PRODUCERS`; registry check; `verify_anchor` recomputes `anchor_id`, `witness_id` and `pair` (`PT-FAB-INTEGRITY`) |
| Silent deletion of analyst work | a sink removes only its own (producer, batch); analyst content lives in `PinPort` rows (FAB-4) that no producer can retract |
| Fabric used as a ranker | nothing scored or counted is persisted; `find` order is canonical (kind, key, side, role, subject, id); PIL ranks |
| Invisible characters in source (bidirectional controls, separators, combining marks; an authoring tool may turn `\u` escapes into the raw characters) | the sources build them from code points and `test_no_fabric_file_hides_an_invisible_character` scans every FAB file, this plan included |

## 7. Contracts

Package `patchtrace.fabric`, contract `fabric/1`. Additive only: new optional fields default to None; new kinds, roles, sides and producers are appended to the tuples, and a reader skips and counts what it does not know instead of failing the batch.

- `limits.py`: `ERROR_CODES`, `EXIT_CODES`, `FabricError(code, message, reason=None)` (a fixed template, never untrusted text), `FabricLimits` and `DEFAULT_LIMITS`. F-01 anchors per publish 20,000; F-02 per project 200,000; F-03 witnesses per anchor 16; F-04 facets per witness 16; F-05 label chars 200; F-06 key chars 200; F-07 facet value chars 300; F-08 RVAs per pair side 256; F-09 page rows 500; F-10 origins per witness 8; F-11 batch chars 64; F-12 resolve candidates 20; F-13 ref id chars 256; F-14 pointer chars 4096; F-15 tool chars 64.
- `contracts.py` (strict, frozen, extra forbidden): `Ref{kind, id, pointer?, sha256?}`; `Witness{witness_id, producer, batch, source, origins[1..8], label, facets[<=16 of (name, text)], tool?, tool_version?, input_sha256?, ref?}`; `PairRef{older_sha256, newer_sha256, older_rvas, newer_rvas}`; `Anchor{anchor_id, kind, key, side, role, subject?, pair?, witnesses[1..16]}`. In-process dataclasses: `AnchorQuery{kind?, key?, side?, role?, subject?, producer?, offset, limit}`, `AnchorPage{items, total}`, `Resolution{status found|ambiguous|unknown|unsupported, anchor_id?, label?, candidates, count}`, `PublishReport{added, merged, unchanged, removed}`.
- Vocabulary: kinds as s4; sides `older, newer, both, none`; roles `observed, stated, hint`; producers `core, ue, cap, die, wb3, wbq, wb2, wb1, yrx, kb, kev, pil, analyst` (this order picks the display witness). Roles by kind: function observed; string, import observed or hint; capability observed; rule, build_fact observed or stated; advisory_phrase, cwe stated or hint; cve, kb stated. Reserved facet names (convention): `name, dll, exact, phrase_kind, basis, namespace, scope, change, kev, date_added, snapshot, redacted`.
- Functions other slices call. `ids.py`: `anchor_id`, `witness_id`, `anchors_digest`; key constructors `pair_key`, `image_key`, `pair_members`, `string_key`, `api_key`, `ordinal_key`, `cve_key`, `cwe_key`, `kb_key`, `key_for_value`; builders `make_witness` and `make_anchor` (sanitise, derive ids, typed errors); `check_anchor`, `verify_anchor`, `check_orientation`. `origins.py`: `components`, `independent_count`, `anchor_components`, `DefaultOriginRegistry`, `check_origins`. `memory.py`: `MemoryAnchorStore(registry=None, limits=DEFAULT_LIMITS)`, `NullAnchorSink`, `NullAnchorReader`.
- Identity: `anchor_id = domain_id('fabric-anchor', 1, {kind, key, side, role, subject})`; `witness_id = domain_id('fabric-witness', 1, <all other witness fields>)`; `anchors_digest = domain_id('fabric-anchors', 1, sorted (anchor_id, sorted witness ids))`. Labels, facets and timestamps are never identity. Merge = union of witnesses by `witness_id`.
- Errors (exit codes of `enrichment-cli/1`): `PT-FAB-INPUT` 2, `PT-FAB-KIND` 2, `PT-FAB-KEY` 2, `PT-FAB-ORIENTATION` 2, `PT-FAB-ORIGIN` 2, `PT-FAB-UNSUPPORTED` 2, `PT-FAB-LIMIT` 3, `PT-FAB-STALE` 3, `PT-FAB-STORAGE` 3, `PT-FAB-INTEGRITY` 3, `PT-FAB-NOTFOUND` 4, `PT-FAB-CANCEL` 5. FAB-0 raises INPUT, KIND, KEY, ORIENTATION, ORIGIN, LIMIT and INTEGRITY; the rest are reserved for FAB-1 and FAB-5.
- `ports.py` (Protocols only): `AnchorSink.publish(project_key, anchors) -> PublishReport` (atomic; first removes every witness of each (producer, batch) present in the call; a no-op sink is valid) and `retract(project_key, producer, batch)`; `AnchorReader.get(project_key, anchor_id)`, `find(project_key, query) -> AnchorPage` (a `pair:` subject also matches its member `image:` subjects), `resolve(project_key, kind, value, side)` (`value` becomes a key through the kind's constructor, a `function` value that is not a key matches facet `name` exactly; code-side kinds consider observed anchors only; side older or newer also matches `both`; side None is any); `OriginRegistry` as PIL's. `project_key` is the persisted project id (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`). `PublishReport` counts the anchors a call touched (in the call, or losing a witness to the replacement): `added`, `merged` (witness set changed), `unchanged`, `removed`. `MemoryAnchorStore.bind_pair(project_key, older_sha256, newer_sha256)` switches on `check_orientation`, whose reasons are `orientation-swapped`, `pair-mismatch`, `input-sha-mismatch`, `subject-sha-mismatch`, `subject-side-mismatch`; an unbound project cannot tell a swapped pair from a right one and says so by accepting both.
- Store request (FAB-1, the integrator edits `KINDS`; not in `DERIVED_KINDS`, no `extension_version` bump, as `patch-intent`): `anchor-batch`, one row per (project, producer, batch), id `fabric:<producer>:<batch>`, body `{contract:'fabric-batch/1', producer, batch, origins_digest, anchors:[Anchor]}` (11 MiB at F-01 for one-witness anchors [M]; the store refuses a body above 24 MiB with `PT-FAB-LIMIT` reason `row-size`, because the enrichment row limit is 32 MiB), Guard = (project_id, run_id, raw_sha256, `input_digest = domain_id('fabric-batch', 1, {producer, batch, origins_digest, anchors_digest})`); a stale row is listed with its flag, never hidden. FAB-4 adds `anchor-pin` (analyst events, id `fabric-pin:<uuid>`, text <= 2 KiB). Cache-key input for consumers: the project's `anchors_digest` (PIL may add `fabric_digest` additively).

## 8. CLI and GUI

CLI (FAB-5, read-only: producers publish, analysts do not edit anchors from a shell): `patchtrace fabric list|show|resolve|stats --project <path>` with `--kind --side --role --subject --limit --json`. Qt-free `fabric/cli.py`; adapter `cli_commands/fabric.py` of <= 25 lines; envelope `enrichment-cli/1`; exit 0 ok, 2 invalid input, 3 runtime or partial (stale, integrity), 4 legitimate no result (`resolve` unknown, empty list), 5 cancelled.

GUI (FAB-6, after GUI F5): one panel through the registry and no widget class of its own. `PanelSpec(id='related', title='Related evidence', area='bottom', tabify_with='leads', shortcut='Ctrl+Shift+J', requires=('project',), anchors_in=anchors_out=all ten kinds)`; `panels check` arbitrates the shortcut.
- Model and view: rows are the anchors whose subject is the selected pair (`find` with `AnchorQuery.subject`), loaded by a worker through `ctx.tasks` (500-row pages) into the framework `VirtualTable` (virtualized past 100,000 rows). Columns: Kind, Label, Side, Role (chip with glyph and text: `+` observed, `i` stated, `?` hint), Witnesses ("2 independent of 3"), Producers. Order is the canonical `find` order; no score column and no sum.
- Keyboard and accessibility: the table is one Tab stop; arrows move rows, Enter or double-click routes the anchor through `AnchorRef.from_fabric` and the `AnchorRouter` to the owning panel, Space opens the detail pane, Ctrl+C copies TSV (all framework behaviour). Names: "Related evidence panel", "Related evidence table", "Kind filter"; cells carry `AccessibleTextRole`, for example "Imports RtlULongAdd, newer, observed, 2 independent origins of 3 witnesses". Tooltip ids: `related.dock`, `related.action`, `related.role`, `related.witnesses`. Teach ids: `fabric.origin.once`, `fabric.role.hint`, `fabric.related.unknown`.
- Copy (ASCII): empty "Nothing else is known about this function yet. Run capabilities, strings or build tools to add evidence. Missing evidence is unknown, not a negative result."; no-project, loading, partial, stale, error (with the `PT-FAB-*` code) and too-large use the framework copy; there is no blocked state of its own (`requires=('project',)`). Detail pane: "Seen by {n} witnesses from {m} independent origins: {producers}. Witnesses that share an origin count once."; for a hint "A hint is something to look for; it was not found here."; for a statement "A statement comes from an advisory or catalog; by itself it says nothing about this code."
- Qt, UIA and threading pitfalls, the offscreen approach and the 200 ms first-paint and 100 ms filter budgets are the GUI plan's s8.4 to s8.11, which cite the Qt and Microsoft sources; this panel adds none. Its test drives the pure view-model with 100,000 synthetic anchors and, after F2, the widget under offscreen Qt with the 20x repeat gate.

## 9. Slice plan

| Slice | Scope | Exclusive files | Deps | Tier (reason) | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| FAB-0 | this plan; pure core, memory and null implementations | this file, `src/patchtrace/fabric/{__init__,limits,contracts,ids,origins,ports,memory}.py`, `tests/test_fabric_*.py` | none | Sonnet (specified, pure) | M, ~1,200 LOC + ~1,700 test | focused tests green on 3.12 and 3.13, ruff clean, parity with pilot and unified, mutation check | none |
| FAB-1 | `EnrichmentAnchorStore` (sink and reader over `anchor-batch`), schemas with regenerate-and-compare, per-anchor skip-and-count on read, `bind_pair` from the project | `fabric/store.py`, `tools/generate_fabric_schemas.py`, `docs/schemas/fabric/`, tests | FAB-0; integrator `KINDS` edit | Sonnet (Opus review if Guard semantics fail) | M | round trip, stale flag, retention untouched, old reader ignores the kind | keep the memory store |
| FAB-2 | converters from existing contracts (K `Anchor`, `PilotAnchor`, DIE `BuildFactAnchor` when built) and registry data additions (s10) | `fabric/convert.py`, rows in `fabric/origins.py`, tests | FAB-0 | Haiku (mechanical) | S | each K and PIL sample converts and verifies | each track converts its own |
| FAB-3 | adoption: `pilot/origins.py` and `pilot/ports.py` rebound to the fabric; PIL goldens re-pinned | PIL-owned files, by the PIL owner | FAB-0, FAB-2 | Sonnet | S | PIL suites unchanged except the origins digest | PIL keeps its copy |
| FAB-4 | `PinPort`, `anchor-pin` rows, WB1 "Pin as lead" | `fabric/pins.py`, tests | FAB-1 | Sonnet | S | pins survive batch replacement and retraction | no pin button |
| FAB-5 | `fabric` verbs | `fabric/cli.py`, `cli_commands/fabric.py`, tests | FAB-1, GUI F1b | Haiku | S | envelope and exit codes | none |
| FAB-6 | `related` panel and `AnchorRef.from_fabric` | `fabric/panel.py`, `ui_related.py`, tests | FAB-1; GUI F1, F3, F4, F5 | Sonnet | M | state matrix, hostile text, `a11y_audit`, 100k rows, 20x repeat | table-only first release |

## 10. Amendments required, test and QA plan

Amendments (exact edits for the integration owner; FAB-0 edits no existing spec):
- `GUI-integration-plan.md` s7 `AnchorRef` row and s11 Q1: the fabric kinds are the ten GUI names verbatim; `from_fabric(anchor, run_id, origin)` is a pure function.
- `GDE-integration-plan.md` s7.6 and Q3: the port is `AnchorReader.resolve(project_key, ...)`; `absent` is unavailable in v1.
- `KB-integration-plan.md` s4 ports and Q9: `AnchorSink.publish` takes fabric `Anchor`s; use the kind table above. `PIL-integration-plan.md` s4: rebind at FAB-3.
- `CAP-integration-plan.md` s4: `capobs/1` and `apiobs/1` are views of `anchor_id`; `api_key` lives in `fabric/ids.py`. `DIE-integration-plan.md` s7: `BuildFactAnchor` gets a converter. `WB1-integration-plan.md` s4: pin becomes `PinPort`.
- `YRX-integration-plan.md` s10 row for `intelligence/contracts.py`: delete the `Anchor.kind` edit. `KEV-integration-plan.md` Q15: the row stays `kev-context`.
- `docs/plans/multi-instance-coordination.md` s4: the no-op sink is `fabric.memory.NullAnchorSink`. `enrichment/storage.py` `KINDS`: `anchor-batch` at FAB-1, `anchor-pin` at FAB-4.
- Registry data additions, requested by their owners in a FAB PR: CAP lineage (`D_pe_tables`, `D_capa_rules` on capa observations versus the PIL table's single `D_vivisect`), KEV `kev-catalog`, WBQ `pe-self-report` (DiE reads the Rich header), WB3 `emulation:` and `ir:` groups.

Tests: red first; hermetic (no Microsoft data, no network, no fixtures: everything is built in code, so no `.gitattributes` line); short explicit parametrize ids; no sleeps. Goldens pin `anchor_id`, `witness_id`, `string_key` and `anchors_digest`. Properties (hypothesis): `components` equals PIL's on random tag sets; the publish order of different batches does not change `anchors_digest`; republishing is idempotent; replace then retract leaves no witness of that batch. Parity: `pair_key` equals `unified.keys.row_id` and `pilot.keys.candidate_key`; the registry table contains every PIL source with equal tags; `clean_line` equals `sanitize_text`; the kinds, error codes and F-xx limits of this plan equal the code. Guards: `ports.py` holds Protocols only; no import of Qt, sqlite3, socket, subprocess or another feature package (AST); no float in any dump. Windows pitfalls: LF in this plan, `>=` on timings, no POSIX paths. Live gates only the owner or CI can close: the Windows CI run of the new tests, the frozen-smoke import once a consumer exists, and the 100k-row GUI walk with NVDA and Narrator (GUI M26).

## 11. Open questions (a default for each; none blocks)

1. Kind spelled `import` (GUI, GDE) not `api` (K, KB): default `import`.
2. Add `absent` once a producer can declare a complete batch: default later, as an optional `publish` argument in FAB-1.
3. Should `capa` keep PIL's single tag or gain CAP's lineage: default keep the PIL table until CAP-7 lands, then change it in one data PR.
4. One store row per (producer, batch) or one per project: default per batch (bounded rows, cheap replace).
5. `project_key` is the project id: default yes; the GUI `ProjectKey.identity()` supplies it.
6. Panel shortcut and tab group for `related`: default `Ctrl+Shift+J`, tabbed with `leads`.
