# Combined source assembly review — 2026-11-19

Reviewed source: `9335e7dcadc6d0337243f894e8f234ccc74bc62e`.
Tree: `05509de7d8038a9079fe80b08fa97da8cb61b7fd`.
Core319 baseline: `ac3a98150bd17bbbd973c7e7dcadb7edcf551934`.

**Scoped source approval:** no component mismatch, unintended runtime overlap or
broader native/package/held-input source import was found. This review reads
immutable Git pins; it changes no runtime source and runs no broad test suite.
It does not approve release gates. The unsuppressed runtime security scan
remains red, as recorded below.

## Exact component equality

All 30 changed runtime files match the already reviewed component pins:

| Component | Runtime files | Reviewed pin |
|---|---:|---|
| Inventory | 17 | `0afd6f5410f8a527d697f79e415b31efcc84407a` |
| Bounded GUI help/announcements | 3 | `dc841095307c486ad8397e6e44ccea2c98b4e7d1` |
| Shared tool admission | 1 | `41af7c7e3f3bd5e50c49b86bc061fdef834b4daf` |
| Search source binding | 4 | `b5aace25a36809ae7e4ab044e692c12015772a7d` |
| Strings shared composition | 5 | `2f8f69c268dcc03750596114ef891ad651c59506` |

The 106 inventory, shared-publication, schema and selected-control blobs checked
in the earlier source audit still match 0afd. The inventory author does not
self-certify that boundary here: the separate GUI review of 0afd supplies its
independent approval; this audit establishes equality in the assembly.

Of 27 protected core repair files, 25 are byte-identical. The two intentional
overlaps are `search/cli.py` and `search/qt_panel.py`, both exactly matching b5.
The CLI diff binds optional source ports after the saved-query plan handling.
The dock retains SavedController and owner-thread service access while changing
worker capture to BoundService. Saved query models, actions, controller and
tooltip code remain exact core blobs.

Dependency declarations are unchanged. The only changed tool is the reviewed
inventory schema generator. The only workflow change adds shared-owned/KBC
publication controls to the existing Windows publication step; no gate is
removed. The recovered inventory and Search module-index sections are both
present, alongside the shared admission and Strings composition entries.

## Shared boundaries

- **Ownership/publication:** core persistence, owned publication, advisory
  storage, raw and Strings export repairs remain byte-identical. Inventory
  callers retain the reviewed publication boundary. Search and Strings import
  the one shared admission module; public ToolStore and EnrichmentStore remain
  unchanged.
- **Worker ownership:** Search captures source values on the store owner thread
  and deep-copies the project into BoundService. Strings captures admitted FLOSS
  source values for its existing immutable Request. The reviewed project,
  generation and cancellation result guards remain intact.
- **Consent:** stored-source comparison adds no tool invocation or network
  retrieval. Inventory `fetch_source` verifies the reconstructed plan, exact host
  set and plan digest before opening a request. URL and DNS/TLS checks, disabled
  proxy inheritance/automatic redirects, and ordered-chain admission remain the
  reviewed 0afd implementation.
- **Scope/provenance:** saved-scope admission is the exact core implementation;
  the inventory service retains loaded-index/unreadable propagation. Cache
  evidence uses the admitted originating run. Strings retains recorded raw
  provenance and does not claim to reread current raw-file bytes.

The separate corrected Search persisted-row proof and its historical fixture
correction are retained in `../tool-admission-20261119/`. This review does not
revive the withdrawn claim based on the original rolled-back CLI mutation.

## Unsuppressed runtime security diagnostics

Both trees were exported from Git and scanned with Ruff 0.17.5 using:

```sh
python -m ruff check src --isolated --select S --ignore-noqa --no-cache \
  --no-respect-gitignore --output-format json
```

Scope is runtime `src` only. These results are not a scan of tests/tools or a
substitute for every hosted security mechanism. Both commands exited 1.

| Comparison | Findings |
|---|---:|
| Core319 baseline | 68 |
| Combined 9335 source | 82 |
| Added | 14 |
| Removed | 0 |

The comparison uses a multiset of rule, relative file and diagnostic message,
ignoring line shifts. Added findings are 12 S608 diagnostics in inventory
storage, one S310 in its HTTP opener, and one S608 in Search wiring.

The inspected inventory SQL fragments come from fixed inventory/support table
constants or `docs`; the production public callers do not accept a table name,
and record values remain bound parameters. Search interpolates only a fixed
number of question-mark placeholders derived from its constant kind tuple;
kind values and the limit are bound. The flagged opener first admits the HTTPS
scheme, fixed host/path policy and GET method; its production connection retains
DNS-pinned public addresses and hostname-verified TLS. Exact plan/host consent
is checked by its calling fetch boundary before opening a request.

These are source-boundary observations, **not suppressions, waivers, or a green
security verdict**. All 82 diagnostics remain in the raw receipt. Combined
tests, hosted security jobs and native/package qualification require their own
outcomes.

## Retained evidence

`evidence.zip` contains the complete component/core blob map, both raw Ruff JSON
outputs, and their delta. `manifest.json` records source/tree pins and all member
digests. Archive CRC and every member SHA-256 were verified. Archive SHA-256:

`7a752b01e24f824d8a453fd501603a07cedbec84271568fcde37776ef67ea90b`.
