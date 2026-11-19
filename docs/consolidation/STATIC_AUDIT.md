# Supplemental static security review — 2026-11-19

## Scope and result

This review classifies the **65 actual Ruff `S` findings** in
`verification/security-static-current.json`, initially against source
`69fa6b8b588645a895b3edbdeff3aa4b74856be7`. It traces reported operations and
their callers; it is not a claim that the scanner is clean or the source secure.
The normal configured Ruff gate and this supplemental rule selection are
different checks.

The baseline `fdc2696c` and current receipts contain the same **multiset** of
normalized `(source path, rule, message)` findings, including repeated findings.
That establishes no added findings under this comparison, not absence of defects.
Indeed, review reproduced a malformed CSAF redirect escaping the typed error
boundary. The narrow correction below was applied after integration head
`af8772bf9f5abe54eee214f8b05f379389b2f076`.

| Rule | Count | Classification |
| --- | ---: | --- |
| S608 | 21 | SQL fragments trace to placeholders, fixed dictionaries/constants, or literal internal callers; no injection path demonstrated at these sites. |
| S105 | 14 | Lexical, display or algorithm tokens; no credential literal identified in the flagged expressions. |
| S110 | 13 | Observer, cleanup, optional metadata and persistence-error suppression; the historical failure-history finding is updated by Phase 4 below. |
| S101 | 9 | Internal state or source-definition assertions; no authorization boundary relying solely on these assertions found. |
| S310 | 5 | Guarded URL-dispatch paths; one malformed-redirect error-contract defect reproduced and corrected. |
| S603 | 1 | Deliberate configured-tool execution with argv/environment/supervision controls; execution still trusts the configured tool. |
| S314 | 1 | Bounded XML decoded and scanned for DTD/entity declarations before ElementTree; parser/runtime qualification remains separate. |
| S108 | 1 | Random staging directory under the project, with exclusive creation and containment check. |
| **Total** | **65** | **All reported sites classified; no warning suppression added.** |

Receipt SHA-256 values:

- Baseline JSON: `36eb550cdb6e3125dc8978a8b0b4708d6d37b178c381a61b2177df0c5cc2d350`.
- Current JSON: `3b80a80a61847a2e354d50db95f7a53296a375e83ad958ba971f958f7e3a7153`.

## SQL construction: all 21 S608 sites

Locations below identify the scan records. Paths are relative to
`src/patchtrace/`; symbols are authoritative if later changes move line numbers.
The SQL review also examined adjacent statements using the same builders.

| Reported location | Evidence for classification |
| --- | --- |
| `diaphora/sqlite_guard.py:54,66` | `count`/`rows` first index `SCHEMA[table]`; only `config`, `results`, `unmatched` and their fixed columns qualify. Row limits are bound. Production callers supply those literals. |
| `enrichment/storage.py:348,399` | Dynamic text consists only of comma-separated `?` markers. Kinds and deletion IDs remain bound; deletion chunks are capped at 400. |
| `kbcorrelation/store.py:302` | `_dictionary` has literal production callers for `kbs`, `cves`, `products`; imported names are bound values. The helper's identifier itself is not a public input boundary. |
| `kbcorrelation/store.py:320` | `_edges` receives only literal `kbs.name=?` or `cves.name=?` clauses; requested names remain bound. |
| `persistence.py:546` | A placeholder list for at most 500 history sequence IDs; IDs remain bound. |
| `pilot/store.py:387,427` | Placeholder lists for 400-ID chunks; retention kind and prefix pattern also remain bound. |
| `project_cli.py:198` | Interpolated `LIMIT` is the source constant `DERIVED_KIND_LIMIT = 64`. |
| `search/segment.py:199` | `_insert` receives keys created by `_rows`/validated `_fts_names`; `columns[table]` gates table/column names before execution. Rows remain bound. |
| `search/service.py:140` | `_fetch` receives literal FTS table names. `_in` generates fixed-column placeholder clauses; expressions, filters and cap remain bound. |
| `search/service.py:186,196` | `DOC_COLUMNS` is constant; the optional function-kind clause is literal; filter values and cap are bound. |
| `search/service.py:229` | `where` is assembled from fixed SHA/RVA/subject templates and placeholders. Actual SHA, address-derived subjects and filter values are bound. |
| `search/service.py:238` | Constant projection and placeholder list for fixed `NAME_KINDS`; values, flag and cap remain bound. |
| `unified/ir/ingest.py:160` | `flush` iterates literal table names `fn`, `bb`, `str`, `cst`, `ref`, `ins`; row width determines markers and row content is bound. |
| `unified/ir/reader.py:297` | Projection combines literal columns with source constant `FN_COLUMNS`. |
| `unified/ir/schema.py:173` | `COLUMNS[table]` and `_ORDER[table]` gate identifiers and ordering before execution; normal callers iterate fixed `TABLES`. |
| `unified/store.py:770,844` | Placeholder lists for chunks of at most 400 IDs; IDs and kinds remain bound. |

Three independent, in-memory controls actually passed: a SQL-looking dictionary
value remained literal and its table survived; a SQL-looking search filter
became `AND d.kind IN (?)` plus a separate parameter; an unknown IR table name
raised `KeyError` before executing SQL. These are narrow controls, not exhaustive
fuzzing or a test-suite result. Existing search/Diaphora/retention tests were
inspected, not rerun for this SQL review.

Keep `_dictionary`, `_edges`, `_fetch` and `_in` internal or add explicit
identifier/fragment allowlists before exposing new caller-controlled arguments.
Parameterized values do not establish safe admission of attacker-authored
SQLite schemas, virtual tables, triggers, retention identities or expensive
queries; those are separate boundaries.

## URL dispatch: all five S310 sites

- `acquisition/transport.py:149`: public operations call `_consented`/`_check`
  before the opener. Initial URLs require exact consent, HTTPS and approved
  hosts. Winbindex redirects are refused; a symbol download permits one checked
  Azure blob redirect. Fixed request headers and `ProxyHandler({})` are used.
- `enrichment/intelligence.py:166`: plan/consent validation precedes fetch;
  `_attempt` checks the HTTPS provider allowlist each hop. A cross-host redirect
  removes the NVD `apiKey`. Environment proxies and automatic redirects are
  disabled, with response/deadline bounds applied by the transport.
- `intelligence/csaf/transport.py:111`: consent, HTTPS host/port/path restrictions
  and per-hop checks precede dispatch; the default opener disables proxies and
  automatic redirects. The malformed-target gap below occurred before the next
  checked dispatch.
- `kev/transport.py:99`: `KevConsent` admits fixed catalog URLs; redirect targets
  must satisfy the strict HTTPS grammar and retain the initial host. Automatic
  redirects and environment proxies are disabled.
- `providers.py:126`: `ProviderConfig` and `request_completion` validate endpoint
  shape. Remote OpenAI-compatible endpoints require HTTPS; Ollama requires a
  loopback host and refuses mapped IPv6 literals. Redirects and environment
  proxies are disabled. This review does not qualify the entire UI consent flow
  or a configured remote provider's behavior.

These arguments rely on the current guarded callers of the low-level opener
helpers. No live request, DNS/TLS compatibility check or remote-provider
qualification was performed.

### Reproduced and corrected: malformed CSAF redirect

A fake response to an allowed CSAF URL with status 302 and
`Location: https://[` raised raw `ValueError('Invalid IPv6 URL')` from
`urllib.parse.urljoin`. The response closed and only the initial allowed URL was
requested. The transport's `IntelError` contract was bypassed; the CLI's typed
error wrapper could not handle it through that contract. This did **not**
demonstrate SSRF, an extra request or code execution.

The CSAF transport file was identical in PR319 (`a56ab13a`), PR320 (`188b4962`)
and the reviewed integration source, so those retained branches did not already
correct this case. The repair catches only `ValueError` from joining the
redirect URL and raises the existing
`IntelError('PT-INTEL-CONFIG', 'invalid URL refused')`, matching `check_url`'s
malformed-URL taxonomy. The existing `finally` still closes the response. No
schema or public contract changed; SPEC-28 sections D/J/L already define the
guarded transport and typed CLI mapping.

[The ten regression controls](../../tests/test_csaf_redirect_integrity.py)
cover four malformed bracketed targets, three valid relative/absolute redirects
and three disallowed targets. They check response closure, no invalid-target
dispatch/cache write, and exact original/final URL, body and SHA-256 preservation
on success.

| Verification | Actual result |
| --- | --- |
| New controls before runtime edit, integration base `af8772bf` | **4 failed, 6 passed in 1.63s**; the four raw `ValueError` cases failed. |
| New controls plus existing `test_intel_transport.py`, final rerun | **33 passed in 1.08s**; `verification/static-csaf-green-v3.log/xml`. |
| Changed transport/test files, configured Ruff | **Passed**. |
| Other offline URL/environment/XML probes | **26 controls passed**; no network or tool subprocess launched. |

The first green attempt was interrupted by an unavailable execution environment;
its result is unknown. After recovery, a rerun had 30 passes and three fixture
errors because its `/tmp` parent no longer existed. Recreating only that test
directory allowed the final 33-case run above. Receipts retain both attempts.
An automated cybersecurity-risk flag prevented a child agent's read-only
follow-up review; no specific source finding was supplied. Root subsequently
reviewed the exact correction and all ten controls and found no blocker. The
filter outcome is not evidence that the reviewed code or review tools are unsafe.

## Process, environment and XML findings

**S603, `jobs.py:346`.** `run_process` requires an absolute executable, validates
argv and environment entry structure, calls `Popen` with `shell=False`, closes
stdin and supervises time/output/process-tree cleanup. Windows batch arguments
have a separate metacharacter refusal. `backend.build_child_env` and
`secondary.engine_env` constrain inherited variables; BinDiff uses private
configuration locations. These controls govern deliberately configured analysis
tools. Absolute paths do not authenticate tool bytes or sandbox their behavior.
Explicit unrestricted-environment settings and retained library/plugin search
variables remain trust choices; this review did not qualify native Windows
launches or every engine.

**S314, `pe_overview/manifest.py:148`.** `observe_manifest` caps bytes, strictly
decodes supported UTF-8/UTF-16 forms, rejects DTD/entity markers in that decoded
text, then passes that same text to ElementTree. Three fresh encoding controls
verified that a DTD never reached the parser; a valid manifest and over-limit
control behaved as expected. Existing entity, encoding, inert-include and
malformed-XML tests provide further seams, but were not rerun here. The byte cap
does not by itself prove a hard CPU/RSS bound for every tree or every packaged
Expat build. No dependency vulnerability audit was performed.

## Remaining 37 findings

**S105 (14):** `enrichment/signals.py` has seven comparisons against punctuation
tokens; `gui/qt/chips.py` has three `plain` style comparisons; `gui/qt/theme.py`
has one; `rules/contracts.py` has the hex-token regex and wildcard comparison;
`unified/ladder/types.py` compares pass ID `P00`. The flagged expressions contain
parser/display/algorithm vocabulary, not session credentials.

**S101 (9):** `callgraph/delta._change`, `callgraph/minimap_qt.model`,
`enrichment/wil._region`, `kbcorrelation/store._cas`,
`secondary/bindiff_probe.probe_report`, `secondary/bindiff_run.run_bindiff` and
`ui_series._show_view` assert state established by their current callers or
earlier results. `kbcorrelation/panel_qt` and `unified/ladder/passes` check static
definition consistency. Optimized Python removes these checks; malformed-state
recovery and `-O` behavior were not exhaustively tested. No sole authorization
gate was found at these sites. If caller contracts change, replace boundary
assertions with typed validation rather than relying on optimization-sensitive
diagnostics.

**S110 (13):**

| Source | Count | Disposition and remaining limit |
| --- | ---: | --- |
| `jobs.notify_progress` | 1 | A failing observer is isolated from process supervision. |
| `netutil.interruptible` | 1 | Late abandoned-result cleanup is best effort; its failure cannot publish a cancelled result. |
| `secondary/scheduler` | 2 | Observer failure and delivery during exception unwinding are isolated; no failure-to-success conversion established. |
| `service` creation rollback | 2 | Unprovable database state is retained; close is best effort. Cleanup failure can leave remnants. |
| `ui_engine_setup` settings write | 1 | Preference persistence failure is ignored. |
| `ui_evidence` settings/failure publication | 2 | One preference write; one failed/cancelled-run persistence handler. The latter can lose the attempt's durable history while still showing the engine error: a real observability gap, not a demonstrated successful-result promotion. |
| `unified/extract/ghidra_script` | 4 | Two optional runtime-version probes and project/decompiler cleanup handlers. Missing provenance fields and cleanup failures need separate native qualification. |

**S108 (1), `pilot/store.py:146`:** the string fragment `/tmp-` forms a directory
under the contained project path `intelligence/pilot`, followed by
`secrets.token_hex(8)`. `mkdir` uses exclusive creation. This is not a fixed
shared temporary-directory name. Concurrent hostile filesystem substitution
was not exercised by this classification.

## Next checks and limits

1. Qualify the final integration head with the normal repository gates and the
   required hosted/platform checks. These scoped probes do not replace them.
2. Audit resolved dependency versions and packaged interpreter/Expat/Qt/native
   components against vulnerability advisories; that work is still unperformed.
3. The Phase 4 diagnostic recovery and real post-write controls are complete;
   retain malformed-row retention and the underlying post-write exception as open work.
4. Retain URL/parser negative controls on supported runtimes, and re-audit SQL
   helpers if new callers can supply identifiers or SQL fragments.

This report does not cover every unreported statement, filesystem race, native
tool, network service or dependency. Existing PR319/320 work is neither repeated
nor declared qualified by unchanged scanner findings.


## Phase 4 disposition of failure-history observability

The warning tables above describe the audited baseline. Recovered source `254190a0b36153d28f76782f8d5dae26e9d9a020`, integrated through `520b524b`, preserves bounded attempt-storage diagnostics without replacing original engine errors or prior trusted sets. Generic publication exceptions now say **"Attempt storage unconfirmed"** because a row may already have committed. Definite not-saved wording requires a returned ownership refusal; a result-kept claim requires confirmed publication. Lifecycle resets clear transient details. Malformed-row retention and the underlying post-write retention exception remain open.

Baseline: 12 failed/8 passed in 19.07s. Recovered slice: 79 passed in 42.63s. Real SQLite post-write controls: 2 failed in 3.59s. Final affected UI/host selection: 81 passed in 37.33s; whole-tree Ruff and whitespace checks pass. Independent source review found no blocker in the recovered diagnostics, scheduler/producer boundary or persistence ownership/refusal contract. Authored offscreen controls do not qualify native comparators or atomic storage.

[History evidence](evidence/history-diagnostic-20261119.zip): 9 verified payloads, 16,801 bytes; SHA-256 `60248a2e1bc603b6dba92451df639d22b7c58cc0d8153262a387242ae4dc5f67`.

This amendment does not rewrite baseline warning counts or claim a new complete static audit.


## Final supplemental scan on the Phase 4 source

The supplemental security-rule scan on `520b524b` reports **64 findings**. The
normalized comparison adds no warning and removes one S110 finding: the swallowed
`ui_evidence` attempt-publication failure addressed by the history diagnostic
slice. Configured whole-tree Ruff passes. The original 65-finding inventory above
remains the frozen `69fa6b8b` baseline; it is not rewritten as the final count.

Raw final receipt: `/tmp/pt81-final-results/security-static-final.json`. The
coordinator will archive it with later qualification evidence. These are scanner
findings, not a clean security verdict. Malformed-row retention, the underlying
post-write retention exception, and the other listed native/dependency/security
obligations remain open.
