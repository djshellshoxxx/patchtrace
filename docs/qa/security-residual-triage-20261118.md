# Residual strict-security review — 2026-11-18

## Result and scope

The six URL sites, the subprocess site and the additional current SQL site did
not yield a new production-boundary defect in this bounded review. Their input
guards were traced and exercised with independent local controls. The fourteen
S105 labels are parser, rendering or pass-identity tokens, not credentials.
Twelve remaining S110 sites have intentional observation, preference,
unknown-version or cleanup behavior; their primary-result guards and practical
limits are recorded below. Native cleanup completeness is not established.

Three confirmed defects found during the larger review have separate repairs:
the manifest DTD encoding bypass, deletion of an unowned staging directory, and
hidden engine-attempt persistence failure (including false “result kept” text).
Their original failures are retained, and unchanged probes pass on the current
continuation.

**The strict scan still fails with 80 findings.** Manual dispositions do not
change raw detector output, scanning policy, accepted baselines, allowlists or
release qualification. This packet contains no product changes or suppressions.

## Exact sources and detector accounting

Initial residual review used detached source
`36e14051a4d36f5c66df0186f037a4905b01bf05`. Final controls used a separate detached
checkout at **`3faf436a3b11c69220641a167cf424e7f4060839`**, the current continuation
over actual PR316. Of 23 reviewed files, 21 are byte-identical between those
sources. The only changes are the independently accepted staging and UI repairs;
their final source hashes match their original repair receipts. The comparison
is retained as `continuation-equivalence.json`.

| Snapshot | Source | Raw findings | Reason for the difference |
| --- | --- | ---: | --- |
| Original configured scan | `9e5a5303da6e9a745e604979932f814de8eca4b0` | 78 | Configured Ruff without explicit `--ignore-noqa`. |
| Original strict scan | `95bf8f5e71a4704befbf0e79f75ba64afe886cbc` | 79 | Isolated configuration and source suppressions ignored; 34 S608 sites. |
| Combined pre-UI-repair strict scan | `cdeada1b1bcc8078f31e6627e3a00b3bb8146542` | 81 | Manifest parser construction adds a second S314 diagnostic; retained-context metadata adds one S608. Root's earlier expectation of 80 failed and was not a scan pass. |
| Current complete strict scan | `3faf436a3b11c69220641a167cf424e7f4060839` | **80** | UI persistence failure is now reported, removing that silent-catch S110; no rule was disabled. |

All four raw snapshots are retained byte-for-byte with hashes and source/command
receipts. The current counts are S101 9, S105 14, S108 1, S110 12, S310 6, S314 2,
S603 1 and S608 35. Each command exits 1.

The original strict 79 divides into the previously reviewed 43 S101/S608 sites
and 36 residual sites. At the initial residual source, the 36 correspond to 37
diagnostics because one original XML site maps to two current XML warnings.
The accepted UI repair then removes one current S110. Adding the new SQL site
produces the final accounting:

`43 prior + 36 original residual + 1 extra XML + 1 new SQL - 1 repaired UI catch = 80`.

`strict-disposition-ledger.json` has an entry for every original strict finding,
the new SQL site, exact current file SHA-256s, original/current lines, current
statements, guard rationale, controls and limits. Its reconciliation asserts
that all 80 current `(rule, path, line, column)` positions are covered. Source
line extraction uses LF, matching Python AST and Ruff positions; Unicode line
separator characters inside a regex literal are not treated as source lines.
The prior 43-site evidence remains in
`docs/qa/security-contract-triage-20261118.md`; it is referenced, not silently
counted as a second new review.

## URL request boundaries — S310

Paths in the following tables are relative to `src/patchtrace/`. The named
low-level urllib helpers are not independent consent interfaces: their actual
production callers and request preparation are part of the boundary.

| Current site | Actual input and enforced boundary | Independent controls and disposition |
| --- | --- | --- |
| `acquisition/transport.py:149` | File-name-derived metadata or planned symbol-server URL. `_consented` checks exact URL/host, `_check` limits HTTPS/443/no userinfo/control text. Metadata redirects are refused. Downloads admit one checked Azure blob redirect and verify planned size and SHA-256. | Malformed scheme/authority/spelling and consent mismatches make no opener call; bad redirect makes no second call; authored non-executable bytes traverse the allowed blob path and match their digest. No new defect established. |
| `enrichment/intelligence.py:166` | Fixed CVE/provider plan. `_validate` rederives URL, headers and key-header and checks consent. Every hop passes `_check_url`; changing provider host removes the NVD key. | Tampered plans remain rejected even with matching forged consent. Disallowed redirects stop before another request. The supported cross-provider redirect strips the dummy key. No new defect established. |
| `intelligence/csaf/transport.py:111` | Explicit host consent, except offline cache mode. `get` and each hop enforce the exact Microsoft host, HTTPS/443, CSAF path prefixes and restricted URL spelling. | Initial and redirected URLs with bad scheme/host/path/userinfo/query are refused; missing consent fails; a valid same-host path works. No new defect established. |
| `kbcorrelation/sources/inventory_http.py:259` | Complete ordered URL plan, exact host set and plan digest. Redirect drift requires a new preview. The production opener revalidates URL/kind/GET. DNS answers are bounded, all validated as public before connecting, and used as numeric addresses without a second resolution; verified TLS remains required. | Bad raw URLs stop before opener construction; changed chain stops before contacting the new target; allowed chain works. Mixed public/private, mapped and translated private addresses are rejected before creating a socket. A fake socket receives only the once-validated numeric address. No new defect established. |
| `kev/transport.py:99` | Strict plan/consent names one fixed catalog URL. Redirects must remain plain HTTPS on that same host. Fixed headers; no proxy inheritance or automatic redirect following. | Wrong source consent and disallowed redirects are refused; a same-host redirect works and carries only the fixed headers. No new defect established. |
| `providers.py:126` | Explicitly configured endpoint from the Send context dialog. `interpret` validates exact context/digest. Constructor/request validate HTTPS remote or loopback local endpoints. Proxy inheritance and redirect followups are refused. | Nineteen independent fake-opener controls inspect exact POST destinations/messages, dummy-key handling, invalid endpoints, pre-cancellation and redirect refusal. Two actual Qt controls verify rejected consent sends nothing and exact preview/session-only credentials. No generic SSRF defect is inferred from an explicitly chosen HTTPS/self-hosted destination. |

The independent wrapper controls also invoke all five fixed transports' real
urllib request-construction functions with a recording director. Every request
has the expected URL and method; every opener has an empty proxy map and an
explicit no-redirect handler, even with a proxy variable present.

No real resolver, HTTP/TLS server, provider, catalog or downloaded binary was
used. Fake responses establish local policy behavior, not live service
compatibility, certificate behavior, freshness or the authenticity of response
claims. The fixed-helper caller contracts remain necessary: arbitrary direct
calls to low-level urllib wrappers are outside those consented production paths.

## Subprocess boundary — S603

`jobs.py:346` is the POSIX `Popen` boundary. `run_process` requires an absolute
executable, rejects NUL arguments and invalid explicit environment entries,
passes a list with `shell=False`, closes stdin with `DEVNULL`, and retains child
supervision. The reviewed primary callers use configured tool executables and
fixed Python/Java entry points; target paths remain arguments. The earlier
primary inherited-environment defect has its own accepted repair and receipt.

One harmless, source-pinned Python child printed its received arguments and two
authored environment values. Semicolons, command substitutions, backticks,
redirection characters, quotes, spaces and a newline remained exact argument
data; the marker file was absent and an unrelated parent variable was not
inherited. Four invalid-input controls and a pre-cancellation control reached
no `Popen`. The seventh control exercises the pure Windows batch argument
policy without launching Windows code.

No new command-injection defect was established at this boundary. This does
not certify arbitrary configured executables, native Windows process behavior,
or primary memory/total-output caps. Those resource-cap limitations remain
separate open work; bounded tails alone do not prove bounded total output.

## Literal-token labels — S105

All fourteen exact sites were inspected. The source and data flow identify
their values as syntax, rendering or pass identifiers.

| File and current lines | Count | Meaning |
| --- | ---: | --- |
| `enrichment/signals.py:172,173,242,244,573,574,575` | 7 | Parentheses, brackets and dereference/operator tokens used to inspect decompiled source syntax. |
| `gui/qt/chips.py:46,85,93` | 3 | The `plain` visual-style token. |
| `gui/qt/theme.py:51` | 1 | The `plain` visual-style token. |
| `rules/contracts.py:152,220` | 2 | Hex-byte/wildcard grammar and pattern metrics. |
| `unified/ladder/types.py:104` | 1 | `P00`, the manual-anchor pass identifier used to avoid emitting duplicate manual atoms. |

These are false positives for credential assignment at the reviewed boundary.
Relevant signals, chip/theme and rule-contract suites are in the current gate.
No token was renamed to hide it from the scanner, and this is not a general
credential-exposure assessment.

## Exception boundaries — S110

The independent S110 source ledger and original four-case SQLite probe are
retained unchanged. Every source site below was read again with its primary
result/error path. “No defect established” refers to that stated contract; it
does not promise complete resource cleanup or observer delivery.

| Original → current site | Primary behavior and disposition | Practical limit |
| --- | --- | --- |
| `jobs.py:413 → 413` | Progress observer only; ProcessResult, output collection and supervision are independent. No false-success path established. | Observer delivery/logging and prompt return are not guaranteed. |
| `netutil.py:68 → 68` | Late-response close after caller cancellation; the late value is not published as success. | A failed close can leave resources; native cleanup not qualified. |
| `secondary/scheduler.py:99 → 99` | EngineEvent observer only. Typed outcomes are separate; normal `on_outcome` errors propagate. | Progress events can be lost. |
| `secondary/scheduler.py:239 → 239` | Best-effort completed-outcome delivery while an existing BaseException already unwinds. Primary failure still propagates. | A secondary delivery failure may remain unpersisted; no atomic durable-delivery guarantee. |
| `service.py:64 → 69` | Failed-create rollback retains uncertain state and uses the ownership ledger; original failure propagates. | Cooperative observed-seam guarantee; cleanup may leave files/locks. |
| `service.py:69 → 74` | Best-effort store close after failed creation. | A failed close is not a successful cleanup guarantee. |
| `ui_engine_setup.py:137 → 137` | Optional setup/path preference save; no validated-input, result or network-consent admission. | Reopen may not remember the preference. |
| `ui_evidence.py:579 → 579` | Optional filter/hide-agreed/show-index preferences only. | Reopen may not remember presentation settings. |
| `ui_evidence.py:1229 → removed warning` | **Confirmed defect, repaired at `7b4402a0`.** Actual SQLite refusal hid failed/cancelled/timeout attempt retention failure; transient `ok` could also produce false kept wording. | Repair retains bounded transient diagnostics and original status; no automatic retry or atomic storage claim. |
| `unified/extract/ghidra_script.py:320 → 320` | Optional Ghidra version getter leaves explicit `unknown`. | Native version probing not executed. |
| `unified/extract/ghidra_script.py:324 → 324` | Optional Java version getter leaves explicit `unknown`. | Native version probing not executed. |
| `unified/extract/ghidra_script.py:783 → 783` | Project close after program-hash/extraction result or error. The primary decision is not bypassed. | Native cleanup/handle/resource behavior needs native evidence. |
| `unified/extract/ghidra_script.py:853 → 853` | Decompiler dispose after per-function status/code collection; output write failure still propagates. | Native disposal completeness not qualified. |

The twelve remaining source boundaries do not establish another production
defect within this review. Their warnings remain visible in the strict scan.
Any future claim about lossless interruption or native cleanup would require
additional evidence; no such claim is made here.

## Additional current SQL site — S608

`pilot/sources/kb_context.py:212` was absent from the original strict 79 and the
prior 43-site review. It belongs to the separately reviewed row-budget repair.
The source SHA-256 is
`1a092df304919c8bd5c21790a8ff19fb46df85627c00cb14cddbab38a93672dc`.

The SQL expression names come only from ten literal text columns (`id`, `kind`,
`project_id`, `run_id`, `raw_sha256`, `input_digest`, `status`, `created`, `body`,
`body_sha256`) and two literal integer columns (`project_revision`, `stale`).
Only fixed `typeof(column)` and `length(CAST(column AS BLOB))` expressions are
joined. SELECT/FROM/ORDER BY clauses are fixed, while `kind` and LIMIT use `?`
bindings with `('kb-context', MAX_ROWS + 1)`. Row, body, project and CLI text do
not enter SQL syntax.

Four independent actual-SQLite controls capture valid authored CVRF contexts
with ordinary and SQL-looking titles without changing schema or row bytes.
A SQL-looking metadata ID stays a literal value and changes the captured
identity; a different kind containing SQL text does not widen the fixed kind
selection. The independent author's fixed-column source trace and source bytes
are also retained. No SQL-injection defect was established. This is not a
hostile-schema, total-store-I/O or publication-race qualification.

## Confirmed repairs and their unchanged controls

| Finding | Preserved original evidence | Accepted repair and present result |
| --- | --- | --- |
| Manifest DTD encoding bypass | Original external 4 failures / 3 positives. BOM-less UTF-16BE plus leading whitespace bypassed the early screen and expanded an internal entity. | `e1c5006e`: parser-level DTD refusal, including pure-Python fallback; unchanged 7-case probe and normal-encoding/PE-resource controls pass. XMLParser at 156 and fromstring at 161 are both still raw S314 findings. No external-file/network XXE or large-expansion claim. |
| Pilot staging cleanup ownership | Original real-directory collision 1 failure / 1 positive; independently replayed by root. | `43ac4829`: exclusive mkdir before the owned-cleanup try. Author 219 / root 140 checks accepted; unchanged external probe passes here. S108 remains at current 147. No nonce-prediction or arbitrary namespace-race guarantee. |
| UI attempt retention / kept wording | Independent actual SQLite/Qt 3 failures / 1 positive; separate kept-wording 1 failure / 1 positive. | `7b4402a0`: class-only/refusal diagnostics survive row, Copy details and final summary; kept wording needs publication success. Author/root 156 gates accepted; both unchanged probes pass here. |

The S108 literal is project-relative under `safe_path`, rather than a shared
absolute `/tmp` path. Its adjacent confirmed ownership defect was repaired on
its own evidence; it was not dismissed merely because the detector's lexical
label was imprecise.

The larger historical repair-gate counts refer to their separate accepted QA
packets. They are not additional cases in the current 768-check receipt.

## Current control receipt

| Receipt | Source | Actual result |
| --- | --- | --- |
| Initial external boundary controls | `36e14051` | 72 passed in 0.83 s: five URL transports, harmless Python argv/environment, actual metadata SQL and unchanged manifest probe. |
| Independent provider slice | `36e14051` | 21 passed in 1.31 s: nineteen fake-opener controls plus two actual Qt consent/preview controls. |
| Final combined bounded gate | **`3faf436a`** | **768 passed, 12 explicitly deselected live-socket cases in 8.58 s; no skips/errors.** |

The final gate includes all external controls above, unchanged staging/UI/kept
probes, related transport and inventory-source tests, signals, chips/theme,
rule contracts, manifest DTD boundary tests and the two Qt consent controls.
An external pytest plugin refuses real `socket.connect`, `connect_ex` and DNS
lookups. Twelve existing live-socket test cases are deliberately deselected to
respect this task's offline scope; their exact node selectors are retained in
the command receipt. They are not counted as passes.

Python is `/workspace/scratch/3a6632a6e5ff/venv/bin/python` (3.12.14), Qt is
offscreen, and every run uses absolute `PYTHONPATH` entries for its exact
checkout's `src` and `tests` (plus the external guard directory for the final
gate). The shared venv's older editable install is not the intended source.
The only independently authored subprocess control launches that interpreter
with a fixed, harmless standard-library script; it executes no target/helper.
Existing pure import checks inherit the same source pin.

The complete raw output/JUnit, command/exit/source records, independent probes,
source equivalence map, all detector snapshots and final per-site ledger are
hashed in `security-residual-triage-20261118.manifest.json` and packaged in the
adjacent `security-residual-triage-20261118.evidence.zip`. The ledger is also
provided separately as `security-residual-triage-20261118.ledger.json`.

## Remaining qualification limits

No target downloads/execution, live providers, paid/native experiments, frozen
corpus/outcome edits, remote mutations or scanner-policy edits occurred.
The controls do not qualify native Windows/Linux engines, hosted security jobs,
live network behavior, matching accuracy, native cleanup completeness, primary
memory/total-output caps or arbitrary same-user filesystem races. Authored
passing tests and manual dispositions remain separate from the still-failing
strict security lane and from release acceptance.
