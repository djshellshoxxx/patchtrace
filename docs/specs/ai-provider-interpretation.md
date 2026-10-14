# AI provider and interpretation contract (SPEC-41)

<<<<<<< HEAD
Status: draft, 2026-10-14, documents existing behaviour of `src/patchtrace/providers.py`, `interpretation.py`, `evidence.py` and states proposals separately. Basis: worktree HEAD `fd6cdba`; GitHub was not queried; registry snapshot `main` 1560531 (`docs/specs/REGISTRY.md:5`). Citations are `path:line` at that basis. **[proposal]** marks a recommended default that the code does not decide and that the owner must approve. **[unverified]** marks a fact not confirmed (section 10). Probes P1 to P5 (section 9) were run offline on 2026-10-14 with a scratch script that is not committed.
=======
Status: draft, 2026-10-14, documents existing behaviour of `src/patchtrace/providers.py`, `interpretation.py`, `evidence.py` and states proposals separately. Basis: worktree HEAD `fd6cdba`; GitHub was not queried; registry snapshot `main` 1560531 (`docs/specs/REGISTRY.md:5`). Citations are `path:line` at that basis. **[proposal]** marks a recommended default that the code does not decide and that the owner must approve. **[unverified]** marks a fact not confirmed (section 10). Probes P1 to P5 (section 9) were run offline on 2026-10-14 with a scratch script that is not committed. **Amended by slice AI-FIX (2026-10-14):** R11, R14, R18 (as printable ASCII, stricter than the Latin-1 it proposed, per audit RA-7), R29 and R33 are implemented (new error texts and the claim rule are listed in `docs/modules.md` under `[AI-FIX:ai-provider-fixes]`), gaps G1 to G10, G12 and G17 now have tests, and probes P1 (mapped loopback) and P3 (BadStatusLine) no longer reproduce; sections 2 to 8 below still describe the earlier basis. Still open: R12, R15, R25, R26, R35 to R37, gaps G11, G13 to G16 and G18 to G20, and live acceptance.
>>>>>>> origin/claude/clever-clarke-s4nhi6

Process: a red test before each [proposal] change; spec first for any contract change (`AGENTS.md:5`); regenerate schemas when a persisted field is added (`AGENTS.md:7`). Mocked provider tests are not live compatibility evidence (`AGENTS.md:7`).

## 1. Scope

- In scope: the two transports (loopback Ollama, HTTPS OpenAI-compatible), endpoint validation, redirects, size and time limits, session-only credentials, context construction and evidence IDs, prompt and response versions, citation validation, quarantine of model output, and the rules for AI-written text in exports.
- Out of scope: NVD and MSRC enrichment transport (SPEC-07, SPEC-07h; `enrichment/intelligence.py`, `enrichment/cve.py`), KB and CSAF transports, the Ghidriff backend.
- Owners: `providers.py` is transport only and owns no project state (`docs/modules.md:18`, `:56`). `interpretation.py` owns the prompt, strict response models, validation and run assembly (`docs/modules.md:17`). `evidence.py` owns context and evidence IDs.
- Callers: the only call sites are the UI send path (`ui.py:2936`) and its imports (`ui.py:51-52`, `:55`). There is no CLI path: `cli.py` has no interpretation verb, and its only key option is the NVD key (`cli.py:172-173`, `:416`).
- Other readers: load validation (`persistence.py:99-108`), commit (`service.py:246-258`), export (`reports.py:125` snapshot; `:269-271` entry point). `sample.py:118-123` writes a curated record, not model output.
- Runtime: CPython 3.12 (`docs/plans/program-e-research-brief.md:9`).

## 2. Normative requirements

Requirements without a [proposal] tag describe what the code does today and what this spec keeps.

### 2.1 Transport

- **R1** A send MUST be one user-confirmed request, and a sent request MUST NOT be retried (`providers.py:97-103`; `docs/specs/architecture.md:43`). No test counts requests (G17).
- **R2** Ollama MUST POST to `<endpoint>/api/chat` (suffix added if missing) with `stream: false` and `format: "json"`, and MUST read `message.content` (`providers.py:76-80`, `:127-128`).
- **R3** OpenAI-compatible MUST POST to `<endpoint>/chat/completions` with `stream: false` and `response_format: {"type": "json_object"}`, MUST read `choices[0].message.content` (`providers.py:81-85`, `:129-130`), and MUST send `Authorization: Bearer` only when a key is set on this kind (`providers.py:87-88`).
- **R4** A request MUST carry no tools, functions or other model-directed capabilities (`providers.py:80`, `:84-85`; `tests/test_interpretation.py:280`).
- **R5** Environment proxies MUST be disabled for provider calls, so localhost traffic cannot be forwarded (`providers.py:90-91`, `ProxyHandler({})`).
- **R6** Redirects MUST be refused with `PT-PROVIDER` (`providers.py:65-67`, `:91`). No provider test covers this (G2); the acquisition transport has the analogue (`tests/test_acquisition_transport.py:250-261`).
- **R7** Each blocking step (connect, each read) MUST be cancellable within the 0.1 s poll; abandoned threads are capped at 4 (`providers.py:97-103`, `:113-118`; `netutil.py:7`, `:25`, `:38-40`, `:64-71`; `tests/test_cancel_latency.py:108-125` asserts under 0.5 s).

### 2.2 Endpoint validation

- **R8** An endpoint MUST have a parseable port, no userinfo, query or fragment, and no whitespace or control characters (`providers.py:45-52`).
- **R9** `openai` MUST use `https` and any non-empty host (`providers.py:53-55`). A loopback HTTPS endpoint is accepted (P1).
- **R10** `ollama` MUST use `http` or `https` with a loopback host: a loopback IP literal, or the literal name `localhost` in any letter case (`providers.py:56-62`). Names are not resolved, so a DNS override of `localhost` is not detected. Keep as is.
- **R11** [proposal] IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`) SHOULD be rejected explicitly. Today the result depends on the interpreter: `ipaddress.ip_address('::ffff:127.0.0.1').is_loopback` is False on CPython 3.12 and True on 3.13 (P1), so `http://[::ffff:127.0.0.1]:11434` is rejected on 3.12 and accepted on 3.13 (`providers.py:58-62`).
- **R12** [proposal] An unknown `kind` MUST get its own message. Today the kind test shares one condition with the credential rule, so `kind='vllm'` reports "endpoint must have no credentials, query, or fragment" (`providers.py:49-52`; P1).

### 2.3 Size and time limits

- **R13** A response body MUST be capped at 2 MiB and read in chunks of at most 64 KiB (`providers.py:16`, `:112`, `:122-123`). The decoded content is capped by the same constant (`interpretation.py:126-127`).
- **R14** A call MUST end within 120 s of its start (`providers.py:17`, `:93`). Today the deadline is checked only between reads (`providers.py:107-110`), and each blocking operation has a 120 s socket timeout (`providers.py:98`, `:114`), so a blocked read can run past the deadline. [proposal] Give every blocking step the remaining time (Q5).
- **R15** [proposal] A request body MUST be capped. Today nothing caps it in `providers.py` (`providers.py:89`); the size is bounded only by the context budget (`evidence.py:36`; the UI clamps the budget to 512 to 200000 characters at `ui.py:1036`, `:2924`). Default in Q4.

### 2.4 Credentials

- **R16** The key MUST be typed per send into a masked field with the placeholder "Session only; never saved" (`ui.py:1305-1307`) and MUST NOT be written to settings, projects, exports or logs. The send path saves kind, endpoint and model only (`ui.py:2932-2935`). `InterpretationRun` has no key field (`models.py:147-158`). Analysis-run settings are filtered on export by `_safe_settings` (`reports.py:55-71`, called at `:192`; `tests/test_interpretation.py:322-336`).
- **R17** `ProviderConfig.api_key` MUST be hidden from `repr` (`providers.py:33`; `tests/test_interpretation.py:202-205`).
- **R18** A key MUST be at most 4096 characters with no control characters (`providers.py:39-40`). [proposal] It SHOULD also be header-safe (Latin-1). P2: `k€y` passes the constructor, and the call then fails as `PT-PROVIDER: malformed provider envelope` before any socket opens (`providers.py:136-141`). The non-Latin-1 header is the likely cause; this was inferred, not traced.

### 2.5 Context and evidence

- **R19** Context MUST be deterministic, fit its character budget, record every omission and carry an exact digest (`evidence.py:36-42`, `:88-89`, `:96-140`, `:143-144`; `tests/test_interpretation.py:65-76`).
- **R20** The user message MUST equal the previewed payload (`providers.py:75`; digest check `interpretation.py:75-77`; `tests/test_interpretation.py:166`, `:279`).
- **R21** A citation MUST resolve to evidence whose artifact, side, run, function, text and ID match the stored context (`interpretation.py:103-108`; `evidence.py:175-187`; `tests/test_interpretation.py:173-188`, `:313-319`).

### 2.6 Prompt, response and versions

- **R22** The system prompt MUST say that code and strings are untrusted evidence (`interpretation.py:59`), that output is a hypothesis (`:61`), and that CVE, severity, exploitability and affected versions are not to be inferred (`:66-67`). It embeds the response JSON schema (`interpretation.py:55-69`).
- **R23** Responses MUST be strict: duplicate keys and NaN or Infinity rejected (`interpretation.py:78-80`, `:115-121`, `:129-130`); unknown fields rejected by `extra='forbid'` and `strict=True` (`interpretation.py:26-27`; `tests/test_interpretation.py:144-151`); confidence limited to low, medium and high (`interpretation.py:37`).
- **R24** Model output MUST NOT set review status, analyst conclusion or the stale flag. Findings are built without those fields (`interpretation.py:151-155`; `models.py:142-144`).
- **R25** Each run MUST record `prompt_version`. Today `interpret()` leaves the default `patchtrace-1` (`models.py:152`, `interpretation.py:161-162`), so a changed prompt is still recorded as `patchtrace-1`, and no response-schema version exists. [proposal] Add a `PROMPT_VERSION` constant and additive `prompt_sha256` and `response_schema_sha256` fields, a golden-digest test, and regenerated `docs/schemas/InterpretationRun.json` (`:364` holds the current field).

### 2.7 Citation validation

- **R26** A finding MUST have at least one supporting citation in its primary hypothesis (`interpretation.py:142-143`). Alternatives are not checked and may have none (P5). [proposal] Each alternative SHOULD carry support or an `unknowns` entry.
- **R27** Every citation in every hypothesis MUST lie inside the scope of the finding's matches (`interpretation.py:138-148`; `tests/test_interpretation.py:79-106`).
- **R28** A CWE MUST match `^CWE-[0-9]{1,5}$` and carry a rationale when present (`interpretation.py:47`, `:149-150`). No catalogue check exists; P5 accepted `CWE-99999`. Default in Q6.
- **R29** [proposal] A CVE identifier, CVSS number, severity word or exploitability phrase in `summary`, `fix_purpose` or any `explanation` MUST appear verbatim in the context payload, or the finding is quarantined. Today this rests on prompt text (`interpretation.py:66-67`). P5 accepted "CVE-2099-0001", "CVSS 9.8" and "remotely exploitable" with no supporting evidence. Default in Q7.

### 2.8 Quarantine and failure

- **R30** A malformed, oversized or out-of-scope response MUST create no findings. Its raw text MUST stay on the run with status `failed` and MUST be excluded from exports (`interpretation.py:126-133`, `:167`, `:175-177`; `reports.py:170`; `tests/test_interpretation.py:132-141`, `:285-288`, `:291-300`).
- **R31** The UI shows stored raw responses in a plain-text dialog (`ui.py:1839`, `:2558`).
- **R32** Cancellation MUST end as `cancelled` with no findings (`interpretation.py:172-174`). A completion that arrives after cancel is converted to `cancelled` before commit (`ui.py:2939-2942`).
- **R33** [proposal] Any exception from the transport MUST map to a `PT-PROVIDER` code with fixed text, so that no peer-controlled text reaches the UI. Today `request_completion` maps `ProviderError`, `HTTPError`, `URLError`/`OSError` and the envelope exceptions only (`providers.py:134-141`), and `interpret()` catches three classes (`interpretation.py:172-177`). An `http.client.HTTPException` such as `BadStatusLine` escapes both (P3). The UI worker catches `Exception` and shows `str(exc)` (`ui.py:216-217`, `:2965`). Default in Q8.

### 2.9 AI-written report text

- **R34** Each export that contains AI text MUST carry provenance: provider, model, endpoint, `prompt_version`, `context_id`, status, review and stale. The JSON export carries these (`reports.py:170`, `:173-178`). HTML and Markdown append the whole serialized snapshot (`reports.py:245`, `:265`) and show summary, fix purpose, review and stale for each finding (`reports.py:241-244`, `:261-264`). [proposal] Show provider, model and `prompt_version` beside each finding.
- **R35** [proposal] AI text MUST be opt-in per export. Today the default exports every finding (`reports.py:129`, `:133`, `:153-154`; `export_project` defaults at `reports.py:269-270`). Proposed default: `include_ai_findings=False`, with `finding_ids` as explicit selection. Default in Q3.
- **R36** AI text MUST be escaped for HTML and Markdown (`reports.py:241-242`, `:261-262`). HTML escaping is tested (`tests/test_interpretation.py:211-219`); Markdown escaping of AI text is not (G15).
- **R37** [proposal] R29 applies to exported text. Exports MUST NOT add claims absent from the context.
- **R38** Analyst conclusions MUST stay separate from model text (`models.py:143`; `interpretation.py:151-155`; `docs/specs/architecture.md:45`).

## 3. Transports and endpoint validation

| Kind | Appended path | Payload flags | Auth | Content read | Endpoint rule |
|---|---|---|---|---|---|
| `ollama` | `/api/chat` | `stream: false`, `format: "json"` | none sent | `message.content` | `http` or `https`, loopback host (`providers.py:56-62`) |
| `openai` | `/chat/completions` | `stream: false`, `response_format: json_object` | `Bearer` when a key is set | `choices[0].message.content` | `https` only, any host (`providers.py:53-55`) |

Dialog defaults: `http://127.0.0.1:11434` for ollama and `https://api.openai.com/v1` for openai (`ui.py:1303`, `:1323`).

Endpoint probe P1 (CPython 3.13.16 unless noted; constructor only, no socket):

| Input | Verdict | Rule |
|---|---|---|
| ollama `http://[::1]:11434` | accept | R10 |
| ollama `http://LOCALHOST:11434` | accept | R10 |
| ollama `http://127.0.0.2:11434` | accept | R10 (all of 127/8) |
| ollama `http://127.1:11434` | reject, loopback | R10 |
| ollama `http://[::ffff:127.0.0.1]:11434` | accept on 3.13; reject on 3.12 by the same `is_loopback` result (`providers.py:58-62`) | R11 |
| ollama `http://0.0.0.0:11434` | reject, loopback | R10 |
| ollama `https://localhost:11434` | accept | R10 |
| ollama `http://localhost:99999` | reject, invalid URL | R8 |
| ollama `http://localhost:11434?x=1` | reject, credentials, query or fragment | R8 |
| openai `https://127.0.0.1:8443/v1` | accept | R9 |
| openai `http://localhost/v1` | reject, HTTPS required | R9 |
| openai `https://api.example.com/v1/` | accept | R9 |
| openai `https://api.example.com/v1 ` (trailing space) | reject, whitespace (same message as R12) | R8 |
| kind `vllm` | reject, misleading message | R12 |

## 4. Limits

| Limit | Value | Source | Enforced | Test |
|---|---|---|---|---|
| Response body | 2 MiB | `providers.py:16`, `:122-123` | yes | none (G3) |
| Decoded content | 2 MiB | `interpretation.py:126-127` | yes | none |
| Call deadline | 120 s | `providers.py:17`, `:93` | between reads only (R14) | `tests/test_audit_ai_reports.py:14-38` (instant reads) |
| Socket timeout | 120 s per operation | `providers.py:98`, `:114` | yes | none |
| Cancel poll | 0.1 s | `netutil.py:25` | yes | `tests/test_cancel_latency.py:108-125` |
| Abandoned threads | 4 | `netutil.py:7`, `:38-40` | yes | none for providers (G9) |
| Model name | 1 to 200 characters | `providers.py:37-38` | yes | none (G9) |
| API key | at most 4096; no control characters | `providers.py:39-40` | yes | none (G9) |
| Context budget | default 24000 characters; minimum 512 | `evidence.py:36-38`; `ui.py:1036` | yes | `tests/test_interpretation.py:65-70` |
| Token estimate | ceil(UTF-8 bytes / 3) | `evidence.py:140` | estimate only | none |
| Response schema | findings 100; alternatives 20; match IDs 200; list items 100; explanation 8000; summary and fix purpose 4000 | `interpretation.py:31-52` | pydantic | none |

The context budget counts characters; the 2 MiB caps count bytes.

## 5. Prompt, response and version rules

| Item | Source | Recorded on the run | Changes when |
|---|---|---|---|
| System prompt text | `system_prompt()`, `interpretation.py:55-69` | no digest | any edit to the text |
| Response schema | `Response.model_json_schema()`, `interpretation.py:56` | no digest | any edit to the response models |
| `prompt_version` | `models.py:152`, default `patchtrace-1` | constant value | never automatically |
| Context schema | `schema_version: 1`, `evidence.py:79`, `interpretation.py:81-82` | in payload | schema change |
| Context digest and ID | `evidence.py:137-140`, `:143-144`; `ctx-<digest>` | `AnalysisContext.digest`, `id` | payload or omissions change |
| Evidence ID | `ev-<sha256>` over the reference and artifact hash, `evidence.py:19-21` | `EvidenceReference.id` | text, range, side or artifact hash changes |

## 6. Run outcomes

| Status | Set by | Findings | Raw response |
|---|---|---|---|
| `completed` | `interpretation.py:171` | validated | kept |
| `failed` | `interpretation.py:175-177` for `InterpretationError` and `ProviderError` | none | kept when a response arrived (`:167`) |
| `cancelled` | `interpretation.py:172-174` | none | kept when a response arrived |
| any other exception | not handled (`interpretation.py:172-177`) | escapes to the caller | escapes (P3) |

## 7. Error codes

| Code | Source | Tested |
|---|---|---|
| `PT-PROVIDER: supply a model name of at most 200 characters` | `providers.py:38` | no |
| `PT-PROVIDER: invalid credential` | `providers.py:40` | no |
| `PT-PROVIDER: invalid endpoint URL` | `providers.py:48` | no (P1 rejects a bad port) |
| `PT-PROVIDER: endpoint must have no credentials, query, or fragment` | `providers.py:52` | partly (`tests/test_interpretation.py:194-196`); also reported for unknown kinds (R12) |
| `PT-PROVIDER: remote endpoints require HTTPS` | `providers.py:55` | yes (`tests/test_interpretation.py:193`) |
| `PT-PROVIDER: Ollama endpoint must use a loopback host` | `providers.py:62` | yes (`tests/test_interpretation.py:191-192`) |
| `PT-PROVIDER: endpoint redirects are refused; configure the final endpoint` | `providers.py:67` | no (G2) |
| `PT-CANCEL: interpretation cancelled` | `providers.py:74,101,108,116,125`; `interpretation.py:166,169` | yes (`tests/test_cancel_latency.py:108-125`; `tests/test_interpretation.py:202-208`) |
| `PT-PROVIDER: previous requests are still closing; retry shortly` | `providers.py:103,118` | no (G9) |
| `PT-PROVIDER: connection failed or timed out; check endpoint and server` | `providers.py:110,139` | deadline path only (`tests/test_audit_ai_reports.py:32-38`) |
| `PT-PROVIDER: response exceeds 2 MiB limit` | `providers.py:123` | no (G3) |
| `PT-PROVIDER: server returned HTTP {code}` | `providers.py:137` | no (G4) |
| `PT-PROVIDER: malformed provider envelope` | `providers.py:141` | no (G4); also reported for header-encoding failures (P2) |
| `PT-PROVIDER: context is stale; rebuild it before interpretation` | `interpretation.py:74` | yes (`tests/test_interpretation.py:303-310`) |
| `PT-PROVIDER: context digest does not match preview` | `interpretation.py:77` | no |
| `PT-PROVIDER: malformed response; raw text quarantined, no findings created` | `interpretation.py:133` | yes (`tests/test_interpretation.py:132-141`, `:285-288`) |
| `PT-PROVIDER: oversized response quarantined, no findings created` | `interpretation.py:127` | no (G3) |
| `PT-PROVIDER: response cites an unknown or duplicate match ID` | `interpretation.py:139` | no |
| `PT-PROVIDER: finding requires supporting context evidence` | `interpretation.py:143` | no |
| `PT-PROVIDER: response cites unknown or out-of-scope evidence` | `interpretation.py:148` | yes (`tests/test_interpretation.py:79-106`) |
| `PT-PROVIDER: CWE classification requires a rationale` | `interpretation.py:150` | no (G10) |
| `PT-SCHEMA: evidence ownership or code range is invalid`; `evidence is stale`; `unknown evidence ID` | `evidence.py:183`, `:186`, `:187` | yes (`tests/test_interpretation.py:173-188`) |
| `PT-SCHEMA: evidence context is invalid` | `evidence.py:164` | yes (`tests/test_interpretation.py:313-319`) |
| `PT-SCHEMA: interpretation context belongs to a different project/revision`; `outdated interpretation context must be marked stale` | `persistence.py:106`, `:108` | no |
| `PT-SCHEMA: interpretation already belongs to project`; `belongs to another project` | `service.py:249`, `:252` | no |
| `PT-EXPORT: requested finding ID is not in the saved project` | `reports.py:131` | yes (`tests/test_interpretation.py:238-239`) |

Codes are area-level, so `PT-PROVIDER` also covers context, evidence and response failures (Q9).

## 8. Tests and acceptance

### 8.1 Existing evidence (local run, 2026-10-14)

- `tests/test_interpretation.py`: 29 passed, unfiltered, CPython 3.13.16, `QT_QPA_PLATFORM=offscreen`.
- Provider cancel (`tests/test_cancel_latency.py::test_provider_completion_cancel_latency`), deadline (`tests/test_audit_ai_reports.py::test_total_deadline_bounds_slow_drip`), and two UI tests (`tests/test_ui.py::test_context_dialog_exact_preview_and_secret_is_session_only`, `::test_interpretation_preview_cancel_sends_nothing`): 4 passed.
- `tests/test_core.py -k "interpret or forged or stale or sample"`: 4 passed, 18 deselected.
- Not run: Linux and Windows CI, live providers, `ruff`.

### 8.2 Gaps

- **G1** No Ollama wire-format or envelope test (`providers.py:77-80`, `:127-128`; no `api/chat` in any test).
- **G2** No provider redirect test (`providers.py:65-67`, `:91`).
- **G3** No 2 MiB response-cap test (`providers.py:122-123`).
- **G4** No test for HTTP, envelope or header-encoding mapping (`providers.py:134-141`; P2).
- **G5** The deadline test uses instantaneous reads (`tests/test_audit_ai_reports.py:14-38`); no blocked-read case (R14).
- **G6** No test for an unclassified transport exception (P3); the UI shows raw text (`ui.py:216-217`).
- **G7** Endpoint tests reject six inputs only (`tests/test_interpretation.py:191-199`); no accept matrix, IPv6, port or unknown-kind case (section 3).
- **G8** Loopback validation differs by interpreter (R11; P1 on 3.12 and 3.13).
- **G9** No provider test for abandoned-thread mapping (`providers.py:102-103`, `:117-118`) or for model and key limits (`providers.py:37-40`).
- **G10** CWE pattern and rationale rule untested (`interpretation.py:47`, `:149-150`); P5 accepted `CWE-99999`.
- **G11** Alternatives without support are untested; P5 accepted an empty list.
- **G12** No CVE, CVSS, severity or exploitability check; the only control is prompt text (`interpretation.py:66-67`; P5).
- **G13** `prompt_version` is a constant default and no response version exists (`models.py:152`, `interpretation.py:161-162`).
- **G14** The default export includes every AI finding (`reports.py:129`), and tests pin that default (`tests/test_interpretation.py:211-226`, `:291-300`); no opt-in exists to test (R35).
- **G15** Markdown escaping of AI text is untested (`reports.py:261-262`; no test references `_markdown_escape`).
- **G16** The key save path is not exercised: `tests/test_ui.py:105-113` checks the dialog field and never accepts the dialog through `preview_interpretation` (`ui.py:2932-2935`).
- **G17** No test that a send is single-shot; `tests/test_interpretation.py:276` reads `captured[0]` only.
- **G18** No removal path for runs: `service.py` and `persistence.py` only add and validate (`service.py:246-258`, `persistence.py:99-108`). Each run can hold up to 2 MiB of raw text (`providers.py:16`, `models.py:156`).
- **G19** `tests/test_interpretation.py:169` asserts `'tools' in system_prompt()`, which passes on the word anywhere in the prompt.
- **G20** No CLI path, so acceptance is GUI-only (`cli.py`).

### 8.3 Proposed tests [proposal]

Hermetic: fake opener or loopback server, no network. Tier L (low-cost) or M (mid-tier).

- `test_ollama_request_and_envelope_shape` (L): path, `stream`, `format`, `message.content`.
- `test_provider_refuses_redirect` (L): loopback 302 yields the redirect message.
- `test_provider_response_cap_is_two_mib` (L): a body of 2 MiB plus one byte fails with the cap message.
- `test_blocked_read_respects_call_deadline` (M): fake clock and blocked read; returns within the deadline plus one poll.
- `test_transport_exception_maps_to_fixed_code` (M): `BadStatusLine` becomes `PT-PROVIDER` with fixed text.
- `test_endpoint_accept_and_reject_matrix` (L): parametrized with `ids=` from section 3; `test_ipv4_mapped_loopback_rejected_on_every_python` (L).
- `test_key_must_be_header_safe` (L).
- `test_claims_absent_from_context_quarantine_finding` (M).
- `test_cwe_format_and_rationale`, `test_alternatives_need_support` (L).
- `test_prompt_version_golden_digest` (L).
- `test_default_export_excludes_ai_findings` (M; behaviour change).
- `test_markdown_escapes_finding_text` (L).
- `test_send_path_never_persists_key` (L): drives `preview_interpretation` with an accepted dialog.
- `test_single_post_per_send` (L).

### 8.4 Acceptance

- Live local Ollama and remote OpenAI-compatible acceptance is open (`tasks/todo.md:9`). Nothing in this spec closes it. Report it separately from automated evidence (`CLAUDE.md`).
- P1 to P5 are offline and local. They are not CI evidence, not live evidence and not Windows evidence.

## 9. Probe record (2026-10-14)

- **P1** Endpoint matrix (section 3). Run on CPython 3.13.16. The IPv4-mapped `ipaddress` check also ran on 3.12 and returned False. The 3.12 interpreter has no `pydantic`, so the full probe did not run there.
- **P2** `ProviderConfig('openai', 'https://api.example.com/v1', 'm', 'k€y')` was accepted. `request_completion` then raised `ProviderError: malformed provider envelope`, with `HTTPSConnection.connect` stubbed so that no socket could open.
- **P3** A loopback server that answered `NOT-HTTP garbage` made both `request_completion` and `interpret()` raise `http.client.BadStatusLine` (an `HTTPException`), unclassified (CPython 3.13.16).
- **P5** On a copy of the `tests/test_interpretation.py:28-41` fixture, `validate_response` accepted a finding whose summary named a CVE identifier, a CVSS value, severity and exploitability wording, with a `CWE-99999` rationale "invented", and an alternative with an empty `supporting` list.

## 10. External facts

- **E1** Ollama API, https://github.com/ollama/ollama/blob/main/docs/api.md, retrieved 2026-10-14 through WebFetch (a model-generated extract, not the raw page). Confirms `POST /api/chat` with `model`, `messages`, `stream` (`false` returns a single object) and `format` (`json` or a JSON schema). The non-streaming example shows `message.content`. No default for `stream` is stated; the code sets it explicitly (`providers.py:80`).
- **E2** OpenAI OpenAPI description, https://raw.githubusercontent.com/openai/openai-openapi/master/openapi.yaml, retrieved 2026-10-14. Confirms the `/chat/completions` path with `POST` and `createChatCompletion`. **[unverified]**: the `response_format` `json_object` value, the default of `stream`, and the `choices[].message.content` schema. The fetch covered 100000 of 4070488 characters, and `platform.openai.com` did not resolve from the sandbox on 2026-10-14.
- **E3** Python stdlib behaviour (`ipaddress` loopback handling; `http.client` exception hierarchy). **[unverified]** as documentation citations: docs.python.org did not resolve on 2026-10-14. The behaviour rests on the probes in section 9.
- **E4** OWASP LLM Top 10 labels (prompt injection; improper output handling). **[unverified]**: genai.owasp.org did not resolve on 2026-10-14. Used as labels only; no requirement depends on them.
- No package, licence or new dependency is involved: the transport uses `urllib`, `ipaddress`, `json` and `threading`; `pydantic` is already used (`interpretation.py:9`).

## 11. Open questions (default in bold)

- **Q1** Should `openai` accept loopback HTTPS? **Keep** (`providers.py:53-55`); the preview shows the endpoint before any send.
- **Q2** Should IPv4-mapped loopback be rejected? **Yes**, so the rule no longer depends on the stdlib (R11).
- **Q3** Should exports include AI findings by default? **No**; a user selects findings or sets `include_ai_findings` (R35). Behaviour change; owner decision.
- **Q4** Request-body cap? **4 MiB** (R15). It covers the UI maximum of 200000 characters at worst-case escaping: `providers.py:89` uses `json.dumps` with its default `ensure_ascii=True`, so a supplementary-plane character can take 12 bytes, about 2.4 MB in total.
- **Q5** Enforce the deadline during blocking reads? **Yes**: give each blocking step the remaining time and check the deadline in `interruptible` (R14). Tests use fake clocks.
- **Q6** CWE catalogue? **Keep format-only validation** and label exports "CWE format checked, not catalogued" [proposal]. A bundled catalogue needs a licence check [unverified].
- **Q7** Claim check (R29)? **Quarantine the finding, not the run**, and count it in the run's status note.
- **Q8** Transport exceptions (R33)? **Map to `PT-PROVIDER: transport failed unexpectedly (<exception class name>)`**, with no message text.
- **Q9** Area-level error codes? **Keep existing strings** for stability; new codes use `PT-INTERP-*` and `PT-PROVIDER-*`.
- **Q10** Run retention? **Manual delete action** (new) and a warning above 64 MiB of retained raw text; no automatic deletion.

## 12. Integrator asks

1. `docs/specs/REGISTRY.md`: add a Table A row for `docs/specs/ai-provider-interpretation.md` (SPEC-41, draft; owners `providers.py`, `interpretation.py`, `evidence.py`). Move "next free" from SPEC-41 to SPEC-42 at `:14` and `:84`. `tests/test_spec_registry.py` requires the backticked path (`REGISTRY.md:17`) and fails until this row lands.
2. `docs/audits/spec-gaps-20261014.md:121` (section 5, row 6) and `:79`: point to SPEC-41.
3. `docs/specs/architecture.md:43` and `:45`: add a SPEC-41 cross-reference. The sentence "Timeout 120 seconds, response cap 2 MiB" describes R13 and R14 only.
4. `docs/modules.md:17-18`: add SPEC-41 to the interpretation and providers rows (append-only).
5. `tasks/todo.md:9`: keep open; this spec changes no status.
6. When R11, R25 or R33 are approved: regenerate schemas (`AGENTS.md:7`) and write the listed tests first.
7. `ui.py` (R31, R33, R35 defaults) and `reports.py` (R34 to R36) are frozen for builders (worker brief section 3); changes need stubs or separate slices.
