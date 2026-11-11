# Which model should do which task (ChatGPT Pro lineup, researched 2026-10-15)

Audience: the project owner, and any LLM orchestrating work on PatchTrace. Purpose: pick the cheapest model that can do each
task reliably, and escalate only on evidence. The task lists in `01` to `08` each carry a "Recommended model tier" line using
the TIER names below; this file maps tiers to concrete ChatGPT models and says why.

## 0. Read this first: how reliable this information is

The model lineup changes every few weeks. The facts below come from web searches on 2026-10-15. OpenAI's own pages
(help.openai.com, developers.openai.com, chatgpt.com) were NOT reachable from the sandbox that wrote this file, so every number
here comes from search-result summaries of OpenAI pages and from third-party blogs, and the sources disagree in places.
Confidence labels: **CONFIRMED** = two or more independent results agree; **SINGLE-SOURCE** = one result only;
**CONFLICT** = sources disagree. Before relying on any figure, open the model menu in the ChatGPT or Codex app (the Codex
`/model` command, and `/status` for limits) and check what your plan actually offers.

## 1. The lineup as found (names exactly as the sources wrote them)

| Model | What it is | Best for | Confidence |
|---|---|---|---|
| **GPT-6 Astra** | OpenAI's flagship, "for the most demanding and important projects" | hardest multi-constraint reasoning, computer use, long agentic tasks | CONFIRMED (several results) |
| **GPT-6 Pro** (Astra-powered; also called "Astra Pro") | extended-thinking variant offered on Pro, Business, Enterprise | the highest-effort answers where one wrong step is costly | CONFIRMED that it exists; no separate benchmark numbers were found |
| **GPT-6 Sol** | mid tier; "judgement" work: coding, document analysis | day-to-day implementation, review, refactors | CONFIRMED (one source says it is not yet in regular chat; check the picker) |
| **GPT-6 Luna** | cheap and fast tier | summarising, extracting, quick questions, bulk transforms | CONFIRMED |
| **GPT-5.6 Sol / Terra / Luna** | the previous family, still in Codex on Plus and above (Free and Go get Terra) | Terra = balanced mid cost; Sol = strongest of that family; Luna = cheapest | SINGLE-SOURCE for the Codex plan mapping (OpenAI help text quoted by a search summary) |
| **GPT-5.6 Sol Pro** | Pro-variant of the previous family, "remains available" | same job as GPT-6 Pro when Astra is not offered | SINGLE-SOURCE |
| **GPT-5.5** | retired from ChatGPT, Work and Codex on 2026-10-14 per one article | do not plan around it | SINGLE-SOURCE |
| **GPT-5 Pro / GPT-5.1 Pro / GPT-5.3-Codex / GPT-5.4** | older generations; "previous generation" on OpenAI's developer model list | only if nothing newer is available | CONFIRMED as older |

Pro plan tiers found: Pro $100 (about 5x the Plus usage), Pro $200 (about 20x Plus), and a Pro 500 tier ($500 per month,
announced 2026-09-29, the only one with the faster "Astra Ultrafast" service tier; one source says 8x the standard rate).
Picker options mentioned in the June 2026 release notes: Instant, Medium, High, Extra High, and Pro-only "Pro Standard" and
"Pro Extended". What "Extended" changes (longer thinking) is the usual meaning but is UNVERIFIED for this lineup.
OpenAI does not publish fixed message counts; limits are weekly and anecdotal (community forum threads report Codex limits
being reached quickly on Pro). Treat usage as a budget to spend deliberately, not as unlimited.

## 2. Numbers worth knowing (all third-party, treat as indicative)

- Coding benchmark DeepSWE: Astra about 74.1 percent; GPT-5.6 Sol about 72.7; GPT-6 Sol about 68.8; GPT-6 Luna about 66.6
  (one source: Luna is only about 2 points behind Sol at max effort). CONFLICT on exact values across blogs.
- Terminal-Bench: Astra about 56 percent versus about 37 percent for Sol (Artificial Analysis). Agentic coding index in Codex:
  Astra about 62 to 67 depending on the source (CONFLICT). Computer use (OSWorld 2.0): Astra about 72.6 percent.
- Reasoning index (one aggregator): Astra max 52.7, Sol max 47.6, Luna max 38.1. SINGLE-SOURCE.
- Speed (tokens per second at max effort): Astra about 58, Sol about 104, Luna about 157. SINGLE-SOURCE.
- API price per million tokens (input/output): Astra about $10/$50, Sol about $2/$10, Luna about $0.10/$0.50. GPT-5.6 Sol is
  quoted at $4/$20 by one source and $5.62/$28.08 by another (CONFLICT). The Pro plan itself is a flat fee; these prices matter
  only for API use.
- Reasoning effort: one analysis says every effort level from low to max sits on the efficient frontier, and Astra at max
  effort uses about a third of the output tokens of a rival flagship for a similar score.
- One source says OpenAI rates Astra as "Critical" for cybersecurity, so extra safety checks can pause legitimate
  security-adjacent tasks. This project is reverse-engineering tooling; expect occasional refusals or pauses on tasks that
  look like exploit work and phrase tasks defensively (analysis of patches, not weaponising).

## 3. Tier definitions used in this project's task lists

| Tier | Meaning | ChatGPT model to choose | Claude equivalent used inside this repo |
|---|---|---|---|
| **T0 cheap** | mechanical, well-specified, easily checked: doc formatting, link and registry rows, fixtures, lint, reading CI logs by rule, renaming, bulk edits with a test | GPT-6 Luna (or GPT-5.6 Luna), Medium effort | Haiku-class |
| **T1 standard** | normal implementation with a red test first: CLI verbs, adapters, panel features, workflow edits, test fixes, doc pages that need code reading | GPT-6 Sol (or GPT-5.6 Terra when Sol is unavailable or you are saving usage), High effort | Sonnet-class |
| **T2 hard** | multi-file design inside a strict contract, tricky concurrency or platform bugs, statistics code, anything where a plausible-looking wrong answer is easy | GPT-6 Sol at Extra High, or GPT-6 Astra | Opus-class, only after a Sonnet-class failure |
| **T3 critical** | security invariants, irreversible or outward actions' design, pre-registration decisions, final review of a locked methodology | GPT-6 Pro (Astra) with Extended, or Astra at max effort | top tier; never for routine work |

Escalation rule (matches `CLAUDE.md`): start at the lowest tier that the task description allows; move up one tier only after
a concrete failure (a test that still fails after one honest attempt, a design with an unresolved contradiction), and never
retry the same tier repeatedly with the same prompt. De-escalate for the verification step: have a T0 or T1 model run the
commands and compare outputs, and keep T2/T3 for the reasoning.

Why Sol, not Astra, is the default: Astra is slower (about half Sol's speed), costs about five times as much through the API,
and on routine coding benchmarks is only a couple of points ahead; its clear wins are the hardest multi-constraint problems,
terminal and computer-use agents, and long agentic runs. Luna is only about two benchmark points behind Sol on coding but
reasons noticeably worse, so keep it away from anything that needs design judgement.

## 4. Assignment table by feature area (matches files 01 to 08)

Size is the effort class used in each file (S, M, L, XL). "Reviewer" is a second, independent model pass for risky items.

| Area (file) | Item class | Tier | Suggested ChatGPT model | Reviewer |
|---|---|---|---|---|
| Unified engine (01) | reading a red gate and deciding next step; dispatching live runs; annotating reports | T1 | GPT-6 Sol, High | none |
| Unified engine (01) | fusion / ladder correctness (same-class atoms in support tuple xfail), noise model, new gate evaluators | T2 | Sol Extra High, escalate to Astra if two attempts fail | Astra (T3) on anything touching G-U3/G-U8 attestation logic |
| Unified engine (01) | decompile persistence, code-view alignment, flag UI | T1 | Sol, High | T0 runs the tests |
| Unified engine (01) | BinDiff pin provisioning | T0 for the runbook, owner for the download | Luna drafts commands | owner |
| Label training (02) | nested threshold selection (D-01), grouped CV, calibration, bootstrap undefined-share logic, shift ladder | T2, final check T3 | Astra for design; Sol to implement | GPT-6 Pro Extended to review the statistics before the pre-registration lock |
| Label training (02) | deferred items D-02..D-12 (small guards, thresholds, wording) | T1 | Sol, High | none |
| Label training (02) | prereg-file check, single-use `run_locked_test` option, report wording | T2 (these protect the locked methodology) | Sol Extra High | Pro Extended |
| Label training (02) | adding mutation operators, channel packs, fixtures | T1 | Sol, High | none |
| Label training (02) | pre-registration lock and the real Tier R run | T3 for the decision text, then T0 to execute | Pro Extended to read the whole lock once; Luna to run commands | owner sign-off is required (never delegate) |
| Tier W and corpus (03) | recipe additions, catalogue edits, pins, licence rows | T1 | Sol, High (licence rows: Sol plus a check against the register) | none |
| Tier W and corpus (03) | filling ChatGPT corpus candidates (tags, fix commits) | T0 research with verification | Luna with web access, every fact re-checked by a script | Sol spot-checks 10 percent |
| Tier W and corpus (03) | owner-local runs | owner | none | none |
| Qt panels (04) | a panel feature from the recipe (Calls DOT export, call-site, minimap; Rules flows; Strings pairing) | T1 | Sol, High | T0 runs qt-gate locally |
| Qt panels (04) | Related panel manifest wiring, tooltip registry shrinkage | T1 | Terra or Sol | none |
| Qt panels (04) | thread-lifetime, GC, teardown or platform crashes | T2 | Sol Extra High / Astra | none |
| Qt panels (04) | guide panel (not built) | T1 after its spec exists; spec writing T1 | Sol | none |
| Domain features (05) | wiring `--anchors-from` to `patchtrace.search.anchors`, CLI verbs, adapters, envelopes | T1 | Sol, High | none |
| Domain features (05) | FAB audit items, KEV / KB / YARA-X / CAP / DIE follow-ups | T1 (T2 if a contract change is needed) | Sol | Sol second pass if a persisted contract changes (additive only) |
| Domain features (05) | consent / network / offline rules, anything about upload | T3 for the design review | Astra or Pro Extended | owner |
| Bundle, Windows beta, signing (06) | running the bundle build, reading logs | T0 | Luna | none |
| Bundle, Windows beta, signing (06) | pin and digest logic (content_sha256), hostile-archive refusals, release gate parsing | T2 / T3 (supply-chain security) | Sol Extra High to implement, Pro Extended to review | Pro Extended |
| Bundle, Windows beta, signing (06) | signing, release creation | owner (never automate a non-prerelease) | none | owner |
| CI and QA (07) | reading CI logs, grouping failures, fixing stale tests, Windows/non-root fixes | T1 | Sol, High (Luna for log reading only) | none |
| CI and QA (07) | a hang or crash with no obvious cause | T2 | Sol Extra High / Astra | none |
| Core, docs, ops (08) | docs, help pages, registry rows, ledger updates | T0 | Luna, Medium (it must run the docs tests) | none |
| Core, docs, ops (08) | new CLI verb end to end, persisted field additions | T1 | Sol | Sol second pass on the contract |

## 5. How to apply this with the ChatGPT apps

1. **Codex / ChatGPT agent mode for implementation**: Sol (High) by default; keep one chat per slice so context stays small;
   paste the relevant section of the matching file (`01` to `08`) and the exact commands, nothing else.
2. **GPT-6 Pro / Astra Extended**: use for ONE review pass per high-risk change, with the diff and the acceptance criteria. Do
   not run it in loops. It is the most expensive use of the Pro allowance.
3. **Luna for chores**: log reading, formatting, registry rows. Give it the exact rule and the command to verify; it will happily
   produce plausible wrong text otherwise.
4. **Parallelism**: several Sol or Luna chats on disjoint files is fine; never two chats editing the same file or pushing to the
   same branch. Follow `docs/plans/multi-instance-coordination.md` and check open PRs first.
5. **Budget**: pick the plan tier by expected load. The $100 tier suffices for steady Sol use; heavy Astra review passes and
   many parallel agents are what justify $200 or $500. Usage resets are not granted by support, so spread heavy work.
6. **Verify the lineup again** each time you start a new phase of work: the names above may have changed.

## 6. Sources (search summaries, 2026-10-15)

- OpenAI help: GPT-6 and other models in ChatGPT, https://help.openai.com/en/articles/20001354-gpt-6-and-other-models-in-chatgpt
- OpenAI help: ChatGPT release notes, https://help.openai.com/en/articles/6825453-chatgpt-release-notes
- OpenAI developer docs: all models, https://developers.openai.com/api/docs/models/all
- Codex pricing, https://chatgpt.com/codex/pricing/
- Codex pricing 2026 (Morph), https://www.morphllm.com/codex-pricing
- Codex pricing: what each plan gets (Carly), https://www.usecarly.com/blog/codex-pricing/
- GPT-6 Astra vs Sol vs Luna (Origami), https://origami.sa/en/blog/gpt-6-astra-sol-luna-difference/
- GPT-6 Astra, Sol, Luna explained (Lindy), https://www.lindy.ai/blog/gpt-6
- GPT-6 Sol vs Astra vs Luna, October 2026 (AIToolsReview), https://aitoolsreview.co.uk/insights/gpt-6-sol-vs-astra-vs-luna
- GPT-5.6 Sol, Terra and Luna (Codersera), https://codersera.com/blog/gpt-5-6-sol-terra-luna/
- Benchmarking GPT-6 Astra (Artificial Analysis), https://artificialanalysis.ai/articles/benchmarking-gpt-6-astra
- GPT-6 Astra benchmarks explained (Vellum), https://www.vellum.ai/blog/gpt-6-astra-benchmarks-explained
- GPT-6 Astra benchmarks, pricing and speed (BenchLM), https://benchlm.ai/models/gpt-6-astra
- Model comparison GPT-5.0 to 6.1 (Fello AI), https://felloai.com/the-ultimate-chatgpt-model-comparison/
- Community threads on Codex limits for Pro users, https://community.openai.com/t/frustrated-with-new-codex-limits-for-the-pro-users/1380784
