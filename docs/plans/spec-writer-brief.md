# Spec-writer brief (Haiku workers; documents only)

Read first: `docs/plans/worker-brief.md` sections 1-3 (conventions), `docs/plans/program-e-research-brief.md` section 3 (research rules), `docs/specs/REGISTRY.md` section 1 (status and citation rules). Your card is named in your prompt (a row of `docs/audits/spec-gaps-20261014.md` section 5, or a plan section).

Write exactly ONE file (the path is in your prompt), at most 350 lines, in the style of `docs/specs/enrichment-hardening-backlog.md` and `docs/specs/runtime-discovery.md`:
- title `# <Title> (SPEC-NN)`, then a status line (`draft`, date, owner, what existing code it documents);
- scope and non-goals;
- numbered normative requirements (MUST / SHOULD), contracts and tables, error codes `PT-<AREA>-*` where relevant;
- test and acceptance plan (name the existing tests that cover each rule and the gaps; owner-only or Windows-only gates are listed separately and never counted as done);
- open questions with a recommended default each.

Rules: every statement about existing behaviour comes from code or tests you read (cite `file:line`); where the code does not decide, write the recommended default and mark it `[proposal]`; external facts need a primary-source URL (vendor, standard, upstream docs) and a retrieval date, else `[unverified]`; never invent behaviour, hosts, versions or numbers. Do not edit any existing file (the integrator adds the `docs/specs/REGISTRY.md` row; list it and any other edit under "Integrator asks"). No code, no tests. Product invariants apply (offline by default, no silent upload, unknown is not negative, uncalibrated numbers never shown as confidence, advisory/string/code text is untrusted).

Report in at most 200 words: file, line count, three key decisions or gaps found, `[unverified]` items, Integrator asks.
