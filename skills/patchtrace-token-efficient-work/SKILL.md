---
name: patchtrace-token-efficient-work
description: Reduce token costs during PatchTrace engineering with selective reads, reusable context, bounded delegation and least-cost capable models while keeping full code and verification quality.
---

# Economize the process, not the proof

- Start with `AGENTS.md`, applicable spec index/registry entries, owning modules and limited relevant sections. Search symbol names/paths before reading full files. Avoid giant file/tree dumps and redundant summaries.
- Preserve a compact reusable handoff: goal; exact branch/base; file ownership; spec paths and invariants; acceptance tests; unresolved risks. Recheck branch state after handoff or compaction.
- Reuse current code and tests rather than rebuilding. Prefer the smallest complete slice, not unrequested extensibility or churn. Stop when acceptance is proven.
- Assign straightforward documentation, inventory, fixtures or routine edits to the cheapest capable model. Use stronger reasoning for hard architecture, binary evidence, concurrency, security/privacy and complex integration. Escalate instead of repeatedly retrying failing cheap workers.
- Delegate only independent scoped work. Provide workers the necessary exact contract and acceptance criteria, not the entire conversation. Avoid agents for tiny changes, overlapping file ownership or unbounded exploration.
- Use focused tests first, then broad gates when warranted. Preserve code, assertions, exact commands, exceptions, error logs, provenance and risk findings byte-for-byte. Compress narration, not deliverables.
- No automatic Caveman proxy/CLI, cloud service, telemetry, external model provider or installer. Optional `caveman` affects communication style only and is not verified token savings.
- Report only measured savings as numbers. Final handoff: changed paths, tests with status, blockers and PR/commit.

This skill never overrides safety, specification or release obligations.
