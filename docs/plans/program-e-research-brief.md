# Program E research brief (read this first; your prompt only adds your feature card)

You are a research worker for PatchTrace (repo root = your worktree). Goal: plan ONE feature so that it adds **more value inside PatchTrace than the same tool used standalone**, and so that the build succeeds first time. You write documents only; no source code, no pushes, no GitHub access.

## 1. Read first (in this order, skim what is not yours)
`AGENTS.md`, `CLAUDE.md`, `docs/plans/program-e-roadmap.md` (charter in section 3 is your acceptance test), `docs/modules.md` (module map), `tasks/todo.md`, the spec files named on your feature card, and the existing code the card names (read it; do not assume). ChatGPT-authored specs are good drafts, not truth: verify their claims against the code and primary sources, and say where they are wrong or thin.

## 2. Product invariants you must design within
PatchTrace compares an older and a newer build of a binary (and the patch itself) to find what changed and why. Never execute a target binary; never silently upload content; never fabricate unavailable disassembly; never show an uncalibrated score as vulnerability confidence; never average different engines' or channels' scores; keep conflicting evidence; unmatched or missing means unknown, not a negative vote; shared-origin evidence counts once; older/newer orientation is explicit; provenance on everything; offline by default, network only with operation-specific consent; analyst control (no automatic publishing or deletion); advisory, string and code text is untrusted data (bound it, escape it, never execute it); one main window (new UI = dock/tab/panel in the existing window, never a separate app window). Microsoft-derived binaries/PDBs/Winbindex-derived labels stay on the owner's machine and are never committed. Python 3.12, PySide6, SQLite, Pydantic, Windows and Linux, PyInstaller one-folder Windows build; installs must work with `pip --only-binary=:all:`.

## 3. Research rules
Primary sources only: upstream repositories and release pages, official documentation, standards, papers (arXiv/ACM/USENIX/IEEE), vendor docs (Qt, SQLite, Microsoft Learn, CISA, MITRE, NIST). No blogs, videos, forums or AI summaries. Every non-obvious fact gets a URL and a retrieval date; mark `[unverified]` when you could not confirm (some hosts are blocked from the sandbox: record that, do not guess). Pin versions and licenses (SPDX id) of every tool and data source; never copy GPL/AGPL code. Spend research effort where it changes a decision; skip background the team already has.

## 4. Deliverable: exactly one file, `docs/specs/program-e/<ID>-integration-plan.md` (at most ~450 lines)
Create no other file and edit no existing file (list needed edits in section 10 instead; the integration owner applies them). Sections, in order:
1. **Verdict and scope** (at most 10 lines): what we build, what we deliberately do not.
2. **Sources and facts**: table `claim | source URL | retrieved | confidence`; versions, licenses, Windows/Linux install and provisioning, wheels availability, resource use, security notes, limits.
3. **Standalone baseline versus PatchTrace value**: what the tool gives alone; what PatchTrace context adds (pairs, deltas, series, provenance, triage); the concrete workflows this enables.
4. **Cross-feature links**: table of anchors/evidence this feature emits and consumes (function, string, import/API, capability, rule, build fact, advisory phrase, CVE, KB, CWE), which other tracks use them, and how.
5. **Synergy test**: one known-answer scenario (synthetic, committed-fixture-friendly) where the combined result beats each channel alone, with expected outputs.
6. **Traps and guards**: noise, false precision, misleading claims, UI deception risks, and the guard for each.
7. **Contracts**: Pydantic model field lists, error codes (`PT-<AREA>-*`), enrichment-store kind or sidecar, cache key inputs, size/time limits, versioning (additive only).
8. **CLI and GUI**: CLI commands (envelope `enrichment-cli/1`, exit codes 0/2/3/4/5); GUI module design inside the single window: where it docks, widgets, model/view structure, virtualization for 100k rows, keyboard navigation, accessible names, tooltip ids, empty/loading/error/blocked states and exact user-facing copy, Qt (PySide6) pitfalls, offscreen test approach, performance budget. Cite Qt/PySide6/Microsoft accessibility documentation for GUI decisions.
9. **Slice plan**: ordered build slices; for each: scope, exclusive files (new package/module names, tests, fixtures), dependencies, recommended model tier (haiku/sonnet/opus) with reason, size, acceptance gate, fallback. Slices must be small enough to merge on their own and must not require two builders to edit the same file.
10. **Amendments required** to existing specs/docs/code (exact file, section, change) and **test and QA plan** (fixtures without Microsoft binaries, goldens, properties, Windows pitfalls from the roadmap checklist, live-acceptance gates that only CI or the owner's machine can close).
11. **Open questions** with a recommended default each (never block on them).

## 5. Quality bar
Concrete beats general: name modules, fields, limits, copy text and test names. Prefer the smallest design that satisfies the charter; call out anything that looks valuable but fails the charter (standalone duplicate, noise, false precision). Report back in at most 200 words: file written, 3 key decisions, biggest risk, anything the integration owner must decide.
