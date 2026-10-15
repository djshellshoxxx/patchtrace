# Follow evidence and check provenance

Evidence links connect an interpretation to specific supplied records. Select a Support, Counterevidence, or alternative evidence entry to navigate to its recorded side and line range.

Before relying on the location, check:

1. The project and analysis run.
2. The older or newer artifact identity.
3. The function relationship being reviewed.
4. The cited function and supplied line range.
5. Whether the context is current or stale.
6. Whether relevant material was omitted or unavailable.

A valid citation establishes a traceable reference within the supplied context. It does not establish that the accompanying explanation is correct or that the selected function relationship is accurate.

Decompiled line numbers refer to the retained decompiler text. Display alignment can insert gaps, so equal visible row numbers do not establish corresponding original lines.

Use `Bookmark selected evidence` to retain an analyst annotation. Copying a code representation also includes documented project, artifact-hash, run, match, and function provenance.

Stale evidence belongs to an earlier context. The documented interface shows a stale notice and retained historical context rather than redirecting its citation into current code.

If a citation does not navigate, inspect its context status before assuming the line is missing. Reopening a current function does not repair a historical reference.

**Missing evidence remains unknown.** An unavailable representation or omitted record does not establish that the behavior under investigation is absent.

Sources: README.md; docs/specs/ui.md; src/patchtrace/tooltips.py; AGENTS.md.

next

Worked for 1m 54s

<!-- FORMAT NOTE: The raw text ends with stray UI-capture lines "next" and "Worked for 1m 54s" (likely pasted from a chat transcript). Kept as plain text; confirm and remove if unintended. -->
