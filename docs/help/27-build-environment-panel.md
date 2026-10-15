# Build environment panel

Planned. The DIE plan describes build-environment presentation, initially as a card in file inspection and later as a dock. The dock declaration was unavailable during review. Migration status is UNVERIFIED.

Build-environment information helps explain differences introduced by compilers, linkers, packaging, or analysis conditions.

The design combines PatchTrace’s header checks with stored Detect It Easy results. Without Detect It Easy, the interface should identify which local checks ran and which tool-derived names remain unavailable.

Compare the older and newer values alongside their basis. A linker header field and a signature-based compiler identification are different kinds of evidence.

A toolchain difference can explain some code changes without a source edit. It does not establish the cause of every changed function. Conversely, **no detected toolchain difference does not establish identical compiler options.**

Packed, protected, managed, installer, and large-overlay notices describe limits on interpretation. PatchTrace does not unpack a target by executing it. An installer’s embedded application payload may remain unanalyzed.

The planned `Read with Detect It Easy` action explicitly invokes the configured tool. Merely reading stored build facts does not run it.

Use `Technical details` and `Copy details` to retain the underlying observations. A failed side should leave readable information from the other side available.

The central manifest reserves Ctrl+Shift+B. The earlier card design specifies no global shortcut; availability depends on migration.

Sources: docs/specs/program-e/DIE-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.
