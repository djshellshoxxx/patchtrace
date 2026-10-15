# Leads

Open Leads from View or Ctrl+Shift+L. The implemented dock presents an explained list of places to investigate using stored comparison and advisory evidence. A lead is a reading suggestion; its rank does not establish that the function contains or fixes the selected CVE.

Check the current project and selected advisory context before reading the list. Review the lead's pairing, channels, flags, and expected changes seen. The observations table exposes standing, evidence, role, how it is known, source, and detail. Read missing and conflicting evidence alongside supporting observations.

Use the available class and text filters to narrow the list, then clear them when checking coverage. A filtered empty list is not the same as a complete assessment with no leads. The supplied evidence can be partial, stale, or unavailable.

Go to function depends on resolving the stored relationship into current code. A blocked or stale navigation result must not select an unrelated function silently. Pin, dismiss, and note actions record analyst review separately from source observations; dismissing a lead is not a statement that its underlying code was validated.

The source stores review events rather than rewriting prior evidence. Keep the result identity and provenance with any exported discussion.

Sources: src/patchtrace/ui_leads.py, [CLI guide](../guide/16-cli-reference.md), and docs/qa.md. **UNVERIFIED:** PE-backed navigation, large-project responsiveness, native Windows behavior, and screen-reader output were not exercised here.
