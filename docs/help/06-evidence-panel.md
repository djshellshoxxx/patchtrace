# Engine evidence

Open Engine evidence through View or Ctrl+Shift+E. The Evidence tab compares stored engine observations for the current pair. The Engines tab probes optional tools and starts explicitly selected secondary analysis. These are separate activities: opening stored evidence does not require rerunning an engine.

Filter by verdict, search names, or hide agreed rows to focus your review. Select a row and inspect each engine's native units and provenance. Copy provenance records the source relationships; Go to match returns to the navigator when a corresponding match can be resolved.

Agree means comparable endpoints align without a reported contradiction. Contested means another pairing conflicts. Single engine means only one comparable observation is available. Unknown means the evidence cannot support that comparison. An engine that failed or did not run is not a negative vote.

Keep conflicting alternatives visible. Several tools can derive results from the same disassembly, so their agreement is not automatically independent corroboration. PatchTrace does not average engine scores.

The optional triage index is an ordinal reading aid for matching. It is uncalibrated and is hidden by default; leave it out of claims about a particular fix. Refresh stale evidence before using it for a current review.

Source: [evidence guide](../guide/12-evidence-and-engines.md), docs/modules.md, and src/patchtrace/secondary/evidence_panel.py. **UNVERIFIED:** probes, engine execution, control states, and Windows accessibility were not exercised here.
