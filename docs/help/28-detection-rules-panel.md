# Detection rules panel

Planned. The YRX plan defines the detection-rules interface. Its panel declaration was unavailable during review. Desktop availability is UNVERIFIED.

The manifest reserves Ctrl+Shift+R. The planned workspace includes candidates, a test grid, and saved rules.

Start with a function pair and choose Propose. Inspect the proposed side, selected features, generated text, and checks before accepting a candidate. A candidate is not automatically a saved or exported rule.

Feature cells distinguish present, absent after completed evaluation, and unknown when a producing tool is missing or failed.

Use Accept, Reject, or Defer to record a decision. Acceptance requires a label and creates a retained rule version. Export is a separate action.

Test the selected rule against explicit target builds and comparison files. Grid results distinguish:

| Result | Meaning |
|---|---|
| `Match` | The tested file contains the rule’s recognized pattern |
| `No match` | Testing completed without a match |
| `Not scanned` | The file was not successfully evaluated |
| `Timeout or error` | Evaluation did not establish a result |

Expected outcomes are analyst-defined test expectations. **An unexpected result requires investigation rather than automatic relabelling.**

A pattern match identifies pattern presence. It does not establish whether a file contains a particular flaw or remediation.

Review the test engine, target identities, and stale-grid notices before exporting. Planned history preserves accepted versions and decisions; it does not provide a general delete action.

Sources: docs/specs/program-e/YRX-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.
