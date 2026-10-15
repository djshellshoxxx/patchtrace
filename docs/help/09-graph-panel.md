# Graph and call relationships

**Planned:** the manifest reserves Graph at Ctrl+Shift+G. The inspected branch does not contain its panel implementation. The WB2 plan describes a pair-aware call-change explorer with changes, neighbors, a call tree, and a diagram.

The intended analyst question is what changed around a function, including changed callees and relationships shared by several modified functions. A graph edge must retain its source and direction. Static call information can be incomplete. The absence of an observed edge does not prove that execution cannot reach a function.

The plan distinguishes changes in function identity from renamed or moved labels. Raw caller/callee name differences can reflect address-based naming noise. Review the underlying matching evidence before treating a new label as a genuinely new call.

Until this panel exists, read available caller/callee context in stored function records and inspect the paired code. Do not infer call counts, execution order, or runtime coverage from a static set of names.

The planned textual tables are also the accessible alternative to the diagram. A diagram alone cannot supply a complete keyboard or screen-reader workflow. Large graphs must disclose limits and omitted context.

Sources: [WB2 integration plan](../specs/program-e/WB2-integration-plan.md), [panel guide](../guide/13-panels-and-layout.md), and src/patchtrace/panel_manifest.py. **UNVERIFIED:** graph extraction, navigation, drawing, keyboard behavior, and performance are not accepted functionality in this documentation.
