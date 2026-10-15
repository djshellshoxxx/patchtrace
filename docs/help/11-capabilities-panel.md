# Capabilities

**Planned:** the Capabilities dock is reserved at Ctrl+Shift+A. The panel implementation is absent from the inspected branch. The existing intel-tools CLI and stored evidence adapters do not imply that this graphical workflow is already available.

The CAP integration plan connects capa observations to the older/newer pair and other evidence. A capability label summarizes a static rule match. It is not a behavioral recording, and it does not establish that the associated code executes under a particular input.

For current work, consult the documented intel-tools probe, run, and delta commands. Run optional tools deliberately, then read their stored provenance. Check the exact artifact, tool version, rules, and analysis configuration on each side before interpreting an apparent delta.

A capability observed only in the newer output can reflect a code change, different coverage, or changed extraction conditions. An unsupported or failed older run is unknown, not evidence of absence. Preserve that limitation in notes.

A capability and a function match may share their disassembly origin. Their agreement must not be counted as two independent observations automatically. Never combine native tool values by averaging them.

Sources: [CAP plan](../specs/program-e/CAP-integration-plan.md), [evidence guide](../guide/12-evidence-and-engines.md), and [CLI guide](../guide/16-cli-reference.md). **UNVERIFIED:** GUI controls, capability-to-function joins, native tool compatibility, and Windows acceptance remain outside this documentation's verification.
