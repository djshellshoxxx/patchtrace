# External tools and discovery

PatchTrace's desktop runtime is separate from the comparison backend. Setup must point to the backend's Python executable and the unpacked Ghidra root. PatchTrace.exe is not a substitute for the backend interpreter. A private Java home can isolate child-process configuration from global settings.

Find existing installations performs bounded, read-only discovery. A unique candidate can prefill an empty field; multiple candidates require an explicit selection. Manually configured paths are retained. Discovery does not install packages or prove compatibility by executing a full comparison.

Diagnose dependencies checks paths and available runtime information. If it succeeds but comparison fails, inspect the retained log and test the configured combination through the documented workflow. Restart the app after changing inherited system Java settings.

Secondary engines have separate requirements. BinDiff uses an explicit executable location and validated exports for the exact pair. The existing guide describes rz-diff discovery through PATH or an explicit path. Static capa, FLOSS, and Detect It Easy adapters use explicit configuration and stored provenance.

A tool being installed does not mean it has produced evidence for this project. Check whether the relevant run completed, which side it read, and whether its settings match the other side.

Sources: [getting-started discovery table](../guide/10-getting-started.md), [Windows setup](../windows.md), and [evidence guide](../guide/12-evidence-and-engines.md). **UNVERIFIED:** installed versions, upstream licenses, executable probes, discovery precedence on Windows, and native tool compatibility were not independently checked here.
