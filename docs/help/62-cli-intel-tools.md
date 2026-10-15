# `patchtrace intel-tools`

Runs and reads the optional static evidence tools: capa, FLOSS and Detect It Easy. Each tool runs only when you start it with an explicit verb. Stored results keep the tool version and settings.

```
patchtrace intel-tools probe ...   # verify the configured tool executables (runs --version / --help)
patchtrace intel-tools run ...     # run the profile engines on both artifacts and store the evidence
patchtrace intel-tools delta ...   # compare stored older and newer evidence (never runs a tool)
patchtrace intel-tools pairs ...   # capa capability changes per matched function pair (stored evidence; never runs a tool)
```

- `probe` starts the configured executables, with their version or help flags only.
- `run` starts the profile's engines on both artifacts. Check the profile before you start it.
- `delta` and `pairs` read stored results and never start a tool.

A tool that is installed has not thereby produced evidence for your project. Check that the run completed and that its settings match on both sides. A failed or missing run is unknown, not a negative result. See [evidence and engines](../guide/12-evidence-and-engines.md) and [Capabilities](26-capabilities-panel.md).

Sources: `src/patchtrace/intelligence/tools/cli.py`, top-level `patchtrace --help`.
