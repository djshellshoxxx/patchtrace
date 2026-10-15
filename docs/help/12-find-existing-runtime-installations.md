# Find existing runtime installations

`Find existing installations` searches bounded local locations for Python and Ghidra installations. Use it when the tools are already installed but their paths are not configured.

Discovery reads local filesystem information. It does not download dependencies, install software, execute the discovered programs, or analyze a target binary.

1. `Open` `Setup.`
2. Select `Find existing installations.`
3. Read the discovery output.
4. Check any populated Python and Ghidra fields.
5. Use `Browse` when you need to select a candidate explicitly.
6. Select `Diagnose dependencies.`
7. Review the diagnosis and select `Save setup.`

A unique candidate can populate an empty field. An existing manually configured path is retained. Multiple candidates require an explicit choice rather than an arbitrary selection.

The documented search includes the dedicated backend interpreter at:

```
%LOCALAPPDATA%\PatchTrace-backend\Scripts\python.exe
```

It also checks common Ghidra extraction locations. The search is bounded, so an installation elsewhere can remain undiscovered.

If nothing appears, use `Browse` to select the external interpreter and unpacked Ghidra root. An empty result does not establish that the tools are absent from the computer.

Discovery and diagnosis answer different questions. Discovery finds candidate paths. Diagnosis checks the selected configuration. A native comparison then exercises the complete backend workflow.

> UNVERIFIED: successful discovery in every customized, redirected, or synchronized Windows directory is not established by filesystem fixtures.

Sources: `README.md,` “Windows setup”; `docs/windows.md;` `src/patchtrace/tooltips.py.`
