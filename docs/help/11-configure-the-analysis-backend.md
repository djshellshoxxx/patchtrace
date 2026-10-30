# Configure the analysis backend

`Open` `Setup` to select the external runtime used by `Run comparison.` The Python included with the desktop application does not replace this backend.

Configure these paths:

| Field | What to select |
| --- | --- |
| External Python executable | The `python.exe` in the environment where Ghidriff is installed |
| Ghidra installation directory | The unpacked Ghidra root containing its application files |
| Optional private Java home | The JDK installation directory, when using a dedicated Java runtime |

Select the actual files and directories. **Do not select `PatchTrace.exe` as Python, a Ghidra ZIP as the installation directory, or the parent of the intended Ghidra installation.**

The README records a native fixture using Python 3.12.10, Ghidra 12.0.4, Temurin Java 25, and Ghidriff revision 4f5d895fcbb1eacd65efd81145922c15bb7e741d. That result covers the recorded combination and fixture.

Select `Diagnose dependencies,` read the output, then `Save setup.` Diagnosis checks configured dependencies without executing either target binary. A successful diagnosis does not establish that every native comparison will complete.

The backend runs Python in isolated mode. Install Ghidriff and its dependencies in that interpreter's own environment, preferably a dedicated virtual environment, and select its `python.exe` (Windows) or `bin/python` (Linux). Packages installed only with `pip install --user` or supplied through `PYTHONPATH` are ignored. The executable path keeps the selected virtual environment even when it is a symlink to a base Python binary.

When using system Java, restart PatchTrace after changing environment variables. A configured private Java home applies to backend child processes without requiring a global Java change.

If diagnosis fails, correct the reported dependency first. Repeatedly starting a comparison does not repair a missing interpreter, incompatible JDK, or incorrect Ghidra directory.

> UNVERIFIED: compatibility of another tool combination requires a native comparison check.

Sources: `README.md,` “Install the comparison backend”; `docs/specs/ui.md;` `src/patchtrace/tooltips.py.`
