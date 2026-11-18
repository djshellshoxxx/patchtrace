# `patchtrace runtime`

Use `patchtrace runtime` to inspect or install a local runtime ZIP. These commands never download files or execute Python, Java, Ghidra, or the target binaries.

Inspect an archive without extracting it:

```console
patchtrace runtime inspect-zip runtime.zip --json
patchtrace runtime inspect-zip runtime.zip --sha256 TRUSTED_SHA256 --json
```

Inspection checks the manifest, member paths, sizes and hashes. Windows and Linux archives can both be inspected. `installable_here` indicates whether the archive platform matches this host; inspection is not a native compatibility test.

Install after obtaining the archive digest from a source you trust:

```console
patchtrace runtime install-zip runtime.zip --sha256 TRUSTED_SHA256 --confirm --runtimes-dir /absolute/path/to/runtimes --json
```

Use an absolute Windows path on Windows, for example `C:\Users\you\AppData\Local\PatchTrace\runtimes`. Without `--runtimes-dir`, the default is `%LOCALAPPDATA%\PatchTrace\runtimes` on Windows or `$HOME/.local/share/patchtrace/runtimes` on Linux. If the corresponding environment variable is absent, specify the directory explicitly.

SHA-256 proves integrity against the supplied digest, not publisher authenticity. Installation requires `--confirm` and the digest; a missing confirmation refuses before reading the archive. Existing runtime directories are never overwritten. Linux archives need executable metadata for their Python and Java launchers; rebuild legacy archives that lack it from executable source files. The installer retains only safe executable permissions, never special or group/world-write bits.

The result prints the installed Python, Ghidra and Java locations. It does not change desktop settings. Use these paths in Setup or with `patchtrace compare --python ... --ghidra-dir ...`. Diagnose the runtime before relying on it: archive integrity and installation do not establish native compatibility.

`--json` emits one `enrichment-cli/1` document with a `runtime-cli/1` result. Exit codes: 0 success; 2 invalid arguments or archive; 3 installation failure; 5 cancellation. Failures retain previous files. Newly created empty installation ancestors are removed only when their filesystem identity still matches this attempt. A runtime already published before interruption is retained; inspect the destination before retrying. If staging cleanup fails, the service reports the path for review.
