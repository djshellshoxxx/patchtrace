# Authored BinExport / BinDiff harness contract — 2026-11-02

This external-tool QA harness targets production source
`1367889d549a4db290b669df4ed97ac20b553428`. It adds no product producer,
schema, UI, acceptance override or trust promotion. Ghidra 11.0.3 is isolated
from core Ghidra 12.0.4. Tool archives and runtime files remain outside git.

The default invocation checks paths, source/import binding, versions and pinned
tool/script hashes without executing compiler, Java or BinDiff. `--run` is only
for the coordinator's explicit serial-run release after independent source review.
It requires a fresh output directory, preserves receipt/logs/partial exports on
failure, and never executes a target DLL. Every observed completion/failure is
written to the receipt; success requires accepted real exporter bytes and the
production BinDiff scheduler/importer result, not a child exit code alone.

The only inputs are `tests/fixtures/old.c` and `new.c`, with fixed source hashes.
The copied native venv binds imports to this checkout. Zig 0.17.0 and its binary
hash match the published November 1 compile receipt. Compilation uses that
receipt's no-entry/no-runtime PE command shape and records actual new hashes.
All child processes have time/output bounds and use `jobs.run_process`. Java
uses the official launcher's Utility.jar/Ghidra/AnalyzeHeadless entry with an
explicit pinned Java executable, a 2 GiB heap, 8 GiB process address-space cap,
two VM processors, one analysis CPU and private home/cache/temp directories.
The standalone harness temporarily wraps C3's existing runner only to record
actual worker argv, request/results and logs; it delegates unchanged arguments
to `jobs.run_process` and restores the original runner in `finally`. No C3
acceptance result, snapshot, limit or environment is replaced by a fake.

Each side is imported into a new project, then exported in a separate noanalysis
prescript invocation. The reviewed Java script checks the program's stored
SHA-256, invokes the official extension's exporter with identical default false
options on both sides, publishes by exclusive hardlink from a private stage,
and emits its completion marker only after success. Failure preserves a partial
stage. C3 acceptance with `accept_unbound=False` remains mandatory. Raw exports
are never rewritten to pass validation.

Swapped bound exports and a wrong artifact hash must be refused before BinDiff
execution. The success path uses `c3_acceptor`, `BinDiffAdapter`, `ProjectRef`,
`scheduler.run_engines` and its existing supervised runner/importer. It checks
ordered ownership, a nonempty match set, algorithm provenance, exact retained
raw `.BinDiff` digest and the pinned version. These are authored real-plugin
compatibility checks, not Tier R calibration, a signed BinDiff oracle, Windows,
Tier W, release or full G-U acceptance. BinDiff remains unsigned/unverified by
the independent-trust gate even if this local observational smoke passes.

The official BinExport asset is unsigned and has no upstream asset digest. Its
local pinned hash binds the inspected bytes only. Ghidra archive SHA comes from
the official release; JDK archive SHA comes from the repository pin. No extra
patch to upstream BinExport is used. The 20240417 extension does not contain the
current README's BinExport.java, so this small script calls its packaged API.

Review and native results will be appended with exact source hashes. Setup-only
receipts live under the coordinator's external `native-20261102` directory.

## Independent review and first native attempt

Independent review found no blocking source findings at harness
`25c4114db1ee518a695372597473163e51eb1861`, tree
`4efdf4cca7a429784c6886357c3670139bc0299e`. Eleven safe harness controls
passed in 0.73 seconds and four independent controls passed in 0.53 seconds.
Source/import/tool preflight, Ruff and diff checks passed. The review was
source-only for Java; it did not claim exporter compatibility. Its unmodified
receipt and control artifacts are retained beside the native evidence.

The coordinator released one serial authored attempt on that unchanged source.
It **failed** during the first export and was stopped without repair or retry:

| Stage | Actual outcome |
|---|---|
| Older authored PE compilation | Exit 0, 0.052 seconds |
| Ghidra 11.0.3 import and analysis | Exit 0, 16.478 seconds |
| Exporter invocation | Exit 1, 5.687 seconds |
| Accepted BinExport files | Zero |
| Newer-side compilation/export | Not reached |
| C3 wrong-hash/swapped native controls | Not reached |
| BinDiff execution/import | Not reached |
| Target DLL execution | Never performed |

The actual exporter failure is `java.lang.IllegalAccessError`: generated
`com.google.security.zynamics.BinExport$BinExport2` attempted to access
`com.google.protobuf.LazyStringArrayList.emptyList()`. The stack enters
`BinExport2Builder.java:68`, `BinExportExporter.java:92` and the reviewed
script's exporter call. The script compiled and ran to that call. An empty
private `.partial` export remains, with no published or accepted export.

Static inventory finds both host `protobuf-java-3.21.8.jar` and extension
`protobuf-java-3.25.1.jar`. A runtime classpath collision is a hypothesis;
the actual loaded class origin has not yet been established. Neither runtime
JARs, classpath, pins, limits nor production acceptance were changed after this
failure. Ghidra 12.0.4 remains untouched. BinDiff's independent trust gate remains
blocked even though its local download/executable hashes matched the TOFU pin.

The generated older DLL hash is
`32559bf2fd92ff8223b49cf66b3e044428fac1754f48502f309a32dbaa8afb17`.
Compilation also emitted a local PDB; this is a symbol-visible authored case,
not hidden-symbol evidence. The archive retains source/compiler outputs,
Ghidra project, application/process logs, partial export, compiled authored
script, exact first-attempt receipt, preflight/setup metadata and independent
review artifacts. Tool binaries and derived tool caches are excluded; a complete
session inventory records their local hashes without embedding their payloads.

Files: `native-binexport-bindiff-attempt1-20261102.json` is the unmodified raw
receipt; `native-binexport-bindiff-attempt1-summary-20261102.json` binds archive
and receipt hashes; the adjacent `.tar.gz` contains the retained evidence and
its member manifest. This qualifies only the frozen production base `1367889`,
not later central fixes. It provides an actual compatibility failure, not a
completed BinExport/BinDiff, full-suite, Windows, corpus or release gate.
