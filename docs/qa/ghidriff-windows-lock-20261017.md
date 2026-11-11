# Windows Ghidriff overlapping lock: 2026-10-17

Evidence: user-provided ghidriff.log, analysis.log and failure.txt from run quarantine-e28c2521-4255-49f0-bd5e-49e568fb42c7 (not committed, because logs contain local paths and target details).

Observed: Ghidriff reports `threaded: True`, analyzes the older and newer inputs concurrently, and Ghidra's WindowsResourceReferenceAnalyzer raises `java.nio.channels.OverlappingFileLockException` while loading a Java script. Individual decompiler timeouts follow. Final PatchTrace failure.txt says `PT-CANCEL`; the logs do **not** prove that the lock warning itself caused cancellation or that another PatchTrace engine overlapped this run.

Mitigation: primary backend now passes the documented Ghidriff `--no-threaded` option. The adapter raw-cache version advances to /2, preventing accidental reuse of outputs made with a different threading policy. Engine scheduler behavior, isolated project/GZF/settings directories and failure quarantine remain unchanged.

Validation needed: run focused pytest and full pytest/ruff CI. On Windows repeat the same binary pair at least three times using this branch/build; ensure Ghidriff reports `threaded: False`, no overlapping file locks occur, Ghidriff produces a complete JSON, and PatchTrace publishes a completed run. Test manual cancellation separately. This is a mitigation pending a real Ghidra-backed run, not a proven upstream defect fix.
