# Headless version and source observations

Recovery source: `buildinfo.py` at
`62b9a3de4d1036a6e4b9bd2618372f4042b15f7f`. This additive contract adapts that
historical feature to the current CLI registry; it does not change settings,
doctor, Windows version resources, release gates or package publication.

`patchtrace version [--json]` reads the current package version, Python and
installed dependency versions, frozen state, and available build/source facts.
It writes no project, starts no analysis tool and makes no network request.
Source installations may invoke the installed Git executable through the existing
bounded process supervisor: fixed read-only arguments, at most three seconds and
4096 stdout bytes per call, no shell, no Git environment overrides, optional locks
disabled and fsmonitor disabled. Only `rev-parse HEAD` and `describe --always
--tags` object/ref queries run. Source installations always report `dirty: null`;
`status` and `describe --dirty` are deliberately excluded because they may execute
repository-configured clean filters. A configuration preflight cannot bind a
later command against concurrent edits. Missing Git, refused/oversized output or
a moving HEAD leaves the relevant facts unknown; it never implies a clean checkout.

The source SHA-256 keeps the historical definition: hash the UTF-8 concatenation
of sorted `relative-posix-path TAB file-sha256 LF` records, relative to `src`, for
`patchtrace/**/*.py`. Python caches are excluded. At most 8192 directory entries,
32 directory levels, 2 MiB per Python file and 128 MiB aggregate source bytes are
admitted, with a ten-second cooperative deadline. No linked directory or Python
file is accepted. File content uses the shared held, bounded reader. The complete
inventory and file/directory observations are compared again before returning;
an absent, changing, oversized or unreadable source tree produces unknown source
provenance and a bounded warning. This is an observed source-content fingerprint,
not an atomic filesystem snapshot, a loaded-bytecode identity, package authenticity
proof, clean-Git attestation or native compatibility result.

Frozen installations read only `_MEIPASS/patchtrace/build-info.json`, at most
16 KiB, through the same no-link reader. JSON must have no duplicate keys or
nonfinite numbers and exactly the historical version keys with their documented
types: version, git_commit, git_describe, dirty (boolean/null), source_sha256,
python, pyinstaller (string/null), pyside6 (string/null), built_utc (UTC ISO
timestamp/null), frozen (true). Version must match the running package. Missing
or invalid metadata leaves build facts unknown and produces a warning. Neither
case fabricates source provenance by hashing a frozen extraction directory.
This recovery adds the consumer; current builders do not yet produce this file.

The result adds `contract: build-info/1` and a provenance basis (`source-tree` or
`packaged-record`) around the historical fields. It uses `enrichment-cli/1`:
exit 0/status complete for the available observations, even when some optional
facts are unknown; warnings state why. Exit 5 means cancellation, and malformed
CLI input keeps exit 2. Text goes through the existing terminal escaping layer.
No Qt import is allowed in discovery or execution.
