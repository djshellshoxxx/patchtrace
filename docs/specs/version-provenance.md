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
disabled and fsmonitor disabled. Only `rev-parse` root/HEAD observations and
`describe --always --tags` object/ref queries run. The observed top-level path
must equal the selected ordinary source root before and after the ref queries;
an enclosing repository is not attributed to an unrelated nested source tree.
Root identity must remain unchanged, and legitimate Git worktrees are supported.
Source installations always report `dirty: null`;
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
The initial recovery added this consumer; the producer amendment below completes
the existing desktop builders.

The result adds `contract: build-info/1` and a provenance basis (`source-tree` or
`packaged-record`) around the historical fields. It uses `enrichment-cli/1`:
exit 0/status complete for the available observations, even when some optional
facts are unknown; warnings state why. Exit 5 means cancellation, and malformed
CLI input keeps exit 2. Text goes through the existing terminal escaping layer.
No Qt import is allowed in discovery or execution.

## Desktop build producer amendment (2026-11-19)

`tools/package_buildinfo.py` supplies the existing Windows and Linux onedir
builders. Before PyInstaller runs, it verifies that the imported observation
module belongs to the selected source root, records the bounded source digest,
object/ref Git observations, actual Python/PyInstaller/PySide versions and a UTC
timestamp, and validates the exact existing record contract. Missing Git stays
unknown and source cleanliness stays null. A missing or invalid source digest
refuses the build; no environment-supplied commit substitutes for Git observation.

After freezing, the helper recomputes the bounded source fingerprint and Git
observations and refuses a detected change. It publishes the exact prepared
bytes exclusively to `_internal/patchtrace/build-info.json` in the current
PyInstaller onedir layout, through the existing no-link, anchored publisher.
The package and `_internal` directories must already exist. Existing metadata,
links, changed roots or malformed records refuse rather than being overwritten.
The record is installed before `file-inventory.json` is generated, so the ordinary
archive inventory includes it. Archive labels and Windows version resources
retain their existing contracts; the record's version is the runtime package
version, not a release label.
When Git commit provenance is available, the Windows version resource's commit
must agree before freezing; a conflicting CI environment label cannot override
the observed checkout identity.

Before archiving, the builder runs its own freshly built executable with
`version --json` through the existing bounded process supervisor (30 seconds,
at most 16 KiB stdout and 4 KiB retained stderr). Strict JSON must report the
version command's complete envelope, packaged-record basis, no warnings and
exactly the expected build fields. A source fallback, missing/changed metadata,
malformed output, timeout, output overflow or nonzero exit refuses archiving.
This executes only the application produced by the build, never an analysis
target or downloaded sample.

The before/after observations detect changes; they do not lock a mutable source
tree throughout freezing or attest compiled bytecode, package authenticity,
signing or native compatibility. Portable helper tests and authored process
controls are not actual Windows packaging acceptance. Existing native smoke,
dependency, security and release qualification gates remain required.
