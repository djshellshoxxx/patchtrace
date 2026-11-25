# Headless version and source observations

Status: consumer recovery candidate, 2026-11-24 Pacific. Selected source:
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a` (retained PR #320), including its
reviewed Git-root and no-worktree-filter corrections. The original feature came
from `62b9a3de4d1036a6e4b9bd2618372f4042b15f7f`. This additive contract uses the
current lazy CLI registry and maintained bounded file reader. It leaves settings,
doctor, builders, Windows version resources and publication policy unchanged.

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
The consumer checks the final process result as well as its exit reason: raw
stdout must be present, match the reported total byte count and stay within
4096 bytes. A successful quick exit with oversized or truncated output cannot
turn a retained tail into a complete Git observation.

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
This recovery provides the consumer only. The current desktop builders do not
produce this record, so their frozen installations will report unknown build
facts until the separately retained producer is integrated and qualified.

The result adds `contract: build-info/1` and a provenance basis (`source-tree` or
`packaged-record`) around the historical fields. It uses `enrichment-cli/1`:
exit 0/status complete for the available observations, even when some optional
facts are unknown; warnings state why. Exit 5 means cancellation, and malformed
CLI input keeps exit 2. Text goes through the existing terminal escaping layer.
No Qt import is allowed in discovery or execution.

## Acceptance and remaining work

Focused controls cover source fingerprint parity and bounds, missing or changing
source and Git state, ordinary and linked Git worktrees, an unrelated enclosing
repository, no configured clean-filter invocation, strict packaged records,
unknown frozen facts, lazy headless CLI discovery, the standard output envelope
and cancellation. They use authored files and temporary Git repositories; they
are not native packaged-build or release evidence.

The producer (`tools/package_buildinfo.py` and builder integration) remains a
separate retained PR #320 slice. This consumer does not establish a frozen
executable's source identity without an admitted record, sign artifacts, attest
compiled bytecode or authorize publication. Exact-source hosted Linux/Windows
QA and existing package gates remain required for integration.
