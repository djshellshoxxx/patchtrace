# Headless version and source observations

Status: consumer recovery plus desktop producer continuation, 2026-11-26 Pacific. Selected source:
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a` (retained PR #320), including its
reviewed Git-root and no-worktree-filter corrections. The original feature came
from `62b9a3de4d1036a6e4b9bd2618372f4042b15f7f`. This additive contract uses the
current lazy CLI registry and maintained bounded file reader. The producer amendment
below adds build records to the existing desktop builders. Settings, doctor,
Windows version-resource formats and publication policy retain their contracts.

`patchtrace version [--json]` reads the current package version, Python and
installed dependency versions, frozen state, and available build/source facts.
It writes no project, starts no analysis tool and makes no network request.
Source installations may invoke the installed Git executable through the existing
bounded process supervisor: fixed read-only arguments, at most three seconds and
4096 stdout bytes per call, no shell, no inherited Git environment overrides, optional locks
disabled and fsmonitor disabled. Only `rev-parse` root/HEAD observations and
`describe --always --tags` object/ref queries run. The Git executable must resolve to an absolute
path; a relative candidate is refused so the changed working directory cannot select a planted Git.
The child inherits only PATH, PATHEXT, SystemRoot, WINDIR, COMSPEC, TEMP, TMP, TMPDIR,
HOME, HOMEDRIVE, HOMEPATH, USERPROFILE, LANG, LC_ALL and LC_CTYPE (case-insensitive names).
All other inherited settings—including provider credentials, proxies, loader hooks, Python
hooks and GIT_* overrides—are excluded. GIT_OPTIONAL_LOCKS=0, GIT_TERMINAL_PROMPT=0,
GIT_CONFIG_NOSYSTEM=1 and GIT_CONFIG_GLOBAL=os.devnull are the only controlled additions.
No hard memory cap is claimed for the Git probe: an unqualified RLIMIT_AS would risk
breaking native Git, particularly on Windows. Each fixed read-only command instead has a
three-second process deadline and a 4096-byte total stdout cap; those bounds are not a
memory-allocation guarantee. Native memory qualification remains separate. The observed top-level path
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
The initial recovery provided the consumer. The producer amendment below adds
record generation and execution checks to the existing desktop builders;
published packages require qualification on their actual build platform.

The result adds `contract: build-info/1` and a provenance basis (`source-tree` or
`packaged-record`) around the historical fields. It uses `enrichment-cli/1`:
exit 0/status complete for the available observations, even when some optional
facts are unknown; warnings state why. Exit 5 means cancellation, and malformed
CLI input keeps exit 2. Text goes through the existing terminal escaping layer.
No Qt import is allowed in discovery or execution.

## Desktop build producer continuation (2026-11-26)

Recover only `tools/package_buildinfo.py`, its focused tests and the builder
integration from retained PR #320, commit
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a`. Before PyInstaller runs, the helper
verifies that the imported observer belongs to the selected source root and
records the bounded source digest, Git object/ref observations, actual
Python/PyInstaller/PySide versions and a UTC timestamp. It validates the exact
existing record contract. Missing Git remains unknown and cleanliness stays
null. Missing source identity or dependency metadata refuses the build; CI
environment variables never substitute for an observed Git commit.

After freezing, recompute the source digest and Git observations and refuse
detected changes. Publish the prepared bytes exclusively to
`_internal/patchtrace/build-info.json` through the existing anchored, no-link
publisher. Both package directories must already exist. Existing records,
links, changed roots or invalid records refuse publication. Install before the
file inventory is generated so both archive formats include the record.
Archive labels and Windows resource fields keep their existing contracts;
the record's version is the runtime package version. When an observed Git
commit is available, the Windows resource commit must agree before freezing.

Before archiving, run only the freshly built application's absolute executable
path with `version --json`, through the existing process supervisor: 30 seconds,
16 KiB total stdout and 4 KiB retained stderr. Use the Git probe's documented
platform/path/locale environment allow-list and controlled Git settings, with
`QT_QPA_PLATFORM=offscreen`; do not forward credentials, proxy settings or
loader/Python hooks. No hard memory cap is claimed for this native package
probe; the process and output bounds are not a memory-allocation guarantee.
The completed result must contain raw stdout whose length exactly equals the
reported byte total and does not exceed the cap, even after a quick exit.
Strict JSON must contain the complete version envelope, packaged-record basis,
no warnings and exactly the prepared fields with their declared types.
Missing or changed metadata, source fallback, malformed or truncated output,
timeout, output overflow and nonzero exit all prevent archiving.

The before/after comparison detects changes without locking a mutable source
tree throughout freezing. This record does not attest compiled bytecode, sign
packages or establish authenticity. Helper tests and authored subprocesses are
portable controls; native Windows and Linux package production and consumption
remain required. Existing full frozen smoke, dependency, accuracy and release
gates remain unchanged. No analysis target or downloaded sample is executed.

## Extracted and installed package acceptance (2026-11-27)

The frozen smoke checks the delivered package's version record before its other
commands. It reads `_internal/patchtrace/build-info.json` relative to the selected
executable through the same anchored, no-link, 16 KiB reader, then reuses the
producer's bounded `version --json` verification against those exact bytes. The
child runs from the delivered package directory. Missing, invalid, oversized or
linked metadata, a changed package root, an incomplete response, any warning or
a mismatch fails acceptance. Recheck the package anchor and record after the
child exits; a detected package or record change fails acceptance. This is an
observation, not an atomic snapshot across the child lifetime.

`tools/frozen_smoke.py EXECUTABLE --version-only` runs only this check, allowing
the portable ZIP and installed Windows consumers to check their own extracted
or installed executable. Full frozen smoke includes the same check. A source
CLI run is never credited as frozen version acceptance. Archive checksums must
still be verified before executing downloaded code; this check does not replace
that admission. On success, print the admitted Git commit and source digest so
native job evidence can be bound to its actual checkout and delivered record.
This mode needs only the standard-library host interpreter and the reviewed
source checkout, and runs under `python -S`. It installs no application or
development dependencies into the independent Windows artifact-consumer job.
The shared response parser uses the existing duplicate-key and nonfinite-value
refusal hooks; floating-point literals are also rejected because this exact
version contract has no numeric fields. The checker source path is never
forwarded to the frozen child through its restricted environment.

Authored records, injected process results and authored local consumer scripts
exercise refusal and integration controls only. They are not native frozen
package evidence. Source observation, compiled-bytecode identity, authenticity,
signing and release qualification retain their distinct existing boundaries.

## Acceptance and remaining work

Focused controls cover source fingerprint parity and bounds, missing or changing
source and Git state, ordinary and linked Git worktrees, an unrelated enclosing
repository, no configured clean-filter invocation, strict packaged records,
unknown frozen facts, lazy headless CLI discovery, the standard output envelope
and cancellation. They use authored files and temporary Git repositories; they
are not native packaged-build or release evidence.

The producer and builder wiring require source-change refusal, exclusive record
publication, strict frozen-response equality, final-output completeness and
archive-order regressions. A consumer without an admitted record still reports
unknown build identity. Exact-source hosted Linux/Windows QA, actual package
production and independent downloaded-artifact gates remain required before
integration. Signing, manual acceptance and release publication remain separate.
