# Exclusive directory publication (2026-11-18)

This shared boundary is used by complete project backups and verified offline
runtime installation. It replaces their duplicated public-directory reservation
algorithm. No wire, SQLite, project layout or normal overwrite contract changes.

## Contract

`publish_directory_no_replace(stage, destination)` receives distinct absolute
paths to siblings under the caller-controlled parent. The stage is an ordinary
directory privately created and populated by that caller. Embedded NUL is
refused before any native C-string conversion. Source links and nonsibling or
relative paths are outside this internal contract and are refused.
On Windows, the source's `lstat` reparse-point attribute is also refused,
regardless of the reported directory mode or reparse tag. Junctions can retain
directory mode and cannot be admitted by an `S_ISDIR` check alone. Portable
metadata controls are separate from a native Windows junction control.

The final publication is one native operation that refuses **any existing
destination entry**, including an empty directory, a file or a dangling link.
The destination must not be reserved with `mkdir` or removed on any failure.
On success the complete stage is renamed into place. On failure the publisher
does not remove either pathname; the existing caller cleans only its own stage.
An entry appearing immediately before native publication is preserved by the
same rule. No `exists` check followed by an overwriting rename is equivalent.

| Platform | Operation | Failure behavior |
| --- | --- | --- |
| Windows | `os.rename`, whose Windows contract refuses an existing destination | Propagate the native error; no replace/copy fallback |
| Linux | libc `renameat2` with `RENAME_NOREPLACE` | Propagate collision, cross-device, permission and unsupported-filesystem errors |
| Other OS or libc without the required symbol | Explicit `ENOTSUP` refusal | Preserve both entries; never downgrade to an overwriting primitive |

`ENOSYS`, `EINVAL`, `EOPNOTSUPP` and `EXDEV` are failures, not invitations to
retry with a weaker primitive. No architecture-dependent raw syscall number,
external executable, new dependency, network operation or target execution is
introduced. Existing backup and offline-installer error envelopes remain.

## Import boundary (2026-11-18)

Importing the publisher and its pure IR/ingestion callers must not load ctypes,
Qt, subprocess or network modules. Load the Linux FFI only when the validated
publication operation selects the Linux native path. Windows dispatch and
unsupported-platform refusal happen before that import; invalid paths also
refuse before native dependencies are loaded. If the Linux FFI is unavailable,
the publication fails without a weaker fallback or any source/destination
mutation. This changes import timing only: native calls, errno propagation,
path admission, reparse refusal and caller-owned cleanup remain as specified.

Fresh-interpreter controls must preserve the original IR import-purity assertion
and prove both import refusal boundaries and the existing publication behavior.
Authored Windows dispatch remains a portable contract control, never native
Windows acceptance. Existing POSIX/Windows ownership controls remain required.

## Ownership boundary

The caller retains the existing controlled parent and private-stage ownership
assumptions through the operation and cleanup. This repair gives an atomic
no-replacement guarantee for the destination leaf. It does not establish
rooted-handle protection against a noncooperating process replacing source or
parent pathnames, nor power-loss durability or transactional external storage.
The stronger immutable-file `owned_publication` API remains separate and
unchanged. Runtime authenticity still depends on its existing provenance and
explicit consent; a self-hashed bundle does not become publisher authenticated.

## Acceptance and original evidence

Preserve the original four failing held-directory-FD probes and two healthy
public backup/install controls. Their old `os.rename` interception is specific
to the removed reservation algorithm; it must remain archived without being
reported as a passing test of a different native call.

The new controls cover the same foreign-directory identity/link-count oracle
at the new native-operation seam, with both collision and injected failure.
Exercise the actual `ProjectService.backup` and `install_offline_bundle` paths,
ordinary complete publication, no public placeholder, all existing leaf kinds,
Unicode names, two competing publishers, invalid inputs, unsupported primitives
and native errno propagation. No changed assertion or disabled test is permitted
to turn a failure into a pass. Native Windows and Linux results are distinct;
mocked platform dispatch is only a contract control.

Primary operation references:

- [Python 3.12 `os.rename`](https://docs.python.org/3.12/library/os.html#os.rename)
- [Linux `renameat2` and `RENAME_NOREPLACE`](https://man7.org/linux/man-pages/man2/rename.2.html)
- [Microsoft MoveFileExW flags and directory behavior](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
