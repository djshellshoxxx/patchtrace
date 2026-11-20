# Linux forced-publication primitive assessment

## Disposition

**The final Linux source-name substitution finding remains open.** No examined
documented primitive and no tested alternative supplies a held-source-descriptor
atomic replacement of an existing destination. This is a bounded conclusion
about the interfaces below, not a proof that every filesystem-specific,
privileged or future design is impossible.

No production source, test, schema, default behavior or `--force` capability was
changed. This follow-up contributes new native primitive evidence and rejects
several tempting but insufficient repairs. The current security finding is not
waived, and these results do not qualify Windows or release acceptance.

Base: `8cfda72b736ddbd704180dcf39e4a71a33fbc06f`.
The reviewed export source SHA-256 is
`32c6f01694268aa30b07d92d65bf66c65bb23881bcdb0969009f84c4b6be7cd0`.
The original recovery and retained final-boundary regression are documented in
[security-force-recovery-20261119.md](security-force-recovery-20261119.md).

## Required property and available guarantees

The missing property is selection of the verified held source inode in the
same atomic operation that replaces an existing destination. Holding the
destination directory solves a different problem: it roots name resolution in
that directory despite changes to its former parent pathname.

The Linux man-pages interfaces specify `renameat`/`renameat2` with a source
directory descriptor **and a source pathname**. Atomic replacement preserves
destination namespace continuity; there is no documented inode-identity
condition binding a preceding userspace check to the later source lookup.
The documented flags are `RENAME_NOREPLACE`, `RENAME_EXCHANGE` and
`RENAME_WHITEOUT`; none supplies `AT_EMPTY_PATH` source selection.
[Primary source: rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html).

`linkat` can instead select the held inode through `AT_EMPTY_PATH`, or through
the documented `/proc/self/fd/<fd>` plus `AT_SYMLINK_FOLLOW` alternative. Both
retain link's existing-destination refusal. The manual lists a capability
requirement for `AT_EMPTY_PATH`; success on this host is not a portable
capability claim. `O_TMPFILE` lets an application prepare an unnamed file and
link it later, without adding an overwrite operation.
[link(2)](https://man7.org/linux/man-pages/man2/link.2.html),
[open(2)](https://man7.org/linux/man-pages/man2/open.2.html).

Kernel directory locks serialize a rename while it finds source and target.
Inferring from those documented operation boundaries, they do not give userspace
a lock spanning its earlier verification call and later rename call.
[Kernel directory-locking documentation](https://docs.kernel.org/filesystems/directory-locking.html).
This assessment reviewed that documentation, not current `fs/namei.c` source.

## Native experiment results

The [probe](evidence/linux-force-primitives/probe.py) uses authored bytes in
private temporary directories, actual libc `linkat`/`renameat2`, `flock` and
`F_SETLEASE`, and separately launched Python children with the same effective
UID. The production control patches only the scheduling boundary before the
real rename; a real child changes the source entry. This is deterministic
fault scheduling, not a measurement of uncontrolled race frequency.

All **14 controls completed on each of tmpfs and overlayfs**, with **zero
capability-unavailable outcomes in either run**. These are two filesystem
replays of the same controls, not 28 independent tests.
Observed environment: Linux 6.18.57, x86-64, glibc 2.41, Python
3.12.14, effective UID 1000. Effective UID alone does not establish the absence
of capabilities. The fixture's private directory mode was 0700.

| Experiment | Observed result | What it establishes |
|---|---|---|
| `linkat` from held fd with `AT_EMPTY_PATH`; absent destination | Success; destination device/inode equals the held source | Descriptor selection works on this host. |
| Same call; existing destination | `EEXIST`; prior bytes preserved | It does not implement overwrite. |
| `linkat` through `/proc/self/fd` with `AT_SYMLINK_FOLLOW`; absent/existing destination | Same inode on success; `EEXIST` on collision | The documented alternative changes source selection, not replacement semantics. |
| `renameat2(source_fd, "", ..., 0)` | `ENOENT`; prior target preserved | Empty source does not select that descriptor. |
| Same empty source with `AT_EMPTY_PATH` as a rename flag | `EINVAL`; prior target preserved | That link flag is not a rename capability here. |
| Rename from `/proc/self/fd/<fd>` | `EXDEV`; prior target preserved | Renaming the proc entry does not rename its referent into this filesystem. |
| `RENAME_NOREPLACE` over existing destination | `EEXIST`; source and prior target preserved | Exclusive publication remains distinct from replacement. |
| Same-UID source swap followed by `RENAME_EXCHANGE` | Foreign bytes at destination; prior bytes at source name | Atomic exchange does not bind the source inode. |
| Blind exchange rollback after an authored intervening publication | Later value displaced from destination by the rollback; the bytes survive at the stage name | Rollback can overwrite a subsequent namespace change and cannot undo prior visibility. This intervening event is enacted by the probe parent, not a second child. |
| Held file `flock(LOCK_EX)`; held directory `flock(LOCK_EX)` | Child substitutes source and foreign bytes are renamed to destination | These locks do not exclude this noncooperating writer. |
| Held source write lease | Child substitutes source and foreign bytes are published; the lease remains `F_WRLCK`; no SIGIO observed | This lease did not guard namespace replacement. |
| Private 0700 staging directory | Same-UID child substitutes source successfully | Ordinary private-directory permissions do not separate these processes. |
| Current production `_replace_linux` final boundary | Foreign bytes visible; typed `PT-STR-EXPORT` receipt refusal; intended bytes remain at displaced source | Reconfirms the unresolved product behavior with a real separate writer. |

The rows combine related controls; do not sum table rows as independent tests.
Raw return values, inode identities, errors and source/environment identities are
in [results-final.json](evidence/linux-force-primitives/results-final.json)
(tmpfs) and [results-overlay.json](evidence/linux-force-primitives/results-overlay.json)
(overlayfs). The checked operation/outcome/errno and lease-state fields agree
between these runs; inode identities naturally differ.

Ordinary Linux `flock` semantics are advisory; network filesystem behavior can
differ. File leases document conflicting open/truncate notification and blocking,
not source-name exclusion. Owner permissions depend on filesystem identity,
not the application that created a directory. These documented limits agree
with the local observations; the experiments do not certify other mounts.
[flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html),
[F_SETLEASE](https://man7.org/linux/man-pages/man2/F_SETLEASE.2const.html),
[path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html).

## Reviewable capability recommendation

Keep the current distinction explicit:

| Operation | Supported claim | Unsupported claim |
|---|---|---|
| Linux creation without replacement | Publication selects the held source inode and refuses an existing name, subject to supported primitives and the existing checks | Immutability against later external edits. |
| Current Linux forced replacement | Rooted directory operations, verified anonymous staging, atomic namespace replacement, postcondition validation and receipt refusal on observed substitution | Held-inode selection by the final rename, guaranteed absence of foreign-byte visibility, or rollback/prior-target preservation in the reproduced interval. |
| A future requirement for forced replacement safe against same-principal namespace mutation | Capability unavailable in the examined implementation | Equating ordinary `--force` availability with that stronger guarantee. |

If the stronger property is mandatory, the next implementation must either
establish a different enforceable trust boundary for its source or explicitly
refuse that stronger operation before mutation. A separately privileged or
otherwise isolated publication broker is an architectural candidate, not a
proven fix: source-directory access, source-inode writes, handle ownership,
destination authority and native acceptance would all need a new specification
and independent verification. Mode 0700, more prechecks, locks, leases, or
exchange-and-rollback alone do not supply that boundary.

This follow-up does not silently disable existing overwrite or weaken the
standing acceptance requirement. Replacing `--force` with refusal would change
the supported contract rather than implement compatible replacement; that
choice must be explicit in a future reviewed capability change. Exporting to a
new destination continues to use the existing stronger exclusive-publication
path. Preserve the regression that demonstrates visibility before refusal.

## Verification and reproduction

The existing final-source race regression passed **1 test in 0.54 seconds**:
its expected result is reproduction of the open limitation, not successful
hardening. The primitive probe completed in the recorded command with exit 0.
Whole configured Ruff plus the probe passes. Its first Ruff attempt found only
the `datetime.UTC` spelling rule in the authored probe; the original output and
exact initially executed probe are retained. Independent review then found that
the first result's `filesystem` field described the checkout, while the fixtures
used temporary directories. The final probe records each actual fixture's
filesystem, asserts the specific expected errno values, and uses `ExitStack`
for fixture and lock/signal cleanup. A fresh 14-control replay completed with
zero capability-unavailable outcomes. All fixtures in that replay reported
tmpfs. A separate replay selected a new private temporary root inside the
worktree and recorded overlayfs for all 14 controls, also with no unavailable
outcome. The
initial JSON/log and compressed executed script remain unchanged, explicitly
superseded for the filesystem attribution. No product file was edited to make
a check pass; replays must not be counted as additional distinct controls.

```sh
PYTHONPATH=src python docs/engineering/evidence/linux-force-primitives/probe.py /tmp/new-probe-result.json
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_strings_export_force_ownership.py::test_final_linux_source_race_is_reported_without_deleting_foreign_bytes
python -m ruff check src tests tools docs/engineering/evidence/linux-force-primitives/probe.py
```

The probe requires Linux/glibc `renameat2`, `O_TMPFILE`, procfs and the relevant
filesystem operations; it is diagnostic evidence, not a portable product test.
Its output path must be new. It changes only its own authored temporary files
and process-local locks/signal handler, restoring/closing owned state on exit.
It does not install dependencies, change kernel controls or shared permissions,
execute analyzed targets, or repeat root's running aggregate suite.

To compare another filesystem, select a newly created private directory on that
filesystem through `TMPDIR` for the standalone probe invocation. The observed
per-control `fixture_filesystem` field, rather than the checkout location,
establishes where the operations ran. Remove the empty private root afterward.

Original results, probe source, primary source map, review and hashes are under
`evidence/linux-force-primitives/`. The task ledger should retain the security
finding as open and use this evidence to avoid repeating rejected mechanisms.
