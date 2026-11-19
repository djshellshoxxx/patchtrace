# Exclusive backup and runtime directory publication

## Result and source

The reproduced POSIX destination-ownership defect is repaired in both public
paths. Complete project backups and verified offline runtime installations now
share a native operation that refuses an existing destination, including a
foreign empty directory appearing immediately before publication. Independent
review accepted the bounded repair. Native Windows acceptance remains pending.

| Checkpoint | Exact commit |
|---|---|
| Baseline continuation | `3faf436a3b11c69220641a167cf424e7f4060839` |
| Initial specification and failing controls | `b781aae7f0e377857c73b8806ad4c52aa6e52e5d` |
| Initial native no-replacement implementation | `c9290ce82b3f1f2463c56c69f5853cb795f70f2c` |
| Missing specification registrations | `6bfe678e07a74cbd10305bc82e452a5a4a1e8cf5` |
| Independent-review reparse regression/specification | `038707c994070dab6c384a5d473729e7ef6ea088` |
| Accepted implementation | `843dfec72dcb5751e53d01f217263771dd6d65d2` |
| Accepted tree | `96e12cdf58bbf9dc740bde29c475071b181395f8` |

The production change is confined to the shared `directory_publication.py` and
the two existing private publisher aliases in `persistence.py` and
`offline_bundle.py`. SQLite schemas, copied project sidecars, verified archive
validation, consent, locks and existing caller error envelopes are unchanged.
The separate immutable-file publication API is not modified.

## Reproduction and repair

The historical `audit/core` helper was retained in current source; it was not a
missing branch port. Both copies created the public destination as an empty
directory, then used an overwriting POSIX rename. If another owner replaced the
reservation, publication removed that owner's empty directory. If the rename
instead failed, cleanup removed the foreign replacement. A held directory file
descriptor proved that its inode lost its final pathname link. The original
project database/archive bytes remained unchanged.

The coordinator exercised actual `ProjectService.backup` and
`install_offline_bundle`, using tiny authored runtime payloads that were never
executed: four preservation failures and two ordinary positive controls. The
original probes and red logs are retained byte-for-byte. Their `os.rename`
interception belongs to the removed algorithm and is not relabeled a passing
control for a different primitive.

Linux now calls libc `renameat2` with `RENAME_NOREPLACE`; Windows uses Python's
non-replacing `os.rename`. The helper creates and removes no destination entry.
Missing symbols/unsupported systems and filesystem, permission or cross-device
errors propagate without a copy/replace fallback. Paths must be distinct
absolute siblings; NUL and nonordinary source entries are refused before native
publication. The callers continue cleaning their own private stage.

Independent review found an additional input-refusal gap in the first candidate:
Windows junction metadata can retain directory mode. Two portable controls
showed that a source marked as a reparse point reached the native seam. The
follow-up first added failing controls and the explicit contract, then retained
the `lstat` result and rejected the reparse attribute regardless of tag. A native
Windows junction test is included, with no Linux execution credit.

## Exact verification and preserved failures

| Receipt | Actual result | Meaning |
|---|---|---|
| Both original public-path probes at `3faf436a` | 4 failed / 2 passed | Original ownership defect; no setup errors |
| Initial specification controls on unchanged production | 24 failed / 10 passed | Two public-placeholder failures; 22 new-API controls fail because the module does not exist yet |
| Initial committed affected gate at `c9290ce8` | 209 passed, 2.51 s | Backup, persistence, runtime install and neighboring immutable backup behavior |
| Independent initial review at `c9290ce8` | 49 passed / 3 failed / 3 fixture errors | Includes 34 authored positives; two reparse failures, one unavailable Unix socket and three reviewer fixture setup errors are preserved |
| Corrected independent controls at `c9290ce8` | 18 passed / 2 failed / 1 unavailable Unix-socket skip | Isolates the two reparse refusal failures; assertions preserved |
| Coordinator reparse regressions before repair | 34 passed / 2 failed / 1 native-Windows skip | Both metadata controls reach the unguarded native seam |
| Final coordinator affected gate at `843dfec7` | **319 passed / 1 native-Windows skip**, 2.57 s | Twelve files, including all specification registrations; no foreign source imports |
| Independent unchanged controls plus authored module at `843dfec7` | **56 passed / 2 explicit skips**, 0.53 s | Twenty independent controls pass; native junction and local Unix socket remain unverified |

The coordinator's final command is `python -m pytest -q -ra -p
full_batch_receipt` with the exact twelve file arguments retained in
`affected-843dfec7-command.json`. The interpreter is Python 3.12.14 at
`/workspace/scratch/3a6632a6e5ff/venv/bin/python`; Qt is offscreen and absolute
`PYTHONPATH` entries point to the exact checkout. The read-only receipt plugin
records all collected node IDs and actual imported source paths/digests.
Normal Ruff over `src tests tools` passed. The duplicate-ZIP-member warning is
the existing intentional rejection fixture, not an unexpected installer input.

The independent controls invoke the native Linux primitive beneath both public
paths, preserve held-FD identity on collision and native error, verify ordinary
complete publication, exercise existing destination kinds and six concurrent
publishers, and retain errno/invalid-source refusal. The coordinator also tests
Unicode payloads, all existing destination leaf kinds, two competing publishers,
no public placeholder, invalid paths, unsupported primitives and Windows dispatch.
Mocked dispatch/metadata controls do not establish native Windows behavior.

The existing registry test also exposed the earlier missing dependency/security
specification registration plus the new directory contract. Both rows were added;
the original 2-failure/106-positive receipt and 108-positive registry correction
are retained. No test or scanner policy was relaxed.

## Ownership and platform limits

The caller must retain control of the stable parent and private staging directory
through publication and cleanup. This repair supplies atomic refusal for the
destination leaf; it does not establish rooted-handle protection against hostile
parent/source replacement, durability across power loss, or transactional remote
filesystems. Unsupported native primitives fail closed. Existing runtime source
authenticity/consent requirements remain necessary; a bundle's self-hash is not
publisher authentication.

No target executable, live provider, Windows native runtime, frozen package,
release, tag or deployment was run by this slice. Full integrated and hosted
acceptance remain separate requirements. The original backup/runtime findings
are bounded POSIX empty-directory ownership observations, not evidence of source
project corruption or a native Windows exploit.

## Evidence packet

The adjacent manifest binds all raw commands, logs, JUnit, original probes,
independent review packets and immutable source snapshots. Every archive member
was reopened, CRC-checked, checked for unique names, and verified by size/SHA-256.
The independent probe stays at SHA-256
`821adaf139289250acbade0ff36b0a46bea741c2e6c38062739f9df0e1d45da0`.

Archive: `directory-publication-20261118.evidence.zip`; **61 payloads**, **206438 bytes**, SHA-256 **`1c4a6d4e5aaa559801e5bef0855593506b7ca891c4c8ebe228a9b5ea6ced9a07`**.
