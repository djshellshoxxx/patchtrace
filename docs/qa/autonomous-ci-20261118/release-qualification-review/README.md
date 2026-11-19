# Independent-review repair — release qualification

Implementation: **05176698d0265e4e1e577e06fa38bb52d7bbcf43**.
Predecessors: implementation 0bb63363ed675266ec4572a85ee0c0861aa714b7 and original
QA checkpoint 8d090f9722ba9b412c89c9877729a77f35afeca9.
The earlier implementation must not be promoted without this repair.

## Findings reproduced and repaired

The independent reviewer supplied eleven authored controls. Seven failed
against 0bb63363; four positive controls passed. The original test source, log
and JUnit are copied byte-for-byte into this new packet, leaving the reviewer
directory and original committed QA packet unchanged.

1. Git replacement objects, assume-unchanged and skip-worktree could mask
   modified tracked source from the earlier diff-based check.
2. JSON exponent overflow produced positive/negative infinity even though
   literal NaN and Infinity tokens were already refused. An unused native
   metadata field with that value could still qualify the aggregate.
3. The two platform artifact names could share a single artifact ID, causing
   the same archive to supply both native results.

The specification clarification was written before the implementation changes.
Source verification now uses the canonical, replacement-disabled commit tree
and hashes actual file/link bytes in Git blob format. It does not rely on index
visibility, cached file statistics, clean filters or diff drivers. File sizes,
types, executable modes on the Linux publisher, identities and changes during
reads are checked. Unsupported entries, linked/reparse parents, oversized trees
or changing source fail closed. The existing literal commit hold is read from
canonical commit metadata before those content reads.

The decoder now checks every parsed float for finiteness, including nested
unused fields. Native artifact IDs must be unique across the whole bounded
artifact list. These are shared-checker changes; no publisher bypass or scanner
lane was added.

## Authored verification

Additional owned controls cover replacement objects, index flags, a restored
mtime/size case, a clean-filter mask, exponent overflow and duplicate artifact
identity. The initial combined focused check recorded **14 failures / 1 pass**;
the passing stat-cache control already refused its modified file. After the
repair, the unchanged reviewer controls and owned guard tests reported
**90 passes**.

The affected workflow/release suite plus all eleven original reviewer controls
reported **469 passes / 3 existing expected failures**, both before commit and
in the exact-source rerun of 05176698. The expected failures remain CODEX-1,
CODEX-5 and CODEX-6. Normal Ruff over src, tests and tools passes.

The exact-source command receipt records the SHA/tree, executable, arguments,
absolute PYTHONPATH, source hashes, original reviewer-test hash and exit code.
The original reviewer tests are included in the command; they were not weakened
or edited. This is local authored evidence. It does not establish a hosted
qualification, dependency safety, real native-backend acceptance or publication.

## Remaining gates

Independent re-review of 05176698 is required. Final combined full-suite and
canonical Linux/Windows native gates remain necessary. Dependency/security scan
qualification is still absent. Windows BinDiff's disconnected native check
still reports blocked. The original 78 Ruff security findings remain untriaged
in the predecessor packet. No release, tag, remote mutation or dispatch occurred.

The source guard's canonical-byte rule intentionally refuses a filtered checkout
whose actual bytes differ from the commit; both publisher jobs run on Linux.
No Windows application functionality or native gate was disabled by this repair.

## Packet

The manifest lists SHA-256 and size for each archived member. New receipts are
stored separately from the frozen original packet. The passing exact-source
rerun is a repair receipt, not a replacement for the original failures.
