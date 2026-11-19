# Isolated UTF-8 dependency evidence — 2026-11-18

## Source and bounded result

Exact source **6dea194adf52ae0257d94c1604707a056d11c92c** passes **167 checks**, zero failures/errors/skips,
in the retained 1.20-second portable pytest run. All **41 loaded project/tool
modules** match the canonical source; no drift or prohibited execution occurred.
The final exact-source full normal Ruff check over `src tests tools` and source
diff whitespace check pass. Independent root review and corrected hosted
Windows acceptance remain separate gates.

| Role | Commit |
|---|---|
| Approved implementation baseline | `207eea9d4e125ac1d371139d4db803ddbc2b4c8a` |
| Specification and failing controls | `2eeb5b4a35b45d61993e6f1f484ca473a3cb5ce5` |
| Production correction | `6dea194adf52ae0257d94c1604707a056d11c92c` |

The `codex/dependency-utf8-20261118` branch reuses `security-residual-qa`.
The completed core branch remains at `b9041430042d3ba6308c23942d4f10949b7487c0`.
Only `tools/dependency_security.py` changes in production: one immutable
`PYTHON_OPTIONS = ('-I', '-X', 'utf8')` tuple replaces the literal isolated flag
at all 14 direct Python invocation sites. The existing qualification spec and
one focused test module changed first. No new specification registry entry or
production module is introduced.

## Actual hosted failure and primary semantics

The original verified runtime artifact 14470840684 and packaging artifact
14471515532 bind hosted source `a94495abb6117400c138eaaa0127d260c3010094`,
run 44395588481, attempt 1, Windows CPython 3.12.10. Both actual
`python -I -m pip inspect --local` receipts exit 2, without timeout/output-limit
or launcher error, and preserve the same Rich-to-CP1252 UnicodeEncodeError for
U+1F44B. The complete partial stdout, original stderr, process record, context
and interpreter identity are included; source artifact ZIP hashes are retained.
The shared stderr SHA-256 is
`9c8d5bab13d580f90abd73417ffd68363ec7a855ff703a1e5f8492156c1c072f`.

The hosted Git object is unavailable in the local repository. No fetch was
performed and no local/hosted source-byte equality is claimed. The diagnosed
local tool at `3e0d4695b6e2b94ba1eddeba3a2a31b78fe9f657` constructs the same
observed prefix; its tool, release guard and spec bytes equal the approved
implementation baseline. Initial unsuccessful hosted-object lookups remain
in the provenance receipts.

Official [Python 3.12 command-line documentation](https://docs.python.org/3.12/using/cmdline.html)
states that isolated mode ignores PYTHON environment settings and that explicit
`-X utf8` enables UTF-8 mode. The [mode documentation](https://docs.python.org/3.12/library/os.html#python-utf-8-mode)
documents UTF-8 standard streams and other text defaults. These live manuals
identified as 3.12.16 when read; exact archived 3.12.10 pages/tagged C source
were unavailable and are not claimed reviewed. Local 3.12.14 help and direct
interpreter observations are retained. This version distinction remains
separate from the real hosted 3.12.10 traceback.

The parent launcher already removes PYTHON variables and captures binary
output. Changing its decoding cannot fix a producer failing before it emits
the character. The explicit option precedes `-m`/`-c` and retains isolated mode.
Environment-only UTF-8 configuration cannot provide this isolated contract.

## Contract and preservation controls

The canonical prefix covers environment preparation, pinned bootstrap,
installers, identity, inventory, dependency checks and scanners. A pure
before/after comparison checks all 22 runtime, 22 packaging and 11 static
commands: command keys/order are equal and removing only `-X utf8` gives the
exact old argv. All other module AST nodes are unchanged. These command plans
are inspected without executing any installer/scanner.

Exact process-receipt validation already reconstructs those canonical commands;
it now refuses receipts with missing/disabled flags. Raw output, its hashes,
limits, timeouts, source guards, environment filtering, pins, rule selection,
bootstrap/closure/advisory validation and failure interpretation are unchanged.
The interpreter option also affects its documented text defaults inside these
isolated subprocesses. No historical failed receipt is relabeled as successful.

The new eight repository controls cover all three profiles, Unicode raw bytes,
actual startup mode/isolation, unwanted PYTHON settings, altered/missing argv,
and retained nonzero encoding failure. The unchanged five-node independent
probe also passes; its SHA-256 is
`08fc908b2daa0b869f36a8e836f73e2285a90ad48a0bbb7681e5f8d1dcabbea3`.

## Chronology: original failures remain evidence

| Run | Result and scope |
|---|---|
| Initial diagnostic fixture | Empty selected dependencies correctly refused before any child; runner/log retained |
| Second diagnostic harness | Duplicate `-X` override assumption failed; both actually executed children and raw receipts retained |
| Corrected diagnostic harness | Actual current prefix fails the authored CP1252 model; one explicit flag passes |
| Original external probe at local 3e0d4695 | 4 failed / 1 positive; exact tool-file pin, without a full imported-module manifest |
| Committed spec/test-first 2eeb5b4a | 9 failed / 4 positive; 41 canonical imports, no drift/denied attempts |
| First uncommitted source candidate | 13 passed; complete tool snapshot equals the final source |
| Clean committed 6dea194a affected gate | 167 passed / 0 skips; 41 canonical imports, no drift/denied attempts |

Counts overlap and are not additive. The conditional CP1252 producer is an
**authored simulation**: only when explicit mode is absent does it force
CP1252; the corrected branch keeps the real interpreter startup stream.
It does not execute pip/Rich or reproduce native Windows. The real hosted
receipt supplies the Windows failure evidence. The preliminary unexecuted
`current-command-plans.json` was regenerated by diagnostic v3; original
scripts/logs and every actually executed child receipt remain unchanged.

The exact gate includes existing dependency-security/bootstrap validators.
Its audit recorder allows 12 authored Python `-c` children and 68 local Git
children, with zero socket or disallowed process attempts. It runs no pip,
installer, dependency audit, native helper, target or remote mutation.

## Reproduction and limits

`affected.command.json` records exact cwd, interpreter, environment, test paths,
test hashes and argv. `run_gate.py` binds the source and records loaded module
paths/Git blobs/SHA-256; it refuses overwrite of an existing observation label.
Use an available fresh label when replaying. The full command uses absolute
PYTHONPATH entries for this checkout's `src` and root, because the shared
environment's editable installation points elsewhere.

`source-chain.json` retains 56 canonical source/spec/test/config snapshots,
commits/parents/trees and file hashes. Patches, original JUnit counts, original
probe hash, candidate/source equality, test equality and unchanged prior files
are independently checkable in `validation.json` and its neighboring receipts.

These controls establish the option/receipt/byte-preservation boundary on the
local POSIX interpreter. A corrected hosted Windows install/inspection/closure/
audit has not run. No native acceptance, scan cleanliness, dependency closure,
security pass, frozen-corpus outcome or release readiness follows from this
portable repair. Existing strict findings and independent root review remain.

## Sealed packet

The [archive](windows-dependency-encoding-20261118.zip) contains 168 verified payloads
(1,544,977 uncompressed bytes; 521,904 ZIP bytes).
Archive SHA-256: `45625ae4a79d862973338c41174cfeeb435ef4f8a22e985a68b09c91e1ef1fcb`.
The [manifest](windows-dependency-encoding-20261118.manifest.json) records each payload's hash and size.
The external original receipts remain in `qa/windows-dependency-encoding`.
