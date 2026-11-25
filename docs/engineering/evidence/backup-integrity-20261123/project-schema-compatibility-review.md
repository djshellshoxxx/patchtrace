# Project schema and historical backup compatibility

Aggregate `cca6ce4a0d20725e8a421421cd2e0fddb8313bf7`, tree `bcec5a89a5046652f02a9e5c758a95212bf28cbf`. The project database has one supported on-disk version, SQLite user_version 1, with version 1 records. The earliest persisted implementation at `8b5ae1e912204bafa422e42db70606a8abbad66f` introduced that version. The reachable history of the application schema declaration shows no other value. A zero-byte interrupted creation candidate is a creation-retry case. No historical format conversion is required. The architecture calls for backups and explicit ordered transforms if a later release introduces migrations. [Architecture](https://github.com/djshellshoxxx/PatchTrace/blob/cca6ce4a0d20725e8a421421cd2e0fddb8313bf7/docs/specs/architecture.md#L37-L39) · [Project data handling](https://github.com/djshellshoxxx/PatchTrace/blob/cca6ce4a0d20725e8a421421cd2e0fddb8313bf7/README.md#L295-L301) · [Record validation](https://github.com/djshellshoxxx/PatchTrace/blob/cca6ce4a0d20725e8a421421cd2e0fddb8313bf7/src/patchtrace/models.py#L20-L22)

## Historical projects and backups

The earliest implementation generated a two-artifact project with no runs and a populated sample project. The aggregate ran its normal open, backup and reopen operations on copies. A separate run used the earliest implementation's backup operation, then opened both historical backups with the aggregate. Every field present in each old model retained its value. All current snapshots and history rows, project IDs, revisions, and artifact/run file contents matched across restores. Opening either source project preserved the database and companion file bytes. Both source lock files were refreshed.

| Earliest-writer fixture | Historical state | Aggregate result |
|---|---|---|
| Two artifacts | Revision 0, one history row, two companion files | Source and both backup paths reopened |
| Populated synthetic sample | Revision 1, five history rows, three companion files, one run, four matches, one annotation and one interpretation | Source and both backup paths reopened |

## Rejected files

The aggregate refused closed SQLite projects marked user_version 0, 2 or 99. It also refused a valid-hash snapshot with JSON version 2, and one with an undeclared key. All five produced PT-SCHEMA, preserved database and companion file bytes, and updated only the project lock file. The reader opens SQLite read/write and acquires the persistent lock before its version check. [Database open](https://github.com/djshellshoxxx/PatchTrace/blob/cca6ce4a0d20725e8a421421cd2e0fddb8313bf7/src/patchtrace/persistence.py#L437-L501)

One separate interruption test committed user_version 2 to a WAL and terminated the SQLite writer before an orderly close. The aggregate refused the file with PT-SCHEMA. SQLite checkpointed the pending commit into the database and removed the WAL and shared-memory sidecars. The logical version remained 2. This limits physical byte-preservation claims for rejected projects. A successful v1 open also has documented write effects when recovering queued/running work or maintaining eligible duplicate raw files. [Recovery](https://github.com/djshellshoxxx/PatchTrace/blob/cca6ce4a0d20725e8a421421cd2e0fddb8313bf7/src/patchtrace/persistence.py#L664-L688) · [Open maintenance](https://github.com/djshellshoxxx/PatchTrace/blob/cca6ce4a0d20725e8a421421cd2e0fddb8313bf7/src/patchtrace/service.py#L109-L121)

## Test evidence

| Platform and source | Evidence from the eight selected storage test modules |
|---|---|
| Linux, exact aggregate, Python 3.12.14 / SQLite 3.53.1 | 97 passed, including schema and create admission, interrupted writes, post-commit reconciliation, history, backup and writer-lock cases. |
| Historical Windows baseline `ea16019601486c831941f9bc1a7ba5862a170317` | 67 passed in the six modules then present, including both future snapshot cases and interrupted creation and recovery. [Job](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193/job/136892880665) · [Artifact](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44919714193/artifacts/14715790556) |
| Historical Windows PR #360 head `6ffe819e71d48793f8207bd64d7480fbc03e2ef5`, checked merge `8135def48fe3fd1b651928f6c6144e08f047619a` | 89 passed, four failed, four skipped. Both future snapshot and all 15 post-commit tests passed. Four failures involved creation/rollback, including Ctrl+C cleanup, atomic initialization, owned-file removal, and retaining the cleanup lock. [Job](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45280338559/job/138062824857) · [Artifact](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45280338559/artifacts/14872874311) |

These runs cover the one supported project schema with two earliest-writer data sets and ordinary interrupted storage scenarios on the aggregate. The exact-aggregate historical fixture replay was Linux-only. The historical Windows archives were CRC-checked and their QA JUnit files parsed directly. Neither archive establishes native results for the aggregate. Optional feature-specific databases, every possible v1 data shape, and whole-release acceptance are outside this review.
