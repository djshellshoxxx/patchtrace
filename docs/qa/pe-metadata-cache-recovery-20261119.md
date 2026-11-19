# Offline PE metadata cache recovery — November 19, 2026

## Scope and provenance

This is a selective recovery of the PE metadata cache and its existing inspection-worker consumer from completion head **`2511301fc26bf0e039f54828959c422b4ff761a2`** (pull request #322). The cache source paths originate in **`bdc929ebd3c6aaa2563c758936beb315a10eeea0`**. The integration starts at **`8c89a488a22a9317aa4fe593f602536f46853944`**, whose runtime baseline is `cb1b508c`. It preserves the candidate's current project lifecycle, stale-result checks, accessible widget identifiers and independent GUI changes.

The new `cache_codec.py` and `cache_store.py` have a production consumer. The owner thread reads only the current pair's exact enrichment rows and passes immutable metadata to the existing artifact inspection worker. That worker still opens and hash-verifies each artifact, computes missing metadata, and evaluates current OS trust separately. The Files view consumes the completed metadata without starting another thread on readers already handed to the GUI. Owner-thread publication checks the current project and oriented pair again. Cache errors leave the live inspection available.

Cache keys include the artifact digest, overview version, PE and resource limits, offline mode and platform fingerprint. Bodies are bounded to 8 MiB, metadata structure to 250,000 nodes and depth 32, strings to 8,192 characters, and selected row metadata to 4 KiB before Python materialization. Strict decoding checks complete frozen record shapes and consistent digest/signature fields. These checks validate retained observations; they do not re-prove cached signature math. Chain and revocation claims are not restored from this cache.

## Demonstrated defects and repairs

Two controls first failed on the unchanged candidate: inspection returned no metadata before handing readers to the GUI, and missing metadata displayed the empty-version message. After the scoped source port, eleven additional controls failed against source behavior: future, negative and textual row revisions; six owner or revision changes immediately before the SQL write; a cache capacity failure that requested history eviction; and artifact-pair admission that consumed beyond its fixed pair. Three further controls demonstrated that a small body could conceal oversized row metadata crossing the SQLite/Python boundary. All negative logs are retained in the [evidence directory](pe-metadata-cache-recovery-20261119/source-and-evidence.json).

The recovery refuses invalid or future revisions, consumes at most three artifact records to validate the pair, and uses a commit-time SQL predicate that protects the existing row's kind, complete guard and revision. Cache publication disables retention fallback; it cannot delete existing history to make room. Body and row-metadata predicates both apply to the actual body SELECT. The bounds concern data returned to Python, not SQLite's internal page reads or cast allocation.

The first inspection regression group also exposed five old announcement-sequence expectations. Metadata now starts on the shared worker, so its existing loading message moves to the start of inspection. The controls now verify that both section-loading events occur once, retries and failure remedies remain visible, repeated refreshes do not duplicate events, and focus remains unchanged. The earlier failing log is preserved separately.

## Verification

The final source is covered by **214 passing checks, with no failures, errors or skips**, in four separate bounded processes. The selected test files are disjoint between these groups.

| Group | Result | Pytest duration | Coverage |
| --- | --- | --- | --- |
| Cache | 75 passed | 6.22 s | Real store/reopen, corruption, exact identity, revision and write-time ownership, capacity refusal, metadata bounds, artifact verification, cancellation, current worker and GUI handoff |
| Storage | 20 passed | 1.98 s | Existing enrichment storage, extension compatibility, backup, retention and capacity behavior for existing publishers |
| Inspection | 81 passed | 17.53 s | Existing signing view, artifact integration, stale failures, loading/completion events, retry behavior, keyboard focus and GUI host seams |
| Metadata and CLI | 38 passed | 1.89 s | Existing metadata comparison, cache port, inspect CLI and trust-mode refusal behavior |

Scoped Ruff and `git diff --check` passed. The [source-and-evidence manifest](pe-metadata-cache-recovery-20261119/source-and-evidence.json) records SHA-256 hashes for the exact source, tests, specification, module index and retained logs/XML. Earlier intermediate passes overlap these final checks and are not added to their count.

An attempted broad `test_pe_*.py` regression run was killed by the environment before pytest produced a summary or XML. Its partial progress log is retained and receives no completion credit. No broad-pass or whole-repository claim follows from this receipt.

## Qualification limits

The evidence uses synthetic PE fixtures and offscreen Qt. It does not qualify real Windows catalog trust, online revocation, a native analysis backend, packaged application behavior or assistive-technology behavior. Cache storage remains outside pipeline-generation retention; publication can fail when the existing project cap is full. The SQL owner predicate protects replacement of an existing cache row; it does not turn the entire project store into a transactionally isolated snapshot against arbitrary concurrent writers.

Independent read review of immutable `e59e9fce` found no scoped blocker in row
bounds, owner/revision predicates, retention refusal or the worker/GUI handoff;
it adds no test count. Integrated source `6d0f1509` passed 85 cache, Qt and current
project retry/lifecycle controls in 14.55 s. Root log/XML are retained separately
under `docs/consolidation/evidence/integrated-pe-cache.*`.
