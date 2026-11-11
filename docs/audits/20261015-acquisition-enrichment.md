# Audit: acquisition, enrichment network/cache and maintenance (2026-10-15)

Read-only audit. No file under `src/` or `tests/` was changed. Base: `origin/main` at `21a005e`
(fast-forwarded 2026-10-15). Every Medium and Low entry below has a repro that ran offline (loopback
socket server or fake opener); the scripts live outside the repo in the session scratchpad
`acq-audit/` (`r1_transport.py` ... `r9_journal.py`). Existing audit `docs/audits/20261014-C-acquisition-gui.md`
was read first; its findings are marked **known** and are not repeated.

## Findings

| ID | Severity | File:line | Summary | Repro |
|---|---|---|---|---|
| ACQ-1 | Medium | `acquisition/transport.py:299-300`; `enrichment/intelligence.py:384` | Malformed redirect `Location` raises a raw `ValueError` from `urljoin`; in `fetch_all` it aborts the whole batch | r1, r7(a) |
| ACQ-2 | Medium | `enrichment/intelligence.py:404-421` (read at 408) | Total deadline not enforced during a blocking body read; a slow-drip server holds the call open past its budget (acquisition twin of known C-01) | r4 |
| ACQ-3 | Medium | `acquisition/transport.py:96-108, 169-175` | `http.client.BadStatusLine` and other `HTTPException`s escape the transport untyped | r2 |
| ACQ-4 | Medium | `acquisition/winbindex.py:94-95, 154` | A lone `\ud800` escape in a Winbindex record raises `UnicodeEncodeError` out of `parse` | r3 |
| ACQ-5 | Medium | `acquisition/quarantine.py:56-61`; `cli.py:604-605`; `ui.py:663, 669, 691` | Staging cleanup raises on a locked file (Windows AV) and masks a successful acquisition; no sweep of crashed staging | r7(b) |
| ACQ-6 | Medium | `enrichment/cache.py:335-336`; `contracts.py` `CacheManifest.size` | Manifest with an absurd `size` makes `DerivedCache.get` raise `MemoryError`; the stage fails on every run | r5(a) |
| ACQ-7 | Medium | `enrichment/cache.py:344-361, 417-419, 524-525, 612-660` | Quarantine directory is outside the byte budget and is never pruned | r5(b) |
| ACQ-8 | Medium | `verified_backup.py:162-163` (`_remember` at 105-109) | Verdict is fingerprinted after the check, so a backup swapped in between is trusted; weakens "no backup, no deletion" | r8 |
| ACQ-9 | Low | `enrichment/cache.py:195-202, 262-297, 527-540` | An empty or torn lock/lease file is never reclaimed: the key is uncacheable and an entry is pinned | r5(c) |
| ACQ-10 | Low | `enrichment/cve.py:147-170, 328-335`; `contracts.py:197-210` | Imported CVE snapshots keep a caller-chosen `snapshot_id` and an unparsed `retrieved_at`; the error surfaces later without naming the snapshot | r6 |
| ACQ-11 | Low | `raw_cleanup.py:150-153` | A torn journal line makes `restore_raw_duplicates` fail with an untyped `JSONDecodeError` after partial work | r9 |
| ACQ-12 | Low | `docs/specs/acquisition.md` §4.5; `acquisition/quarantine.py:19, 81-84` | Spec says identification uses `ingestion.inspect_artifact`; code uses `validate_pe` | grep |
| ACQ-13 | Low | `cli.py:424`; `enrichment/intelligence.py:97-99, 318-319` | Enrichment URL-level consent is built from the same plan it authorises, so the check cannot fail (same class as known C-14) | code read |

Counts: High 0, Medium 8, Low 5.

## Finding details

### ACQ-1 Medium: malformed redirect Location escapes as a raw ValueError

- Where: `acquisition/transport.py:299-300` (`urljoin` then `_check`, outside any `try`); `enrichment/intelligence.py:384-385` (same pattern, inside `_attempt`). `fetch_all` (`intelligence.py:298-302`) continues only on `EnrichmentError`.
- Evidence: `urllib.parse.urljoin('https://msdl.microsoft.com/x', 'https://[x')` raises `ValueError: Invalid IPv6 URL`. The acquisition download and the enrichment fetch both let it escape. In the CLI enrichment path (`cli.py:424`, non-fail-fast) one hostile response discards the successful results of every other CVE in the batch, because the exception is not an `EnrichmentError`.
- Repro: `python3 -I r1_transport.py` prints `location-bad-ipv6 RAW ValueError Invalid IPv6 URL`; `r7_redirect_and_staging.py` part (a) prints `RAW ValueError`.
- Expected: `PT-ACQ-NETWORK` / `PT-ENRICH-NETWORK` refusal without echoing the URL.
- Fix: wrap `urljoin` and `urlsplit` of the target in `try/except ValueError` and raise the typed refusal. Test: a fake opener returning 302 with `Location: https://[x`, for both modules, asserting a typed error and, for `fetch_all`, that the other CVE still returns.

### ACQ-2 Medium: total deadline not enforced during a blocking body read

- Where: `enrichment/intelligence.py:404-405` (deadline checked only before each chunk), `:408` (`interruptible(partial(response.read, size), cancel)`); `netutil.py:34-35` (no `cancel` means the call runs inline with no bound). Acquisition twin: `acquisition/transport.py:189-195` (`_read`), root cause of known C-01.
- Evidence: `http.client` `read(65536)` on a non-chunked body blocks until 64 KiB or EOF. A server sending one byte every 2 s never trips the 10 s per-operation socket timeout.
- Repro: `python3 -I r4_slowdrip.py` prints `elapsed 20.0s against a 5s total deadline` (the 30 s product budget scales the same way). Impact by reading, not reproduced: with `cancel` set the reader thread is abandoned, and `netutil.MAX_ABANDONED = 4` then makes every later provider fetch fail with `previous requests still closing` for the rest of the process, because a dripping server never lets those threads finish.
- Fix: enforce the deadline inside the read, either with a per-`recv` socket timeout set to the remaining budget (read via `read1`/`readinto` in small pieces) or with a timer that closes the response at the deadline so the blocked read raises. Regression test: loopback drip server with a monkeypatched small `TOTAL_TIMEOUT`, asserting return within 1.5x the budget. Apply the same fix to acquisition `_read`.

### ACQ-3 Medium: HTTP protocol errors escape the acquisition transport untyped

- Where: `acquisition/transport.py:96-108` (`urllib_open` maps only `HTTPError` and `URLError`); `:169-175` (`_open` maps only `TimeoutError` and `OSError`).
- Evidence: a server answering with a non-HTTP status line raises `http.client.BadStatusLine` straight out of `Transport._open`. `enrichment/intelligence.py:376` and `:416` already catch `http.client.HTTPException`, so the two transports disagree. The raw message (which carries server bytes) reaches the GUI status and log.
- Repro: `python3 -I r2_badstatus.py` prints `RAW http.client BadStatusLine NOT-HTTP garbage`.
- Fix: in `_open` also catch `http.client.HTTPException` and raise `AcquisitionError('PT-ACQ-NETWORK', 'connection failed', recoverable=True)`. Test with a socket server that sends garbage.

### ACQ-4 Medium: a lone surrogate in a Winbindex record crashes parsing

- Where: `acquisition/winbindex.py:94-95` (`_canonical` encodes with `ensure_ascii=False` and then UTF-8), called at `:154`. `strict_json` (`:77-82`) accepts the `\ud800` escape, which is legal JSON.
- Evidence: the escape survives strict parsing and fails only at `.encode('utf-8')`. `enrichment/cve.py:103-128` already rejects unpaired surrogates in its strict parser, so this is the acquisition outlier. The whole metadata record becomes unusable, and the CLI (`_candidates`) and GUI do not map the error.
- Repro: `python3 -I r3_winbindex.py` prints `clean candidates 1` and `lone-surrogate RAW UnicodeEncodeError`.
- Fix: reject unpaired surrogates in `strict_json` (reuse the `cve.py` check) as `PT-ACQ-PROVIDER`. Add the hostile-input test required by E4 section 2.5.

### ACQ-5 Medium: staging cleanup can raise, masking a successful acquisition

- Where: `acquisition/quarantine.py:56-61` (`remove_staging`; the `onexc` handler re-raises when the retried unlink fails). Callers: `cli.py:604-605` (`finally`, after `promote` has already created the project), `ui.py:663`, `ui.py:669`, `ui.py:691` (`finally` in `complete_download`).
- Evidence: a sharing violation on a file in staging escapes `remove_staging` (repro below). In the CLI the exception replaces the success result, so the user sees a failure while the project exists and a retry is refused. In the GUI it escapes the slot and skips the "Project created" log line. Antivirus and indexers commonly hold handles on freshly written 1 GiB inputs.
- Retention gap: `create_staging` is the only code that makes `patchtrace-acquire-*` directories and nothing sweeps them, so a crash leaves up to 2 GiB of PE files in the user temp directory.
- Repro: `python3 -I r7_redirect_and_staging.py` part (b) prints `remove_staging RAISES OSError staging left behind: True` (unlink patched to fail on `*.sys`).
- Fix: cleanup never raises. Retry with backoff, then record the leftover path as a warning. Add a sweep of `patchtrace-acquire-*` older than a bound, honouring a live lock. Test: patched unlink raising `PermissionError`, asserting no exception and a warning.

### ACQ-6 Medium: an oversized manifest size crashes the derived-cache read

- Where: `enrichment/cache.py:335-336` (`handle.read(manifest.size + 1)`, no bound for derived stages); `enrichment/contracts.py` `CacheManifest.size: int = Field(ge=0)` (no upper bound).
- Evidence: `MemoryError` escapes `DerivedCache.get`. `_load` converts only `OSError` and `_Corrupt`, and `pipeline._cached` (`pipeline.py:168-172`) catches only `EnrichmentError`. The entry is not quarantined, so the stage fails on every run until the user deletes the cache directory.
- Repro: `python3 -I r5_cache.py` part (a) prints `RAW MemoryError`.
- Fix: in `_load`, treat `manifest.size > config.budget_bytes` (and `> raw_max_bytes` for raw) as `_Corrupt('size bound')` before any read, and read in bounded pieces. Test: manifest with `size = 2**40` returns a miss and quarantines the entry.

### ACQ-7 Medium: quarantined cache entries grow outside the budget

- Where: `enrichment/cache.py:344-361` (`_quarantine`) and `:417-419` (`_admit`) move entries to `v1/quarantine/`. `_usage` (`:524-525`) and `prune` (`:612-660`) walk only `_entries()`, which skips `quarantine` (`_RESERVED`, `:46`). `status()` counts quarantined files but nothing bounds them.
- Evidence: a corrupt entry moved to quarantine survives `prune(0)`. Spec section 9 sets a 20 GiB budget and says corrupt entries move to quarantine; the quarantine is outside that budget.
- Repro: `python3 -I r5_cache.py` part (b) prints `quarantined files 1` before and after `prune(0)` (`removed: 0`).
- Fix: count quarantine bytes in `_usage`, and let `prune` evict quarantined entries oldest first before live ones. Test: corrupt entries plus `prune(0)` leaves the quarantine within budget.

### ACQ-8 Medium: a verdict can be attached to a different backup file (TOCTOU)

- Where: `verified_backup.py:162-163` (`_verify` runs first, then `_remember` takes the fingerprint); `:112-122` (`_cached` trusts a verdict while `(size, mtime_ns)` match).
- Evidence: the verdict is computed on file A. If another writer replaces the file with B of the same size and mtime before `_remember`, the fingerprint of B is stored with the verdict of A. `find_verified_backup` then returns B, and `ensure_verified_backup` (`:214-233`) hands it to the retention path, which deletes rows on the strength of "a trusted backup exists" (`storage.py` `_ensure_retention_backup`, `_delete`).
- Narrow: needs a concurrent writer in the project's `backups/` directory, so it is local-only. The invariant it breaks is the one the module exists to keep.
- Repro: `python3 -I r8_backup_toctou.py` prints `trusted candidate: ...` and `file on disk now passes quick_check: False`.
- Fix: take the fingerprint before `_verify`, store that fingerprint, and re-stat after verification (discard on mismatch). Test: the swap hook used in `r8`.

### ACQ-9 Low: an unreadable lock or lease file blocks its key permanently

- Where: `enrichment/cache.py:262-282` (`_try_lock` creates the file with `O_EXCL` and writes the owner JSON afterwards); `:195-198` (`_owner_dead` returns False for an unreadable owner); `:284-297` (`_recover`); `:527-540` (`_leased`).
- Evidence: an empty `<key>.lock` makes `put` return False, `verify` and `prune` reclaim nothing, and the lock stays. A lease in the same state makes `_leased` True forever, so `prune` skips the entry and the budget stays full. The state is reachable after a crash between the create and the write.
- Impact: silent cache misses and a pinned budget; no wrong result is served.
- Repro: `python3 -I r5_cache.py` part (c) prints `put -> False`, `verify` with zero recovered, `put again -> False lock still present True`.
- Fix: publish the owner file atomically (write a temp file, then `os.link`/rename to the lock name), so a visible lock always has an owner. Keep "never by age", and have `verify` report unreadable locks as a warning. Test: empty lock, then `put` succeeds after `verify`.

### ACQ-10 Low: imported CVE snapshots are not checked for identity or timestamp

- Where: `enrichment/cve.py:147-170` (`parse_snapshots` builds `CveSnapshot` from the file); `enrichment/contracts.py:197-210` (`snapshot_id` and `retrieved_at` have no validator); `cve.py:328-335` (`_timestamp`, reached only later); `cve.py:422` (`select_latest`).
- Evidence: `snapshot_id` is caller-chosen. Spec section 8 says the identity pins provider digests, which `normalize` does but import does not check. A bad `retrieved_at` is accepted and fails later in `select_latest` with `PT-ENRICH-INPUT: timestamp must be ISO 8601 with a timezone`, without naming the snapshot. The file is labelled unverified, so the impact is misleading errors and a forgeable identity, not a silent wrong fact.
- Repro: `python3 -I r6_snapshot.py` prints `imported snapshot_id is caller-chosen: True` and the `select_latest EnrichmentError` line.
- Fix: in `parse_snapshots`, recompute `domain_id('cve-snapshot', 1, ...)` and reject a mismatch; parse `retrieved_at` at import and name the snapshot index in the error.

### ACQ-11 Low: a torn raw-cleanup journal line aborts restore with an untyped error

- Where: `raw_cleanup.py:150-153` (`json.loads` runs before the `PT-STORAGE` shape check); the journal is written by `_append_journal` (`:69-78`).
- Evidence: a truncated final line (possible after a crash mid-append) raises `json.JSONDecodeError: Unterminated string ...`, which has no `PT-STORAGE:` prefix. Earlier valid lines were already restored, so the caller gets no count and cannot tell how far it got. The journal is not repaired.
- Repro: `python3 -I r9_journal.py` prints `ValueError: Unterminated string ...`, and the first duplicate is on disk.
- Fix: wrap `json.loads` and raise `ValueError('PT-STORAGE: raw duplicate journal line N is malformed')`. Decide whether an unterminated last line is skipped with a warning. Test: a journal with a truncated final line.

### ACQ-12 Low: spec and code disagree on how identification checks AMD64

- Where: `docs/specs/acquisition.md` §4.5 says PE must be AMD64 "via existing `ingestion.inspect_artifact`"; `acquisition/quarantine.py:19, 81-84` calls `ingestion.validate_pe` and catches only `ValueError`.
- Evidence: `validate_pe` (`ingestion.py:71-96`) does enforce `0x8664` and PE32+, so the gate is equivalent for this purpose, and `ProjectService.create` checks again later. The spec and the code still disagree, and the reviewer cannot tell which one is authoritative.
- Fix: either amend SPEC-08 §4.5 to name `validate_pe`, or call `inspect_artifact` and update the tests. Either way, add a test that names the function the spec requires.

### ACQ-13 Low: enrichment URL-level consent cannot fail

- Where: `cli.py:424` (`FetchConsent.for_plan(plan)`); `enrichment/intelligence.py:97-99` (`for_plan` derives the URL set from the plan) and `:318-319` (`_validate` checks membership).
- Evidence: the URL set and the executed plan come from the same object, so the membership check is always true. Only the provider list (`--consent-providers`, `cli.py:411-412`) is an independent check. The URLs are printed to stderr before the fetch (`cli.py:422-423`), so a preview exists. The gap is that the consent object is not bound to what the user saw. Same class as known C-14 for acquisition, reported here for the enrichment instance.
- Fix: build `FetchConsent` from the confirmed URL list (or from a token that the preview produced), not from `plan` at the fetch site. Test: a plan altered after consent is refused.

## Suspicions (no repro; not counted)

- S-1 `acquisition/delta.py:60-69`: `_load` creates a new `ctypes.WinDLL` per `apply_raw` call and never releases it. Windows-only; not run.
- S-2 `enrichment/pipeline.py:170-182`: the cache-hit path does not apply the `cancelled`/`failed` filter that the compute path applies (`:186-188`), and detector fields (weights, confidence, status) are not re-derived, only locations and ownership. Spec section 9 defines that boundary; exploitable only by a local writer.
- S-3 `enrichment/storage.py:369-372` (`_run_rows`): `json.loads(body).get(...)` raises `AttributeError` for a non-object body, which is not caught. `apply_retention` swallows only `EnrichmentError` and `sqlite3.Error`, so this would fail a publish. Needs a non-object `secondary-matches` row, whose import path was not checked.
- S-4 `enrichment/intelligence.py:425`: `response.close()` runs in `finally` while an abandoned reader thread may still be inside `read` on the same socket. Not reproduced.

## Reviewed and found sound (no finding)

- Host allowlist, userinfo and port refusal: `acquisition/transport.py:57-68`; `enrichment/intelligence.py:70-78`.
- Redirects are re-checked per hop; the NVD key is stripped on a cross-host redirect (`intelligence.py:385-387`); environment proxies are ignored (`ProxyHandler({})`).
- Blob redirect: any `*.blob.core.windows.net` account is admitted (`transport.py:64`). This matches spec section 4.4; integrity rests on the SHA-256 check. Design note, not a defect.
- Size caps: Content-Length pre-check plus streaming cap (`transport.py:181-204`); gzip bomb bounded (`winbindex.py:45-61`); NVD/MSRC 4 MiB (`intelligence.py:398-423`; `cve.py:134-135`).
- Path handling: `validate_file_name` uses `fullmatch` with no separators; staging is `mkdtemp` 0700; `raw_cleanup._REMOVED` forbids separators and `:`; restore writes only journal-named shapes.
- Hash and size are verified on the staged temp file before `os.replace`; the temp file is unlinked on any failure (`transport.py:330-336`).
- Regex review (ReDoS): every pattern in `signals.py:58-163`, `wil.py:35-43` and `cve.py:42-53` is bounded or linear; `wil._IS_ENABLED` is anchored at a finite match.
- Strict JSON: duplicates, NaN and infinity rejected (`cve.py:120-128`; `winbindex.py:64-82`).
- Cache publication: manifest written last, staging then `os.replace` (`cache.py:431-451`); stage and key validated (`:209-213`); symlinks and junctions refused (`:136-146`, `:229-250`).
- Retention generation rules (`storage.py:304-325`, `:410-431`): roll back on failure; `secondary-matches` and `cve-snapshot` are never deleted.
- Profiles: reserved Windows device names refused (`profiles.py:29, 53`); `cache_dir` must be absolute (`:63-65`).
- Known findings C-01 (transport drip, acquisition side), C-06 (`InvalidURL`), C-11, C-12, C-13, C-14 and C-18 were confirmed by reading and are not repeated. ACQ-1 is the adjacent `urljoin` escape, not C-06.

## What I reviewed

- Acquisition (all): `transport.py`, `quarantine.py`, `contracts.py`, `winbindex.py`, `delta.py`, `acquisition/__init__.py`.
- Enrichment, network and cache: `intelligence.py`, `cache.py`, `cve.py`, `pipeline.py` (cache path, publish, load paths, `_gc_paused`, `algorithm_digests`), `storage.py` (publish, entries, retention, `make_room`, `_run_rows`), `profiles.py` (validators, save, paths), `contracts.py` (`CacheManifest`, `CveSnapshot`, `CvssRecord`).
- Module-level: `netutil.py`, `raw_cleanup.py`, `verified_backup.py`.
- Callers that decide consent, staging and cleanup: `cli.py` `cmd_acquire`, `_candidates`, enrichment `--fetch` (`cli.py:405-430`); `ui.py` acquisition task and `complete_download` (`:636-694`).
- Specs: `docs/specs/acquisition.md` (sections 3-4), `docs/specs/enrichment.md` (sections 0-3, 5-6, 8-10), `docs/specs/network-egress-privacy.md` (inventory rows 1-5, 14; section 4 is a proposal and was not expected to be implemented).
- Repros run: `r1` to `r9` (listed above). No network access was used.

## Not reviewed

- `enrichment/signals.py` detector logic (1016 lines; only its regexes and scan bounds were read), `wil.py` body, `views.py`, `ranking.py`, `identity.py`.
- `pipeline.py` stage bodies (`run`/`_run`), `storage.py` `ensure`, migration and the `_BACKUP_COMPARE` tables, the rest of `contracts.py`, and the rest of `profiles.py` (load and dump).
- Test suite: no pytest run, no test edits, and no check of whether existing tests cover the cases above beyond grep.
- Windows behaviour: the sharing-violation path (ACQ-5), `delta.py` (S-1), and `_pid_alive` on Windows were read, not run.
- SPEC-42 offline switch (section 4 of `network-egress-privacy.md`) is marked as a proposal and is not implemented; this is not a defect.
