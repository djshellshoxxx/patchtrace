# Audit: kev, rules, kbcorrelation, calibration (shipped), pilot

Date: 2026-10-15. Author: Claude Haiku 5.5 (worker slice). Scope: `src/patchtrace/{kev,rules,kbcorrelation,calibration,pilot}`.
Method: targeted greps for the audit classes (network and file writes, atomic writes, unbounded reads, broad excepts,
unknown-as-negative defaults, untrusted-text rendering, averaging), followed by reading each hit. Spec drift was
spot-checked only (KEV limits and snapshot naming). Not completed: a full dead-code pass (scan stopped for run time)
and a full spec-drift pass against `docs/specs/program-e/{KEV,YRX,KB,PIL}-integration-plan.md`.

## Findings

| id | severity | file:line | evidence | suggested fix | status |
|---|---|---|---|---|---|
| H-01 | Medium | `src/patchtrace/pilot/store.py:131` (`_write`) | Sidecar bytes were written with `write_bytes` and no `fsync` before `os.replace`. The KEV, KBC and rules stores all fsync before publishing. After a crash the final name can point at an empty or partial file. | fsync the `.part` file before the rename. | **Fixed** (red test `tests/test_pilot_store_durability.py`, green; `tests/test_pilot_store.py` 52 passed; ruff clean). |
| D-01 | Medium | `src/patchtrace/rules/store.py:236` | The sidecar is read with `path.read_bytes()` and only then compared with its stored SHA-256. Memory use is not bounded by a limit before the read. The file is PatchTrace's own, so exposure is low. | stat the file, refuse above a named limit, then read. | Deferred: needs a limit constant chosen in the RULE spec. |
| D-02 | Low | `src/patchtrace/kbcorrelation/sources/cvrf.py:485` and `:623` | `desc[:limits.text_field_bytes]` slices by characters, but the limit is named in bytes. A 64 KiB limit of non-ASCII text can reach about 256 KiB. Remediation descriptions are not rendered; they are only scanned for KB tokens. | Encode-and-cut at a byte boundary, or rename the limit to `text_field_chars`. | Deferred. |
| D-03 | Low | `src/patchtrace/kbcorrelation/cli_index.py:152` | The workspace manifest is loaded with `json.loads(path.read_text(...))` and no size bound. It is a local workspace file. | Bound the read with the same helper used for objects. | Deferred. |
| D-04 | Low | `src/patchtrace/pilot/store.py:159` and `src/patchtrace/calibration/ledger.py:127` | Both swallow the exception text into a status string. The text comes from local parsing, not from untrusted input, so this is not a leak. Recorded for completeness. | None required. | Informational. |

## Checked and found sound

- `kev/transport.py`: one consent covers fixed URLs only; redirects are restricted to the same https host; the body
  is capped while it streams; Content-Length is verified; deadlines are enforced per read; retry-after is bounded.
- `kev/cli.py` `_escape` and `kev/report.py` `escape_md`: escape Markdown and HTML metacharacters, including `|`, in
  every value that is not a fixed vocabulary.
- `kev/store.py`: snapshots are written atomically with fsync and `os.replace`; reads are capped at 16 MiB and
  gunzipped with a bounded read; snapshot names match their raw SHA-256 as the header says.
- `kev/join.py`: `not-listed` is never reported when the catalog is missing (`unavailable`); the not-listed wording
  states that it is not a negative result.
- `pilot/fusion.py`, `pilot/tiers.py`: no score averaging; counts only.
- `kbcorrelation/cli_index.py` `_atomic_write` and `kbcorrelation/products.py` `clean_text`: atomic and bounded.
- `calibration/artifact.py`: model JSON is read with a `MAX_BYTES + 1` bound; any failure yields "no model".
- `calibration/policy.py` falls back to L0 on any exception.

## Deferred list

1. D-01 (sidecar read bound in `rules/store.py`).
2. D-02 (byte versus character limit in CVRF descriptions).
3. D-03 (unbounded manifest read in `kbcorrelation/cli_index.py`).
4. Dead-code pass over the five packages (not completed).
5. Full spec-drift pass against the four `program-e` integration plans (not completed).
