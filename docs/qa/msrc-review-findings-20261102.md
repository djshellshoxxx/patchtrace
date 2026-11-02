# Native MSRC review findings — fresh author verification, 2026-11-02

Base/current reviewed #153 head: `3bd48a710dcec1b471944f439a79b0fc8655921d`.
Branch: `codex/msrc-review-findings-20261102`. This work is separate from the saved-investigation-scope
repair. Both exact review comments were read through the GitHub connector and independently reproduced:

- [4440130537](https://github.com/djshellshoxxx/patchtrace/pull/153#discussion_r4440130537): conflicting active card metadata.
- [4440130544](https://github.com/djshellshoxxx/patchtrace/pull/153#discussion_r4440130544): absent Type 2 remediation description.

## Reproduction and bounded disposition

Two mutations of the existing native factual projection retained two active snapshots and 86 edges
under unknown revision order. Importing A then B returned `Alpha title` / `CWE-416`; reversing
insertion order returned `Beta title` / `CWE-125`. Neither output reported the conflicting card facts.
The repair computes consensus separately per CVE and source kind for title, stated CWE and severity
context. Differing fields, including absent versus present, become unavailable; agreeing fields are
retained. `CARD_FACT_CONFLICT` names the differing fields. KB/CVE lookups report the warning, and
attached context records it among unknowns. Raw imported cards, raw objects, all original edges and
the existing active-revision rules remain intact. CVRF and CSAF cards remain separate. There is no
card-schema expansion, arbitrary metadata winner, or claim that all advisory ambiguity is resolved.

Removing `Description` from the first Type 2 row removed its two KB5041571 edges without a row
diagnostic. It now produces `ROW_SHAPE` at the existing remediation object and names `Description`.
The bot's unconditional suggested guard was not adopted: the factual projection contains **17 Type 3
rows without Description**, so the new required-field diagnostic is restricted to Type 2 vendor fixes.
Existing malformed-description rejection and nonfix-row handling remain unchanged.

## Fresh checks

Tests use offline mutations of the existing hash-pinned factual projection and a validated synthetic
CSAF fixture. Sockets are disabled; real importer, reverse index, SQLite reload, service search,
synthetic local PE attachment and explanation paths are exercised. No target PE is executed.

| Check | Actual result |
|---|---|
| `tests/test_kbc_msrc_review_findings.py` before production edits | **8 failed, 8 passed in 1.10s** |
| Same regression file after repair | **16 passed in 0.96s** |
| All `tests/test_kbc_*.py` | **1009 passed in 21.59s** |
| `python -m ruff check src tests tools` | **All checks passed** |
| `git diff --check` | **Passed** |

All commands ran from this worktree using `/workspace/scratch/142cb233d750/venv/bin/python`,
`PYTHONPATH=.:src:tests`, and `QT_QPA_PLATFORM=offscreen` for pytest. Broad command:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q tests/test_kbc_*.py
```

Controls cover unknown/tied revision order, both insertion orders, agreement, one-field conflicts,
missing versus present fields, independently typed CVRF/CSAF cards, comparable newer revisions,
raw snapshot SHA and exact-byte reload, source-card immutability, edge retention, KB warning and
context propagation, no rule hypothesis from a conflicting CWE, and Type 2 absent/malformed versus
legitimate nonfix description omission. Independent review, integrated full-suite, current-head CI,
native Windows, frozen packaging and live vendor acceptance are not claimed by this receipt.
The integration owner retains publication responsibility; no remote writes occurred here.

## Verified content

| File | SHA-256 |
|---|---|
| `src/patchtrace/kbcorrelation/index.py` | `a447c1e07c84f452c756d06f3fcd636fbc4efee000451ca3454311377029f32d` |
| `src/patchtrace/kbcorrelation/sources/cvrf_msrc.py` | `16988c383a864607b276fffa81203d125eaf52b807b990b63594d9b9aa8bdb67` |
| `src/patchtrace/kbcorrelation/context.py` | `bb075cbad4a79189f27f287935c1aeb405de93171a796058b360c104f45dc707` |
| `tests/test_kbc_msrc_review_findings.py` | `7f532e8b59422794e988d3423656e6e9adc17238e0b5a2c65f7731c31015d1fd` |
| `docs/specs/kb-cve/31-B-msrc-reverse-index.md` | `948b425b42687edce74a9e80f2636f6a57fc5181fbd7b215ba5d45505eb9b95a` |

Independent review of7533fe0 found no blockers:165focusedpasses plus six-order severity/scope/raw-source preservation controls; source hashes in adjacent review receipt. Fresh exact-head hosted QA remains required.
