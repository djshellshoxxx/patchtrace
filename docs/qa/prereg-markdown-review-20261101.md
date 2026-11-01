# Preregistration QA parser review — November 1

Base: local main port `918653cf76abf7b986442048356627666ef4a987`, whose tree equals
published #154 `4aa99f7bd989765000c6ebd659c9565030a48849`. Actual #154 review threads
were fetched before repair. No thread was resolved and no issue/PR was closed.

| Finding | Reproduction and final behavior |
|---|---|
| Comment fragment manufactures a column-zero record | `<!-- hidden` followed by `\| --> \| C9-PREREG-v1 \| SHA \|` accepted before repair. Eligibility now requires the original first pipe to be visible outside any comment already open at physical line start. |
| SHA substring is treated as a digest value | Matching `SHA-draft`, `draft-SHA` and `(SHA)` cells accepted before repair; all now fail the complete plain-cell digest requirement. |
| Literal same-line-code comment marker hides a real row | Literal backtick-quoted `<!--` poisoned comment state and rejected a later genuine record. Matched same-line code spans are recognized before comment syntax. Fenced and indented examples remain excluded. |
| Escaped pipe manufactures a cell | `\| note\\\| C9-PREREG-v1 \| SHA \|` accepted before repair even though the identifier was part of another cell. Escaped pipes now remain cell text. |
| Optional trailing pipe | Otherwise valid rows without a final pipe were rejected. The bounded supported grammar now permits either form. |

These changes remain inside `prereg_gate.py` and its existing selection tests. `train.py`, its parser and
`_run`, frozen protocol bytes, approval rules, natural grouping, and final-look guards are unchanged.
The spec amendment defines the supported simple table grammar; this is not a general Markdown renderer.
Unsupported raw HTML and multiline/unclosed code still fail closed. Verified identity conveys no owner
approval or locked-evaluation authorization. No actual corpus or locked final evaluation was consumed.

## Evidence

- Existing selection/tools/frozen-constant baseline: **99 passed**, 1.43 s.
- New regression run against original helper: **21 failed / 61 passed**, 1.15 s. Failures include the
  three reported boundaries, escaped-pipe false identity, inline/indented examples and optional delimiter.
- Separate original `_run` probes reached a mocked corpus boundary for the comment fragment, digest suffix
  and escaped-pipe cell. The probe deliberately raised there; no corpus directory existed or was read.
- First repaired selection/tools/constants run: **123 passed**, 1.07 s; focused Ruff and diff checks passed.
  Final exact-source verification and independent review are recorded separately below/by the coordinator.

The original red/green logs and baseline-boundary JSON are retained in the session's reconciliation
evidence directory (`pr154-markdown-red-20261101.log`, `pr154-markdown-green-20261101.log`,
`pr154-before-inputs-baseline-20261101.json`). Full suite/cross-OS/native acceptance remains separate.

## Preserved #155 overlap disposition

Closed, unmerged #155 head `15370a0bf690ea65f49d1f6cc67c40f73fd3d77c`, branch
`fix/remediation-53088704-982db3`, was fetched and preserved without remote mutation. Its exact diff adds
two tests and comment/code handling. Both advertised behaviors are incorporated by this repair's own
regressions; no unreviewed patch was cherry-picked. Its replacement of original provenance with
`visible.startswith('|')` would accept the existing negative `<!-- prefix -->| C9-PREREG-v1 | SHA |`.
An exact-module bounded probe confirms that regression and continued `SHA-draft` acceptance, while its
two intended cases pass. Therefore its implementation is not adopted wholesale. Source/diff and probes
are retained as `pr155-overlap-patch-20261101.json`, `pr155-prereg-gate-original.py` and
`pr155-bounded-overlap-review-20261101.json`. Author activity outside those observed refs remains unknown.

## Root review escaped-opening follow-up

Root independently found that backslash-escaped ticks around a comment opener could falsely
protect a closed multiline HTML comment containing a matching row.
Exact QA bytes are retained in `pr154-escaped-opening-baseline-20261101.json`. On `5e008a5`, direct
selection returned the matching SHA and actual `_run` reached a deliberately mocked corpus boundary.
The earlier approval of `5e008a5` is therefore qualified/withdrawn pending this repair; it must not be
published or integrated alone.

Primary CommonMark 0.31.2 rules ([escapes](https://spec.commonmark.org/0.31.2/#backslash-escapes),
[code spans](https://spec.commonmark.org/0.31.2/#code-spans), [comments](https://spec.commonmark.org/0.31.2/#raw-html))
and official `commonmark/commonmark.js` `lib/inlines.js` blob
`ea8419a46b816bc5e283f64cfd708899322af467` establish the distinction: escapes act outside code;
one escaped opening tick is literal and remaining ticks can still open code. Inside code, backslashes
cannot escape closing delimiters. The repair applies escape parity only when finding opening ticks;
the exact-run closing search remains unchanged.

New regression on `5e008a5`: **6 failed / 91 passed**, 0.90 s. Final selection/tools/constants:
**138 passed**, 1.04 s; whole-tree Ruff and diff checks pass. The 123 previous checks remain included.
Controls cover the closed multiline comment, actual run/shift refusal before corpus access, odd/even
backslash parity, literal backslashes before one/two/three-tick closers, a lone escaped tick, and an
escaped first tick that leaves a valid opener. No real corpus, protocol, approval or final-look guard changed.
Exact follow-up independent review remains required.

Final combined source b6b5495 (including5e008a5) independently approved with138 checks passing1.13s; earlier5e008alone approval withdrawn after root escaped-opening comment reproduction. Full original red/green/before-corpus/primary-source/PR155 overlap evidence is retained in `prereg-review-followup-20261101.tar.gz`. No actual corpus/final evaluation.
