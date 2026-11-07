# Diff-engine adapters

`tools/research_qualification/adapters/` turns engine output into the scoring input `{case_id: [function, ...] | null}`
(`scoring.score_run`). Each adapter has `parse(source) -> list[str]`: changed functions, most changed first, ties by
name, unchanged excluded, added/removed-only after the changed ones. `source` is text/bytes content or an
`os.PathLike` (confined by `pathguard.confine`). CLI: `python -m tools.research_qualification adapters ENGINE FILE [--case ID]`.

| Engine | Input | Magnitude | Status |
|---|---|---|---|
| Ghidriff | `*.ghidriff.json` or `.md` | JSON: `1 - ratio` (then block, mnemonic ratio). Markdown: count of `+`/`-` lines in the function's diff block | JSON field names checked against ghidriff 1.0.0 source; markdown headings checked against its writer. No real run was available, so fixtures are hand-written. |
| BinDiff | `.BinDiff` SQLite, table `function` | `1 - similarity` (then lower confidence) | UNVERIFIED: no real export seen; documented schema. Only matched pairs are stored, so added/removed functions cannot be reported. |
| Rizin | `radiff2 -C` text or `-j` JSON | `1 - similarity` | UNVERIFIED: row layout from memory of radiff2 source, JSON keys guessed (tolerant reader). `-g` graph output unsupported. |

Notes:
- Ghidriff "modified" entries with no `code` diff type and ratio 1.0 (rename/address/call-graph only) and the markdown
  "Modified (No Code Changes)" section are treated as unchanged.
- Names are kept as reported, including C++ `A::b`, `sub_XXXX`, `FUN_XXXX`. Only x86 decoration on a plain identifier
  (`_f@8`, `@f@8`) is stripped. Nothing is invented from addresses; unnamed rows are skipped.
- Empty input raises rather than returning `[]`: an empty file means the engine did not produce output (BLOCKED, use
  `null`), whereas a valid report with no changes returns `[]`.
- Hostile input: 64 MiB input cap, 1 MiB line cap, 512-char names, 500k functions; NUL/binary, invalid UTF-8, NaN,
  deep nesting, control/bidi characters and `..` path segments in names all raise `ValueError`. Input is never executed;
  BinDiff files are opened `mode=ro` with `query_only`.
- `bindiff.parse` refuses a plain `str` (ambiguous between path and content): pass a `Path` or bytes.
