# jsonlite: development history

A small JSON tokenizer and recursive-descent parser that works over caller-owned buffers (no allocation, no libc).
Six versions, written as a believable maintenance history; every transition below is covered by a complete `truth`
block in `suite.json`. Version directories are `v1` .. `v6`; the notes are commit-style summaries of what changed and why.

## v1: initial release (0.1)
Tokenizer (`json_lex.c`), parser building a flat node tree in a caller-supplied pool (`json_parse.c`), string, number and
tree-access helpers (`json_util.c`). It works, but it is a first release: nesting depth is unbounded, `\uXXXX` output
is not capacity-checked, integer parsing wraps on overflow, numbers like `01` and `1.` are accepted, raw control
characters and invalid UTF-8 pass through strings, surrogate pairs are encoded as two 3-byte sequences, and keys written
with escapes cannot be looked up. These are the defects the next releases fix.

## v1 -> v2: serializer, path lookup, strict numbers, nesting limit
Adds `json_write.c`, a bounds-checked serializer over a caller buffer (sticky error, comma tracking with a 32-bit
container bitmap), and `json_get_path` for lookups such as `servers[1].host`. Number scanning now follows the JSON
grammar (no leading zeros, digits required after `.` and the exponent marker). The recursive parser gains a nesting
limit (`max_depth`, default 128) and returns `JSON_ERR_DEPTH`, which closes the stack-exhaustion denial of service on
inputs like `[[[[...`. Two latent writer bugs ship in this release and are fixed in v3: the escape routine checks
for 2 bytes of room but can emit 6, and the container bitmap is not guarded at 32 levels. A few locals are tidied
(`json_hex4`, `json_peek`).

## v2 -> v3: security hardening
A fuzzing round turns up several memory-safety and robustness issues. `json_utf8_encode` now receives the remaining
capacity and refuses surrogates and code points above U+10FFFF, which fixes the 1 to 3 byte overflow in
`json_unescape`; `json_unescape` also joins surrogate pairs and maps lone surrogates to U+FFFD. `json_parse_int` and
`json_number_value` detect overflow and return `JSON_ERR_RANGE` (signed overflow was undefined behaviour). The string
scanner rejects raw control characters and validates UTF-8 through the new `json_utf8_seq_len`. The serializer's
escape routine computes the bytes each escape needs, and `json_w_begin` refuses to open more containers than the
bitmap can track. Accessors tolerate NULL (`json_root`, `json_get_string`); `JSON_ERR_UTF8` is added.

## v3 -> v4: refactor and file split
No intended behaviour change except one bug fix. Lexer functions are renamed to a `json_lex_*` family
(`json_scan_digits`, `_literal`, `_number`, `json_skip_ws`) and `json_advance` becomes `json_parser_advance`; the
string scanner is split into `json_lex_string` plus `json_lex_escape`. String helpers leave `json_util.c` for a new
`json_str.c` (`json_hex4`, `json_utf8_encode`, `json_utf8_seq_len`, `json_unescape`), the hex predicate and value
function are merged into `json_hex_digit`, `json_peek` is inlined into its only caller, and `json_unescape` is split
so that a single-escape decoder (`json_decode_escape`) can be shared. Lexer and parser internals move to
`json_internal.h`. The one behaviour change: `json_member` and `json_str_eq` now compare decoded text through
`json_text_eq`, so keys containing escapes are found.

## v4 -> v5: performance, options, retuned limits
`json_lex_string`, the hottest function in profiles of large documents, is rewritten: a 256-entry byte-class table
replaces the per-byte branch chain, and runs of plain bytes are skipped eight at a time with a SWAR test
(`json_load64`, `json_str_special`). The rewrite keeps the exact error precedence. `json_parse` becomes a wrapper over
the new `json_parse_ex`, which takes a `json_options` (nesting limit, and `JSON_OPT_COMMENTS` to treat `//` and block
comments as whitespace); defaults live in `json_options_default`. Limits are retuned: the default nesting limit drops
from 128 to 64 so that every document that parses can also be written back, and the serializer's container bitmap
widens to 64 levels with a per-writer limit.

## v5 -> v6: 1.0 tidy-up
A cleanup release. Public accessors are renamed to a consistent scheme (`json_member` to `json_obj_get`, `json_element`
to `json_arr_get`, `json_mem_eq` to `json_bytes_eq`). `json_u32_digits` and `json_u32_write` merge into
`json_u32_format`, and `json_node_path` is simplified around it and a new `json_child_index`. Dead diagnostics
(`json_tok_name`, `json_doc_stats`, `json_node_depth`) are removed. `json_util.c` is regrouped (tree access, paths,
numbers), which shifts every definition in the file without changing its text. A style pass touches a dozen small
functions without changing behaviour. One contract fix: `json_w_finish` now reports `JSON_ERR_NOMEM` when the buffer
has no room for the terminating NUL instead of leaving the output unterminated.
