# Injection fixture (SPEC-28 K1)

**SYNTHETIC.** `hostile-advisory.json` was derived from `../synthetic-advisory-rev1.json` by a throwaway script on 2026-10-14 (strings replaced, structure unchanged). It is a valid CSAF 2.0 document that carries hostile advisory text so the report writers can be tested against it. It describes no real vulnerability, product or vendor.

The JSON is written with `ensure_ascii`, so every control, bidi and format character appears as a `\uXXXX` escape and the file itself holds no hidden characters.

| Payload | Where |
|---|---|
| HTML (`<script>`, `<img onerror>`, `<a href="javascript:...">`, `<b>`, `<h1>`) | tracking ID, publisher, titles, notes, remediation details, threat details, product names, CWE name, other identifiers |
| Markdown (`**bold**`, `_under_`, backticks, `~~strike~~`, links, images, autolinks, pipes, `# heading`, bullets, ordered items, quotes, rules, fences) | vulnerability title, description note, FAQ note, product names |
| URLs as text (`javascript:`, `https://...?a=1&b=2`, `www.`, e-mail) | remediation URL, notes, product names |
| bidi override and isolates (`U+202E`, `U+202C`, `U+2066`, `U+2069`, `U+200E`) | publisher, titles, notes, remediation details |
| C0 controls (NUL, BEL, ESC with a CSI and an OSC title sequence, `U+0001`), DEL, C1 controls (`U+0080`, `U+009B`, `U+009F`) | description note, threat and remediation details, product name |
| Layout characters (tab, CR, NEL `U+0085`, LS `U+2028`, PS `U+2029`) | description note, product names |
| Zero-width and format characters (`U+200B`, `U+200D`, `U+FEFF`, `U+00AD`), Unicode tag characters (`U+E0041`), private use (`U+E000`) | description note |
| Long cells | a 995-character product name, a 5,630-character description note, a 986-character threat detail |
| Entity text (`&amp;`, `&lt;b&gt;`), quotes, `$100 @mention #123`, a Windows path | description note |

A lone surrogate escape (`\ud800`) is deliberately **not** in the document: the normalizer rejects it (`PT-INTEL-LIMIT`), which `tests/test_intel_cli.py` pins.

The report goldens in `../expected/` are built from this file with the synthetic sample project.
