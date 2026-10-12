# Winbindex fixture (trimmed)

`afd.sys.json` holds 4 of the 286 entries from
`https://winbindex.m417z.com/data/by_filename_compressed/afd.sys.json.gz`, fetched on 2026-10-12
(compressed body SHA-256 `609ad52f79f12d8eaa0918bbd06c3fad115739e1670350e6f5a9b79c46438c3a`).
It is stored decompressed so it can be read; tests gzip it at runtime. Entries are unmodified.

- `7f145acc…70eb`: 10.0.28000.3086, direct download (verified live: `D37888A1b2000` URL gives these bytes)
- `a151f225…236a`: no `virtualSize`, only `lastSection*` (classified as `candidates`)
- `6df5003f…`, `b15c7e83…`: 10.0.10240.x, direct

Winbindex data is GPL-3.0 (https://github.com/m417z/winbindex). This is a small metadata excerpt
for tests only; it holds no Microsoft binaries. Synthetic variants (missing fields, non-x64,
malformed JSON) are built inside the tests.
