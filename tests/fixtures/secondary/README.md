`rzdiff-functions.json` is a hand-trimmed four-entry sample in the exact shape recorded in
`docs/research/phase3/rizin.md` (rz-diff 0.9.1 `-C -j -t functions` on two afd.sys builds);
the second entry is the verbatim example from that note, the others follow its documented
COMPLETE / one-sided UNLIKE shapes. It is not a full real output file.
BinDiff SQLite fixtures are generated inside the tests from the schema in
`docs/research/phase3/binexport-bindiff.md`.
`bindiff-synthetic-pair.BinDiff`, `bindiff-synthetic-stdout.txt` and `bindiff-synthetic.json` are SYNTHETIC
goldens written by `tools/make_bindiff_fixtures.py` from `tests/bindiff_builder.py` (SPEC-29 §9.3). They are
not BinDiff output; the JSON records generator, SQLite version and SHA-256. A live v8 golden produced by
`.github/workflows/live-bindiff.yml` replaces them once BinDiff is provisioned (still blocked).
