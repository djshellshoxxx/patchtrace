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
`bindiff-8-help.txt` is REAL output: stdout of `bindiff --nologo --help` from the official BinDiff 8 Linux
package (`bindiff_8_amd64.deb`, SHA-256 `821990e3...4dda`, `opt/bindiff/bin/bindiff` SHA-256 `eb0a88eb...d0fb`),
captured 2026-10-14 as uid 65534 with an empty environment; exit code 1, stderr empty. The fake `bindiff`
(`tests/fake_bindiff.py`) prints it by default. BinDiff is Apache-2.0.
