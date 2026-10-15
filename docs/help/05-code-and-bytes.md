# Read code and verified bytes

Select a function relationship and confirm the Older and Newer headers. Decompiled code is generated C-like text, not original source. Assembly is available only when actual instruction text was retained. Metadata describes saved analysis records. Missing representations are labeled rather than reconstructed.

Previous diff and Next diff, with Alt+Up and Alt+Down, move through changed regions. The hunk selector chooses a specific insertion, removal, or replacement. Alignment gaps are display aids. Equal addresses or line numbers do not establish correspondence, and displayed text can be truncated.

Hex, Binary, and Base64 show verified original artifact bytes. They do not encode the displayed decompiled text. Whole file scope uses file offsets. From function entry translates the selected entry address through the PE section mapping; it does not claim a verified function extent. Bytes after the function's end may therefore appear.

A refused mapping or hash mismatch must remain unavailable. Do not substitute guessed offsets. Equal-offset byte highlighting is a display comparison, not an instruction-aware semantic classification.

Copy behavior depends on the representation: raw modes copy the displayed page with provenance. Check the copied side and identifiers before pasting into notes. Clipboard contents can contain project information.

Source: [Files and raw-byte guide](../guide/15-files-and-pe-overview.md), the [README](../../README.md), and src/patchtrace/tooltips.py. **UNVERIFIED:** navigation, copying, truncation, and byte reads were not run here.
