# Read Hex, Binary, and Base64 views

Experimental. The byte views and paired-window controls have source and offscreen test coverage. Native manual accessibility and packaged behavior for the paired-window workflow remain UNVERIFIED.

Choose Hex, Binary, or `Base64` in the representation selector. These views render bytes from the project-owned artifact copies after checking their recorded SHA-256 identities.

They do not encode the decompiled text.

The documented scopes are:

| Scope | Meaning |
| --- | --- |
| Whole file | File bytes from the beginning of the artifact |
| Selected function entry | File bytes beginning at a mapped function entry |

Function-entry scope does not establish the function’s complete extent. Bytes displayed after its actual end can belong to another function or data.

An entry must map through the PE section table to file-backed bytes. Virtual-only, ambiguous, or out-of-image addresses remain unavailable; a range must not be guessed.

In the default fixed-offset view, pages contain up to 4,096 bytes. Both sides use the same logical page position within their chosen scopes. Different file layouts can place corresponding instructions at different offsets.

`Go to offset` accepts a hexadecimal file offset and switches to whole-file scope. A file offset is different from an RVA or virtual address.

Check scope, side, offset, and artifact identity when copying observations. Matching page numbers do not establish matching function bodies.

## Align independent physical windows

In **Hex** or **Binary**, turn on **Align paired physical offsets (bounded)** to inspect independently chosen older and newer file windows. This mode is optional; **Base64** continues to use the fixed-offset view.

1. Enter **Older file offset (hex)** and **Newer file offset (hex)**. Each is a physical file offset, optionally prefixed with `0x`, between zero and that file's end. These values are not RVAs or virtual addresses.
2. Set **Window bytes** to a multiple of 16 between 16 and 4,096.
3. Select **Align windows**, or press **Enter** in either offset field. The window reads verified original artifact bytes in the background. Windows near the end of a file are clipped and labelled; a window starting exactly at EOF has no bytes to align.
4. Inspect the status and span list. **Previous span** and **Next span** navigate the current windows; they do not choose new offsets or infer a following window.

An `equal` span establishes byte equality in these windows. Inserted, deleted or replaced spans describe local byte differences; they do not establish instruction or function correspondence. Repeated or conflicting anchors can produce `ambiguous` or `unaligned` results. Work limits can leave `unresolved` bytes. Read those outcomes before treating the displayed alignment as complete.

Display-only gaps contain no bytes. The Copy buttons, **Ctrl+C** and **Copy original window bytes** context-menu action copy the selected side's whole original window text with project, artifact and window provenance. Alignment labels and gaps are excluded, even when a smaller displayed selection is highlighted.

Editing an offset or the window size clears the previous result; choose **Align windows** to read the new windows. Changing the project, match, representation or inspected artifact, hiding the pane, or closing the window also invalidates the result and prevents copying stale bytes. Turn the paired-window option off to return to ordinary pages. **Go to offset** returns to fixed-offset whole-file navigation.

If artifact verification fails, resolve the integrity issue before relying on displayed bytes. **Do not bypass it by editing recorded hashes.**

Sources: `src/patchtrace/ui_raw_alignment.py`, `src/patchtrace/raw_alignment_view.py`, `src/patchtrace/representations/alignment.py`, `src/patchtrace/tooltips.py`; `docs/specs/byte-representations.md`.
