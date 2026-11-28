# Strings panel

The **Strings** panel compares the strings of the older and newer build. It is a bottom dock, shown with `Ctrl+Shift+T`, and it is tabbed with **Calls** and **Capabilities**. It needs an open project.

Choose a **Source**, then select **Compare strings**. **Automatic** uses an admitted stored FLOSS result for each side when available and otherwise scans that side's bytes. **Stored FLOSS** requires an admitted result for both sides. **Built-in scan** reads both files without consulting stored tool results. Each row names its source. None of these choices starts FLOSS or runs either input file. **Compare again** repeats the comparison; **Cancel** stops it and retains earlier results.

**Advisory anchors...** chooses a local AnchorSet JSON file, as with the command line's `--anchors`. **Clear anchors** removes that choice. Anchors supply text and API hints, and a match is not a vulnerability finding. Changing the source or anchors marks earlier results stale until the next explicit comparison. Cancelling the file chooser leaves the current comparison unchanged. The file is read only when comparing; malformed or unreadable input reports an error and preserves earlier results.

Filter with the change filter, which offers `Differences`, `All changes`, `Only in newer`, `Only in older` and `Edited`. Use the text box (*Text to find*) and the **Hide noise-like strings** checkbox to narrow the table.

Select a row to see its details. The row shows the function it links to, or *No supported function link*, and its file offset, or *No file offset*. Then:

- **Open function** opens the function that uses the string.
- **Open in hex** opens the string's bytes in the hex view.
- **Copy escaped** copies the selected strings with escaped characters.

A string in a file is not proof that a function uses it, and an unlinked string is not proof that none does. Secret-looking text is handled as data. Copy only what you need.

Run and configure FLOSS separately with [`patchtrace intel-tools`](62-cli-intel-tools.md), then use its stored results here. Stored results retain their original extraction settings and provenance, including cache hits. An incomplete extraction cannot establish a missing string, and incompatible emulation settings are not compared. The command-line equivalent is [`patchtrace strings`](73-cli-strings.md).

Sources: `src/patchtrace/strings/panel.py`, `src/patchtrace/strings/qt_panel.py`, `src/patchtrace/strings/cli.py`.
