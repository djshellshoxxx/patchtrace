# Strings panel

The **Strings** panel compares the strings of the older and newer build. It is a bottom dock, shown with `Ctrl+Shift+T`, and it is tabbed with **Calls** and **Capabilities**. It needs an open project.

Start with **Scan both builds**, which runs the built-in scan of both files. It reads the bytes and does not run either file. **Re-scan both builds** repeats it. **Cancel** stops the scan. The status line then says *Extraction cancelled. Earlier results are unchanged.*

Filter with the change filter, which offers `Differences`, `All changes`, `Only in newer`, `Only in older` and `Edited`. Use the text box (*Text to find*) and the **Hide noise-like strings** checkbox to narrow the table.

Select a row to see its details. The row shows the function it links to, or *No supported function link*, and its file offset, or *No file offset*. Then:

- **Open function** opens the function that uses the string.
- **Open in hex** opens the string's bytes in the hex view.
- **Copy escaped** copies the selected strings with escaped characters.

A string in a file is not proof that a function uses it, and an unlinked string is not proof that none does. Secret-looking text is handled as data. Copy only what you need.

FLOSS, a separate tool with its own settings, is not part of this panel. Use [`patchtrace intel-tools`](62-cli-intel-tools.md) for it. The command-line scan is [`patchtrace strings`](73-cli-strings.md).

Sources: `src/patchtrace/strings/panel.py`, `src/patchtrace/strings/qt_panel.py`, `src/patchtrace/strings/cli.py`.
