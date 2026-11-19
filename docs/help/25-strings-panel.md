# Strings panel

The **Strings** panel compares the strings of the older and newer build. It is a bottom dock, shown with `Ctrl+Shift+T`, and it is tabbed with **Calls** and **Capabilities**. It needs an open project.

Choose a **Source**, then select **Scan both builds**. **Auto** reads existing FLOSS results for each current build when available and uses the built-in scan otherwise. **Built-in scan** reads both files directly. **FLOSS results** requires stored results for both current builds; if one is missing, the panel names it and keeps earlier results. Changing the source affects the next comparison. None of these choices runs either file or starts FLOSS.

The comparison uses the same sources, import/export cues and function links as the command line. Results describe the selected older and newer artifacts; stored results from before an orientation swap are not used for the wrong build. **Re-scan both builds** repeats the selected comparison. **Cancel** stops it, and the status line says *Extraction cancelled. Earlier results are unchanged.* The displayed comparison is not a new saved project result.

Filter with the change filter, which offers `Differences`, `All changes`, `Only in newer`, `Only in older` and `Edited`. Use the text box (*Text to find*) and the **Hide noise-like strings** checkbox to narrow the table.

Select a row to see its details. The row shows the function it links to, or *No supported function link*, and its file offset, or *No file offset*. Then:

- **Open function** opens the function that uses the string.
- **Open in hex** opens the string's bytes in the hex view.
- **Copy escaped** copies the selected strings with escaped characters.

A string in a file is not proof that a function uses it, and an unlinked string is not proof that none does. Secret-looking text is handled as data. Copy only what you need.

To run FLOSS, use [`patchtrace intel-tools`](62-cli-intel-tools.md) with its separate settings and consent. This panel reads its stored results. The command-line comparison is [`patchtrace strings`](73-cli-strings.md).

Sources: `src/patchtrace/strings/panel.py`, `src/patchtrace/strings/qt_panel.py`, `src/patchtrace/strings/cli.py`.
