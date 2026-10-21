# Search panel

The **Search** panel finds text across the saved names, strings, APIs, code, notes and advisories of a project. It is a bottom dock. Open it from the **View** menu or with `Ctrl+Shift+F`. It needs an open project. Search is offline: nothing is uploaded and no target runs.

Controls, as labelled in the panel:

- **Search box.** Type the text to find.
- **Side**: `Both`, `Older` or `Newer`. Results keep their side.
- **Scope**: `Everything indexed` or `Changed only`.
- **Mode**: `Auto`, `Words`, `Exact`, `Prefix`, `Substring` or `Similar`.
- **Sort**: `Relevance`, `Change`, `Name` or `Address`.
- **Search** runs the query. **Cancel** stops a running search or build. The status line then says *Cancelled. Earlier results are unchanged.*
- **Build index** rebuilds the search index. It does not rerun the binary analysis.
- **Coverage** shows which groups are indexed. Check it before you read an empty result as absence.
- **Go to code** opens the selected result in the code panes. **Other side** shows the other build of that result. **Copy** copies the selected reference.

Read results with care. A hit in a string, advisory or code record shows that the text was observed in that source. It does not show that a particular function uses it. A repeated name can belong to more than one function, so check the side and address.

The same search is available from the command line: [`patchtrace search`](72-cli-search.md).

Sources: `src/patchtrace/search/panel.py`, `src/patchtrace/search/qt_panel.py`, `src/patchtrace/search/cli.py`.
