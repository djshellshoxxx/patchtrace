# Search panel

The **Search** panel finds text across the saved names, strings, APIs, code, notes and advisories of a project. It is a bottom dock. Open it from the **View** menu or with `Ctrl+Shift+F`. It needs an open project. Search is offline: nothing is uploaded and no target runs.

Controls, as labelled in the panel:

- **Search box.** Type the text to find.
- **Side**: `Both`, `Older` or `Newer`. Results keep their side.
- **Scope**: `Everything indexed` or `Changed only`.
- **Mode**: `Auto`, `Words`, `Exact`, `Prefix`, `Substring` or `Similar`.
- **Sort**: `Relevance`, `Change`, `Name` or `Address`.
- Typing searches after a short pause; **Enter** searches immediately. **Cancel** stops a running search or build. The status line then says *Cancelled. Earlier results are unchanged.*
- **Build index** rebuilds the search index. It does not rerun the binary analysis.
- **Coverage** shows which groups are indexed. Check it before you read an empty result as absence.
- **Go to code** opens the selected result in the code panes. **Other side** shows the other build of that result. **Copy** copies the selected reference.

Read results with care. A hit in a string, advisory or code record shows that the text was observed in that source. It does not show that a particular function uses it. A repeated name can belong to more than one function, so check the side and address.

## Save a query in this project

Choose the text, mode, side and scope, then select **Save query…**. Enter a name of 1–64 characters and choose **Save**. This saves the effective query in the open project; it does not run a search or build an index. Results and sort order are not saved. A project can hold up to 200 active saved queries. To change a query already saved under a name, delete that saved entry first or choose another name.

Select an entry under **Saved in this project**, then choose **Run saved** to search current indexed data with its saved mode and filters. Selecting an entry alone does not run it. Use **Build index** when coverage needs updating. **Delete saved** removes the entry from the active list while retaining its history in the project. Saving, running and deleting all apply to the current open project; a project change dismisses an open naming dialog.

## Recall recent text for this user

**Recent text (this user)** keeps successfully parsed query text across project sessions in local desktop settings. It retains at most 20 queries within an 8 KiB serialized budget, dropping the oldest complete entries when needed. This list can include text from another project.

Selecting recent text fills the search box and restores filters from that text in **Auto** mode. It does not run the query, including when an earlier index build is still finishing. Review the text and press **Enter** to search. **Clear recent text** clears this user's recent list; saved queries in projects remain available. A settings write failure is reported if the list cannot be cleared.

The same search is available from the command line: [`patchtrace search`](72-cli-search.md).

Sources: `src/patchtrace/search/panel.py`, `src/patchtrace/search/qt_panel.py`, `src/patchtrace/search/qt_saved.py`, `src/patchtrace/search/saved.py`, `src/patchtrace/search/cli.py`.
