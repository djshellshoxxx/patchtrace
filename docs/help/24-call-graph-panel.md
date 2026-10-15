Call graph panel
Planned. The WB2 integration plan defines the graph workspace. Its panel declaration was unavailable during review; packaged behavior is UNVERIFIED.
The planned Ctrl+Shift+G command opens views of stored call relationships. The workspace includes Changes, Neighbours, Tree, and Diagram views. An across-builds view is a later addition.
Start with a selected function. Choose older, newer, or both sides; callers, callees, or both directions; and a bounded traversal depth. Follow selection is intended to track the main navigator.
Use the textual neighbour table or tree to inspect relationships. The diagram provides spatial context, while the textual views provide the alternative needed for keyboard and screen-reader use.
A missing edge does not establish that a call is absent from the program. The planned view depends on retained call lists, address and name resolution, and the stored change set. Unchanged functions may lack stored lists.
When the view reports truncated neighbours, reduce depth or narrow filters. Increasing visible complexity does not recover evidence that was never stored.
Planned actions include opening a function, showing an available call site, changing the traversal focus, returning through history, copying details, and exporting DOT.
The design specifies arrow-key node navigation, Enter to open, Space to select, and +, -, and 0 for zoom and fit. Actual assistive-technology behavior requires Windows acceptance testing.
Sources: docs/specs/program-e/WB2-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.
