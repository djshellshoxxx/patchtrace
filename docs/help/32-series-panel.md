Series panel
Experimental. The reviewed source contains a Series dock declaration and controller. Older documentation also describes a separate Series window. Behavior in your installed release is UNVERIFIED.
A series follows function relationships across explicitly ordered builds. The README describes three to eight builds, with an ordinary comparison project for each adjacent pair.
Open a series.json through the Series file-opening action. The dock design provides one tab per opened series. Opening reads the series and its pair projects; it does not run comparisons.
Select a chain, then inspect its individual hops. The documented tables include relationship categories, match types, native ratios, attention scores, pair state, and stale status.
Adjacent relationships form an inferred chain. The README describes optional direct first-to-last comparison as a separate check. Even a direct confirmation concerns recorded correspondence, rather than proof of identical behavior throughout the series.
Split, merged, and ambiguous relationships can end a chain. Do not join the remaining fragments by matching names alone.
Use Open pair at this function to inspect an available hop in its ordinary comparison project. The action depends on the pair’s current readable state.
Reload rereads the stored series view. Cancel load stops loading. Copy chain retains the displayed chain information.
Closing a series tab does not delete its projects. Keep the series file and associated pair projects together when preserving the investigation.
Sources: README.md, “Acquisition, build series and second-opinion engines”; src/patchtrace/nway/panel.py; src/patchtrace/ui_series.py.
