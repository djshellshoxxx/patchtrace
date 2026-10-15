# Series

The Series dock reads a series.json containing an explicitly ordered set of builds and their adjacent pair projects. The existing workflow creates series through the CLI, not through a GUI creation wizard. Open the file through Project > Series window or the Series dock.

Select a chain to inspect its hops, match types, categories, events, and pair states. Open pair at this function moves to a readable pair project; Copy chain preserves the selected chain's context. Reload refreshes the view, while Cancel load stops the current load.

Only one-to-one hops extend a chain. Split, merged, ambiguous, and unmatched events end the inferred relationship rather than silently joining many functions. A direct first-to-last comparison can confirm or contradict the endpoints, but neither status proves a security interpretation.

Stored per-hop attention values are reading priorities. A missing ranking is not zero, and a sum does not become a calibrated statement. Check whether a pair is locked, unreadable, or changed before interpreting missing cells.

A stale mark means an underlying pair no longer matches the recorded series state. Recompute the series through its documented workflow rather than editing the saved JSON manually. Build order is your explicit input.

Source: [Series guide](../guide/14-series.md). **UNVERIFIED:** native three-build comparison, frozen GUI loading, cancellation, and Windows DPI behavior were not exercised here.
