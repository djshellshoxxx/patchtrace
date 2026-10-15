Backend and desktop settings
Use Setup to edit backend paths and desktop preferences. Select Save setup to apply saved changes. Closing with Cancel discards unsaved setup edits.
The documented numeric settings are:
Setting	Documented range	Meaning
Comparison timeout	10–86,400 seconds	Maximum permitted comparison duration
Code font size	8–28 points	Text size in the code panes
Interpretation context budget	512–200,000 characters	Bound used when selecting interpretation context


The README records defaults of 3,600 seconds, 11 points, and 24,000 characters. A character budget is different from a provider’s token limit.
Synchronize code scrolling stores the preferred paired-pane scrolling behavior.
Allow Ghidriff symbol-server lookups is disabled by default. Enabling it permits the backend’s symbol retrieval feature to contact servers. This setting governs that feature; it does not isolate external processes from the network.
Experimental: the tooltip registry describes an environment allowlist setting and additional environment-variable names to retain. The allowlist is documented as off by default pending local validation. Rejected passthrough names include PYTHONPATH, PYTHONHOME, LD_PRELOAD, and names ending in _OPTIONS.
UNVERIFIED: availability of those experimental environment controls in your packaged release.
Provider kind, endpoint, model, and request credential are entered in the interpretation preview. Credentials are not saved.
Planned: user-configurable worker count and theme selection are described as future work in the core UI specification. Later framework plans require separate release verification.
Sources: README.md; docs/specs/ui.md; src/patchtrace/tooltips.py.
