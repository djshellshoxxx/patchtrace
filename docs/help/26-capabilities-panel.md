Capabilities panel
Planned. The CAP plan specifies a capa-based comparison panel. The declared panel module was unavailable during review. Desktop availability is UNVERIFIED.
The planned shortcut is Ctrl+Shift+A. The Changes tab compares stored capa recognition results against function relationships. Setup and run configures and explicitly runs the separate capa program.
Opening the panel does not run capa. Select the intended executable and review the configured rules, backend, and timeout before starting extraction.
Read each side’s state carefully:
State	Meaning
Present	capa reported the capability
Absent	The relevant evaluation completed without that recognition
Not evaluated	capa did not evaluate the function
No function	The relationship has no function on that side


The planned change labels include gained, lost, moved, unchanged, and not compared. A moved label is a candidate explanation. Recognition on both sides does not establish identical code.
Group by namespace or function pair, then inspect Why capa matched. The matching features help distinguish a useful recognition from an irrelevant one.
Detection differences can arise from analysis behavior. A capability appearing in output does not establish new program behavior, purpose, or a defect.
Copy provenance to retain tool version, rule identity, options, artifact hashes, and cautions. Missing or stale evidence must remain visible.
Screen-reader output and display scaling require manual Windows checks; interface specifications alone do not establish those results.
Sources: docs/specs/program-e/CAP-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.
