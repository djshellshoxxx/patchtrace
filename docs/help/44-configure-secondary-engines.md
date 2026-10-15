Configure secondary comparison engines
Experimental. Secondary-engine execution and BinDiff setup appear in the reviewed source. Compatibility of your installed tools and desktop package is UNVERIFIED.
Secondary results supplement the primary Ghidriff comparison. Each engine retains its own relationships, values, and provenance.
For BinDiff:
1. Open the Engine evidence panel’s Engines tab.
2. Expand the BinDiff setup section.
3. Select the exact bindiff.exe.
4. Choose Probe BinDiff.
5. Review its version and capability result.
6. Select and validate the older and newer BinExport files.
7. Select BinDiff for Run selected engines when it becomes available.
BinDiff discovery reads standard installation locations and configured hints. It does not search PATH or execute suggestions automatically. The explicit probe runs version and help checks.
A newer BinDiff major version can remain untested even when its required options are present. Read the probe’s compatibility information.
The README also documents an rz-diff runner with an optional explicit executable path and timeout. Its similarity is raw-byte Levenshtein, rather than a measurement interchangeable with BinDiff or Ghidriff values.
A failed or unavailable engine leaves missing evidence. It does not cast a negative vote against another engine.
Run only the engines needed for the investigation. Inspect agreement and disagreement in terms of function endpoints before interpreting the associated code changes.
Sources: src/patchtrace/ui_engine_setup.py; src/patchtrace/runtime_discovery.py; src/patchtrace/tooltips.py; README.md.
