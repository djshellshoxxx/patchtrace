Attention ranking and change signals
After a completed comparison, choose Analysis → Rank changes or press Ctrl+R. The documented ranking runs deterministic detectors over changed hunks in one-to-one function relationships.
Its integer attention score establishes a reading order. It does not estimate whether a function contains a flaw, whether a change fixes one, or whether a selected CVE applies.
The documented detectors are:
ID	Looks for
BND	Added bounds checks near relevant uses
INT	Comparison strictness or cast changes
OVF	Overflow guards or checked arithmetic
VAL	Validation calls or newly checked return values
ERR	Predicate-controlled early error returns
SIZE	Changed size arguments
WIL	Changes enclosed by recognized feature gates
SCRUB	Zeroing or masking before copying data out


Detectors inspect decompiled text and have recognition limits. A reported signal requires inspection of its exact lines and surrounding code.
Select a CHANGE SIGNALS entry to navigate to its recorded lines. Check the detector label, evidence availability, and selected profile.
An unavailable score is different from a completed evaluation with no recognized signal. Missing decompiled text can prevent assessment.
The list’s ordering selector returns to project order. Profile weights and disabled detectors affect ranking, so preserve the profile identity when comparing results.
A new analysis run or manual match correction can make stored ranking stale. Use a current ranking when preparing a current report.
Sources: README.md, “Rank changes, feature flags and CVE context”; src/patchtrace/tooltips.py.
