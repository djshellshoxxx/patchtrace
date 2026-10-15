Read calibration and confidence labels
Experimental. Calibration infrastructure exists in the reviewed source. A released, validated model for your input domain is UNVERIFIED.
Different labels answer different questions:
Display	What it represents
Engine-native value	That engine’s own measurement
Detector confidence label	A rule’s evidence-strength category
Attention score	Research ordering
Model confidence label	A generated interpretation’s stated confidence
Calibration display	An estimate permitted by a specific model and validation policy


Do not transfer the meaning of one display to another.
The reviewed calibration policy falls back to ordinal display when a usable qualifying artifact is unavailable. Synthetic-only evidence cannot promote the display to a Windows-system-file calibration claim.
Read the scope notice and its evidence limits. Documented notices distinguish untested, tested on synthetic builds, tested on Windows files, degraded validation data, and expired validation data.
Even a Windows-tested notice requires checking what was covered: code families, architectures, engine versions, compiler conditions, and the measured outcome.
The policy supports bands or numeric display only when the artifact satisfies the corresponding gates and domain requirements. That code path does not establish that an eligible artifact ships.
A calibrated measurement applies to its stated prediction target and domain. It is not a general estimate of vulnerability presence.
When validation is missing, unreadable, expired, or outside scope, retain the reduced claim. Do not manually reinterpret ordinal ranks as percentages.
Sources: src/patchtrace/calibration/policy.py; src/patchtrace/calibration/scope.py; docs/modules.md; README.md.
