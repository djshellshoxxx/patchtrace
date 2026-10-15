Explore the sample
Use Sample to learn the review workflow before configuring external tools. Choose a parent directory when prompted. PatchTrace creates a separate timestamped sample project.
The sample contains an authored, synthetic bounds-check example and a curated finding. It is an exercise in navigating stored data. Opening it does not run a live model or analyze a real binary.
1. Select the modified function in FUNCTION MATCHES.
2. Read the older and newer representations in the paired panes.
3. Use Next diff to navigate to the changed region.
4. Choose Decompiled code, Assembly, or Metadata and examine the information available in each representation.
5. Select the finding in FINDINGS & ANALYST REVIEW.
6. Read its explanation, unknowns, and supporting evidence.
7. Select an evidence entry and check the side and supplied line range it references.
8. Enter an analyst conclusion and use Save finding review.
9. Open Export, inspect the preview, and write a report.
10. Close the project and reopen its directory with Open.
An unavailable representation should be identified explicitly. Missing assembly must not be replaced with invented instructions.
Each use of Sample creates a separate persistent project. Keep the exercise if you want to test saving, reopening, and exporting.
A successful sample exercise confirms those paths for synthetic data. It does not establish native backend compatibility, general matching accuracy, or the correctness of generated interpretations.
Sources: README.md, “Try the sample”; docs/specs/ui.md; docs/qa.md.
