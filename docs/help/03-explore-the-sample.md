# Explore the sample

Use `Sample` to learn the review workflow before configuring external tools. Choose a parent directory when prompted. PatchTrace creates a separate timestamped sample project.

The sample contains an authored, synthetic bounds-check example and a curated finding. It is an exercise in navigating stored data. Opening it does not run a live model or analyze a real binary.

1. Select the modified function in **FUNCTION MATCHES**.
2. Read the older and newer representations in the paired panes.
3. Use `Next diff` to navigate to the changed region.
4. Choose **Decompiled code**, **Assembly**, or **Metadata** and examine the information available in each representation.
5. Select the finding in **FINDINGS & ANALYST REVIEW**.
6. Read its explanation, unknowns, and supporting evidence.
7. Select an evidence entry and check the side and supplied line range it references.
8. Choose a **Finding review status**, enter an **Analyst conclusion**, and use **Save finding review**. To add a separate note, choose **Note on selected match** or **Note on selected finding**, enter the text, and select **Save note**.
9. Choose **Export** (`Ctrl+E`), [inspect the preview and export options](47-preview-and-export-reports.md), and select **Write report**.
10. Close PatchTrace, then reopen its project directory with **Open** (`Ctrl+O`).

An unavailable representation should be identified explicitly. Missing assembly must not be replaced with invented instructions.

Each use of `Sample` creates a separate persistent project. Keep the exercise if you want to test saving, reopening, and exporting.

Use `Tab` and `Shift+Tab` to move between controls and arrow keys to select list rows. Selecting a function updates the paired panes; selecting an evidence entry navigates to its retained location. See [keyboard navigation](49-keyboard-and-command-navigation.md).

A successful sample exercise confirms those paths for synthetic data. It does not establish native backend compatibility, general matching accuracy, or the correctness of generated interpretations.

Sources: `src/patchtrace/ui.py` (`open_sample`, function/finding selection and review controls); `src/patchtrace/sample.py`.
