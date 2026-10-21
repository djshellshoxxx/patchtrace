# Import an existing Ghidriff comparison

Use `Import JSON` when a comparison has already been produced elsewhere. Import reviews existing analysis output; it does not rerun the native comparison backend.

Prepare a PatchTrace project containing the exact older and newer binaries used for that output. Artifact identities and orientation must agree.

1. Create or open the corresponding project.
2. Wait for any active operation to finish.
3. Select `Import JSON.`
4. Choose the raw Ghidriff comparison JSON.
5. Wait for validation and normalization.
6. Read the final status before inspecting the imported matches.

Raw comparison output commonly appears in Ghidriff’s output json directory with a `.ghidriff.json` filename. Select the actual comparison document rather than a rendered HTML or Markdown report.

A PatchTrace exported report is also a different format. Renaming a report to .json does not make it an importable Ghidriff comparison.

If import is rejected, check the binary hashes, older/newer direction, and upstream output contract. Renaming an unrelated binary does not repair an identity mismatch. The README identifies a pinned Ghidriff integration baseline; output from another revision may require compatibility verification.

Validation and import run in the background. Failed or cancelled attempts must preserve prior committed results.

Imported fields can be unavailable. In particular, an instruction hash cannot supply an assembly listing. Treat an explicit unavailable label as a limit of the retained evidence.

Sources: `README.md,` “Import a comparison made elsewhere”; `docs/specs/ui.md;` `docs/qa.md.`
