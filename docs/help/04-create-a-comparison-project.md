# Create a comparison project

Create a project from two versions of the same Windows binary. Choose their chronological direction explicitly; PatchTrace does not infer older and newer from filenames or dates.

1. Select `New,` or press `Ctrl+N.`
2. Enter a project name.
3. Choose the file for Older PE x64.
4. Choose the file for Newer PE x64.
5. Select an absent or empty `New project` directory.
6. Review the two input paths.
7. If reversed, use `Swap older and newer` in the dialog.
8. Select `Create project.`

You can browse for inputs or drop a local file into its corresponding field. Check which field receives the file before creating the project.

Creation validates the binaries, computes their hashes, and stores project-owned copies. Your original files remain unchanged. Use `Open` to resume an existing project rather than selecting its directory as a new destination.

If creation rejects an input, check its actual architecture and file format. A .dll, .exe, or .sys extension is insufficient. The documented initial contract requires PE AMD64.

If creation rejects the destination, choose a new directory or inspect why the selected directory contains existing material. **Do not empty a project directory to force creation.**

After creation, confirm the artifact headers before running analysis. Reversing an existing project is a separate operation with consequences for interpretation context.

Sources: `README.md,` “Create a project”; `docs/specs/ui.md;` `AGENTS.md.`
