# Import an existing comparison

Import JSON reuses raw Ghidriff output generated elsewhere. First open or create a project for the exact binary pair used by that comparison. Check the older/newer orientation and recorded artifact identities before choosing the file.

Choose Import JSON, select the raw comparison JSON, and wait for validation. A rendered HTML or Markdown report is not raw comparison input. A PatchTrace report export is also a different format. Renaming an unrelated file does not establish ownership or orientation.

The importer preserves the raw input and normalizes supported records. Invalid or incompatible output is rejected rather than guessed into the current contract. Earlier committed results remain available after failure. Read the retained diagnostic message and determine whether the problem is the selected file, a different artifact pair, or an upstream output version.

Unavailable assembly or decompiled text remains unavailable after import. An instruction hash cannot supply missing instruction text. Use Metadata or [verified raw bytes](05-code-and-bytes.md) when those representations answer your question; they do not replace decompilation.

After a successful import, inspect a known function relationship and its run provenance before interpreting other rows. Importing data is not independent validation of the engine's proposed matches.

Source: [README import procedure](../../README.md) and [desktop specification](../specs/ui.md). **UNVERIFIED:** a live import, supported upstream version compatibility, error rendering, and packaged file-picker behavior were not exercised for these pages.
