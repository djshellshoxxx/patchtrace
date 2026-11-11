# Files panel

Experimental. The reviewed source contains the Files panel declaration and controller. It replaces an earlier file-overview dialog. Packaged availability is UNVERIFIED.

The Files panel compares recorded project fields and parsed PE information for the older and newer artifacts. It provides structural context before, or without, a Ghidriff comparison.

Open a project before using the panel. Recorded fields can appear while the bounded inspection of project-owned artifact copies is still running.

Check identity first: confirm the intended older and newer files, their recorded hashes, and the available size and metadata fields. Then inspect the parsed comparison.

The module index describes inspection of PE headers, sections, directories, imports, exports, entropy, overlay, and certificate-table information. Individual fields can be unavailable or rejected when input structure cannot be read.

A certificate table’s presence does not establish a valid signature or publisher trust. The module index places Authenticode trust checking in a separate Windows-specific component. UNVERIFIED: availability and native acceptance of that check in your release.

Likewise, entropy or section layout can suggest packaging characteristics without establishing a particular packer or compressed payload.

If one side fails inspection, read its error and retain the other side’s available information. **Do not interpret a missing value as zero or an unchanged field.**

This panel reads files without executing target code or modifying the project. A completed structural inspection does not establish that function analysis will succeed.

Sources: src/patchtrace/pe_overview/panel.py; src/patchtrace/ui_inspection.py; docs/modules.md.
