Read Hex, Binary, and Base64 views
Experimental. The reviewed tooltip registry and module index describe byte-oriented representations. Packaged behavior is UNVERIFIED.
Choose Hex, Binary, or Base64 in the representation selector. These views render bytes from the project-owned artifact copies after checking their recorded SHA-256 identities.
They do not encode the decompiled text.
The documented scopes are:
Scope	Meaning
Whole file	File bytes from the beginning of the artifact
Selected function entry	File bytes beginning at a mapped function entry


Function-entry scope does not establish the function’s complete extent. Bytes displayed after its actual end can belong to another function or data.
An entry must map through the PE section table to file-backed bytes. Virtual-only, ambiguous, or out-of-image addresses remain unavailable; a range must not be guessed.
Pages contain 4,096 bytes. Both sides use the same logical page position within their chosen scopes. Different file layouts can place corresponding instructions at different offsets.
Go to offset accepts a hexadecimal file offset and switches to whole-file scope. A file offset is different from an RVA or virtual address.
Check scope, side, offset, and artifact identity when copying observations. Matching page numbers do not establish matching function bodies.
If artifact verification fails, resolve the integrity issue before relying on displayed bytes. Do not bypass it by editing recorded hashes.
Sources: src/patchtrace/tooltips.py, viewer.*; docs/modules.md, artifact bytes and raw view entries.
