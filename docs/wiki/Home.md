# PatchTrace Wiki

PatchTrace compares two Windows x64 PE binaries (older and newer), runs Ghidriff/Ghidra static
analysis, lets you match and review changed functions, and can optionally produce evidence-linked
AI hypotheses. It is a local desktop app; no target binary is executed.

- [User Guide](User-Guide)
- [Developer Guide](Developer-Guide)
- [Architecture and Design Rationale](Architecture-and-Design-Rationale)
- [Codebase Map](Codebase-Map)

The full README is at the repository root. Authoritative specs are in `docs/specs/`; the module
index is `docs/modules.md`.

Important: a function change, matching score or model assessment does not establish that a
vulnerability exists.
