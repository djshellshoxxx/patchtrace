Strings panel
Planned. The WB3 plan defines string extraction and comparison controls. The panel declaration was unavailable during review. Implemented and packaged coverage is UNVERIFIED.
The planned entry shortcut is Ctrl+Shift+T. Start with the built-in scan for plain strings. FLOSS is a separate optional tool for additional extraction methods.
Running FLOSS with emulation requires an explicit review step. It is distinct from the built-in byte scan and must not start merely because the panel opens.
Before reading differences, inspect the comparison basis. The two sides need compatible extraction settings. A blocked basis requires rescanning with matching settings rather than interpreting inconsistent inventories.
Planned row labels distinguish Only in newer, Only in older, Edited, In both, and Not compared. If a scan hits its limit, missing strings remain unresolved; they must not become definite added or removed claims.
Filter by side, change, type, cue, length, text, or selected function. The detail view records links and provenance. Function attribution can be unavailable or indirect.
Planned actions include opening an attributed function, opening an available byte offset, copying escaped text, and explicitly requesting exact text. Secret-looking values are redacted by default.
No differences means no differences within that scan’s coverage. Text stored in unsupported encodings, compressed data, or encrypted data can remain outside it.
UNVERIFIED: final dock placement differs between the older feature plan and the central manifest.
Sources: docs/specs/program-e/WB3-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.
