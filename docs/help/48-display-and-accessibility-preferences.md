# Adjust display and accessibility preferences

Experimental: the reviewed framework source implements theme and motion handling. Real Windows behavior with your package, assistive technology, and display settings is UNVERIFIED.

The newer framework provides `View → Theme` choices for `Dark` and System. This supersedes the older core UI specification’s statement that theme selection is planned, for builds containing that implementation.

Windows high contrast overrides the selected variant. The framework removes its custom stylesheet and uses platform colors. Status meaning remains available through text, glyphs, and shape.

The theme controller also reads the platform reduced-motion preference and adjusts supported Qt interface animations. This does not establish that every feature-specific movement has passed manual acceptance.

Use `Setup → Code font size` to change code text within the documented 8–28-point range. This setting does not replace Windows display scaling or guarantee that every interface element scales identically.

For keyboard use, follow the visible focus indicator. Table headers, values, states, and short control descriptions are intended to be exposed through Windows accessibility interfaces.

A tooltip must not be the only way to discover a required action or limitation. Read adjacent status and explanatory text as well.

> UNVERIFIED: NVDA, Narrator, high contrast, reduced motion, and 100/150/200-percent DPI acceptance require recorded checks on the Windows build being distributed.

Sources: src/patchtrace/gui/qt/theme.py; docs/specs/program-e/GUI-integration-plan.md, sections 8.6–8.7; docs/specs/ui.md.
