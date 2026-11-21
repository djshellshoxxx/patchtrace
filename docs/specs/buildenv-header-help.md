# Build environment table header help

Status: bounded implementation contract, 2026-11-21.

This extends the Build environment presentation in
[the DIE integration plan, section 8](program-e/DIE-integration-plan.md) and the
existing registered-header mechanism in
[the GUI integration plan](program-e/GUI-integration-plan.md). It changes the
help available on the five existing table headings, not the build-fact model,
comparison, parsing, tool execution, or stored data.

## Required behavior

Every prepared Build environment table exposes the matching registered tooltip
through its horizontal `ToolTipRole`, both with no rows and after results arrive:

| Existing heading | Registry ID | Meaning |
| --- | --- | --- |
| Fact | `build_env.col.fact` | The build-environment property described by the row. |
| OLDER | `build_env.col.older` | The recorded value shown for the older file; a dash means no value is shown for that side. |
| NEWER | `build_env.col.newer` | The recorded value shown for the newer file; a dash means no value is shown for that side. |
| Status | `build_env.col.status` | The row's comparison state: changed, added, removed, same, or unknown (one side). Unknown is not a difference. |
| Basis | `build_env.col.basis` | The recorded source or sources supporting the fact comparison. Signatures and header fields do not prove how a file was built. |

These are static `TooltipEntry` values in the panel's existing `TIPS` dictionary,
registered through the existing panel/controller registration. Column declarations
refer to them with `ColumnSpec.tip_id`; no new registration or rendering mechanism
is introduced. The declaration and help data remain importable without Qt.

Help describes the displayed row without claiming that every value is known,
that unknown or missing values represent a change, or that the entire toolchain
can be identified conclusively. The panel's loading, incomplete, stale and error
messages remain authoritative about the available results.

## Preserved behavior

- Display and accessible header labels remain exactly `Fact`, `OLDER`, `NEWER`,
  `Status`, and `Basis`, in that order.
- Cell display, accessible text, cell tooltips, sort/filter behavior, row keys,
  selection, and plain-text copying remain unchanged.
- The existing tooltip registry escapes rich-text metacharacters. Unknown or
  unregistered help IDs retain the framework's title fallback.
- Reading help performs no file read, network request, tool execution, project
  mutation, or persistence operation.
- Native screen-reader output, high contrast, DPI behavior and Windows desktop
  acceptance remain separate manual/native gates.

## Verification

Use actual Build environment controllers and table models to verify all five
horizontal header roles before and after result publication. Observe registration
through the real panel host as well as an isolated controller; merely finding
five string IDs in source is insufficient.

Confirm unchanged display/accessibility labels and representative cell/copy
behavior, and cover registry escaping and a removed-column-mapping control.
Keep the initial missing-help failure and final passing source identities.
The application's registry-coverage audit must observe actual header help after
the host initializes this panel, without new tooltip exemptions. Schema generation
is unnecessary because no stored or wire contract changes.
