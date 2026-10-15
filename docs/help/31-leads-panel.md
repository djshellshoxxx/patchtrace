# Leads panel

Experimental. The reviewed source contains the Leads panel, controller, and read model. Availability in a particular desktop release is UNVERIFIED.

Use `Ctrl+Shift+L` when available. Leads organizes changed functions into an explainable reading order using stored comparison results, advisories, and previously computed signals.

Choose an advisory context or No advisory (code evidence only). A different context can produce a different ordering for the same functions.

The documented classes are:

| Class | How to read it |
|---|---|
| `Fits advisory` | Stored evidence meets the workflow’s advisory-fit rules |
| `Needs review` | Conflicting or contested evidence requires inspection |
| `Partial fit` | Some expected evidence or applicability remains unresolved |
| `Code change` | A change is recorded without advisory-fit assessment |
| `Changed, no fit` | The function remains in the review queue without an established fit |

A class does not establish that a function contains or fixes the selected CVE.

Select a lead to inspect supporting observations, counterevidence, unknowns, and alternatives. Tied leads share a rank range; **do not infer a stronger distinction within that tie.**

`Prepare leads` computes a derived result from stored inputs. `Refresh` reloads stored results. Neither action downloads advisories or runs an external analysis tool.

Pinning changes presentation while preserving the lead’s class. Dismissal records a review event without deleting the lead. `Show dismissed leads` to restore one.

Read applicability and multiple-CVE notices before assigning a change to one advisory.

Sources: src/patchtrace/pilot/panel.py; src/patchtrace/pilot/read_model.py; src/patchtrace/ui_leads.py.
