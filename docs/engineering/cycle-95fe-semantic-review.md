# Cycle 95fe historical semantic review

Reviewed candidate: `ccc3664f11a81d3d30f907da36fc3d22da0063d0`. Main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.

Independent source/history reviewers accounted for nine retained scopes: eight
are semantically superseded; one already has no commits outside main ancestry.
No source/ref edits or tests were performed by these reviewers. Current runtime
evidence is separate. Preserve every branch and its historical documentation.

| Branch | Exact head | Scoped disposition |
| --- | --- | --- |
| `feat/tooltip-registry` | `0a3843ea2abe37d42ff0291d621fa9a7c9744bbc` | SUPERSEDED |
| `fix/pe-inspection-row-tooltips-20261013` | `0182a8035d64071fc88b5f299edc3ef3760946b5` | SUPERSEDED |
| `feature/gui-inspection-preview` | `8b94227a81b71841c65783c775f704a538d35710` | SUPERSEDED |
| `feat/acquisition-gui` | `7ae34d8fa26a6b6c8b7acf40f5c16d99643151ce` | SUPERSEDED |
| `feature/alpha-file-overview-20261013` | `476016590be5cd1315613759af18ff61c7c27851` | SUPERSEDED |
| `audit/core` | `fae13b2ed3043ddce00bbf387e386e93e7b3ee06` | SUPERSEDED |
| `audit/ai-reports` | `dd6402b9c00d5aae79f152f4fe5ce0fa8597dc24` | SUPERSEDED |
| `security/offline-bundle-no-overwrite-20261013` | `a39cab81de3e0eeadf57e6255d2fe3e131b3294a` | SUPERSEDED |
| `repair/project-create-rollback-20261105` | `2a3639adde50585dd7ac6dbcb029f085ac0856c6` | NO UNIQUE CODE |

Seven previously unresolved scopes and one patch-equivalent scope now have
source-level product dispositions; the ninth confirms an existing ancestor.
The frozen mechanical census is deliberately unchanged. Do not interpret these
reviews as whole-branch document equivalence, release acceptance or permission
to delete refs. [Structured details](cycle-95fe-semantic-review.json) retain
merge bases, exact paths and the scoped evidence.

## feat/tooltip-registry

All 143 original registry keys and three original templates remain; semantic application delegates to gui/tips.py; Files-dock test replaces the original overview dialog.

Current paths: `src/patchtrace/tooltips.py`, `src/patchtrace/gui/tips.py`, `tests/test_tooltips.py`.

## fix/pe-inspection-row-tooltips-20261013

Escaped overview.pe_row values, unavailable comparison explanation and Authenticode diagnostics survive model/view migration; original regression assertions retained.

Current paths: `src/patchtrace/ui_inspection.py`, `tests/test_inspection_row_tooltips.py`.

## feature/gui-inspection-preview

Cross-function/one-hunk navigation retained; semantic ACTION_TIPS replaces old visible-title tooltip dictionary. Test blob 55b7896f3888383d0c9986b787e0d5e92e8e7618 is donor-exact.

Current paths: `src/patchtrace/ui.py`, `tests/test_diff_navigation_extra.py`.

## feat/acquisition-gui

All original AcquisitionDialog methods remain; 18 have equal ASTs. Later changed methods add tooltip, destination admission and error handling. Test blob 561986a9edefe0841b3c3902d925077bf4fe1b40 is donor-exact.

Current paths: `src/patchtrace/ui.py`, `tests/test_ui_acquisition.py`.

## feature/alpha-file-overview-20261013

Pure preflight model blob 4d10eabe556e8de1bc3c7b1c840734996fa68086 and three pure tests retained; display migrated from dialog to registered Files dock.

Current paths: `src/patchtrace/preflight.py`, `src/patchtrace/ui.py`, `tests/test_preflight_overview.py`.

## audit/core

Strict JSON numbers, initialization rollback, foreign/older revision refusal, reserved annotation, backup recovery and cleanup incorporated through 1223cdd5517c2d49423210a6c7a35b5946679a07 / PR11. Audit test blob 1b3c2818fe9cb9cef343e09b57b269d837b59ce5 is donor-exact.

Current paths: `src/patchtrace/persistence.py`, `src/patchtrace/service.py`, `tests/test_audit_core.py`.

## audit/ai-reports

Total provider deadline and Windows-path-with-spaces metadata redaction incorporated through PR11; both original regression ASTs retained. Current transport additionally uses existing interruption wrapper.

Current paths: `src/patchtrace/providers.py`, `src/patchtrace/reports.py`, `tests/test_audit_ai_reports.py`.

## security/offline-bundle-no-overwrite-20261013

Exclusive os.link publication and competing-publisher preservation regression incorporated through 4d9fa9f06b1f744fc948413167a97f4241313666 / PR18; original regression AST retained.

Current paths: `src/patchtrace/offline_bundle.py`, `tests/test_offline_bundle.py`.

## repair/project-create-rollback-20261105

Donor ancestor of main and candidate; _remove_owned/_rollback_creation/ProjectService.create ASTs unchanged. Test blob 4e3c8fd77039825e9feac3a094413faca11d94e3 is donor-exact. GUI retry coverage already exists.

Current paths: `src/patchtrace/service.py`, `tests/test_audit116_create_rollback.py`, `tests/test_gui_creation_retry.py`.
