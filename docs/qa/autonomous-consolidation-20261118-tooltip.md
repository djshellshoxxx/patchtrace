# Inventory tooltip coverage repair — 2026-11-18

Source baseline: `1418617a80d6057de11f985488cfe6043a7787a2` (PR #307).

The full hosted Linux suite failed because the shipped KB panel registers the
inventory dialog's tooltips, but the global control sweep never constructs that
dialog. A focused run reproduced the same failure before this change. The
dialog's controls already carry their registered tooltips.

The sweep now constructs the real `InventoryDialog` with the existing task owner
and temporary workspace. It inspects the real status label and tab container and
enumerates the dialog's controls with the unchanged global coverage assertion.
No registry entry is exempted, and no application behavior changes.

## Verification in this session

Runtime: Python 3.12, pytest 9.2.0, PySide6 6.12.0; Linux offscreen Qt.

```text
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_tooltips.py::test_every_registry_id_is_applied_somewhere --tb=short
Before change: 1 failed.

QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_tooltips.py tests/test_ui_kb_inventory.py \
  tests/test_ui_kb_inventory_retention.py --tb=short
After change: 51 passed in 9.84s.
```

An intermediate sweep correctly reported the still-unaccounted-for tab container;
that failure was resolved by inspecting the real container. These checks are
focused Linux coverage, not a full-suite or native Windows acceptance claim.
Original red, intermediate and final green logs and JUnit records accompany this
report in `autonomous-consolidation-20261118/tooltip/`.
