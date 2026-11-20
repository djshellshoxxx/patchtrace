# Independent review: recovered header help and evidence announcements

## Conclusion and source boundary

No blocking finding was identified in this selective recovery. This review covers
`83ed3471569f01a273c429fb055a0d27ec0fe3a8`, tree
`77810c95bc838ae5f3a517bb0cd1d790b93c36b6`, on
`codex/accessibility-recovery-20261120-2bad`. It reviews the recovered donor source
`b9adfa438e96e73ef61ec1248b9cd92fb4a49f73` and subsequent regression controls,
independently of the implementation worker. The original retained donor is
`f6f4c1dce74a7e7e506d9d23219bf7b2c9e6630f`.

The review branch changes only this document. Product source, tests, contracts,
thresholds and native acceptance gates were not changed by the reviewer.

## Findings

1. `ColumnSpec.tip_id` is appended after all nine existing constructor fields.
   Existing positional calls preserve their callback meanings. The new field is
   an optional static string registry identifier, not an external-input parser.
2. `headerData` checks orientation and bounds before registry access. Only the
   tooltip role with a nonempty identifier requests rich help. Unknown identifiers
   retain the title/unit fallback. Display and accessible header text do not
   consult the registry. Registered text uses the existing escaping renderer;
   all five entry fields were independently checked. Cell help and accessible
   text keep their original callbacks.
3. `EvidencePanel` adds an optional keyword-only announcer. Existing standalone
   construction remains valid. `EvidenceController` supplies its existing shell
   port, and the panel passes that port to its existing `StateView`. No second
   accessibility-event sender was introduced. The existing `StateView` policy
   compares the state-kind/text pair, suppresses repeated identical states and
   blank text, and sends errors assertively. Independently constructed panels
   keep separate announcers; changing a port's delivery method is observed on
   the next state transition.
4. **Scope limitation:** an AST scan found 90 direct named `ColumnSpec(...)`
   calls under `src`, with no explicit `tip_id` keyword or tenth positional
   argument. This recovery supplies header-help framework support. Existing
   application columns still require explicit registry identifiers to use it.
   Dynamic or aliased construction outside that static scan was not enumerated.
   The evidence announcement connection is implemented in the application host.

Actual Windows screen-reader output, clean-machine accessibility and whole-product
acceptance remain separate, unverified gates. This review makes no empirical
accuracy or native compatibility claim.

## Independent verification

| Selection | Result | Scope |
|---|---|---|
| Six maintained test files | 202 passed, 0 failed, 0 skipped; 17.86 seconds | Table/model, Qt-free preparation, evidence host, state view, tooltip integration and core import isolation |
| Fresh reviewer controls, final source | 9 passed, 0 failed, 0 skipped; 0.65 seconds | Positional compatibility, empty/unknown registry fallback, all-field escaping, role isolation, legacy panel construction and per-panel announcement delivery |
| Focused Ruff | Passed | Three product files, two maintained regression files and the independent controls |

The maintained selection overlaps the author's affected selection. The initial
reviewer-control run also passed the same nine cases in 0.61 seconds; it is not
additional coverage. Its first lint invocation found five E731 lambda bindings
in the disposable reviewer controls. Those bindings were rewritten as ordinary
functions and the final nine cases and Ruff passed. Product source was unchanged.

### Exact-source environment

A private environment at `/tmp/patchtrace-accessibility-review-2bad-venv` was
created with `python -m venv --without-pip`. Its local `.pth` lists the review's
`src` directory followed by the existing dependency site-packages. The nested
editable-install `.pth` in the shared dependency directory is not processed.
No shared environment was modified.

The private interpreter was explicitly checked with `-I`: `patchtrace.__file__`
resolved to `/tmp/PatchTrace-accessibility-review-2bad/src/patchtrace/__init__.py`.
It imported pytest 9.2.0 and PySide6 6.12.0. Consequently the maintained evidence
host's isolated `-I` subprocess exercised the reviewed source, rather than the
older source referenced by the original shared environment's editable install.
This is a bounded local review environment, not a clean external dependency
installation or Windows qualification.

### Commands

From the exact review worktree, with `PYTHONDONTWRITEBYTECODE=1` and
`QT_QPA_PLATFORM=offscreen`:

```text
/tmp/patchtrace-accessibility-review-2bad-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_gui_table.py tests/test_gui_table_spec.py tests/test_evidence_host.py tests/test_gui_state_view.py tests/test_gui_tips.py tests/test_gui_core_isolation.py --basetemp=/tmp/patchtrace-accessibility-review-2bad-maintained --junitxml=/tmp/patchtrace-accessibility-review-2bad-evidence/maintained.xml
/tmp/patchtrace-accessibility-review-2bad-venv/bin/python -m pytest -q -p no:cacheprovider /tmp/patchtrace-accessibility-review-2bad-evidence/test_peer.py --basetemp=/tmp/patchtrace-accessibility-review-2bad-peer-final --junitxml=/tmp/patchtrace-accessibility-review-2bad-evidence/peer-final.xml
/tmp/patchtrace-accessibility-review-2bad-venv/bin/python -m ruff check --no-cache src/patchtrace/gui/table_spec.py src/patchtrace/gui/qt/table.py src/patchtrace/ui_evidence.py tests/test_gui_table.py tests/test_evidence_host.py /tmp/patchtrace-accessibility-review-2bad-evidence/test_peer.py
```

## Source identities

| File | Git blob |
|---|---|
| `src/patchtrace/gui/table_spec.py` | `4bab0fb8013bbb32a3e5c0b58ac5bc02d8fade89` |
| `src/patchtrace/gui/qt/table.py` | `e90b3acd981fa7045b370a080b7e27694f4e01d9` |
| `src/patchtrace/ui_evidence.py` | `a97f981594e755f2dba42c8c220aaebb61732970` |
| `tests/test_gui_table.py` | `7a1cb7f1796a240cc7f37a93ab9c4aab4bcfbd05` |
| `tests/test_evidence_host.py` | `b6e03813877c8a1daf86973b3b8a08f45ee39f73` |

## Retained receipt identities

Scratch receipts are in `/tmp/patchtrace-accessibility-review-2bad-evidence`.
The complete independent control source is embedded below for reproduction if
those disposable files expire. The table identifies actual retained bytes.

| Receipt | Bytes | SHA-256 |
|---|---:|---|
| `maintained.xml` | 25189 | `6a127d0a6a61ceba6e058fec4207dcd5660f0761e564c6868ebb5323d0d3edb5` |
| `maintained.log` | 261 | `7e6f3210bf1b376f58daa11df068ed0ec358337188e020f174ebba55f7bd4180` |
| `peer-final.xml` | 1694 | `1b766c84fee7446931c14102688178a26a3ff81e7bf5691364a1e0f13fdc38a4` |
| `peer-final.log` | 98 | `e3c9d8a2ed98e75df3f95f33132e7db857874cf66009f1cf745da1eb608896b3` |
| `ruff.log` | 19 | `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18` |
| `test_peer.py` | 4857 | `01b002803a44bf0bf4b491caf192aa49409c09d9a242e380b826517e592278c9` |

## Reproducible independent controls

```python
"""Independent local controls for the recovered header-help/announcement slice."""
import html
from dataclasses import fields
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget

from patchtrace import tooltips
from patchtrace.gui.qt.table import VirtualTableModel
from patchtrace.gui.table_spec import ColumnSpec, TableSpec, prepare_table
from patchtrace.ui_evidence import EvidencePanel


def model(column):
    result = VirtualTableModel()
    spec = TableSpec(lambda row: row, lambda row: row)
    result.set_prepared(prepare_table(spec, (column,), ('value',)))
    return result


@pytest.mark.parametrize('tip_id', ['', 'peer.unregistered', '0'])
def test_missing_header_id_keeps_units_and_plain_accessibility(qapp, tip_id):
    table = model(ColumnSpec('key', 'Column', str, unit='bytes', tip_id=tip_id))
    horizontal = Qt.Orientation.Horizontal
    assert table.headerData(0, horizontal, Qt.ItemDataRole.ToolTipRole) == 'Column (bytes)'
    assert table.headerData(0, horizontal, Qt.ItemDataRole.AccessibleTextRole) == 'Column (bytes)'
    assert table.headerData(0, horizontal, Qt.ItemDataRole.DisplayRole) == 'Column\nbytes'


def test_old_positional_columns_keep_their_callback_slots(qapp):
    def text(value):
        return value

    def sort(value):
        return value

    def chip(value):
        return 'chip'

    def accessible(value):
        return 'accessible cell'

    def tooltip(value):
        return '<p>cell help</p>'

    column = ColumnSpec('key', 'Column', text, 'units', 7.5, sort, chip, accessible, tooltip)
    assert (column.text, column.sort_key, column.chip, column.accessible, column.tooltip) == (
        text, sort, chip, accessible, tooltip)
    assert column.tip_id == ''
    assert [field.name for field in fields(ColumnSpec)][-1] == 'tip_id'
    table = model(column)
    assert table.index(0, 0).data(Qt.ItemDataRole.ToolTipRole) == '<p>cell help</p>'
    assert table.index(0, 0).data(Qt.ItemDataRole.AccessibleTextRole) == 'accessible cell'


def test_empty_registered_render_uses_the_existing_fallback(qapp, monkeypatch):
    monkeypatch.setattr(tooltips, 'tooltip', lambda _tip_id: '')
    table = model(ColumnSpec('key', 'Column', str, unit='bytes', tip_id='peer.empty'))
    assert table.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.ToolTipRole) == 'Column (bytes)'


def test_every_registered_field_is_escaped_by_the_existing_renderer(qapp, monkeypatch):
    values = ('<what>&', '<why>"', '<effect>\'', '<source>&', '<available>')
    monkeypatch.setitem(tooltips.REGISTRY, 'peer.fields', tooltips.TooltipEntry(*values))
    table = model(ColumnSpec('key', 'Column', str, tip_id='peer.fields'))
    rendered = table.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.ToolTipRole)
    for value in values:
        assert html.escape(value) in rendered
        assert value not in rendered


def test_plain_header_roles_never_access_the_tooltip_registry(qapp, monkeypatch):
    def unavailable(_tip_id):
        raise AssertionError('plain header roles must not request rich help')

    monkeypatch.setattr(tooltips, 'tooltip', unavailable)
    table = model(ColumnSpec('key', 'Column', str, tip_id='peer.unavailable'))
    assert table.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole) == 'Column'
    assert table.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.AccessibleTextRole) == 'Column'
    assert table.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.DecorationRole) is None


def test_standalone_old_panel_constructor_needs_no_announcer(qtbot):
    parent = QWidget()
    qtbot.addWidget(parent)
    panel = EvidencePanel(None, parent, bindiff_setup=False)
    assert panel.parent() is parent
    panel.set_failed('Standalone failure')
    panel.set_loading(False)
    assert 'Standalone failure' in panel.state_view.model.text


def test_announcer_is_per_panel_and_is_resolved_at_delivery(qtbot):
    first, second, replacement = [], [], []
    a = SimpleNamespace(announce=lambda text, *, assertive=False: first.append((text, assertive)))
    b = SimpleNamespace(announce=lambda text, *, assertive=False: second.append((text, assertive)))
    left = EvidencePanel(bindiff_setup=False, announcer=a)
    right = EvidencePanel(bindiff_setup=False, announcer=b)
    qtbot.addWidget(left)
    qtbot.addWidget(right)
    first.clear()
    second.clear()
    left.set_failed('Left failure')
    assert first == [(left.state_view.model.text, True)] and second == []
    a.announce = lambda text, *, assertive=False: replacement.append((text, assertive))
    left.set_failed('Later left failure')
    assert replacement == [(left.state_view.model.text, True)] and second == []
    right.set_failed('Right failure')
    assert second == [(right.state_view.model.text, True)]
```

## Integration disposition

The coordinator may integrate this scoped recovery and this note, subject to the
final combined-source checks and applicable hosted/native gates. These focused
passes do not establish a full-suite pass or grant main-merge/release acceptance.
The existing suite-interruption investigation and all unrelated repository
blockers retain their separate recorded status.
