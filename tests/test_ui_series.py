"""SPEC-09b section 9: Series window states, filtering, intents and teardown (offscreen)."""
import threading

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QGuiApplication
from test_nway_series import builds  # noqa: F401, F811  (fixture reuse)
from test_nway_view_model import FakeReader, ids, ok, series_file  # noqa: F401, F811
from test_tooltips import audit

from patchtrace import ui_series
from patchtrace.nway.contracts import ChainEvent
from patchtrace.nway.pair_access import PairSnapshot
from patchtrace.nway.view_model import ChainRow, HopView, LoadedSeries
from patchtrace.ui_series import SeriesWindow


@pytest.fixture
def settings(tmp_path):
    return QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)


def make(qtbot, path, snapshots, settings=None):
    reader = snapshots if hasattr(snapshots, 'read') else FakeReader(snapshots)
    window = SeriesWindow(path, settings, reader)
    qtbot.addWidget(window)
    qtbot.waitUntil(lambda: window.loaded is not None, timeout=5000)
    window.reader_probe = reader
    return window


def test_ready_state_shows_table_and_scores(qtbot, series_file):  # noqa: F811
    path, series = series_file
    first, second = ids(series)
    window = make(qtbot, path, {0: ok({first: 70}), 1: ok({second: 40})})
    window.show()
    assert window.view.state == 'ready' and window.splitter.isVisible() and not window.banner.isVisible()
    assert window.chain_model.rowCount() == 1 and window.chain_model.data(window.chain_model.index(0, 2)) == '70'
    window.chain_table.selectRow(0)
    assert window.hop_model.rowCount() == 2
    assert window.hop_model.data(window.hop_model.index(0, 6)) == '70'
    assert 'Attention score' in window.hop_model.data(window.hop_model.index(0, 6), Qt.ItemDataRole.ToolTipRole)
    assert not window.progress.isVisible()


def test_partial_banner_names_the_pair_and_scores_show_na(qtbot, series_file):  # noqa: F811
    path, series = series_file
    _, second = ids(series)
    window = make(qtbot, path, {0: PairSnapshot('locked', 'locked by another PatchTrace window'),
                                1: ok({second: 40})})
    window.show()
    assert window.view.state == 'partial' and window.banner.isVisible()
    assert window.banner.text().startswith('Warning:') and 'pair 0->1: locked by another' in window.banner.text()
    window.chain_table.selectRow(0)
    assert window.hop_model.data(window.hop_model.index(0, 6)) == 'n/a'
    assert 'cannot be read' in window.hop_model.data(window.hop_model.index(0, 6), Qt.ItemDataRole.ToolTipRole) \
        or 'locked' in window.hop_model.data(window.hop_model.index(0, 6), Qt.ItemDataRole.ToolTipRole)


def test_stale_state_banner_and_open_pair_stays_enabled(qtbot, series_file, tmp_path):  # noqa: F811
    path, series = series_file
    for ref in series.pair_projects:
        (path.parent / ref.path).rename(tmp_path / f'moved-{ref.from_ordinal}')
    window = make(qtbot, path, {0: PairSnapshot('changed', 'project changed since the series was computed'),
                                1: PairSnapshot('changed', 'project changed since the series was computed')})
    window.show()
    assert window.view.state == 'stale' and 'out of date' in window.banner.text()
    assert 'series create' in window.banner.text()
    window.chain_table.selectRow(0)
    window.hop_table.selectRow(0)
    assert window.open_pair.isEnabled()


def test_failed_and_empty_states(qtbot, series_file, tmp_path, builds, capsys):  # noqa: F811
    path, _ = series_file
    path.write_text('{')
    window = make(qtbot, path, {})
    window.show()
    assert window.view.state == 'failed' and window.message.isVisible() and not window.splitter.isVisible()
    assert 'PT-NWAY-STORAGE' in window.message.text() and '--replace-corrupt' in window.message.text()
    from test_nway_series import create
    root = tmp_path / 'empty'
    assert create(capsys, builds[:3], root)[0] == 0
    snap = PairSnapshot('no-run', 'pair has no completed run')
    window = make(qtbot, root / 'series.json', {0: snap, 1: snap})
    window.show()
    assert window.view.state == 'empty' and window.message.text().startswith('No 1:1 chain')
    assert window.message.isVisible() and not window.splitter.isVisible()


def test_loading_state_then_ready(qtbot, series_file):  # noqa: F811
    path, series = series_file
    gate = threading.Event()

    class Slow(FakeReader):
        def read(self, *args):
            gate.wait(5)
            return super().read(*args)

    window = SeriesWindow(path, None, Slow({0: ok({}), 1: ok({})}))
    qtbot.addWidget(window)
    window.show()
    assert window.progress.isVisible() and not window.chain_table.isEnabled() and window.cancel_button.isEnabled()
    gate.set()
    qtbot.waitUntil(lambda: window.loaded is not None, timeout=5000)
    assert not window.progress.isVisible() and window.chain_table.isEnabled()


def test_filter_and_sort_do_not_touch_disk(qtbot, series_file):  # noqa: F811
    path, series = series_file
    first, second = ids(series)
    window = make(qtbot, path, {0: ok({first: 70}), 1: ok({second: 40})})
    calls = window.reader_probe.calls
    window.filter_text.setText('zzz-no-such-function')
    assert window.chain_model.rowCount() == 0 and window.view.hidden_by_filter == 1
    window.filter_text.setText('')
    window.min_score.setValue(90)
    assert window.chain_model.rowCount() == 0
    window.min_score.setValue(0)
    window.only_stale.setChecked(True)
    assert window.chain_model.rowCount() == 0
    window.only_stale.setChecked(False)
    window.sort.setCurrentIndex(3)
    window.filter_status.setCurrentIndex(1)
    assert window.chain_model.rowCount() == 1
    assert window.reader_probe.calls == calls


def test_open_pair_signal_payload_and_button_rules(qtbot, series_file):  # noqa: F811
    path, series = series_file
    first, second = ids(series)
    window = make(qtbot, path, {0: ok({first: 70}), 1: PairSnapshot('missing', 'pair project is missing')})
    assert not window.open_pair.isEnabled() and not window.copy_chain.isEnabled()
    window.chain_table.selectRow(0)
    assert window.copy_chain.isEnabled() and not window.open_pair.isEnabled()
    window.hop_table.selectRow(1)
    assert not window.open_pair.isEnabled()
    window.hop_table.selectRow(0)
    assert window.open_pair.isEnabled()
    with qtbot.waitSignal(window.open_pair_requested) as blocker:
        window.open_pair.click()
    assert blocker.args == [str(path.parent / series.pair_projects[0].path), first]


def test_copy_chain_is_plain_text_with_hash_prefixes(qtbot, series_file):  # noqa: F811
    path, series = series_file
    window = make(qtbot, path, {0: ok({}), 1: ok({})})
    window.chain_table.selectRow(0)
    window.copy_chain.click()
    text = QGuiApplication.clipboard().text()
    assert series.builds[0].artifact_sha256[:12] in text and series.builds[0].artifact_sha256[:13] not in text
    assert 'inferred hypothesis' in text and series.builds[1].label in text


def test_close_during_load_tears_down_thread_cleanly(qtbot, series_file):  # noqa: F811
    path, _ = series_file
    gate = threading.Event()

    class Blocking(FakeReader):
        def read(self, *args):
            gate.wait(5)
            return super().read(*args)

    window = SeriesWindow(path, None, Blocking({0: ok({}), 1: ok({})}))
    qtbot.addWidget(window)
    thread = window.thread
    assert thread is not None and thread.isRunning()
    gate.set()
    window.close()
    qtbot.waitUntil(lambda: thread.isFinished(), timeout=5000)
    qtbot.waitUntil(lambda: thread not in ui_series._LIVE_THREADS, timeout=5000)
    assert window.thread is None


def test_reload_cancels_previous_load(qtbot, series_file):  # noqa: F811
    path, _ = series_file
    gate = threading.Event()

    class Blocking(FakeReader):
        def read(self, *args):
            gate.wait(5)
            return super().read(*args)

    window = SeriesWindow(path, None, Blocking({0: ok({}), 1: ok({})}))
    qtbot.addWidget(window)
    first = window.thread
    window.reload()
    assert first.cancel.is_set() and window.thread is not first
    gate.set()
    qtbot.waitUntil(lambda: window.loaded is not None, timeout=5000)
    qtbot.waitUntil(lambda: first not in ui_series._LIVE_THREADS, timeout=5000)


def test_untrusted_labels_render_as_plain_text(qtbot, series_file):  # noqa: F811
    path, _ = series_file
    window = make(qtbot, path, {0: ok({}), 1: ok({})})
    nasty = '<b>x</b>\x1b[31m'
    hop = HopView(0, 1, nasty, '<i>c</i>', ('<u>t</u>',), '<b>1</b>', False, nasty, nasty, None, None, None,
                  'no-ranking', 'm', 'ok', '<b>why</b>')
    row = ChainRow('a' * 64, nasty, (hop,), 'inferred', False, 'x', (), (ChainEvent(kind='split', ordinal=1),),
                   None, None, 0, 1, True)
    window.loaded = LoadedSeries('ready', '', rows=(row,))
    window.requery()
    shown = window.chain_model.data(window.chain_model.index(0, 0))
    assert '<b>x</b>' in shown and '\x1b' not in shown
    window.chain_table.selectRow(0)
    tip = window.hop_model.data(window.hop_model.index(0, 6), Qt.ItemDataRole.ToolTipRole)
    assert '<b>why</b>' not in tip and '&lt;b&gt;why' in tip
    for label in (window.banner, window.message):
        assert label.textFormat() == Qt.TextFormat.PlainText


def test_every_series_control_has_registry_tooltip(qtbot, series_file):  # noqa: F811
    path, _ = series_file
    window = make(qtbot, path, {0: ok({}), 1: ok({})})
    covered = audit(window)
    assert {'series.reload', 'series.chain_table', 'series.hop_table', 'series.open_pair'} <= covered
    assert window.objectName() == 'series.window'
