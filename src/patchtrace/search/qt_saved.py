"""Saved-query controls on the GUI owner thread; recent recall never submits a query."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..gui.qt.labels import PlainLabel, labelled
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip
from .errors import SearchError
from .limits import DEFAULT_LIMITS
from .query import parse_query
from .saved import RECENT_MAX, RecentQueries, dump_recent, load_recent, rerun_plan
from .saved_actions import bounded_recent, find_saved, project_store


class SettingsRecentStore:
    """Adapt the unchanged per-panel string-list API to RecentStore's bounded JSON interface."""

    def __init__(self, settings):
        self.settings = settings
        self.write_failed = False

    def load(self) -> str | None:
        try:
            return dump_recent(bounded_recent(self.settings.get_list('recent', (), max_items=RECENT_MAX)))
        except Exception:  # corrupt/unavailable settings must not stop an analyst query
            return None

    def store(self, text: str) -> None:
        self.write_failed = False
        try:
            self.settings.set('recent', list(bounded_recent(load_recent(text))))
        except Exception:
            self.write_failed = True


class NameDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle('Save search in this project')
        self.name = QLineEdit()
        self.name.setMaxLength(64)
        self.name.setAccessibleName('Saved query name')
        apply_tip(self.name, 'search.saved_name')
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        apply_tip(buttons.button(QDialogButtonBox.StandardButton.Save), 'search.save')
        apply_tip(buttons.button(QDialogButtonBox.StandardButton.Cancel), 'confirm.no')
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(labelled(self.name, 'Name (1–64 characters)'))
        layout.addWidget(self.name)
        layout.addWidget(buttons)


class SavedWidgets(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.save = self._button('Save query…', 'search.save')
        self.saved = self._combo('Saved queries in this project', 'search.saved')
        self.run = self._button('Run saved', 'search.saved_run')
        self.delete = self._button('Delete saved', 'search.saved_delete')
        self.recent = self._combo('Recent query text for this user', 'search.recent')
        self.clear = self._button('Clear recent text', 'search.recent_clear')
        self.note = PlainLabel('', wrap=True, limit=400)
        self.note.setAccessibleName('Saved query status')
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        saved = QHBoxLayout()
        saved.addWidget(self.save)
        saved.addWidget(labelled(self.saved, 'Saved in this project'))
        saved.addWidget(self.saved, 1)
        saved.addWidget(self.run)
        saved.addWidget(self.delete)
        recent = QHBoxLayout()
        recent.addWidget(labelled(self.recent, 'Recent text (this user)'))
        recent.addWidget(self.recent, 1)
        recent.addWidget(self.clear)
        root.addLayout(saved)
        root.addLayout(recent)
        root.addWidget(self.note)
        # Build the real dialog now so registry/a11y audits inspect its actual controls.
        self.name_dialog = NameDialog(self)

    @staticmethod
    def _button(text, tip):
        widget = QPushButton(text)
        widget.setAccessibleName(text)
        apply_tip(widget, tip)
        return widget

    @staticmethod
    def _combo(name, tip):
        widget = QComboBox()
        widget.setAccessibleName(name)
        widget.setMinimumContentsLength(12)
        widget.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        widget.view().setAccessibleName(name + ' options')
        apply_tip(widget, tip)
        return widget


class SavedController:
    def __init__(self, controller):
        self.controller = controller
        self.closed = False
        self.rows_owner = None
        self.widgets = SavedWidgets(controller.panel)
        controller.panel.layout().insertWidget(2, self.widgets)
        self.recent_store = SettingsRecentStore(controller.ctx.settings)
        self.recent = RecentQueries(self.recent_store)
        self.widgets.save.clicked.connect(lambda _checked=False: self.save_current())
        self.widgets.run.clicked.connect(lambda _checked=False: self.run_selected())
        self.widgets.delete.clicked.connect(lambda _checked=False: self.delete_selected())
        self.widgets.saved.currentIndexChanged.connect(lambda _index: self.enable())
        self.widgets.saved.activated.connect(lambda _index: controller.debounce.stop())
        self.widgets.recent.activated.connect(self.recall_recent)
        self.widgets.clear.clicked.connect(lambda _checked=False: self.clear_recent())
        self._refresh_recent()

    def owner(self):
        c = self.controller
        service = c.service()
        project = getattr(service, 'project', None)
        if self.closed or c.key is None or project is None or getattr(service, 'store', None) is None:
            return None
        return c.epoch, c.key, id(service), project.id, project.revision

    def _fresh(self, owner):
        if owner is not None and owner == self.owner():
            return True
        self._status('The project changed; select a current saved query and try again.')
        return False

    def _status(self, text):
        self.widgets.note.setText(text)
        self.controller.ctx.shell.announce(sanitize_text(text, 400))

    def _error(self, exc):
        self._status(exc.message if isinstance(exc, SearchError)
                     else f'Saved queries are unavailable ({type(exc).__name__}).')

    def project_changed(self):
        self.widgets.name_dialog.reject()
        self.widgets.name_dialog.name.clear()
        self.refresh()
        self._refresh_recent()

    def refresh(self):
        self.controller.debounce.stop()
        token = self.owner()
        self.rows_owner = None
        combo = self.widgets.saved
        combo.blockSignals(True)
        combo.clear()
        try:
            if token is not None:
                result = project_store(self.controller.service()).list()
                for item in result.items[:DEFAULT_LIMITS.saved_searches]:
                    combo.addItem(f'{sanitize_text(item.name, 64)} ({item.mode})', item.saved_id)
                self.rows_owner = token
                omitted = max(0, len(result.items) - DEFAULT_LIMITS.saved_searches)
                self.widgets.note.setText(f'{result.skipped} unreadable rows; {omitted} additional rows not shown.'
                                          if result.skipped or omitted else '')
        except Exception as exc:
            self._error(exc)
        finally:
            combo.blockSignals(False)
        self.enable()

    def save_current(self, name: str | None = None):
        c = self.controller
        c.debounce.stop()
        token = self.owner()
        if not self._fresh(token):
            return
        try:
            plan = c._plan()
            if name is None:
                dialog = self.widgets.name_dialog
                dialog.name.clear()
                if dialog.exec() != QDialog.DialogCode.Accepted:
                    return
                name = dialog.name.text()
            if not self._fresh(token):
                return
            project_store(c.service()).save(name, plan)
            self.refresh()
            self._status('Query saved in this project. Run saved executes it when requested.')
        except Exception as exc:
            self._error(exc)

    def run_selected(self, *, owner=None):
        c = self.controller
        c.debounce.stop()
        token = self.rows_owner if owner is None else owner
        if not self._fresh(token):
            return
        try:
            item = find_saved(project_store(c.service()), self.widgets.saved.currentData())
            plan = rerun_plan(item)
            self._load(plan)
            c.submit()
        except Exception as exc:
            self._error(exc)

    def delete_selected(self, *, owner=None):
        self.controller.debounce.stop()
        token = self.rows_owner if owner is None else owner
        if not self._fresh(token):
            return
        try:
            deleted = project_store(self.controller.service()).delete(self.widgets.saved.currentData())
            self.refresh()
            self._status('Saved query deleted; its history is retained.' if deleted
                         else 'That saved query was already absent; nothing changed.')
        except Exception as exc:
            self._error(exc)

    def _load(self, plan):
        c, panel = self.controller, self.controller.panel
        c.debounce.stop()
        c.tasks.cancel('search.query')
        for widget in (panel.query, panel.mode, panel.side, panel.scope):
            widget.blockSignals(True)
        try:
            panel.query.setText(plan.text)
            for widget, value in ((panel.mode, plan.mode), (panel.scope, plan.scope),
                                  (panel.side, plan.sides[0] if len(plan.sides) == 1 else None)):
                widget.setCurrentIndex(widget.findData(value))
        finally:
            for widget in (panel.query, panel.mode, panel.side, panel.scope):
                widget.blockSignals(False)
        c._reset_results()
        c._render()
        panel.query.setFocus()

    def remember(self, text):
        self.recent.add(text)
        self._refresh_recent()

    def _refresh_recent(self):
        combo = self.widgets.recent
        combo.blockSignals(True)
        combo.clear()
        combo.addItem('Choose recent text; press Enter to search', None)
        for text in self.recent.items():
            combo.addItem(text, text)
        combo.blockSignals(False)
        self.enable()

    def recall_recent(self, index):
        self.controller.debounce.stop()
        text = self.widgets.recent.itemData(index)
        if not text or self.controller.key is None or self.closed:
            return
        try:
            self._load(parse_query(text))
            self._status('Recent text recalled in automatic mode. Review it and press Enter to search.')
        except SearchError as exc:
            self._error(exc)
        self.widgets.recent.setCurrentIndex(0)

    def clear_recent(self):
        self.controller.debounce.stop()
        self.recent.clear()
        self._refresh_recent()
        self._status('Recent text could not be cleared because these settings could not be written.'
                     if self.recent_store.write_failed else
                     'Recent text cleared for this user. Project-owned saved queries remain available.')

    def enable(self):
        token = self.owner()
        selected = token is not None and token == self.rows_owner and self.widgets.saved.currentIndex() >= 0
        self.widgets.save.setEnabled(token is not None and bool(self.controller.panel.query.text().strip()))
        self.widgets.saved.setEnabled(token is not None)
        self.widgets.run.setEnabled(selected)
        self.widgets.delete.setEnabled(selected)
        self.widgets.recent.setEnabled(not self.closed and self.controller.key is not None)
        self.widgets.clear.setEnabled(not self.closed and self.widgets.recent.count() > 1)

    def shutdown(self):
        self.closed = True
        self.rows_owner = None
        self.widgets.name_dialog.reject()
        self.enable()
