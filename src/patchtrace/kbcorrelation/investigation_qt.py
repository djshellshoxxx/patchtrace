"""Investigation dialog; workers own explicit source requests and no widgets or SQLite objects."""
from __future__ import annotations

import time
from dataclasses import replace
from functools import partial
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..gui.qt.labels import PlainLabel, SafeTextView
from ..gui.qt.tasks import TaskRunner
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip, register_tips
from ..tooltips import TooltipEntry
from .investigation_service import InvestigationRequest, InvestigationResult, execute_request
from .store import default_workspace

SOURCE = ('Local advisory workspace and inspected local PE files. Optional MSRC advisory downloads require '
          'an exact preview and separate consent; binary inputs remain local.')
DESCRIPTIONS = {
    'workspace': 'Directory containing the local advisory workspace.',
    'source': 'Local supported advisory document to import.',
    'lead': 'KB or CVE identifier to search in the stored documents.',
    'scope': 'Explicit product, architecture and release used for this comparison.',
    'months': 'Explicit advisory months to preview, separated by commas, such as 2026-09,2026-10.',
    'plan_sources': 'Preview exact monthly MSRC advisory requests without accessing the network.',
    'sync_sources': 'Consent once to fetching exactly the displayed advisory URLs, hosts and plan digest.',
    'older': 'Older local AMD64 PE binary; its bytes are inspected and never executed.',
    'newer': 'Newer local AMD64 PE binary; its bytes are inspected and never executed.',
    'destination': 'New or empty directory outside the currently open project.',
    'name': 'Name for the new comparison project.',
    'manual_pair_start': 'Start from two local files with unverified product lineage and no advisory linkage.',
    'same_component': 'Explicitly confirm differently named files represent the same component.',
    'import': 'Import the chosen local advisory into the workspace.',
    'search': 'Search stored advisory documents without accessing the network.',
    'use_current': 'Verify and use the currently open project input copies; origin is preview-only.',
    'preview': 'Inspect the chosen local pair and display its hashes and limitations.',
    'create': 'Create a separate project using exactly the current pair preview.',
    'cancel': 'Cancel pending work, or retain a project whose commit already started.',
    'close': 'Close the investigation without replacing the currently open project.',
    'details': 'Plain-text coverage, source evidence, pair hashes and operation results.',
    'status': 'Current local investigation status.',
    'browse_workspace': 'Choose the local advisory workspace directory.',
    'browse_source': 'Choose a local advisory JSON or compressed JSON file.',
    'browse_older': 'Choose the older local binary.',
    'browse_newer': 'Choose the newer local binary.',
    'browse_destination': 'Choose a parent directory for a new comparison folder.',
}
TIPS = {f'kb.investigation.{key}': TooltipEntry(text, 'Keeps the local investigation explicit and inspectable.',
                                             ('Only the exact consented advisory plan is fetched; targets are not run.'
                                              if key == 'sync_sources' else
                                              'Local operation only; target binaries are not run.'), SOURCE)
        for key, text in DESCRIPTIONS.items()}


class InvestigationDialog(QDialog):
    def __init__(self, parent=None, *, workspace=None, tasks=None, on_created=None, current_project=None,
                 execute=execute_request, notice=None, current_inputs=None, is_current=None):
        super().__init__(parent)
        register_tips(TIPS)
        self.setWindowTitle('Investigate KB/CVE or local pair')
        self.resize(920, 760)
        self.tasks = tasks if tasks is not None else TaskRunner(self)
        self._own_tasks = tasks is None
        self._execute, self._on_created, self._notice = execute, on_created, notice
        self._available_current, self._input_origin = current_inputs, None
        self._is_current = is_current if is_current is not None else lambda: True
        self._current_project = Path(current_project) if current_project is not None else None
        self._channel = f'kb.investigation.{id(self)}'
        self._generation, self._closed = 0, False
        self._pending = None
        self._preview = None
        self._online_plan = None
        self._investigation_id = None
        self._cancel_create, self._close_after_create = False, False
        root = QVBoxLayout(self)
        heading = PlainLabel('Search a local KB/CVE advisory and choose a product, or start from local files. '
                             'Preview older/newer files before creating a separate comparison. '
                             'Optional advisory downloads require a separate preview and consent. '
                             'Binary files remain local and are never executed.',
                             wrap=True)
        root.addWidget(heading)
        self.manual_pair_start = QCheckBox('Start from local files without advisory linkage')
        self._tip(self.manual_pair_start, 'manual_pair_start')
        self.manual_pair_start.toggled.connect(self._mode_changed)
        root.addWidget(self.manual_pair_start)
        form = QFormLayout()
        tab_order = [self.manual_pair_start]
        self.fields = {}
        self.buttons = {}
        values = {'workspace': str(workspace if workspace is not None else default_workspace()),
                  'source': '', 'lead': '', 'older': '', 'newer': '', 'destination': '', 'name': 'KB comparison'}
        for key, title in (('workspace', 'Advisory &workspace'), ('source', '&Advisory file'), ('lead', '&KB/CVE'),
                           ('older', '&Older local binary'), ('newer', '&Newer local binary'),
                           ('destination', 'New project &directory'), ('name', 'Project na&me')):
            field = self.fields[key] = QLineEdit(values[key])
            self._tip(field, key)
            tab_order.append(field)
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(field, 1)
            if key in {'workspace', 'source', 'older', 'newer', 'destination'}:
                button = self._button('browse_' + key, 'Browse…')
                button.clicked.connect(lambda _checked=False, k=key: self._browse(k))
                layout.addWidget(button)
                tab_order.append(button)
            if key in {'source', 'lead'}:
                action = 'import' if key == 'source' else 'search'
                button = self._button(action, 'Import advisory' if action == 'import' else 'Search locally')
                if action == 'search':
                    button.clicked.connect(self._search_new)
                else:
                    button.clicked.connect(lambda: self._submit(self._request('import')))
                layout.addWidget(button)
                tab_order.append(button)
            label = PlainLabel(title, wrap=True)
            label.setBuddy(field)
            form.addRow(label, row)
            field.textChanged.connect(lambda _text, k=key: self._edited(k))
        self.scope = QComboBox()
        self._tip(self.scope, 'scope')
        self.scope.addItem('Choose a product explicitly', None)
        self.scope.currentIndexChanged.connect(self._scope_changed)
        form.insertRow(3, '&Product / architecture / release', self.scope)
        tab_order.insert(tab_order.index(self.fields['older']), self.scope)
        self.same_component = QCheckBox('I confirm that differently named files are the same component')
        self._tip(self.same_component, 'same_component')
        self.same_component.toggled.connect(lambda _: self._invalidate())
        form.addRow(self.same_component)
        tab_order.append(self.same_component)
        root.addLayout(form)
        source_actions = QHBoxLayout()
        months = self.fields['months'] = QLineEdit()
        self._tip(months, 'months')
        months.setPlaceholderText('YYYY-MM,YYYY-MM (up to 24 months)')
        months.textChanged.connect(lambda _: self._invalidate())
        months_label = PlainLabel('Advisory mon&ths', wrap=True)
        months_label.setBuddy(months)
        source_actions.addWidget(months_label)
        source_actions.addWidget(months, 1)
        tab_order.append(months)
        for key, title in (('plan_sources', 'Preview advisory downloads'),
                           ('sync_sources', 'Fetch exactly this advisory plan')):
            button = self._button(key, title)
            source_actions.addWidget(button)
            tab_order.append(button)
        self.buttons['plan_sources'].clicked.connect(self._plan_sources)
        self.buttons['sync_sources'].clicked.connect(self._sync_sources)
        root.addLayout(source_actions)
        actions = QHBoxLayout()
        for key, title in (('use_current', 'Use current project inputs'), ('preview', 'Preview local pair'),
                           ('create', 'Create and open comparison'),
                           ('cancel', 'Cancel operation'), ('close', 'Close')):
            button = self._button(key, title)
            actions.addWidget(button)
            tab_order.append(button)
        self.buttons['use_current'].clicked.connect(self._use_current)
        self.buttons['preview'].clicked.connect(lambda: self._submit(self._request('preview')))
        self.buttons['create'].clicked.connect(self._create)
        self.buttons['cancel'].clicked.connect(self.cancel_operation)
        self.buttons['close'].clicked.connect(self.reject)
        root.addLayout(actions)
        self.details = SafeTextView('Local investigation details', wrap=True, limit=65536)
        self._tip(self.details, 'details')
        root.addWidget(self.details, 1)
        self.status = PlainLabel('Local files only. No comparison has been created.', wrap=True)
        self._tip(self.status, 'status')
        root.addWidget(self.status)
        tab_order.append(self.details)
        for before, after in zip(tab_order, tab_order[1:], strict=False):
            QWidget.setTabOrder(before, after)
        self._enable()

    @staticmethod
    def _tip(widget, key):
        widget.setObjectName('kb.investigation.' + key)
        widget.setAccessibleName(DESCRIPTIONS[key])
        apply_tip(widget, 'kb.investigation.' + key)

    def _button(self, key, text):
        button = QPushButton(text)
        self._tip(button, key)
        self.buttons[key] = button
        return button

    def _browse(self, key):
        if key in {'workspace', 'destination'}:
            value = QFileDialog.getExistingDirectory(self, 'Choose a directory', self.fields[key].text())
            if value and key == 'destination':
                value = str(Path(value) / time.strftime('kb-comparison-%Y%m%d-%H%M%S'))
        else:
            value, _ = QFileDialog.getOpenFileName(self, DESCRIPTIONS[key], self.fields[key].text())
        if value:
            self.fields[key].setText(value)

    def _request(self, operation):
        def path(key):
            value = self.fields[key].text().strip()
            return Path(value).expanduser() if value else None
        manual = self.manual_pair_start.isChecked()
        return InvestigationRequest(operation, path('workspace') or default_workspace(), source=path('source'),
                                    lead='' if manual else self.fields['lead'].text().strip(),
                                    investigation_id=None if manual else self._investigation_id,
                                    scope_id=None if manual else self.scope.currentData(),
                                    older=path('older'), newer=path('newer'),
                                    destination=path('destination'), name=self.fields['name'].text().strip(),
                                    current_project=self._current_project,
                                    confirm_same_component=self.same_component.isChecked(),
                                    current_inputs=self._input_origin if operation in {'preview', 'create'} else None,
                                    manual_pair_start=manual, source_months=self.fields['months'].text().strip())

    def _mode_changed(self):
        self._investigation_id = None
        self._set_scopes([], None)
        self._invalidate()
        self.status.setText('Binary-only: product lineage and fix boundary are unverified; no advisory linkage.'
                            if self.manual_pair_start.isChecked() else 'Search locally and choose an explicit product.')

    def _edited(self, key):
        if key in {'older', 'newer'}:
            self._input_origin = None
        self._invalidate()
        if key in {'workspace', 'lead'}:
            self._investigation_id = None
            self._set_scopes([], None)
            self._enable()

    def _invalidate(self):
        self._preview = None
        self._online_plan = None
        if self._pending is not None and self._pending.operation != 'create':
            self._generation += 1
            self.tasks.cancel(self._channel)
            self._pending = None
        self._enable()

    def _set_scopes(self, scopes, selected):
        self.scope.blockSignals(True)
        self.scope.clear()
        self.scope.addItem('Choose a product explicitly', None)
        for scope in scopes:
            text = ' · '.join(str(scope.get(k) or 'unknown') for k in
                              ('display_name', 'architecture', 'release', 'mapping'))
            self.scope.addItem(sanitize_text(text, 500), scope['scope_id'])
        index = self.scope.findData(selected) if selected else 0
        self.scope.setCurrentIndex(max(0, index))
        self.scope.blockSignals(False)

    def _scope_changed(self):
        self._invalidate()
        if self._investigation_id and self.scope.currentData():
            self._submit(self._request('search'))

    def _search_new(self):
        self._preview = None
        self._submit(replace(self._request('search'), investigation_id=None, scope_id=None))

    def _plan_sources(self):
        self._invalidate()
        self._submit(replace(self._request('plan_sources'), investigation_id=None, scope_id=None))

    def _sync_sources(self):
        if self._online_plan is None:
            return
        request, result = self._online_plan
        self._online_plan = None
        self._submit(replace(request, operation='sync_sources', source_plan_json=result.data['plan_json'],
                             consent_hosts=tuple(result.data['hosts']), consent_plan=result.data['plan_sha']))

    def _use_current(self):
        self._invalidate()
        if self._available_current is not None:
            self._submit(replace(self._request('current_inputs'), current_inputs=self._available_current))

    @staticmethod
    def _origin_text(origin):
        return (f'\nInput origin (preview only): project {origin["project_id"]}, revision {origin["revision"]}'
                f'\nOlder artifact: {origin["older_artifact_id"]} · {origin["older_name"]}'
                f'\nNewer artifact: {origin["newer_artifact_id"]} · {origin["newer_name"]}'
                f'\n{origin["status"]}')

    def _enable(self):
        busy = self._pending is not None
        manual = self.manual_pair_start.isChecked()
        self.manual_pair_start.setEnabled(not busy)
        for field in self.fields.values():
            field.setEnabled(not busy)
        self.scope.setEnabled(not busy and not manual and self._investigation_id is not None)
        self.same_component.setEnabled(not busy)
        for button in self.buttons.values():
            button.setEnabled(not busy)
        self.buttons['use_current'].setEnabled(not busy and self._available_current is not None
                                               and self._is_current())
        for key in ('source', 'lead', 'months'):
            self.fields[key].setEnabled(not busy and not manual)
        for key in ('browse_source', 'import', 'search'):
            self.buttons[key].setEnabled(not busy and not manual)
        self.buttons['plan_sources'].setEnabled(not busy and not manual
                                                and bool(self.fields['lead'].text().strip())
                                                and bool(self.fields['months'].text().strip()))
        self.buttons['sync_sources'].setEnabled(not busy and not manual and self._online_plan is not None)
        self.buttons['cancel'].setEnabled(busy)
        self.buttons['close'].setEnabled(True)
        pair_ready = manual or (self._investigation_id is not None and self.scope.currentData() is not None)
        self.buttons['preview'].setEnabled(not busy and pair_ready
                                          and bool(self.fields['older'].text() and self.fields['newer'].text()))
        self.buttons['create'].setEnabled(not busy and self._preview is not None
                                         and bool(self.fields['destination'].text().strip()))

    def _submit(self, request):
        if self._closed or self._pending is not None:
            return
        if not self.fields['workspace'].text().strip():
            self.status.setText('Choose an advisory workspace directory before continuing.')
            self.fields['workspace'].setFocus(Qt.FocusReason.OtherFocusReason)
            return
        if request.current_inputs is not None and not self._is_current():
            self._preview = None
            self.status.setText('PT-KBC-STALE: The current project changed; reopen the investigation.')
            self._enable()
            return
        self._online_plan = None
        self._generation += 1
        generation = self._generation
        self._pending = request
        self._cancel_create, self._close_after_create = False, False
        self.status.setText({'import': 'Importing local advisory…', 'search': 'Searching stored documents…',
                             'current_inputs': 'Verifying current project input copies…',
                             'plan_sources': 'Preparing exact advisory download preview; no request is sent…',
                             'sync_sources': 'Fetching the consented advisory plan…',
                             'preview': 'Inspecting local pair…', 'create': 'Creating separate comparison…'}
                            [request.operation])
        self._enable()
        # The worker owns only immutable plain request data and a pure function.
        execute = self._execute
        def work(token, _report):
            return execute(request, token)
        self.tasks.submit(self._channel, work,
                          partial(self._loaded, generation, request), partial(self._failed, generation))

    def _loaded(self, generation, request, result: InvestigationResult):
        if self._closed or generation != self._generation:
            return
        self._pending = None
        if request.current_inputs is not None and not self._is_current():
            self._input_origin = request.current_inputs
            result = replace(result, success=False, error_code='PT-KBC-STALE',
                             text='The current project changed; reopen the investigation.')
        self.status.setText(('' if result.success else f'{result.error_code or "PT-KBC-INPUT"}: ') + result.text)
        text = result.text
        if result.success and request.operation == 'plan_sources':
            self._online_plan = (request, result)
        elif result.success and request.operation == 'current_inputs':
            self._preview = None
            for key in ('older', 'newer'):
                self.fields[key].blockSignals(True)
                self.fields[key].setText(result.data[key])
                self.fields[key].blockSignals(False)
            self._input_origin = request.current_inputs
            text += self._origin_text(result.data['input_origin'])
            text += '\nExplicit same-component confirmation and exact pair preview remain required.'
        elif result.success and request.operation == 'import':
            self._investigation_id, self._preview = None, None
            self._set_scopes([], None)
        elif result.success and request.operation in {'search', 'sync_sources'}:
            self._preview = None
            self._investigation_id = result.data.get('investigation_id')
            self._set_scopes(result.data.get('scopes', ()), request.scope_id)
            refs = [ref for edge in result.data.get('edges', ()) for ref in edge.get('refs', ())]
            text += '\n' + '\n'.join(f'Source {r.get("doc_id", "unknown")} {r.get("pointer", "")}' for r in refs)
        elif result.success and request.operation == 'preview':
            self._preview = (request, result)
            pair = result.data.get('pair', {})
            product = 'unselected; no advisory linkage' if request.manual_pair_start else self.scope.currentText()
            text += (f'\nProduct: {product}\nOlder SHA-256: {pair.get("older_sha256")}\n'
                     f'Newer SHA-256: {pair.get("newer_sha256")}\nLineage: {pair.get("lineage_state")}\n'
                     f'Fix boundary: {pair.get("fix_boundary")}\nLimits: {", ".join(pair.get("reason_codes", ()))}')
            if result.data.get('input_origin'):
                text += self._origin_text(result.data['input_origin'])
        elif request.operation == 'create' and result.project_path is not None:
            self._preview = None
            if not result.success or self._cancel_create or self._close_after_create or self._on_created is None:
                prefix = result.text + '\n' if not result.success else ''
                text = prefix + f'Project retained without opening: {result.project_path}'
                self.status.setText(text)
                if self._notice:
                    self._notice(text)
            elif self._on_created:
                try:
                    self._on_created(result.project_path)
                except Exception:
                    text = f'Project retained, but could not be opened: {result.project_path}'
                    self.status.setText(text)
                    if self._notice:
                        self._notice(text)
                else:
                    self._closed = True
                    self._shutdown()
                    super().accept()
            if self._close_after_create:
                self._closed = True
                self._shutdown()
                super().reject()
        elif not result.success:
            self._preview = None
        self.details.setPlainText(text)
        self._enable()
        if request.operation == 'create' and self._close_after_create and not self._closed:
            if self._notice:
                self._notice(self.status.full_text())
            self._closed = True
            self._shutdown()
            super().reject()

    def _failed(self, generation, failure):
        if self._closed or generation != self._generation:
            return
        self._pending, self._preview = None, None
        self.status.setText(f'{failure.code}: {failure.exception_class} stopped the local operation. Previous results remain.')
        self._enable()
        if self._close_after_create:
            if self._notice:
                self._notice(self.status.full_text())
            self._closed = True
            self._shutdown()
            super().reject()

    def _create(self):
        if self._preview is None:
            return
        request, result = self._preview
        request = replace(request, operation='create', expected_pair_id=result.data['pair']['pair_id'],
                          expected_revision=result.data['investigation_revision'])
        self._submit(request)

    def cancel_operation(self):
        self._online_plan = None
        if self._pending is not None and self._pending.operation == 'create':
            self._cancel_create = True
            self.status.setText('Finishing local project creation; any completed project will be retained, not opened.')
            return
        self._generation += 1
        self.tasks.cancel(self._channel)
        self._pending, self._preview = None, None
        self.status.setText('Cancelled. Previous results remain available.')
        self._enable()

    def _shutdown(self):
        if self._own_tasks:
            self.tasks.shutdown()

    def reject(self):
        if self._pending is not None and self._pending.operation == 'create':
            self._close_after_create = True
            self.cancel_operation()
            return
        self.cancel_operation()
        self._closed = True
        self._shutdown()
        super().reject()
