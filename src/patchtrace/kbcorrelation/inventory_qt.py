"""PW-01 desktop inventory workflow. Widgets own no parser, store or network policy.

Each operation carries a frozen request to a TaskRunner worker, constructs its own
KbService there, and returns only plain data. Source previews are invalidated by
input edits; fetching requires a separate, unchecked-by-default consent control.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..gui.qt.labels import PlainLabel, SafeTextView
from ..gui.qt.tasks import TaskRunner
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip, register_tips
from ..tooltips import TooltipEntry
from .inventory_contracts import InventoryContext
from .sources.cvrf import SourceError
from .store import KbcStoreError, default_workspace

PAGE_SIZE = 200
DESCRIPTIONS = {
    'workspace': 'Local advisory workspace containing retained inventory sources.',
    'browse_workspace': 'Choose the local advisory workspace directory.',
    'csv': 'Saved KB file-information CSV to import without fetching.',
    'browse_csv': 'Choose a saved CSV file. It remains an unverified local source.',
    'kb': 'KB identifier explicitly associated with this inventory.',
    'product_scope': 'Optional product scope ID asserted for the imported CSV.',
    'product': 'Optional product label asserted as parsing context.',
    'release': 'Optional release label asserted as parsing context.',
    'build': 'Optional OS build asserted as parsing context, separate from file versions.',
    'architecture': 'Explicit architecture context; unknown leaves source metadata unresolved.',
    'delimiter': 'Explicit CSV delimiter; separators are never guessed.',
    'locale': 'Explicit numeric grouping rules; dates remain original text.',
    'asserted_source': 'Optional unverified source URL; it does not authenticate a local file.',
    'import': 'Import the selected saved CSV using the displayed context.',
    'refresh': 'List retained file inventories in this workspace without fetching.',
    'imports': 'Choose a retained inventory explicitly for inspection.',
    'inspect': 'Verify and inspect the chosen retained inventory.',
    'list_previous': 'Show the previous page of retained inventory sources.',
    'list_next': 'Show the next page of retained inventory sources.',
    'retain_architecture': 'Architecture to retain from the saved source; unknown and conflicted rows remain included.',
    'source_page': 'One-based source page to retain; separate from pagination over rows already retained.',
    'retain': 'Retain this source page offline without selecting a filename or changing an investigation.',
    'filter_name': 'Filter retained entries by basename text.',
    'filter_architecture': 'Filter retained entries by architecture, including unknown.',
    'filter_state': 'Filter retained entries by metadata state.',
    'filter': 'Apply the displayed entry filters to the chosen inventory.',
    'previous': 'Show the previous page of filtered entries.',
    'next': 'Show the next page of filtered entries.',
    'rows': 'Inventory metadata rows. Selecting a row only displays its details.',
    'investigation': 'Existing investigation ID to receive the explicitly selected filename.',
    'target_product': 'Existing product scope ID for the selected investigation.',
    'revision': 'Exact current investigation revision; stale selections are refused.',
    'assert_scope': 'Explicitly assert the chosen product scope for inventory metadata with no recorded mapping.',
    'select': 'Record this row as an analyst-selected filename for the stated investigation and revision.',
    'html': 'Saved Microsoft support HTML to inspect as inert local data.',
    'browse_html': 'Choose saved support HTML. Scripts and links are never executed.',
    'page_url': 'Explicit support page URL used only to resolve saved relative links.',
    'links': 'Inspect and retain candidate file-information links from saved HTML.',
    'candidates': 'All extracted candidates, including rejected links and their reasons.',
    'use_link': 'Copy the explicitly chosen accepted link into the request URL; no request is sent.',
    'url': 'Exact first URL to include in a source request preview.',
    'kind': 'Choose support-page HTML or a file-inventory CSV request.',
    'redirects': 'Exact expected redirect URLs, one per line, in their request order.',
    'plan': 'Preview the exact source requests, hosts, limits and consent digest without fetching.',
    'preview': 'Exact request plan for review before one-time consent.',
    'consent': 'Approve only the currently displayed request chain, hosts, limits and digest.',
    'fetch': 'Fetch and retain exactly the displayed and approved source plan.',
    'revised': 'Preview the server-proposed request chain again; it does not fetch the new target.',
    'details': 'Plain-text source provenance, row references, counts, conflicts and operation details.',
    'status': 'Current inventory operation status and remedies.',
    'cancel': 'Cancel the pending operation and ignore late results; saved successes remain available.',
    'close': 'Close this inventory dialog and cancel pending work.',
    'tabs': 'Saved CSV import, retained inventory inspection and optional source requests.',
}
TIPS = {f'kb.inventory.{key}': TooltipEntry(
    text, 'Keeps inventory provenance, scope and analyst choices inspectable.',
    ('Requires an exact preview and separate consent; no binary is downloaded or executed.'
     if key in {'fetch', 'consent'} else 'No target or package-supplied program is executed.'),
    'Local file inventories and explicitly consented Microsoft support sources.')
        for key, text in DESCRIPTIONS.items()}
TIPS['kb.inventory'] = TooltipEntry(
    'Open file inventories for KB component discovery.',
    'Inspect saved CSV metadata and source links, including without an open project.',
    'Opens the inventory dialog. Network requests require a separate exact preview and consent.')


def register_inventory_tips() -> None:
    register_tips(TIPS)


@dataclass(frozen=True)
class InventoryRequest:
    operation: str
    workspace: Path
    payload: str  # immutable JSON, captured from widgets on their owner thread


@dataclass(frozen=True)
class InventoryReply:
    outcome: object | None = None
    code: str | None = None
    message: str = ''
    details: dict | None = None
    display_text: str = ''
    entry_texts: tuple[str, ...] = ()


def _service(workspace):
    from .wiring import build_service
    return build_service(workspace)


def _context(values) -> InventoryContext:
    from .ids import normalise_kb_edge
    return InventoryContext(kb=normalise_kb_edge(values['kb']), **{
        key: (value or None) if key in {'product_scope_id', 'product', 'release', 'build'} else value
        for key, value in values.items() if key != 'kb'})


def _bounded_details(text, limit=65536):
    suffix = '\n[Display truncated; inspect the retained source or use the CLI for complete records.]'
    return text if len(text) <= limit else text[:limit - len(suffix)] + suffix


def _source_label(item):
    context, source = item.get('context', {}), item.get('source', {})
    label = (f'{context.get("kb", "Unknown KB")} · {item["import_id"][:12]} · '
             f'{item.get("accepted_count", 0)} rows · {source.get("authenticity", "unknown")}')
    retention = item.get('retention')
    if isinstance(retention, dict):
        label += f' · {retention.get("architecture", "unknown")} source page {retention.get("page", "unknown")}'
    return sanitize_text(label, 500)


def execute_inventory(request: InventoryRequest, token, *, service_factory=_service) -> InventoryReply:
    """Worker-only facade dispatch. No widget, live project or SQLite handle crosses in."""
    data = json.loads(request.payload)
    try:
        token.raise_if_cancelled()
        service = service_factory(request.workspace)
        op = request.operation
        if op == 'import':
            out = service.import_inventory(Path(data['path']), _context(data['context']),
                                           asserted_source=data['asserted_source'] or None, cancel=token)
        elif op == 'retain':
            out = service.retain_inventory(data['import_id'], architecture=data['architecture'], page=data['page'],
                                           cancel=token)
        elif op == 'list':
            out = service.inventories(limit=20, offset=data['offset'], cancel=token)
        elif op == 'show':
            out = service.inventory_details(data['import_id'], name=data['name'],
                                            architecture=data['architecture'], state=data['state'],
                                            limit=PAGE_SIZE, offset=data['offset'], cancel=token)
        elif op == 'select':
            out = service.select_inventory(data['investigation'], data['import_id'], data['entry_id'],
                                           product=data['product'], expected_revision=data['revision'],
                                           assert_scope=data['assert_scope'], cancel=token)
        elif op == 'links':
            out = service.support_links(Path(data['path']), page_url=data['page_url'], cancel=token)
        elif op == 'plan':
            out = service.inventory_plan(data['url'], kind=data['kind'], redirects=tuple(data['redirects']))
        elif op == 'fetch':
            from .sources.inventory_fetch import parse_plan
            plan = parse_plan(json.dumps(data['plan']))
            out = service.fetch_inventory(plan, context=_context(data['context']) if plan.kind == 'file-inventory'
                                          else None, consent_hosts=tuple(plan.hosts), consent_plan=plan.plan_sha,
                                          offline=False, cancel=token)
        else:
            raise SourceError('PT-KBC-INPUT', 'Unknown inventory operation.')
        display = out.text + '\n\n' + json.dumps(out.result, ensure_ascii=False, indent=2)
        entries = out.result.get('entries', ())
        source = out.result.get('inventory', {})
        # Do not repeat the source's full section/diagnostic arrays for every row.
        source_text = _bounded_details(json.dumps({key: source.get(key) for key in
                                                  ('import_id', 'source', 'context', 'retrieval', 'asserted_source',
                                                   'status', 'truncated', 'retention', 'scan_complete',
                                                   'matching_count', 'excluded_count', 'omitted_count',
                                                   'conflict_witness_count')}, ensure_ascii=False, indent=2), 16384)
        witnesses = {item['conflict_group']: item for item in source.get('conflict_witnesses', ())}
        row_texts = []
        for entry in entries:
            detail = source_text
            witness = witnesses.get(entry.get('conflict_group'))
            if witness is not None:
                # Keep the exact matching evidence before original fields can exhaust the display budget.
                detail += '\n\nConflict witness:\n' + json.dumps(witness, ensure_ascii=False, indent=2)
            detail += '\n\nEntry:\n' + json.dumps(entry, ensure_ascii=False, indent=2)
            row_texts.append(_bounded_details(detail))
        return InventoryReply(outcome=out, display_text=_bounded_details(display), entry_texts=tuple(row_texts))
    except (SourceError, KbcStoreError) as exc:
        return InventoryReply(code=exc.code, message=exc.message, details=exc.details)
    except ValueError:
        return InventoryReply(code='PT-KBC-INPUT', message='Check the KB identifier and explicit inventory context.')


class InventoryDialog(QDialog):
    def __init__(self, parent=None, *, workspace=None, tasks=None, execute=execute_inventory,
                 investigation=None, product=None, expected_revision=None):
        super().__init__(parent)
        register_inventory_tips()
        self.setWindowTitle('KB file inventories')
        self.resize(1050, 850)
        self.tasks, self._own_tasks = (tasks, False) if tasks is not None else (TaskRunner(self), True)
        self._execute = execute
        self._channel = f'kb.inventory.{id(self)}'
        self._generation, self._closed, self._pending = 0, False, None
        self._plan = self._proposed_plan = self._shown = None
        self._entry_texts = ()
        self._list_offset = self._entry_offset = self._list_total = self._entry_total = 0
        self.fields, self.buttons, self.combos = {}, {}, {}
        root = QVBoxLayout(self)
        root.addWidget(PlainLabel('File inventories supply metadata and candidate filenames. They do not establish '
                                 'binary identity or show that a file contains a CVE fix.', wrap=True))
        workspace_form = QFormLayout()
        self._field(workspace_form, 'workspace', '&Workspace',
                    str(workspace if workspace is not None else default_workspace()), browse=True)
        root.addLayout(workspace_form)
        self.tabs = QTabWidget()
        self._tip(self.tabs, 'tabs')
        self.tabs.tabBar().setObjectName('kb.inventory.tabs.bar')
        apply_tip(self.tabs.tabBar(), 'kb.inventory.tabs')
        self.tabs.tabBar().setAccessibleName('Inventory workflow tabs')
        root.addWidget(self.tabs, 1)
        self._build_import()
        self._build_inventory(investigation, product, expected_revision)
        self._build_sources()
        self.details = SafeTextView('Inventory source and row details', wrap=True, limit=65536)
        self._tip(self.details, 'details')
        self.details.setMaximumHeight(190)
        root.addWidget(self.details)
        self.status = PlainLabel('Import a saved CSV or list retained inventories. Network is inactive.', wrap=True)
        self._tip(self.status, 'status')
        root.addWidget(self.status)
        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(self._button('cancel', 'Cancel operation', self.cancel_operation))
        actions.addWidget(self._button('close', 'Close', self.reject))
        root.addLayout(actions)
        self._enable()

    @staticmethod
    def _tip(widget, key):
        widget.setObjectName('kb.inventory.' + key)
        widget.setAccessibleName(DESCRIPTIONS[key])
        apply_tip(widget, 'kb.inventory.' + key)

    def _button(self, key, title, action):
        button = self.buttons[key] = QPushButton(title)
        button.setAutoDefault(False)
        self._tip(button, key)
        button.clicked.connect(action)
        return button

    def _field(self, form, key, title, value='', *, browse=False):
        field = self.fields[key] = QLineEdit(value)
        field.setMaxLength(4096 if key in {'workspace', 'csv', 'html', 'page_url', 'url', 'asserted_source'} else 1000)
        self._tip(field, key)
        label = PlainLabel(title, elide=False)
        label.setBuddy(field)
        if browse:
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(field, 1)
            layout.addWidget(self._button('browse_' + key, 'Browse…', partial(self._browse, key)))
            form.addRow(label, row)
        else:
            form.addRow(label, field)
        field.textChanged.connect(partial(self._edited, key))
        return field

    def _combo(self, key, items):
        combo = self.combos[key] = QComboBox()
        self._tip(combo, key)
        combo.view().setAccessibleName(DESCRIPTIONS[key] + ' options')
        for title, value in items:
            combo.addItem(title, value)
        combo.currentIndexChanged.connect(partial(self._edited, key))
        return combo

    def _tab(self, title):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.tabs.addTab(tab, title)
        return layout

    def _build_import(self):
        layout = self._tab('Saved CSV')
        form = QFormLayout()
        self._field(form, 'csv', '&CSV file', browse=True)
        for key, title in (('kb', '&KB identifier'), ('product_scope', 'Product scope ID (optional)'),
                           ('product', 'Product label (optional)'), ('release', 'Release (optional)'),
                           ('build', 'OS build (optional)'), ('asserted_source', 'Asserted source URL (unverified)')):
            self._field(form, key, title)
        for key, title, options in (
            ('architecture', 'Architecture context', [('Unknown', 'unknown'), ('AMD64 / x64', 'amd64'),
                                                     ('ARM64', 'arm64'), ('x86', 'x86')]),
            ('delimiter', 'CSV delimiter', [('Comma', 'comma'), ('Semicolon', 'semicolon'), ('Tab', 'tab')]),
            ('locale', 'Numeric grouping', [('English (US)', 'en-US'), ('Invariant digits', 'invariant'),
                                            ('German', 'de-DE')])):
            form.addRow(title, self._combo(key, options))
        layout.addLayout(form)
        layout.addWidget(self._button('import', 'Import saved CSV', self._import))
        layout.addWidget(PlainLabel('Context is an analyst assertion. Local imports remain unverified even when '
                                   'a Microsoft URL is supplied. Unknown and conflicting metadata remain visible.',
                                   wrap=True))
        layout.addStretch()

    def _build_inventory(self, investigation, product, revision):
        layout = self._tab('&Retained inventories')
        source_row = QHBoxLayout()
        self.imports = self._combo('imports', [('Choose an inventory explicitly', None)])
        self.imports.currentIndexChanged.connect(self._source_changed)
        source_row.addWidget(self.imports, 1)
        for key, label, action in (
            ('refresh', 'List inventories', self._list), ('inspect', 'Inspect source', self._show),
            ('list_previous', 'Previous sources', partial(self._list_page, -1)),
            ('list_next', 'Next sources', partial(self._list_page, 1))):
            source_row.addWidget(self._button(key, label, action))
        layout.addLayout(source_row)
        retention = QHBoxLayout()
        architecture = self._combo('retain_architecture', [('AMD64 / x64', 'amd64'), ('ARM64', 'arm64'),
                                                           ('x86', 'x86'), ('Unknown', 'unknown'),
                                                           ('All architectures', 'all')])
        architecture_label = PlainLabel('Retain &architecture', elide=False)
        architecture_label.setBuddy(architecture)
        retention.addWidget(architecture_label)
        retention.addWidget(architecture)
        self.source_page = QSpinBox()
        self._tip(self.source_page, 'source_page')
        self.source_page.setRange(1, 100000)
        self.source_page.lineEdit().setAccessibleName(DESCRIPTIONS['source_page'])
        self.source_page.lineEdit().setToolTip(self.source_page.toolTip())
        self.source_page.valueChanged.connect(partial(self._edited, 'source_page'))
        page_label = PlainLabel('&Source page', elide=False)
        page_label.setBuddy(self.source_page)
        retention.addWidget(page_label)
        retention.addWidget(self.source_page)
        retention.addWidget(self._button('retain', 'Retain source page', self._retain))
        retention.addStretch()
        layout.addLayout(retention)
        layout.addWidget(PlainLabel('Retain a page from the chosen saved CSV, including later architecture sections. '
                                   'Then inspect the resulting source before selecting a filename.', wrap=True))
        filters = QHBoxLayout()
        name = self.fields['filter_name'] = QLineEdit()
        name.setMaxLength(128)
        name.setPlaceholderText('Basename filter')
        self._tip(name, 'filter_name')
        name.textChanged.connect(partial(self._edited, 'filter_name'))
        filters.addWidget(name, 1)
        filters.addWidget(self._combo('filter_architecture', [('All architectures', None), ('AMD64', 'amd64'),
                                                              ('ARM64', 'arm64'), ('x86', 'x86'),
                                                              ('Unknown', 'unknown')]))
        filters.addWidget(self._combo('filter_state', [('All states', None), ('Metadata only', 'metadata-only'),
                                                       ('Unknown', 'unknown'), ('Conflicted', 'conflicted'),
                                                       ('Descriptive only', 'descriptive-only')]))
        for key, label, action in (('filter', 'Apply filters', self._show),
                                   ('previous', 'Previous rows', partial(self._entry_page, -1)),
                                   ('next', 'Next rows', partial(self._entry_page, 1))):
            filters.addWidget(self._button(key, label, action))
        layout.addLayout(filters)
        self.rows = QTableWidget(0, 7)
        self._tip(self.rows, 'rows')
        self.rows.setHorizontalHeaderLabels(['Filename', 'Version', 'Architecture', 'State', 'Product', 'Build', 'Record'])
        self.rows.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rows.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rows.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.rows.setSortingEnabled(False)
        self.rows.horizontalHeader().setStretchLastSection(True)
        self.rows.itemSelectionChanged.connect(self._row_changed)
        layout.addWidget(self.rows, 1)
        target = QFormLayout()
        self._field(target, 'investigation', 'Existing investigation ID', investigation or '')
        self._field(target, 'target_product', 'Selected product scope ID', product or '')
        self.revision = QSpinBox()
        self._tip(self.revision, 'revision')
        self.revision.setRange(0, 2**31 - 1)
        self.revision.setSpecialValueText('Current revision required')
        self.revision.setValue(revision or 0)
        self.revision.lineEdit().setAccessibleName(DESCRIPTIONS['revision'])
        self.revision.lineEdit().setToolTip(self.revision.toolTip())
        self.revision.valueChanged.connect(partial(self._edited, 'revision'))
        target.addRow('Exact investigation revision', self.revision)
        layout.addLayout(target)
        self.assert_scope = QCheckBox('I explicitly map this inventory to the selected product scope')
        self._tip(self.assert_scope, 'assert_scope')
        self.assert_scope.toggled.connect(partial(self._edited, 'assert_scope'))
        layout.addWidget(self.assert_scope)
        layout.addWidget(self._button('select', 'Select this filename for the investigation', self._select))
        layout.addWidget(PlainLabel('Selection needs an existing investigation, its product scope and current '
                                   'revision. It retains row provenance and does not select or download a binary pair.',
                                   wrap=True))

    def _build_sources(self):
        layout = self._tab('&Support sources')
        form = QFormLayout()
        self._field(form, 'html', 'Saved support HTML', browse=True)
        self._field(form, 'page_url', 'Explicit support page URL')
        layout.addLayout(form)
        links = QHBoxLayout()
        links.addWidget(self._button('links', 'Inspect saved links', self._links))
        self.candidates = self._combo('candidates', [('Choose a source link explicitly', None)])
        self.candidates.currentIndexChanged.connect(self._link_changed)
        links.addWidget(self.candidates, 1)
        links.addWidget(self._button('use_link', 'Use selected link', self._use_link))
        layout.addLayout(links)
        plan = QFormLayout()
        self._field(plan, 'url', 'Exact request URL')
        plan.addRow('Source kind', self._combo('kind', [('File inventory CSV', 'file-inventory'),
                                                       ('Support page HTML', 'support-page')]))
        self.redirects = QPlainTextEdit()
        self._tip(self.redirects, 'redirects')
        self.redirects.setMaximumHeight(65)
        self.redirects.textChanged.connect(partial(self._edited, 'redirects'))
        plan.addRow('Expected redirects (one per line)', self.redirects)
        layout.addLayout(plan)
        controls = QHBoxLayout()
        controls.addWidget(self._button('plan', 'Preview exact requests', self._preview_plan))
        controls.addWidget(self._button('revised', 'Review revised request', self._review_proposal))
        layout.addLayout(controls)
        self.preview = SafeTextView('Exact source request preview', wrap=True, limit=65536)
        self._tip(self.preview, 'preview')
        layout.addWidget(self.preview, 1)
        self.consent = QCheckBox('I approve this exact request chain, hosts, limits and plan digest')
        self._tip(self.consent, 'consent')
        self.consent.toggled.connect(self._enable)
        layout.addWidget(self.consent)
        layout.addWidget(self._button('fetch', 'Fetch exactly this approved plan', self._fetch))

    def _text(self, key):
        return self.fields[key].text().strip()

    def _context_values(self):
        return {'kb': self._text('kb'), 'product_scope_id': self._text('product_scope'),
                **{key: self._text(key) for key in ('product', 'release', 'build')},
                **{key: self.combos[key].currentData() for key in ('architecture', 'delimiter', 'locale')}}

    def _edited(self, key=None, *_):
        if not hasattr(self, 'consent'):
            return
        self._plan = self._proposed_plan = None
        self.consent.setChecked(False)
        self._generation += 1
        if self._pending is not None:
            self.tasks.cancel(self._channel)
            self._pending = None
            self.status.setText('Inputs changed; late results are ignored. Any completed import remains saved.')
        if key == 'workspace':
            self.imports.blockSignals(True)
            self.imports.clear()
            self.imports.addItem('Choose an inventory explicitly', None)
            self.imports.blockSignals(False)
            self._list_offset = self._list_total = 0
            self._source_changed()
            self.status.setText('Workspace changed. List its saved inventories before inspecting or selecting.')
        self._enable()

    def _source_changed(self, *_):
        self._shown = None
        self._entry_texts = ()
        self._entry_offset = self._entry_total = 0
        self.rows.setRowCount(0)
        self._enable()

    def _browse(self, key, *_):
        if key == 'workspace':
            path = QFileDialog.getExistingDirectory(self, 'Choose advisory workspace', self._text(key))
        else:
            pattern = 'CSV files (*.csv);;All files (*)' if key == 'csv' else 'Saved HTML (*.html *.htm);;All files (*)'
            path, _ = QFileDialog.getOpenFileName(self, 'Choose saved source', self._text(key), pattern)
        if path:
            self.fields[key].setText(path)

    def _submit(self, operation, payload):
        if self._closed or self._pending is not None:
            return
        if not self._text('workspace'):
            self.status.setText('Choose a local advisory workspace first.')
            return
        self._generation += 1
        generation = self._generation
        request = InventoryRequest(operation, Path(self._text('workspace')).expanduser(),
                                   json.dumps(payload, ensure_ascii=True, separators=(',', ':')))
        self._pending = request
        self.status.setText({'import': 'Importing saved CSV…', 'list': 'Listing saved inventories…',
                             'retain': 'Retaining a page from the saved source; no request is sent…',
                             'show': 'Verifying and reading saved inventory…', 'select': 'Recording scoped filename selection…',
                             'links': 'Inspecting saved HTML; no request is sent…',
                             'plan': 'Preparing exact request preview; no request is sent…',
                             'fetch': 'Fetching the explicitly approved source plan…'}[operation])
        self._enable()
        execute = self._execute
        def work(token, report):
            report('Inventory ' + operation)
            return execute(request, token)
        self.tasks.submit(self._channel, work, partial(self._loaded, generation, request),
                          partial(self._failed, generation))

    def _import(self):
        self._submit('import', {'path': self._text('csv'), 'context': self._context_values(),
                                'asserted_source': self._text('asserted_source')})

    def _retain(self):
        if self.imports.currentData():
            self._submit('retain', {'import_id': self.imports.currentData(),
                                    'architecture': self.combos['retain_architecture'].currentData(),
                                    'page': self.source_page.value()})

    def _list(self):
        self._list_offset = 0
        self._submit('list', {'offset': 0})

    def _list_page(self, direction):
        self._submit('list', {'offset': max(0, self._list_offset + 20 * direction)})

    def _show(self):
        self._request_entries(0)

    def _entry_page(self, direction):
        self._request_entries(max(0, self._entry_offset + PAGE_SIZE * direction))

    def _request_entries(self, offset):
        if self.imports.currentData():
            self._submit('show', {'import_id': self.imports.currentData(), 'name': self._text('filter_name'),
                                  'architecture': self.combos['filter_architecture'].currentData(),
                                  'state': self.combos['filter_state'].currentData(), 'offset': offset})

    def _selected_row(self):
        selected = self.rows.selectionModel().selectedRows()
        return selected[0].row() if len(selected) == 1 else -1

    def _selected_entry(self):
        row = self._selected_row()
        entries = self._shown.get('entries', []) if self._shown else []
        return entries[row] if 0 <= row < len(entries) else None

    def _row_changed(self):
        entry = self._selected_entry()
        if entry is not None:
            row = self._selected_row()
            if row < len(self._entry_texts):
                self.details.setPlainText(self._entry_texts[row])
        self._enable()

    def _select(self):
        entry = self._selected_entry()
        if entry is None or (self._shown or {}).get('inventory', {}).get('scan_complete') is False:
            return
        self._submit('select', {'import_id': self.imports.currentData(), 'entry_id': entry['entry_id'],
                                'investigation': self._text('investigation'), 'product': self._text('target_product'),
                                'revision': self.revision.value(), 'assert_scope': self.assert_scope.isChecked()})

    def _links(self):
        self._submit('links', {'path': self._text('html'), 'page_url': self._text('page_url')})

    def _link_changed(self, *_):
        link = self.candidates.currentData()
        if link:
            self.details.setPlainText(json.dumps(link, ensure_ascii=False, indent=2))
        self._enable()

    def _use_link(self):
        link = self.candidates.currentData()
        if link and link.get('accepted') and link.get('url'):
            self.fields['url'].setText(link['url'])
            self.combos['kind'].setCurrentIndex(0)
            self.redirects.clear()

    def _preview_plan(self):
        self._plan = None
        self.consent.setChecked(False)
        redirects = self.redirects.toPlainText()
        if len(redirects) > 16384 or len(redirects.splitlines()) > 4:
            self.status.setText('PT-KBC-INPUT: Supply at most four exact redirect URLs, within 16 KiB.')
            self._enable()
            return
        self._submit('plan', {'url': self._text('url'), 'kind': self.combos['kind'].currentData(),
                              'redirects': redirects.splitlines()})

    def _fetch(self):
        if self._plan is None or not self.consent.isChecked():
            return
        plan = self._plan
        self._plan = None
        self.consent.setChecked(False)
        self._submit('fetch', {'plan': plan, 'context': self._context_values()})

    def _review_proposal(self):
        proposed = self._proposed_plan
        if not isinstance(proposed, dict) or not proposed.get('urls'):
            return
        self.fields['url'].setText(proposed['urls'][0])
        self.combos['kind'].setCurrentIndex(self.combos['kind'].findData(proposed.get('kind')))
        self.redirects.setPlainText('\n'.join(proposed['urls'][1:]))
        self._preview_plan()

    def _loaded(self, generation, request, reply):
        if self._closed or generation != self._generation:
            return
        self._pending = None
        if reply.code:
            self.status.setText(f'{reply.code}: {reply.message} Previous displayed results remain available.')
            proposed = (reply.details or {}).get('proposed_plan')
            if isinstance(proposed, dict):
                self._proposed_plan = proposed
                self.preview.setPlainText((reply.details or {}).get('preview', '') +
                                          '\nReview the revised request, then approve its new preview separately.')
            self._enable()
            return
        outcome = reply.outcome
        self.status.setText(outcome.text)
        if outcome.status in {'failed', 'cancelled'}:
            if isinstance(outcome.result.get('proposed_plan'), dict):
                self._proposed_plan = outcome.result['proposed_plan']
                self.preview.setPlainText(outcome.result.get('preview', '') +
                                          '\nReview the revised request, then approve its new preview separately.')
            self._enable()
            return
        result = outcome.result
        op = request.operation
        if op == 'list':
            self._list_offset, self._list_total = result.get('offset', 0), result.get('total', 0)
            current = self.imports.currentData()
            self.imports.blockSignals(True)
            self.imports.clear()
            self.imports.addItem('Choose an inventory explicitly', None)
            for item in result.get('inventories', ()):
                self.imports.addItem(_source_label(item), item['import_id'])
            self.imports.setCurrentIndex(max(0, self.imports.findData(current)))
            self.imports.blockSignals(False)
            self._source_changed()
        elif op == 'retain':
            item = result.get('inventory', {})
            if item.get('import_id') == result.get('import_id') and item.get('import_id'):
                self.imports.blockSignals(True)
                index = self.imports.findData(item['import_id'])
                if index < 0:
                    self.imports.addItem(_source_label(item), item['import_id'])
                    index = self.imports.count() - 1
                self.imports.setCurrentIndex(index)
                self.imports.blockSignals(False)
                self._source_changed()  # choosing a source never chooses a filename
        elif op == 'show':
            self._shown = result
            self._entry_texts = reply.entry_texts
            self._entry_offset, self._entry_total = result.get('offset', 0), result.get('filtered_count', 0)
            entries = result.get('entries', ())
            self.rows.setRowCount(len(entries))
            for n, entry in enumerate(entries):
                values = (entry.get('basename') or entry.get('original_filename'), entry.get('original_version'),
                          entry.get('architecture'), entry.get('state'), entry.get('product'), entry.get('build'),
                          entry.get('reference', {}).get('logical_record'))
                for column, value in enumerate(values):
                    item = QTableWidgetItem(sanitize_text('' if value is None else str(value), 500))
                    item.setData(Qt.ItemDataRole.AccessibleTextRole, item.text())
                    self.rows.setItem(n, column, item)
            self.rows.clearSelection()
            self.rows.setCurrentCell(-1, -1)
        elif op == 'plan':
            self._plan = result.get('plan')
            self._proposed_plan = None
            self.consent.setChecked(False)
            self.preview.setPlainText(result.get('preview', outcome.text))
        elif op == 'links' or (op == 'fetch' and 'extraction' in result):
            self.candidates.blockSignals(True)
            self.candidates.clear()
            self.candidates.addItem('Choose a source link explicitly', None)
            for link in result.get('extraction', {}).get('links', ()):
                state = 'Candidate' if link.get('accepted') else 'Rejected: ' + str(link.get('reason', 'unknown'))
                self.candidates.addItem(sanitize_text(f'{state} · {link.get("text", "")} · {link.get("url", "")}',
                                                      600), link)
            self.candidates.blockSignals(False)
        elif op == 'select' and isinstance(result.get('revision'), int):
            self.revision.blockSignals(True)
            self.revision.setValue(result['revision'])
            self.revision.blockSignals(False)
        self.details.setPlainText(reply.display_text or outcome.text)
        self._enable()

    def _failed(self, generation, failure):
        if self._closed or generation != self._generation:
            return
        self._pending = None
        self.status.setText(f'{failure.code}: {failure.exception_class} stopped the operation. '
                            'Previous displayed results remain available.')
        self._enable()

    def _enable(self, *_):
        if not hasattr(self, 'consent'):
            return
        idle = self._pending is None and not self._closed
        for key, button in self.buttons.items():
            button.setEnabled(idle or key == 'close')
        self.buttons['cancel'].setEnabled(not idle and not self._closed)
        have_source = bool(self.imports.currentData())
        for key in ('inspect', 'filter', 'retain'):
            self.buttons[key].setEnabled(idle and have_source)
        self.buttons['list_previous'].setEnabled(idle and self._list_offset > 0)
        self.buttons['list_next'].setEnabled(idle and self._list_offset + 20 < self._list_total)
        self.buttons['previous'].setEnabled(idle and have_source and self._entry_offset > 0)
        self.buttons['next'].setEnabled(idle and have_source and self._entry_offset + PAGE_SIZE < self._entry_total)
        entry = self._selected_entry()
        eligible = bool(entry and entry.get('basename') and entry.get('architecture') == 'amd64'
                        and entry.get('version_components') and entry.get('state') not in {'conflicted', 'descriptive-only'}
                        and (self._shown or {}).get('inventory', {}).get('scan_complete') is not False)
        self.buttons['select'].setEnabled(idle and eligible and bool(self._text('investigation'))
                                          and bool(self._text('target_product')) and self.revision.value() > 0)
        link = self.candidates.currentData()
        self.buttons['use_link'].setEnabled(idle and bool(link and link.get('accepted') and link.get('url')))
        self.consent.setEnabled(idle and self._plan is not None)
        self.buttons['fetch'].setEnabled(idle and self._plan is not None and self.consent.isChecked())
        self.buttons['revised'].setEnabled(idle and self._proposed_plan is not None)

    def cancel_operation(self):
        self._generation += 1
        self.tasks.cancel(self._channel)
        self._pending = self._plan = self._proposed_plan = None
        self.consent.setChecked(False)
        self.status.setText('Cancelled. Previous results and any completed import remain saved.')
        self._enable()

    def clear_selection_target(self):
        """Host project changed: explicit selection context must be supplied again."""
        self.cancel_operation()
        self.fields['investigation'].clear()
        self.fields['target_product'].clear()
        self.revision.setValue(0)
        self.assert_scope.setChecked(False)
        self.status.setText('The current project changed. Supply the current investigation and product before selecting.')

    def reject(self):
        if not self._closed:
            self.cancel_operation()
            self._closed = True
            if self._own_tasks:
                self.tasks.shutdown(timeout=0)
        super().reject()
