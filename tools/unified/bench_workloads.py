"""Synthetic GT12 workloads over production IR, facts, persisted read model and Qt table paths.

Called only by the dev benchmark child after its test-builder paths are installed. No native engine or target
is executed. Fixture preparation is outside the measured operations and is reported separately.
"""
from __future__ import annotations

import random
import tempfile
import time
from collections import Counter
from pathlib import Path


def facts(n: int, seed: int, insns: int) -> dict:
    from unified_facts_builder import BASE, NEW_SHA, OLD_SHA, build_reader, decided, function

    from patchtrace.unified import keys
    from patchtrace.unified.addressing import AddressMap, PeLayout
    from patchtrace.unified.facts import verdict
    from patchtrace.unified.facts.channels import FactsContext
    from patchtrace.unified.facts.irchannels import IrSides

    rng = random.Random(seed)
    old, new, rows = [], [], []
    t0 = time.perf_counter()
    stride = max(0x400, ((insns * 5 + 64 + 0x3ff) // 0x400) * 0x400)
    for i in range(n):
        rva = 0x4000 + i * stride
        prefix = [('mov_ri', 'EAX', rng.randrange(1, 2**24)) for _ in range(max(1, insns - 6))]
        tails = (
            ([('cmp_ri', 'ECX', 32), ('jcc', 'G', 'done')],
             [('cmp_ri', 'ECX', 33), ('jcc', 'G', 'done')]),
            ([('cmp_ri', 'ECX', 0), ('jcc', 'L', 'done')],
             [('cmp_ri', 'ECX', 0), ('jcc', 'GE', 'done')]),
            ([('mov_ri', 'EAX', i + 1)], [('mov_ri', 'EAX', i + 2)]),
            ([('store_m', 'RAX', 4, 'ECX')], [('store_m', 'RAX', 8, 'ECX')]),
            ([('call_iat', 0x3000, 'kernel32!OldHelper')],
             [('call_iat', 0x3008, 'kernel32!NewHelper')]),
        )[i % 5]
        for side, tail in zip((old, new), tails, strict=True):
            side.append(function(rva, prefix + tail + [('mov_ri', 'EDX', i), ('label', 'done'), ('ret',)],
                                 name=f'changed_{i:06d}'))
        rows.append(decided(rva, rva))
    t1 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix='pt-bench-facts-') as private:
        size = 0x5000 + n * stride
        older = build_reader(Path(private), 'older', old, sha=OLD_SHA, size=size)
        newer = build_reader(Path(private), 'newer', new, sha=NEW_SHA, size=size)
        try:
            t2 = time.perf_counter()
            layout = PeLayout(image_base=BASE, size_of_image=size)
            context = FactsContext.build(
                older_sha256=OLD_SHA, newer_sha256=NEW_SHA, addr=AddressMap(layout, layout), matches=[], rows=rows,
                bindiff_flags={}, ir_sides=IrSides(older, newer, older_sections=((0x2000, 0x4000),),
                                                 newer_sections=((0x2000, 0x4000),)))
            t3 = time.perf_counter()
            counts: Counter = Counter()
            for row in rows:
                evidence = context.collect(row)
                judged = verdict.judge(keys.row_id(OLD_SHA, NEW_SHA, row.older, row.newer), row.decision, evidence)
                counts['pairs'] += 1
                counts['machine_changed'] += evidence.states['C0'] == 'differs'
                counts['with_deltas'] += bool(judged.facts.deltas)
                counts['nonbenign'] += judged.facts.verdict in ('material', 'review')
                counts['limited'] += bool(judged.facts.limits_hit)
                counts[f'verdict_{judged.facts.verdict}'] += 1
            t4 = time.perf_counter()
            counts.update({'generated_pairs': n, 'mutation_families': min(n, 5),
                           'older_instructions': sum(len(f['insns']) for f in old),
                           'newer_instructions': sum(len(f['insns']) for f in new)})
            return {'seconds': {'generate': t1 - t0, 'ingest': t2 - t1, 'context': t3 - t2,
                                'facts': t4 - t3, 'total': t4 - t2},
                    'counts': dict(counts) | {'workload': 'synthetic-ir-changed-pairs',
                                             'older_ir_digest': older.manifest.content_digest,
                                             'newer_ir_digest': newer.manifest.content_digest}}
        finally:
            older.close()
            newer.close()


def _prepare_rows(directory: Path, n: int, seed: int):
    from unified_read_support import atom, delta, make_facts, make_row, publish, request, source_ref

    from patchtrace.unified.read_model import load_unified

    rng = random.Random(seed)
    labels = list(range(n))
    rng.shuffle(labels)
    rows, facts_rows = [], []
    t0 = time.perf_counter()
    for i, label in enumerate(labels):
        old, new = 0x1000 + i * 32, 0x2000 + i * 32
        name = f'{"hit" if i % 10 == 0 else "function"}_{label:08d}_λ'
        change = ('material', 'review', 'unknown', 'cosmetic', 'unchanged')[i % 5]
        atoms = [atom(older=old, newer=new),
                 atom('bindiff', 'name hash matching', older=old, newer=new,
                      native=(('similarity', f'0.{80 + i % 20:02d}'),)),
                 atom('pt-ladder', 'H0', older=old, newer=new)]
        row = make_row([(old, name)], [(new, name)], atoms=atoms, materiality=change,
                       classes=('constant',) if change in ('material', 'review') else ())
        kwargs = ({'second': 'C6', 'C2': 'differs', 'deltas': [delta('constant', older=old, newer=new,
                     old=str(i), new=str(i + 1), channel='C2')]} if change == 'material' else
                  {'deltas': [delta('constant', older=old, newer=new, old=str(i), new=str(i + 1), channel='C2')]}
                  if change == 'review' else {'proof': 'UNCH/1'} if change == 'unchanged' else
                  {'proof': 'COS-PSEUDO/1'} if change == 'cosmetic' else {})
        rows.append(row)
        facts_rows.append(make_facts(row, change, **kwargs))
    loaded = publish(directory, rows, facts_rows, limitations=(),
                     sources=[source_ref(s) for s in ('ghidriff', 'bindiff', 'pt-ladder')])
    del rows, facts_rows
    t1 = time.perf_counter()
    vm = load_unified(request(loaded, extraction_configured=True))
    t2 = time.perf_counter()
    return vm, {'prepare': t1 - t0, 'read_model': t2 - t1}, {
        'workload': 'synthetic-persisted-mixed-rows', 'generated_rows': n, 'rows': len(vm.rows),
        'unique_rows': len({r.row_id for r in vm.rows}), 'sources': len(vm.sources), 'state': vm.state,
        'facts_records': next(p.records for p in loaded.manifest.parts if p.name == 'facts.jsonl.gz'),
        'populated_cells': sum(c.kind == 'value' for r in vm.rows for c in r.cells),
        'materiality_kinds': len({r.materiality for r in vm.rows}),
        'expected_filtered': (n + 9) // 10,
        'result_id': loaded.manifest.result_id,
        **{p.name.removesuffix('.jsonl.gz') + '_sha256': p.sha256 for p in loaded.manifest.parts}}


def read_model(n: int, seed: int, _insns: int) -> dict:
    with tempfile.TemporaryDirectory(prefix='pt-bench-read-') as private:
        _vm, seconds, counts = _prepare_rows(Path(private), n, seed)
        return {'seconds': seconds, 'counts': counts}


def ui_calls(n: int, seed: int, _insns: int) -> dict:
    from PySide6.QtCore import QEvent, QObject, Qt, qVersion
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    from patchtrace.ui_unified import UnifiedTable, UnifiedTableModel

    app = QApplication.instance() or QApplication([])
    app.setStyle('Fusion')
    app.setFont(QFont('DejaVu Sans', 9))

    class PaintCounter(QObject):
        paints = 0

        def eventFilter(self, obj, event):
            if event.type() == QEvent.Type.Paint:
                self.paints += 1
            return False

    with tempfile.TemporaryDirectory(prefix='pt-bench-ui-') as private:
        vm, seconds, counts = _prepare_rows(Path(private), n, seed)
        model, view = UnifiedTableModel(), UnifiedTable()
        view.resize(960, 420)
        view.verticalHeader().hide()
        view.verticalHeader().setDefaultSectionSize(max(28, app.fontMetrics().lineSpacing() * 2 + 6))
        view.horizontalHeader().setDefaultSectionSize(150)
        view.setModel(model)
        model.set_filter(show_collapsed=True)
        counter = PaintCounter(view)
        view.viewport().installEventFilter(counter)

        def painted(operation, action):
            calls, paints = model.data_calls, counter.paints
            start = time.perf_counter()
            action()
            app.processEvents()
            if counter.paints == paints:
                view.viewport().repaint()
            seconds[operation] = time.perf_counter() - start
            visible_rows = min(model.rowCount(), (view.viewport().height() + view.verticalHeader().defaultSectionSize()
                                                - 1) // view.verticalHeader().defaultSectionSize())
            visible_columns = sum(view.columnViewportPosition(i) < view.viewport().width()
                                  and view.columnViewportPosition(i) + view.columnWidth(i) > 0
                                  for i in range(model.columnCount()))
            counts[f'{operation}_data_calls'] = model.data_calls - calls
            counts[f'{operation}_paints'] = counter.paints - paints
            counts[f'{operation}_visible_cells'] = visible_rows * visible_columns

        def show():
            model.set_view_model(vm)
            view.show()

        try:
            painted('first_paint', show)
            counts['shown_rows'] = model.rowCount()
            painted('sort', lambda: view.sortByColumn(0, Qt.SortOrder.AscendingOrder))
            labels = [vm.rows[i].function_label.casefold() for i in model.view]
            counts['sort_correct'] = int(labels == sorted(labels))
            painted('filter', lambda: model.set_filter(search='hit_', show_collapsed=True))
            counts['filtered_rows'] = model.rowCount()
            counts['filter_correct'] = int(all('hit_' in vm.rows[i].function_label for i in model.view))
            counts['qt_version'] = qVersion()
            counts['qt_platform'] = app.platformName()
            counts['qt_style'] = app.style().objectName()
            return {'seconds': seconds, 'counts': counts}
        finally:
            view.setModel(None)
            view.close()
            view.deleteLater()
            app.processEvents()
