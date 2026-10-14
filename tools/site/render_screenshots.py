#!/usr/bin/env python3
"""Render real PatchTrace screenshots for the project site (offscreen Qt, bundled synthetic sample).

    QT_QPA_PLATFORM=offscreen python tools/site/render_screenshots.py [--out DIR] [--only ID ...]

Every image is produced by the real ``MainWindow`` / dialogs of this checkout, driven through the same
widgets a person would use, on the bundled synthetic sample project (``ProjectService.sample``): no
Microsoft binaries, no Ghidra, no model. Nothing is drawn or composited by hand. If rendering fails, the
tool reports why, leaves existing assets untouched and exits 1 (the site then ships without that image).

Outputs in ``--out`` (default ``site/assets/screens``): ``<id>.png`` (lossless, optimised), ``<id>.webp``
and ``screens.json`` (id, size, alt text, caption), which ``build_site.py`` reads.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / 'site' / 'assets' / 'screens'
WIDTH, HEIGHT = 1440, 900
WEBP_QUALITY = 84


class ScreenshotError(RuntimeError):
    """A state could not be reached; the caller must not substitute a fake image."""


@dataclass(frozen=True)
class Shot:
    id: str
    title: str
    alt: str
    caption: str
    prepare: Callable  # (ctx) -> QWidget to grab


class Context:
    """Holds the Qt objects for one rendering session."""

    def __init__(self, tmp: Path):
        from PySide6.QtCore import QSettings
        from PySide6.QtWidgets import QApplication

        from patchtrace.service import ProjectService
        from patchtrace.ui import MainWindow
        self.app = QApplication.instance() or QApplication(['patchtrace-site'])
        self.service = ProjectService.sample(tmp / 'sample-project')
        settings = QSettings(str(tmp / 'ui.ini'), QSettings.Format.IniFormat)
        self.window = MainWindow(self.service, settings, tmp / 'profiles')
        self.window.evidence.auto_probe = False  # never probe the machine for engines while rendering
        self.window.resize(WIDTH, HEIGHT)
        self.window.show()
        self.pump()

    def pump(self, rounds: int = 6):
        for _ in range(rounds):
            self.app.processEvents()
            time.sleep(0.02)

    def wait(self, condition: Callable[[], bool], what: str, timeout: float = 60.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.app.processEvents()
            if condition():
                self.pump(3)
                return
            time.sleep(0.02)
        raise ScreenshotError(f'timed out waiting for {what}')

    def select_function(self, name: str):
        from PySide6.QtCore import Qt
        nav = self.window.navigator
        for row in range(nav.count()):
            item = nav.item(row)
            if name in item.text() and 'modified' in item.text().lower():
                nav.setCurrentItem(item)
                self.pump()
                return item.data(Qt.ItemDataRole.UserRole)
        for row in range(nav.count()):  # fall back to the first row that names the function
            item = nav.item(row)
            if name in item.text():
                nav.setCurrentItem(item)
                self.pump()
                return item.data(Qt.ItemDataRole.UserRole)
        raise ScreenshotError(f'function {name!r} not in the sample match list')

    def close(self):
        window = self.window
        try:
            window.evidence.shutdown()
        finally:
            window.close()
            if window.service:
                window.service.close()
                window.service = None
            self.pump()


# ---- states -----------------------------------------------------------------------------------------


def shot_workspace(ctx: Context):
    w = ctx.window
    ctx.select_function('read_item')
    w.mode.setCurrentText('Decompiled code')
    ctx.pump()
    if w.findings_list.count():
        w.findings_list.setCurrentRow(0)
        ctx.pump()
    w.next_diff.click()
    ctx.pump()
    return w


def shot_ranked(ctx: Context):
    w = ctx.window
    w.mode.setCurrentText('Decompiled code')
    w.rank_action.trigger()
    ctx.wait(lambda: w.worker is None and w.order.currentIndex() == 1, 'the Rank changes job')
    ctx.select_function('read_item')
    if w.signal_list.count():
        w.signal_list.setCurrentRow(0)
        ctx.pump()
    else:
        raise ScreenshotError('ranking produced no change signals for the sample')
    return w


def shot_overview(ctx: Context):
    w = ctx.window
    w.show_file_overview()
    dialog = w._preflight_dialog
    ctx.wait(lambda: w._preflight_status.text().startswith('File inspection complete'), 'the PE inspection')
    dialog.resize(1180, 960)
    ctx.pump()
    return dialog


def shot_hex(ctx: Context):
    w = ctx.window
    ctx.select_function('read_item')
    w.mode.setCurrentText('Hex (raw bytes)')
    ctx.pump()
    for view in w.views.values():  # scroll like a person would, to the line where the two files differ
        view.verticalScrollBar().setValue(30)
    ctx.pump()
    return w


def shot_export(ctx: Context):
    from patchtrace.ui import ExportDialog
    w = ctx.window
    ctx.select_function('read_item')
    selected = []
    dialog = ExportDialog(w.project, w.service.root, selected, w)
    dialog.enrichment = w._enrichment_export()
    # The only edit to a real widget: the default destination is inside this run's temporary directory.
    dialog.destination.setText('report.md')
    dialog.resize(1100, 760)
    dialog.show()
    dialog.refresh_preview()
    ctx.pump()
    return dialog


SHOTS: tuple[Shot, ...] = (
    Shot('workspace', 'Paired code and analyst review',
         'PatchTrace main window on the synthetic bounds-check sample. Left: a list of four function '
         'matches (added, removed and two modified). Centre: the older and newer decompiled read_item '
         'function side by side, with the inserted null and index check highlighted in the newer pane and '
         'a blank gap in the older pane. Right: a finding about a guard added before an indexed buffer '
         'access, its explanation, evidence list and analyst review controls.',
         'The workspace: function matches, older and newer code side by side with the changed region '
         'highlighted, and the review panel.', shot_workspace),
    Shot('ranked', 'Ranked changes with change signals',
         'The same window after Rank changes. The function list now begins with read_item scored 26 in '
         'square brackets, followed by report_invalid_index with a dash instead of a score, get_version '
         'scored 0 and debug_dump with a dash. The change signals list shows one bounds-check detector hit on newer '
         'lines 2 to 5, which are highlighted in the newer code pane.',
         'Deterministic detectors order functions by research priority. The number is an ordinal '
         'attention score, not a vulnerability verdict, and a dash means the evidence needed was '
         'unavailable.', shot_ranked),
    Shot('hex', 'Raw bytes view',
         'The code panes switched to Hex (raw bytes): offset-addressed hexadecimal dumps of the older and '
         'newer files side by side, with whole-file scope, page and go-to-offset controls above them and a '
         'status line reporting that one line differs at equal offsets; that line is highlighted in both '
         'panes.',
         'Raw Hex, Binary and Base64 views of the verified original bytes, with differing lines '
         'highlighted.', shot_hex),
    Shot('overview', 'PE file overview',
         'The File overview dialog. A first table lists recorded fields for the older and newer files '
         '(name, size, size change, SHA-256, hash comparison, format). A status line reads file inspection '
         'complete. A second, longer table lists parsed PE fields for both files, such as machine type '
         'AMD64, characteristics, entry point, image base, alignment and subsystem.',
         'File overview: recorded metadata plus a bounded, read-only PE comparison that works before any '
         'analysis is run.', shot_overview),
    Shot('export', 'Report export preview',
         'The Export dialog. A format selector set to md, a destination field, a checkbox to include '
         'function code (off), one to include analyst notes (on), a note that absolute paths are redacted '
         'and raw provider responses are excluded, and an exact Markdown preview of the report beginning '
         'with the change ranking table.',
         'Exports show the exact report first. Function code is opt-in, analyst notes are opt-out, and '
         'absolute paths are redacted.', shot_export),
)


# ---- image output -----------------------------------------------------------------------------------


def pixmap_to_png(pixmap) -> bytes:
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not pixmap.save(buffer, 'PNG'):
        raise ScreenshotError('Qt could not encode the grabbed pixmap')
    buffer.close()
    return bytes(data)


def write_assets(shot_id: str, png: bytes, out: Path) -> tuple[int, int, int, int]:
    """Optimise with Pillow; returns (width, height, png_bytes, webp_bytes)."""
    from PIL import Image
    image = Image.open(io.BytesIO(png)).convert('RGB')
    width, height = image.size
    png_path, webp_path = out / f'{shot_id}.png', out / f'{shot_id}.webp'
    image.save(png_path, format='PNG', optimize=True)
    image.save(webp_path, format='WEBP', quality=WEBP_QUALITY, method=6)
    return width, height, png_path.stat().st_size, webp_path.stat().st_size


def render(out: Path, only: list[str] | None = None) -> list[dict]:
    selected = [shot for shot in SHOTS if not only or shot.id in only]
    if not selected:
        raise ScreenshotError(f'no screenshot ids match {only!r}; known: {[s.id for s in SHOTS]}')
    out.mkdir(parents=True, exist_ok=True)
    records = []
    with tempfile.TemporaryDirectory(prefix='patchtrace-shots-') as tmp:
        ctx = Context(Path(tmp))
        try:
            for shot in selected:
                widget = shot.prepare(ctx)
                ctx.pump()
                pixmap = widget.grab()
                if pixmap.isNull() or pixmap.width() < 400:
                    raise ScreenshotError(f'{shot.id}: empty grab')
                width, height, png_size, webp_size = write_assets(shot.id, pixmap_to_png(pixmap), out)
                records.append({'id': shot.id, 'title': shot.title, 'alt': shot.alt, 'caption': shot.caption,
                                'width': width, 'height': height, 'png_bytes': png_size,
                                'webp_bytes': webp_size})
                if widget is not ctx.window:
                    widget.close()
                    ctx.pump()
        finally:
            ctx.close()
    return records


def write_manifest(out: Path, records: list[dict]):
    import patchtrace
    manifest = {
        'schema': 'patchtrace-site-screens/1',
        'source': 'Real GUI rendered offscreen from ProjectService.sample (synthetic; no Microsoft binaries, '
                  'no Ghidra, no model).',
        'patchtrace_version': patchtrace.__version__,
        'shots': records,
    }
    (out / 'screens.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n',
                                      encoding='utf-8', newline='\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--only', nargs='*', help='render only these ids (manifest is merged)')
    args = parser.parse_args(argv)
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    sys.path.insert(0, str(ROOT / 'src'))
    try:
        records = render(args.out, args.only)
        manifest_path = args.out / 'screens.json'
        if args.only and manifest_path.exists():  # merge: keep the other shots' records
            kept = {r['id']: r for r in json.loads(manifest_path.read_text(encoding='utf-8'))['shots']}
            kept.update({r['id']: r for r in records})
            order = [s.id for s in SHOTS]
            records = [kept[i] for i in order if i in kept]
        write_manifest(args.out, records)
    except Exception as error:  # noqa: BLE001 - report plainly, keep prior assets, never fake an image
        print(f'render_screenshots: FAILED ({type(error).__name__}: {error}). '
              'Existing site assets were left unchanged; ship the page without the missing screenshot.',
              file=sys.stderr)
        return 1
    for record in records:
        print(f"{record['id']}: {record['width']}x{record['height']} png {record['png_bytes']:,} B "
              f"webp {record['webp_bytes']:,} B")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
