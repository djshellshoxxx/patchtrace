"""Explicit desktop entry point; importing PatchTrace never launches Qt."""
from __future__ import annotations


def main() -> int:
    import os
    import sys
    import tempfile
    from pathlib import Path

    # Headless commands dispatch before any Qt import (SPEC-07 §11).
    # Any other first argument is a CLI typo and must fail with exit 2, never start Qt
    if len(sys.argv) > 1 and sys.argv[1] != '--self-test' and not sys.argv[1].startswith(('-platform', '-style')):
        try:
            from .cli import main as cli_main
            return cli_main(sys.argv[1:])
        except KeyboardInterrupt:  # Ctrl+C while the CLI modules are still importing: exit 5, no traceback
            print('cancelled', file=sys.stderr)
            return 5

    self_test = '--self-test' in sys.argv
    if self_test:
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication

    from .ui import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName('PatchTrace')
    app.setOrganizationName('PatchTrace')
    from .app_icon import app_icon

    app.setWindowIcon(app_icon())
    if self_test:
        from .optional_deps import summary_line
        if app.windowIcon().isNull():
            raise RuntimeError('Application icon did not load: the packaged mark is missing or invalid')
        print(summary_line())  # frozen_smoke asserts the guarded imports survive PyInstaller
        with tempfile.TemporaryDirectory(prefix='patchtrace-self-test-') as directory:
            root = Path(directory)
            from .gui.qt.kb_selftest import MARKER, run_selftest
            try:
                run_selftest(app, root)
            finally:
                # Windows also needs permissions restored when a journey assertion fails.
                for path in root.rglob('*'):
                    if path.is_file():
                        path.chmod(0o600)
        print(MARKER)
        return 0
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
