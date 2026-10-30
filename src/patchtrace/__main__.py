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

    app.setWindowIcon(app_icon())  # an empty icon never blocks startup; the self-test below rejects it
    if self_test:
        from PySide6.QtCore import QSettings

        from .optional_deps import summary_line
        from .service import ProjectService
        print(summary_line())  # frozen_smoke asserts the guarded imports survive PyInstaller
        if app.windowIcon().isNull():
            raise RuntimeError('Application icon did not load: the packaged mark is missing or invalid')
        with tempfile.TemporaryDirectory(prefix='patchtrace-self-test-') as directory:
            root = Path(directory)
            service = ProjectService.sample(root / 'sample')
            settings = QSettings(str(root / 'settings.ini'), QSettings.Format.IniFormat)
            window = MainWindow(service=service, settings=settings)
            try:
                window.show()
                app.processEvents()
                if not window.navigator.count() or 'SYNTHETIC SAMPLE' not in window.project_label.text():
                    raise RuntimeError('Desktop self-test did not display sample matches')
                problems = window.panels.self_check()  # every manifest module imported, every panel built once
                if problems:
                    raise RuntimeError('Panel self-check failed: ' + '; '.join(problems))
            finally:
                # Release the project lock/SQLite connection even on failure so cleanup can proceed.
                window.close()
                app.processEvents()
            # Windows cannot remove immutable copied artifacts until permissions are restored.
            for path in root.rglob('*'):
                if path.is_file():
                    path.chmod(0o600)
        return 0
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
