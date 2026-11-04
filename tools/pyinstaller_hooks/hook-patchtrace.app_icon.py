"""Ship the application mark as a DATA file of the frozen package (read by `patchtrace.app_icon`).

`app_icon.py` reads the SVG through importlib.resources, which PyInstaller's analysis cannot see, so this hook adds
it explicitly (it fires because `__main__.py` imports `patchtrace.app_icon`). The path comes from this file's
location, as in hook-patchtrace.unified.extract.py, so a stale install elsewhere cannot shadow it. The frozen
`--self-test` fails when the icon does not load.
"""
from pathlib import Path

_MARK = Path(__file__).resolve().parents[2] / 'src' / 'patchtrace' / 'resources' / 'patchtrace-mark.svg'
if not _MARK.is_file():
    raise SystemExit(f'PT-BUILD: the application mark is missing ({_MARK}); refusing to build the package')

datas = [(str(_MARK), 'patchtrace/resources')]
