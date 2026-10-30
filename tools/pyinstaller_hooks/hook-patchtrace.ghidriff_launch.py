"""Ship the Ghidriff launcher as a DATA file of the frozen package (SPEC-53 GHR-2).

`ptlaunch.py` is never imported by PatchTrace: `ghidriff_launch.validate` reads its bytes (importlib.resources), copies
them into a private scratch directory and runs the user's EXTERNAL Python on the copy. The path comes from this file's
location (not `collect_data_files`, which can silently collect nothing when a stale editable install shadows the tree).
"""
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / 'src' / 'patchtrace' / 'ghidriff_launch' / 'ptlaunch.py'
if not _SCRIPT.is_file():
    raise SystemExit(f'PT-BUILD: the Ghidriff launcher is missing ({_SCRIPT}); refusing to build the package')

datas = [(str(_SCRIPT), 'patchtrace/ghidriff_launch')]
