"""Ship the Ghidra extractor script as a DATA file of the frozen package (SPEC-31 03 s3, plan s4).

`ghidra_script.py` is never imported by PatchTrace: the runner reads its bytes (importlib.resources), copies them into an
empty private directory and runs the user's EXTERNAL Python on the copy, because the script needs pyghidra, JPype and
Ghidra, which the frozen application does not contain. PyInstaller's analysis cannot see a file that nobody imports, so
this hook adds it explicitly (the hook fires because `backend.py` imports `patchtrace.unified.extract.retain`, and the
runner imports the package, so no hidden import is needed). The path comes from this file's location, not from
`collect_data_files`: that helper imports the package in an isolated child process and silently collects nothing when
a stale editable install elsewhere shadows the source tree, which would build a package that cannot extract. The
build scripts also verify that the file is in the inventory and equals the source tree's copy.
"""
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / 'src' / 'patchtrace' / 'unified' / 'extract' / 'ghidra_script.py'
if not _SCRIPT.is_file():
    raise SystemExit(f'PT-BUILD: the extractor script is missing ({_SCRIPT}); refusing to build the package')

datas = [(str(_SCRIPT), 'patchtrace/unified/extract')]
