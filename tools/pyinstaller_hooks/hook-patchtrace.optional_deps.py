"""Collect the dynamically loaded parts of the optional Program E dependencies (B-0).

rapidfuzz selects its C++/Python backends by name at import time, which is not visible to static
analysis. Missing packages are skipped (collect_submodules returns an empty list and copy_metadata is
guarded), so a build without the extras still works. Metadata makes the self-test report versions.
"""
from PyInstaller.utils.hooks import collect_submodules, copy_metadata

hiddenimports = collect_submodules('rapidfuzz') + ['yara_x', 'iced_x86']
datas = []
for _dist in ('rapidfuzz', 'yara-x', 'iced-x86'):
    try:
        datas += copy_metadata(_dist)
    except Exception:  # extra not installed
        pass
