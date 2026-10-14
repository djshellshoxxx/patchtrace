"""Collect the dynamically loaded parts of the optional Program E dependencies (B-0).

rapidfuzz selects its C++/Python backends by name at import time and pygments resolves lexers and
formatters through generated mappings; neither is visible to static analysis. Missing packages are
simply skipped (collect_submodules returns an empty list), so a build without the extras still works.
"""
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (collect_submodules('rapidfuzz') + collect_submodules('pygments.lexers')
                 + collect_submodules('pygments.formatters') + collect_submodules('pygments.styles')
                 + ['yara_x', 'pefile'])
