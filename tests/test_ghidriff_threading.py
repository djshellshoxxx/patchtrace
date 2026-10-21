"""Guard the real Ghidriff launch path against re-enabling parallel Ghidra analysis."""
from pathlib import Path

import pytest

from patchtrace.backend import BackendConfig, _ghidriff_argv


@pytest.mark.parametrize('bundled,online', [(False, False), (False, True), (True, False), (True, True)])
def test_ghidriff_launch_serializes_analysis(tmp_path: Path, bundled: bool, online: bool):
    config = BackendConfig(python_executable=str(tmp_path / 'python.exe'),
                           ghidra_dir=str(tmp_path / 'ghidra'), bundle=bundled,
                           allow_symbol_downloads=online)
    argv = _ghidriff_argv(config, tmp_path / 'old.bin', tmp_path / 'new.bin',
                          tmp_path / 'raw', tmp_path / 'projects', tmp_path / 'gzfs')
    assert argv.count('--no-threaded') == 1
    assert '--threaded' not in argv
    assert ('--no-symbols' in argv) is not online
    assert ('-I' in argv) is bundled
    assert argv.index('--no-threaded') > argv.index('--gzfs-path')
