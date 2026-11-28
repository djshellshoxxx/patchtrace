"""Compile/run only the authored FDI ABI probe in a configured Windows SDK environment."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from threading import Event

from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.acquisition.package_fdi_abi import SDK_REFERENCE, verify_native_layout
from patchtrace.acquisition.package_platform import require_supported_platform
from patchtrace.jobs import run_process


def check(compiler: str | None = None) -> dict:
    require_supported_platform()  # Before compiler discovery, source reads or process creation.
    compiler = compiler or shutil.which('cl.exe')
    if compiler is None:
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'configure a Windows AMD64 MSVC/SDK environment for ABI qualification')
    compiler_path = Path(compiler).absolute()
    source = Path(__file__).resolve().parent / 'native' / 'package_fdi_abi.cpp'
    source_bytes = source.read_bytes()
    if len(source_bytes) > 64 * 1024:
        raise AcquisitionError('PT-ACQ-LIMIT', 'authored ABI probe source exceeds its bound')
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    with tempfile.TemporaryDirectory(prefix='patchtrace-fdi-abi-') as temporary:
        root = Path(temporary)
        executable = root / 'probe.exe'
        env = dict(os.environ)
        compiled = run_process([str(compiler_path), '/nologo', '/W4', '/WX', '/EHsc', '/std:c++17',
                                str(source), f'/Fo{root / "probe.obj"}', f'/Fe{executable}'],
                               cwd=root, env=env, cancel=Event(), timeout_seconds=90,
                               log_limit=64 * 1024, separate_streams=True, stderr_limit=64 * 1024,
                               memory_limit_bytes=512 * 2**20, max_output_bytes=1024 * 1024)
        if (compiled.returncode != 0 or compiled.reason is not None
                or compiled.stdout_total > 1024 * 1024 or compiled.stderr_total > 64 * 1024):
            raise AcquisitionError('PT-ACQ-VERIFY', 'installed Windows SDK could not compile the authored FDI ABI probe')
        if source.read_bytes() != source_bytes:
            raise AcquisitionError('PT-ACQ-VERIFY', 'authored ABI source changed during compilation')
        measured = run_process([str(executable)], cwd=root, env=env, cancel=Event(), timeout_seconds=10,
                               log_limit=4096, separate_streams=True, stderr_limit=4096,
                               memory_limit_bytes=128 * 2**20, max_output_bytes=4096)
        if (measured.returncode != 0 or measured.reason is not None or measured.stderr_total
                or measured.stdout_total > 4096 or measured.log_bytes is None
                or measured.stdout_total != len(measured.log_bytes)):
            raise AcquisitionError('PT-ACQ-VERIFY', 'authored FDI ABI probe did not complete cleanly')
        layout = verify_native_layout(measured.log_bytes if measured.log_bytes is not None else b'')
    return {'status': 'passed', 'platform': 'windows-amd64', 'header_reference': SDK_REFERENCE,
            'source_sha256': source_hash, 'sdk_version': env.get('WindowsSDKVersion', 'unavailable')[:200],
            'layout': layout, 'scope': 'installed-SDK signatures and layout; no decoder or package acceptance'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', help='explicit MSVC cl.exe; otherwise the configured SDK environment is used')
    args = parser.parse_args(argv)
    try:
        result = check(args.compiler)
    except (AcquisitionError, OSError, ValueError) as exc:
        print(f'package-fdi-abi: {str(exc)[:300]}', file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
