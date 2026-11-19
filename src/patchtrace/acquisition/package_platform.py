"""Platform prerequisite only. It does not load a decoder or claim native acceptance."""
from __future__ import annotations

import platform
import struct
import sys

from .contracts import AcquisitionError


def require_supported_platform(*, system: str | None = None, machine: str | None = None,
                               pointer_bits: int | None = None) -> str:
    system = sys.platform if system is None else system
    if system != 'win32':
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'local CAB/MSU intake requires native Windows')
    machine = platform.machine() if machine is None else machine
    pointer_bits = struct.calcsize('P') * 8 if pointer_bits is None else pointer_bits
    if (type(machine) is not str or machine.casefold() not in {'amd64', 'x86_64'}
            or type(pointer_bits) is not int or pointer_bits != 64):
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'the initial FDI capability requires Windows AMD64')
    return 'windows-amd64'
