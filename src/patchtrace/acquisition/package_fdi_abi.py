"""Pinned AMD64 FDI declarations; no DLL load, package I/O or native qualification.

Microsoft win32metadata a40ed3186943620f304649a077b78f8271034736,
RecompiledIdlHeaders/um/fdi.h and fdi_fci_types.h. DIAMONDAPI is cdecl.
"""
from __future__ import annotations

import ctypes as c
import json

from .contracts import AcquisitionError
from .package_platform import require_supported_platform

SDK_REFERENCE = 'a40ed3186943620f304649a077b78f8271034736'
LONG = BOOL = c.c_int32
ULONG = UINT = c.c_uint32
USHORT = c.c_uint16
INT_PTR = c.c_ssize_t


class ERF(c.Structure):
    _fields_ = [('erfOper', LONG), ('erfType', LONG), ('fError', BOOL)]


class FDICABINETINFO(c.Structure):
    _fields_ = [('cbCabinet', LONG), ('cFolders', USHORT), ('cFiles', USHORT),
                ('setID', USHORT), ('iCabinet', USHORT), ('fReserve', BOOL),
                ('hasprev', BOOL), ('hasnext', BOOL)]


class FDINOTIFICATION(c.Structure):
    # Opaque pointers prevent an implicit unbounded string read in ctypes.
    _fields_ = [('cb', LONG), ('psz1', c.c_void_p), ('psz2', c.c_void_p), ('psz3', c.c_void_p),
                ('pv', c.c_void_p), ('hf', INT_PTR), ('date', USHORT), ('time', USHORT),
                ('attribs', USHORT), ('setID', USHORT), ('iCabinet', USHORT), ('iFolder', USHORT),
                ('fdie', LONG)]


class FDISPILLFILE(c.Structure):
    _fields_ = [('ach', c.c_char * 2), ('cbFile', LONG)]


PFNALLOC = c.CFUNCTYPE(c.c_void_p, ULONG)
PFNFREE = c.CFUNCTYPE(None, c.c_void_p)
PFNOPEN = c.CFUNCTYPE(INT_PTR, c.c_void_p, LONG, LONG)
PFNREAD = c.CFUNCTYPE(UINT, INT_PTR, c.c_void_p, UINT)
PFNWRITE = c.CFUNCTYPE(UINT, INT_PTR, c.c_void_p, UINT)
PFNCLOSE = c.CFUNCTYPE(LONG, INT_PTR)
PFNSEEK = c.CFUNCTYPE(LONG, INT_PTR, LONG, LONG)
PFNFDINOTIFY = c.CFUNCTYPE(INT_PTR, LONG, c.POINTER(FDINOTIFICATION))

EXPECTED_LAYOUT = {
    'pointer_bits': 64,
    'ERF.size': 12, 'ERF.erfOper': 0, 'ERF.erfType': 4, 'ERF.fError': 8,
    'FDICABINETINFO.size': 24, 'FDICABINETINFO.cbCabinet': 0, 'FDICABINETINFO.cFolders': 4,
    'FDICABINETINFO.cFiles': 6, 'FDICABINETINFO.setID': 8, 'FDICABINETINFO.iCabinet': 10,
    'FDICABINETINFO.fReserve': 12, 'FDICABINETINFO.hasprev': 16, 'FDICABINETINFO.hasnext': 20,
    'FDINOTIFICATION.size': 64, 'FDINOTIFICATION.cb': 0, 'FDINOTIFICATION.psz1': 8,
    'FDINOTIFICATION.psz2': 16, 'FDINOTIFICATION.psz3': 24, 'FDINOTIFICATION.pv': 32,
    'FDINOTIFICATION.hf': 40, 'FDINOTIFICATION.date': 48, 'FDINOTIFICATION.time': 50,
    'FDINOTIFICATION.attribs': 52, 'FDINOTIFICATION.setID': 54, 'FDINOTIFICATION.iCabinet': 56,
    'FDINOTIFICATION.iFolder': 58, 'FDINOTIFICATION.fdie': 60,
    'FDISPILLFILE.size': 8, 'FDISPILLFILE.ach': 0, 'FDISPILLFILE.cbFile': 4,
}


def layout_snapshot() -> dict[str, int]:
    result = {'pointer_bits': c.sizeof(c.c_void_p) * 8}
    for structure in (ERF, FDICABINETINFO, FDINOTIFICATION, FDISPILLFILE):
        result[f'{structure.__name__}.size'] = c.sizeof(structure)
        for name, _kind in structure._fields_:
            result[f'{structure.__name__}.{name}'] = getattr(structure, name).offset
    return result


def verify_amd64_layout() -> None:
    if layout_snapshot() != EXPECTED_LAYOUT:
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'FDI declarations do not match the pinned Windows AMD64 ABI')


def verify_native_layout(raw: bytes) -> dict[str, int]:
    """Validate a bounded probe response, without claiming it came from a native process."""
    verify_amd64_layout()
    if type(raw) is not bytes or len(raw) > 4096:
        raise AcquisitionError('PT-ACQ-LIMIT', 'FDI ABI receipt exceeds its byte boundary')

    def pairs(values):
        result = {}
        for name, value in values:
            if name in result:
                raise ValueError('duplicate ABI field')
            result[name] = value
        return result

    def invalid_constant(_value):
        raise ValueError('nonfinite ABI field')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid_constant)
        if (type(value) is not dict or any(type(item) is not int for item in value.values())
                or value != EXPECTED_LAYOUT):
            raise ValueError('SDK receipt differs from the pinned ABI')
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AcquisitionError('PT-ACQ-VERIFY', 'invalid or mismatched FDI SDK layout receipt') from exc
    return value


def bind_functions(library):
    """Type required entries of an already selected trusted DLL; never load a path here."""
    require_supported_platform()
    verify_amd64_layout()
    signatures = {
        'FDICreate': (c.c_void_p, [PFNALLOC, PFNFREE, PFNOPEN, PFNREAD, PFNWRITE, PFNCLOSE,
                                  PFNSEEK, LONG, c.POINTER(ERF)]),
        'FDIIsCabinet': (BOOL, [c.c_void_p, INT_PTR, c.POINTER(FDICABINETINFO)]),
        'FDICopy': (BOOL, [c.c_void_p, c.c_void_p, c.c_void_p, LONG, PFNFDINOTIFY,
                          c.c_void_p, c.c_void_p]),  # Decryption stays NULL in the decoder.
        'FDIDestroy': (BOOL, [c.c_void_p]),
    }
    try:
        functions = {name: getattr(library, name) for name in signatures}
    except AttributeError as exc:
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'system FDI lacks a required entry point') from exc
    for name, function in functions.items():
        function.restype, function.argtypes = signatures[name]
    return library
