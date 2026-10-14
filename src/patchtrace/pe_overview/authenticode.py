"""Windows-only embedded Authenticode probe via WinVerifyTrust (no revocation, no network).

Embedded signatures only; catalog-signed files are out of scope and normally report ``unsigned``
or ``unknown``. A trusted result is never "fully valid": revocation was not checked.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

STATUSES = ('trusted_no_revocation_check', 'unsigned', 'untrusted', 'invalid', 'unknown', 'unavailable')

TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
TRUST_E_NOSIGNATURE = 0x800B0100
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_CHAINING = 0x800B010A
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_CERT_SIGNATURE = 0x80096004
TRUST_E_BAD_DIGEST = 0x80096010

_UNSIGNED = {TRUST_E_NOSIGNATURE}
_UNKNOWN = {TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN}
_INVALID = {TRUST_E_BAD_DIGEST, TRUST_E_CERT_SIGNATURE}
_UNTRUSTED = {CERT_E_UNTRUSTEDROOT, TRUST_E_EXPLICIT_DISTRUST, CERT_E_EXPIRED, TRUST_E_SUBJECT_NOT_TRUSTED,
              CERT_E_CHAINING}


@dataclass(frozen=True, slots=True)
class TrustResult:
    status: str
    hresult: int | None
    detail: str

    def to_dict(self) -> dict:
        return {'status': self.status, 'hresult': self.hresult, 'detail': self.detail}


def classify_hresult(hr: int) -> str:
    code = hr & 0xFFFFFFFF
    if code == 0:
        return 'trusted_no_revocation_check'
    if code in _UNSIGNED:
        return 'unsigned'
    if code in _INVALID:
        return 'invalid'
    if code in _UNTRUSTED:
        return 'untrusted'
    return 'unknown'


_DETAIL = {
    'trusted_no_revocation_check': 'Embedded signature chains to a trusted root; revocation was NOT checked.',
    'unsigned': 'No embedded signature found (a catalog signature is not examined).',
    'untrusted': 'Signature present but the chain or certificate is not trusted.',
    'invalid': 'Signature present but the file digest or signature does not verify.',
    'unknown': 'Trust state could not be determined.',
}


def verify_authenticode(path: str | Path) -> TrustResult:
    if sys.platform != 'win32':
        return TrustResult('unavailable', None, 'Authenticode verification is only available on Windows.')
    try:
        hr = _win_verify(str(path))
    except Exception as exc:  # missing API or ctypes failure must not break preview
        return TrustResult('unavailable', None, f'WinVerifyTrust unavailable: {type(exc).__name__}')
    status = classify_hresult(hr)
    return TrustResult(status, hr & 0xFFFFFFFF, f'{_DETAIL[status]} (HRESULT 0x{hr & 0xFFFFFFFF:08X})')


def _win_verify(path: str) -> int:  # pragma: no cover - exercised on Windows only
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD), ('Data3', wintypes.WORD),
                    ('Data4', ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('pcwszFilePath', wintypes.LPCWSTR),
                    ('hFile', wintypes.HANDLE), ('pgKnownSubject', ctypes.c_void_p)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('pPolicyCallbackData', ctypes.c_void_p),
                    ('pSIPClientData', ctypes.c_void_p), ('dwUIChoice', wintypes.DWORD),
                    ('fdwRevocationChecks', wintypes.DWORD), ('dwUnionChoice', wintypes.DWORD),
                    ('pFile', ctypes.c_void_p), ('dwStateAction', wintypes.DWORD),
                    ('hWVTStateData', wintypes.HANDLE), ('pwszURLReference', wintypes.LPCWSTR),
                    ('dwProvFlags', wintypes.DWORD), ('dwUIContext', wintypes.DWORD),
                    ('pSignatureSettings', ctypes.c_void_p)]

    wtd_ui_none, wtd_revoke_none, wtd_choice_file = 2, 0, 1
    wtd_verify, wtd_close = 1, 2
    wtd_cache_only_url_retrieval, wtd_revocation_check_none = 0x1000, 0x10
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = wtd_ui_none
    data.fdwRevocationChecks = wtd_revoke_none
    data.dwUnionChoice = wtd_choice_file
    data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
    data.dwStateAction = wtd_verify
    data.dwProvFlags = wtd_cache_only_url_retrieval | wtd_revocation_check_none
    fn = ctypes.windll.wintrust.WinVerifyTrust  # type: ignore[attr-defined]
    fn.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    fn.restype = ctypes.c_long
    invalid_handle = wintypes.HWND(-1)
    try:
        return int(fn(invalid_handle, ctypes.byref(action), ctypes.byref(data)))
    finally:
        data.dwStateAction = wtd_close
        fn(invalid_handle, ctypes.byref(action), ctypes.byref(data))
