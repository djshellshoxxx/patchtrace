"""Windows catalog signature probe with a consent gate for revocation (SPEC-51 D2-4). Stdlib and ctypes only.

Most Windows system files carry no embedded signature but are listed in a signed catalog (.cat). The probe hashes
the file, asks the catalog administrator which catalog lists that hash, and runs WinVerifyTrust against the catalog.
Modes: `offline` (no revocation, cache-only URL retrieval, the default), `cache` (revocation from already cached data
only) and `online` (the OS may contact CRL/OCSP hosts named inside certificates; needs `consent=True`, raised as
`ConsentRequired` otherwise). PatchTrace makes no request itself. Other platforms return `unavailable` without
touching `windll`.

STATUS: the mapping, the consent rule and the platform rule are tested with a fake probe. `win_probe` is written from
the documented API and has NOT run on Windows from this workspace; its acceptance (a system catalog-signed DLL read in
place, never copied or committed) is a blocked item for Windows CI.
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass

from patchtrace.hostile_text import is_hostile

from .models import CatalogResult

MODES = ('offline', 'cache', 'online')
_MAX_NAME = 200


class ConsentRequired(Exception):
    """Online revocation was requested without the per-operation consent."""

    def __init__(self) -> None:
        super().__init__('PT-PE-CONSENT-REQUIRED: online revocation needs consent; Windows would contact revocation '
                         'servers named inside the file, which tells them the certificate is being checked')


@dataclass(frozen=True, slots=True)
class CatalogProbe:
    found: bool
    catalog_path: str | None
    hresult: int


def verify_catalog(path: str, *, mode: str = 'offline', consent: bool = False,
                   probe: Callable[[str, str], CatalogProbe] | None = None,
                   platform: str | None = None) -> CatalogResult:
    if mode not in MODES:
        raise ValueError(f'unknown trust mode {mode!r}')
    if mode == 'online' and not consent:
        raise ConsentRequired
    if (platform or sys.platform) != 'win32':
        return CatalogResult('unavailable', None, None)
    try:
        found = (probe or win_probe)(path, mode)
    except Exception:  # noqa: BLE001 - a missing API or a ctypes failure must not break the preview
        return CatalogResult('unavailable', None, None)
    hresult = found.hresult & 0xFFFFFFFF
    if not found.found:
        return CatalogResult('absent', None, hresult)
    state = 'present_trusted_no_revocation_check' if hresult == 0 else 'present_untrusted'
    return CatalogResult(state, _clean_name(found.catalog_path), hresult)


def _clean_name(path: str | None) -> str | None:
    if not path:
        return None
    base = path.replace('\\', '/').rsplit('/', 1)[-1]
    return ''.join('?' if is_hostile(ch) else ch for ch in base[:_MAX_NAME])


def win_probe(path: str, mode: str) -> CatalogProbe:  # pragma: no cover - exercised on Windows only
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD), ('Data3', wintypes.WORD),
                    ('Data4', ctypes.c_ubyte * 8)]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('wszCatalogFile', ctypes.c_wchar * 260)]

    class WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('dwCatalogVersion', wintypes.DWORD),
                    ('pcwszCatalogFilePath', wintypes.LPCWSTR), ('pcwszMemberTag', wintypes.LPCWSTR),
                    ('pcwszMemberFilePath', wintypes.LPCWSTR), ('hMemberFile', wintypes.HANDLE),
                    ('pbCalculatedFileHash', ctypes.c_void_p), ('cbCalculatedFileHash', wintypes.DWORD),
                    ('pcCatalogContext', ctypes.c_void_p), ('hCatAdmin', wintypes.HANDLE)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('pPolicyCallbackData', ctypes.c_void_p),
                    ('pSIPClientData', ctypes.c_void_p), ('dwUIChoice', wintypes.DWORD),
                    ('fdwRevocationChecks', wintypes.DWORD), ('dwUnionChoice', wintypes.DWORD),
                    ('pCatalog', ctypes.c_void_p), ('dwStateAction', wintypes.DWORD),
                    ('hWVTStateData', wintypes.HANDLE), ('pwszURLReference', wintypes.LPCWSTR),
                    ('dwProvFlags', wintypes.DWORD), ('dwUIContext', wintypes.DWORD),
                    ('pSignatureSettings', ctypes.c_void_p)]

    wintrust, kernel32 = ctypes.windll.wintrust, ctypes.windll.kernel32
    kernel32.CreateFileW.restype = wintypes.HANDLE
    admin = wintypes.HANDLE()
    if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(admin), None, 0):
        raise OSError('CryptCATAdminAcquireContext failed')
    handle = kernel32.CreateFileW(path, 0x80000000, 1, None, 3, 0x80, None)  # GENERIC_READ, SHARE_READ
    if handle in (None, wintypes.HANDLE(-1).value):
        wintrust.CryptCATAdminReleaseContext(admin, 0)
        raise OSError('the file cannot be opened for reading')
    try:
        size = wintypes.DWORD(0)
        wintrust.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), None, 0)
        digest = (ctypes.c_ubyte * size.value)()
        if not wintrust.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), digest, 0):
            raise OSError('the catalog hash cannot be computed')
        wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
        context = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size, 0, None)
        if not context:
            return CatalogProbe(False, None, 0x800B0100)
        try:
            info = CATALOG_INFO(ctypes.sizeof(CATALOG_INFO))
            wintrust.CryptCATCatalogInfoFromContext(ctypes.c_void_p(context), ctypes.byref(info), 0)
            tag = ''.join(f'{b:02X}' for b in bytes(digest)[:size.value])
            return CatalogProbe(True, info.wszCatalogFile, _verify_catalog(
                wintrust, GUID, WINTRUST_CATALOG_INFO, WINTRUST_DATA, info.wszCatalogFile, tag, path, handle,
                digest, size.value, admin, mode))
        finally:
            wintrust.CryptCATAdminReleaseCatalogContext(admin, ctypes.c_void_p(context), 0)
    finally:
        kernel32.CloseHandle(handle)
        wintrust.CryptCATAdminReleaseContext(admin, 0)


def _verify_catalog(wintrust, guid_type, catalog_type, data_type, catalog: str, tag: str, member: str, handle,
                    digest, size: int, admin, mode: str) -> int:  # pragma: no cover - exercised on Windows only
    import ctypes
    from ctypes import wintypes

    wtd_revoke_none, wtd_revoke_wholechain = 0, 1
    cache_only, revocation_none = 0x1000, 0x10
    info = catalog_type(ctypes.sizeof(catalog_type), 0, catalog, tag, member, handle,
                        ctypes.cast(digest, ctypes.c_void_p), size, None, admin)
    data = data_type()
    data.cbStruct = ctypes.sizeof(data_type)
    data.dwUIChoice = 2  # WTD_UI_NONE
    data.fdwRevocationChecks = wtd_revoke_none if mode == 'offline' else wtd_revoke_wholechain
    data.dwUnionChoice = 2  # WTD_CHOICE_CATALOG
    data.pCatalog = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
    data.dwProvFlags = (cache_only | revocation_none) if mode == 'offline' else (
        cache_only if mode == 'cache' else 0)
    action = guid_type(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    fn = wintrust.WinVerifyTrust
    fn.argtypes = [wintypes.HWND, ctypes.POINTER(guid_type), ctypes.c_void_p]
    fn.restype = ctypes.c_long
    invalid = wintypes.HWND(-1)
    try:
        return int(fn(invalid, ctypes.byref(action), ctypes.byref(data))) & 0xFFFFFFFF
    finally:
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        fn(invalid, ctypes.byref(action), ctypes.byref(data))
