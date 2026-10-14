"""BinExport2 message class from the checked-in descriptor set, in a private pool, upb only (SPEC-10b §2).

The protobuf runtime is imported lazily. A pure-Python runtime is refused (85x memory, ~125x slower on hostile
input), as is a runtime older than the pin. No gencode module exists, so there is no gencode/runtime coupling.
"""
from __future__ import annotations

import base64
import hashlib
import re
import threading

from . import binexport_descriptor as D

PINNED_PROTOBUF = (7, 36, 2)
REASONS = ('protobuf_missing', 'protobuf_not_upb', 'protobuf_too_old', 'descriptor_mismatch')


class ProtoUnavailable(Exception):
    def __init__(self, reason: str, detail: str = ''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason


_lock = threading.Lock()
_cached: tuple[type | None, ProtoUnavailable | None] | None = None


def _version_tuple(text: str) -> tuple[int, ...]:
    parts = []
    for piece in text.split('.')[:3]:
        match = re.match(r'\d{1,6}', piece)  # leading digits: '2rc1' -> 2
        parts.append(int(match.group()) if match else 0)
    return tuple(parts)


def descriptor_bytes() -> bytes:
    data = base64.b64decode(D.DESCRIPTOR_SET_B64, validate=True)
    if hashlib.sha256(data).hexdigest() != D.DESCRIPTOR_SET_SHA256:
        raise ProtoUnavailable('descriptor_mismatch', 'descriptor set hash differs from its recorded value')
    return data


def runtime_info() -> dict[str, str]:
    """Version/implementation facts for provenance; raises ProtoUnavailable."""
    try:
        import google.protobuf as protobuf
        from google.protobuf.internal import api_implementation
    except ImportError:
        raise ProtoUnavailable('protobuf_missing', 'the protobuf runtime is not installed') from None
    implementation = api_implementation.Type()
    if implementation != 'upb':
        raise ProtoUnavailable('protobuf_not_upb', f'protobuf implementation is {implementation!r}, need upb')
    if _version_tuple(protobuf.__version__) < PINNED_PROTOBUF:
        raise ProtoUnavailable('protobuf_too_old', f'protobuf {protobuf.__version__} is older than the pin')
    return {'protobuf_version': protobuf.__version__, 'implementation': implementation}


def _build() -> type:
    runtime_info()
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    files = descriptor_pb2.FileDescriptorSet.FromString(descriptor_bytes())
    if [f.name for f in files.file] != ['binexport2.proto'] or files.file[0].package:
        raise ProtoUnavailable('descriptor_mismatch', 'unexpected descriptor set layout')
    pool = descriptor_pool.DescriptorPool()  # private: never registers a top-level BinExport2 globally
    pool.Add(files.file[0])
    return message_factory.GetMessageClass(pool.FindMessageTypeByName('BinExport2'))


def load_binexport2_class() -> type:
    """Memoised; raises ProtoUnavailable(reason) with a §7 UNSUPPORTED slug."""
    global _cached
    with _lock:
        if _cached is None:
            try:
                _cached = (_build(), None)
            except ProtoUnavailable as exc:
                _cached = (None, exc)
        cls, error = _cached
    if error is not None:
        raise error
    return cls  # type: ignore[return-value]


def reset_cache() -> None:
    """Tests only: forget the memoised class/error."""
    global _cached
    with _lock:
        _cached = None
