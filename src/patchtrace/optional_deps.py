"""Capability probe for optional Program E dependencies.

Every import is an explicit, guarded top-level statement so PyInstaller's static analysis collects the
package; feature code asks `available(name)` instead of importing and degrades to a clear unavailable state.
Importing this module never raises and never touches the network.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata

try:
    import rapidfuzz  # noqa: F401
    from rapidfuzz import fuzz, process  # noqa: F401
except ImportError as exc:  # pragma: no cover - exercised through _IMPORT_ERRORS in tests
    rapidfuzz, _rf_error = None, repr(exc)
else:
    _rf_error = ''
try:
    import pygments  # noqa: F401
    import pygments.formatters  # noqa: F401
    import pygments.lexers  # noqa: F401
except ImportError as exc:  # pragma: no cover
    pygments, _pg_error = None, repr(exc)
else:
    _pg_error = ''
try:
    import networkx  # noqa: F401
except ImportError as exc:  # pragma: no cover
    networkx, _nx_error = None, repr(exc)
else:
    _nx_error = ''
try:
    import pefile  # noqa: F401
except ImportError as exc:  # pragma: no cover
    pefile, _pe_error = None, repr(exc)
else:
    _pe_error = ''
try:
    import yara_x  # noqa: F401
except ImportError as exc:  # pragma: no cover
    yara_x, _yx_error = None, repr(exc)
else:
    _yx_error = ''

# capability name -> (extra, distribution name, module object or None, import error)
_REGISTRY: dict[str, tuple[str, str, object, str]] = {
    'rapidfuzz': ('workbench', 'rapidfuzz', rapidfuzz, _rf_error),
    'pygments': ('workbench', 'Pygments', pygments, _pg_error),
    'networkx': ('workbench', 'networkx', networkx, _nx_error),
    'pefile': ('workbench', 'pefile', pefile, _pe_error),
    'yara-x': ('rules', 'yara-x', yara_x, _yx_error),
}
NAMES = tuple(_REGISTRY)


@dataclass(frozen=True)
class Capability:
    name: str
    extra: str
    available: bool
    version: str
    detail: str


def _version(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:  # frozen builds may lack dist-info
        return 'unknown'


def probe(names: tuple[str, ...] | None = None) -> dict[str, Capability]:
    """Return one Capability per requested name (all by default); unknown names raise KeyError."""
    out: dict[str, Capability] = {}
    for name in names or NAMES:
        extra, distribution, module, error = _REGISTRY[name]
        ok = module is not None
        out[name] = Capability(name, extra, ok, _version(distribution) if ok else '',
                               '' if ok else (error or 'not installed') + f'; pip install "patchtrace[{extra}]"')
    return out


def available(name: str) -> bool:
    return probe((name,))[name].available


def summary_line() -> str:
    caps = probe()
    have = ','.join(f'{c.name}={c.version}' for c in caps.values() if c.available) or 'none'
    missing = ','.join(c.name for c in caps.values() if not c.available) or 'none'
    return f'optional-deps: present={have} missing={missing}'
