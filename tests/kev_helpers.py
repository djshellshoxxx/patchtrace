"""Shared builders for the kev/1 tests: fixture bytes, catalog documents, injected clocks. Offline and deterministic."""
from __future__ import annotations

import copy
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchtrace.kev.parse import parse_catalog

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures' / 'kev'
SYNTHETIC = 'kev-synthetic-2099.json'
REAL = 'kev-real-trimmed.json'
RETRIEVED = '2099-03-02T08:00:00Z'
SHA_A, SHA_B = 'a' * 64, 'b' * 64


def socket_guard():
    """Body of the module-scoped autouse fixture ``no_sockets = pytest.fixture(autouse=True, scope='module')(...)``:
    any socket use fails the test, so no non-live KEV test can reach a network (module scope keeps Hypothesis happy)."""
    def refuse(*args, **kwargs):
        raise AssertionError('KEV tests must not open sockets')

    with pytest.MonkeyPatch.context() as patch:
        for name in ('socket', 'create_connection', 'getaddrinfo'):
            patch.setattr(socket, name, refuse)
        yield


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_document(name: str) -> dict:
    return json.loads(fixture_bytes(name))


def at(year: int, month: int, day: int, hour: int = 12, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=UTC)


NOW = at(2099, 3, 2)                      # one day after the synthetic catalog was released


def parse_bytes(raw: bytes, *, name: str = 'catalog.json', retrieved_at: str = RETRIEVED):
    return parse_catalog(raw, source='local-import', retrieved_at=retrieved_at, file_name=name)


def parse_fixture(name: str):
    return parse_bytes(fixture_bytes(name), name=name)


def parse_document(document: dict, *, indent: int | None = 4, name: str = 'catalog.json'):
    return parse_bytes(render(document, indent=indent), name=name)


def render(document: dict, *, indent: int | None = 4) -> bytes:
    return json.dumps(document, indent=indent, ensure_ascii=False).encode('utf-8')


class _Absent:
    def __repr__(self) -> str:
        return 'ABSENT'


ABSENT = _Absent()                        # entry(notes=ABSENT) leaves the key out


def entry(number: int = 1, **overrides) -> dict:
    """One valid upstream entry (all twelve fields), CVE-2098-<number>."""
    value = {'cveID': f'CVE-2098-{number:05d}', 'vendorProject': 'Example Vendor', 'product': 'Example Product',
             'vulnerabilityName': f'Example Vulnerability {number}', 'dateAdded': '2098-01-10',
             'shortDescription': f'SYNTHETIC description {number}.', 'requiredAction': 'SYNTHETIC action.',
             'dueDate': '2098-01-31', 'knownRansomwareCampaignUse': 'Unknown', 'forensicTriage': 'No',
             'notes': 'https://example.invalid/a ; https://example.invalid/b', 'cwes': ['CWE-20']}
    value.update(overrides)
    return {key: item for key, item in value.items() if item is not ABSENT}


def document(entries: list[dict] | None = None, **overrides) -> dict:
    """A valid upstream document; ``count`` follows the entries unless overridden."""
    rows = [entry(1), entry(2)] if entries is None else entries
    value = {'title': 'SYNTHETIC', 'catalogVersion': '2098.02.01', 'dateReleased': '2098-02-01T12:00:00.1234Z',
             'count': len(rows), 'vulnerabilities': rows}
    value.update(overrides)
    return {key: item for key, item in value.items() if item is not ABSENT}


def mutated(base: dict, path: tuple, value) -> dict:
    """A deep copy of ``base`` with the item at ``path`` replaced (``ABSENT`` deletes a key)."""
    result = copy.deepcopy(base)
    target = result
    for step in path[:-1]:
        target = target[step]
    if value is ABSENT:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return result
