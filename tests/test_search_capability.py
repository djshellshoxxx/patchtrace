from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from patchtrace.search import capability as cap_mod
from patchtrace.search.capability import SearchCapability, probe_capability, require_search
from patchtrace.search.errors import ERROR_CODES, EXIT_CODES, SearchError
from patchtrace.search.limits import DEFAULT_LIMITS

_SPEC = importlib.util.spec_from_file_location(
    'check_search_runtime', Path(__file__).resolve().parents[1] / 'tools' / 'check_search_runtime.py')
check_search_runtime = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_search_runtime)


def test_probe_reports_this_runtime():
    cap = probe_capability()
    assert cap.sqlite_version == sqlite3.sqlite_version
    assert cap.fts5 and cap.unicode61 and cap.trigram and cap.usable
    require_search(cap)


def test_probe_is_false_when_fts5_creation_fails(monkeypatch):
    class Boom:
        def execute(self, *a):
            raise sqlite3.OperationalError('no such module: fts5')

        def close(self):
            pass

    monkeypatch.setattr(cap_mod.sqlite3, 'connect', lambda *_: Boom())
    cap = probe_capability()
    assert not (cap.fts5 or cap.unicode61 or cap.trigram or cap.usable)
    with pytest.raises(SearchError) as err:
        require_search(cap)
    assert err.value.code == 'PT-SEARCH-CAPABILITY' and err.value.exit_code == 2
    assert 'FTS5' in err.value.message and 'trigram' in err.value.message


@pytest.mark.parametrize('missing', ['trigram', 'unicode61'], ids=['trigram', 'unicode61'])
def test_require_names_the_missing_tokenizer(missing):
    cap = SearchCapability('3.40.0', True, missing != 'unicode61', missing != 'trigram', '', '')
    with pytest.raises(SearchError, match=missing):
        require_search(cap)


@pytest.mark.parametrize('module,expected', [
    ('rapidfuzz.fuzz_cpp_avx2', 'cpp-avx2'), ('rapidfuzz.fuzz_cpp', 'cpp'),
    ('rapidfuzz.fuzz_py', 'python'), ('rapidfuzz.other', 'unknown')], ids=['avx2', 'cpp', 'py', 'other'])
def test_rapidfuzz_backend_names(monkeypatch, module, expected):
    class Stub:
        class ratio:
            __module__ = module

    monkeypatch.setattr('rapidfuzz.fuzz', Stub, raising=False)
    monkeypatch.setattr(cap_mod.optional_deps, 'available', lambda name: True)
    assert cap_mod.rapidfuzz_backend() == expected


def test_rapidfuzz_absent_reports_empty_backend(monkeypatch):
    monkeypatch.setattr(cap_mod.optional_deps, 'available', lambda name: False)
    assert cap_mod.rapidfuzz_backend() == ''
    assert not SearchCapability('3.45.1', True, True, True, '', '').rapidfuzz_native


def test_error_codes_have_exit_codes():
    assert set(ERROR_CODES) == set(EXIT_CODES)
    assert SearchError('PT-SEARCH-CANCEL', 'x').exit_code == 5
    assert SearchError('PT-SEARCH-STORE', 'x' * 1000).message == 'x' * 400
    with pytest.raises(ValueError):
        SearchError('PT-WB-QUERY', 'x')


def test_limits_match_the_spec_table():
    limits = DEFAULT_LIMITS
    assert (limits.query_chars, limits.query_terms, limits.query_excludes, limits.page_max) == (256, 8, 4, 200)
    assert (limits.candidate_cap, limits.gui_rows_max, limits.query_timeout_s) == (20_000, 5_000, 2.0)
    assert (limits.segments_per_project, limits.cache_bytes) == (64, 4 * 1024 ** 3)
    with pytest.raises(AttributeError):
        limits.page_max = 1  # type: ignore[misc]


def test_runtime_check_tool_json(capsys):
    assert check_search_runtime.main(['--json']) == 0
    document = json.loads(capsys.readouterr().out)
    assert document['ok'] and document['usable'] and document['sqlite_version'] == sqlite3.sqlite_version


def test_runtime_check_tool_requires_native_rapidfuzz(monkeypatch, capsys):
    monkeypatch.setattr(cap_mod, 'rapidfuzz_backend', lambda: 'python')
    assert check_search_runtime.main(['--require-native-rapidfuzz']) == 1
    assert 'FAIL' in capsys.readouterr().out
