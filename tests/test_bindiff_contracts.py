"""SPEC-29 §5/§6 additive contract changes: EngineRun.provenance, cache_key(extra=), SecondaryError.kind."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from patchtrace.secondary.contracts import SecondaryError
from patchtrace.secondary.runs import EngineRun, cache_key, new_run_id

OLD, NEW = 'a' * 64, 'b' * 64
BASE = ('bindiff', '8', 'd' * 64, OLD, NEW, 'older->newer')


def run(**over):
    data = dict(run_id=new_run_id('k' * 64, 't'), engine='bindiff', engine_version='8',
                executable_path_sha256=None, argv_digest='d' * 64, older_sha256=OLD, newer_sha256=NEW,
                orientation='older->newer', cache_key='c' * 64, status='ok', error_code=None, returncode=0,
                started_utc='t', duration_ms=1, stderr_tail='', output_sha256=None, match_set_id=None)
    return EngineRun(**(data | over))


def test_cache_key_without_extra_is_unchanged_and_extra_changes_it():
    assert cache_key(*BASE) == cache_key(*BASE, extra=())
    one = cache_key(*BASE, extra=('e' * 64, 'f' * 64))
    assert one != cache_key(*BASE)
    assert one != cache_key(*BASE, extra=('f' * 64, 'e' * 64))
    assert one == cache_key(*BASE, extra=('e' * 64, 'f' * 64))


def test_provenance_default_is_omitted_so_old_rows_round_trip_byte_identically():
    record = run()
    dumped = record.model_dump(mode='json')
    assert 'provenance' not in dumped
    old_row = json.dumps(dumped, sort_keys=True)
    again = EngineRun.model_validate_json(old_row)
    assert json.dumps(again.model_dump(mode='json'), sort_keys=True) == old_row


def test_provenance_round_trips_when_present():
    record = run(provenance={'failure_kind': 'timeout', 'binding': 'sha256'})
    back = EngineRun.model_validate_json(record.model_dump_json())
    assert back.provenance == {'failure_kind': 'timeout', 'binding': 'sha256'}


@pytest.mark.parametrize('bad', [
    {f'k{i}': 'v' for i in range(17)},
    {'k': 'v' * 257},
    {'Bad Key': 'v'},
    {'k': 1},
])
def test_provenance_bounds(bad):
    with pytest.raises(ValidationError):
        run(provenance=bad)


def test_secondary_error_kind_is_optional_and_keeps_message():
    plain = SecondaryError('PT-SECONDARY-RUN', 'x')
    assert plain.kind is None and str(plain) == 'PT-SECONDARY-RUN: x'
    kinded = SecondaryError('PT-SECONDARY-INPUT', 'y', kind='binexport-unbound')
    assert kinded.kind == 'binexport-unbound' and kinded.code == 'PT-SECONDARY-INPUT'
