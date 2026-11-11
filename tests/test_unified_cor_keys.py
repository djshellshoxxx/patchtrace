"""SPEC-31 cache keys (02 s5), audit `cor`: every input digest changes the planned `result_id`; settings that do not
change a result's bytes do not. Synthetic inputs only."""
from __future__ import annotations

import dataclasses

import pytest
from unified_s0_fixtures import addr_map, rich_inputs

from patchtrace.unified.compute import plan_identity
from patchtrace.unified.exchange import ALL_SOURCES
from patchtrace.unified.limits import DEFAULT_LIMITS, OPERATIONAL_LIMIT_FIELDS, UnifiedLimits
from patchtrace.unified.sources import SnapshotMatch

IR = ('1' * 64, '2' * 64)


def rid(data=None, *, sources=ALL_SOURCES, limits=DEFAULT_LIMITS, ir=None, residual=True) -> str:
    return plan_identity(data or rich_inputs(), addr_map(), sources, limits=limits, ir=ir, residual=residual).result_id


def with_run(data, **changes):
    return dataclasses.replace(data, run=dataclasses.replace(data.run, **changes))


def test_the_baseline_is_stable():
    assert rid() == rid() and rid(ir=IR) == rid(ir=IR)


@pytest.mark.parametrize('name,change', [
    ('older sha', lambda d: dataclasses.replace(d, older_sha256='9' * 64)),
    ('newer sha', lambda d: dataclasses.replace(d, newer_sha256='8' * 64)),
    ('raw sha', lambda d: with_run(d, raw=dataclasses.replace(d.run.raw, sha256='7' * 64))),
    ('raw status', lambda d: with_run(d, raw=dataclasses.replace(d.run.raw, status='hash-mismatch'))),
    ('backend version', lambda d: with_run(d, backend_version='99')),
    ('one secondary set missing', lambda d: dataclasses.replace(d, secondary=d.secondary[:1])),
    ('a secondary set re-hashed', lambda d: dataclasses.replace(
        d, secondary=(dataclasses.replace(d.secondary[0], match_set=d.secondary[0].match_set.model_copy(
            update={'file_sha256': '6' * 64})), *d.secondary[1:]))),
])
def test_each_input_digest_changes_the_result_id(name, change):
    assert rid(change(rich_inputs())) != rid(), name


def test_an_analyst_correction_changes_the_result_id():
    data = rich_inputs()
    manual = next(m for m in data.matches if m.manual)
    flipped = manual.model_copy(update={'older': manual.newer, 'newer': manual.older})
    other = dataclasses.replace(data, matches=tuple(flipped if m is manual else m for m in data.matches))
    assert rid(other) != rid()
    without = dataclasses.replace(data, matches=tuple(m for m in data.matches if not m.manual))
    assert rid(without) != rid()


def test_each_selected_source_and_the_ir_digests_and_the_residual_switch_change_the_result_id():
    ids = {rid(sources=chosen) for chosen in (ALL_SOURCES, ('ghidriff',), ('ghidriff', 'bindiff'),
                                              ('ghidriff', 'rz-diff'), ('ghidriff', 'manual'))}
    assert len(ids) == 5
    base = rid(ir=IR)
    assert len({base, rid(), rid(ir=(IR[1], IR[0])), rid(ir=('3' * 64, IR[1])), rid(ir=(IR[0], '3' * 64)),
                rid(ir=IR, residual=False)}) == 6


def test_a_content_limit_changes_the_result_id_and_an_operational_one_does_not():
    content = dataclasses.replace(DEFAULT_LIMITS, l20_cosine_min_milli=900)
    assert rid(limits=content) != rid()
    for field in ('l32_results_kept', 'l33_displayed_rows', 'l34_worker_timeout_s', 'l35_filter_ms',
                  'l30_part_bytes', 'l31_pointer_body_bytes', 'l42_worker_mem_max_bytes'):
        assert rid(limits=dataclasses.replace(DEFAULT_LIMITS, **{field: getattr(DEFAULT_LIMITS, field) + 1})) == rid(), field


def test_every_limit_is_classified_content_or_operational_exactly_once():
    names = {f.name for f in dataclasses.fields(UnifiedLimits)}
    assert set(DEFAULT_LIMITS.content_dict()) | set(OPERATIONAL_LIMIT_FIELDS) == names
    assert not set(DEFAULT_LIMITS.content_dict()) & set(OPERATIONAL_LIMIT_FIELDS)


def test_input_order_does_not_change_the_result_id():
    from unified_s0_fixtures import shuffled
    data = rich_inputs()
    assert rid(shuffled(data, 5)) == rid(data)
    assert rid(with_run(data, run_id='another-run-id')) != rid(data)    # the run id is a `ghidriff` source entry
    assert isinstance(data.matches[0], SnapshotMatch)
