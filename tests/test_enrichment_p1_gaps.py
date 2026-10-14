"""SPEC-07h P1 leftovers found while re-verifying H3/H5 and SPEC-07 §4 (synthetic fixtures only)."""
from __future__ import annotations

import pytest
from test_enrichment_signals import fn, found, view

from patchtrace.enrichment import pipeline, signals, views
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.signals import detect
from patchtrace.service import ProjectService

# --- H3: truncation is partial even when the scanned part shows no edit ------------------------

def _long(tail):
    return fn(*[f'  buf[{i}] = {i};' for i in range(8)], f'  {tail};', '  return 0;')


def test_truncated_without_visible_edit_is_partial(monkeypatch):
    monkeypatch.setattr(views, 'MAX_LINES', 5)  # the only edit sits in the unscanned tail
    result = detect(view(_long('len = 1'), _long('len = 2')))
    assert result.status == 'partial'
    assert any(o.status == 'partial' and o.reason.startswith(signals.LIMIT) for o in result.outcomes)


def test_truncated_with_visible_edit_is_partial(monkeypatch):
    monkeypatch.setattr(views, 'MAX_LINES', 5)
    old = fn('  buf[idx] = 1;', *[f'  buf[{i}] = {i};' for i in range(8)], '  return 0;')
    new = fn('  if (idx >= len) return -1;', '  buf[idx] = 1;', *[f'  buf[{i}] = {i};' for i in range(8)],
             '  return 0;')
    result = detect(view(old, new))
    assert result.status == 'partial' and any(s.detector == 'BND' for s in result.signals)


def test_untruncated_unchanged_function_stays_complete():
    assert detect(view(_long('len = 1'), _long('len = 1'))).status == 'complete'


# --- H5: `do { } while (c)` closer is a loop header ---------------------------------------------

def test_bnd_added_do_while_is_not_a_guard():
    old = ['  return 0;']
    new = ['  do {', '    buf[i] = 0;', '    i = i + 1;', '  } while (i < len);', '  return 0;']
    assert found(fn(*old), fn(*new), 'BND') == []


def test_bnd_changed_do_while_bound_fires():
    old = ['  do {', '    buf[i] = 0;', '    i = i + 1;', '  } while (i < len);', '  return 0;']
    new = ['  do {', '    buf[i] = 0;', '    i = i + 1;', '  } while (i < len && i < idx);', '  return 0;']
    assert len(found(fn(*old), fn(*new), 'BND')) == 1


# --- SPEC-07 §4: validate_location ---------------------------------------------------------------

@pytest.fixture
def located(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    result = pipeline.run(svc.project)
    signal = next(s for ss in result.signal_sets for s in ss.signals)
    yield svc.project, result.views, signal.locations[0]
    svc.close()


def test_validate_location_accepts_live_location(located):
    project, run_view, loc = located
    for subject in (project, run_view):
        function = views.validate_location(subject, loc)
        assert function.id == loc.function_id and function.side == loc.side


@pytest.mark.parametrize('field,value,code', [
    ('function_id', 'forged-function', 'PT-ENRICH-OWNERSHIP'),
    ('artifact_id', 'forged-artifact', 'PT-ENRICH-OWNERSHIP'),
    ('run_id', 'forged-run', 'PT-ENRICH-OWNERSHIP'),
    ('excerpt_sha256', '0' * 64, 'PT-ENRICH-STALE'),
    ('end_line', 10_000, 'PT-ENRICH-STALE'),
])
def test_validate_location_rejects_forgery_and_drift(located, field, value, code):
    _project, run_view, loc = located
    data = loc.model_dump()
    data[field] = value
    if field == 'end_line':
        data['start_line'] = loc.start_line
    bad = type(loc).model_validate(data)
    with pytest.raises(EnrichmentError) as info:
        views.validate_location(run_view, bad)
    assert info.value.code == code


def test_validate_location_rejects_wrong_side(located):
    _project, run_view, loc = located
    flipped = loc.model_copy(update={'side': 'older' if loc.side == 'newer' else 'newer'})
    with pytest.raises(EnrichmentError) as info:
        views.validate_location(run_view, flipped)
    assert info.value.code == 'PT-ENRICH-OWNERSHIP'


def test_truncated_pairing_wil_outcome_is_partial(monkeypatch):
    monkeypatch.setattr(views, 'MAX_LINES', 5)  # the flag check sits in the unscanned tail
    pairing = view(_long('if (Feature_1234__private_IsEnabledDeviceUsage()) { len = 1; }'),
                   _long('if (Feature_1234__private_IsEnabledDeviceUsage()) { len = 2; }'))
    outcome = pipeline._wil_outcome(pairing.pairing_id, pairing, (), 'complete')
    assert outcome.status == 'partial' and outcome.reason.startswith(signals.LIMIT)
    monkeypatch.setattr(views, 'MAX_LINES', 20_000)
    whole = view(_long('len = 1'), _long('len = 2'))
    assert pipeline._wil_outcome(whole.pairing_id, whole, (), 'complete').status == 'complete'
