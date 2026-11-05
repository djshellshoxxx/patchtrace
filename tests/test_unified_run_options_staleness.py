"""The staleness of a stored unified result is judged against the options its run chose (COR-08, GUI-09).

A run records whether it asked for ProgramIR (`use_ir`) and for the residual passes (`residual`) in its provenance, so
the read model compares a stored result with the plan of those options: a result made with `--no-extract` or
`--no-residual` stays current while nothing changed, and an S0 result that was S0 only because no ProgramIR was placed
becomes stale once a ProgramIR is placed (a better result is now possible).
"""
from __future__ import annotations

import pytest
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

from patchtrace.unified import pipeline, read_model
from patchtrace.unified.pipeline import UnifiedOptions


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def _state(service) -> tuple[str, tuple[str, ...]]:
    request = read_model.request_from_service(service)
    return request.loaded.state, tuple(request.changed_inputs)


def test_the_run_row_records_the_ir_and_residual_options(project):
    pipeline.run_unified(project, UnifiedOptions(isolate=False, use_ir=False, residual=False))
    run = pipeline.recent_runs(project, 1)[0]
    assert run.provenance['use_ir'] == 'no' and run.provenance['residual'] == 'no'


@pytest.mark.parametrize('options', [dict(use_ir=False), dict(residual=False), dict(sources=('ghidriff',))],
                         ids=['no-extract', 'no-residual', 'one-source'])
def test_a_result_made_with_non_default_options_loads_current_while_nothing_changed(project, options):
    pipeline.run_unified(project, UnifiedOptions(isolate=False, **options))
    assert _state(project) == ('current', ())


def test_an_s0_result_made_because_no_ir_was_placed_is_stale_once_ir_is_placed(project, tmp_path):
    pipeline.run_unified(project, UnifiedOptions(isolate=False))           # default options; nothing placed: S0
    assert _state(project)[0] == 'current'
    place_pair(project, scratch=tmp_path)
    state, changed = _state(project)
    assert state == 'stale' and changed                                     # an IR-mode result is now possible


def test_an_explicit_no_extract_result_stays_current_when_ir_is_placed(project, tmp_path):
    pipeline.run_unified(project, UnifiedOptions(isolate=False, use_ir=False))
    place_pair(project, scratch=tmp_path)
    assert _state(project) == ('current', ())


def test_a_real_input_change_is_still_stale(project):
    pipeline.run_unified(project, UnifiedOptions(isolate=False, residual=False))
    match = next(m for m in project.project.matches if m.older and m.newer)
    project.correct_match(match.id, [match.older[0].id], [], 'removed', 'analyst decision')
    state, changed = _state(project)
    assert state == 'stale' and changed
