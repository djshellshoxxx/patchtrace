# Independent review: final-progress ownership and report cleanup

## Verdict and scope

No blocking finding was found in the two scoped repairs. The reviewer independently inspected both code paths, ran their maintained checks, and authored additional lifecycle and filesystem-outcome controls. This accepts these source changes for coordinator integration; it does not grant main-merge, full-suite, Windows, packaging, accessibility, native-runtime, or release acceptance.

The review was performed by a fresh `review_integrated_fixes` worker that did not author either repair. No remote ref, author worktree, shared task ledger, target binary, external service, or source-execution capability was modified.

## Exact sources

- Starting candidate: `67f7e08ea9bee61653f8ab5ad66048d3e7141810` (PR #344).
- Report specification/tests recovered as `7a305f32`; implementation recovered as `b119f5570590107f65a0d96371f7816ed38eb99c`. Original donor commits are `ddbcacf4d22d1ef0868f0ed9f9207a5ccf0245a9` and `b3d7d3999370b09f9c6c061680e12026ba36d8bf`.
- TaskRunner specification, tests, and implementation: `ffd50497b184aa81d908f9686d10f9720948daf6`.
- Frozen combined review source: `c2e1f9b11cb9aba8f49dc4df4a8a8967d5c08e16`, tree `71c927a460bb42453421dea667ec52f37c576a3a`. This is `b119f557` plus the unchanged TaskRunner source patch, in an isolated worktree. It is a reviewer-local source identity, not a remote publication claim.
- The reviewer baseline replay used the census worktree at `53d69f68`, whose runtime/test source remains unchanged from `67f7e08e`; its additional files are census documentation only.

| Reviewed file | Exact Git blob |
| --- | --- |
| `src/patchtrace/gui/qt/tasks.py` | `0b08892fd383d91a5f4d1766ba932adc9c92507b` |
| `tests/test_gui_tasks.py` | `b52517b4f3e2a7d90a172f7933d5afbab44e4ee4` |
| `src/patchtrace/reports.py` | `d3450d7610593ea89294fc59ce73a5c40db08e92` |
| `tests/test_report_export_cleanup.py` | `f31d502f3af39e9e83ebf91d2231bf7b779ce2d0` |

## Review reasoning

### TaskRunner final progress

`_deliver` removes only its own task from `_running`, then checks lifetime, generation, drop state, and hidden state. Final progress may synchronously reenter the runner. The new second check after `_flush_progress` prevents an old outcome from reaching its callback after cancellation, supersession, shutdown, or bridge deletion. It does not clear a replacement's running task or token.

If progress hides the channel, delivery parks the completed outcome. `task.sent` is set before invoking progress, so resuming the parked outcome does not replay that progress. The `finally` block releases the current event unless that exact event is parked. This identity comparison also preserves a different event parked by a replacement during a nested GUI wait. Callback references and payloads are released on the GUI thread on refusal or an escaping progress exception.

Generation-less FIFO lane requests and cooperative token-only cancellation keep their existing semantics. The review does not claim to repair unrelated FIFO cancellation or general worker-result resource protocols.

### Report cleanup

A successful `os.replace` consumes the staging name. Removing the unconditional cleanup prevents a later error from changing success, and prevents deletion of an independent file that has subsequently reused that name. On failure, the code removes the attempt's staging file where possible. An `OSError` from cleanup adds a fixed note instead of replacing the primary typed error or interruption. New staging and backup failures retain the original destination bytes. There is no report content or wire-schema change.

The repair does not make the pre-existing report publisher an OS-level path-race sandbox. Its scope is cleanup outcome precedence and successful-stage ownership.

## Verification

All runs used Python 3.12.14, the existing declared-dependency environment, explicit reviewed `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE=1`, `QT_QPA_PLATFORM=offscreen`, disabled pytest cache, and isolated tmpfs test data. The Qt controls use actual threads and queued GUI delivery. Filesystem controls use local authored files; no analyzed binary is executed.

| Selection | Passed | Failed | Errors | Skipped | JUnit SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| Maintained selection | 95 | 0 | 0 | 0 | `69237b431eaba02c95d3ba6a5ad948658a1161cebbdbcbcb8b75b21b23f69b33` |
| Fresh controls, repaired | 11 | 0 | 0 | 0 | `522f7e29d5a21c8499e1c9ed54d95aab30c29796dd7ab106b62f55522283bbd2` |
| Fresh controls, baseline | 2 | 9 | 0 | 0 | `9c8890356d2401625f29e4974bc80158c2334f7e6f002fca0b4607d145d0dbee` |

The maintained selection completed in **7.55 seconds**. The fresh repaired controls completed in **0.56 seconds**. The identical fresh controls against baseline source completed with **9 failures and 2 passes in 10.99 seconds**, establishing that the controls distinguish the missing behavior. The failures were six final-progress lifecycle cases, two reused report staging-name cases, and one interruption/cleanup-precedence case. They are expected baseline failures and remain recorded separately.

Maintained command, on the frozen combined source:

```sh
PYTHONPATH=/tmp/PatchTrace-review-2bad/src PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen /workspace/scratch/b1d1356aa953/patchtrace-venv/bin/python -m pytest -q -p no:cacheprovider tests/test_gui_tasks.py tests/test_report_export_cleanup.py tests/test_report_export_backup.py tests/test_export_destination_guard.py --basetemp=/tmp/patchtrace-review-2bad-maintained --junitxml=/tmp/patchtrace-review-2bad-maintained.xml
```

Focused Ruff on both product files and their two maintained regression files passed. `git diff --check` passed. The working tree was clean before this review note. Counts here overlap author/coordinator selections and must not be added to those selections as new product coverage.

Fresh controls cover shutdown from final progress, nested replacement while hidden, cancellation after parking, preservation of a foreign file reusing a consumed report staging name, initial staging failure, backup refusal with successful cleanup, and `SystemExit` plus cleanup denial.

## Limits and handoff

Coordinator must test the final combined integration source, retain source-specific CI receipts, and satisfy all applicable repository gates before a guarded remote merge. No full-suite, native Windows, packaged desktop, external runtime, empirical accuracy, or human accessibility acceptance was executed by this reviewer. The Linux Strings publication change belongs to a separate review scope.

The fresh control source is embedded below so this evidence is reproducible after temporary paths disappear. Save the block as `test_independent_review.py`, select the desired frozen checkout with `PYTHONPATH`, and run it under pytest/pytest-qt. Original XML and baseline failure log currently remain under `/tmp/patchtrace-review-2bad-controls/`; this document retains their hashes and outcomes, not a claim that those temporary files are durable.

Control source SHA-256: `4fc82a6469483cd6d2551a1e10bd99949a2b9707e620b486203e56b891a2c086`.

## Reproducible independent controls

```python
"""Fresh reviewer controls for final-progress lifetime and consumed report stages."""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest

from patchtrace import reports
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.sample import create_sample


@pytest.fixture
def runner(qapp):
    value = TaskRunner(reraise=True)
    yield value
    assert value.shutdown(timeout=5) == []


def submit_completed(runner, progress, results, errors, fails):
    def work(token, report):
        report('complete', 1, 1)
        if fails:
            raise ValueError('unobserved private detail')
        return 'old'

    runner.submit('review', work, results.append, errors.append, progress)
    runner._bridge.timer.stop()
    return next(iter(runner._running))


@pytest.mark.parametrize('fails', [False, True])
def test_final_progress_shutdown_releases_outcome(runner, qtbot, fails):
    seen, results, errors = [], [], []

    def close(progress):
        seen.append(progress)
        assert runner.shutdown(timeout=5) == []

    task = submit_completed(runner, close, results, errors, fails)
    qtbot.waitUntil(lambda: bool(seen), timeout=5000)
    assert results == errors == []
    assert task.fn is task.on_result is task.on_error is task.on_progress is None
    assert not runner.busy() and not runner._parked


@pytest.mark.parametrize('fails', [False, True])
def test_final_progress_nested_replacement_preserves_its_parked_event(runner, qtbot, fails):
    seen, results, errors = [], [], []
    release = threading.Event()

    def replace_and_hide(progress):
        seen.append(progress)
        runner.set_applying('review', False)
        runner.submit('review', lambda token, report: release.wait(5) and 'new',
                      results.append, errors.append)
        release.set()
        # A nested GUI wait can deliver the replacement while old progress is still on the stack.
        qtbot.waitUntil(lambda: 'review' in runner._parked, timeout=5000)

    old = submit_completed(runner, replace_and_hide, results, errors, fails)
    qtbot.waitUntil(lambda: bool(seen) and 'review' in runner._parked, timeout=5000)
    assert results == errors == []
    assert old.fn is old.on_result is old.on_error is old.on_progress is None
    runner.set_applying('review', True)
    assert results == ['new'] and errors == [] and len(seen) == 1
    assert not runner._parked


@pytest.mark.parametrize('fails', [False, True])
def test_final_progress_park_then_cancel_releases_without_replay(runner, qtbot, fails):
    seen, results, errors = [], [], []

    def hide(progress):
        seen.append(progress)
        runner.set_applying('review', False)

    task = submit_completed(runner, hide, results, errors, fails)
    qtbot.waitUntil(lambda: 'review' in runner._parked, timeout=5000)
    runner.cancel('review')
    runner.set_applying('review', True)
    assert results == errors == [] and len(seen) == 1
    assert not runner._parked
    assert task.fn is task.on_result is task.on_error is task.on_progress is None


@pytest.fixture
def project(tmp_path):
    with create_sample(tmp_path / 'project') as service:
        return service.project


@pytest.mark.parametrize('version', [1, 2])
def test_successful_report_does_not_remove_reused_staging_name(tmp_path, project, monkeypatch, version):
    destination = tmp_path / 'report.json'
    original_replace = reports.os.replace
    foreign = []

    def replace_then_reuse(source, target):
        original_replace(source, target)
        source = Path(source)
        source.write_bytes(b'concurrent independent file')
        foreign.append(source)

    monkeypatch.setattr(reports.os, 'replace', replace_then_reuse)
    manifest = reports.export_project(project, 'json', destination, report_version=version)
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == manifest.sha256
    assert len(foreign) == 1 and foreign[0].read_bytes() == b'concurrent independent file'


def test_initial_staging_failure_stays_typed_without_cleanup_note(tmp_path, project, monkeypatch):
    destination = tmp_path / 'report.json'
    destination.write_bytes(b'previous report')

    def refuse(*args, **kwargs):
        raise PermissionError('private path should not be included')

    monkeypatch.setattr(reports.tempfile, 'NamedTemporaryFile', refuse)
    with pytest.raises(reports.ExportError) as failure:
        reports.export_project(project, 'json', destination)
    assert str(failure.value) == 'PT-EXPORT: cannot write report; check destination permissions and free space'
    assert not getattr(failure.value, '__notes__', [])
    assert destination.read_bytes() == b'previous report'


def test_backup_failure_successful_cleanup_keeps_same_typed_error(tmp_path, project, monkeypatch):
    destination = tmp_path / 'report.json'
    destination.write_bytes(b'previous report')
    error = reports.ExportError('PT-EXPORT: backup refused')

    def refuse(*args, **kwargs):
        raise error

    monkeypatch.setattr(reports, '_keep_previous', refuse)
    with pytest.raises(reports.ExportError) as failure:
        reports.export_project(project, 'json', destination)
    assert failure.value is error and not getattr(error, '__notes__', [])
    assert destination.read_bytes() == b'previous report'
    assert list(tmp_path.glob('.patchtrace-export-*')) == []


def test_system_exit_survives_cleanup_denial(tmp_path, project, monkeypatch):
    destination = tmp_path / 'report.json'
    destination.write_bytes(b'previous report')
    original_unlink = Path.unlink
    error = SystemExit(31)

    def stop(*args, **kwargs):
        raise error

    def refuse_stage(path, *args, **kwargs):
        if path.name.startswith('.patchtrace-export-'):
            raise PermissionError('private cleanup detail')
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(reports.os, 'replace', stop)
    monkeypatch.setattr(Path, 'unlink', refuse_stage)
    with pytest.raises(SystemExit) as failure:
        reports.export_project(project, 'json', destination)
    assert failure.value is error and error.code == 31
    assert error.__notes__ == [
        'PT-EXPORT: temporary report cleanup failed; a staging file may remain beside the destination'
    ]
    assert destination.read_bytes() == b'previous report'
```
