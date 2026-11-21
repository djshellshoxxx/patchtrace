"""Bounded observations of existing live-acceptance probes; never executes an additional process."""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from patchtrace.diagnostics import redact_log
from patchtrace.intelligence.tools import process

MAX_PROBES = 4
STREAM_LIMIT = 4096


def _text(value, limit):
    if value is None:
        return None, False
    redacted = redact_log(value, limit + 1)
    return redacted[-limit:], len(redacted) > limit


def _remember(document, executable, argument, result=None, exception=None):
    if argument is None:
        return
    if len(document['probes']) >= MAX_PROBES:
        document['probes_omitted'] += 1
        return
    entry = {}
    document['probes'].append(entry)
    try:
        command, entry['command_truncated'] = _text(executable.name, 128)
        entry['argv'] = [command, argument]
        if exception is not None:
            entry['exception_class'] = type(exception).__name__
            return
        entry.update(returncode=result.returncode, oversize=result.oversize, elapsed_ms=result.elapsed_ms)
        for field, limit in [('reason', 256), ('spawn_error', 1024),
                             ('stdout', STREAM_LIMIT), ('stderr', STREAM_LIMIT)]:
            value = getattr(result, field)
            entry[field], entry[field + '_truncated'] = _text(value, limit)
            if field in ('stdout', 'stderr'):
                entry[field + '_chars'] = len(value)
    except Exception as exc:
        # Diagnostic formatting must not replace an actual outcome or its original exception.
        entry['observation_error_class'] = type(exc).__name__


@contextmanager
def capture_version_probes():
    """Forward the original calls/results/exceptions and restore the callable on every exit."""
    document = {'contract': 'intel-version-probes/1', 'probes': [], 'probes_omitted': 0}
    original = process.run_version_probe

    def observed(executable, args, *positional, **kwargs):
        argument = args[0] if args in (['--version'], ['--help'], ['-H']) else None
        try:
            result = original(executable, args, *positional, **kwargs)
        except BaseException as exc:
            _remember(document, executable, argument, exception=exc)
            raise
        _remember(document, executable, argument, result=result)
        return result

    with patch.object(process, 'run_version_probe', observed):
        yield document
