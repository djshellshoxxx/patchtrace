"""`tools/bench_enrichment.py` peak RSS (random audit 1, RA-10): where the platform gives no figure the report says so
(`null`) instead of printing 0.0 MiB, which would read as passing the 512 MiB objective."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bench_enrichment  # noqa: E402


def test_peak_rss_is_none_without_the_resource_module(monkeypatch):
    monkeypatch.setitem(sys.modules, 'resource', None)  # what Windows looks like: `import resource` fails
    assert bench_enrichment.peak_rss_mib() is None


def test_the_report_says_null_not_zero_without_the_resource_module(monkeypatch, capsys):
    """Recipe R6 of the audit, on a 40-pair workload."""
    monkeypatch.setitem(sys.modules, 'resource', None)
    monkeypatch.setattr(sys, 'argv', ['bench_enrichment.py', '--pairs', '40', '--lines', '2000', '--json'])
    assert bench_enrichment.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report['peak_rss_mib'] is None and report['status'] == 'complete'


@pytest.mark.parametrize('platform,maxrss', [('linux', 524_288), ('darwin', 536_870_912)],
                         ids=['kibibytes-on-linux', 'bytes-on-macos'])
def test_peak_rss_unit_follows_the_platform(monkeypatch, platform, maxrss):
    fake = SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda who: SimpleNamespace(ru_maxrss=maxrss))
    monkeypatch.setitem(sys.modules, 'resource', fake)
    monkeypatch.setattr(sys, 'platform', platform)
    assert bench_enrichment.peak_rss_mib() == 512.0
