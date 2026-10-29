"""The leads view model's banner lines and copy block carry ``stale_reasons`` and ``kev_source`` (pure, no Qt)."""
from __future__ import annotations

from patchtrace.kbcorrelation.leads import TEXT_NO_ADVISORY, KevSource, LeadsReport
from patchtrace.kbcorrelation.view_model import STALE_REASON_TEXT, LeadsViewModel


def report(**fields) -> LeadsReport:
    return LeadsReport(state=fields.pop('state', 'no-advisory'), text=fields.pop('text', TEXT_NO_ADVISORY), **fields)


def test_default_report_says_kev_is_not_loaded():
    lines = LeadsViewModel.from_report(report()).status_lines
    assert lines == (TEXT_NO_ADVISORY, 'KEV: not loaded.')


def test_stale_reasons_and_kev_source_are_banner_lines_in_order():
    source = KevSource(state='loaded', text='KEV: catalog 2099.01.01 (45 days old; from a local file, unverified).',
                       snapshot_id='a' * 64, catalog_version='2099.01.01', freshness='stale', age_days=45,
                       banner='This catalog is 45 days old.', notes=('The record of the catalog in use is damaged.',))
    vm = LeadsViewModel.from_report(report(state='stale', text='stale text', stale=True,
                                           stale_reasons=('file-pair', 'advisory-revision'), kev_source=source))
    assert vm.status_lines == ('stale text', STALE_REASON_TEXT['file-pair'], STALE_REASON_TEXT['advisory-revision'],
                               source.text, 'This catalog is 45 days old.',
                               'KEV note: The record of the catalog in use is damaged.')
