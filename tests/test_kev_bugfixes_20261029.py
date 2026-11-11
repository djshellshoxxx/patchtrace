"""Regression tests for issue #105 BUG-KEV-1..3: a future-dated catalog never takes over, Markdown never autolinks,
and prune leaves a snapshot an install is still writing. Offline; synthetic catalogs only."""
from __future__ import annotations

import os
from datetime import timedelta

from kev_helpers import at, document, entry, render

from patchtrace.kev import cli as kev_cli
from patchtrace.kev.service import KevService
from patchtrace.kev.store import SNAPSHOT_DIR, SNAPSHOT_SUFFIX, UNREFERENCED_GRACE_SECONDS, KevStore

TODAY = at(2026, 10, 29)


def install(service: KevService, folder, released: str):
    path = folder / f'catalog-{released[:10]}.json'
    path.write_bytes(render(document([entry(1), entry(2)], dateReleased=released,
                                     catalogVersion=released[:10].replace('-', '.'))))
    return service.import_file(path)


def test_kev1_a_future_dated_catalog_does_not_lock_out_the_genuine_one(tmp_path):
    service = KevService(tmp_path / 'kev', now=lambda: TODAY)
    assert install(service, tmp_path, '2099-01-01T00:00:00Z').result.outcome == 'installed'   # only one so far
    genuine = install(service, tmp_path, '2026-10-29T08:00:00Z')
    assert genuine.result.outcome == 'installed'
    assert service.store.load_current().catalog.meta.date_released == '2026-10-29T08:00:00Z'


def test_kev1_a_future_dated_catalog_never_replaces_a_current_one(tmp_path):
    service = KevService(tmp_path / 'kev', now=lambda: TODAY)
    install(service, tmp_path, '2026-10-28T08:00:00Z')
    assert install(service, tmp_path, '2099-01-01T00:00:00Z').result.outcome == 'kept-newer'
    assert install(service, tmp_path, '2026-10-29T08:00:00Z').result.outcome == 'installed'   # a later real one wins


def test_kev1_a_catalog_released_today_or_tomorrow_still_counts_as_newer(tmp_path):
    service = KevService(tmp_path / 'kev', now=lambda: TODAY)
    install(service, tmp_path, '2026-10-28T08:00:00Z')
    assert install(service, tmp_path, '2026-10-30T06:00:00Z').result.outcome == 'installed'  # within one day


def test_kev2_markdown_escapes_urls_hosts_and_addresses():
    for text in ('https://evil.example/login', 'www.evil.example', 'a@evil.example'):
        escaped = kev_cli._escape(text)
        assert escaped.replace('\\', '') == text                       # nothing lost, only escaped
        for index, char in enumerate(escaped):
            if char in ':./@':
                assert escaped[index - 1] == '\\', (text, escaped)        # no bare autolink trigger survives


def test_kev3_prune_keeps_a_fresh_unreferenced_snapshot_and_removes_an_old_one(tmp_path):
    root = tmp_path / 'kev'
    service = KevService(root, now=lambda: TODAY)
    install(service, tmp_path, '2026-10-28T08:00:00Z')
    orphan = root / SNAPSHOT_DIR / ('c' * 64 + SNAPSHOT_SUFFIX)
    orphan.write_bytes(b'snapshot being installed')
    stamp = TODAY.timestamp() - 10
    os.utime(orphan, (stamp, stamp))
    assert KevStore(root).prune(keep=1, yes=True, now=TODAY).removed_files == 0 and orphan.exists()
    later = TODAY + timedelta(seconds=UNREFERENCED_GRACE_SECONDS + 1)
    assert KevStore(root).prune(keep=1, yes=True, now=later).removed_files == 1 and not orphan.exists()
