"""Content-addressed keys for derived-cache stages `strings-table` and `strings-delta` (spec WB3 s7)."""
from __future__ import annotations

from ..enrichment.identity import domain_id

TABLE_VERSION = 1
DELTA_VERSION = 1
TABLE_STAGE = 'strings-table'
DELTA_STAGE = 'strings-delta'


def basis_digest(basis_payload: dict) -> str:
    return domain_id('strings-basis', 1, basis_payload)


def table_key(basis_digest_: str, source_sha256: str) -> str:
    """`source_sha256` is the part's raw sha for a FLOSS part, the artifact sha for the built-in scan."""
    return domain_id('strings-table', 1, {'basis_digest': basis_digest_, 'source_sha256': source_sha256,
                                          'table_version': TABLE_VERSION})


def pairing_digest(run_id: str, raw_sha256: str, manual_overrides: list) -> str:
    return domain_id('strings-pairing', 1, {'run_id': run_id, 'raw_sha256': raw_sha256,
                                            'manual_overrides': manual_overrides})


def delta_key(older_table_key: str, newer_table_key: str, pairing_digest_: str, anchors_digest: str | None) -> str:
    return domain_id('strings-delta', 1, {'older_table_key': older_table_key, 'newer_table_key': newer_table_key,
                                          'pairing_digest': pairing_digest_, 'anchors_digest': anchors_digest,
                                          'delta_version': DELTA_VERSION})
