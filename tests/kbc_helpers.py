"""Synthetic fixtures and builders for the KB-CVE correlator (plan K0f). Pure: no network, no Microsoft data.

Every identifier here is synthetic: CVE-2099-*, KB5099*, PT-* product ids, "Example" product names and
``example.invalid`` hosts. The committed files live in ``tests/fixtures/kbcorrelation/`` and are listed, with
hashes, in ``MANIFEST.json``. :func:`generated_files` is the source of the builder-made JSON; the test
``tests/test_kbc_fixtures.py`` asserts the committed bytes still equal it, so editing a builder without
regenerating the file fails the gate.

Commands for the synergy baseline (plan s5), to rerun by hand against a project ``P``::

    python -m patchtrace rank P --dry-run
    python -m patchtrace correlate P --cve CVE-2099-20001 --snapshot F --dry-run

Their numbers are golden provenance owned by K4a, so nothing here asserts them.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from patchtrace.sample import synthetic_pe

FIXTURE_DIR = Path(__file__).resolve().parent / 'fixtures' / 'kbcorrelation'
MANIFEST_NAME = 'MANIFEST.json'
README_NAME = 'README.md'

DIALECT = 'cvrf-json/0'
RELEASE_ID = '2099-Feb'

PRODUCT_CLIENT = 'PT-CLIENT'
PRODUCT_ARM = 'PT-CLIENT-ARM'
PRODUCT_SERVER = 'PT-SERVER'
PRODUCT_SERVER_CORE = 'PT-SERVER-CORE'
PRODUCT_SERVER_LEGACY = 'PT-SERVER-LEGACY'  # CSAF only; absent from the CVRF product tree
PRODUCT_UNKNOWN = 'PT-NOPE'  # referenced by a remediation but never defined (S06)

KB_CLIENT = 'KB5099001'
KB_SERVER = 'KB5099002'
KB_SHARED = 'KB5099007'  # one KB, three CVEs, two architectures (S03)

CVE_A = 'CVE-2099-20001'  # KEV-listed, CWE-125 stated, client and ARM64 plus server
CVE_B = 'CVE-2099-20002'  # CWE-190, server only
CVE_MENTION = 'CVE-2099-20003'  # KB5099001 appears only in a Type 5 known-issue text

PRODUCTS: tuple[dict[str, str], ...] = (
    {'product_id': PRODUCT_CLIENT, 'name': 'Example OS 24H2 x64', 'family': 'windows-client', 'architecture': 'amd64'},
    {'product_id': PRODUCT_ARM, 'name': 'Example OS 24H2 ARM64', 'family': 'windows-client', 'architecture': 'arm64'},
    {'product_id': PRODUCT_SERVER, 'name': 'Example Server 2099 x64', 'family': 'windows-server',
     'architecture': 'amd64'},
    {'product_id': PRODUCT_SERVER_CORE, 'name': 'Example Server 2099 Core x64', 'family': 'windows-server',
     'architecture': 'amd64'},
)

REMEDIATION_VENDOR_FIX = 2
REMEDIATION_KNOWN_ISSUE = 5


class FixtureError(ValueError):
    """Raised for a bad fixture name or a duplicate key in strict JSON."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_path(name: str) -> Path:
    """Path of a committed fixture. Names are plain basenames; traversal is refused."""
    if not name or '/' in name or '\\' in name or name.startswith('.') or name in (MANIFEST_NAME, README_NAME):
        raise FixtureError(f'not a fixture name: {name!r}')
    return FIXTURE_DIR / name


def read_fixture_bytes(name: str) -> bytes:
    return fixture_path(name).read_bytes()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f'duplicate key {key!r}')
        result[key] = value
    return result


def load_fixture_json(name: str, *, strict: bool = False) -> Any:
    """Parse a committed JSON fixture. ``strict=True`` refuses duplicate keys (NEG-07)."""
    text = read_fixture_bytes(name).decode('utf-8')
    if strict:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    return json.loads(text)


def render_json(obj: Any) -> bytes:
    """Canonical committed form: sorted keys, two-space indent, ASCII escapes, LF, final newline."""
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')


# --- CVRF month documents (synthetic dialect cvrf-json/0; the real shape is unverified until probe L1) ---


def remediation(kind: int, description: str, product_ids: tuple[str, ...] | list[str],
                fixed_build: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {'type': kind, 'description': description, 'product_ids': list(product_ids)}
    if fixed_build is not None:
        row['fixed_build'] = fixed_build
    return row


def vulnerability(cve: str, title: str, *, description: str = '', cwe: tuple[str, str] | None = None,
                  remediations: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
                  product_statuses: dict[str, list[str]] | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        'cve': cve,
        'title': title,
        'description': description,
        'remediations': [dict(item) for item in remediations],
        'product_statuses': {k: list(v) for k, v in (product_statuses or {}).items()},
    }
    if cwe is not None:
        row['cwe'] = {'id': cwe[0], 'name': cwe[1]}
    return row


def cvrf_document(vulnerabilities: list[dict[str, Any]] | tuple[dict[str, Any], ...], *,
                  release_id: str = RELEASE_ID, products: tuple[dict[str, str], ...] = PRODUCTS) -> dict[str, Any]:
    return {
        'dialect': DIALECT,
        'synthetic': True,
        'document': {
            'tracking_id': f'PT-CVRF-{release_id}',
            'title': f'Synthetic monthly bulletin {release_id} (PatchTrace fixture, not Microsoft)',
            'release_id': release_id,
            'current_release_date': '2099-02-13',
            'publisher': 'PatchTrace synthetic fixture',
        },
        'product_tree': [dict(p) for p in products],
        'vulnerabilities': [dict(v) for v in vulnerabilities],
    }


def baseline_cvrf() -> dict[str, Any]:
    """The two-CVE month of plan s3.1 and s5: client and ARM64 take KB5099001, server takes KB5099002."""
    fixed_client = '10.0.26100.9001'
    fixed_server = '10.0.26100.9002'
    return cvrf_document([
        vulnerability(
            CVE_A, 'Out-of-bounds read in the item reader',
            description='Synthetic: an item-reader index is not checked before a read.',
            cwe=('CWE-125', 'Out-of-bounds Read'),
            remediations=[
                remediation(REMEDIATION_VENDOR_FIX, KB_CLIENT[2:], [PRODUCT_CLIENT, PRODUCT_ARM], fixed_client),
                remediation(REMEDIATION_VENDOR_FIX, KB_SERVER[2:], [PRODUCT_SERVER], fixed_server),
            ],
            product_statuses={'Fixed': [PRODUCT_CLIENT, PRODUCT_ARM, PRODUCT_SERVER]},
        ),
        vulnerability(
            CVE_B, 'Integer overflow in the allocation size check',
            description='Synthetic: a size product wraps before the allocation.',
            cwe=('CWE-190', 'Integer Overflow or Wraparound'),
            remediations=[remediation(REMEDIATION_VENDOR_FIX, KB_SERVER[2:], [PRODUCT_SERVER], fixed_server)],
            product_statuses={'Fixed': [PRODUCT_SERVER]},
        ),
        vulnerability(
            CVE_MENTION, 'Information disclosure in the diagnostic log',
            description='Synthetic: diagnostic text is written to a shared log.',
            remediations=[remediation(REMEDIATION_KNOWN_ISSUE,
                                      f'Known issue (synthetic note): {KB_CLIENT} changes startup timing; '
                                      'this is not a fix.', [PRODUCT_CLIENT])],
        ),
    ])


def neg_cvrf() -> dict[str, Any]:
    """Negative cases, one per row of the plan's NEG and S matrix (see README for the mapping)."""
    client_pair = [PRODUCT_CLIENT, PRODUCT_ARM]
    return cvrf_document([
        vulnerability('CVE-2099-20004', 'Use-after-free in the session cache',  # S05 duplicate pointers
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, '5099003', [PRODUCT_SERVER_CORE],
                                                '10.0.26100.9003')] * 2),
        vulnerability('CVE-2099-20005', 'Heap overflow in the rendering helper',  # S04 multi-product, one source
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, '5099004',
                                                [PRODUCT_SERVER, PRODUCT_SERVER_CORE], '10.0.26100.9004')]),
        vulnerability('CVE-2099-20006', 'Denial of service in the name parser',  # S06 undefined ProductID
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, '5099005', [PRODUCT_UNKNOWN],
                                                '10.0.26100.9005')]),
        vulnerability('CVE-2099-20007', 'Elevation of privilege in the token broker',  # S07, NEG-06
                      remediations=[remediation(REMEDIATION_KNOWN_ISSUE,
                                                'Known issue KB5099006 (synthetic): no fix ships in this row.',
                                                [PRODUCT_CLIENT])]),
        vulnerability('CVE-2099-20008', 'Spoofing in the update helper',  # S08 negative status contradicts fix
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, '5099008', [PRODUCT_CLIENT],
                                                '10.0.26100.9008')],
                      product_statuses={'Not affected': [PRODUCT_CLIENT]}),
        vulnerability('CVE-2099-20009', 'Tampering in the settings reader',  # S09 unrelated number
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, 'build 19045 reference, not a KB',
                                                [PRODUCT_CLIENT])]),
        vulnerability('CVE-2099-20010', 'Information disclosure in the cache index',  # NEG-01 slash and control
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, '5099010/../x\u0007', [PRODUCT_CLIENT])]),
        vulnerability('CVE-2099-20011', 'Spoofing in the preview pane <img src=x onerror=alert(1)> ‮plain',
                      description='Click [here](https://evil.example.invalid/redirect?to=//x) '
                                  '<script>alert(1)</script>',  # S19, NEG-24, NEG-25: text only, never fetched
                      remediations=[remediation(REMEDIATION_VENDOR_FIX, '5099011', [PRODUCT_CLIENT],
                                                '10.0.26100.9011')]),
        *[vulnerability(f'CVE-2099-2001{n}', f'Shared parser flaw {label}',  # S03 one KB, three CVEs, two arches
                        remediations=[remediation(REMEDIATION_VENDOR_FIX, KB_SHARED[2:], client_pair,
                                          '10.0.26100.9007')])
          for n, label in ((2, 'A'), (3, 'B'), (4, 'C'))],
    ], products=PRODUCTS)


def reordered(doc: dict[str, Any]) -> dict[str, Any]:
    """Same content with every array reversed. Parsing must not depend on array order (plan s10.2)."""
    out = copy.deepcopy(doc)
    out['product_tree'].reverse()
    out['vulnerabilities'].reverse()
    for row in out['vulnerabilities']:
        row['remediations'].reverse()
        for item in row['remediations']:
            item['product_ids'].reverse()
        for status in row['product_statuses'].values():
            status.reverse()
    return out


# --- CSAF advisory with KB-relevant cases (S05, S12, S13, S14, NEG-08) ---


def baseline_csaf() -> dict[str, Any]:
    products = [
        ('Example OS 24H2 x64', PRODUCT_CLIENT),
        ('Example OS 24H2 ARM64', PRODUCT_ARM),
        ('Example Server 2099 x64', PRODUCT_SERVER),
        ('Example Server 2099 Core x64', PRODUCT_SERVER_CORE),
        ('Example Server 2089 x64', PRODUCT_SERVER_LEGACY),
    ]
    return {
        'document': {
            'category': 'csaf_security_advisory',
            'csaf_version': '2.0',
            'lang': 'en',
            'title': 'Synthetic KB fixture advisory (not Microsoft)',
            'publisher': {
                'category': 'vendor',
                'name': 'PatchTrace Synthetic Fixture Vendor (not Microsoft)',
                'namespace': 'https://example.invalid/csaf-kb',
            },
            'tracking': {
                'id': 'PT-SYNTH-KB-2099-02',
                'status': 'final',
                'version': '1',
                'initial_release_date': '2099-02-13T00:00:00Z',
                'current_release_date': '2099-02-13T00:00:00Z',
                'revision_history': [
                    {'number': '1', 'date': '2099-02-13T00:00:00Z', 'summary': 'Initial synthetic release'},
                ],
            },
        },
        'product_tree': {
            'branches': [
                {'category': 'product_name', 'name': name,
                 'product': {'name': name, 'product_id': pid}}
                for name, pid in products
            ],
            'product_groups': [
                {'group_id': 'PT-GRP-CLIENT', 'product_ids': [PRODUCT_CLIENT, PRODUCT_ARM]},
                {'group_id': 'PT-GRP-SERVER', 'product_ids': [PRODUCT_SERVER, PRODUCT_SERVER_CORE]},
            ],
        },
        'vulnerabilities': [
            {
                'cve': CVE_A,
                'title': 'Out-of-bounds read in the item reader',
                'cwe': {'id': 'CWE-125', 'name': 'Out-of-bounds Read'},
                'notes': [{'category': 'description', 'title': 'Summary',
                           'text': 'Synthetic note: an item-reader index is not checked before a read.'}],
                'product_status': {
                    'known_affected': [PRODUCT_CLIENT, PRODUCT_ARM, PRODUCT_SERVER],
                    'fixed': [PRODUCT_CLIENT, PRODUCT_ARM],
                },
                'remediations': [{
                    'category': 'vendor_fix',
                    'details': f'Install update {KB_CLIENT} for Example OS 24H2.',
                    'group_ids': ['PT-GRP-CLIENT'],
                    'url': 'https://support.example.invalid/help/5099001',
                }],
            },
            {
                'cve': CVE_B,
                'title': 'Integer overflow in the allocation size check',
                'cwe': {'id': 'CWE-190', 'name': 'Integer Overflow or Wraparound'},
                'notes': [{'category': 'description', 'title': 'Summary',
                           'text': 'Synthetic note: a size product wraps before the allocation.'}],
                'product_status': {
                    'known_affected': [PRODUCT_SERVER, PRODUCT_SERVER_CORE],
                    'known_not_affected': [PRODUCT_SERVER_LEGACY],
                },
                'remediations': [{  # S12: a vendor fix without any KB token yields no KB association
                    'category': 'vendor_fix',
                    'details': 'Install the latest servicing update for Example Server 2099.',
                    'group_ids': ['PT-GRP-SERVER'],
                }],
            },
        ],
    }


# --- KEV snapshot (synthetic; field names follow the public KEV shape, values are invented) ---


def kev_snapshot() -> dict[str, Any]:
    return {
        'contract': 'synthetic-kev-snapshot/0',
        'synthetic': True,
        'catalog_version': '2099.02.14-synthetic',
        'snapshot_retrieved_at': '2099-02-14T00:00:00Z',
        'count': 1,
        'vulnerabilities': [{
            'cveID': CVE_A,
            'vendorProject': 'Example Vendor',
            'product': 'Example OS',
            'vulnerabilityName': 'Synthetic out-of-bounds read',
            'dateAdded': '2099-02-12',
            'requiredAction': 'Synthetic fixture: no action',
            'dueDate': '2099-03-05',
            'knownRansomwareCampaignUse': 'Unknown',
        }],
    }


# --- identifier syntax matrix (kb-syntax/1 and CVE edge rules, checked against ids.py) ---


def identifier_matrix() -> list[dict[str, Any]]:
    def row(rid: str, op: str, raw: str, expect: str, output: Any = None, note: str = '') -> dict[str, Any]:
        out: dict[str, Any] = {'id': rid, 'op': op, 'input': raw, 'expect': expect, 'note': note}
        if output is not None:
            out['output'] = output
        return out

    return [
        row('K01', 'canonical_kb', 'KB5099001', 'ok', 'KB5099001'),
        row('K02', 'canonical_kb', 'KB1234', 'ok', 'KB1234', 'lower bound: 4 digits'),
        row('K03', 'canonical_kb', 'KB0001234', 'ok', 'KB0001234', 'leading zeros are kept'),
        row('K04', 'canonical_kb', 'KB1234567890', 'ok', 'KB1234567890', 'upper bound: 10 digits'),
        row('K05', 'canonical_kb', 'KB123', 'reject', note='3 digits'),
        row('K06', 'canonical_kb', 'KB12345678901', 'reject', note='11 digits'),
        row('K07', 'canonical_kb', 'kb5099001', 'reject', note='lower-case prefix is edge-only'),
        row('K08', 'canonical_kb', 'KB 5099001', 'reject', note='space is edge-only'),
        row('K09', 'canonical_kb', '5099001', 'reject', note='bare digits are edge-only'),
        row('K10', 'canonical_kb', 'KB5099001 ', 'reject', note='trailing space'),
        row('K11', 'canonical_kb', 'KB-5099001', 'reject', note='dash is edge-only'),
        row('K12', 'canonical_kb', 'KB٥٠٩٩٠٠١', 'reject',
            note='Arabic-Indic digits are not ASCII'),
        row('K13', 'canonical_kb', 'KB５０９９００１', 'reject',
            note='full-width digits are not ASCII'),
        row('K14', 'canonical_kb', 'KB5099001\n', 'reject', note='newline suffix'),
        row('K15', 'canonical_kb', 'KB/5099001', 'reject', note='slash (NEG-01)'),
        row('K16', 'canonical_kb', 'KB5099001\u0007', 'reject', note='control character (NEG-01)'),
        row('K17', 'canonical_kb', 'XKB5099001', 'reject', note='glued prefix'),
        row('K18', 'canonical_kb', 'KB', 'reject', note='no digits'),
        row('K19', 'canonical_kb', '', 'reject', note='empty'),
        row('E01', 'edge_kb', 'kb5099001', 'ok', 'KB5099001', 'lower-case prefix'),
        row('E02', 'edge_kb', 'KB 5099001', 'ok', 'KB5099001', 'one space'),
        row('E03', 'edge_kb', 'kb-5099001', 'ok', 'KB5099001', 'one dash'),
        row('E04', 'edge_kb', '5099001', 'ok', 'KB5099001', 'bare digits'),
        row('E05', 'edge_kb', ' KB5099001\t', 'ok', 'KB5099001', 'outer spaces and tabs are trimmed'),
        row('E06', 'edge_kb', 'KB\t5099001', 'ok', 'KB5099001', 'one tab'),
        row('E07', 'edge_kb', '0005099001', 'ok', 'KB0005099001', 'bare 10 digits keep leading zeros'),
        row('E08', 'edge_kb', '0001234', 'ok', 'KB0001234', 'bare 7 digits keep leading zeros'),
        row('E09', 'edge_kb', 'KB12', 'reject', note='2 digits (kb12 in the search matrix)'),
        row('E10', 'edge_kb', '123', 'reject', note='bare, 3 digits'),
        row('E11', 'edge_kb', 'KB5099001x', 'reject', note='trailing letter'),
        row('E12', 'edge_kb', 'KB\t\t5099001', 'reject', note='two separators'),
        row('E13', 'edge_kb', '5099001 KB', 'reject', note='suffix prefix'),
        row('E14', 'edge_kb', 'KB/5099001', 'reject', note='slash (NEG-01)'),
        row('E15', 'edge_kb', 'KB5099001\n', 'reject', note='newline is not trimmed'),
        row('E16', 'edge_kb', 'KB12345678901', 'reject', note='11 digits'),
        row('E17', 'edge_kb', 'KB٥٠٩٩٠٠١', 'reject', note='non-ASCII digits'),
        row('E18', 'edge_kb', '', 'reject', note='empty'),
        row('C01', 'edge_cve', 'CVE-2099-20001', 'ok', 'CVE-2099-20001'),
        row('C02', 'edge_cve', 'cve-2099-20001', 'ok', 'CVE-2099-20001', 'prefix is upper-cased'),
        row('C03', 'edge_cve', ' CVE-2099-0001 ', 'ok', 'CVE-2099-0001', 'trimmed; 4-digit lower bound'),
        row('C04', 'edge_cve', 'CVE-2099-1234567890123456789', 'ok', 'CVE-2099-1234567890123456789',
            'upper bound: 19 digits'),
        row('C05', 'edge_cve', 'CVE-2099-123', 'reject', note='3 digits'),
        row('C06', 'edge_cve', 'CVE-99-20001', 'reject', note='2-digit year'),
        row('C07', 'edge_cve', 'CVE_2099_20001', 'reject', note='underscore'),
        row('C08', 'edge_cve', 'CVE-2099-12345678901234567890', 'reject', note='20 digits'),
        row('C09', 'edge_cve', 'CVE-2099-２０００１', 'reject', note='full-width digits'),
        row('C10', 'edge_cve', 'CVE-2099-20001\n', 'reject', note='newline is not trimmed'),
        row('T01', 'kb_tokens', 'Fixed by KB5099001 and KB5099002.', 'ok',
            ['KB5099001', 'KB5099002'], 'two exact tokens'),
        row('T02', 'kb_tokens', 'kb5099001 is lower case', 'ok', [], 'lower case is not a token'),
        row('T03', 'kb_tokens', 'XKB5099001 and KB5099001x', 'ok', [], 'glued to letters'),
        row('T04', 'kb_tokens', 'KB123 and KB12345678901', 'ok', [], 'digit count out of range'),
        row('T05', 'kb_tokens', 'KB0001234 KB1234', 'ok', ['KB1234', 'KB0001234'],
            'sorted by digit count, not by number'),
        row('T06', 'kb_tokens', 'Build 19045 (not a KB) and KB5099001.', 'ok', ['KB5099001'],
            'build number is not a token'),
        row('T07', 'kb_tokens', 'KB5099001 KB5099001', 'ok', ['KB5099001'], 'duplicates collapse'),
        row('T08', 'kb_tokens', 'KB5099001/KB5099002', 'ok', ['KB5099001', 'KB5099002'],
            'slash is a boundary'),
    ]


# --- builder-made committed files: name -> bytes ---


def generated_files() -> dict[str, bytes]:
    """Every committed file that a builder produces. The hand-authored files (negative encodings) are not here."""
    return {
        'cvrf-2099-Feb.json': render_json(baseline_cvrf()),
        'cvrf-2099-Feb-neg.json': render_json(neg_cvrf()),
        'cvrf-2099-Feb-reordered.json': render_json(reordered(baseline_cvrf())),
        'csaf-kb.json': render_json(baseline_csaf()),
        'kev-synthetic.json': render_json(kev_snapshot()),
        'identifiers.json': render_json({'contract': 'kb-syntax-matrix/1', 'synthetic': True,
                                         'rows': identifier_matrix()}),
    }


# --- two-CVE project baseline (plan s5 (c)) ---


@dataclass(frozen=True)
class TwoCveProject:
    """Inputs of the baseline project. Creating the on-disk project belongs to K1 and K2, not to this helper."""

    root: Path
    older_path: Path
    newer_path: Path
    older_sha256: str
    newer_sha256: str
    file_name: str
    kb_client: str
    kb_server: str
    cve_first: str
    cve_second: str
    cve_mention: str
    products: tuple[str, ...]
    cvrf_path: Path
    csaf_path: Path
    kev_path: Path


def two_cve_project(root: Path) -> TwoCveProject:
    """Write the synthetic pair as ``old/exampledrv.sys`` and ``new/exampledrv.sys`` under ``root``.

    The bytes are ``synthetic_pe(0)`` and ``synthetic_pe(1)``, as in plan s5 (c). The source documents are
    the committed fixtures, returned by path and never copied. Pure apart from the two writes.
    """
    older_dir = root / 'old'
    newer_dir = root / 'new'
    older_dir.mkdir(parents=True, exist_ok=True)
    newer_dir.mkdir(parents=True, exist_ok=True)
    older = synthetic_pe(0)
    newer = synthetic_pe(1)
    older_path = older_dir / 'exampledrv.sys'
    newer_path = newer_dir / 'exampledrv.sys'
    older_path.write_bytes(older)
    newer_path.write_bytes(newer)
    return TwoCveProject(
        root=root,
        older_path=older_path,
        newer_path=newer_path,
        older_sha256=sha256_hex(older),
        newer_sha256=sha256_hex(newer),
        file_name='exampledrv.sys',
        kb_client=KB_CLIENT,
        kb_server=KB_SERVER,
        cve_first=CVE_A,
        cve_second=CVE_B,
        cve_mention=CVE_MENTION,
        products=(PRODUCT_CLIENT, PRODUCT_ARM, PRODUCT_SERVER),
        cvrf_path=fixture_path('cvrf-2099-Feb.json'),
        csaf_path=fixture_path('csaf-kb.json'),
        kev_path=fixture_path('kev-synthetic.json'),
    )
