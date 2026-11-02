"""Bounded native MSRC monthly JSON, with pointers into the original imported bytes.

SPEC-31-B B3.1 and tests/fixtures/kbcve/msrc/*provenance.json pin the observed dialect. The official
PowerShell sample establishes remediation Type 2. Paired official JSON/XML establishes document
status 2 (Final) and product status 3 (Known Affected), not the meaning of any other integer.
Unknown status applicability withholds fixes; unknown date zones never become invented UTC.

No network, target execution, synthetic-document conversion or authenticity upgrade occurs here.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import replace
from datetime import datetime

from ..ids import is_cve
from ..limits import KbcLimits
from ..products import clean_text
from .cvrf import (
    DIALECT_MSRC,
    REMEDIATION_VENDOR_FIX,
    CvrfDocument,
    Problem,
    RawProduct,
    RawRemediation,
    RawRevision,
    RawStatus,
    RawVulnerability,
    _finish,
    _shape,
    normal_timestamp,
    pointer,
)

_MONTH = re.compile(r'^[0-9]{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')
_CWE = re.compile(r'^CWE-[1-9][0-9]{0,5}$')
_NAIVE_DATE = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?$')


def _text(value) -> str | None:
    return value if isinstance(value, str) else None


def _wrapped(value) -> str | None:
    return _text(value.get('Value')) if isinstance(value, dict) else None


def _members(value) -> bool:
    return isinstance(value, list) and all(_product_id(x) for x in value)


def _product_id(value) -> bool:
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 1000
            and not any(0xd800 <= ord(ch) <= 0xdfff for ch in value))


def parse_document(value: dict, limits: KbcLimits) -> CvrfDocument:
    """Read the verified structural dialect; row anomalies remain visible, never wildcard applicability."""
    tracking = value.get('DocumentTracking')
    tree = value.get('ProductTree')
    vulns = value.get('Vulnerability')
    if _wrapped(value.get('DocumentType')) != 'Security Update' or not isinstance(tracking, dict):
        raise _shape('unsupported native DocumentType or DocumentTracking')
    identification = tracking.get('Identification')
    release = _wrapped(identification.get('ID')) if isinstance(identification, dict) else None
    if release is None or not _MONTH.fullmatch(release):
        raise _shape('/DocumentTracking/Identification/ID/Value is not a monthly id')
    if type(tracking.get('Status')) is not int or tracking['Status'] != 2:
        raise _shape('/DocumentTracking/Status is not the verified Final code')
    if not isinstance(tracking.get('Version'), str) or not 0 < len(tracking['Version']) <= 1000:
        raise _shape('/DocumentTracking/Version is not a bounded revision string')
    if not isinstance(tree, dict) or not isinstance(tree.get('FullProductName'), list):
        raise _shape('/ProductTree/FullProductName is not an array')
    if not isinstance(vulns, list):
        raise _shape('/Vulnerability is not an array')
    problems: list[Problem] = []
    stamp = _current_date(tracking, problems)
    revisions = _revisions(tracking.get('RevisionHistory'), '/DocumentTracking/RevisionHistory', problems)
    products = _products(tree['FullProductName'], problems)
    rows = [_vulnerability(i, row, limits, problems) for i, row in enumerate(vulns)]
    return replace(_finish(DIALECT_MSRC, release, release, stamp, products, rows, problems), revisions=revisions)


def _current_date(tracking: dict, problems) -> str | None:
    if 'CurrentReleaseDate' not in tracking:
        problems.append(Problem('DATE_INVALID', '/DocumentTracking',
                                'missing CurrentReleaseDate; revision order is unknown'))
        return None
    value = tracking['CurrentReleaseDate']
    at = '/DocumentTracking/CurrentReleaseDate'
    # normal_timestamp also accepts date-only strings; native revision ordering needs an explicit zone.
    stamp = normal_timestamp(value) if isinstance(value, str) and 'T' in value else None
    if stamp is not None:
        return stamp
    if isinstance(value, str) and _NAIVE_DATE.fullmatch(value):
        try:
            datetime.fromisoformat(value)
        except ValueError:
            pass
        else:
            problems.append(Problem('DATE_ZONE_UNKNOWN', at, 'revision timestamp has no zone; order is unknown'))
            return None
    problems.append(Problem('DATE_INVALID', at, 'missing or invalid revision instant; order is unknown'))
    return None


def _revisions(value, at: str, problems) -> tuple[RawRevision, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        problems.append(Problem('REVISION_SHAPE', at, 'revision history is not an array'))
        return ()
    rows = []
    for i, row in enumerate(value):
        rat = at + '/' + str(i)
        if not isinstance(row, dict):
            problems.append(Problem('REVISION_SHAPE', rat, 'revision is not an object'))
            continue
        number, date = _text(row.get('Number')), _text(row.get('Date'))
        if number is None or date is None:
            problems.append(Problem('REVISION_SHAPE', rat, 'revision number/date is not a string'))
        rows.append(RawRevision(number, date, rat))
    return tuple(rows)


def _products(value: list, problems) -> list[RawProduct]:
    out = []
    counts = Counter(row.get('ProductID') for row in value if isinstance(row, dict)
                     and isinstance(row.get('ProductID'), str))
    for i, row in enumerate(value):
        at = pointer('ProductTree', 'FullProductName', i)
        pid = row.get('ProductID') if isinstance(row, dict) else None
        name = row.get('Value') if isinstance(row, dict) else None
        if not _product_id(pid) or not isinstance(name, str) or not clean_text(name).strip() or len(name) > 1000:
            problems.append(Problem('PRODUCT_ID_INVALID', at, 'product needs a bounded nonempty ProductID and Value'))
        elif counts[pid] != 1:
            problems.append(Problem('PRODUCT_DUPLICATE', at, 'product id defined more than once; no edges'))
        else:
            out.append(RawProduct(pid, name, None, None, at))
    return out


def _statuses(value, at: str, problems) -> tuple[tuple[RawStatus, ...], set[str]]:
    """Return all interpretable memberships and the subset with verified, unopposed applicability."""
    if not isinstance(value, list):
        problems.append(Problem('STATUS_SHAPE', at, 'status membership is not an array; fixes withheld'))
        return (), set()
    statuses = []
    known, unknown = set(), set()
    malformed = False
    for i, row in enumerate(value):
        sat = at + '/' + str(i)
        pids = row.get('ProductID') if isinstance(row, dict) else None
        kind = row.get('Type') if isinstance(row, dict) else None
        if not _members(pids) or type(kind) is not int:
            problems.append(Problem('STATUS_SHAPE', sat, 'status needs integer Type and ProductID array; fixes withheld'))
            malformed = True
            continue
        if kind == 3:
            label = 'Known Affected'
            known.update(pids)
        else:
            # Never infer enum values from the order of an XML schema or an unrelated CSAF status list.
            label = f'MSRC status Type {kind} (unverified)'
            unknown.update(pids)
            problems.append(Problem('STATUS_TYPE_UNSUPPORTED', sat + '/Type',
                                    'unverified numeric status; associated fixes withheld'))
        statuses.extend(RawStatus(label, pid, sat + '/ProductID/' + str(k)) for k, pid in enumerate(pids))
    return tuple(statuses), set() if malformed else known - unknown


def _vulnerability(index: int, value, limits, problems) -> RawVulnerability | None:
    at = pointer('Vulnerability', index)
    if not isinstance(value, dict):
        problems.append(Problem('ROW_SHAPE', at, 'vulnerability is not an object'))
        return None
    cve = value.get('CVE')
    if not isinstance(cve, str) or not is_cve(cve):
        problems.append(Problem('CVE_INVALID', at + '/CVE' if 'CVE' in value else at,
                                'not a canonical CVE id' if 'CVE' in value else 'missing CVE'))
        return None
    statuses, allowed = _statuses(value.get('ProductStatuses', []), at + '/ProductStatuses', problems)
    rems = []
    raw_rems = value.get('Remediations', [])
    if not isinstance(raw_rems, list):
        problems.append(Problem('ROW_SHAPE', at + '/Remediations', 'remediations is not an array'))
    else:
        for i, rem in enumerate(raw_rems):
            parsed = _remediation(i, rem, at + '/Remediations/' + str(i), allowed, limits, problems)
            if parsed is not None:
                rems.append(parsed)
    cwe = None
    raw_cwe = value.get('CWE', [])
    if not isinstance(raw_cwe, list):
        problems.append(Problem('CWE_SHAPE', at + '/CWE', 'CWE is not an array'))
    else:
        ids = {row['ID'] for row in raw_cwe if isinstance(row, dict) and isinstance(row.get('ID'), str)
               and _CWE.fullmatch(row['ID'])}
        invalid = [i for i, row in enumerate(raw_cwe) if not isinstance(row, dict)
                   or not isinstance(row.get('ID'), str) or not _CWE.fullmatch(row['ID'])]
        for i in invalid:
            problems.append(Problem('CWE_INVALID', at + '/CWE/' + str(i), 'not a canonical CWE id'))
        if len(ids) == 1 and not invalid:
            cwe = next(iter(ids))
        elif len(ids) > 1:
            problems.append(Problem('CWE_MULTIPLE', at + '/CWE', 'several CWEs; no singular CWE selected'))
    return RawVulnerability(index, at, cve, clean_text(_wrapped(value.get('Title'))) or None, cwe,
                            tuple(rems), statuses, _revisions(value.get('RevisionHistory'),
                                                             at + '/RevisionHistory', problems))


def _remediation(index: int, value, at: str, allowed: set[str], limits, problems) -> RawRemediation | None:
    if not isinstance(value, dict):
        problems.append(Problem('ROW_SHAPE', at, 'remediation is not an object'))
        return None
    kind = value.get('Type')
    if type(kind) is not int:
        problems.append(Problem('TYPE_INVALID', at + '/Type' if 'Type' in value else at,
                                'remediation type is not an integer' if 'Type' in value else 'missing Type'))
        return None
    desc = _wrapped(value['Description']) if 'Description' in value else ''
    pids = value.get('ProductID', [])
    if desc is None or not _members(pids):
        problems.append(Problem('ROW_SHAPE', at, 'Description.Value or ProductID has the wrong type'))
        return None
    try:
        desc_bytes = len(desc.encode('utf-8'))
    except UnicodeEncodeError:
        problems.append(Problem('ROW_SHAPE', at + '/Description/Value', 'description has an invalid Unicode scalar'))
        return None
    if desc_bytes > limits.text_field_bytes:
        problems.append(Problem('TEXT_LIMIT', at + '/Description/Value', 'description exceeds the text limit; no edge'))
        return None
    if value.get('GroupID'):
        problems.append(Problem('GROUP_UNSUPPORTED', at + '/GroupID', 'product group applicability is not verified'))
        return None
    if kind == REMEDIATION_VENDOR_FIX and not pids:
        problems.append(Problem('PRODUCT_ID_MISSING', at, 'vendor fix has no concrete product membership'))
    members = []
    for i, pid in enumerate(pids):
        pat = at + '/ProductID/' + str(i)
        if kind == REMEDIATION_VENDOR_FIX and pid not in allowed:
            problems.append(Problem('PRODUCT_STATUS_UNRESOLVED', pat, 'no unopposed verified status; fix withheld'))
        else:
            members.append((pid, pat))
    sup = value.get('Supercedence', '')
    if not isinstance(sup, str):
        problems.append(Problem('SUPERSEDES_UNPARSED', at + '/Supercedence', 'supersedence is not a string'))
        sup = ''
    sub = value.get('SubType')
    if sub is not None and not isinstance(sub, str):
        problems.append(Problem('ROW_SHAPE', at + '/SubType', 'subtype is not a string'))
    return RawRemediation(
        index, at, kind, desc, tuple(pid for pid, _ in members), value.get('FixedBuild'),
        tuple(s.strip(' \t\r\n') for s in sup.split(',') if s.strip(' \t\r\n')),
        clean_text(sub) or None,
        field_pointers=(('description', at + '/Description/Value'), ('fixed_build', at + '/FixedBuild'),
                        ('supersedes', at + '/Supercedence')),
        product_pointers=tuple(pat for _, pat in members))
