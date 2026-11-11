"""Write a synthetic CISA-format KEV catalog for manual and integration testing. Offline; nothing is fetched.

usage: make_kev_catalog.py OUT.json [--cve CVE-YYYY-NNNN[@YYYY-MM-DD] ...] [--version V] [--released TIMESTAMP]
                           [--ransomware CVE ...]

The catalog has CISA's field set, so ``patchtrace kev import OUT.json`` accepts it. Every text field says
SYNTHETIC. Before it writes the file, the tool checks the bytes with the production parser
(``kev.parse.parse_catalog``), so a file it writes always imports. Typical use, for the KEV chips of ``kb leads``:

    python tools/make_kev_catalog.py /tmp/kev.json --cve CVE-2099-20001@2099-02-12 --released 2099-02-14T12:00:00Z
    python -m patchtrace kev import /tmp/kev.json --kev-dir /tmp/kevstore
    python -m patchtrace kb leads PROJECT --kev-dir /tmp/kevstore --json

``--released`` far in the past gives a stale catalog, and one in the future gives the future-clock banner.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DEFAULT_RELEASED = '2099-02-14T12:00:00Z'
_CVE = re.compile(r'(CVE-[0-9]{4}-[0-9]{4,})(?:@([0-9]{4}-[0-9]{2}-[0-9]{2}))?')


def entry(cve: str, date_added: str, *, ransomware: bool = False) -> dict:
    return {'cveID': cve, 'vendorProject': 'SYNTHETIC Vendor', 'product': 'SYNTHETIC Product',
            'vulnerabilityName': f'SYNTHETIC entry for {cve}', 'dateAdded': date_added,
            'shortDescription': 'SYNTHETIC test entry; not a real advisory.', 'requiredAction': 'SYNTHETIC: none.',
            'dueDate': date_added, 'knownRansomwareCampaignUse': 'Known' if ransomware else 'Unknown',
            'notes': '', 'cwes': []}


def catalog(cves: list[tuple[str, str]], *, version: str, released: str, ransomware: frozenset[str] = frozenset()
            ) -> dict:
    rows = [entry(cve, day, ransomware=cve in ransomware) for cve, day in cves]
    return {'title': 'SYNTHETIC KEV catalog (PatchTrace test data, not CISA)', 'catalogVersion': version,
            'dateReleased': released, 'count': len(rows), 'vulnerabilities': rows}


def parse_cve(text: str, default_day: str) -> tuple[str, str]:
    match = _CVE.fullmatch(text)
    if match is None:
        raise argparse.ArgumentTypeError(f'expected CVE-YYYY-NNNN[@YYYY-MM-DD], got {text!r}')
    return match.group(1), match.group(2) or default_day


def render(document: dict) -> bytes:
    """The bytes written, after the production parser has accepted them."""
    from patchtrace.kev.parse import parse_catalog
    raw = json.dumps(document, indent=2).encode('utf-8')
    parse_catalog(raw, source='local-import', retrieved_at=document['dateReleased'][:19] + 'Z', file_name='kev.json')
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('out', type=Path)
    parser.add_argument('--cve', action='append', default=[], help='CVE-YYYY-NNNN[@dateAdded]; repeat for several')
    parser.add_argument('--version', default='2099.02.14-synthetic')
    parser.add_argument('--released', default=DEFAULT_RELEASED, help='UTC timestamp YYYY-MM-DDTHH:MM:SSZ')
    parser.add_argument('--ransomware', action='append', default=[], metavar='CVE')
    args = parser.parse_args(argv)
    day = args.released[:10]
    try:
        cves = [parse_cve(text, day) for text in (args.cve or ['CVE-2099-20001'])]
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    raw = render(catalog(cves, version=args.version, released=args.released, ransomware=frozenset(args.ransomware)))
    args.out.write_bytes(raw)
    print(f'wrote {args.out} ({len(cves)} entries, catalog {args.version}, released {args.released})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
