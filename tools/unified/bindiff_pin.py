"""Offline check of `tools/bindiff_pin.json` for the unified gates (U8; dev-only, never shipped, no network).

`verify` reports whether the pin may count as verified (G-U3's BinDiff oracle part needs that): the schema holds, no
digest is a placeholder, the maintainer recorded a successful signature check and the Linux asset is fully pinned.
It never computes or invents a digest; the owner obtains one with docs/runbooks/bindiff-pin.md. Exit codes: 0 ok (with
`--require-verified`: verified), 2 unreadable or malformed pin or a placeholder digest, 3 `--require-verified` and not
verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPORT_CONTRACT = 'bindiff-pin-report/1'
PIN_CONTRACT = 'bindiff-pin/1'
ALLOWED_PREFIX = 'https://github.com/google/bindiff/releases/download/'   # same rule as tools/provision_bindiff.py
MAX_ASSET = 1 << 30
SHA256 = re.compile(r'[0-9a-f]{64}')
EMPTY_INPUT = hashlib.sha256(b'').hexdigest()
OSES = ('linux', 'windows')


@dataclass(frozen=True)
class PinReport:
    version: str
    verified: bool
    errors: tuple[str, ...]          # the file cannot be used at all
    placeholders: tuple[str, ...]    # digest fields that are not real digests
    reasons: tuple[str, ...]         # why it is not verified (also lists errors and placeholders)


def is_placeholder(value: object) -> bool:
    """Not a plausible SHA-256: wrong shape, a repeated or counting pattern, or the digest of empty input."""
    if not isinstance(value, str) or not SHA256.fullmatch(value) or value == EMPTY_INPUT:
        return True
    return len(set(value)) <= 4 or value in '0123456789abcdef' * 4 or value in 'fedcba9876543210' * 4


def _digest(field: str, value: object, placeholders: list[str], required: bool) -> None:
    if value is None and not required:
        return
    if is_placeholder(value):
        placeholders.append(f'{field} is not a real SHA-256')


def _asset(os_name: str, asset: object, errors: list[str], placeholders: list[str], required: bool) -> None:
    where = f'assets.{os_name}'
    if not isinstance(asset, dict):
        errors.append(f'{where} is missing')
        return
    url, size = asset.get('url'), asset.get('size')
    if not isinstance(url, str) or not url.startswith(ALLOWED_PREFIX):
        errors.append(f'{where}.url is not an upstream google/bindiff release download')
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ASSET:
        errors.append(f'{where}.size is not a positive integer')
    _digest(f'{where}.sha256', asset.get('sha256'), placeholders, True)
    _digest(f'{where}.executable_sha256', asset.get('executable_sha256'), placeholders, required)


def check_pin(pin: object) -> PinReport:
    if not isinstance(pin, dict) or pin.get('contract') != PIN_CONTRACT:
        return PinReport('', False, (f'contract is not {PIN_CONTRACT}',), (), ('pin file unusable',))
    errors: list[str] = []
    placeholders: list[str] = []
    reasons: list[str] = []
    assets = pin.get('assets') if isinstance(pin.get('assets'), dict) else {}
    for os_name in OSES:
        if os_name == 'linux' or os_name in assets:
            _asset(os_name, assets.get(os_name), errors, placeholders, required=os_name == 'linux')
    signature = pin.get('signature') if isinstance(pin.get('signature'), dict) else {}
    _digest('signature.sha256', signature.get('sha256'), placeholders, True)
    if not isinstance(pin.get('verified'), bool):
        errors.append('verified must be true or false')
    elif not pin['verified']:
        reasons.append('verified is false (trust-on-first-use values only)')
    if signature.get('verified') is not True:
        reasons.append('signature.verified is not true: the .asc was not checked')
    by = signature.get('signature_verified_by')
    if not isinstance(by, str) or not by.strip():
        reasons.append('signature.signature_verified_by names nobody')
    reasons += [*errors, *placeholders]
    return PinReport(str(pin.get('version', '')), not reasons, tuple(errors), tuple(placeholders), tuple(reasons))


def check(path: Path) -> PinReport:
    try:
        pin = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        return PinReport('', False, (f'cannot read {path.name}: {type(error).__name__}',), (), ('pin file unusable',))
    return check_pin(pin)


def _document(report: PinReport) -> dict:
    return {'contract': REPORT_CONTRACT, 'version': report.version, 'verified': report.verified,
            'errors': list(report.errors), 'placeholders': list(report.placeholders), 'reasons': list(report.reasons)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='bindiff_pin', description='Offline check of tools/bindiff_pin.json.')
    parser.add_argument('action', choices=('verify', 'print'))
    parser.add_argument('--pin', type=Path, default=Path(__file__).resolve().parents[1] / 'bindiff_pin.json')
    parser.add_argument('--require-verified', action='store_true', help='exit 3 unless the pin is verified')
    parser.add_argument('--github-output', type=Path, help='append bindiff_pin_verified and bindiff_pin_version lines')
    args = parser.parse_args(argv)
    report = check(args.pin)
    if args.github_output:
        with open(args.github_output, 'a', encoding='utf-8', newline='\n') as handle:
            handle.write(f'bindiff_pin_verified={str(report.verified).lower()}\nbindiff_pin_version={report.version}\n')
    if args.action == 'print':
        sys.stdout.write(json.dumps(_document(report), sort_keys=True) + '\n')
    else:
        for line in (*report.errors, *report.placeholders):
            print(f'error: {line}', file=sys.stderr)
        print('bindiff pin: ' + ('verified' if report.verified else 'not verified: ' + '; '.join(report.reasons)))
    if report.errors or report.placeholders:
        return 2
    return 3 if args.require_verified and not report.verified else 0


if __name__ == '__main__':
    sys.exit(main())
