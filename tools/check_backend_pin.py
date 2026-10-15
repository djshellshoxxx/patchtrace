"""Validate tools/backend_pin.json (BUNDLE integration plan 7.1, slice B1). Stdlib only; no network.

usage: check_backend_pin.py [--pin tools/backend_pin.json] [--release]

Exit codes: 0 pin valid (and, with --release, fully resolved); 1 pin malformed; 3 --release and at least one
component is still a placeholder (unresolved digest); 4 --release and a shipped copyleft component in
license_policy still has owner_approved false (--allow-unapproved-licenses downgrades that to a loud warning
for non-publishing acceptance builds). A placeholder is allowed in the repository so the pin can
land before every host is reachable, but a release build must pass --release, so none can ship.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_PIN = Path(__file__).resolve().parent / 'backend_pin.json'
SCHEMA = 'patchtrace-backend-pin/1'
PLACEHOLDER = 'PLACEHOLDER-UNRESOLVED'
COMPONENTS = ('python-windows', 'python-linux', 'ghidra', 'jdk-windows', 'jdk-linux')
DIGEST_SOURCES = ('vendor-file', 'vendor-listing', 'pypi-json', 'sigstore-verified', 'gpg-verified', 'git-rebuilt', 'none')
# No trust on first use ('tofu' is refused everywhere): a digest without a vendor digest is accepted only after a
# verification, and only for the component the verification applies to.
PYTHON_WINDOWS_SOURCES = ('sigstore-verified', 'gpg-verified')
TARBALL_SOURCES = ('git-rebuilt',)
VERIFIED_ONLY = ('sigstore-verified', 'gpg-verified', 'git-rebuilt')
KINDS = ('wheel', 'sdist-built-to-wheel')
REQUIRED_DISTRIBUTIONS = ('jpype1', 'pyghidra', 'packaging', 'mdutils')
PLATFORM_SECTIONS = {'windows': ('windows', 'any'), 'linux': ('linux', 'any')}
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_HEX40 = re.compile(r'^[0-9a-f]{40}$')
# Any GPL-family licence (GPL, LGPL, AGPL, also inside an expression such as "GPL-2.0-only WITH ...").
_COPYLEFT = re.compile(r'(?<![A-Za-z])(?:A|L)?GPL(?![A-Za-z])', re.IGNORECASE)
LICENSE_CODE = 'PT-BUNDLE-LICENSE'
POLICY_FIELDS = ('spdx', 'role', 'owner_approved', 'rationale', 'shipped', 'match')
APPROVAL_FIELDS = ('approved_on', 'approved_via')  # optional audit trail for an approval


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _check_digest(where: str, entry: dict, problems: list[str], *, allow_placeholder: bool) -> bool:
    """Validate status/sha256/size/digest_source/url of one downloadable. Returns True when it is a placeholder."""
    url, sha, size = entry.get('url'), entry.get('sha256'), entry.get('size')
    if not isinstance(url, str) or not url.startswith('https://'):
        problems.append(f'{where}: url must be an https:// string')
    status = entry.get('status', 'pinned')
    source = entry.get('digest_source')
    if source not in DIGEST_SOURCES:
        problems.append(f'{where}: digest_source must be one of {DIGEST_SOURCES}')
    if status == 'placeholder':
        if not allow_placeholder:
            problems.append(f'{where}: placeholder status not allowed here')
        if sha != PLACEHOLDER:
            problems.append(f'{where}: a placeholder must carry sha256 {PLACEHOLDER}')
        if size is not None:
            problems.append(f'{where}: a placeholder must have size null')
        if source != 'none':
            problems.append(f'{where}: a placeholder must have digest_source none')
        return True
    if status != 'pinned':
        problems.append(f'{where}: status must be pinned or placeholder')
    if not isinstance(sha, str) or not _HEX64.match(sha):
        problems.append(f'{where}: sha256 must be 64 lowercase hex characters')
    if not _is_int(size):
        problems.append(f'{where}: size must be a positive integer')
    if source == 'none':
        problems.append(f'{where}: a pinned digest needs a real digest_source')
    return False


def _restrict_source(where: str, entry: dict, allowed: tuple, problems: list[str]) -> None:
    """A pinned entry must use one of `allowed` sources; verification-only sources fit nowhere else."""
    if entry.get('status', 'pinned') != 'pinned':
        return
    source = entry.get('digest_source')
    if allowed and source not in allowed:
        problems.append(f'{where}: a pinned digest here needs digest_source in {allowed} (no trust on first use)')
    if not allowed and source in VERIFIED_ONLY:
        problems.append(f'{where}: digest_source {source} is not valid for this component')


def _check_spdx(where: str, entry: dict, problems: list[str]) -> None:
    spdx = entry.get('spdx')
    if not isinstance(spdx, str) or not spdx.strip():
        problems.append(f'{where}: spdx is required')


def is_copyleft(spdx: object) -> bool:
    return isinstance(spdx, str) and bool(_COPYLEFT.search(spdx))


def _policy_allowed(data: object) -> dict:
    policy = data.get('license_policy') if isinstance(data, dict) else None
    allowed = policy.get('allowed') if isinstance(policy, dict) else None
    return allowed if isinstance(allowed, dict) else {}


def copyleft_problems(items: list[tuple[str, str]], pin: object) -> list[str]:
    """PT-BUNDLE-LICENSE problems for (component id, spdx) pairs: every GPL-family component must be listed.

    `pin` is the whole pin (anything holding `license_policy`). An entry covers a component only when the id is
    in its `match` list and the SPDX strings are identical, so a changed licence is refused again.
    """
    allowed = _policy_allowed(pin)
    problems = []
    for ident, spdx in items:
        if not is_copyleft(spdx):
            continue
        covered = any(isinstance(entry, dict) and ident in (entry.get('match') or ()) and entry.get('spdx') == spdx
                      for entry in allowed.values())
        if not covered:
            problems.append(f'{LICENSE_CODE}: {ident} is {spdx!r} and is not listed in license_policy')
    return problems


def unapproved_licenses(data: object) -> list[str]:
    """Ids of shipped license_policy components whose owner_approved is not true."""
    return sorted(name for name, entry in _policy_allowed(data).items()
                  if isinstance(entry, dict) and entry.get('shipped', True) and entry.get('owner_approved') is not True)


def shipped_gpl_dir_problems(files: list[str], data: object) -> list[str]:
    """A manifest listing ghidra/GPL/** is refused unless license_policy lists that directory as shipped+approved."""
    entry = _policy_allowed(data).get('ghidra-GPL-dir')
    if isinstance(entry, dict) and entry.get('shipped') is True and entry.get('owner_approved') is True:
        return []
    hits = [name for name in files if name.lower().startswith('ghidra/gpl/')]
    return [f'{LICENSE_CODE}: payload ships Ghidra GPL/ files ({hits[0]}, {len(hits)} total) but '
            'license_policy ghidra-GPL-dir is not shipped and owner-approved'] if hits else []


def _check_license_policy(data: dict, problems: list[str]) -> None:
    policy = data.get('license_policy')
    allowed = policy.get('allowed') if isinstance(policy, dict) else None
    if not isinstance(allowed, dict) or not allowed:
        problems.append('license_policy.allowed must be a non-empty object')
        return
    for name, entry in allowed.items():
        where = f'license_policy.allowed.{name}'
        if not isinstance(entry, dict) or not set(POLICY_FIELDS) <= set(entry) <= {*POLICY_FIELDS, *APPROVAL_FIELDS}:
            problems.append(f'{where}: fields must be {POLICY_FIELDS} plus optional {APPROVAL_FIELDS}')
            continue
        for key in ('spdx', 'role', 'rationale'):
            if not isinstance(entry[key], str) or not entry[key].strip():
                problems.append(f'{where}.{key} is required')
        for key in ('owner_approved', 'shipped'):
            if not isinstance(entry[key], bool):
                problems.append(f'{where}.{key} must be a boolean')
        if not isinstance(entry['match'], list) or not all(isinstance(m, str) for m in entry['match']):
            problems.append(f'{where}.match must be a list of component ids')
    ghidriff = allowed.get('ghidriff')
    if not (isinstance(ghidriff, dict) and ghidriff.get('spdx') == (data.get('ghidriff') or {}).get('spdx')):
        problems.append('license_policy.allowed.ghidriff must exist and carry the pinned ghidriff SPDX')
    # every GPL-family component of the pin must be explicitly listed
    items: list[tuple[str, str]] = []
    for name, entry in (data.get('components') or {}).items():
        if isinstance(entry, dict):
            items.append((name, str(entry.get('spdx', ''))))
    for lane in (data.get('wheels') or {}).values():
        items.extend((str(w.get('distribution')), str(w.get('spdx', ''))) for w in lane if isinstance(w, dict))
    if isinstance(data.get('ghidriff'), dict):
        items.append(('ghidriff', str(data['ghidriff'].get('spdx', ''))))
    problems.extend(copyleft_problems(items, data))
    # a component listed as not shipped must really be stripped from the payload
    strip = data.get('strip') if isinstance(data.get('strip'), dict) else {}
    gpl = allowed.get('ghidra-GPL-dir')
    if not isinstance(gpl, dict):
        problems.append('license_policy.allowed.ghidra-GPL-dir is required (Ghidra GPL/** is policy-gated)')
    elif gpl.get('shipped') is False:
        if 'GPL/**' not in (strip.get('ghidra') or []) or 'GPL/**' in (strip.get('keep') or []):
            problems.append('license_policy ghidra-GPL-dir is not shipped: strip.ghidra must contain GPL/** and '
                            'strip.keep must not')
    elif 'GPL/**' in (strip.get('keep') or []) and gpl.get('owner_approved') is not True:
        problems.append('strip.keep keeps GPL/** without owner approval in license_policy')


def _wheel_tag_ok(platform: str, name: str) -> bool:
    if platform == 'any':
        return name.endswith('-py3-none-any.whl')
    if platform == 'windows':
        return '-cp312-cp312-win_amd64.whl' in name
    return '-cp312-cp312-manylinux' in name and 'x86_64' in name and name.endswith('.whl')


def validate_pin(data: object) -> list[str]:
    """Return a list of problems (empty = valid). Placeholders are valid here; see release_problems."""
    problems: list[str] = []
    if not isinstance(data, dict):
        return ['pin is not a JSON object']
    if data.get('schema') != SCHEMA:
        problems.append(f'schema must be {SCHEMA}')
    fmt = data.get('runtime_id_format')
    if fmt != 'ghidra-{ghidra}-ghidriff-{sha7}-{os}-amd64':
        problems.append('runtime_id_format is not the SPEC-06 runtime id format')

    components = data.get('components')
    if not isinstance(components, dict):
        problems.append('components must be an object')
        components = {}
    for name in sorted(set(components) - set(COMPONENTS)):
        problems.append(f'components.{name}: unknown component')
    for name in COMPONENTS:
        entry = components.get(name)
        if not isinstance(entry, dict):
            problems.append(f'components.{name}: missing')
            continue
        where = f'components.{name}'
        _check_digest(where, entry, problems, allow_placeholder=True)
        _restrict_source(where, entry, PYTHON_WINDOWS_SOURCES if name == 'python-windows' else (), problems)
        _check_spdx(where, entry, problems)
        if not isinstance(entry.get('version'), str) or not entry.get('version'):
            problems.append(f'{where}: version is required')
    py_versions = {components.get(n, {}).get('version') for n in ('python-windows', 'python-linux')}
    if len(py_versions) != 1:
        problems.append('python-windows and python-linux must pin the same Python version')
    ghidra = components.get('ghidra', {})
    if isinstance(ghidra, dict) and isinstance(ghidra.get('version'), str):
        if f"ghidra_{ghidra['version']}_PUBLIC" not in str(ghidra.get('url')):
            problems.append('components.ghidra: url does not match the pinned Ghidra version')
    for name in ('jdk-windows', 'jdk-linux'):
        entry = components.get(name, {})
        if isinstance(entry, dict) and isinstance(entry.get('version'), str):
            if not entry['version'].startswith('21.'):
                problems.append(f'components.{name}: JDK must be 21.x (the documented Ghidra requirement)')
            if str(entry.get('url', '')).count('%2B') != 1:
                problems.append(f'components.{name}: url must be a Temurin release asset')
    fallback = components.get('python-windows', {}).get('fallback') if isinstance(components.get('python-windows'), dict) else None
    if fallback is not None:
        if not isinstance(fallback, dict):
            problems.append('components.python-windows.fallback must be an object')
        else:
            _check_digest('components.python-windows.fallback', fallback, problems, allow_placeholder=False)

    wheels = data.get('wheels')
    if not isinstance(wheels, dict) or set(wheels) != {'windows', 'linux', 'any'}:
        problems.append('wheels must have exactly windows, linux and any')
        wheels = {}
    versions: dict[str, set[str]] = {}
    for platform, items in wheels.items():
        if not isinstance(items, list) or not items:
            problems.append(f'wheels.{platform}: must be a non-empty list')
            continue
        for index, item in enumerate(items):
            where = f'wheels.{platform}[{index}]'
            if not isinstance(item, dict):
                problems.append(f'{where}: not an object')
                continue
            if _check_digest(where, item, problems, allow_placeholder=False):
                continue
            _check_spdx(where, item, problems)
            if item.get('kind') not in KINDS:
                problems.append(f'{where}: kind must be one of {KINDS}')
            name = item.get('name')
            if not isinstance(name, str) or not name:
                problems.append(f'{where}: name is required')
                continue
            if item.get('kind') == 'wheel' and not _wheel_tag_ok(platform, name):
                problems.append(f'{where}: wheel tag does not fit the {platform} lane (cp312, win_amd64/manylinux x86_64, py3-none-any)')
            if item.get('kind') == 'sdist-built-to-wheel' and not name.endswith('.tar.gz'):
                problems.append(f'{where}: an sdist entry must be a .tar.gz')
            if isinstance(item.get('url'), str) and not item['url'].endswith(name):
                problems.append(f'{where}: url does not end with the file name')
            dist, version = item.get('distribution'), item.get('version')
            if not isinstance(dist, str) or not isinstance(version, str) or not version:
                problems.append(f'{where}: distribution and version are required')
                continue
            if not name.lower().startswith(f'{dist}-{version}'.lower()):
                problems.append(f'{where}: file name does not match distribution {dist} {version}')
            versions.setdefault(platform, set()).add(dist)
    for lane, sections in PLATFORM_SECTIONS.items():
        present = set().union(*(versions.get(s, set()) for s in sections))
        for dist in REQUIRED_DISTRIBUTIONS:
            if dist not in present:
                problems.append(f'wheels: {dist} is not pinned for the {lane} lane (no unpinned dependency may remain)')
    pinned = {item.get('distribution'): item.get('version') for items in wheels.values() if isinstance(items, list)
              for item in items if isinstance(item, dict)}
    if pinned.get('jpype1') != '1.5.2':
        problems.append('wheels: pyghidra 3.0.2 requires Jpype1==1.5.2')
    if pinned.get('mdutils') != '1.6.0':
        problems.append('wheels: ghidriff requires mdutils==1.6.0')
    if not str(pinned.get('pyghidra', '')).startswith('3.'):
        problems.append('wheels: ghidriff requires pyghidra>=3.0.0,<4')

    ghidriff = data.get('ghidriff')
    if not isinstance(ghidriff, dict):
        problems.append('ghidriff must be an object')
    else:
        if not isinstance(ghidriff.get('sha'), str) or not _HEX40.match(ghidriff['sha']):
            problems.append('ghidriff.sha must be a 40-hex git commit')
        if not str(ghidriff.get('repo', '')).startswith('https://'):
            problems.append('ghidriff.repo must be https://')
        _check_spdx('ghidriff', ghidriff, problems)
        tarball = ghidriff.get('source_tarball')
        if not isinstance(tarball, dict):
            problems.append('ghidriff.source_tarball must be an object')
        else:
            _check_digest('ghidriff.source_tarball', tarball, problems, allow_placeholder=True)
            _restrict_source('ghidriff.source_tarball', tarball, TARBALL_SOURCES, problems)
            if isinstance(ghidriff.get('sha'), str) and ghidriff['sha'] not in str(tarball.get('url')):
                problems.append('ghidriff.source_tarball: url does not name the pinned commit')
    offer = data.get('jdk_source_offer')
    if not isinstance(offer, dict):
        problems.append('jdk_source_offer must be an object')
    else:
        _check_digest('jdk_source_offer', offer, problems, allow_placeholder=False)
    strip = data.get('strip')
    if not isinstance(strip, dict) or not all(isinstance(strip.get(k), list) and strip[k] for k in ('ghidra', 'jdk', 'keep')):
        problems.append('strip must list ghidra, jdk and keep globs')
    _check_license_policy(data, problems)
    return problems


def _walk(prefix: str, value: object, out: list[str]) -> None:
    if isinstance(value, dict):
        if value.get('status') == 'placeholder' or value.get('sha256') == PLACEHOLDER:
            out.append(prefix)
        for key, child in value.items():
            if key != 'fallback':
                _walk(f'{prefix}.{key}' if prefix else key, child, out)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(f'{prefix}[{index}]', child, out)


def release_problems(data: dict) -> list[str]:
    """Places that still hold a placeholder digest; a release build must see an empty list."""
    found: list[str] = []
    _walk('', data, found)
    return [f'{path}: unresolved placeholder digest' for path in found]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--pin', type=Path, default=DEFAULT_PIN)
    parser.add_argument('--release', action='store_true', help='also fail (exit 3) while any placeholder remains, '
                        'and (exit 4) while a shipped license_policy component lacks owner approval')
    parser.add_argument('--allow-unapproved-licenses', action='store_true',
                        help='non-publishing acceptance builds only: warn loudly instead of exit 4')
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.pin.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        print(f'FAIL: cannot read pin: {error}', file=sys.stderr)
        return 1
    problems = validate_pin(data)
    if problems:
        for line in problems:
            print(f'FAIL: {line}', file=sys.stderr)
        return 1
    unresolved = release_problems(data)
    if unresolved:
        stream = sys.stderr if args.release else sys.stdout
        for line in unresolved:
            print(f'{"FAIL" if args.release else "note"}: {line}', file=stream)
        if args.release:
            return 3
    pending = unapproved_licenses(data)
    if pending:
        text = ('LICENSE POLICY: owner approval is still pending for ' + ', '.join(pending)
                + ' (policy gate, not a legal finding); a published release is refused')
        if args.release and not args.allow_unapproved_licenses:
            print(f'FAIL: {LICENSE_CODE}: {text}', file=sys.stderr)
            return 4
        print(f'WARNING: {text}', file=sys.stderr)
    print('backend pin ok' + (f' ({len(unresolved)} unresolved placeholder(s))' if unresolved else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
