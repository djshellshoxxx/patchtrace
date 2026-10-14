"""Validate corpus INPUTS: found open-source cases (catalog case cards) and our own synthetic suites.

usage: corpus_check.py catalog FILE.json        structural check of case cards (offline)
       corpus_check.py suite DIR                structure + clang syntax check + truth completeness of one suite
       corpus_check.py all [ROOT]               every corpus/catalog/*.json and corpus/ours/*/*/suite.json
Exit status: 0 ok, 1 findings, 3 BLOCKED (clang is needed and missing). Findings are printed one per line.

Dev-only tool (not shipped). Formats and rules: corpus/README.md. Stdlib only; clang is used for syntax checks and
function enumeration (`-Xclang -ast-dump=json`), never to run anything.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPDX = {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'Zlib', 'ISC', 'CC0-1.0', 'Unlicense', 'Libpng-2.0',
        'curl', 'IJG', 'BSL-1.0', 'blessing', 'OpenSSL', 'PostgreSQL'}
CARD_KINDS = {'release', 'cve-fix', 'constant-only', 'bounds-only', 'refactor-control', 'large-rewrite',
              'build-system-only', 'no-op'}
BUILD_SYSTEMS = {'make', 'cmake', 'autotools', 'meson', 'single', 'other'}
TRUTH_LABELS = {'same', 'changed', 'cosmetic', 'moved', 'added', 'removed', 'renamed', 'split', 'merged', 'inlined'}
TAXONOMY = {f'N{i}' for i in range(1, 13)}
FREESTANDING_HEADERS = {'float.h', 'iso646.h', 'limits.h', 'stdalign.h', 'stdarg.h', 'stdbool.h', 'stddef.h',
                        'stdint.h', 'stdnoreturn.h'}
MAX_FILE = 120_000
MAX_VERSION = 400_000
HEX40 = re.compile(r'[0-9a-f]{40}')
ID = re.compile(r'[a-z0-9][a-z0-9._-]{2,80}')
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.MULTILINE)


class Blocked(Exception):
    pass


def _need(condition: bool, findings: list[str], where: str, message: str) -> None:
    if not condition:
        findings.append(f'{where}: {message}')


def check_catalog(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        cards = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return [f'{path.name}: unreadable JSON ({exc})']
    if not isinstance(cards, list) or not cards:
        return [f'{path.name}: must be a non-empty JSON array of case cards']
    seen: set[str] = set()
    for index, card in enumerate(cards):
        where = f'{path.name}[{index}]'
        if not isinstance(card, dict):
            findings.append(f'{where}: card must be an object')
            continue
        _need(card.get('contract') == 'case-card/1', findings, where, "contract must be 'case-card/1'")
        ident = card.get('id', '')
        where = f'{path.name}:{ident or index}'
        _need(isinstance(ident, str) and ID.fullmatch(ident) is not None, findings, where, 'bad id')
        _need(ident not in seen, findings, where, 'duplicate id')
        seen.add(ident)
        _need(card.get('license_spdx') in SPDX, findings, where,
              f"license_spdx must be one of {sorted(SPDX)} (unknown or copyleft = do not use)")
        _need(bool(card.get('license_evidence')), findings, where, 'license_evidence (quote + path/URL) is required')
        _need(str(card.get('upstream_git', '')).startswith('https://'), findings, where, 'upstream_git must be https')
        for side in ('old', 'new'):
            ref = card.get(side)
            ok = isinstance(ref, dict) and HEX40.fullmatch(str(ref.get('commit', ''))) and ref.get('ref')
            _need(bool(ok), findings, where, f'{side} needs ref and a 40-hex commit')
        if isinstance(card.get('old'), dict) and isinstance(card.get('new'), dict):
            _need(card['old'].get('commit') != card['new'].get('commit'), findings, where, 'old and new are identical')
        _need(card.get('kind') in CARD_KINDS, findings, where, f'kind must be one of {sorted(CARD_KINDS)}')
        functions = card.get('changed_functions')
        _need(isinstance(functions, list), findings, where, 'changed_functions must be a list (may be empty for controls)')
        if isinstance(functions, list):
            for entry in functions:
                _need(isinstance(entry, dict) and entry.get('name') and entry.get('file'), findings, where,
                      'each changed function needs name and file')
            if card.get('kind') in {'cve-fix', 'bounds-only', 'constant-only'}:
                _need(bool(functions), findings, where, 'a fix case must name its changed functions')
            if card.get('kind') in {'refactor-control', 'no-op', 'build-system-only'}:
                _need(card.get('semantic_change') is False, findings, where,
                      'controls must set "semantic_change": false')
        if card.get('kind') == 'cve-fix':
            _need(bool(card.get('cve')), findings, where, 'cve-fix needs a cve list')
        build = card.get('build')
        _need(isinstance(build, dict) and build.get('system') in BUILD_SYSTEMS, findings, where,
              f'build.system must be one of {sorted(BUILD_SYSTEMS)}')
        verification = card.get('verification')
        _need(isinstance(verification, dict) and verification.get('method') and
              verification.get('verified_by_agent_run') is True, findings, where,
              'verification.method and verification.verified_by_agent_run=true are required (run the git diff)')
        sources = card.get('sources')
        _need(isinstance(sources, list) and sources and all(str(s).startswith('https://') for s in sources),
              findings, where, 'sources must be a non-empty list of https URLs')
    return findings


def _clang() -> str:
    exe = shutil.which('clang')
    if exe is None:
        raise Blocked('clang is not installed')
    return exe


def _ast_functions(source: Path, version_dir: Path, defines: list[str]) -> dict[str, tuple[str, bytes]]:
    """Defined functions of one translation unit: name -> (file, exact source slice)."""
    command = [_clang(), '-std=c11', '-ffreestanding', '-fsyntax-only', '-Wall', '-Wextra', '-Wno-unused-parameter',
               f'-I{version_dir}', *[f'-D{d}' for d in defines], '-Xclang', '-ast-dump=json', str(source)]
    run = subprocess.run(command, capture_output=True, timeout=120, check=False)
    if run.returncode != 0:
        raise ValueError(run.stderr.decode('utf-8', 'replace').strip()[:600] or 'clang failed')
    tree = json.loads(run.stdout)
    current = [str(source)]
    found: dict[str, tuple[str, bytes]] = {}
    cache: dict[str, bytes] = {}

    def locate(location: object) -> None:
        if isinstance(location, dict):
            for part in (location, location.get('spellingLoc'), location.get('expansionLoc')):
                if isinstance(part, dict) and 'file' in part:
                    current[0] = part['file']

    def walk(node: dict) -> None:
        locate(node.get('loc'))
        extent = node.get('range')
        if isinstance(extent, dict):
            locate(extent.get('begin'))
        if node.get('kind') == 'FunctionDecl' and any(c.get('kind') == 'CompoundStmt' for c in node.get('inner', [])):
            file_name = current[0]
            begin, end = extent.get('begin', {}), extent.get('end', {})
            data = cache.setdefault(file_name, Path(file_name).read_bytes() if Path(file_name).is_file() else b'')
            if 'offset' in begin and 'offset' in end and 'expansionLoc' not in begin:
                piece = data[begin['offset']:end['offset'] + end.get('tokLen', 1)]
            else:
                piece = b''
            found[node['name']] = (file_name, piece)
        for child in node.get('inner', []) or []:
            if isinstance(child, dict):
                walk(child)
                locate(child.get('range', {}).get('end') if isinstance(child.get('range'), dict) else None)

    walk(tree)
    return {name: value for name, value in found.items() if Path(value[0]).resolve().is_relative_to(version_dir.resolve())}


def _version_functions(version_dir: Path, defines: list[str], findings: list[str], where: str) -> dict:
    names: dict[str, tuple[str, bytes]] = {}
    total = 0
    for source in sorted(version_dir.rglob('*')):
        if not source.is_file():
            continue
        data = source.read_bytes()
        total += len(data)
        _need(len(data) <= MAX_FILE, findings, where, f'{source.name} exceeds {MAX_FILE} bytes')
        _need(b'\x00' not in data, findings, where, f'{source.name} is not text')
        if source.suffix not in {'.c', '.h'}:
            findings.append(f'{where}: only .c and .h files are allowed ({source.name})')
            continue
        for kind, header in INCLUDE.findall(data.decode('utf-8', 'replace')):
            if kind == '<' and header not in FREESTANDING_HEADERS:
                findings.append(f'{where}: {source.name} includes <{header}>; only freestanding headers are allowed')
    _need(total <= MAX_VERSION, findings, where, f'version exceeds {MAX_VERSION} bytes')
    for source in sorted(version_dir.rglob('*.c')):
        try:
            found = _ast_functions(source, version_dir, defines)
        except ValueError as exc:
            findings.append(f'{where}: {source.name} does not compile: {exc}')
            continue
        for name, value in found.items():
            if name in names and names[name][0] != value[0]:
                findings.append(f'{where}: function name {name} is defined in two files (names must be unique)')
            names[name] = value
    return names


def _entry_sides(entry: dict) -> tuple[list[str], list[str]]:
    label = entry.get('label')
    one = [entry['function']] if 'function' in entry else []
    if label in {'same', 'changed', 'cosmetic', 'moved'}:
        return one, one
    if label == 'added':
        return [], one
    if label in {'removed', 'inlined'}:
        return one, []
    if label == 'renamed':
        return [entry.get('from', '')], [entry.get('to', '')]
    if label == 'split':
        return [entry.get('from', '')], list(entry.get('to', []))
    if label == 'merged':
        return list(entry.get('from', [])), [entry.get('to', '')]
    return [], []


def check_suite(directory: Path) -> list[str]:
    findings: list[str] = []
    try:
        suite = json.loads((directory / 'suite.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return [f'{directory.name}: suite.json unreadable ({exc})']
    where = f'{directory.parent.name}/{directory.name}'
    _need(suite.get('contract') == 'suite/1', findings, where, "contract must be 'suite/1'")
    _need(suite.get('license_spdx') in {'MIT', 'CC0-1.0', 'Unlicense'}, findings, where,
          'our own code must be MIT (or CC0/Unlicense)')
    versions = suite.get('versions')
    _need(isinstance(versions, list) and len(versions) >= 2, findings, where, 'needs at least two versions')
    if not isinstance(versions, list):
        return findings
    defines = list(suite.get('build', {}).get('defines', []))
    functions: dict[str, dict] = {}
    for version in versions:
        folder = directory / version
        if not folder.is_dir():
            findings.append(f'{where}: version directory {version} is missing')
            continue
        functions[version] = _version_functions(folder, defines, findings, f'{where}/{version}')
    for pair in suite.get('pairs', []):
        old, new = pair.get('old'), pair.get('new')
        pwhere = f'{where} {old}->{new}'
        if old not in functions or new not in functions:
            findings.append(f'{pwhere}: unknown version')
            continue
        old_names, new_names = set(functions[old]), set(functions[new])
        seen_old: list[str] = []
        seen_new: list[str] = []
        for entry in pair.get('truth', []):
            label = entry.get('label')
            if label not in TRUTH_LABELS:
                findings.append(f'{pwhere}: bad label {label!r}')
                continue
            for tag in entry.get('taxonomy', []):
                _need(tag in TAXONOMY, findings, pwhere, f'unknown taxonomy tag {tag}')
            old_side, new_side = _entry_sides(entry)
            if label == 'inlined':
                _need(entry.get('into') in new_names, findings, pwhere, 'inlined needs "into" (a new function)')
            seen_old += old_side
            seen_new += new_side
            if label in {'same', 'changed', 'cosmetic', 'moved'} and entry.get('function') in old_names & new_names:
                file_old, text_old = functions[old][entry['function']]
                file_new, text_new = functions[new][entry['function']]
                if text_old and text_new:
                    same_text = text_old == text_new
                    moved_file = Path(file_old).name != Path(file_new).name
                    # same = identical text in the same file; moved = relocated to a different file (text may also have
                    # changed); cosmetic/changed = the text differs
                    expected = {'same': same_text and not moved_file, 'moved': moved_file,
                                'cosmetic': not same_text, 'changed': not same_text}[label]
                    _need(expected, findings, pwhere,
                          f"{entry['function']}: labelled {label} but the source text is "
                          f"{'identical' if same_text else 'different'} and the file is "
                          f"{'different' if moved_file else 'the same'}")
        for side, names, seen in (('old', old_names, seen_old), ('new', new_names, seen_new)):
            for name in seen:
                _need(name in names, findings, pwhere, f'truth names {name!r} which is not defined in the {side} version')
            duplicates = {n for n in seen if seen.count(n) > 1}
            _need(not duplicates, findings, pwhere, f'{side} functions labelled twice: {sorted(duplicates)}')
            missing = names - set(seen)
            _need(not missing, findings, pwhere, f'{side} functions without a truth entry: {sorted(missing)}')
    _need(bool(suite.get('pairs')), findings, where, 'needs at least one pair')
    return findings


def check_all(root: Path = ROOT, *, compile_checks: bool = True) -> list[str]:
    findings: list[str] = []
    for catalog in sorted((root / 'corpus' / 'catalog').glob('*.json')):
        findings += check_catalog(catalog)
    if compile_checks:
        for suite_file in sorted((root / 'corpus' / 'ours').glob('*/*/suite.json')):
            findings += check_suite(suite_file.parent)
    return findings


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {'catalog', 'suite', 'all'}:
        print(__doc__)
        return 1
    try:
        if argv[1] == 'catalog':
            findings = check_catalog(Path(argv[2]))
        elif argv[1] == 'suite':
            findings = check_suite(Path(argv[2]))
        else:
            findings = check_all(Path(argv[2]) if len(argv) > 2 else ROOT)
    except Blocked as exc:
        print(f'BLOCKED: {exc}')
        return 3
    for line in findings:
        print(line)
    print(f'{len(findings)} finding(s)')
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
