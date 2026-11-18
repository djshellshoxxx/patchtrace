"""Bounded dependency/static scan receipts; a failure never becomes a clean scan.

Scans run in fresh environments and retain raw installation, inventory and scanner
evidence. This module neither upgrades the project nor publishes anything.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from tools import release_qualification as gate

EvidenceError = gate.QualificationError
require = gate.require
MAX_JSON = 16 * 1024 * 1024
MAX_ITEMS = 5000
MAX_DEPTH = 64
PINS = {'pip-audit': '2.10.1', 'ruff': '0.17.5'}
BOOTSTRAP_PIP = '26.3'
BOOTSTRAP_WHEEL_SHA256 = 'f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13'
BOOTSTRAP_WHEEL_URL = (
    'https://files.pythonhosted.org/packages/07/25/'
    'ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/pip-26.3-py3-none-any.whl')
WORKFLOW = '.github/workflows/dependency-security.yml'
PLATFORMS = {'ubuntu-latest': 'Linux', 'windows-latest': 'Windows'}
EXTRAS = {'runtime': ['search', 'rules'], 'packaging': ['dev', 'search', 'rules']}
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z')
VERSION = re.compile(r'[0-9][A-Za-z0-9.!+_-]{0,119}\Z')
NUMERIC = re.compile(r'[0-9]+(?:\.[0-9]+)*\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
UNAUDITED = [
    'External Ghidra, JDK, Rizin, BinDiff and NSIS binaries and their dependency closures',
    'Operating-system components and vendored Qt/native-library code',
    'A separate frozen executable or backend bundle bill of materials',
    'Optional calibration-dev extra, which is not installed in these profiles',
    'Scanner tooling dependencies (inventory retained separately, not included in the product audit)',
    'Exploitability and vulnerabilities absent from the selected public advisory database',
]
IDENTITY_CODE = (
    'import ensurepip,json,platform,sys; '
    'print(json.dumps({"executable":sys.executable,"prefix":sys.prefix,"base_prefix":sys.base_prefix,'
    '"version":platform.python_version(),"implementation":platform.python_implementation(),'
    '"system":platform.system(),"machine":platform.machine(),"ensurepip":ensurepip.version()}))'
)


def dump_new(path, value):
    try:
        with path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
    except (OSError, ValueError) as exc:
        raise EvidenceError(f'cannot preserve new receipt {path.name}: {exc}') from exc


def read_bytes(path, limit=MAX_JSON):
    try:
        info = path.lstat()
        open_state = gate.source_open_state(info)
        require(stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                f'{path.name}: evidence must be a regular file')
        require(info.st_size <= limit, f'{path.name}: evidence size limit exceeded')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            require(gate.source_open_state(opened) == open_state,
                    f'{path.name}: evidence changed at open')
            raw = stream.read(limit + 1)
            require(gate.source_state(os.fstat(stream.fileno())) == gate.source_state(opened),
                    f'{path.name}: evidence changed during read')
        require(gate.source_state(path.lstat()) == gate.source_state(info), f'{path.name}: evidence was replaced')
        require(len(raw) <= limit, f'{path.name}: evidence size limit exceeded')
        return raw
    except OSError as exc:
        raise EvidenceError(f'{path.name}: required evidence unavailable') from exc


def read_json(path):
    document = gate.strict_json(read_bytes(path), MAX_JSON)
    pending = [(document, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        require(depth <= MAX_DEPTH and count <= MAX_ITEMS * 100, 'JSON structure limit exceeded')
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return document


def digest(path):
    return hashlib.sha256(read_bytes(path)).hexdigest()


def canonical_name(value):
    require(isinstance(value, str) and NAME.fullmatch(value), 'invalid dependency name')
    return re.sub(r'[-_.]+', '-', value).lower()


def package_id(metadata):
    require(isinstance(metadata, dict), 'missing distribution metadata')
    name, version = canonical_name(metadata.get('name')), metadata.get('version')
    require(isinstance(version, str) and VERSION.fullmatch(version), f'{name}: unsafe or missing version')
    return name, version


def distributions(inspect):
    require(isinstance(inspect, dict) and inspect.get('version') == '1' and
            isinstance(inspect.get('pip_version'), str), 'unsupported pip inspect schema')
    rows = inspect.get('installed')
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_ITEMS, 'missing or unbounded installed inventory')
    found = {}
    for row in rows:
        require(isinstance(row, dict), 'invalid installed distribution')
        name, version = package_id(row.get('metadata'))
        require(name not in found, 'duplicate installed distribution identity')
        found[name] = (version, row)
    return found


def selected_requirements(project, profile):
    require(profile in EXTRAS, 'unsupported inventory profile')
    require(isinstance(project, dict) and isinstance(project.get('project'), dict), 'missing project metadata')
    metadata = project['project']
    optional = metadata.get('optional-dependencies')
    require(isinstance(optional, dict), 'missing optional dependency metadata')
    groups = [project.get('build-system', {}).get('requires'), metadata.get('dependencies')]
    groups.extend(optional.get(extra) for extra in EXTRAS[profile])
    require(all(isinstance(group, list) and group for group in groups), 'missing selected dependency group')
    return [item for group in groups for item in group]


def requirement_parts(requirement):
    """Parse the repository's bounded subset before any installer sees an argv."""
    require(isinstance(requirement, str) and len(requirement) <= 1000, 'invalid selected requirement')
    match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9._-]*)([^\s;\[\]@]+)', requirement)
    require(match is not None, 'unsupported selected requirement syntax')
    bounds = []
    for constraint in match[2].split(','):
        bound = re.fullmatch(r'(==|>=|<=|<|>)([0-9][A-Za-z0-9.!+_-]*)', constraint)
        require(bound is not None and VERSION.fullmatch(bound[2]), 'unsupported selected version constraint')
        require(bound[1] == '==' or NUMERIC.fullmatch(bound[2]), 'unsupported nonnumeric version bound')
        bounds.append(bound.groups())
    return canonical_name(match[1]), bounds


def require_selected(installed, requirements):
    """The repository uses this bounded subset; new PEP 508 forms fail closed."""
    require(len(requirements) <= MAX_ITEMS, 'too many selected requirements')
    for requirement in requirements:
        name, bounds = requirement_parts(requirement)
        require(name in installed, f'{name}: selected dependency is missing')
        version = installed[name][0]
        for operator, wanted in bounds:
            if operator == '==':
                require(version == wanted, f'{name}: installed version differs from exact requirement')
                continue
            require(NUMERIC.fullmatch(version) and NUMERIC.fullmatch(wanted),
                    'numeric bound cannot verify this installed version form')
            actual_parts, wanted_parts = tuple(map(int, version.split('.'))), tuple(map(int, wanted.split('.')))
            width = max(len(actual_parts), len(wanted_parts))
            actual_parts += (0,) * (width - len(actual_parts))
            wanted_parts += (0,) * (width - len(wanted_parts))
            allowed = {'>=': actual_parts >= wanted_parts, '<=': actual_parts <= wanted_parts,
                       '<': actual_parts < wanted_parts, '>': actual_parts > wanted_parts}[operator]
            require(allowed, f'{name}: installed version violates selected requirement')


def owned_origin(origin, root):
    require(isinstance(origin, dict) and origin.get('dir_info') == {'editable': True},
            'repository-owned distribution is not an editable directory')
    url = origin.get('url')
    require(isinstance(url, str), 'repository-owned origin is missing')
    parsed = urlsplit(url)
    require(parsed.scheme == 'file' and parsed.netloc in {'', 'localhost'} and
            not parsed.query and not parsed.fragment, 'repository-owned origin is not a local file URI')
    try:
        actual = Path(url2pathname(parsed.path)).resolve(strict=True)
        require(actual == root.resolve(strict=True), 'repository-owned distribution comes from another checkout')
    except OSError as exc:
        raise EvidenceError('repository-owned origin does not exist') from exc
    return url


def validate_inventory(inspect, root, project, profile, system, check_exit):
    require(type(check_exit) is int and check_exit == 0, 'pip check did not succeed')
    installed = distributions(inspect)
    environment = inspect.get('environment')
    require(isinstance(environment, dict) and environment.get('platform_system') == system,
            'installed inventory has a different platform')
    metadata = project.get('project', {})
    owner, expected_version = package_id(metadata)
    require(owner == 'patchtrace' and owner in installed, 'repository-owned distribution is missing')
    version, row = installed[owner]
    require(version == expected_version, 'repository-owned version differs from source metadata')
    origin = owned_origin(row.get('direct_url'), root)
    for name, (_, entry) in installed.items():
        require(name == owner or 'direct_url' not in entry, f'{name}: unauditable foreign direct dependency')
    require_selected(installed, selected_requirements(project, profile))
    return {'repository_owned': {'name': owner, 'version': version, 'origin': origin},
            'selected_extras': EXTRAS[profile],
            'auditable': [{'name': name, 'version': value[0]} for name, value in sorted(installed.items())
                          if name != owner]}


def validate_audit(report, expected, exit_code):
    require(type(exit_code) is int and exit_code == 0, 'dependency scanner did not exit successfully')
    require(isinstance(report, dict) and set(report) == {'dependencies', 'fixes'}, 'invalid pip-audit JSON schema')
    require(report['fixes'] == [], 'unexpected dependency remediation')
    rows = report['dependencies']
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_ITEMS, 'missing or unbounded audit coverage')
    actual = {}
    for row in rows:
        require(isinstance(row, dict) and 'skip_reason' not in row, 'dependency audit skipped a distribution')
        name, version = package_id(row)
        require(name not in actual, 'duplicate dependency audit result')
        require(row.get('vulns') == [], f'{name}: reported vulnerability or missing result')
        actual[name] = version
    required = {}
    for row in expected:
        name, version = package_id(row)
        require(name not in required, 'duplicate requested dependency')
        required[name] = version
    require(actual == required, 'dependency audit does not cover the exact installed closure')
    return len(actual)


def validate_static(report, exit_code):
    require(type(exit_code) is int and exit_code == 0, 'static scanner did not exit successfully')
    require(type(report) is list and not report, 'static scan has findings or invalid JSON shape')


def validate_context(recorded, expected):
    require(isinstance(recorded, dict) and isinstance(expected, dict) and expected,
            'missing actual scan ownership context')
    require(recorded == expected and all(type(recorded[key]) is type(value) for key, value in expected.items()),
            'scan receipt source/run/platform/profile ownership differs')


def checked_tree(root, sha):
    """Verify literal tree bytes, including held commits which are valid scan inputs.

    Publication's separate checked_source still rejects [no release]. Reuse its
    byte reader, never its index/diff status or a forged Git replacement object.
    """
    require(isinstance(sha, str) and gate.SHA_RE.fullmatch(sha), 'full source SHA is required')
    git = ['git', '--no-replace-objects']
    require(gate.command([*git, 'rev-parse', '--verify', 'HEAD'], cwd=root).decode().strip() == sha,
            'checked-out source SHA differs')
    tree = gate.command([*git, 'rev-parse', '--verify', f'{sha}^{{tree}}'], cwd=root).decode().strip()
    require(gate.SHA_RE.fullmatch(tree), 'invalid source tree identity')
    raw = gate.command([*git, 'ls-tree', '-r', '-z', '-l', '--full-tree', sha], cwd=root)
    require(raw.endswith(b'\0'), 'empty or malformed source tree')
    entries = raw[:-1].split(b'\0')
    require(len(entries) <= gate.MAX_SOURCE_FILES, 'source file count exceeds limit')
    parents, files, total = {}, {}, 0
    for entry in entries:
        header, name = entry.split(b'\t', 1)
        mode, kind, oid, length = header.split()
        require(kind == b'blob' and mode in {b'100644', b'100755', b'120000'} and length.isdigit() and
                gate.SHA_RE.fullmatch(oid.decode('ascii')), 'unsupported source tree entry')
        parts = os.fsdecode(name).split('/')
        require(all(part and part not in {'.', '..'} for part in parts), 'invalid source tree path')
        require(mode != b'120000' or parts[0] != 'src', 'application source symlink cannot be qualified')
        path, size = root.joinpath(*parts), int(length)
        total += size
        require(total <= gate.MAX_SOURCE_BYTES and path not in files, 'source tree limit or duplicate path')
        for parent in (root, *reversed(path.parents[:len(parts) - 1])):
            info = parent.lstat()
            identity = (info.st_dev, info.st_ino, info.st_mode)
            require(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                    'source parent is not a plain directory')
            require(parent not in parents or parents[parent] == identity, 'source parent was replaced')
            parents[parent] = identity
        actual, state = gate.source_blob(path, mode, size)
        require(actual == oid, 'actual source bytes differ from canonical commit')
        files[path] = state
    require(all(gate.source_unchanged(path, state) for path, state in files.items()),
            'source bytes changed during verification')
    for parent, identity in parents.items():
        info = parent.lstat()
        require((info.st_dev, info.st_ino, info.st_mode) == identity, 'source parent changed during verification')
    # An untracked module could be packaged or scanned without belonging to this source SHA.
    for count, path in enumerate((root / 'src').rglob('*.py'), 1):
        require(count <= gate.MAX_SOURCE_FILES and path in files, 'untracked application Python source')
    require(gate.command([*git, 'rev-parse', '--verify', 'HEAD'], cwd=root).decode().strip() == sha,
            'source HEAD changed during verification')
    return tree


def context(root, sha, repository, profile, target):
    require(profile in {*EXTRAS, 'static'} and target in PLATFORMS, 'invalid scan profile/platform')
    require(PLATFORMS[target] == platform.system(), 'requested native platform differs from this interpreter')
    require(isinstance(repository, str) and gate.REPO_RE.fullmatch(repository), 'invalid repository identity')
    hosted = os.environ.get('GITHUB_ACTIONS') == 'true'
    run_id, attempt, event = 0, 0, 'local'
    if hosted:
        require(os.environ.get('GITHUB_REPOSITORY') == repository and os.environ.get('GITHUB_SHA') == sha,
                'GitHub repository/SHA ownership differs')
        require(os.environ.get('RUNNER_OS') == PLATFORMS[target], 'GitHub runner platform differs')
        run_text, attempt_text = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
        require(run_text.isdecimal() and attempt_text.isdecimal(), 'missing GitHub run/attempt')
        run_id, attempt = int(run_text), int(attempt_text)
        require(run_id > 0 and attempt > 0, 'invalid GitHub run/attempt')
        event = os.environ.get('GITHUB_EVENT_NAME')
        require(event in {'push', 'pull_request', 'workflow_dispatch'}, 'unexpected scanner event')
        workflow_ref = os.environ.get('GITHUB_WORKFLOW_REF', '')
        require(workflow_ref.startswith(f'{repository}/{WORKFLOW}@refs/'), 'different GitHub workflow owner')
    return {'schema': 1, 'repository': repository, 'source_sha': sha, 'source_tree': checked_tree(root, sha),
            'workflow': WORKFLOW, 'run_id': run_id, 'run_attempt': attempt, 'event': event,
            'origin': 'github-actions' if hosted else 'local', 'platform': target, 'profile': profile,
            'checkout': str(root), 'controller_python': {'executable': sys.executable,
            'version': platform.python_version(), 'implementation': platform.python_implementation()}}


def run_logged(argv, out, name, *, timeout=600, limit=MAX_JSON):
    require(0 < timeout <= 900 and 0 < limit <= MAX_JSON, 'invalid process bounds')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,60}', name), 'invalid receipt command name')
    paths = [out / f'{name}.{suffix}' for suffix in ('stdout', 'stderr', 'process.json')]
    require(not any(path.exists() or path.is_symlink() for path in paths), 'prior command receipts exist')
    record = {'argv': argv, 'exit_code': None, 'timed_out': False, 'output_limited': False, 'error': None,
              'started_at': dt.datetime.now(dt.UTC).isoformat(), 'timeout_s': timeout}
    started = time.monotonic()
    # No caller pip configuration, extra index, inherited PYTHONPATH or user-site injection.
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('PIP_', 'PYTHON'))}
    env.update({'PIP_CONFIG_FILE': os.devnull, 'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1'})
    with paths[0].open('xb') as stdout, paths[1].open('xb') as stderr:
        try:
            with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) as process:
                errors = []

                def drain(source, destination):
                    written = 0
                    try:
                        while chunk := source.read(65536):
                            available = limit - written
                            destination.write(chunk[:available])
                            written += min(len(chunk), available)
                            if len(chunk) > available:
                                record['output_limited'] = True
                                process.kill()
                                break
                    except OSError as exc:
                        errors.append(str(exc)[:200])
                        process.kill()

                readers = [threading.Thread(target=drain, args=pair, daemon=True)
                           for pair in ((process.stdout, stdout), (process.stderr, stderr))]
                for reader in readers:
                    reader.start()
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record['timed_out'] = True
                    process.kill()
                    process.wait(timeout=5)
                for reader in readers:
                    reader.join(timeout=5)
                require(not any(reader.is_alive() for reader in readers), 'command output pipes did not close')
                record['exit_code'] = process.returncode
                record['error'] = '; '.join(errors) or None
        except (OSError, subprocess.SubprocessError) as exc:
            record['error'] = str(exc)[:500]
    record.update({'elapsed_s': round(time.monotonic() - started, 6),
                   'stdout_sha256': digest(paths[0]), 'stderr_sha256': digest(paths[1])})
    dump_new(paths[2], record)
    return record


def successful(record):
    require(isinstance(record, dict) and type(record.get('exit_code')) is int and record['exit_code'] == 0 and
            record.get('timed_out') is False and record.get('output_limited') is False and record.get('error') is None,
            'required command failed, timed out or exceeded evidence bounds')


def process_receipt(out, name, argv):
    record = read_json(out / f'{name}.process.json')
    require(isinstance(record, dict) and record.get('argv') == argv, f'{name}: command provenance differs')
    require(record.get('stdout_sha256') == digest(out / f'{name}.stdout') and
            record.get('stderr_sha256') == digest(out / f'{name}.stderr'), f'{name}: raw command output changed')
    timeout, elapsed = record.get('timeout_s'), record.get('elapsed_s')
    require(type(timeout) is int and 0 < timeout <= 900 and type(elapsed) in {int, float} and
            0 <= elapsed <= timeout + 15, f'{name}: missing or invalid process timing')
    try:
        started = dt.datetime.fromisoformat(record['started_at'])
        require(started.tzinfo is not None, 'process start time has no timezone')
        age = (dt.datetime.now(dt.UTC) - started).total_seconds()
        require(-120 <= age <= 24 * 60 * 60, f'{name}: stale or future process evidence')
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceError(f'{name}: missing or invalid process start time') from exc
    successful(record)
    return record


def python_path(out, name):
    return str(out / name / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))


def pip_install(python, report, requirements):
    return [python, '-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input',
            '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '--timeout', '15', '--retries', '1',
            '--report', str(report), *requirements]


def audit_argv(python, out):
    return [python, '-I', '-m', 'pip_audit', '-r', str(out / 'audit-requirements.txt'),
            '--strict', '--no-deps', '--disable-pip', '--vulnerability-service', 'pypi',
            '--format', 'json', '--progress-spinner', 'off', '--timeout', '15',
            '--cache-dir', str(out / 'advisory-cache')]


def static_argv(python, root):
    return [python, '-I', '-m', 'ruff', 'check', str(root / 'src'), '--isolated', '--select', 'S',
            '--ignore-noqa', '--no-cache', '--no-respect-gitignore', '--output-format', 'json']


def bootstrap_requirements_text():
    return f'pip=={BOOTSTRAP_PIP} --hash=sha256:{BOOTSTRAP_WHEEL_SHA256}\n'


def bootstrap_commands(out, label):
    require(label in {'scanner', 'profile'}, 'unknown bootstrap environment')
    python = python_path(out, f'{label}-env')
    return {
        f'{label}-venv': [sys.executable, '-I', '-m', 'venv', str(out / f'{label}-env')],
        f'{label}-bootstrap-identity': [python, '-I', '-c', IDENTITY_CODE],
        f'{label}-bootstrap-inspect': [python, '-I', '-m', 'pip', 'inspect', '--local'],
        f'{label}-bootstrap-check': [python, '-I', '-m', 'pip', 'check'],
        f'{label}-bootstrap-install': pip_install(python, out / f'{label}-bootstrap-install.json',
            ['--upgrade', '--force-reinstall', '--no-deps', '--require-hashes', '-r', str(out / 'bootstrap-pip.txt')]),
        f'{label}-prepared-inspect': [python, '-I', '-m', 'pip', 'inspect', '--local'],
    }


def commands(out, root, project, profile):
    if profile != 'static':
        for requirement in selected_requirements(project, profile):
            requirement_parts(requirement)
    scanner, product = python_path(out, 'scanner-env'), python_path(out, 'profile-env')
    pins = [f'{name}=={version}' for name, version in PINS.items() if profile != 'static' or name == 'ruff']
    result = {
        **bootstrap_commands(out, 'scanner'),
        'scanner-install': pip_install(scanner, out / 'scanner-install.json', pins),
        'scanner-identity': [scanner, '-I', '-c', IDENTITY_CODE],
        'scanner-inspect': [scanner, '-I', '-m', 'pip', 'inspect', '--local'],
        'scanner-check': [scanner, '-I', '-m', 'pip', 'check'],
    }
    if profile == 'static':
        result['static'] = static_argv(scanner, root)
    else:
        result.update({
            **bootstrap_commands(out, 'profile'),
            'build-install': pip_install(product, out / 'build-install.json', project['build-system']['requires']),
            'profile-install': pip_install(product, out / 'profile-install.json',
                ['--no-build-isolation', '-e', f'{root}[{",".join(EXTRAS[profile])}]']),
            'profile-identity': [product, '-I', '-c', IDENTITY_CODE],
            'profile-inspect': [product, '-I', '-m', 'pip', 'inspect', '--local'],
            'profile-check': [product, '-I', '-m', 'pip', 'check'],
            'audit': audit_argv(scanner, out),
        })
    return result


def validate_interpreter(identity, python, system, inspect):
    fields = ('executable', 'prefix', 'base_prefix', 'version', 'implementation', 'system', 'machine', 'ensurepip')
    require(isinstance(identity, dict) and all(isinstance(identity.get(key), str) and identity[key] for key in fields),
            'missing or malformed interpreter identity')
    require(identity['system'] == system and system in PLATFORMS.values() and
            identity['implementation'] == 'CPython', 'interpreter platform/implementation differs')
    require(Path(identity['prefix']).absolute() != Path(identity['base_prefix']).absolute() and
            Path(identity['executable']).absolute() == Path(python).absolute() and
            Path(python).absolute().parent.parent == Path(identity['prefix']).absolute(),
            'inventory interpreter is not the requested isolated environment')
    require(re.fullmatch(r'3\.12\.[0-9]+', identity['version']) and VERSION.fullmatch(identity['ensurepip']),
            'scan interpreter/bootstrap version is malformed or not stable Python 3.12')
    require(isinstance(inspect, dict), 'missing or malformed interpreter inspection')
    environment = inspect.get('environment', {})
    require(isinstance(environment, dict) and 7 <= len(environment) <= 32 and
            all(isinstance(key, str) and isinstance(value, str) and value for key, value in environment.items()),
            'missing or malformed pip interpreter environment')
    expected = {'platform_system': system, 'python_version': '3.12', 'python_full_version': identity['version'],
                'implementation_name': 'cpython', 'implementation_version': identity['version'],
                'platform_python_implementation': identity['implementation'], 'platform_machine': identity['machine']}
    require(all(environment.get(key) == value for key, value in expected.items()),
            'pip inspect interpreter metadata differs')


def validate_bootstrap_start(identity, before):
    installed = distributions(before)
    require(isinstance(identity, dict), 'missing bootstrap interpreter identity')
    validate_interpreter(identity, identity.get('executable'), identity.get('system'), before)
    require(set(installed) == {'pip'} and before['pip_version'] == installed['pip'][0] == identity['ensurepip'] and
            'direct_url' not in installed['pip'][1], 'initial inventory is not the fresh ensurepip bootstrap')
    require_selected(installed, [f'pip<={BOOTSTRAP_PIP}'])
    return installed['pip'][0]


def validate_bootstrap(record, final_identity):
    require(isinstance(record, dict) and set(record) == {'identity', 'before', 'installation', 'after'},
            'missing bootstrap transition evidence')
    identity, before, report, after = (record[key] for key in ('identity', 'before', 'installation', 'after'))
    original = validate_bootstrap_start(identity, before)
    require(identity == final_identity, 'bootstrap and final interpreter identities differ')
    prepared = distributions(after)
    validate_interpreter(identity, identity['executable'], identity['system'], after)
    require(set(prepared) == {'pip'} and after['pip_version'] == prepared['pip'][0] == BOOTSTRAP_PIP and
            'direct_url' not in prepared['pip'][1] and after['environment'] == before['environment'],
            'prepared bootstrap inventory differs from the pinned transition')
    require(isinstance(report, dict) and report.get('version') == '1' and
            report.get('pip_version') == original and report.get('environment') == before['environment'],
            'bootstrap installation issuer/environment differs')
    rows = report.get('install')
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
            'bootstrap installation must record exactly one target')
    row = rows[0]
    require(package_id(row.get('metadata')) == ('pip', BOOTSTRAP_PIP) and row.get('is_yanked') is False and
            row.get('requested') is True and row.get('is_direct') is False, 'unapproved bootstrap installation target')
    origin = row.get('download_info')
    require(isinstance(origin, dict) and origin.get('url') == BOOTSTRAP_WHEEL_URL and
            isinstance(origin.get('archive_info'), dict) and
            isinstance(origin['archive_info'].get('hashes'), dict) and
            origin['archive_info'].get('hashes', {}).get('sha256') == BOOTSTRAP_WHEEL_SHA256,
            'bootstrap wheel origin/digest differs from the reviewed pin')
    return {'from_version': original, 'to_version': BOOTSTRAP_PIP, 'wheel_sha256': BOOTSTRAP_WHEEL_SHA256}


def bootstrap_record(out, label):
    return {'identity': read_json(out / f'{label}-bootstrap-identity.stdout'),
            'before': read_json(out / f'{label}-bootstrap-inspect.stdout'),
            'installation': read_json(out / f'{label}-bootstrap-install.json'),
            'after': read_json(out / f'{label}-prepared-inspect.stdout')}


def validate_installation(inspect, identity, reports, root, *, owned=False, bootstrap=None):
    """No transition means the predecessor ensurepip-only contract, never the current pipeline."""
    installed, reported = distributions(inspect), {}
    require(isinstance(identity, dict), 'missing or malformed interpreter identity')
    validate_interpreter(identity, identity.get('executable'), identity.get('system'), inspect)
    require('pip' in installed and inspect['pip_version'] == installed['pip'][0],
            'inspect and installed pip identities differ')
    if bootstrap is None:
        require(installed['pip'][0] == identity['ensurepip'], 'unproved change from the original ensurepip bootstrap')
        unreported = {'pip'}
    else:
        proof = validate_bootstrap(bootstrap, identity)
        require(installed['pip'][0] == proof['to_version'] and
                inspect['environment'] == bootstrap['after']['environment'], 'final environment differs after bootstrap')
        reported['pip'] = proof['to_version']
        unreported = set()
    for report in reports:
        require(isinstance(report, dict) and report.get('version') == '1' and
                report.get('pip_version') == inspect['pip_version'] and
                report.get('environment') == inspect['environment'] and isinstance(report.get('install'), list) and
                0 < len(report['install']) <= MAX_ITEMS, 'invalid installation report')
        for row in report['install']:
            require(isinstance(row, dict) and row.get('is_yanked') is False, 'yanked or malformed installation')
            name, version = package_id(row.get('metadata'))
            require(name in installed and installed[name][0] == version, 'installation differs from final inventory')
            require(name not in reported, 'ambiguous repeated installation identity')
            info = row.get('download_info')
            require(isinstance(info, dict), 'missing installation origin')
            if owned and name == 'patchtrace':
                owned_origin(info, root)
            else:
                parsed = urlsplit(info.get('url', ''))
                require(parsed.scheme == 'https' and parsed.hostname == 'files.pythonhosted.org' and
                        not parsed.username and not parsed.password and unquote(parsed.path).endswith('.whl'),
                        'non-wheel or foreign installation origin')
                hashes = info.get('archive_info', {}).get('hashes', {})
                require(isinstance(hashes, dict) and isinstance(hashes.get('sha256'), str) and
                        SHA256.fullmatch(hashes['sha256']), 'missing installed wheel digest')
            reported[name] = version
    require(set(installed) == set(reported) | unreported, 'installed distribution has no build/install origin receipt')


def requirements_text(inventory):
    return ''.join(f'{row["name"]}=={row["version"]}\n' for row in inventory['auditable'])


def validate_evidence(out, expected, root, project):
    validate_context(read_json(out / 'context.json'), expected)
    require(read_bytes(out / 'bootstrap-pip.txt') == bootstrap_requirements_text().encode(),
            'missing or changed reviewed bootstrap requirements')
    profile, system = expected['profile'], PLATFORMS[expected['platform']]
    plan = commands(out, root, project, profile)
    for name, argv in plan.items():
        process_receipt(out, name, argv)
    inspect = read_json(out / 'scanner-inspect.stdout')
    identity = read_json(out / 'scanner-identity.stdout')
    validate_interpreter(identity, python_path(out, 'scanner-env'), system, inspect)
    tooling = distributions(inspect)
    for name, version in PINS.items():
        if profile != 'static' or name == 'ruff':
            require(name in tooling and tooling[name][0] == version, 'scanner version differs from pinned policy')
    scanner_bootstrap = bootstrap_record(out, 'scanner')
    validate_installation(inspect, identity, [read_json(out / 'scanner-install.json')], root,
                          bootstrap=scanner_bootstrap)
    require(read_json(out / 'unaudited.json') == UNAUDITED, 'unaudited categories missing or changed')
    if profile == 'static':
        validate_static(read_json(out / 'static.stdout'), read_json(out / 'static.process.json')['exit_code'])
        return {'kind': 'static', 'finding_count': 0,
                'bootstrap_pip': {'scanner': validate_bootstrap(scanner_bootstrap, identity)}}
    inspect = read_json(out / 'profile-inspect.stdout')
    identity = read_json(out / 'profile-identity.stdout')
    validate_interpreter(identity, python_path(out, 'profile-env'), system, inspect)
    inventory = validate_inventory(inspect, root, project, profile, system,
                                   read_json(out / 'profile-check.process.json')['exit_code'])
    profile_bootstrap = bootstrap_record(out, 'profile')
    validate_installation(inspect, identity, [read_json(out / 'build-install.json'),
                                             read_json(out / 'profile-install.json')], root, owned=True,
                          bootstrap=profile_bootstrap)
    require(read_json(out / 'inventory.json') == inventory, 'derived inventory differs from raw installed evidence')
    require(read_bytes(out / 'audit-requirements.txt') == requirements_text(inventory).encode(),
            'audit requirements differ from complete installed closure')
    coverage = validate_audit(read_json(out / 'audit.stdout'), inventory['auditable'],
                              read_json(out / 'audit.process.json')['exit_code'])
    return {'kind': 'dependency', 'audited_distributions': coverage,
            'repository_owned': inventory['repository_owned'],
            'bootstrap_pip': {'scanner': validate_bootstrap(scanner_bootstrap, scanner_bootstrap['identity']),
                              'profile': validate_bootstrap(profile_bootstrap, identity)}}


def execute_scan(out, expected, root, project):
    dump_new(out / 'context.json', expected)
    dump_new(out / 'unaudited.json', UNAUDITED)
    with (out / 'bootstrap-pip.txt').open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(bootstrap_requirements_text())
    profile = expected['profile']
    plan = commands(out, root, project, profile)
    for name, argv in plan.items():
        if name.endswith('-bootstrap-install'):
            label = name.split('-', 1)[0]
            validate_bootstrap_start(read_json(out / f'{label}-bootstrap-identity.stdout'),
                                     read_json(out / f'{label}-bootstrap-inspect.stdout'))
        if name == 'audit':
            inspect = read_json(out / 'profile-inspect.stdout')
            inventory = validate_inventory(inspect, root, project, profile, PLATFORMS[expected['platform']],
                                           read_json(out / 'profile-check.process.json')['exit_code'])
            dump_new(out / 'inventory.json', inventory)
            with (out / 'audit-requirements.txt').open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(requirements_text(inventory))
        record = run_logged(argv, out, name)
        successful(record)
        if name.endswith('-prepared-inspect'):
            prepared = bootstrap_record(out, name.split('-', 1)[0])
            validate_bootstrap(prepared, prepared['identity'])
    return validate_evidence(out, expected, root, project)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('audit', 'static', 'validate'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--profile', choices=(*EXTRAS, 'static'), required=True)
    parser.add_argument('--platform', choices=tuple(PLATFORMS), required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--repository', required=True)
    args = parser.parse_args(argv)
    root, out = Path(__file__).resolve().parents[1], args.out.absolute()
    report = {'schema': 1, 'status': 'failed', 'source_sha': args.head, 'profile': args.profile,
              'platform': args.platform, 'blockers': [], 'qualification': 'local/unverified until hosted review'}
    owned = args.operation == 'validate'
    try:
        if args.operation != 'validate':
            require((args.operation == 'static') == (args.profile == 'static'), 'operation/profile mismatch')
            out.mkdir(parents=True, exist_ok=False)
            owned = True
        expected = context(root, args.head, args.repository, args.profile, args.platform)
        project = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
        result = (validate_evidence(out, expected, root, project) if args.operation == 'validate'
                  else execute_scan(out, expected, root, project))
        validate_context(context(root, args.head, args.repository, args.profile, args.platform), expected)
        report.update({'status': 'passed', 'result': result, 'context': expected})
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        report['blockers'].append(str(exc)[:1000] or type(exc).__name__)
    if not owned:
        print(json.dumps(report, sort_keys=True, allow_nan=False))
        return 1
    receipt = out / ('validation.json' if args.operation == 'validate' else 'verdict.json')
    try:
        dump_new(receipt, report)
    except EvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
