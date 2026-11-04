"""Offline verification of a published PatchTrace prerelease (windows-acceptance spec section 1.3,
docs/release-process.md "Verify assets before announcing"). Stdlib only: it never uses the network, never
extracts an archive and never runs a downloaded file; it reads only the files named on its command line.

Produce the inputs first, from a clone of the repository and with an empty download directory:
  gh release view TAG --json tagName,isPrerelease,isDraft,targetCommitish,assets,body > release.json
  git ls-remote --tags origin refs/tags/TAG 'refs/tags/TAG^{}' > peeled.txt
  gh release download TAG --dir DIR

Checks (a failure names its code):
  tag                 tagName is TAG                                                  PT-REL-TAG-MISMATCH
  prerelease          isPrerelease true and isDraft false                             PT-REL-NOT-PRERELEASE
  commit:*            targetCommitish, the peeled tag (the plain ref of a lightweight tag) and the Windows
                      ZIP's PatchTrace/dependency-versions.json "PatchTrace commit" are SHA, and its
                      "PatchTrace" label is TAG without the leading v                 PT-REL-COMMIT-MISMATCH
  asset:<name>        each of the 8 assets is listed and downloaded with equal sizes  PT-REL-ASSET-MISSING
  sidecar:<name>      each .sha256 is exactly "<64 lowercase hex>  <name>\\n" (LF)     PT-REL-SIDECAR-FORMAT
  hash:<name>         the file's SHA-256 equals its sidecar, the listed "sha256:" digest and every hash the
                      notes print on a line naming it; portable: Portable.zip is the Windows ZIP
                                                                                      PT-REL-HASH-MISMATCH
  archive:*           the ZIP holds PatchTrace/PatchTrace.exe, file-inventory.json and dependency-versions.json;
                      the tar holds PatchTrace/PatchTrace with an executable bit; no absolute, '..', duplicate
                      or escaping-link member                                         PT-REL-ARCHIVE-CONTENT
The Linux package records no commit yet (tools/build_linux.py), so commit:linux-tar is not-checked until its
dependency-versions.json carries one; not-checked is never a pass. Notes come from --notes, else the release body.

Exit 0 when no check fails, 2 for a usage error or unreadable input, 3 when any check fails.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import sys
import tarfile
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, NamedTuple, NoReturn

WINDOWS_ZIP = 'PatchTrace-0.1.0-windows-x64.zip'
PORTABLE_ZIP = 'PatchTrace-Windows-x64-Portable.zip'
SETUP_EXE = 'PatchTrace-Windows-x64-Setup.exe'
LINUX_TAR = 'PatchTrace-0.1.0-linux-x86_64.tar.gz'
PAYLOADS = (WINDOWS_ZIP, PORTABLE_ZIP, SETUP_EXE, LINUX_TAR)
SIDECAR = '.sha256'
ASSETS = tuple(name for payload in PAYLOADS for name in (payload, payload + SIDECAR))
VERSIONS_MEMBER = 'PatchTrace/dependency-versions.json'
ZIP_REQUIRED = ('PatchTrace/PatchTrace.exe', 'PatchTrace/file-inventory.json', VERSIONS_MEMBER)
LINUX_EXE = 'PatchTrace/PatchTrace'

MAX_JSON_BYTES = 1 << 20  # one archive member read into memory
MAX_MEMBERS = 100_000
MAX_INPUT_BYTES = 8 << 20  # release JSON, notes and ls-remote listing
MAX_SIDECAR_BYTES = 4096
DETAIL_LIMIT = 300
LISTED_PROBLEMS = 3

PASS, FAIL, NOT_CHECKED = 'pass', 'fail', 'not-checked'
TAG_MISMATCH = 'PT-REL-TAG-MISMATCH'
NOT_PRERELEASE = 'PT-REL-NOT-PRERELEASE'
COMMIT_MISMATCH = 'PT-REL-COMMIT-MISMATCH'
ASSET_MISSING = 'PT-REL-ASSET-MISSING'
SIDECAR_FORMAT = 'PT-REL-SIDECAR-FORMAT'
HASH_MISMATCH = 'PT-REL-HASH-MISMATCH'
ARCHIVE_CONTENT = 'PT-REL-ARCHIVE-CONTENT'

TAG = re.compile(r'v[0-9A-Za-z][0-9A-Za-z.+-]{0,99}')
SHA = re.compile(r'[0-9a-f]{40}')
REF_LINE = re.compile(r'([0-9a-f]{40})\t(\S+)')
SIDECAR_LINE = re.compile(rb'([0-9a-f]{64})  ([^\r\n]+)\n')
SIDECAR_HASH = re.compile(rb'([0-9a-fA-F]{64}) [ *]')
HEX64 = re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])')
DRIVE = re.compile(r'[A-Za-z]:')
NAME_IN_NOTES = {name: re.compile(rf'(?<![\w.-]){re.escape(name)}(?![\w-]|\.[\w-])') for name in ASSETS}

ZIP_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError,
              OSError)
TAR_ERRORS = (tarfile.TarError, zlib.error, EOFError, OSError)


class InputError(Exception):
    """A usage error or an input file that cannot be read: exit 2, no report."""


class _HelpShown(Exception):
    pass


class Check(NamedTuple):
    id: str
    status: str
    code: str | None
    detail: str


class Inputs(NamedTuple):
    tag: str
    sha: str
    release: Mapping[str, object]
    refs: Mapping[str, str]
    directory: Path
    notes: str


class Archive(NamedTuple):
    problems: list[str]
    versions: Mapping[str, object] | None
    versions_note: str


class Report(NamedTuple):
    checks: list[Check]
    files: dict[str, tuple[int, str]]  # name -> (bytes, SHA-256) of every downloaded asset
    peeled: str | None


def clean(text: str, limit: int = DETAIL_LIMIT) -> str:
    """Printable ASCII on one line, at most `limit` characters: release text is untrusted."""
    flat = ' '.join(text.split())
    return ''.join(char if char.isascii() and char.isprintable() else '?' for char in flat)[:limit]


def shown(value: object) -> str:
    if isinstance(value, str):
        value = value[:120]
    return clean(json.dumps(value), 160)


def outcome(check_id: str, ok: bool, code: str, detail: str) -> Check:
    return Check(check_id, PASS if ok else FAIL, None if ok else code, clean(detail))


def skipped(check_id: str, detail: str) -> Check:
    return Check(check_id, NOT_CHECKED, None, clean(detail))


# ---------------------------------------------------------------- reading the inputs

def read_bounded(path: Path, limit: int) -> bytes:
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'larger than {limit} bytes')
    return data


def strict_json(text: str) -> object:
    """JSON with duplicate keys and NaN/Infinity refused, so no value can hide behind a later one."""
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError('duplicate key')
        return dict(items)

    def constant(name: str) -> NoReturn:
        raise ValueError(f'{name} is not JSON')

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def read_input(path: Path, what: str) -> str:
    try:
        return read_bounded(path, MAX_INPUT_BYTES).decode('utf-8')
    except (OSError, ValueError) as exc:  # UnicodeDecodeError is a ValueError
        raise InputError(f'{what} {path} is unreadable: {exc}') from exc


def load_release(path: Path) -> Mapping[str, object]:
    try:
        document = strict_json(read_input(path, '--release-json'))
    except ValueError as exc:
        raise InputError(f'--release-json {path} is not strict JSON: {exc}') from exc
    if not isinstance(document, dict):
        raise InputError(f'--release-json {path} is not a JSON object')
    return document


def load_refs(path: Path) -> dict[str, str]:
    """`git ls-remote` lines `<sha>\\t<ref>`; anything else means the wrong file."""
    refs = {}
    for line in read_input(path, '--peeled').splitlines():
        if not line.strip():
            continue
        match = REF_LINE.fullmatch(line.strip())
        if match is None:
            raise InputError(f'--peeled {path} is not git ls-remote output: {clean(line, 80)!r}')
        refs[match[2]] = match[1]
    return refs


def load_inputs(args: argparse.Namespace) -> Inputs:
    if not TAG.fullmatch(args.tag):
        raise InputError(f'--tag must look like v0.1.0-beta.N, got {clean(args.tag, 80)!r}')
    if not SHA.fullmatch(args.sha):
        raise InputError('--sha must be a full 40-character lowercase commit SHA')
    if not args.dir.is_dir():
        raise InputError(f'--dir {args.dir} is not a directory')
    release = load_release(args.release_json)
    refs = load_refs(args.peeled)
    if args.notes is not None:
        notes = read_input(args.notes, '--notes')
    else:
        body = release.get('body')
        notes = body if isinstance(body, str) else ''
    return Inputs(args.tag, args.sha, release, refs, args.dir, notes)


# ---------------------------------------------------------------- release metadata

def peeled_commit(refs: Mapping[str, str], tag: str) -> str | None:
    return refs.get(f'refs/tags/{tag}^{{}}') or refs.get(f'refs/tags/{tag}')


def metadata_checks(inputs: Inputs, peeled: str | None) -> list[Check]:
    release, sha = inputs.release, inputs.sha
    tag_name, prerelease, draft = release.get('tagName'), release.get('isPrerelease'), release.get('isDraft')
    target = release.get('targetCommitish')
    return [
        outcome('tag', tag_name == inputs.tag, TAG_MISMATCH, f'tagName {shown(tag_name)}, expected {inputs.tag}'),
        outcome('prerelease', prerelease is True and draft is False, NOT_PRERELEASE,
                f'isPrerelease {shown(prerelease)}, isDraft {shown(draft)}'),
        outcome('commit:target', target == sha, COMMIT_MISMATCH,
                f'targetCommitish {shown(target)}, expected {sha}'),
        outcome('commit:peeled', peeled == sha, COMMIT_MISMATCH,
                f'refs/tags/{inputs.tag} peels to {peeled or "nothing: the tag is not in the listing"}, '
                f'expected {sha}'),
    ]


# ---------------------------------------------------------------- assets, sidecars and hashes

def listed_assets(release: Mapping[str, object]) -> tuple[dict[str, Mapping[str, object]], set[str]]:
    """Release assets by name, and the names listed more than once."""
    items = release.get('assets')
    entries = [item for item in items if isinstance(item, dict) and isinstance(item.get('name'), str)] \
        if isinstance(items, list) else []
    counts = Counter(item['name'] for item in entries)
    return {item['name']: item for item in entries}, {name for name, count in counts.items() if count > 1}


def downloaded(directory: Path) -> dict[str, Path]:
    found = {}
    for name in ASSETS:
        path = directory / name
        if path.is_file() and not path.is_symlink():
            found[name] = path
    return found


def file_facts(files: Mapping[str, Path]) -> dict[str, tuple[int, str]]:
    facts = {}
    for name, path in files.items():
        with path.open('rb') as stream:
            facts[name] = (path.stat().st_size, hashlib.file_digest(stream, 'sha256').hexdigest())
    return facts


def asset_checks(listed: Mapping[str, Mapping[str, object]], twice: set[str],
                 facts: Mapping[str, tuple[int, str]]) -> list[Check]:
    checks = []
    for name in ASSETS:
        entry, problems = listed.get(name), []
        if entry is None:
            problems.append('not in the release asset list')
        if name in twice:
            problems.append('listed more than once')
        if name not in facts:
            problems.append('not downloaded')
        if entry is not None and name in facts and entry.get('size') != facts[name][0]:
            problems.append(f'listed size {shown(entry.get("size"))}, downloaded {facts[name][0]} bytes')
        detail = '; '.join(problems) or f'{facts[name][0]} bytes, listed and downloaded'
        checks.append(outcome(f'asset:{name}', not problems, ASSET_MISSING, detail))
    return checks


def sidecar_checks(files: Mapping[str, Path]) -> tuple[list[Check], dict[str, str]]:
    """Strict format checks, and the hash each readable sidecar states (read leniently, so a CRLF sidecar is
    reported once, as a format failure, while its hash is still compared)."""
    checks, stated = [], {}
    for payload in PAYLOADS:
        name = payload + SIDECAR
        if name not in files:
            checks.append(skipped(f'sidecar:{name}', 'not downloaded'))
            continue
        try:
            data = read_bounded(files[name], MAX_SIDECAR_BYTES)
        except (OSError, ValueError) as exc:
            checks.append(outcome(f'sidecar:{name}', False, SIDECAR_FORMAT, f'unreadable: {exc}'))
            continue
        loose = SIDECAR_HASH.match(data)
        if loose:
            stated[payload] = loose[1].decode('ascii').lower()
        strict = SIDECAR_LINE.fullmatch(data)
        ok = strict is not None and strict[2] == payload.encode('ascii')
        if ok:
            detail = f'{strict[1].decode("ascii")}, two spaces, {payload}, LF'
        elif b'\r' in data:
            detail = 'CRLF or CR line ending; expected "<64 lowercase hex>  <name>" and one LF'
        else:
            got = shown(data[:120].decode('latin-1'))
            detail = f'expected "<64 lowercase hex>  {payload}" and one LF, got {got}'
        checks.append(outcome(f'sidecar:{name}', ok, SIDECAR_FORMAT, detail))
    return checks, stated


def notes_hashes(notes: str, name: str) -> set[str]:
    """Every 64-hex value on a notes line that names this asset and no other."""
    found: set[str] = set()
    for line in notes.splitlines():
        named = [other for other, pattern in NAME_IN_NOTES.items() if pattern.search(line)]
        if named == [name]:
            found.update(value.lower() for value in HEX64.findall(line))
    return found


def hash_checks(listed: Mapping[str, Mapping[str, object]], facts: Mapping[str, tuple[int, str]],
                stated: Mapping[str, str], notes: str) -> list[Check]:
    checks = []
    for name in ASSETS:
        check_id = f'hash:{name}'
        if name not in facts:
            checks.append(skipped(check_id, 'not downloaded'))
            continue
        actual, sources, missing = facts[name][1], [], []
        if name in PAYLOADS:
            if name in stated:
                sources.append(('sidecar', stated[name]))
            else:
                missing.append('no readable sidecar')
        listed_digest = (listed.get(name) or {}).get('digest')
        if isinstance(listed_digest, str) and listed_digest.startswith('sha256:'):
            sources.append(('digest', listed_digest.removeprefix('sha256:').lower()))
        else:
            missing.append('no sha256 digest listed')
        printed = sorted(notes_hashes(notes, name))
        sources += [('notes', value) for value in printed]
        if not printed:
            missing.append('notes print no hash for this name')
        wrong = [f'{source} {clean(value, 72)}' for source, value in sources if value != actual]
        gaps = f'; {", ".join(missing)}' if missing else ''
        if wrong:
            checks.append(outcome(check_id, False, HASH_MISMATCH, f'{actual} differs from {", ".join(wrong)}'))
        elif not sources or (name in PAYLOADS and name not in stated):
            checks.append(skipped(check_id, f'{actual}, nothing to compare it with{gaps}'))
        else:
            agreed = ', '.join(sorted({source for source, _ in sources}))
            checks.append(outcome(check_id, True, HASH_MISMATCH, f'{actual} equals {agreed}{gaps}'))
    return checks


def portable_check(facts: Mapping[str, tuple[int, str]]) -> Check:
    if WINDOWS_ZIP not in facts or PORTABLE_ZIP not in facts:
        return skipped('portable', 'a Windows ZIP is not downloaded')
    same = facts[WINDOWS_ZIP] == facts[PORTABLE_ZIP]
    return outcome('portable', same, HASH_MISMATCH,
                   f'{PORTABLE_ZIP} {"is" if same else "is not"} byte-identical to {WINDOWS_ZIP}')


# ---------------------------------------------------------------- archives (read, never extracted)

def escapes(name: str) -> bool:
    return name.startswith(('/', '\\')) or bool(DRIVE.match(name)) or '..' in re.split(r'[\\/]', name)


def member_problems(names: Sequence[str]) -> list[str]:
    counts = Counter(names)
    bad = [f'unsafe member {shown(name)}' for name in names if escapes(name)]
    bad += [f'duplicate member {shown(name)}' for name, count in counts.items() if count > 1]
    return bad


def link_problems(members: Sequence[tarfile.TarInfo]) -> list[str]:
    bad = []
    for member in members:
        if member.issym():
            target = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname))
        elif member.islnk():
            target = posixpath.normpath(member.linkname)
        else:
            continue
        absolute = member.linkname.startswith(('/', '\\')) or DRIVE.match(member.linkname)
        if absolute or target == '..' or target.startswith('../'):
            bad.append(f'link {shown(member.name)} escapes the archive')
    return bad


def read_versions(size: int, opener: Callable[[], IO[bytes] | None]) -> tuple[Mapping[str, object] | None, str]:
    if size > MAX_JSON_BYTES:
        return None, 'is larger than 1 MiB; not read'
    stream = opener()
    if stream is None:
        return None, 'is not a regular file'
    with stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        return None, 'is larger than 1 MiB; not read'
    try:
        value = strict_json(data.decode('utf-8'))
    except ValueError:
        return None, 'is not strict JSON'
    return (value, 'read') if isinstance(value, dict) else (None, 'is not a JSON object')


def read_zip(path: Path) -> Archive:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                return Archive([f'more than {MAX_MEMBERS} members'], None, 'not read: member cap')
            names = [info.filename for info in infos]
            problems = member_problems(names)
            by_name = {info.filename: info for info in infos}
            problems += [f'{member} missing' for member in ZIP_REQUIRED
                         if member not in by_name or by_name[member].is_dir()]
            info = by_name.get(VERSIONS_MEMBER)
            if info is None or info.is_dir():
                return Archive(problems, None, 'is not in the ZIP')
            if names.count(VERSIONS_MEMBER) > 1:
                return Archive(problems, None, 'is in the ZIP more than once')
            versions, note = read_versions(info.file_size, lambda: archive.open(info))
    except ZIP_ERRORS as exc:
        return Archive([f'unreadable ZIP ({type(exc).__name__})'], None, 'unreadable')
    if note.startswith('is larger'):
        problems.append(f'{VERSIONS_MEMBER} {note}')
    return Archive(problems, versions, note)


def read_tar(path: Path) -> Archive:
    try:
        with tarfile.open(path, 'r:gz') as archive:
            members = []
            for member in archive:
                if len(members) >= MAX_MEMBERS:
                    return Archive([f'more than {MAX_MEMBERS} members'], None, 'not read: member cap')
                members.append(member)
            problems = member_problems([member.name for member in members]) + link_problems(members)
            by_name = {member.name: member for member in members}
            executable = by_name.get(LINUX_EXE)
            if executable is None or not executable.isreg():
                problems.append(f'{LINUX_EXE} missing')
            elif not executable.mode & 0o111:
                problems.append(f'{LINUX_EXE} has no executable bit (mode {executable.mode:04o})')
            info = by_name.get(VERSIONS_MEMBER)
            if info is None or not info.isreg():
                return Archive(problems, None, 'is not in the tar')
            versions, note = read_versions(info.size, lambda: archive.extractfile(info))
    except TAR_ERRORS as exc:
        return Archive([f'unreadable tar.gz ({type(exc).__name__})'], None, 'unreadable')
    if note.startswith('is larger'):
        problems.append(f'{VERSIONS_MEMBER} {note}')
    return Archive(problems, versions, note)


def archive_check(check_id: str, archive: Archive | None) -> Check:
    if archive is None:
        return skipped(check_id, 'not downloaded')
    shown_problems = archive.problems[:LISTED_PROBLEMS]
    more = len(archive.problems) - len(shown_problems)
    detail = '; '.join(shown_problems) + (f'; {more} more' if more > 0 else '')
    return outcome(check_id, not archive.problems, ARCHIVE_CONTENT,
                   detail or 'required members present, all safe')


def commit_check(check_id: str, archive: Archive | None, sha: str, label: str, *, required: bool) -> Check:
    if archive is None:
        return skipped(check_id, 'not downloaded')
    if archive.versions is None:
        detail = f'{VERSIONS_MEMBER} {archive.versions_note}'
        return outcome(check_id, False, COMMIT_MISMATCH, detail) if required else skipped(check_id, detail)
    commit, found = archive.versions.get('PatchTrace commit'), archive.versions.get('PatchTrace')
    if not required and commit is None and found is None:
        return skipped(check_id, 'the Linux package records no commit (tools/build_linux.py); not compared')
    return outcome(check_id, commit == sha and found == label, COMMIT_MISMATCH,
                   f'PatchTrace commit {shown(commit)}, label {shown(found)}; expected {sha}, {label}')


# ---------------------------------------------------------------- the whole verification

def verify(inputs: Inputs) -> Report:
    peeled = peeled_commit(inputs.refs, inputs.tag)
    listed, twice = listed_assets(inputs.release)
    files = downloaded(inputs.directory)
    facts = file_facts(files)
    windows = read_zip(files[WINDOWS_ZIP]) if WINDOWS_ZIP in files else None
    linux = read_tar(files[LINUX_TAR]) if LINUX_TAR in files else None
    label = inputs.tag[1:]
    sidecars, stated = sidecar_checks(files)
    checks = [
        *metadata_checks(inputs, peeled),
        commit_check('commit:windows-zip', windows, inputs.sha, label, required=True),
        commit_check('commit:linux-tar', linux, inputs.sha, label, required=False),
        *asset_checks(listed, twice, facts),
        *sidecars,
        *hash_checks(listed, facts, stated, inputs.notes),
        portable_check(facts),
        archive_check('archive:windows-zip', windows),
        archive_check('archive:linux-tar', linux),
    ]
    return Report(checks, facts, peeled)


def exit_code(report: Report) -> int:
    return 3 if any(check.status == FAIL for check in report.checks) else 0


def counts(report: Report) -> dict[str, int]:
    tally = Counter(check.status for check in report.checks)
    return {status: tally[status] for status in (PASS, FAIL, NOT_CHECKED)}


def render_json(inputs: Inputs, report: Report) -> str:
    document = {'tool': 'verify_release', 'tag': inputs.tag, 'sha': inputs.sha,
                'result': FAIL if exit_code(report) else PASS, 'counts': counts(report),
                'checks': [check._asdict() for check in report.checks]}
    return json.dumps(document, indent=2) + '\n'


def render_text(report: Report) -> str:
    width = max(len(check.id) for check in report.checks)
    lines = [f'{check.status:<11} {check.id:<{width}} {check.code or "-":<22} {check.detail}'
             for check in report.checks]
    tally = counts(report)
    lines.append(f'result={FAIL if exit_code(report) else PASS} pass={tally[PASS]} fail={tally[FAIL]} '
                 f'not-checked={tally[NOT_CHECKED]}')
    return '\n'.join(lines) + '\n'


def render_record(inputs: Inputs, report: Report) -> str:
    """A docs/qa.md block: tag, peeled SHA, bytes and SHA-256 per asset, and the outcome with its gaps."""
    tally = counts(report)
    failed = [check.id for check in report.checks if check.status == FAIL]
    open_checks = [f'{check.id} ({check.detail})' for check in report.checks if check.status == NOT_CHECKED]
    release = inputs.release
    lines = [
        f'### Release verification: {inputs.tag}', '',
        f'- `tools/verify_release.py` exit {exit_code(report)}: {tally[PASS]} pass, {tally[FAIL]} fail, '
        f'{tally[NOT_CHECKED]} not-checked. Offline check of `gh release view`, `git ls-remote` and '
        '`gh release download` output.',
        f'- Tag `{inputs.tag}`, expected commit `{inputs.sha}`, peeled SHA `{report.peeled or "absent"}`, '
        f'targetCommitish {shown(release.get("targetCommitish"))}, '
        f'isPrerelease {shown(release.get("isPrerelease"))}, isDraft {shown(release.get("isDraft"))}.',
        f'- fail: {", ".join(failed) or "none"}',
        f'- not-checked: {"; ".join(open_checks) or "none"}',
        '- Not covered here: the run URL and number, and the comparison with the Actions artifact of the same '
        'run.',
        '', '| Asset | Bytes | SHA-256 |', '|---|---|---|',
    ]
    for name in ASSETS:
        size, digest = report.files.get(name, ('not downloaded', '-'))
        lines.append(f'| `{name}` | {size} | `{digest}` |')
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------- command line

class _Parser(argparse.ArgumentParser):
    def __init__(self, out: IO[str], **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.out = out

    def print_help(self, file: IO[str] | None = None) -> None:
        self.out.write(self.format_help())

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise _HelpShown

    def error(self, message: str) -> NoReturn:
        raise InputError(f'usage: {message}')


def build_parser(out: IO[str]) -> argparse.ArgumentParser:
    parser = _Parser(out, prog='verify_release.py', description=__doc__, allow_abbrev=False,
                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--tag', required=True, help='release tag, e.g. v0.1.0-beta.751')
    parser.add_argument('--sha', required=True, help='the reviewed main commit (40 lowercase hex)')
    parser.add_argument('--release-json', required=True, type=Path, help='gh release view --json output')
    parser.add_argument('--peeled', required=True, type=Path, help='git ls-remote output for the tag')
    parser.add_argument('--dir', required=True, type=Path, help='directory gh release download wrote')
    parser.add_argument('--notes', type=Path, help='release notes file (default: the body in --release-json)')
    parser.add_argument('--json', action='store_true', help='print one JSON object instead of text lines')
    parser.add_argument('--record', type=Path, help='write a docs/qa.md record block to this file')
    return parser


def main(argv: Sequence[str] | None = None, *, out: IO[str] | None = None, err: IO[str] | None = None) -> int:
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        args = build_parser(out).parse_args(argv)
        inputs = load_inputs(args)
        report = verify(inputs)
        if args.record is not None:
            try:
                args.record.write_text(render_record(inputs, report), encoding='utf-8', newline='\n')
            except OSError as exc:
                raise InputError(f'--record {args.record} cannot be written: {exc}') from exc
    except _HelpShown:
        return 0
    except InputError as exc:
        err.write(f'verify_release: error: {clean(str(exc), 500)}\n')
        return 2
    out.write(render_json(inputs, report) if args.json else render_text(report))
    return exit_code(report)


if __name__ == '__main__':
    sys.exit(main())
