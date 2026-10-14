"""Microsoft CSAF directory discovery (SPEC-28 section C; CSAF 2.0 §7.1.7, §7.1.11-13, §7.1.18, §7.3).

Discovery never guesses a file name. It reads the provider metadata, uses only the directory-based
distributions it lists, reads each directory's ``index.txt`` and selects the index entries whose file name
contains the CVE identifier as a whole token. A file name is only a hint (§5.1 derives it from the tracking ID),
so a downloaded document must itself list the CVE. Integrity: the ``.sha256`` file next to a document
(Requirement 18) is compared when present; OpenPGP signatures are not checked.

The default provider-metadata location is UNVERIFIED LIVE (msrc.microsoft.com was blocked from the authoring
sandbox); ``--provider-metadata`` overrides it within the same allowlist.
"""
from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field

from ..contracts import IntelError, ValidationReport
from .transport import CAPS, CsafTransport, Fetched, check_url
from .validate import ValidationFailed, load_document, parse_json, provider_metadata_errors, safe_label

DEFAULT_PROVIDER_METADATA = 'https://msrc.microsoft.com/csaf/provider-metadata.json'
INDEX_ENTRY = re.compile(r'[0-9]{4}/[+\-a-z0-9_]+\.json')
MAX_DISTRIBUTIONS = 8
MAX_CANDIDATES = 8
MAX_INDEX_LINES = 1_000_000


@dataclass(frozen=True)
class IndexEntry:
    directory_url: str
    path: str

    @property
    def url(self) -> str:
        return f'{self.directory_url}/{self.path}'


@dataclass(frozen=True)
class Discovery:
    provider_url: str
    directories: tuple[str, ...]
    candidates: tuple[IndexEntry, ...]
    skipped_lines: int
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class FetchedDocument:
    url: str
    file_name: str
    raw: bytes = field(repr=False)
    retrieved_at: str
    authenticity_state: str
    document: dict = field(repr=False)
    report: ValidationReport


def provider_url_ok(url: str) -> str:
    check_url(url)
    if not url.endswith('/provider-metadata.json'):
        raise IntelError('PT-INTEL-CONFIG', 'provider metadata URL must end with /provider-metadata.json')
    return url


def parse_provider_metadata(raw: bytes) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(allowlisted directory URLs without trailing slash, warnings)."""
    value = parse_json(raw, max_bytes=CAPS['provider-metadata'], what='provider metadata')
    errors = provider_metadata_errors(value)
    if errors:
        first = errors[0]
        raise IntelError('PT-INTEL-PROVIDER', f'provider metadata is invalid: {first.pointer or "/"}: {first.message}')
    warnings: list[str] = []
    directories: list[str] = []
    rolie = False
    for distribution in value.get('distributions') or ():
        rolie = rolie or 'rolie' in distribution
        url = distribution.get('directory_url')
        if not isinstance(url, str):
            continue
        url = url.rstrip('/')
        try:
            check_url(f'{url}/index.txt')
        except IntelError:
            warnings.append(f'directory {safe_label(url, 120)} is outside the CSAF allowlist; ignored')
            continue
        if url not in directories:
            directories.append(url)
    if rolie:
        warnings.append('ROLIE feed distributions are not used (directory index only; SPEC-28 section C)')
    if not directories:
        if rolie:
            raise IntelError('PT-INTEL-UNSUPPORTED', 'the provider offers only ROLIE feeds, which are not supported')
        raise IntelError('PT-INTEL-PROVIDER', 'the provider metadata lists no usable directory distribution')
    if len(directories) > MAX_DISTRIBUTIONS:
        warnings.append(f'only the first {MAX_DISTRIBUTIONS} directory distributions are used')
    return tuple(directories[:MAX_DISTRIBUTIONS]), tuple(warnings)


def parse_index(raw: bytes, directory_url: str) -> tuple[list[IndexEntry], int]:
    """Entries of one ``index.txt``; lines that are not ``YYYY/<filename>.json`` are skipped and counted."""
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise IntelError('PT-INTEL-PROVIDER', 'index.txt is not valid UTF-8') from None
    entries, skipped = [], 0
    for number, line in enumerate(text.splitlines()):
        if number >= MAX_INDEX_LINES:
            raise IntelError('PT-INTEL-LIMIT', f'index.txt has more than {MAX_INDEX_LINES} lines')
        line = line.strip()
        if not line:
            continue
        if INDEX_ENTRY.fullmatch(line):
            entries.append(IndexEntry(directory_url, line))
        else:
            skipped += 1
    return entries, skipped


def matches_cve(path: str, cve: str) -> bool:
    name = path.rsplit('/', 1)[-1].lower()
    return re.search(r'(?<![a-z0-9])' + re.escape(cve.lower()) + r'(?![a-z0-9])', name) is not None


def discover(transport: CsafTransport, cve: str, provider_url: str = DEFAULT_PROVIDER_METADATA) -> Discovery:
    provider_url_ok(provider_url)
    meta = transport.get(provider_url, 'provider-metadata')
    directories, warnings = parse_provider_metadata(meta.body)
    candidates: list[IndexEntry] = []
    skipped = 0
    for directory in directories:
        index = transport.get(f'{directory}/index.txt', 'index')
        entries, dropped = parse_index(index.body, directory)
        skipped += dropped
        candidates += [e for e in entries if matches_cve(e.path, cve)]
    unique = sorted({e.url: e for e in candidates}.values(), key=lambda e: e.url)
    if len(unique) > MAX_CANDIDATES:
        raise IntelError('PT-INTEL-LIMIT', f'{len(unique)} index entries name {cve}; at most {MAX_CANDIDATES} are '
                                           'fetched (import the right document locally instead)')
    if skipped:
        warnings += (f'{skipped} index line(s) were not CSAF document paths and were skipped',)
    return Discovery(provider_url, directories, tuple(unique), skipped, tuple(warnings))


def _hash_value(fetched: Fetched | None) -> str | None:
    if fetched is None:
        return None
    try:
        text = fetched.body.decode('ascii').strip()
    except UnicodeDecodeError:
        raise IntelError('PT-INTEL-INTEGRITY', 'the .sha256 file is not ASCII') from None
    token = text.split()[0].lower() if text else ''
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        raise IntelError('PT-INTEL-INTEGRITY', 'the .sha256 file does not start with a SHA-256 value')
    return token


def fetch_documents(transport: CsafTransport, discovery: Discovery, cve: str,
                    cancel: threading.Event | None = None) -> tuple[list[FetchedDocument], list[str]]:
    """Download, integrity-check and validate every candidate. A candidate that fails is reported and skipped;
    cancellation and integrity mismatches stop the whole fetch."""
    accepted: list[FetchedDocument] = []
    warnings: list[str] = []
    for entry in discovery.candidates:
        document = transport.get(entry.url, 'document')
        expected = _hash_value(transport.get(f'{entry.url}.sha256', 'hash', allow_404=True))
        if expected is None:
            state = 'tls-allowlisted-host'
            warnings.append(f'{entry.path}: no .sha256 file; integrity rests on TLS to the allowlisted host only')
        elif expected != hashlib.sha256(document.body).hexdigest():
            raise IntelError('PT-INTEL-INTEGRITY', f'{entry.path}: SHA-256 differs from its .sha256 file')
        else:
            state = 'tls-allowlisted-host-hash-match'
        try:
            parsed, report = load_document(document.body, cancel=cancel)
        except ValidationFailed as exc:
            warnings.append(f'{entry.path}: rejected ({exc.message})')
            continue
        except IntelError as exc:
            if exc.code == 'PT-INTEL-CANCEL':
                raise
            warnings.append(f'{entry.path}: rejected ({exc.code}: {exc.message})')
            continue
        except Exception as exc:  # defence in depth: a validator bug on one hostile candidate must not abort the batch
            warnings.append(f'{entry.path}: rejected (unexpected {type(exc).__name__} while validating)')
            continue
        if not any(v.get('cve') == cve for v in parsed.get('vulnerabilities') or ()):
            warnings.append(f'{entry.path}: the document does not list {cve}; discarded (file names are hints only)')
            continue
        accepted.append(FetchedDocument(url=entry.url, file_name=entry.path.rsplit('/', 1)[-1], raw=document.body,
                                        retrieved_at=document.retrieved_at, authenticity_state=state,
                                        document=parsed, report=report))
    return accepted, warnings
