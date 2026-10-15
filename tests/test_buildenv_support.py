"""Shared helpers of the build-environment tests (no tests here): fingerprints of synthetic PEs and of the
committed real `diec` 3.21 goldens. Nothing is run; no Microsoft binary is involved."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from test_intel_tools_pe import PAIRS

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.buildenv.adapters import pe_facts_from
from patchtrace.buildenv.contracts import BuildFingerprint, DieSummary
from patchtrace.buildenv.fingerprint import build_fingerprint
from patchtrace.intelligence.tools import diec
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview.build_facts import collect_build_facts

GOLDENS = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools' / 'diec'
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'buildenv'
PIN = 'a' * 64
WINDOWS_DB = 'a862337efa9558e1c52608fdbd8c25b1537a2a11d62a38acbb9c6b9bcb39adda'
LINUX_DB = '301b24a78ffb8491c377bd8d6a08a24d9faf6374f29fb072ea528596d2bc2b86'


def detects(*items: tuple[str, str, str]) -> bytes:
    """A minimal diec JSON document of (type, name, version) leaves."""
    values = [{'info': '', 'name': name, 'string': f'{kind}: {name}({version})', 'type': kind, 'version': version}
              for kind, name, version in items]
    node = {'filetype': 'PE64', 'info': '', 'offset': '0', 'parentfilepart': 'Header', 'size': '1', 'values': values}
    return json.dumps({'detects': [node]}).encode()


def die_summary(side: str, sha: str, *, status: str = 'ok', db: str = LINUX_DB, version: str = '3.21',
                heuristics: bool = False) -> DieSummary:
    produced = status in ('ok', 'none-found')
    return DieSummary(status=status, run_id=f'run-{side}', tool_version=version, db_label=diec.KNOWN_DATABASES.get(db),
                      db_sha256=db, argv_version='diec/1', heuristics=heuristics,
                      cache_key=hashlib.sha256(f'{side}{sha}{version}{db}'.encode()).hexdigest() if produced else None)


def evidence_of(raw: bytes, side: str, sha: str):
    ctx = diec.ParseContext(run_id=f'run-{side}', side=side, artifact_sha256=sha, cache_key=PIN, config_digest=PIN,
                            limits=DEFAULT_LIMITS['diec'])
    return diec.parse(raw, ctx)


def fingerprint_of(tmp_path: Path, data: bytes, side: str, diec_json: bytes | None = None, *,
                   db: str = LINUX_DB, version: str = '3.21', heuristics: bool = False) -> BuildFingerprint:
    path = tmp_path / f'{side}.bin'
    path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    with VerifiedArtifactReader.open_path(path, sha) as reader:
        overview = inspect_pe(reader)
        pe = pe_facts_from(collect_build_facts(reader, overview))
    kw: dict = {}
    if diec_json is not None:
        kw = {'die': die_summary(side, sha, db=db, version=version, heuristics=heuristics),
              'evidence': evidence_of(diec_json, side, sha)}
    return build_fingerprint(sha, side, pe=pe, hints=overview.packer_hints, **kw)


def golden(name: str) -> bytes:
    return (GOLDENS / name).read_bytes()


def pair_fingerprints(tmp_path: Path, pair: str, kind: str | None = None, *, heuristics: bool = False,
                      **kw) -> tuple[BuildFingerprint, BuildFingerprint]:
    """Fingerprints of a synthetic pair; `kind` names the committed goldens `diec-<kind>-{older,newer}.json`."""
    out = []
    for side, data in zip(('older', 'newer'), PAIRS[pair](), strict=True):
        raw = None
        if kind:
            heur = GOLDENS / f'diec-{kind}-{side}.heuristic.json'
            raw = golden(heur.name if heuristics and heur.is_file() else f'diec-{kind}-{side}.json')
        out.append(fingerprint_of(tmp_path, data, side, raw, heuristics=heuristics, **kw))
    return out[0], out[1]
