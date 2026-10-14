"""Shared helpers of the SPEC-29 tools tests: open the deterministic synthetic PE pairs as verified readers and
write fake engine executables that print committed real-tool help/version text. No tool is run for real here."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from fake_exe import make_fake_exe
from test_intel_tools_pe import PAIRS

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools.normalize import PeMap
from patchtrace.intelligence.tools.process import ArtifactCopy

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools'


def golden(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def image_getter(tmp_path: Path):
    """(get, close): get(pair, side) -> (ArtifactCopy, reader, PeMap) of a synthetic pair member."""
    opened, out = [], {}

    def get(pair: str, side: str):
        if (pair, side) not in out:
            data = dict(zip(('older', 'newer'), PAIRS[pair](), strict=True))[side]
            path = tmp_path / f'{pair}-{side}.bin'
            path.write_bytes(data)
            copy = ArtifactCopy(path, hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(),
                                hashlib.sha1(data).hexdigest(), len(data))
            reader = VerifiedArtifactReader.open_path(path, copy.sha256)
            opened.append(reader)
            out[(pair, side)] = (copy, reader, PeMap.from_reader(reader))
        return out[(pair, side)]

    def close():
        for reader in opened:
            reader.close()
    return get, close


def fake_engine(directory: Path, engine: str, *, run_body: str = '', version: str | None = None,
                help_text: str | None = None) -> Path:
    """A fake `capa`/`floss`/`diec` executable: `--version`/`--help`/`-H` print the committed real texts; any
    other invocation runs `run_body` (Python source; `ARGS` holds the argv tail, the artifact path is ARGS[-1])."""
    texts = {'capa': ('capa/version.stdout.txt', 'capa/help.stdout.txt'),
             'floss': ('floss/version.stdout.txt', 'floss/help-advanced.stdout.txt'),
             'diec': ('diec/version.stdout.txt', 'diec/help.stdout.txt')}
    version_text = version if version is not None else golden(texts[engine][0]).decode()
    help_body = help_text if help_text is not None else golden(texts[engine][1]).decode()
    source = (f'import sys\nARGS = sys.argv[1:]\n'
              f'VERSION = {version_text!r}\nHELP = {help_body!r}\n'
              'if ARGS[:1] == ["--version"]:\n    sys.stdout.write(VERSION); sys.exit(0)\n'
              'if ARGS[:1] in (["--help"], ["-H"]):\n    sys.stdout.write(HELP); sys.exit(0)\n'
              + run_body)
    return make_fake_exe(directory, engine, source)


PYTHON = Path(sys.executable)
