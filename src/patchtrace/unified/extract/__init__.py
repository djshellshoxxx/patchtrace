"""SPEC-31 S1 extraction: the Ghidra script (data file, runs in the user's external Python) and its runner.

`ghidra_script.py` is a DATA file for the frozen build (tools/pyinstaller_hooks/hook-patchtrace.unified.extract.py):
PatchTrace code never imports it, it only reads its bytes, copies them into an empty private directory and runs the
configured external interpreter on the copy (03 s3). This package module holds the few definitions the runner and
the script must agree on; the script keeps its own copies (it may not import `patchtrace`) and a test pins both.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from importlib import resources

SCRIPT_NAME = 'ghidra_script.py'
PRIVATE_SCRIPT_NAME = 'pt_ir_extract.py'
SYMBOLS_BY_MODE = {'gzf': 'primary', 'analyze': 'none'}


def script_bytes() -> bytes:
    """The packaged extractor script (works from source and from the frozen onedir data file)."""
    return resources.files(__package__).joinpath(SCRIPT_NAME).read_bytes()


def script_sha256() -> str:
    return hashlib.sha256(script_bytes()).hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def analysis_options_digest(mode: str, options: Mapping[str, str] | None) -> str:
    """SHA-256 of canonical JSON of `{"mode", "options"}` (03 s12.5); the script computes the same value."""
    payload = canonical_json({'mode': mode, 'options': dict(options or {})})
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()
