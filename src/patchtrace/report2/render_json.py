"""JSON renderer and `content_digest` (SPEC-50 7.1): the digest covers canonical JSON without time-dependent keys."""
from __future__ import annotations

import hashlib

from . import text
from .contracts import Report2

VOLATILE_KEYS = ('generated_at', 'created', 'content_digest')


def content_digest(data: dict) -> str:
    canonical = {k: v for k, v in data.items() if k not in VOLATILE_KEYS}
    return hashlib.sha256(text.encode_report(text.json_dumps(canonical))).hexdigest()


def finalize(report: Report2) -> dict:
    data = report.to_dict()
    data['content_digest'] = content_digest(data)
    return data


def render_json(data: dict) -> str:
    return text.json_dumps(data, indent=2) + '\n'
