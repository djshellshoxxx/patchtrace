"""Small diagnostic summaries and bounded log redaction; never dump environment."""
from __future__ import annotations

import re

_ASSIGNMENT = re.compile(
    r'''(?ix)(authorization["']?\s*[:=]\s*["']?\s*(?:(?:bearer|basic)\s+)?|
    (?:api[_-]?key|token|password|secret)["']?\s*[:=]\s*["']?)([^\s,;"']+)'''
)
_URL_AUTH = re.compile(r'(https?://)[^/\s:@]+:[^/\s@]+@', re.IGNORECASE)


def redact_log(text: str, limit: int = 2 * 1024 * 1024) -> str:
    text = _URL_AUTH.sub(r'\1[redacted]@', text)
    text = _ASSIGNMENT.sub(r'\1[redacted]', text)
    # Publicly common key prefixes can occur without a field label.
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{8,}\b', '[redacted]', text)
    return text[-limit:]


def diagnose(config):
    """Public convenience alias, with backend import deferred to avoid a cycle."""
    from .backend import diagnose as backend_diagnose
    return backend_diagnose(config)
