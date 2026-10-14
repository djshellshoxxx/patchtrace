"""Small diagnostic summaries and bounded log redaction; never dump environment."""
from __future__ import annotations

import re

_ASSIGNMENT = re.compile(
    r'''(?ix)(authorization["']?\s*[:=]\s*["']?\s*(?:(?:bearer|basic)\s+)?|
    (?:api[_-]?key|token|password|secret)["']?\s*[:=]\s*)
    (?:"[^"\n]*"|'[^'\n]*'|[^\s,;"']+)'''
)
# Conservative bare credential shapes: GitHub, AWS access key IDs, bearer, sk- keys.
_BARE_TOKENS = re.compile(
    r'\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{8,}'
)
# Whole header value: schemes such as Token/ApiKey/Digest would otherwise leave the secret visible.
_AUTH_HEADER = re.compile(r'(?i)(\bauthorization["\']?\s*[:=]\s*)[^\r\n]+')
_BEARER = re.compile(r'\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}', re.IGNORECASE)
# Greedy to the last '@' before the path: unencoded '@' in a password must not
# leave its tail visible, and proxy schemes such as socks5:// carry credentials too.
_URL_AUTH = re.compile(r'([a-z][a-z0-9+.-]*://)[^/\s]*@', re.IGNORECASE)


def redact_log(text: str, limit: int = 2 * 1024 * 1024) -> str:
    text = _URL_AUTH.sub(r'\1[redacted]@', text)
    text = _AUTH_HEADER.sub(r'\1[redacted]', text)
    text = _ASSIGNMENT.sub(r'\1[redacted]', text)
    text = _BEARER.sub(r'\1[redacted]', text)
    text = _BARE_TOKENS.sub('[redacted]', text)
    return text[-limit:]


def diagnose(config):
    """Public convenience alias, with backend import deferred to avoid a cycle."""
    from .backend import diagnose as backend_diagnose
    return backend_diagnose(config)


def describe_backend_exit(returncode: int, log_tail: str) -> str:
    """Return fixed recovery hints for recognizable native process failures.

    Never interpolate untrusted output into UI errors, reports or telemetry.
    The separately saved bounded analysis.log remains the authoritative trace.
    """
    log = log_tail[-(2 * 1024 * 1024):].casefold()
    if 'path element starting with' in log and 'not permitted' in log:
        hint = ('Ghidra rejected a dot-prefixed path component; use a project and '
                'temporary directory without hidden path components')
    elif 'symbols are disabled, but the symbol is already downloaded' in log:
        hint = ('Ghidriff found a matching PDB in a local symbol location while symbol lookup is '
                'disabled (cached-symbol conflict); PatchTrace isolates Ghidra settings per run, so check '
                'for a PDB beside the analysed binary or enable symbol lookup in Setup')
    elif ('unsupportedclassversionerror' in log or 'class file version' in log
          or 'compiled by a more recent version of the java runtime' in log):
        hint = 'JDK is incompatible with Ghidra or one of its plugins; check the supported Java version'
    elif ("no module named 'ghidriff'" in log or 'no module named ghidriff' in log):
        hint = 'Ghidriff installation is missing from the selected external Python environment'
    elif ('outofmemoryerror' in log or 'java heap space' in log
          or 'gc overhead limit exceeded' in log or 'memoryerror' in log):
        hint = 'Ghidra ran out of memory; check available RAM and Ghidriff JVM settings'
    elif ('no space left on device' in log or 'not enough space on the disk' in log
          or 'disk full' in log):
        hint = 'Insufficient disk space for Ghidra analysis; free space on workspace and project drives'
    elif ('accessdeniedexception' in log or 'permission denied' in log
          or 'access is denied' in log):
        hint = 'Filesystem permissions or locks prevent Ghidra analysis; check writable paths'
    else:
        return f'PT-BACKEND: ghidriff exited with code {returncode}; inspect analysis.log'
    return f'PT-BACKEND: ghidriff exited with code {returncode}; {hint}; inspect analysis.log'
