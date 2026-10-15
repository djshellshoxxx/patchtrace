"""Small diagnostic summaries and bounded log redaction; never dump environment."""
from __future__ import annotations

import re

_ASSIGNMENT = re.compile(
    r'''(?ix)(authorization["']?\s*[:=]\s*["']?\s*(?:(?:bearer|basic)\s+)?|
    (?:api[_-]?key|access[_-]?key|secret[_-]?key|token|password|secret)["']?\s*[:=]\s*)
    (?:"[^"\n]*"|'[^'\n]*'|[^\s,;"']+)'''
)
# Conservative bare credential shapes: GitHub (classic and fine-grained), AWS access key IDs, bearer, sk- keys, Slack.
_BARE_TOKENS = re.compile(
    r'\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b|\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{8,}'
    r'|\bxox[abprs]-[A-Za-z0-9-]{10,}'
)
# Whole header value: schemes such as Token/ApiKey/Digest would otherwise leave the secret visible.
_AUTH_HEADER = re.compile(r'(?i)(\bauthorization["\']?\s*[:=]\s*)[^\r\n]+')
# Same for Cookie and Set-Cookie: every pair is a credential and the attributes after them say nothing worth keeping.
_COOKIE_HEADER = re.compile(r'(?i)(cookie["\']?[ \t]{0,8}:[ \t]{0,64})[^\r\n]+')
_BEARER = re.compile(r'\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}', re.IGNORECASE)
# '://' is the anchor: a pattern that began with the scheme rescanned a long run of letters from every offset (quadratic).
# Greedy to the last '@' before the path: unencoded '@' in a password must not
# leave its tail visible, and proxy schemes such as socks5:// carry credentials too.
_URL_AUTH = re.compile(r'(://)[^/\s]*@')
# Azure SAS signature, percent-encoded base64 in a query string (after the ';' of '&amp;' too). The other SAS fields,
# version, permissions and expiry, are not secret. A '?', '&' or ';' lead keeps 'sig=15' in prose alone.
_SAS_SIGNATURE = re.compile(r'(?i)([?&;]sig=)[^&;#\s"\'<>)]++')
# `--password x`, `--github-token x` and the list form `'--token', 'x'` that str(CalledProcessError) prints. The keyword
# ends the flag, so `--token-file x` and `--max-tokens 5` stay (`--token=x` is an assignment). The lookbehind gives a
# run of dashes one attempt, not one per dash. An unquoted value runs to whitespace, commas included, so a finished
# `[redacted]` from an earlier pass is skipped (not one with text glued to it); a quote that never closes hides the rest.
_ARGV_SECRET = re.compile(
    r'''(?ix)(?<![\w-])(--[a-z0-9_-]{0,24}?(?:api[_-]?key|access[_-]?key|secret[_-]?key|token|password|passwd|secret)
    ["']?(?:[ \t]{1,16}|[ \t]{0,16},[ \t]{0,16}))
    (?:"[^"\r\n]*+"|'[^'\r\n]*+'|(?!\[redacted\](?:[\s,"']|\Z))[^\s"']++|["'][^\r\n]*+)'''
)
# header.payload.signature, each base64url, header and payload starting '{"'. The lookbehind gives a run of 'eyJ' one
# attempt, not one per offset, yet admits an escaped delimiter ('%3DeyJ'); the caps sit far above any real segment.
_JWT = re.compile(
    r'(?:(?<![A-Za-z0-9_-])|(?<=%[0-9A-Fa-f]{2}))'
    r'eyJ[A-Za-z0-9_-]{1,8192}+\.eyJ[A-Za-z0-9_-]{1,65536}+\.[A-Za-z0-9_-]{0,8192}+'
)


def redact_log(text: str, limit: int = 2 * 1024 * 1024) -> str:
    """Hide credentials, then keep the last `limit` characters (last, so a secret is never cut before it is matched).

    Linear on any input: each pattern has a literal or lookbehind anchor and no nested quantifier;
    tests/test_redaction_coverage.py runs hostile one-MiB inputs."""
    if limit < 1:
        raise ValueError('log tail limit must be positive')
    text = _URL_AUTH.sub(r'\1[redacted]@', text)
    text = _AUTH_HEADER.sub(r'\1[redacted]', text)
    text = _COOKIE_HEADER.sub(r'\1[redacted]', text)
    text = _ASSIGNMENT.sub(r'\1[redacted]', text)
    text = _ARGV_SECRET.sub(r'\1[redacted]', text)
    text = _SAS_SIGNATURE.sub(r'\1[redacted]', text)
    text = _BEARER.sub(r'\1[redacted]', text)
    text = _BARE_TOKENS.sub('[redacted]', text)
    text = _JWT.sub('[redacted]', text)
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
