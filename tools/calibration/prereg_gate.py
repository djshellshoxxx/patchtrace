"""Fail-closed preregistration selection for Tier R training (LBL-30).

A draft may be inspected with --unlocked-prereg, but its SHA never enters a
training report or masquerades as an owner-approved locked preregistration.
The single-use lock is created separately, only at the explicit final-run gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import prereg


class PreregGateError(ValueError):
    """The requested preregistration is not verifiably locked."""


@dataclass(frozen=True)
class Selection:
    sha: str | None
    verified: bool
    rehearsal_sha: str | None = None


def select(path: Path | None, qa_path: Path, *, allow_unlocked: bool = False, require_signoff: bool = False) -> Selection:
    """Return an approved SHA only if it matches the recorded QA lock row.

    The unlocked path still validates exact LF file bytes, but returns no SHA for
    the training key or report. No test data is opened or evaluated here.
    """
    if require_signoff and allow_unlocked:
        raise PreregGateError("a final locked test cannot use an unlocked rehearsal")
    if path is None:
        if require_signoff:
            raise PreregGateError("the final locked test requires --prereg")
        if allow_unlocked:
            raise PreregGateError("--unlocked-prereg requires --prereg FILE")
        return Selection(None, False)
    try:
        actual = prereg.prereg_sha256(Path(path))
    except (prereg.PreregError, OSError) as exc:
        raise PreregGateError(f"preregistration unreadable or invalid: {exc}") from None
    if allow_unlocked:
        return Selection(None, False, actual)
    try:
        text = Path(qa_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        text = ""
    except (OSError, UnicodeError) as exc:
        raise PreregGateError(f"QA lock record unreadable: {exc}") from None
    recorded = prereg.recorded_sha(text)
    if recorded is None:
        raise PreregGateError(f"no recorded {prereg.QA_ROW} SHA-256 in {qa_path}; use --unlocked-prereg for rehearsal")
    if actual != recorded:
        raise PreregGateError(f"{prereg.QA_ROW} SHA-256 mismatch: preregistration bytes differ from recorded lock")
    if require_signoff:
        approval_tokens = ("owner approved", "owner approval recorded", "owner sign-off approved",
                           "owner signed off")
        approved = any(any(token in row.lower() for token in approval_tokens)
                       for row in text.splitlines() if prereg.QA_ROW in row and actual in row)
        if not approved:
            raise PreregGateError(f"{prereg.QA_ROW} needs owner approval recorded in the matching QA row")
    return Selection(actual, True)
