"""Export options shared by the CLI and the dialog view-model (SPEC-50 section 8): conflicts are errors, never ignored."""
from __future__ import annotations

from dataclasses import dataclass

from .inputs import RedactionProfile


@dataclass(frozen=True)
class ExportOptions:
    report_version: int
    profile: RedactionProfile
    include_code: bool
    include_notes: bool


def resolve(*, report_version: int = 1, profile: str = 'local', include_code: bool = False,
            include_notes: bool | None = None, urls: str | None = None,
            include_ordinal_index: bool = False) -> ExportOptions:
    """`include_notes=None` means "the default of the profile" (on for local, off for share). Raises ValueError."""
    if report_version not in (1, 2):
        raise ValueError('--report-version must be 1 or 2')
    if report_version == 1 and (profile != 'local' or urls is not None or include_ordinal_index):
        raise ValueError('--profile share, --urls and --include-ordinal-index need --report-version 2')
    if profile == 'share':
        if include_code:
            raise ValueError('the share profile excludes code; drop --include-code or use --profile local')
        if include_notes:
            raise ValueError('the share profile excludes notes; drop --include-notes or use --profile local')
        if urls == 'text':
            raise ValueError('the share profile writes web addresses defanged or removed, not as plain text')
        chosen = RedactionProfile.share(include_ordinal_index)
        if urls is not None:
            chosen = RedactionProfile('share', urls, include_ordinal_index)
        return ExportOptions(2, chosen, False, False)
    notes = True if include_notes is None else include_notes
    if report_version == 1:
        return ExportOptions(1, RedactionProfile(), include_code, notes)
    return ExportOptions(2, RedactionProfile('local', urls or 'text', include_ordinal_index), include_code, notes)
