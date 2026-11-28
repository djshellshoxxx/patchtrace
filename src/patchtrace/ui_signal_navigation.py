"""Validate supported signal locations before changing desktop presentation (P2-NAV-1)."""
from __future__ import annotations

from .enrichment.contracts import EnrichmentError, SourceLocation
from .enrichment.views import validate_location


def reveal_signal_location(window, location: SourceLocation) -> None:
    """Keep unsupported or stale stored excerpts from changing the current view."""
    try:
        if location.representation != 'decompiled':
            raise EnrichmentError('PT-ENRICH-INPUT', 'Signal navigation supports decompiled locations only.')
        match = window.current_match()
        if (match is None or match.run_id != location.run_id
                or not any((function.id, function.run_id, function.artifact_id) ==
                           (location.function_id, location.run_id, location.artifact_id)
                           for function in getattr(match, location.side))):
            raise EnrichmentError('PT-ENRICH-OWNERSHIP', 'Signal location does not belong to the selected pairing.')
        validate_location(window.project, location)
    except EnrichmentError as exc:
        window.show_error(f'Signal location is unavailable ({exc.code}): {exc.message}'[:300])
        return
    if window.mode.currentIndex() != 0:
        window.mode.setCurrentIndex(0)  # rebuilds text-mode offsets that raw modes empty
    window.reveal_lines(location.function_id, location.start_line, location.end_line)
