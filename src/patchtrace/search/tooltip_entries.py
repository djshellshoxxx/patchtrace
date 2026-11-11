"""Tooltip entries of the search panel as `TooltipEntry` values: the pure `tooltip_data` plus the panel's own extras.
The panel registers them when its controller is built (`gui.tips.register_tips`); nothing here imports Qt."""
from __future__ import annotations

from ..tooltips import TooltipEntry
from . import tooltip_data

_EXTRA = {
    # The shared text says plain words are "safe", which the panel's claims profile rejects.
    'search.query': ('Words to look for. Quotes match an exact phrase; a leading minus excludes a word.',
                     'Plain words are searched as text: no pattern language is interpreted.',
                     'Typing searches after a short pause; Enter searches now; Esc clears.', tooltip_data._LOCAL,
                     tooltip_data._NEEDS),
    'search.cancel': ('Stop the running search or index build.', 'Gives the window back when a query is too slow.',
                      'Cancels background work only; earlier results and the project stay unchanged.',
                      tooltip_data._LOCAL, 'Needs a running search or build.'),
}

TIPS: dict[str, TooltipEntry] = {key: TooltipEntry(*fields)
                                 for key, fields in {**tooltip_data.ENTRIES, **_EXTRA}.items()}
TEMPLATES: dict[str, TooltipEntry] = {key: TooltipEntry(*fields) for key, fields in tooltip_data.TEMPLATES.items()}
