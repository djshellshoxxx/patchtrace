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
    'search.saved_name': ('Name this query using 1 to 64 characters.', 'Recognize a saved question later.',
                          'The accepted name and effective query are saved in the current project.',
                          'Project-owned analyst data; results are never stored.', 'Needs the same open project.'),
    'search.saved_run': ('Reparse and run the selected project query.', 'Repeat its mode and physical-side filters.',
                         'Searches again against current project data after checking the saved row still exists.',
                         'Project-owned saved query text and validated mode.', 'Needs a current saved query.'),
    'search.saved_delete': ('Delete the selected saved query from the active list.', 'Remove an unwanted question.',
                            'Appends a project tombstone; previous history is retained and no search runs.',
                            'Project-owned analyst data.', 'Needs a current saved query in this project.'),
    'search.recent': ('Recall recent query text for this user.', 'Reuse text across project sessions.',
                      'Fills the editor in automatic mode without searching; review it and press Enter.',
                      'Per-user settings; at most 20 queries within an 8 KiB serialized budget.',
                      'Needs an open project; this list is not project-owned.'),
    'search.recent_clear': ('Clear this user\'s recent query text.', 'Remove the bounded local history.',
                            'Clears only recent settings; project-owned saved queries remain available.',
                            'Per-user settings.', 'Needs recent query text.'),
}

TIPS: dict[str, TooltipEntry] = {key: TooltipEntry(*fields)
                                 for key, fields in {**tooltip_data.ENTRIES, **_EXTRA}.items()}
TEMPLATES: dict[str, TooltipEntry] = {key: TooltipEntry(*fields) for key, fields in tooltip_data.TEMPLATES.items()}
