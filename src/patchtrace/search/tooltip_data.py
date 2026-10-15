"""Tooltip text of the search panel as plain data (WB1 section 8). Qt-free and free of `tooltips` imports.

Each value is `(what, why, effect, source, availability)`. The integration owner appends them to
`tooltips.REGISTRY` and `tooltips.TEMPLATES` with `_e(*fields)`:

    REGISTRY.update({key: _e(*fields) for key, fields in search_tooltip_data.ENTRIES.items()})
    TEMPLATES.update({key: _e(*fields) for key, fields in search_tooltip_data.TEMPLATES.items()})

No angle brackets (the registry renders plain text); template fields are `{title}`, `{where}`, `{name}`, `{edits}`,
`{group}` and `{status}`.
"""
from __future__ import annotations

_LOCAL = "Reads only this project's saved data and a local derived index; nothing is uploaded."
_NEEDS = 'Needs an open project.'

ENTRIES: dict[str, tuple[str, str, str, str, str]] = {
    'search.dock': ('Panel that searches names, strings, APIs, code, notes and advisories of this project.',
                    'Find where a word, an API or an identifier appears and how it relates to the changed functions.',
                    'Read-only; opening or closing it changes no project data.', _LOCAL, _NEEDS),
    'search.action': ('Show the search panel and focus the query field.', 'Start a search from the keyboard.',
                      'Shows the dock; nothing is searched until you type.', '', _NEEDS),
    'search.query': ('Words to look for. Quotes match an exact phrase; a leading minus excludes a word.',
                     'Plain words are safe: no pattern language is interpreted.',
                     'Typing searches after a short pause; Enter searches now; Esc clears.', _LOCAL, _NEEDS),
    'search.side': ('Limit results to the older build, the newer build, or both.',
                    'Orientation stays explicit: older and newer are never mixed up.',
                    'Re-runs the search with the chosen side.', '', _NEEDS),
    'search.kinds': ('Choose which kinds of text to search: functions, code, strings, APIs, build facts, advisories, '
                     'notes.', 'Narrow a broad search to the channel you care about.',
                     'Re-runs the search with the chosen kinds.', '', _NEEDS),
    'search.scope': ('Search everything indexed, or only changed functions and added or removed strings.',
                     'Focus on what differs between the builds.', 'Re-runs the search with the chosen scope.', '', _NEEDS),
    'search.mode': ('How words are matched: automatic, whole words, exact name, prefix, substring or similar names.',
                    'Similar names suggests spellings; it never turns a suggestion into a result.',
                    'Re-runs the search with the chosen mode.', '', _NEEDS),
    'search.sort': ('Order of the leads: by relevance, by change, by name or by address.',
                    'Ordering uses categories and counts, never a combined number.',
                    'Re-runs the search; the order is decided before paging.', '', _NEEDS),
    'search.save': ('Save the current query under a name.', 'Re-run a useful question later.',
                    'Stores the query only, never its results.', 'Analyst data in this project.', _NEEDS),
    'search.saved': ('List, run or delete saved searches.', 'Repeat a question without retyping it.',
                     'Running a saved search searches again; deleting adds a tombstone and keeps history.',
                     'Analyst data in this project.', _NEEDS),
    'search.rebuild': ('Rebuild the local search index from the saved project data.',
                       'Use after a project change or if results look incomplete.',
                       'Runs on a background thread; the project is not changed.', _LOCAL, _NEEDS),
    'search.coverage': ('Show which parts of the project are indexed, building, missing or unavailable.',
                        'An empty result only covers what is indexed.', 'Read-only.', _LOCAL, _NEEDS),
    'search.table': ('Leads for the query. Each row is a pointer to evidence, not a finding.',
                     'Compare where a word appears and whether the function changed.',
                     'Selecting a row shows details; Enter goes to the code; Ctrl+C copies the lead.',
                     'Local index plus the live project pairing.', 'Needs results.'),
    'search.detail': ('Why the selected lead ranks here, its pair, change facts, provenance and limits.',
                      'Check where each piece of evidence came from before relying on it.',
                      'Read-only text.', 'Local index plus the live project pairing.', 'Needs a selected row.'),
    'search.goto': ('Open the selected lead in the code pane.', 'Inspect the matching function text.',
                    'Changes the navigator selection; nothing is modified.', '',
                    'Needs a selected row that still matches the project.'),
    'search.other_side': ('Open the counterpart of the selected lead in the other build.',
                          'Compare the same function in the older and newer builds.',
                          'Changes the navigator selection; nothing is modified.', '',
                          'Needs a selected row with a counterpart.'),
    'search.copy': ('Copy the title, location and provenance of the selected lead.',
                    'Paste an auditable pointer into notes or tickets.',
                    'Writes text to the clipboard only (capped at 16 KiB).', '', 'Needs a selected row.'),
}

TEMPLATES: dict[str, tuple[str, str, str, str, str]] = {
    'search.row': ('Lead {title} at {where}.', 'Open it to see why it matched and where it came from.',
                   'Read-only.', 'Local index plus the live project pairing.', ''),
    'search.suggestion': ('Open the function {name} directly ({edits}).', 'Skip the search when you know the name.',
                          'Changes the navigator selection; nothing is modified.', 'Names in the local index.', ''),
    'search.coverage_row': ('Index group {group} is {status}.', 'Results cover only indexed groups.', 'Read-only.',
                            'Local index.', ''),
}
