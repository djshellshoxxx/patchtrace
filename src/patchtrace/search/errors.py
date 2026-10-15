"""Typed search failures (WB1 section 7). `message` is a fixed template, never untrusted text."""
from __future__ import annotations

ERROR_CODES = ('PT-SEARCH-QUERY', 'PT-SEARCH-CAPABILITY', 'PT-SEARCH-INPUT', 'PT-SEARCH-SOURCE', 'PT-SEARCH-STALE',
               'PT-SEARCH-LIMIT', 'PT-SEARCH-STORE', 'PT-SEARCH-LOCATOR', 'PT-SEARCH-TIMEOUT', 'PT-SEARCH-CANCEL')
# enrichment-cli/1 exit codes (section 8): 2 invalid query/arguments or no FTS5, 3 runtime/store, 5 cancelled
EXIT_CODES = {'PT-SEARCH-QUERY': 2, 'PT-SEARCH-CAPABILITY': 2, 'PT-SEARCH-INPUT': 2, 'PT-SEARCH-SOURCE': 3,
              'PT-SEARCH-STALE': 3, 'PT-SEARCH-LIMIT': 3, 'PT-SEARCH-STORE': 3, 'PT-SEARCH-LOCATOR': 3,
              'PT-SEARCH-TIMEOUT': 3, 'PT-SEARCH-CANCEL': 5}
MESSAGE_LIMIT = 400


class SearchError(Exception):
    def __init__(self, code: str, message: str, recoverable: bool = False):
        if code not in ERROR_CODES:
            raise ValueError(f'unknown search error code {code!r}')
        self.code = code
        self.message = str(message)[:MESSAGE_LIMIT]
        self.recoverable = recoverable
        super().__init__(f'{code}: {self.message}')

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]
