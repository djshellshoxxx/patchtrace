"""Query grammar and the only path from user text to SQL (WB1 section 7 'Query grammar', trap 1).

`parse_query` turns text into a `QueryPlan` or raises `PT-SEARCH-QUERY` with a hint; nothing is guessed.
Only the `match_*` builders turn a plan into FTS5 `MATCH` strings: every term is a double-quoted phrase (inner
quotes doubled), column filters come from a fixed allow-list, and values are bound as parameters. There is
no `LIKE`/`GLOB` anywhere [F7], and no raw user text ever reaches the FTS5 expression language [F6].
"""
from __future__ import annotations

import re
import unicodedata
from typing import get_args

from patchtrace.search.contracts import (
    IdentityTerm,
    InField,
    IsValue,
    Mode,
    QueryPlan,
    Scope,
    SearchKind,
    Side,
    Term,
)
from patchtrace.search.limits import DEFAULT_LIMITS, SearchLimits
from patchtrace.search.normalize import clean_query_text, fold, query_error

TABLE_COLUMNS = {'fts_name': ('raw', 'words'), 'tri_name': ('name',), 'fts_code': ('body', 'idents'),
                 'fts_text': ('title', 'body')}
_FILTERS: dict[str, tuple[str, ...]] = {
    'kind': get_args(SearchKind), 'side': get_args(Side), 'in': get_args(InField),
    'scope': get_args(Scope), 'is': get_args(IsValue)}
_MIN_PREFIX = 2
_IDENTITY = (
    ('sha256', re.compile(r'[0-9a-fA-F]{64}')),
    ('guid', re.compile(r'\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?')),
    ('cve', re.compile(r'(?i)cve-[0-9]{4}-[0-9]{4,7}')),
    ('kb', re.compile(r'(?i)kb[0-9]{6,8}')),
    ('cwe', re.compile(r'(?i)cwe-[0-9]{1,5}')),
    ('module', re.compile(r'(?i)[a-z0-9_.-]{1,64}\.(?:sys|dll|exe|ocx|drv|efi|cpl|mui)')),
)
_HEX = re.compile(r'0[xX]([0-9a-fA-F]{1,16})')
_BARE_HEX = re.compile(r'(?=[0-9a-fA-F]*[0-9])[0-9a-fA-F]{5,16}')
_DECIMAL = re.compile(r'[0-9]{1,20}')


def _searchable(text: str) -> bool:
    """True when the tokenizers would produce at least one token (letters, numbers, private use)."""
    return any(unicodedata.category(char)[0] in 'LN' or unicodedata.category(char) == 'Co' for char in text)


def _scan(text: str) -> list[tuple[str, bool]]:
    """Split on whitespace; a `"` opens a phrase only at the start of a word and must close before whitespace."""
    tokens: list[tuple[str, bool]] = []
    i, size = 0, len(text)
    while i < size:
        if text[i] == ' ':
            i += 1
        elif text[i] == '"':
            end = text.find('"', i + 1)
            if end < 0:
                raise query_error('unbalanced quote: close the phrase with a second "')
            if end + 1 < size and text[end + 1] != ' ':
                raise query_error('text directly after a closing quote: separate words with a space')
            tokens.append((text[i + 1:end], True))
            i = end + 1
        else:
            end = text.find(' ', i)
            end = size if end < 0 else end
            if '"' in text[i:end]:
                raise query_error('a quote can only start a word: put a space before it')
            tokens.append((text[i:end], False))
            i = end
    return tokens


def _integer(token: str) -> int | None:
    hexed, decimal = _HEX.fullmatch(token), _DECIMAL.fullmatch(token)
    if hexed:
        return int(hexed.group(1), 16)
    if decimal and int(token) < 1 << 64:
        return int(token)
    return int(token, 16) if _BARE_HEX.fullmatch(token) else None


def _alternates(token: str) -> tuple[str, ...]:
    value = _integer(token)
    if value is None or value < 16:
        return ()
    return tuple(sorted({f'0x{value:x}', str(value)} - {token.casefold()}))


def _identity(token: str) -> IdentityTerm | None:
    for kind, pattern in _IDENTITY:
        if pattern.fullmatch(token):
            value = token.strip('{}').lower() if kind in ('sha256', 'guid', 'module') else token.upper()
            return IdentityTerm(kind=kind, value=value)
    return _address(token)


def _address(token: str) -> IdentityTerm | None:
    """`0x140001a40`, bare hex of >= 5 digits with a digit among them, or a decimal of >= 5 digits."""
    hexed = _HEX.fullmatch(token)
    digits = hexed.group(1) if hexed else token
    if len(digits) < 5 or not any(char.isdigit() for char in digits):
        return None
    value = _integer(token)
    return None if value is None else IdentityTerm(kind='address', value=f'0x{value:x}')


def _filter(token: str) -> tuple[str, str] | None:
    key, sep, value = token.partition(':')
    if not sep or key.lower() not in _FILTERS:
        return None  # an unknown `key:` stays text, so `std::vector` works
    value = value.lower()
    if value not in _FILTERS[key.lower()]:
        raise query_error(f'{key.lower()}: expects one of {", ".join(_FILTERS[key.lower()])}')
    return key.lower(), value


def _word(token: str, what: str) -> str:
    if not _searchable(token):
        raise query_error(f'{what} has no letters or digits to search for')
    return token


def parse_query(text: str, *, mode: Mode = 'auto', limits: SearchLimits = DEFAULT_LIMITS) -> QueryPlan:
    if len(text) > 4 * limits.query_chars:
        raise query_error(f'the query is longer than {limits.query_chars} characters')
    text = clean_query_text(text)
    if len(text) > limits.query_chars:
        raise query_error(f'the query is longer than {limits.query_chars} characters')
    terms: list[Term] = []
    phrases: list[str] = []
    excludes: list[str] = []
    filters: dict[str, set[str]] = {key: set() for key in _FILTERS}
    identity: dict[tuple[str, str], IdentityTerm] = {}
    last_plain = False  # the last positive token is an ordinary word (implicit prefix candidate)
    for token, quoted in _scan(text):
        if quoted:
            phrases.append(' '.join(_word(token, 'a quoted phrase').split()))
            last_plain = False
        elif token.startswith('-') and len(token) > 1:
            if '*' in token:
                raise query_error('an excluded word cannot carry a wildcard')
            excludes.append(_word(token[1:], 'an exclusion'))
        elif (parsed := _filter(token)) is not None:
            filters[parsed[0]].add(parsed[1])
        else:
            star = token.endswith('*') and token.count('*') == 1
            if '*' in token and not star:
                raise query_error('* is only allowed once, at the end of a word (word*)')
            body = _word(token[:-1] if star else token, 'a word')
            if star and len(body) < _MIN_PREFIX:
                raise query_error(f'a prefix needs at least {_MIN_PREFIX} characters before *')
            found = None if star else _identity(body)
            if found:
                identity[(found.kind, found.value)] = found
            alt = () if star else _alternates(body)
            terms.append(Term(nfc=body, fold=fold(body), prefix=star, alt=alt))
            last_plain = not star and not found and not alt and len(body) >= _MIN_PREFIX
    if not (terms or phrases):
        if excludes:
            raise query_error('an exclusion needs a positive word to exclude from')
        if not (filters['kind'] or filters['is']):
            raise query_error('empty query: type a word, or browse with kind: or is: (for example kind:string)')
    if len(terms) + len(phrases) > limits.query_terms:
        raise query_error(f'more than {limits.query_terms} words and phrases')
    if len(excludes) > limits.query_excludes:
        raise query_error(f'more than {limits.query_excludes} excluded words')
    return QueryPlan(
        text=text, terms=tuple(terms), phrases=tuple(phrases), excludes=tuple(excludes),
        last_prefix=mode == 'auto' and last_plain,
        kinds=tuple(sorted(filters['kind'])), sides=tuple(sorted(filters['side'])),
        scope='changed' if 'changed' in filters['scope'] else 'indexed',
        is_=tuple(sorted(filters['is'])), in_=tuple(sorted(filters['in'])), mode=mode,
        identity=tuple(identity[key] for key in sorted(identity)))


def _quoted(text: str) -> str:
    return '"' + text.replace('"', '""') + '"'


def _term_expression(term: Term, *, folded: bool, prefix: bool) -> str:
    base = _quoted(term.fold if folded else term.nfc) + (' *' if prefix else '')
    if not term.alt:
        return base
    return '(' + ' OR '.join([base, *(_quoted(alt) for alt in term.alt)]) + ')'


def match_words(plan: QueryPlan, table: str, columns: tuple[str, ...] | None = None) -> str | None:
    """FTS5 expression for a word table (`fts_name`, `fts_code`, `fts_text`); None without a positive part.
    Name tables match the NFKC-folded form, text tables the NFC form (compat folding is for names only)."""
    if table not in TABLE_COLUMNS or table == 'tri_name':
        raise ValueError(f'not a word table: {table!r}')
    folded = table == 'fts_name'
    parts = [_term_expression(term, folded=folded, prefix=term.prefix or (plan.last_prefix and i == len(plan.terms) - 1))
             for i, term in enumerate(plan.terms)]
    parts += [_quoted(fold(p) if folded else p) for p in plan.phrases]
    if not parts:
        return None
    expression = ' AND '.join(parts)  # juxtaposition cannot precede a parenthesised group
    if plan.excludes:
        expression = f'({expression}) NOT ({" OR ".join(_quoted(fold(e) if folded else e) for e in plan.excludes)})'
    return _restrict(expression, table, columns)


def match_substring(plan: QueryPlan) -> str | None:
    """FTS5 expression for `tri_name` (literal substring phrases, >= 3 characters each); None when the plan has
    a phrase, an alternate spelling or a fragment the trigram tokenizer cannot index."""
    fragments = [term.fold for term in plan.terms]
    excluded = [fold(e) for e in plan.excludes]
    if not fragments or plan.phrases or any(len(f) < 3 for f in (*fragments, *excluded)):
        return None
    expression = ' AND '.join(_quoted(f) for f in fragments)
    if excluded:
        expression = f'({expression}) NOT ({" OR ".join(_quoted(e) for e in excluded)})'
    return expression


def _restrict(expression: str, table: str, columns: tuple[str, ...] | None) -> str:
    if columns is None:
        return expression
    if not columns or not set(columns) <= set(TABLE_COLUMNS[table]):
        raise ValueError(f'columns {columns!r} are not columns of {table}')
    return '{' + ' '.join(columns) + '} : (' + expression + ')'
