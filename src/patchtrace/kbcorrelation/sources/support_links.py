"""Bounded inert extraction of file-information links from explicitly saved support HTML.

This module never follows links, resolves DNS, trusts HTML base tags or executes
document content. Saved bytes remain unverified local data, even with a Microsoft
page URL. Every retained href has an acceptance decision and fixed rejection code.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser

from ..contracts import domain_id
from .cvrf import SourceError
from .inventory_http import MAX_URL, resolve_url, validate_url

PARSER_VERSION = 1
_FILE = re.compile(r'\bfile\s+information\b', re.IGNORECASE)
_DOWNLOAD = re.compile(r'\bdownload\b', re.IGNORECASE)
_SSU = re.compile(r'\b(?:ssu|servicing[\s-]+stack)\b', re.IGNORECASE)
_HASH = re.compile(r'\b(?:hash(?:es)?|checksums?|sha[\s-]?(?:1|256|384|512))\b', re.IGNORECASE)
_VOID = frozenset({'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
                   'param', 'source', 'track', 'wbr'})
_BLOCK = frozenset({'p', 'li', 'tr', 'td', 'th', 'figcaption', 'dd', 'dt', 'div', 'section', 'article',
                    'h1', 'h2', 'h3', 'h4', 'h5', 'h6'})
_INERT = frozenset({'script', 'style', 'template', 'noscript'})


@dataclass(frozen=True, slots=True)
class LinkLimits:
    max_bytes: int = 4 * 1024 * 1024
    max_links: int = 1000
    max_depth: int = 128
    max_nodes: int = 100000
    max_text: int = 1024
    max_context: int = 4096
    max_seconds: int = 10

    def __post_init__(self):
        ceilings = (4 * 1024 * 1024, 1000, 128, 100000, 1024, 4096, 10)
        for item, ceiling in zip(dataclasses.fields(self), ceilings, strict=True):
            value = getattr(self, item.name)
            if type(value) is not int or not 0 < value <= ceiling:
                raise SourceError('PT-KBC-INPUT', 'saved HTML limits must be positive and within hard ceilings')


DEFAULT_LIMITS = LinkLimits()


@dataclass(frozen=True, slots=True)
class FileInformationLink:
    link_id: str
    index: int
    original_href: str
    url: str | None
    text: str
    context: str
    accepted: bool
    reason: str | None


@dataclass(frozen=True, slots=True)
class LinkExtraction:
    page_url: str
    raw_sha256: str
    raw_size: int
    encoding: str
    links: tuple[FileInformationLink, ...]
    scanned_links: int
    truncated: bool
    authenticity: str = 'unverified-local-file'

    def as_dict(self) -> dict:
        return json.loads(json.dumps(dataclasses.asdict(self), ensure_ascii=True, allow_nan=False))


@dataclass
class _Text:
    cap: int
    chunks: list[str] = field(default_factory=list)
    size: int = 0
    overflow: bool = False
    unsafe: bool = False

    def add(self, value):
        if any(unicodedata.category(char) in ('Cc', 'Cf') and char not in '\t\r\n' for char in value):
            self.unsafe = True
        left = self.cap - self.size
        if len(value) > left:
            self.overflow = True
        if left:
            self.chunks.append(value[:left])
            self.size += min(len(value), left)

    def text(self):
        value = ''.join(self.chunks)
        value = ''.join('\ufffd' if unicodedata.category(char) in ('Cc', 'Cf') and char not in '\t\r\n'
                        else char for char in value)
        return ' '.join(value.split())


@dataclass
class _Draft:
    index: int
    href: str
    text: _Text
    block: _Text
    heading: str
    heading_limited: bool
    heading_unsafe: bool
    reason: str | None = None


@dataclass
class _Frame:
    tag: str
    ignored: bool
    block: _Text | None = None
    link: _Draft | None = None


class _LinkLimit(Exception):
    pass


class _Parser(HTMLParser):
    def __init__(self, limits, cancel, deadline):
        super().__init__(convert_charrefs=True)
        self.limits, self.cancel, self.deadline = limits, cancel, deadline
        self.frames = []
        self.blocks = [_Text(limits.max_context)]
        self.rows = []
        self.headings = {}
        self.links = []
        self.active = None
        self.scanned = self.nodes = 0
        self.truncated = False

    def guard(self):
        if self.cancel is not None and self.cancel.is_set():
            raise SourceError('PT-KBC-CANCEL', 'saved HTML parsing was cancelled')
        if time.monotonic() >= self.deadline:
            raise SourceError('PT-KBC-LIMIT', 'saved HTML parsing exceeded its time limit')

    def _event(self):
        self.guard()
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise SourceError('PT-KBC-LIMIT', 'saved HTML exceeds the markup event limit')

    def _ignored(self):
        return bool(self.frames and self.frames[-1].ignored)

    def handle_starttag(self, tag, attrs):
        self._event()
        ignored = self._ignored() or tag in _INERT
        frame = _Frame(tag, ignored)
        if tag not in _VOID:
            if len(self.frames) >= self.limits.max_depth:
                raise SourceError('PT-KBC-LIMIT', 'saved HTML exceeds the nesting limit')
            self.frames.append(frame)
        if ignored:
            return
        if tag in _BLOCK:
            frame.block = _Text(self.limits.max_context)
            self.blocks.append(frame.block)
            if tag == 'tr':
                self.rows.append(frame.block)
            elif tag in ('td', 'th') and self.rows:
                self.rows[-1].add(' ')
        if tag in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
            self.headings = {level: text for level, text in self.headings.items() if level < int(tag[1])}
        if tag == 'br':
            self.handle_data(' ')
        if tag != 'a':
            return
        hrefs = [value for key, value in attrs if key == 'href']
        if not hrefs:
            return
        self.scanned += 1
        if self.scanned > self.limits.max_links:
            self.truncated = True
            # The rest of an open paragraph could change an earlier decision.
            for block in self.blocks:
                block.overflow = True
            raise _LinkLimit
        href = hrefs[0] if hrefs[0] is not None else ''
        if len(href) > MAX_URL:
            raise SourceError('PT-KBC-LIMIT', 'saved HTML contains an overlong link URL')
        nested = self.active is not None
        if nested:
            self.active.reason = 'ambiguous-markup'
        headings = tuple(self.headings[level] for level in sorted(self.headings))
        draft = _Draft(self.scanned, href, _Text(self.limits.max_text), self.rows[-1] if self.rows else self.blocks[-1],
                       ' '.join(text.text() for text in headings), any(text.overflow for text in headings),
                       any(text.unsafe for text in headings))
        if len(hrefs) != 1:
            draft.reason = 'ambiguous-href'
        elif nested:
            draft.reason = 'ambiguous-markup'
        frame.link = self.active = draft
        self.links.append(draft)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        self._event()
        index = next((i for i in range(len(self.frames) - 1, -1, -1) if self.frames[i].tag == tag), None)
        if index is None:
            return
        for frame in reversed(self.frames[index:]):
            if frame.link is self.active and self.active is not None:
                if frame.tag != tag:
                    self.active.reason = self.active.reason or 'incomplete-anchor'
                self.active = None
            if frame.block is not None:
                self.blocks.pop()
                if frame.tag == 'tr':
                    self.rows.pop()
                if frame.tag in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
                    self.headings[int(frame.tag[1])] = frame.block
        del self.frames[index:]

    def handle_data(self, data):
        self._event()
        if self._ignored():
            return
        self.blocks[-1].add(data)
        if self.rows and self.rows[-1] is not self.blocks[-1]:
            self.rows[-1].add(data)
        if self.active is not None:
            self.active.text.add(data)

    def handle_comment(self, _data):
        self._event()

    def handle_decl(self, _decl):
        self._event()

    def handle_pi(self, _data):
        self._event()

    def unknown_decl(self, _data):
        raise SourceError('PT-KBC-SOURCE', 'saved HTML contains an unsupported declaration')

    def finish(self):
        if self.active is not None:
            self.active.reason = self.active.reason or 'incomplete-anchor'
        self.guard()


def _link(draft, page_url, digest, limits):
    text, local = draft.text.text(), draft.block.text()
    full_context = ' '.join(part for part in (draft.heading, local) if part)
    context = full_context[:limits.max_context]
    reason, target = draft.reason, None
    if reason is None and (draft.text.overflow or draft.block.overflow or draft.heading_limited
                           or len(full_context) > limits.max_context):
        reason = 'context-limit'
    if reason is None and (draft.text.unsafe or draft.block.unsafe or draft.heading_unsafe):
        reason = 'unsafe-text'
    combined = text + ' ' + context
    if reason is None:
        if _SSU.search(combined):
            reason = 'servicing-stack'
        elif _HASH.search(combined):
            reason = 'hash-list'
        elif not (_FILE.search(text) or (_FILE.search(local) and _DOWNLOAD.search(text))):
            reason = 'unrelated'
    try:
        target = resolve_url(page_url, draft.href, kind='file-inventory')
    except SourceError:
        reason = reason or 'invalid-url'
    identity = domain_id('kbc.inventory-link', 1, {'raw_sha256': digest, 'page_url': page_url, 'index': draft.index})
    return FileInformationLink(identity, draft.index, draft.href, target, text, context, reason is None, reason)


def extract_links(raw: bytes, *, page_url: str, cancel=None, limits: LinkLimits = DEFAULT_LIMITS) -> LinkExtraction:
    """Parse bounded UTF-8 saved HTML and retain each scanned href with a decision.

    Context comprises the enclosing paragraph/list cell/block plus current section
    headings, including text after the anchor. Truncated/unsafe context never
    produces an accepted link. Link-count truncation is explicit; structural,
    byte, URL-length and time limits fail atomically.
    """
    if cancel is not None and cancel.is_set():
        raise SourceError('PT-KBC-CANCEL', 'saved HTML parsing was cancelled')
    if type(limits) is not LinkLimits:
        raise SourceError('PT-KBC-INPUT', 'saved HTML requires explicit bounded link limits')
    limits.__post_init__()
    deadline = time.monotonic() + limits.max_seconds
    validate_url(page_url, kind='support-page')
    if type(raw) is not bytes:
        raise SourceError('PT-KBC-INPUT', 'saved HTML must be bytes')
    if len(raw) > limits.max_bytes:
        raise SourceError('PT-KBC-LIMIT', 'saved HTML exceeds its byte limit')
    if any(value < 32 and value not in (9, 10, 13) for value in raw):
        raise SourceError('PT-KBC-SOURCE', 'saved HTML contains forbidden control bytes')
    encoding = 'utf-8-sig' if raw.startswith(b'\xef\xbb\xbf') else 'utf-8'
    try:
        text = raw.decode(encoding, errors='strict')
    except UnicodeError:
        raise SourceError('PT-KBC-SOURCE', 'saved HTML is not valid UTF-8') from None
    digest = hashlib.sha256(raw).hexdigest()
    parser = _Parser(limits, cancel, deadline)
    try:
        for start in range(0, len(text), 32 * 1024):
            parser.guard()
            parser.feed(text[start:start + 32 * 1024])
        parser.close()
    except _LinkLimit:
        pass
    except (ValueError, AssertionError, RecursionError):
        raise SourceError('PT-KBC-SOURCE', 'saved HTML contains malformed markup') from None
    parser.finish()
    rows = []
    for draft in parser.links:
        parser.guard()
        rows.append(_link(draft, page_url, digest, limits))
    return LinkExtraction(page_url, digest, len(raw), encoding, tuple(rows), parser.scanned, parser.truncated)
