"""Raw byte representations (Hex, Binary, Base64) over verified artifact bytes.

See docs/specs/byte-representations.md. Pure stdlib, no Qt.
"""
from __future__ import annotations

from .compare import byte_diff_mask
from .formatters import base64_exact, format_base64, format_binary, format_hex
from .paging import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    MIN_PAGE_SIZE,
    PageBytes,
    page_count,
    read_page,
)
from .render import RenderedPage, Representation, render_page
from .scope import (
    DEFAULT_MAX_FUNCTION_LENGTH,
    UNMAPPED_REASON,
    ByteScope,
    FileRangeLike,
    SectionMapLike,
    Segment,
    file_range,
    function_rva,
    whole_file,
)

__all__ = [
    'ByteScope', 'DEFAULT_MAX_FUNCTION_LENGTH', 'DEFAULT_PAGE_SIZE', 'FileRangeLike', 'MAX_PAGE_SIZE',
    'MIN_PAGE_SIZE', 'PageBytes', 'RenderedPage', 'Representation', 'SectionMapLike', 'Segment',
    'UNMAPPED_REASON', 'base64_exact', 'byte_diff_mask', 'file_range', 'format_base64', 'format_binary',
    'format_hex', 'function_rva', 'page_count', 'read_page', 'render_page', 'whole_file',
]
