"""Operator registry: every implemented generator by id, and the operators restricted to some toolchain profiles."""
from __future__ import annotations

from .operators import OPERATORS_IMPL as _FIRST_SIXTEEN
from .operators import Operator
from .ops_more import MORE_IMPL

__all__ = ['OPERATORS_IMPL', 'PROFILE_ONLY']

OPERATORS_IMPL: dict[str, Operator] = {**_FIRST_SIXTEEN, **MORE_IMPL}
# `api-use` swaps in mingw/Win32 CRT names, which only the mingw profiles can compile (LBL s7.2).
PROFILE_ONLY: dict[str, tuple[str, ...]] = {'api-use': ('mingw-gcc', 'mingw-clang')}
