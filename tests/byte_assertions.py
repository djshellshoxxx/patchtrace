"""Exact byte assertions with bounded diagnostics for large authored fixtures."""
import hashlib

import pytest


def assert_bytes_equal(actual: bytes, expected: bytes) -> None:
    """Compare all bytes; hashes and a small mismatch window explain failures only."""
    if actual != expected:
        offset = next((index for index, (left, right) in enumerate(zip(actual, expected, strict=False))
                       if left != right), min(len(actual), len(expected)))
        start, end = max(0, offset - 8), offset + 9
        pytest.fail(
            f'exact bytes differ: first_difference={offset}; '
            f'actual length={len(actual)} sha256={hashlib.sha256(actual).hexdigest()}; '
            f'expected length={len(expected)} sha256={hashlib.sha256(expected).hexdigest()}; '
            f'context[{start}:{end}] actual={actual[start:end].hex()} expected={expected[start:end].hex()}',
            pytrace=False,
        )
