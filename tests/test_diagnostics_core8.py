"""CORE-8: a non-positive tail limit cannot accidentally return the full log."""
import pytest

from patchtrace.diagnostics import redact_log


@pytest.mark.parametrize('limit', [0, -1, -5], ids=['zero', 'minus-one', 'negative'])
def test_core8_redact_log_refuses_nonpositive_limit(limit):
    with pytest.raises(ValueError, match='limit must be positive'):
        redact_log('ordinary log text', limit)


@pytest.mark.parametrize('limit', [1, 8, 1024], ids=['one', 'short', 'long'])
def test_core8_positive_limit_applies_after_redaction(limit):
    text = 'before password=private-value after'
    expected = 'before password=[redacted] after'
    assert redact_log(text, limit) == expected[-limit:]
