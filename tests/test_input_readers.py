"""Neutral operation capability; no native implementation or package imports."""
import importlib
import pickle
from dataclasses import FrozenInstanceError

import pytest


def api():
    return importlib.import_module('patchtrace.input_readers')


class Reader:
    def check(self, path):
        pass

    def open_reader(self, path):
        raise NotImplementedError

    def __repr__(self):
        return 'private-handle-value'


def test_pair_is_frozen_and_does_not_render_or_serialize_capabilities():
    pair = api().PairInputReaders(Reader(), Reader(), int)
    with pytest.raises(FrozenInstanceError):
        pair.older = Reader()
    assert 'private-handle-value' not in repr(pair)
    with pytest.raises(TypeError, match='serializ'):
        pickle.dumps(pair)


@pytest.mark.parametrize('older,newer,checkpoint', [(None, Reader(), int), (Reader(), None, int),
                                                   (Reader(), Reader(), None), (object(), Reader(), int)])
def test_pair_needs_both_reader_contracts_and_one_callable(older, newer, checkpoint):
    with pytest.raises(api().InputReadError) as caught:
        api().PairInputReaders(older, newer, checkpoint)
    assert caught.value.reason == 'invalid'


@pytest.mark.parametrize('reason', ['cancelled', 'limited', 'changed', 'unavailable', 'invalid'])
def test_read_error_has_a_fixed_bounded_reason_and_core_message(reason):
    error = api().InputReadError(reason)
    assert isinstance(error, ValueError)
    assert error.reason == reason and str(error).startswith('PT-INPUT:')
    assert len(str(error)) < 160


def test_unknown_error_reason_cannot_echo_arbitrary_text():
    with pytest.raises(ValueError) as caught:
        api().InputReadError('secret-token-and-native-handle')
    assert 'secret-token' not in str(caught.value)
