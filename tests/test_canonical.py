import pytest

from abd.canonical import CanonicalError, canonical_decode, canonical_encode


def test_roundtrip_and_key_order():
    obj = {'b': [1, 'x', None, True], 'a': {'z': 0, 'y': -5}}
    enc = canonical_encode(obj)
    assert enc == b'{"a":{"y":-5,"z":0},"b":[1,"x",null,true]}'
    assert canonical_decode(enc) == obj


def test_rejects_floats():
    with pytest.raises(CanonicalError):
        canonical_encode({'a': 1.5})


def test_rejects_non_ascii_and_control_chars():
    with pytest.raises(CanonicalError):
        canonical_encode({'a': 'ключ'})
    with pytest.raises(CanonicalError):
        canonical_encode({'a': 'tab\there'})


def test_rejects_out_of_range_integers():
    with pytest.raises(CanonicalError):
        canonical_encode({'a': 2**53})
    assert canonical_encode({'a': 2**53 - 1}) == b'{"a":9007199254740991}'


def test_rejects_non_string_keys_and_unknown_types():
    with pytest.raises(CanonicalError):
        canonical_encode({1: 'a'})
    with pytest.raises(CanonicalError):
        canonical_encode({'a': b'bytes'})


def test_decode_rejects_non_canonical_input():
    with pytest.raises(CanonicalError):
        canonical_decode(b'{"b":1,"a":2}')
    with pytest.raises(CanonicalError):
        canonical_decode(b'{ "a": 1 }')


def test_mixed_key_types_raise_canonical_error():
    with pytest.raises(CanonicalError):
        canonical_encode({1: 'a', 'b': 2})


def test_trailing_newline_is_outside_the_value_space():
    with pytest.raises(CanonicalError):
        canonical_encode({'a': 'x\n'})
    with pytest.raises(CanonicalError):
        canonical_encode({'x\n': 1})
