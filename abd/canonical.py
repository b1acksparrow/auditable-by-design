"""Deterministic JSON encoding.

The accepted value space is a strict subset of RFC 8785 (JCS): printable-ASCII
strings, booleans, null, integers within the interoperable exact range
[-(2^53-1), 2^53-1], arrays, and objects with printable-ASCII string keys.
Floating-point values, non-ASCII text and non-string keys are rejected rather
than canonicalised.  For this value space the output is byte-identical to JCS
(sorted keys, no whitespace, shortest integer form, JSON string escaping).
"""

import json
import re

SAFE_INT_MIN = -(2**53 - 1)
SAFE_INT_MAX = 2**53 - 1
_PRINTABLE_ASCII = re.compile(r'[\x20-\x7e]*')


class CanonicalError(ValueError):
    pass


def canonical_encode(obj) -> bytes:
    if obj is None:
        return b'null'
    if isinstance(obj, bool):
        return b'true' if obj else b'false'
    if isinstance(obj, int):
        if not (SAFE_INT_MIN <= obj <= SAFE_INT_MAX):
            raise CanonicalError(f"integer {obj} outside interoperable exact range")
        return str(obj).encode('ascii')
    if isinstance(obj, float):
        raise CanonicalError("floating-point values are not permitted in signed statements")
    if isinstance(obj, str):
        if not _PRINTABLE_ASCII.fullmatch(obj):
            raise CanonicalError("string contains characters outside printable ASCII")
        return json.dumps(obj, ensure_ascii=True).encode('ascii')
    if isinstance(obj, (list, tuple)):
        return b'[' + b','.join(canonical_encode(item) for item in obj) + b']'
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise CanonicalError("object keys must be strings")
        parts = []
        for k in sorted(obj.keys()):
            if not _PRINTABLE_ASCII.fullmatch(k):
                raise CanonicalError("key contains characters outside printable ASCII")
            parts.append(json.dumps(k, ensure_ascii=True).encode('ascii') + b':' + canonical_encode(obj[k]))
        return b'{' + b','.join(parts) + b'}'
    raise CanonicalError(f"unsupported type: {type(obj).__name__}")


def canonical_decode(data: bytes):
    """Parse canonical bytes back into Python values and check the round trip."""
    obj = json.loads(data.decode('ascii'))
    if canonical_encode(obj) != data:
        raise CanonicalError("input is not in canonical form")
    return obj
