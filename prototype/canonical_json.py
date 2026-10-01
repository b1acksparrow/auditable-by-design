"""
Deterministic JSON serialization per the paper's specification:
printable ASCII strings, booleans, null, lists, objects with string keys,
integers within interoperable exact range. No floats, no non-ASCII.
"""

import json
import re

SAFE_INT_MIN = -(2**53 - 1)
SAFE_INT_MAX = 2**53 - 1
PRINTABLE_ASCII = re.compile(r'^[\x20-\x7e]*$')


def canonical_encode(obj):
    if obj is None:
        return b'null'
    if isinstance(obj, bool):
        return b'true' if obj else b'false'
    if isinstance(obj, int):
        if not (SAFE_INT_MIN <= obj <= SAFE_INT_MAX):
            raise ValueError(f"integer {obj} outside interoperable exact range")
        return str(obj).encode('ascii')
    if isinstance(obj, str):
        if not PRINTABLE_ASCII.match(obj):
            raise ValueError(f"string contains non-printable-ASCII characters")
        return json.dumps(obj, ensure_ascii=True).encode('ascii')
    if isinstance(obj, list):
        parts = [canonical_encode(item) for item in obj]
        return b'[' + b','.join(parts) + b']'
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys())
        parts = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            if not PRINTABLE_ASCII.match(k):
                raise ValueError(f"key contains non-printable-ASCII characters")
            parts.append(json.dumps(k, ensure_ascii=True).encode('ascii') + b':' + canonical_encode(obj[k]))
        return b'{' + b','.join(parts) + b'}'
    raise TypeError(f"unsupported type: {type(obj)}")
