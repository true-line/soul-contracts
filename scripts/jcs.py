"""RFC 8785 (JCS) canonicalization and strict JSON parsing for fixture checks.

canonicalize(value) -> bytes: object keys sorted by UTF-16 code units, compact
separators, ECMAScript Number::toString for numbers, JSON.stringify string
escaping, UTF-8 output. Refuses -0, NaN, and infinities (JCS forbids them).

parse_strict(text) -> value: json.loads that refuses duplicate object keys and
the non-JSON constants NaN / Infinity (0.4 section 6: implementations reject
duplicate keys before processing payloads).
"""
import json
import math


def _number(x):
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JCS forbids NaN and infinities")
    if x == 0:
        if math.copysign(1.0, x) < 0:
            raise ValueError("JCS forbids -0")
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))  # shortest round-trip digits, same as ECMAScript
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + exp - lead_zeros  # position of the decimal point relative to digits
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def _string(s):
    return json.dumps(s, ensure_ascii=False)


def _ser(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _number(v)
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, list):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _ser(v[k]) for k in keys) + "}"
    raise TypeError(f"not a JSON value: {type(v).__name__}")


def canonicalize(value):
    return _ser(value).encode("utf-8")


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError(f"non-JSON constant {name}")


def parse_strict(text):
    return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constant)
