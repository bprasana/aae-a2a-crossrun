"""JSON Canonicalization Scheme (RFC 8785) and the Section 8.5 request digest.

Standard library only. Implements the parts of RFC 8785 the cross-run
inputs exercise: member sorting by UTF-16 code units, the RFC 8785 string
escaping rules (only the quotation mark, the reverse solidus and the
control characters are escaped; non-ASCII passes through), and the
ECMAScript number serialization of RFC 8785 Section 3.2.2.3. Integral
numbers are written without a fraction, as Section 6.4 of the profile
requires (120.0 and 120 have the same digest).

Correctness is not assumed. run.py checks this module against every
vector in inputs/request-digest.json, octets and digest, before any case
is run.
"""

import hashlib
from decimal import Decimal

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _jcs_string(value):
    out = ['"']
    for ch in value:
        code = ord(ch)
        if code in _ESCAPES:
            out.append(_ESCAPES[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(value):
    if isinstance(value, int):
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite numbers have no JCS form")
    if value == int(value) and abs(value) <= 2 ** 53:
        return str(int(value))
    if value == 0:
        return "0"
    dec = Decimal(repr(value))
    sign = "-" if dec < 0 else ""
    dec = abs(dec)
    digits = "".join(str(d) for d in dec.as_tuple().digits)
    k = len(digits)
    n = dec.as_tuple().exponent + k  # value = 0.<digits> * 10**n
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        e = n - 1
        out = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in members) + "}"
    raise TypeError("no JCS form for %r" % type(value))


def request_digest(request_part):
    octets = jcs(request_part).encode("utf-8")
    return "sha256:" + hashlib.sha256(octets).hexdigest()
