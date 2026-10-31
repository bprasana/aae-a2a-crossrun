"""Pure-Python Ed25519 (RFC 8032), standard library only.

Written for this cross-run because the environment has no cryptography
package and the v0.1 run's rule was standard library only. Extended
coordinates; one inversion per point decode and none per scalar multiply.

Correctness is not assumed. run.py checks this module before any case is
run: the public keys it derives from the seeds in inputs/test-keys.json
must equal the publicKeyJwk values in the published DID documents
(inputs/did/), and a sign and verify round trip must pass for the key
that has no DID document (mallory).
"""

import hashlib

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_D2 = (2 * _D) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
# Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, T = XY/Z.
_B = (_BX, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _Q
    Bv = (P[1] + P[0]) * (Q[1] + Q[0]) % _Q
    C = _D2 * P[3] * Q[3] % _Q
    Dv = 2 * P[2] * Q[2] % _Q
    E = (Bv - A) % _Q
    F = (Dv - C) % _Q
    G = (Dv + C) % _Q
    H = (Bv + A) % _Q
    return (E * F % _Q, G * H % _Q, F * G % _Q, E * H % _Q)


def _double(P):
    A = P[0] * P[0] % _Q
    Bv = P[1] * P[1] % _Q
    C = 2 * P[2] * P[2] % _Q
    Dv = (-A) % _Q
    E = ((P[0] + P[1]) * (P[0] + P[1]) - A - Bv) % _Q
    G = (Dv + Bv) % _Q
    F = (G - C) % _Q
    H = (Dv - Bv) % _Q
    return (E * F % _Q, G * H % _Q, F * G % _Q, E * H % _Q)


def _scalarmult(P, e):
    Q = _IDENTITY
    while e > 0:
        if e & 1:
            Q = _add(Q, P)
        P = _double(P)
        e >>= 1
    return Q


def _encode_point(P):
    zinv = pow(P[2], _Q - 2, _Q)
    x = P[0] * zinv % _Q
    y = P[1] * zinv % _Q
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decode_point(data):
    if len(data) != 32:
        raise ValueError("point encoding must be 32 bytes")
    bits = int.from_bytes(data, "little")
    y = bits & ((1 << 255) - 1)
    sign = (bits >> 255) & 1
    if y >= _Q:
        raise ValueError("y out of range")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _Q - x
    return (x, y, 1, (x * y) % _Q)


def _clamp(h32):
    a = bytearray(h32)
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return int.from_bytes(a, "little")


def public_key(seed32):
    if len(seed32) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = _clamp(h[:32])
    return _encode_point(_scalarmult(_B, a))


def sign(seed32, message):
    if len(seed32) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = _clamp(h[:32])
    pk = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % _L
    R = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(R + pk + message).digest(), "little") % _L
    S = (r + k * a) % _L
    return R + S.to_bytes(32, "little")


def verify(public32, message, signature):
    if len(public32) != 32 or len(signature) != 64:
        return False
    try:
        A = _decode_point(public32)
        R = _decode_point(signature[:32])
    except ValueError:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public32 + message).digest(), "little") % _L
    left = _scalarmult(_B, S)
    right = _add(R, _scalarmult(A, k))
    # Projective equality: x1*z2 == x2*z1 and y1*z2 == y2*z1 (mod q).
    return (
        (left[0] * right[2] - right[0] * left[2]) % _Q == 0
        and (left[1] * right[2] - right[1] * left[2]) % _Q == 0
    )
