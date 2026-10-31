"""Minimal compact-JWS helpers for EdDSA only, standard library only.

Shared encoding primitives for the client and the receiver in this run:
base64url, strict JSON parsing that rejects duplicate member names (the
-02 Section 5 step 4 JOSE profile requires it for the challenge response;
this run applies it to both JWS types) and compact signing. No decision
logic lives here. All decisions are in receiver.py.
"""

import base64
import json
import re

import ed25519

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class JoseError(ValueError):
    pass


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    if not isinstance(text, str) or not _B64URL.match(text) or len(text) % 4 == 1:
        raise JoseError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise JoseError("duplicate member name %r" % key)
        out[key] = value
    return out


def strict_json(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JoseError("not UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates)
    except JoseError:
        raise
    except ValueError as exc:
        raise JoseError("not JSON") from exc


def split_compact(jws, max_bytes):
    if not isinstance(jws, str):
        raise JoseError("JWS is not a string")
    if len(jws.encode("utf-8")) > max_bytes:
        raise JoseError("JWS exceeds size bound")
    parts = jws.split(".")
    if len(parts) != 3 or not all(_B64URL.match(p) for p in parts):
        raise JoseError("not a compact JWS with three parts")
    if parts[1] == "":
        raise JoseError("detached payload")
    return parts[0], parts[1], parts[2]


def sign_compact(header, payload, seed32):
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = ed25519.sign(seed32, (h + "." + p).encode("ascii"))
    return h + "." + p + "." + b64url_encode(signature)
