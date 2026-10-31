"""Client side of the cross-run: builds the artefacts the guide defines.

This is the fixture side, not a receiver. It reads the case definitions
in inputs/cases.json (request part, AAE variant, challenge-response
variant, activation flag) and writes the wire artefacts of spec Sections
6.1 and 6.3 into the exchange directory: a presentation, and, when the
receiver issues a challenge, a challenge response. The AAE variants are
built exactly as guide Section 3 and aae_a2a/testkeys.py define them,
with the published test keys (inputs/test-keys.json). The client never
reads the cases' expect blocks; run.py keeps them for scoring only.

The one thing the guide leaves open is the VC id. This client derives it
deterministically from the case id (uuid5), so the run reproduces. The
iat of the challenge response is the run's frozen instant. Both choices
are logged in findings.md.

Usage:
  python3 client.py presentation CASE_ID EXCHANGE_DIR
  python3 client.py response CASE_ID EXCHANGE_DIR
Standard library only. No network.
"""

import hashlib
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import jose_min
import profile_params as pp

ROOT = Path(__file__).resolve().parent
INPUTS = ROOT / "inputs"

KEYS = json.loads((INPUTS / "test-keys.json").read_text(encoding="utf-8"))["keys"]
SEEDS = {name: bytes.fromhex(entry["ed25519_seed_hex"]) for name, entry in KEYS.items()}
ISSUER = "did:example:issuer"
BUYER = "did:example:buyer"
ISSUER_KID = ISSUER + "#key-1"
BUYER_KID = BUYER + "#key-1"
NOW = datetime(2026, 10, 30, 20, 15, 0, tzinfo=timezone.utc)


def _z(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _case(case_id):
    data = json.loads((INPUTS / "cases.json").read_text(encoding="utf-8"))
    for case in data["cases"]:
        if case["id"] == case_id:
            return case
    raise KeyError(case_id)


def buyer_mandate(actions=("read", "pay")):
    return {
        "actions": list(actions),
        "purpose": "Purchase office supplies on behalf of the principal",
        "scope": "procurement",
        "principal_did": "did:example:principal-acme",
    }


def buyer_constraints(domains):
    return {
        "max_transaction_value": {"value": 500, "currency": "EUR", "required": True},
        "allowed_domains": {"value": list(domains), "required": True},
    }


def build_aae(case):
    variant = case["aae"]
    host = urlparse(pp.AUDIENCE).hostname
    mandate = buyer_mandate()
    constraints = buyer_constraints([host])
    not_before = NOW - timedelta(minutes=5)
    not_after = NOW + timedelta(hours=1)
    if variant == "expired":
        not_before = NOW - timedelta(hours=2)
        not_after = NOW - timedelta(hours=1)
    elif variant == "read_only":
        mandate = buyer_mandate(actions=("read",))
    elif variant == "other_domain":
        constraints = buyer_constraints(["other-supplier.example"])
    vc_id = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "aae-a2a-crossrun/" + case["id"]))
    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://moltrust.ch/contexts/aae/v1"],
        "type": ["VerifiableCredential", "AgentAuthorizationEnvelope"],
        "id": vc_id,
        "issuer": ISSUER,
        "validFrom": _z(not_before),
        "credentialSubject": {
            "id": BUYER,
            "aae": {
                "mandate": mandate,
                "constraints": constraints,
                "validity": {
                    "not_before": _z(not_before),
                    "not_after": _z(not_after),
                    "single_use": False,
                },
            },
        },
    }
    header = {"alg": "EdDSA", "cty": "aae+json", "kid": ISSUER_KID}
    signer = "mallory" if variant == "forged" else "issuer"
    return jose_min.sign_compact(header, vc, SEEDS[signer]), vc_id


def presentation(case_id, exchange_dir):
    case = _case(case_id)
    case_dir = exchange_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    if case["aae"] == "none":
        payload = {
            "activate": bool(case["activate"]),
            "metadata_present": False,
            "aae": None,
            "ancestor_jws": None,
            "request_part": case["request_part"],
            "aae_id": None,
        }
    else:
        aae, vc_id = build_aae(case)
        payload = {
            "activate": bool(case["activate"]),
            "metadata_present": True,
            "aae": aae,
            "ancestor_jws": None,
            "request_part": case["request_part"],
            "aae_id": vc_id,
        }
    (case_dir / "presentation.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("client wrote presentation for", case_id)


def response(case_id, exchange_dir):
    case = _case(case_id)
    case_dir = exchange_dir / case_id
    challenge = json.loads((case_dir / "challenge.json").read_text(encoding="utf-8"))
    presentation_data = json.loads((case_dir / "presentation.json").read_text(encoding="utf-8"))
    body = challenge["challenge"]
    # Spec 6.3: the client MUST check aud and aae_id before signing.
    if body["aud"] != pp.AUDIENCE:
        raise SystemExit("client refuses to sign: aud mismatch")
    if body["aae_id"] != presentation_data["aae_id"]:
        raise SystemExit("client refuses to sign: aae_id mismatch")
    payload = {
        "nonce": body["nonce"],
        "aud": body["aud"],
        "iat": pp.NOW_ISO,
        "aae_id": body["aae_id"],
    }
    header = {"alg": "EdDSA", "kid": BUYER_KID}
    signer = "mallory" if case["challenge_response"] == "wrong_key" else "buyer"
    jws = jose_min.sign_compact(header, payload, SEEDS[signer])
    (case_dir / "response.json").write_text(
        json.dumps(
            {"task_id": challenge["task_id"], "challenge_response": jws},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print("client wrote challenge response for", case_id)


def main():
    mode, case_id, exchange = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    if mode == "presentation":
        presentation(case_id, exchange)
    elif mode == "response":
        response(case_id, exchange)
    else:
        raise SystemExit("unknown mode " + mode)


if __name__ == "__main__":
    main()
