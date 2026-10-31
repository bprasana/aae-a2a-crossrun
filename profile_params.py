"""Fixed parameters for this cross-run, shared by the client and the receiver.

NOW is frozen so the run reproduces byte for byte. AUDIENCE is the
audience value of the spec's own Section 4 example card; the published
cases do not fix an audience, so the run had to choose one. That choice
is an invention of this run and is logged in findings.md. The extension
URI and the draft name are from the spec and from cases.json.
"""

NOW_ISO = "2026-10-30T20:15:00Z"
AUDIENCE = "https://supplier.example/a2a/jsonrpc"
EXTENSION_URI = "https://moltrust.ch/extensions/aae/v1"
DRAFT = "draft-kroehl-agentic-trust-aae-02"
RECEIVER_SECRET = b"aae-a2a-crossrun/receiver-test-secret"
