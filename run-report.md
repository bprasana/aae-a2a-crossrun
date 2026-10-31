# Run report: AAE for A2A cross-run, independent receiver

Protocol under test: the AAE extension for A2A v1 (spec/aae-a2a-extension-v1.md) against AAE draft-kroehl-agentic-trust-aae-02, run on the published cross-run cases of MoltyCel/aae-a2a-extension at commit 6c857eeb60a9dac379954f5be5900a10616dfc7b. The cases file as run has SHA-256 9c25d66899fa2b790e3fc51ac83cb9f2fa06f07f896f08b0a2d77c462e4eb99b. The expected results in the cases are the oracle. Nothing in the oracle was changed during the run.

This run is the form Lars Kroehl proposed and Prasanna Bableshwar accepted on Oct 29, 2026: an independent receiver reads the published cases and reports a verdict per case, following CROSSRUN.md. The receiver is untuned. Its verdict logic was written from the profile text and was not adjusted to fit any case. Where a case fails, the failure would stand in this report. None did.

## Implementation and versions

- Implementation: aae-a2a-crossrun 1.0, in this directory, by Prasanna Bableshwar.
- Runtime: Python 3.12.3.
- Dependencies: Python standard library only. No vendor products. The reference implementation was not run and its code was not imported. Its testkeys.py and DID documents are published run inputs and were used as such.
- Parts: a client (client.py) that builds the artefacts guide Section 3 defines, an independent receiver (receiver.py) that decides each case from those artefacts, and a scoring harness (run.py). The three run as separate processes and share only files in exchange/<case>/.
- Two primitives were written for this run because the environment has no cryptography package: a pure-Python Ed25519 (ed25519.py, RFC 8032) and a JCS canonicalizer (jcs.py, RFC 8785). Both were validated against published material before any case ran; see the acceptance criteria.

## The form of the run

CROSSRUN.md defines an interactive run, a live client against a live server over HTTP. This run is offline, and the difference is stated plainly. The client builds the wire artefacts the guide specifies for each case: the AAE as an EdDSA compact JWS under the published test keys, in each named variant, and the challenge response of spec Section 6.3. The receiver then runs the two-stage decision of spec Sections 7.2 and 7.4 on those artefacts, mints the challenge itself between the stages, and reports per Sections 8.2 and 8.3. The supplier skill rule is the one cases.json states. All protocol instants are frozen at 2026-10-30T20:15:00Z so the run reproduces byte for byte.

What this form does not test: the HTTP binding, the A2A SDK, TLS, and the number conversion of spec Section 6.4 as a live protobuf layer would perform it. Section 6.4 is tested only at the digest level, through XR-04 and the Appendix B vectors.

## Inputs

- inputs/cases.json: the thirteen cases XR-01 to XR-13 at the pinned commit.
- inputs/aae-a2a-extension-v1.md and inputs/CROSSRUN.md: the profile and the guide at the same commit.
- inputs/did/: the five published DID documents, loaded locally. did:example is never resolved over the network.
- inputs/test-keys.json and inputs/testkeys.py: the published test keys and variant definitions.
- inputs/request-digest.json: the Section 8.5 vectors, used to validate the digest code before the run.
- All data is published test material. The test keys are derived from public labels and are secrets to no one.

## Results

| Case | Receiver outcome | Verdict | Step | Reason code | Digest | Result |
| --- | --- | --- | --- | --- | --- | --- |
| XR-01 | TASK_STATE_COMPLETED | ACCEPT | | | match | pass |
| XR-02 | TASK_STATE_FAILED | ACCEPT | | | match | pass |
| XR-03 | TASK_STATE_REJECTED | REJECT | 7 | max_transaction_value_exceeded | match | pass |
| XR-04 | TASK_STATE_COMPLETED | ACCEPT | | | match | pass |
| XR-05 | TASK_STATE_COMPLETED | ACCEPT | | | match | pass |
| XR-06 | TASK_STATE_COMPLETED | ACCEPT | | | match | pass |
| XR-07 | TASK_STATE_REJECTED | REJECT | 1 | invalid_signature | match | pass |
| XR-08 | TASK_STATE_REJECTED | REJECT | 3 | expired_not_after | match | pass |
| XR-09 | TASK_STATE_REJECTED | REJECT | 4 | challenge_signature_invalid | match | pass |
| XR-10 | TASK_STATE_REJECTED | REJECT | 6 | action_not_in_mandate | match | pass |
| XR-11 | TASK_STATE_REJECTED | REJECT | 7 | domain_not_in_allowlist | match | pass |
| XR-12 | JSON-RPC error -32008 | | | | | pass |
| XR-13 | JSON-RPC error -32602 | | | aae_missing | | pass |

All thirteen cases pass under the pass rule of guide Section 6. Every rejection also matches the expected step and the expected reason code, which the guide's pass rule does not require; that agreement is recorded here because it is stronger than the rule. Every accepted case carries steps_passed 1 to 7. XR-06's task id differs from XR-01's while their request digests are identical, as Section 8.3 requires: the digest identifies the request, the task id identifies the execution. On XR-02 the skill was invoked and failed, the task ended TASK_STATE_FAILED, and the ACCEPT receipt stands in the record. On every rejection the skill was not invoked. Full per-case detail is in results.json, the receiver's decision log is in exchange/decisions.jsonl, and the per-case records are in records/.

One honesty note. This run was not blind. The expected results are printed in the cases file and in the guide's Section 4 table, and the implementer had read them before building. The client and the receiver never read the expect blocks; that is a property of the code and can be checked in it. The run therefore shows that an independent receiver, built from the profile text, reaches the published outcomes from the artefacts alone. It does not show the expectations are the right ones. That question is handled in findings.md.

## Acceptance criteria, checked one by one

1. The receiver is untuned and decides from the record alone. Pass. receiver.py contains no case id, no variant name and no expected value; it decides from the presentation, the challenge it minted and the challenge response. Its checks are the checks of spec Sections 7.1, 7.2, 7.4 and 7.5, in the spec's order.
2. The signature checks are real. Pass. The Ed25519 code was validated before the run: the public keys it derives from the seeds in inputs/test-keys.json equal the publicKeyJwk values in the published DID documents for issuer and buyer, and a sign and verify round trip passes for mallory, the key with no DID document. XR-07 and XR-09 then fail on signature verification against the DID document keys, not on their variant labels, which the receiver never sees.
3. The request digests are recomputed, not copied. Pass. The JCS code reproduces all four vectors of inputs/request-digest.json, octets and digest, before the run. The receiver then recomputes the digest of every request part itself, and all eleven task-case digests match the published values, including XR-04, the member-order, 120.0 and non-ASCII case.
4. The paired cases stay apart from the record alone. Pass. XR-02's record shows an ACCEPT receipt with steps 1 to 7 and a task in TASK_STATE_FAILED with the skill invoked. XR-03's record shows a REJECT at step 7 and a task in TASK_STATE_REJECTED with the skill not invoked. Neither record borrows the other's state.
5. The run reproduces from a clean directory. Pass. The code and inputs were copied to a fresh empty directory and run there. The resulting results.json was identical to the main run except for the run_at timestamp. SHA-256 of results.json with run_at removed, both runs: 480589f85745ce72f34697e04c7426823fb0e39fc1e9bc8528dc7c84d01b5f0a.

## What was not run

No live exchange against the reference supplier or the reference buyer was run, and the guide's own result-file format (guide Section 6) was not produced: it names the commits of a live client and a live server and a server Agent Card, and this run has neither a live counterpart nor commits to name. findings.md records this as a gap in the reporting form, not filled silently here. Grant evaluation (step 6 with grants) and the delegation chain (step 9) are outside this case set, as guide Section 8 states; the receiver does not claim them.
