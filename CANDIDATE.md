# Candidate preparation

Submitter: Cyrus Massoumi. Implementation and test runner: Codex acting for Cyrus Massoumi.

Target: the local bounded-execution contract documented in README.md, with an adapter to agent-passport-system 1.46.0. This is not a claim of conformance to the current APS draft or private gateway.

Source: the versioned source commit containing this file. `evidence/run.json` pins the exact implementation and tests by SHA-256. The release archive is also checksummed.

Status: prepared for the owner's review; not submitted to, published by, reviewed by, or admitted to the APS conformance lab.

The fixtures attempt denial bypass across routes and delegation, lost approval state, unsupported completion, causal invalidation, revocation races, and differing revocation knowledge at two isolated policy workers. Reproduction commands and every boundary are in README.md.

Verification split:

- Runtime behavior / actual controlled append and refusals; Codex-run local harness; Mode A; author-produced; this repository's implementation and pinned APS legacy SDK. The harness author also wrote the runtime.
- Evidence bytes and semantics / journal, APS Ed25519 signatures, authority and conditions at commitment, recorded effects and responses; offline verifier; Mode B; author-produced; Node crypto plus separately written checking logic. The verifier author also wrote the runtime and fixture generator.
- Human surface / rendering, exact action presentation, approval submission and subsequent execution; Playwright Chromium at 390 × 844; Mode A; author-produced. Reviewer interaction is automated test input.

These records are attributed per layer. They do not imply independent reproduction, lab acceptance, APS endorsement, or production deployment.

License: original code is Apache-2.0. Dependencies retain their own licenses. The installed APS floor carries its source attribution. No upstream source or floor file is copied into this repository.
