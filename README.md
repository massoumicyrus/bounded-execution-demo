# Bounded execution demonstration

A reusable execution object binds one controlled effect to authority, a runtime-owned turn, prerequisite conditions, inherited agent permissions, human approval, and observed completion.

The demonstration attempts the three failures raised by Tymofii: alternate execution after denial, approval lost during delegation, and success reported without an effect. It also exercises transitive prerequisite invalidation, concurrent attempts, and two isolated APS policy workers with different knowledge after a revocation.

The implementation is an isolated prototype. It does not change MiscSubjects production or Tymofii's gateway, send messages, or submit a contribution to the conformance lab.

## Results

- 26 end-to-end enforcement scenarios pass.
- A real Chromium browser at a 390 × 844 mobile viewport presents an approval, submits the decision, and verifies that the exact action can then execute. This is an automated reviewer fixture, not approval by a real person.
- Three evidence mutations are rejected: missing effects, a rewritten and rehashed effect, and a changed APS request signature.
- Twelve concurrent attempts append one record.
- Eight distinct authorized effects are recorded in the demonstration run. Blocked cases leave their effect absent.
- The offline verifier checks the causal journal, request/response receipts, effect contents, authority and prerequisites at commitment, and APS signatures using Node's crypto implementation. It imports neither the execution runtime nor the APS SDK.

The files under `evidence/` contain the exact recorded run, its summary, test output, and the mobile approval screenshot. `run.json` includes hashes of the source used to produce it. The records are **author-produced**. Running a different verifier written by the same author does not make the evidence independent.

## Run

Requires Node 24 or newer and npm. Tested locally with Node 26.5.0.

```sh
npm ci --ignore-scripts
npm run verify
npx playwright install chromium
npm test
npm run demo
npm run verify
```

`verify` checks the supplied evidence without network access or installed dependencies. `test` starts local services, runs the adversarial scenarios and browser test, then stops the services. `demo` regenerates `evidence/run.json` with fresh ephemeral keys, identifiers, and timestamps. Behavioral expectations repeat; byte-for-byte output is not deterministic.

For an interactive local development server, run `npm start` and open its printed address with `/review` appended. Credentials are generated in `.runtime/secrets.json`, mode 0600. The reviewer credential belongs only in the reviewer input or authenticated test client. The server initially has an empty inbox; `test/review.test.mjs` shows how to create a fixture request. These credentials are never part of the distributed package.

## The six mechanisms

1. **Conditional execution inside the tool.** The runtime validates a call, selects its allowed continuation, obtains an APS preauthorization decision, checks state at the effect, and verifies the resulting record. Unknown states return a bounded result.
2. **A conditional turn lock.** A gateway denial or observed invalid prerequisite locks the execution object for the current turn. Retries, alias tools, child agents, and new request IDs share that lock. Only the administrator can advance a turn. A new turn still requires current authority, prerequisites, and authorization.
3. **Causal dependencies.** Conditions can depend on other conditions. The executor recursively evaluates that declared graph. Invalidating a shared ancestor blocks all dependent actions when attempted; unrelated actions continue. Repairing a condition does not clear an existing lock in the same turn.
4. **An agent invoked as a tool.** `RUN_CHILD` launches a separate scripted process with a narrowed capability over stdin. Its two tool attempts use the same object. The child cannot read the database, spawn a shell through the tested Node API, approve actions, or use administrator endpoints.
5. **Durable approval.** Requests live in SQLite, outside conversational context. They remain in the reviewer inbox across child handoffs and a complete service restart. Presentation and approval are distinct events. Approval binds to an immutable action hash and expires.
6. **Verified completion.** An executor's success-looking return does not set completion. The runtime reads back the effect and checks its content and hash. One fixture exits the executor process after commitment and before its IPC reply. The response is genuinely lost; the runtime reports an unknown outcome, restarts the executor, and reconciles the persisted effect. A retry cannot append it again.

## Execution boundary

The controlled effect is an append to the `effects` table. Each object has one canonical identity derived from its task, verb, and target. Agents cannot create alternative tasks or execution objects. Reusing that identity with a changed value is rejected.

The HTTP service, two APS workers, and effect executor are separate processes. The service and executor share a SQLite database. The executor uses `BEGIN IMMEDIATE` to recheck authority, turn, conditions, scope, expiry, approval, and gateway freshness, then commits the effect and causal event in the same transaction. Administrative revocation and condition updates use that same database. This defines the ordering of concurrent invalidation and execution: a committed earlier effect remains a historical fact; a later execution cannot use invalidated state.

An arbitrary external service would need an equivalent enforcement point or a documented weaker guarantee. A check followed by an unconstrained external call would reopen the gap. This prototype does not provide a distributed transaction across unrelated providers.

## APS integration

The package pins the published **`agent-passport-system@1.46.0` legacy gateway**. It calls the actual `ProxyGateway.approve` implementation using signed requests and a two-hop signed delegation chain. APS machine preauthorization is separate from this prototype's human approval inbox. The APS worker is deliberately unable to execute the controlled effect.

The current accessible SDK version inspected during this work was 8.0.1. Its `ProxyGateway` is a migration stub pointing to `@aeoess/gateway`; that package was unavailable through the accessible registry. This package therefore makes a compatibility claim only for the pinned legacy adapter, not the current private gateway or current APS draft conformance.

In the two-gateway fixture, both workers receive the same signed chain and action. They have separate process-local APS revocation registries. The authority-source outage is deliberately injected: worker A receives propagated ancestor revocation; B retains an active observation. A's APS preauthorization denies. B's raw legacy APS check permits on its stale knowledge, but the adapter classifies its current authority as unknown and refuses dispatch. The shared executor independently blocks the revoked object. This tests the composition and explicit freshness rule; it is not a live distributed network-partition benchmark.

Sources:

```text
APS migration boundary:
https://github.com/aeoess/agent-passport-system/blob/main/MIGRATION.md

APS distinction between decisions and external execution:
https://agent-passport.org/faq.html

Conformance candidate requirements:
https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/main/docs/CANDIDATES.md
```

## API and files

`POST /api/run` accepts `{tool,args}`. `POST /run` is a flat test adapter. `POST /mcp` implements the JSON-RPC `tools/call` surface for this demonstration, including `RUN_CHILD`; it is not a complete MCP transport implementation. Every effect-producing route ends at the same checks. `/agent` is a convenience alias for the scripted child. `/status` reconciles completion. `/human/inbox` and `/human/decide` require the separate reviewer credential. `/admin/*` requires the administrator credential.

- `store.mjs`: object state, conditions, delegation, approval, transactional execution and journal.
- `server.mjs`: authenticated adapters, orchestration, reviewer page and authoritative responses.
- `aps-worker.mjs`: pinned APS preauthorization adapter.
- `executor-worker.mjs`: isolated effect process.
- `child.mjs`: scripted adversarial child.
- `scenarios.mjs`: 26 executable scenarios and raw exchanges with credentials removed.
- `verify.mjs`: standalone offline evidence verifier.
- `test/`: enforcement, browser and evidence-mutation checks.

## Guarantees and limits

The evidence supports the tested routes and declared state transitions inside this boundary. It does not constitute a formal proof over arbitrary programs or every possible execution environment.

- The administrator, reviewer authentication, runtime, database, host clock, and host operating system are trusted. A hostile host administrator could modify both state and code.
- The child is a deterministic adversarial program. Its Node permission checks are useful containment checks, not a claim that Node permissions sandbox arbitrary malicious native code. Network access remains available; the child has no effect-executor or administrator credential.
- Conditions are explicitly registered observations. Automatic discovery of arbitrary environmental causality, external source truth, and continuous monitoring of arbitrary scripts are not implemented.
- The reviewer inbox is durable and browser-tested. External email/push delivery and guaranteed attention by a person are not claimed.
- Authoritative completion responses are evidence-derived. Unrestricted prose from an unrelated model is outside this output boundary.
- SQLite single-effect identity prevents duplicates here. Exactly-once effects across arbitrary external APIs are not claimed.
- The hash-linked journal detects inconsistent edits. Its head is not anchored in an independent external witness.
- The records use generated test identities and public verification keys. Production credentials and private correspondence are excluded.

The contribution demonstrated is the composition of conditional execution, shared state, causal dependencies, inherited authority, durable approval and verified effects. State machines, capability narrowing, revocation, causal graphs, and evidence receipts are established mechanisms. Novelty is not established by this demonstration.
