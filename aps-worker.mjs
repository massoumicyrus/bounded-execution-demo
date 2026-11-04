import { ProxyGateway, attestFloor, loadFloorFromFile, sign, canonicalize, revokeDelegation, verifyDelegation } from 'agent-passport-system';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const packageRoot = resolve(dirname(fileURLToPath(import.meta.resolve('agent-passport-system'))), '../..');
const floor = loadFloorFromFile(resolve(packageRoot, 'values/floor.yaml'));

process.on('message', async ({ id, payload: p }) => {
  try {
    const f = p.fixture;
    if (p.observedAuthority === 'revoked') {
      // Runtime's authority source propagates the ancestor revocation to both signed hops.
      revokeDelegation(f.first.delegationId, f.root.publicKey, 'ancestor revoked', f.root.privateKey);
      revokeDelegation(f.second.delegationId, f.root.publicKey, 'ancestor revoked', f.root.privateKey);
    }
    const delegationStatus = verifyDelegation(f.second);
    const gateway = new ProxyGateway({ gatewayId: p.gateway, gatewayPublicKey: f.gatewayKeys.publicKey,
      gatewayPrivateKey: f.gatewayKeys.privateKey, floor, recheckRevocationOnExecute: true },
      async () => { throw new Error('Policy worker cannot execute effects'); });
    const passport = f.child.signedPassport;
    const registered = gateway.registerAgent(passport, attestFloor(passport.passport.agentId, f.child.keyPair.publicKey,
      floor.version, [], f.child.keyPair.privateKey), [f.second]);
    if (!registered.registered) throw new Error(registered.error);
    const request = { requestId: p.attempt.attemptId, agentId: passport.passport.agentId, agentPublicKey: f.child.keyPair.publicKey,
      tool: 'APPEND', params: { objectId: p.attempt.objectId, value: p.attempt.value }, scopeRequired: p.attempt.scope,
      delegationId: f.second.delegationId };
    request.signature = sign(canonicalize({ requestId: request.requestId, agentId: request.agentId, tool: request.tool,
      params: request.params, scopeRequired: request.scopeRequired, spend: request.spend }), f.child.keyPair.privateKey);
    const result = gateway.approve(request);
    // APS machine preauthorization is distinct from the separate human approval inbox.
    const raw = result.approved ? { approved: true, decision: result.approval.decision, intent: result.approval.intent }
      : { approved: false, denial: result.denial };
    process.send({ id, value: { request, raw, delegationStatus, chain: [f.first, f.second], rootPublicKey: f.root.publicKey,
      gatewayPublicKey: f.gatewayKeys.publicKey, implementation: 'agent-passport-system@1.46.0 ProxyGateway.approve' } });
  } catch (e) { process.send({ id, error: e.message }); }
});
