import { createPassport, createDelegation, subDelegate, generateKeyPair } from 'agent-passport-system';

export function fixture(taskId) {
  const root = generateKeyPair();
  const make = suffix => createPassport({ agentId: `${taskId}-${suffix}`, agentName: suffix, ownerAlias: 'demo-fixture',
    mission: 'Append a controlled test record', capabilities: ['records:append'],
    runtime: { platform: 'isolated-demo', models: ['scripted'], toolsCount: 1, memoryType: 'persistent' } });
  const parent = make('parent'), child = make('child');
  const first = createDelegation({ delegatedBy: root.publicKey, delegatedTo: parent.keyPair.publicKey,
    // Legacy subDelegate rounds fractional expiry hours down; leave a whole-hour margin.
    scope: ['records:append'], spendLimit: 100, maxDepth: 3, expiresInHours: 2, privateKey: root.privateKey });
  const second = subDelegate({ parentDelegation: first, delegatedTo: child.keyPair.publicKey,
    scope: ['records:append'], spendLimit: 100, privateKey: parent.keyPair.privateKey });
  return { root, parent, child, first, second, gatewayKeys: generateKeyPair() };
}
