import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID, randomBytes } from 'node:crypto';

export const canonical = v => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonical).join(',')}]`
  : `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
export const hash = v => createHash('sha256').update(typeof v === 'string' ? v : canonical(v)).digest('hex');
const id = () => randomUUID();
export class Refusal extends Error { constructor(code) { super(code); this.code = code; } }
const requireThat = (v, code) => { if (!v) throw new Refusal(code); };
export const TOOLS = ['APPEND', 'write_record', 'RUN_CHILD'];

export class Store {
  constructor(path) {
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS data (kind TEXT, id TEXT, body TEXT NOT NULL, PRIMARY KEY(kind,id));
      CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS effects (object_id TEXT PRIMARY KEY, body TEXT NOT NULL);`);
  }
  close() { this.db.close(); }
  get(kind, key) { const r = this.db.prepare('SELECT body FROM data WHERE kind=? AND id=?').get(kind, key); return r && JSON.parse(r.body); }
  all(kind) { return this.db.prepare('SELECT body FROM data WHERE kind=? ORDER BY id').all(kind).map(r => JSON.parse(r.body)); }
  put(kind, key, value) { this.db.prepare('INSERT OR REPLACE INTO data VALUES(?,?,?)').run(kind, key, canonical(value)); }
  tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const r = fn(); this.db.exec('COMMIT'); return r; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  event(type, detail, causes = []) {
    const prev = this.db.prepare('SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1').get();
    const e = { seq: (prev?.seq || 0) + 1, previous: prev?.hash || '0'.repeat(64), at: new Date().toISOString(), type, causes, detail };
    this.db.prepare('INSERT INTO events VALUES(?,?,?)').run(e.seq, canonical(e), hash(e));
    return e.seq;
  }
  createTask(name) {
    return this.tx(() => {
      const t = { id: id(), name, turn: 1, authority: 'active', epoch: 1 };
      this.put('task', t.id, t); this.event('task_created', t); return t;
    });
  }
  createCondition(input) {
    return this.tx(() => {
      const c = { id: id(), name: input.name, state: 'valid', revision: 1, checkedAt: Date.now(), ttlMs: input.ttlMs ?? 3600000, parents: input.parents || [] };
      requireThat(Number.isFinite(c.ttlMs) && c.ttlMs > 0, 'invalid_ttl');
      for (const p of c.parents) requireThat(this.get('condition', p), 'unknown_dependency');
      this.put('condition', c.id, c); this.event('condition_created', c); return c;
    });
  }
  changeCondition(key, state) {
    return this.tx(() => {
      requireThat(['valid','invalid','unknown'].includes(state), 'invalid_state');
      const c = this.get('condition', key); requireThat(c, 'unknown_dependency');
      Object.assign(c, { state, revision: c.revision + 1, checkedAt: Date.now() });
      this.put('condition', key, c); this.event('condition_changed', c); return c;
    });
  }
  changeTask(key, change) {
    return this.tx(() => {
      const t = this.get('task', key); requireThat(t, 'unknown_task');
      requireThat(['next_turn','revoke','unknown','refresh'].includes(change), 'invalid_change');
      if (change === 'next_turn') t.turn++;
      else if (change === 'revoke') { t.authority = 'revoked'; t.epoch++; }
      else if (change === 'unknown') { requireThat(t.authority !== 'revoked', 'revocation_final'); t.authority = 'unknown'; t.epoch++; }
      else { requireThat(t.authority !== 'revoked', 'revocation_final'); t.authority = 'active'; t.epoch++; }
      this.put('task', key, t); this.event('task_changed', { change, ...t }); return t;
    });
  }
  createObject(input) {
    return this.tx(() => {
      requireThat(this.get('task', input.taskId), 'unknown_task');
      requireThat(typeof input.target === 'string' && input.target.length > 0 && input.target.length < 200, 'invalid_target');
      requireThat(typeof input.value === 'string' && input.value.length < 2000, 'invalid_value');
      // Identity is effect-based. Neither new request IDs nor aliases create a new effect.
      const key = hash({ taskId: input.taskId, verb: 'append', target: input.target });
      const exists = this.get('object', key);
      if (exists) { requireThat(exists.value === input.value, 'effect_identity_conflict'); return exists; }
      const o = { id: key, taskId: input.taskId, target: input.target, verb: 'append', value: input.value,
        revision: 1, dependencies: input.dependencies || [], requiresApproval: input.approval === true,
        scope: input.scope || 'records:append', mode: input.mode || 'normal', latch: null, outcome: 'ready' };
      requireThat(['normal','no_effect','drop_response','crash_before_commit'].includes(o.mode), 'invalid_mode');
      for (const d of o.dependencies) requireThat(this.get('condition', d), 'unknown_dependency');
      o.actionHash = hash({ verb: o.verb, target: o.target, value: o.value, revision: o.revision });
      this.put('object', key, o); const cause = this.event('object_created', o);
      if (o.requiresApproval) {
        const a = { id: id(), objectId: key, actionHash: o.actionHash, state: 'pending', delivery: 'pending', deliveryAttempts: 0,
          expiresAt: Date.now() + (input.approvalTtlMs ?? 3600000) };
        requireThat(a.expiresAt > Date.now(), 'invalid_expiry');
        this.put('approval', key, a); this.event('approval_requested', a, [cause]);
      }
      return o;
    });
  }
  mint(objectId, parentId = null, tools = TOOLS) {
    return this.tx(() => {
      requireThat(this.get('object', objectId), 'unknown_object');
      requireThat(Array.isArray(tools) && tools.length > 0 && tools.every(t => TOOLS.includes(t)), 'invalid_tools');
      let expiresAt = Date.now() + 3600000;
      if (parentId) {
        const p = this.get('session', parentId); requireThat(p && p.objectId === objectId, 'invalid_parent');
        this.sessionCheck(p);
        requireThat(tools.every(t => p.tools.includes(t)), 'scope_expansion');
        expiresAt = p.expiresAt;
      }
      const token = randomBytes(32).toString('hex');
      const s = { id: id(), objectId, parentId, tools, expiresAt, tokenHash: hash(token), revoked: false };
      this.put('session', s.id, s);
      this.event('delegated', { id: s.id, objectId, parentId, tools, expiresAt });
      return { id: s.id, token };
    });
  }
  authenticate(token) {
    const s = this.all('session').find(s => s.tokenHash === hash(token || ''));
    requireThat(s, 'unauthenticated'); this.sessionCheck(s); return s;
  }
  sessionCheck(s) {
    const seen = new Set();
    while (s) {
      requireThat(!seen.has(s.id), 'delegation_cycle'); seen.add(s.id);
      requireThat(!s.revoked && s.expiresAt > Date.now(), 'session_revoked_or_expired');
      if (!s.parentId) break;
      const p = this.get('session', s.parentId); requireThat(p && p.objectId === s.objectId && s.tools.every(x => p.tools.includes(x)), 'invalid_parent'); s = p;
    }
  }
  revokeSession(key) {
    return this.tx(() => { const s = this.get('session', key); requireThat(s, 'unknown_session'); s.revoked = true; this.put('session', key, s); this.event('session_revoked', { id: key }); return { revoked: key }; });
  }
  dependencies(o) {
    const found = new Map();
    const visit = key => {
      if (found.has(key)) return;
      const c = this.get('condition', key); requireThat(c, 'unknown_dependency');
      requireThat(c.state === 'valid', `dependency_${c.state}`);
      requireThat(Date.now() - c.checkedAt <= c.ttlMs, 'dependency_stale');
      found.set(key, c.revision); c.parents.forEach(visit);
    };
    o.dependencies.forEach(visit); return Object.fromEntries(found);
  }
  checks(sessionId, objectId, tool, value) {
    requireThat(['APPEND','write_record'].includes(tool), 'unsupported_effect_tool');
    const s = this.get('session', sessionId); requireThat(s, 'unknown_session'); this.sessionCheck(s);
    requireThat(s.objectId === objectId && s.tools.includes(tool), 'scope_denied');
    const o = this.get('object', objectId); requireThat(o, 'unknown_object');
    requireThat(value === o.value, 'arguments_changed');
    const t = this.get('task', o.taskId);
    requireThat(t.authority === 'active', `authority_${t.authority}`);
    requireThat(o.latch?.turn !== t.turn, 'turn_locked');
    const deps = this.dependencies(o);
    const a = this.get('approval', objectId);
    if (o.requiresApproval) {
      requireThat(a && a.actionHash === o.actionHash, 'approval_mismatch');
      requireThat(a.state === 'approved', `approval_${a.state}`);
      requireThat(a.expiresAt > Date.now(), 'approval_expired');
    }
    return { o, t, deps, a, s };
  }
  prepare(sessionId, objectId, tool, value, route) {
    return this.tx(() => {
      const attemptId = id(); const invocation = { attemptId, sessionId, objectId, tool, value, route };
      const cause = this.event('invoked', invocation);
      try {
        const { o, t, deps } = this.checks(sessionId, objectId, tool, value);
        const attempt = { ...invocation, turn: t.turn, epoch: t.epoch, revision: o.revision, actionHash: o.actionHash, deps, cause, state: 'prepared', scope: o.scope };
        this.put('attempt', attemptId, attempt); this.event('prepared', attempt, [cause]); return attempt;
      } catch (e) {
        if (!(e instanceof Refusal)) throw e;
        if (e.code.startsWith('dependency_')) this.lockDependency(objectId, e.code, cause);
        this.event('refused', { ...invocation, reason: e.code }, [cause]); return { denied: true, reason: e.code, attemptId };
      }
    });
  }
  lockDependency(objectId, reason, cause) {
    const o = this.get('object', objectId), t = this.get('task', o.taskId);
    o.latch = { turn: t.turn, reason, cause }; this.put('object', objectId, o);
    this.event('turn_locked', { objectId, ...o.latch }, [cause]);
  }
  recordGateway(attempt, record) {
    return this.tx(() => {
      const a = this.get('attempt', attempt.attemptId); requireThat(a?.state === 'prepared', 'attempt_not_prepared');
      a.gateway = record; a.state = record.effective === 'permit' ? 'authorized' : 'denied';
      a.gatewayCause = this.event('gateway_decided', { attemptId: a.attemptId, record }, [a.cause]);
      this.put('attempt', a.attemptId, a);
      if (record.effective === 'deny') {
        const o = this.get('object', a.objectId); o.latch = { turn: a.turn, reason: record.reason, cause: a.gatewayCause };
        this.put('object', o.id, o); this.event('turn_locked', { objectId: o.id, ...o.latch }, [a.gatewayCause]);
      }
      return a;
    });
  }
  inbox(delivered = false) {
    return this.tx(() => this.all('approval').filter(a => a.state === 'pending').map(a => {
      if (delivered) { a.delivery = 'presented'; a.deliveryAttempts++; this.put('approval', a.objectId, a); this.event('approval_presented', a); }
      const o = this.get('object', a.objectId); return { ...a, target: o.target, value: o.value };
    }));
  }
  decideApproval(objectId, actionHash, decision) {
    return this.tx(() => {
      const a = this.get('approval', objectId); requireThat(a && a.actionHash === actionHash, 'approval_mismatch');
      requireThat(a.state === 'pending' && a.expiresAt > Date.now(), 'approval_not_pending_or_expired');
      requireThat(a.delivery === 'presented', 'approval_not_presented');
      requireThat(['approved','denied'].includes(decision), 'invalid_decision');
      a.state = decision; this.put('approval', objectId, a); this.event('approval_decided', a); return a;
    });
  }
  effect(objectId) { const r = this.db.prepare('SELECT body FROM effects WHERE object_id=?').get(objectId); return r && JSON.parse(r.body); }
  commit(attemptId) {
    return this.tx(() => {
      const a = this.get('attempt', attemptId); requireThat(a?.state === 'authorized', 'attempt_not_authorized');
      try {
        const { o, t, deps, a: approval } = this.checks(a.sessionId, a.objectId, a.tool, a.value);
        requireThat(t.turn === a.turn && t.epoch === a.epoch && o.revision === a.revision && canonical(deps) === canonical(a.deps), 'stale_authorization');
        requireThat(Date.now() - a.gateway.checkedAt <= 5000 && a.gateway.effective === 'permit', 'stale_gateway');
        const prior = this.effect(o.id);
        if (prior) { this.event('effect_reused', { attemptId, objectId: o.id, effectHash: prior.effectHash }, [prior.cause, a.gatewayCause]); return { accepted: true, reused: true }; }
        if (o.mode === 'crash_before_commit') throw new Error('injected_executor_failure');
        if (o.mode === 'no_effect') { this.event('executor_returned_without_effect', { attemptId, objectId: o.id }, [a.gatewayCause]); return { accepted: true, reported: 'success' }; }
        const effect = { objectId: o.id, target: o.target, value: o.value, actionHash: o.actionHash, attemptId, turn: t.turn,
          authorityEpoch: t.epoch, dependencies: deps, approvalId: approval?.id || null, at: new Date().toISOString() };
        effect.effectHash = hash(effect);
        effect.cause = this.event('effect_committed', effect, [a.gatewayCause]);
        this.db.prepare('INSERT INTO effects VALUES(?,?)').run(o.id, canonical(effect));
        a.state = 'committed'; this.put('attempt', attemptId, a);
        return { accepted: true, dropResponse: o.mode === 'drop_response' };
      } catch (e) {
        if (!(e instanceof Refusal)) throw e;
        if (e.code.startsWith('dependency_')) this.lockDependency(a.objectId, e.code, a.gatewayCause);
        this.event('commit_refused', { attemptId, objectId: a.objectId, reason: e.code }, [a.gatewayCause]); return { accepted: false, reason: e.code };
      }
    });
  }
  reconcile(objectId, sessionId) {
    return this.tx(() => {
      const s = this.get('session', sessionId); requireThat(s?.objectId === objectId, 'scope_denied'); this.sessionCheck(s);
      const o = this.get('object', objectId); const e = this.effect(objectId);
      if (e) {
        const { effectHash, cause, ...body } = e;
        requireThat(effectHash === hash(body) && e.actionHash === o.actionHash && e.value === o.value && e.target === o.target, 'evidence_mismatch');
        o.outcome = 'verified'; this.put('object', objectId, o);
        this.event('verified', { objectId, effectHash, actionHash: o.actionHash }, [cause]);
        return { status: 'verified', objectId, effect: e, message: 'The record was appended and read back.' };
      }
      return { status: o.outcome, objectId, effect: null, approval: this.get('approval', objectId)?.state || null,
        message: 'An appended record has not been verified.' };
    });
  }
  outcome(objectId, outcome, attemptId) {
    this.tx(() => { const o = this.get('object', objectId); o.outcome = outcome; this.put('object', objectId, o); this.event('outcome', { objectId, outcome, attemptId }); });
  }
  export() {
    return this.tx(() => ({
      objects: this.all('object'), tasks: this.all('task'), conditions: this.all('condition'), approvals: this.all('approval'), attempts: this.all('attempt'),
      sessions: this.all('session').map(({ tokenHash, ...s }) => s),
      effects: this.db.prepare('SELECT body FROM effects ORDER BY object_id').all().map(r => JSON.parse(r.body)),
      events: this.db.prepare('SELECT body,hash FROM events ORDER BY seq').all().map(r => ({ ...JSON.parse(r.body), hash: r.hash }))
    }));
  }
}
