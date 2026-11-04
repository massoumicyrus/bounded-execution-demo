import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
export function worker(file, args = []) {
  const child = fork(fileURLToPath(new URL(file, import.meta.url)), args, {
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { PATH: process.env.PATH }, execArgv: []
  });
  const pending = new Map(); let serial = 0, exited=false;
  child.stderr.on('data', () => {}); // Never expose process environment or request material through logs.
  child.on('message', m => { const p = pending.get(m.id); if (!p) return; clearTimeout(p.timer); pending.delete(m.id); m.error ? p.reject(new Error(m.error)) : p.resolve(m.value); });
  child.on('exit', () => { exited=true; for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new Error('worker_exited')); } pending.clear(); });
  return { pid: child.pid, get dead(){return exited;}, call(payload) { return new Promise((resolve, reject) => {
    if(exited)return reject(new Error('worker_exited'));
    const id = ++serial; const timer = setTimeout(() => { pending.delete(id); reject(new Error('worker_timeout')); }, 10000);
    pending.set(id, { resolve, reject, timer }); child.send({ id, payload });
  }); }, async close() { if (exited) return; await new Promise(resolve => { child.once('exit', resolve); child.kill(); }); } };
}
