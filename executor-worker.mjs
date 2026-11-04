import { Store } from './store.mjs';
const store = new Store(process.argv[2]);
process.on('message', ({ id, payload }) => {
  try {
    const result=store.commit(payload.attemptId);
    if(result.dropResponse) process.exit(86); // Commit persisted; the IPC response is actually lost.
    process.send({ id, value:result });
  }
  catch (e) { process.send({ id, error: e.message }); }
});
