import { mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { scenarios } from './scenarios.mjs';
import { hash } from './store.mjs';
const result = await scenarios();
const root = resolve(process.argv[2] || 'evidence'); mkdirSync(root,{recursive:true});
const files=[...readdirSync('.').filter(x=>x.endsWith('.mjs') || ['review.html','package.json','package-lock.json'].includes(x)),...readdirSync('test').filter(x=>x.endsWith('.mjs')).map(x=>'test/'+x)];
const sourceHashes = Object.fromEntries(files.sort().map(x=>[x,hash(readFileSync(x).toString('utf8'))]));
const record = { schema:'bounded-execution-evidence/1', generatedAt:new Date().toISOString(), node:process.version,
  platform:process.platform, runner:'Codex for Cyrus Massoumi', attribution:'author-produced', aps:'1.46.0',
  humanApproval:'Authenticated automated test client; no real person approved these fixture actions.',
  child:'Scripted child process with Node permission restrictions; no LLM behavioral claim.', sourceHashes, ...result };
writeFileSync(resolve(root,'run.json'),JSON.stringify(record,null,2)+'\n');
writeFileSync(resolve(root,'summary.json'),JSON.stringify({cases:result.cases.length,passed:result.cases.filter(c=>c.passed).length,effects:result.snapshot.effects.length,events:result.snapshot.events.length},null,2)+'\n');
console.log(`Evidence written: ${result.cases.length} scenarios, ${result.snapshot.effects.length} verified test effects.`);
