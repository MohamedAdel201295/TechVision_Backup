'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
function section(start, end) { return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start))); }
function fixture(t, jobs, fault) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-job-delete-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, '.techvision', 'jobs'); fs.mkdirSync(dir, { recursive: true });
  for (const j of jobs) fs.writeFileSync(path.join(dir, j.id + '.json'), JSON.stringify(j));
  const handlers = {};
  const io = Object.create(fs);
  io.unlinkSync = file => { if (fault === 'unlink' && file.endsWith(jobs[0].id + '.json')) throw Error('EPERM: test locked template'); return fs.unlinkSync(file); };
  const context = vm.createContext({ fs: io, path, process, console: { log(){}, error(){}, warn(){} },
    app: { getPath: () => root }, jobHistory: JSON.parse(JSON.stringify(jobs)), activeJobs: new Map(),
    getHistoryPath: () => path.join(dir, 'history.json'), loadWaitingState(){}, saveWaitingState(){},
    notifyJobsUpdated(){}, jobPathValue: v => typeof v === 'string' ? v : v?.path || '',
    ipcMain: { handle: (name, fn) => { handlers[name] = fn; } } });
  vm.runInContext(section('function normalizeJobObject(', '// Tell the main window'), context);
  vm.runInContext(section('async function loadStoredJobs()', '// Persist the drive-wait state'), context);
  vm.runInContext(section("ipcMain.handle('job-delete'", 'function promptRestoreDir()'), context);
  return { context, dir, remove: id => handlers['job-delete'](null, id), restart: () => vm.runInContext('loadStoredJobs()', context) };
}
const base = { id: 'qa-my-backup', name: 'my backup', source: '/qa/source', destination: '/qa/dest', schedule: {enabled:true,time:'00:00',frequency:'Daily'}, runs:[] };
test('deleted scheduled job stays absent after disk reload', async t => {
  const f = fixture(t, [base]); assert.equal((await f.remove(base.id)).success, true);
  await f.restart(); assert.equal(f.context.jobHistory.length, 0);
});
test('locked template must not be reported as successfully deleted', async t => {
  const f = fixture(t, [base], 'unlink'); const r = await f.remove(base.id);
  assert.equal(r.success, false); assert.match(r.error, /template|delete/i);
  assert.equal(f.context.jobHistory.length, 1);
});
test('duplicate templates of same task leave no scheduled ghost in memory or after reload', async t => {
  const duplicate = {...base, id:'qa-legacy-copy', runs:[{id:'old-run',type:'full',status:'completed'}]};
  const f = fixture(t, [base, duplicate]); assert.equal((await f.remove(base.id)).success, true);
  assert.equal(f.context.jobHistory.length, 0); await f.restart(); assert.equal(f.context.jobHistory.length, 0);
});
test('different same-name task survives deletion and reload', async t => {
  const other = {...base, id:'qa-other',source:'/qa/other'}; const f = fixture(t,[base,other]);
  assert.equal((await f.remove(base.id)).success,true); await f.restart();
  assert.equal(f.context.jobHistory.length,1);assert.equal(f.context.jobHistory[0].id,other.id);
});
test('running job cannot be deleted while its completion could recreate history', async t => {
  const f = fixture(t,[base]); f.context.activeJobs.set('run',{name:base.name,jobId:base.id,status:'running'});
  const r=await f.remove(base.id);assert.equal(r.success,false);assert.match(r.error,/running|progress/i);
});
test('history write failure is not reported as successful deletion', async t => {
  const f=fixture(t,[base]);
  f.context.fs.renameSync=()=>{throw Error('EACCES: history locked');};
  const r=await f.remove(base.id);assert.equal(r.success,false);assert.match(r.error,/history/i);
});
test('scheduler cannot start a job deleted while drive resolution was awaiting', async t => {
  const f=fixture(t,[base]); let release;
  f.context.resolveJobPaths=()=>new Promise(resolve=>{release=resolve;});
  f.context.nextScheduledRun=()=>new Date(0);
  f.context.started=0;f.context.executeScheduledBackup=()=>{f.context.started++;};
  vm.runInContext(section('async function checkSchedules()', '// Fill in a job'),f.context);
  const pending=vm.runInContext('checkSchedules()',f.context);
  assert.equal((await f.remove(base.id)).success,true);
  release({source:{found:true},destination:{found:true}});await pending;
  assert.equal(f.context.started,0);await f.restart();assert.equal(f.context.jobHistory.length,0);
});
test('scheduler waiting metadata never loads as an Unnamed Job template', async t => {
  const f=fixture(t,[]); fs.writeFileSync(path.join(f.dir,'waiting.json'),'[]');
  await f.restart();assert.equal(f.context.jobHistory.length,0);
});
// Narrowing (round 3 follow-up): only an unreadable file that could be
// this job's own template (<id>.json / <name>.json) fails the delete.
// Any other unreadable file is skipped, never blocks the delete.
test('unreadable junk template of another job does not block deletion', async t => {
  const f = fixture(t, [base]);
  fs.writeFileSync(path.join(f.dir, 'someone-elses-broken.json'), '{invalid json');
  assert.equal((await f.remove(base.id)).success, true);
  assert.equal(f.context.jobHistory.length, 0);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
});
test('unreadable file named as the job’s own template fails the delete', async t => {
  const f = fixture(t, [base]);
  fs.writeFileSync(path.join(f.dir, base.id + '.json'), '{invalid json');
  const r = await f.remove(base.id);
  assert.equal(r.success, false);
  assert.match(r.error, /Cannot verify job template/i);
  assert.equal(f.context.jobHistory.length, 1);
});
