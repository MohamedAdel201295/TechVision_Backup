'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
function section(start, end) { return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start))); }
function fixture(t, jobs, fault, opts) {
  opts = opts || {};
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-job-delete-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  // Pinned mode mirrors the real app: userData is
  // <root>/TechVision Backup and the legacy folder is
  // <root>/techvision-backup. Classic mode (the old tests) keeps the
  // single flat layout.
  const dir = opts.pinned
    ? path.join(root, 'TechVision Backup', '.techvision', 'jobs')
    : path.join(root, '.techvision', 'jobs');
  fs.mkdirSync(dir, { recursive: true });
  const legacyDir = opts.pinned ? path.join(root, 'techvision-backup', '.techvision', 'jobs') : null;
  if (legacyDir && opts.legacy) {
    fs.mkdirSync(legacyDir, { recursive: true });
    for (const j of opts.legacy) {
      const { _file, ...content } = j;
      fs.writeFileSync(path.join(legacyDir, _file || (j.id + '.json')), JSON.stringify(content));
    }
  }
  for (const j of jobs) {
    // A job may carry _file to override the on-disk filename (legacy
    // templates are often <name>.json with no id field at all). _file
    // is stripped from the written content.
    const { _file, ...content } = j;
    fs.writeFileSync(path.join(dir, _file || (j.id + '.json')), JSON.stringify(content));
  }
  const handlers = {};
  const io = Object.create(fs);
  io.unlinkSync = file => { if (fault === 'unlink' && file.endsWith(jobs[0].id + '.json')) throw Error('EPERM: test locked template'); return fs.unlinkSync(file); };
  // failReads lets a test make a template unreadable AFTER it was
  // loaded (simulating a file locked between load and delete).
  const failReads = new Set();
  io.readFileSync = (p, enc) => { if (failReads.has(path.basename(String(p)))) throw new Error('EACCES: test unreadable template'); return fs.readFileSync(p, enc); };
  const context = vm.createContext({ fs: io, path, process, console: { log(){}, error(){}, warn(){} },
    app: { getPath: (name) => opts.pinned ? (name === 'appData' ? root : path.join(root, 'TechVision Backup')) : root, setPath(){} },
    jobHistory: JSON.parse(JSON.stringify(jobs)), activeJobs: new Map(),
    getHistoryPath: () => path.join(dir, 'history.json'),
    notifyJobsUpdated(){}, jobPathValue: v => typeof v === 'string' ? v : v?.path || '',
    ipcMain: { handle: (name, fn) => { handlers[name] = fn; } } });
  vm.runInContext(section('function normalizeJobObject(', '// Tell the main window'), context);
  vm.runInContext(section('async function loadStoredJobs()', '// Persist the drive-wait state'), context);
  vm.runInContext(section('// Persist the drive-wait state', 'function getAutoStartSetting'), context);
  vm.runInContext(section('// ONE userData folder for every way of running the app.', 'function migrateLegacyUserData()'), context);
  vm.runInContext(section('function migrateLegacyUserData()', '// Assets path for icons'), context);
  vm.runInContext(section("ipcMain.handle('job-delete'", 'function promptRestoreDir()'), context);
  vm.runInContext(section("ipcMain.handle('job-clear-history'", "ipcMain.handle('job-get-config'"), context);
  const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch (e) { return null; } };
  return { context, dir, legacyDir, failReads,
    remove: id => handlers['job-delete'](null, id),
    clear: () => handlers['job-clear-history'](),
    restart: () => vm.runInContext('loadStoredJobs()', context),
    migrate: () => vm.runInContext('migrateLegacyUserData()', context),
    history: () => readJson(path.join(dir, 'history.json')),
    waiting: () => readJson(path.join(dir, 'waiting.json')),
    files: () => fs.readdirSync(dir).filter(f => f.endsWith('.json')),
    legacyFiles: () => legacyDir ? fs.readdirSync(legacyDir).filter(f => f.endsWith('.json')) : [] };
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

// Problem 2 (2026-11-27): the user's "My Backup" TEMPLATE — legacy
// file <name>.json with NO id field, Daily 02:00, never run — returns
// after every delete. Reproduce the exact shape against current code.
test('legacy template with no id (My Backup shape) stays deleted after restart', async t => {
  const legacy = { _file: 'My Backup.json', name: 'My Backup', source: 'C:\\Users\\Mohamed Adel\\Desktop\\M3yar', destination: 'C:\\Users\\Mohamed Adel\\Desktop\\M3yar-backup', schedule: { enabled: true, time: '02:00', frequency: 'Daily' }, type: 'template', runs: [] };
  const f = fixture(t, [legacy]);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 1);
  assert.equal(f.context.jobHistory[0].name, 'My Backup');
  assert.equal((await f.remove(f.context.jobHistory[0].id)).success, true);
  assert.equal(fs.existsSync(path.join(f.dir, 'My Backup.json')), false);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
});
// Silent-success hole: a loaded template whose file turns unreadable
// between load and delete, under a filename that is neither
// <id>.json nor <name>.json, used to be skipped by the content scan
// while delete still reported success — the row vanished and the
// template came back on the next start. The delete must remove the
// recorded template file by name instead (unlink needs no read).
test('loaded template with unreadable oddly-named file is still deleted by name', async t => {
  const odd = { _file: 'weird-name.json', id: 'qa-x', name: 'My Backup', source: '/qa/source', destination: '/qa/dest', schedule: { enabled: true, time: '02:00', frequency: 'Daily' }, type: 'template', runs: [] };
  const f = fixture(t, [odd]);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 1);
  f.failReads.add('weird-name.json');
  assert.equal((await f.remove('qa-x')).success, true);
  assert.equal(fs.existsSync(path.join(f.dir, 'weird-name.json')), false);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
});
// Guard against the fix being too strict: when the recorded template
// file is already gone from disk, the delete must still succeed.
test('delete succeeds when the recorded template file is already gone', async t => {
  const f = fixture(t, [base]);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 1);
  fs.unlinkSync(path.join(f.dir, base.id + '.json'));
  assert.equal((await f.remove(base.id)).success, true);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
});

// Delete-absolute (2026-11-27): the user's "My Backup" came back
// RUNNING after a full Exit + reopen even though the Jobs Delete
// reported success and history.json was empty on load. Root cause:
// migrateLegacyUserData COPIED the template back from the legacy
// folder (%APPDATA%\techvision-backup) on every startup — the copy
// never deleted its source, so a file deleted from the pinned folder
// was "missing" there again and got copied back, loaded as a
// template, and its missed Daily 02:00 schedule fired it. The
// migration must MOVE, not copy. These tests pin the exact shape:
// a legacy template, an empty post-delete history, delete, migrate
// again (next startup), restart — the job must stay gone.
const legacyMyBackup = { _file: 'My Backup.json', name: 'My Backup', source: 'C:\\Users\\Mohamed Adel\\Desktop\\M3yar', destination: 'C:\\Users\\Mohamed Adel\\Desktop\\M3yar-backup', schedule: { enabled: true, time: '02:00', frequency: 'Daily' }, type: 'template', runs: [] };
test('legacy migration moves the template; a later delete stays deleted after restart', async t => {
  const f = fixture(t, [], null, { pinned: true, legacy: [legacyMyBackup] });
  f.migrate();
  assert.equal(fs.existsSync(path.join(f.legacyDir, 'My Backup.json')), false, 'legacy source must be gone after the move');
  assert.equal(fs.existsSync(path.join(f.dir, 'My Backup.json')), true, 'template must be adopted into the pinned folder');
  await f.restart();
  assert.equal(f.context.jobHistory.length, 1);
  assert.equal(f.context.jobHistory[0].name, 'My Backup');
  assert.equal((await f.remove(f.context.jobHistory[0].id)).success, true);
  assert.equal(fs.existsSync(path.join(f.dir, 'My Backup.json')), false);
  f.migrate(); // the next startup: nothing left behind to copy back
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
  assert.deepEqual(f.history(), [], 'history.json must stay empty after the migration');
});
test('legacy migration removes a stale duplicate when the destination already has the file', async t => {
  const f = fixture(t, [legacyMyBackup], null, { pinned: true, legacy: [legacyMyBackup] });
  assert.equal(fs.existsSync(path.join(f.legacyDir, 'My Backup.json')), true);
  f.migrate();
  assert.equal(fs.existsSync(path.join(f.legacyDir, 'My Backup.json')), false, 'stale duplicate must not survive to resurrect a later delete');
  assert.equal(fs.existsSync(path.join(f.dir, 'My Backup.json')), true, 'the live copy is kept');
  await f.restart();
  assert.equal(f.context.jobHistory.length, 1);
});
test('legacy migration keeps a file the destination is missing, and the scheduler still cannot start a deleted job', async t => {
  const f = fixture(t, [], null, { pinned: true, legacy: [legacyMyBackup] });
  f.migrate();
  await f.restart();
  assert.equal(f.context.jobHistory.length, 1);
  // Delete, migrate again, restart — then prove the scheduler has
  // nothing to start: checkSchedules with a due slot and a counting
  // executeScheduledBackup must fire zero runs.
  assert.equal((await f.remove(f.context.jobHistory[0].id)).success, true);
  f.migrate();
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
  f.context.nextScheduledRun = () => new Date(0);
  f.context.started = 0;
  f.context.executeScheduledBackup = () => { f.context.started++; };
  f.context.resolveJobPaths = () => Promise.resolve({ source: { found: true }, destination: { found: true } });
  vm.runInContext(section('async function checkSchedules()', '// Fill in a job'), f.context);
  await vm.runInContext('checkSchedules()', f.context);
  assert.equal(f.context.started, 0);
});

// Clear history (2026-11-27): the Jobs-page "Clear History" button
// used to empty the run records while leaving every template (and
// its schedule) on disk — the jobs came back on the next start and
// their missed schedules fired them. Delete means delete: a clear
// now removes template files, run history and drive-wait state, and
// refuses while a backup is running.
test('clear history removes templates, history and waiting state, and nothing returns after restart', async t => {
  const other = { ...base, id: 'qa-other', name: 'other job', source: '/qa/other', destination: '/qa/other-dest', schedule: { enabled: false }, runs: [] };
  const f = fixture(t, [base, other]);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 2);
  // A run record for the scheduled job + a waiting entry for it.
  fs.writeFileSync(path.join(f.dir, 'history.json'), JSON.stringify([
    { id: 'run-1', jobId: base.id, name: base.name, type: 'full', status: 'completed', success: true, source: base.source, destination: base.destination, timestamp: new Date().toISOString(), files: 3, size: 100, duration: 1, error: null, result: null }
  ]));
  fs.writeFileSync(path.join(f.dir, 'waiting.json'), JSON.stringify([
    { jobId: base.id, name: base.name, since: new Date().toISOString(), due: new Date().toISOString(), which: 'source', path: base.source, label: null }
  ]));
  await f.restart();
  assert.equal(f.context.jobHistory.length, 2);
  assert.equal((await f.clear()).success, true);
  assert.equal(f.context.jobHistory.length, 0);
  assert.deepEqual(f.files(), ['history.json', 'waiting.json']);
  assert.deepEqual(f.history(), []);
  assert.deepEqual(f.waiting(), []);
  await f.restart();
  assert.equal(f.context.jobHistory.length, 0);
});
test('clear history refuses while a backup is running, and nothing is deleted', async t => {
  const f = fixture(t, [base]);
  await f.restart();
  f.context.activeJobs.set('run', { name: base.name, jobId: base.id, status: 'running' });
  const r = await f.clear();
  assert.equal(r.success, false);
  assert.match(r.error, /running/i);
  assert.equal(f.context.jobHistory.length, 1);
  assert.equal(fs.existsSync(path.join(f.dir, base.id + '.json')), true);
});
test('clear history fails loudly when a template file cannot be deleted', async t => {
  const f = fixture(t, [base], 'unlink');
  await f.restart();
  const r = await f.clear();
  assert.equal(r.success, false);
  assert.match(r.error, /template|delete/i);
  assert.equal(f.context.jobHistory.length, 1);
});
