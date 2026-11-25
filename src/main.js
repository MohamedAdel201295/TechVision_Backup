/**
 * TechVision Backup - Main Process
 * Electron main process for backup application
 */

const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } = require('electron');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { BackupEngine, JobConfig, BackupResult } = require('./techvision-core.js');
const { RestoreEngine } = require('./restore.js');
const mailer = require('./mailer.js');
const vault = require('./vault.js');
const driveResolver = require('./drive-resolver.js');
const cloudServerMod = require('./cloud-server.js');
const cloudClient = require('./cloud-client.js');
const vpn = require('./vpn.js');
const wireguard = require('./wireguard.js');
const cloudJoin = require('./cloud-join.js');
const natGateway = require('./nat-gateway.js');
const wgControl = require('./wg-control.js');
// How long a due scheduled job waits for a missing removable drive
// before it is recorded as failed (and emailed about): 2 hours.
const DRIVE_WAIT_MS = 2 * 60 * 60 * 1000;
// Master-password vault: the derived key lives ONLY in memory while
// the vault is unlocked. Nothing about the master password or any job
// password is ever written to disk in the clear.
let vaultKey = null;

// ---------- TechVision Cloud ----------
// Config file: <userData>/.techvision/cloud.json — { server, clients }.
// The server instance holds a reference to this object, so user edits
// apply without a restart (except port changes, which restart it).
let cloudConfig = null;
function cloudConfigPath() {
  return path.join(app.getPath('userData'), '.techvision', 'cloud.json');
}
function getCloudConfig() {
  if (cloudConfig) return cloudConfig;
  try {
    const p = cloudConfigPath();
    if (fs.existsSync(p)) cloudConfig = JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch (e) { cloudConfig = null; }
  if (!cloudConfig || typeof cloudConfig !== 'object') cloudConfig = {};
  if (!cloudConfig.server || typeof cloudConfig.server !== 'object') cloudConfig.server = cloudServerMod.defaultServerConfig();
  if (!Array.isArray(cloudConfig.clients)) cloudConfig.clients = [];
  return cloudConfig;
}
function saveCloudConfig() {
  try {
    const dir = path.join(app.getPath('userData'), '.techvision');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = cloudConfigPath() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(getCloudConfig(), null, 2));
    fs.renameSync(tmp, cloudConfigPath());
  } catch (e) { console.error('[Main] Could not save cloud config:', e.message); }
}
let cloudServer = null;
function getCloudServer() {
  if (!cloudServer) {
    cloudServer = new cloudServerMod.CloudServer({
      config: getCloudConfig(),
      onConfigChange: () => saveCloudConfig(),
      log: (level, message) => appendAppLog(level, message),
    });
    // Cloud join (WireGuard, Phase 2): the /api/wg-join-* routes ride
    // on this same Cloud server — same users, same TLS-pinned channel.
    // Pending requests live in cloud.json at cfg.server.wgJoinRequests
    // (configBackedStore), so they survive a server restart. start()
    // dispatches through this._handle, so attaching here — before any
    // start — is picked up; attaching twice is a no-op. The store is
    // kept here so the wg-cloudjoin-* handlers below can use it.
    try {
      const attached = cloudJoin.attachJoinRoutes(cloudServer, {
        store: cloudJoin.configBackedStore(getCloudConfig(), () => saveCloudConfig()),
      });
      if (attached && attached.store) wgJoinStoreInstance = attached.store;
    } catch (e) { console.error('[Main] Could not attach WireGuard Cloud-join routes:', e.message); }
  }
  return cloudServer;
}
// The pending-request store attached to the Cloud server above (null
// until getCloudServer() has run once).
let wgJoinStoreInstance = null;
// Client-side join requests THIS machine sent: requestId ->
// { serverId, deviceName, privateKey, createdAt }. The private key
// lives only here, in memory, until the server approves (or the
// request expires / the app quits — then the user simply sends a
// fresh request). It is never written to disk and never sent to the
// renderer.
const wgPendingJoins = new Map();
// Client sessions live in main only (tokens never reach the renderer):
// serverId -> { host, port, certPem, token, user, root, canWrite }
const cloudSessions = new Map();

// ---------- TechVision WireGuard VPN ----------
// Config file: <userData>/.techvision/wireguard.json — { server, client }.
// Private keys are stored PLAINTEXT here — the same deliberate
// precedent as the Cloud server TLS key in cloud.json: the tunnel
// service must start at boot with nobody logged in and no vault
// unlocked, and a vault-stored key would block exactly that. See
// wireguard.js for the full reasoning.
let wgConfig = null;
function wgConfigPath() {
  return path.join(app.getPath('userData'), '.techvision', 'wireguard.json');
}
function getWgConfig() {
  if (wgConfig) return wgConfig;
  try {
    const p = wgConfigPath();
    if (fs.existsSync(p)) wgConfig = JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch (e) { wgConfig = null; }
  if (!wgConfig || typeof wgConfig !== 'object') wgConfig = {};
  if (!wgConfig.server || typeof wgConfig.server !== 'object') wgConfig.server = {};
  const s = wgConfig.server;
  if (typeof s.privateKey !== 'string') s.privateKey = '';
  if (typeof s.publicKey !== 'string') s.publicKey = '';
  if (typeof s.address !== 'string' || !s.address) s.address = wireguard.SERVER_ADDRESS;
  // Stored as a bare IPv4 (old configs carried '10.0.0.1/24'); the
  // builders add the /24 themselves, and the UI shows the bare IP.
  if (s.address.indexOf('/') >= 0) s.address = s.address.split('/')[0];
  if (!Number.isInteger(s.listenPort) || s.listenPort < 1 || s.listenPort > 65535) s.listenPort = wireguard.LISTEN_PORT;
  if (typeof s.endpoint !== 'string') s.endpoint = '';
  if (!Array.isArray(s.peers)) s.peers = [];
  if (!('client' in wgConfig)) wgConfig.client = null;
  if (!('nat' in wgConfig) || typeof wgConfig.nat !== 'object' || !wgConfig.nat) wgConfig.nat = null;
  if (!('transport' in wgConfig) || typeof wgConfig.transport !== 'object' || !wgConfig.transport) wgConfig.transport = {};
  /* Phase 2 (core requirement 2026-11-24): AmneziaWG is the
     transport — stock WireGuard cannot be used, it does not
     understand the obfuscation fields and both ends must run
     AmneziaWG. The choice lives in wireguard.json as
     `transportName` ('amneziawg' | 'wireguard'); a fresh config
     defaults to AmneziaWG, and an explicit 'wireguard' stays a
     fallback the user can go back to. The per-binary `transport`
     override below still wins when it is set (custom install path,
     tests). */
  if (wgConfig.transportName !== 'amneziawg' && wgConfig.transportName !== 'wireguard') wgConfig.transportName = 'amneziawg';
  wireguard.setTransport(wgConfig.transportName);
  wireguard.setTransportBinaries(wgConfig.transport);
  return wgConfig;
}
function saveWgConfig() {
  try {
    const dir = path.join(app.getPath('userData'), '.techvision');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = wgConfigPath() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(getWgConfig(), null, 2));
    fs.renameSync(tmp, wgConfigPath());
  } catch (e) { console.error('[Main] Could not save WireGuard config:', e.message); }
}
// The stored peer list joined with live handshake/transfer data from
// `wg show` (matched by public key). Live data is best-effort: a peer
// that never connected simply shows online:false.
function wgPeersWithLive(livePeers) {
  const live = {};
  for (const p of livePeers || []) live[p.publicKey] = p;
  return (getWgConfig().server.peers || []).map((p) => {
    const l = live[p.publicKey] || null;
    return Object.assign({}, p, l ? {
      endpoint: l.endpoint,
      latestHandshake: l.latestHandshake ? l.latestHandshake.getTime() : null,
      transferRx: l.transferRx, transferTx: l.transferTx,
      online: !!l.latestHandshake,
    } : { online: false, latestHandshake: null, transferRx: 0, transferTx: 0 });
  });
}
// The config as the renderer may see it: private keys stripped. The
// only exception is an invite config text, which is built and returned
// by wg-generate-invite itself (the invite IS that peer's key).
function wgPublicConfig() {
  const c = getWgConfig();
  const server = Object.assign({}, c.server);
  delete server.privateKey;
  const client = c.client ? Object.assign({}, c.client) : null;
  if (client) { delete client.privateKey; delete client.obfuscation; }
  return { server, client };
}
/* The obfuscation set every server/invite config carries, as the
   [Interface] lines buildServerConf/buildClientConf take. Generated
   ONCE (generateObfuscationParams) and stored in wireguard.json
   under `obfuscation` — never regenerated silently, or every
   existing peer breaks (S1–S4/H1–H4 must match on both ends). A
   stored set that fails validation throws here instead of writing
   a .conf that silently fails to connect. */
function wgObfuscationLines() {
  const c = getWgConfig();
  if (!c.obfuscation || typeof c.obfuscation !== 'object') {
    const p = wireguard.generateObfuscationParams();
    const v = wireguard.validateObfuscationParams(p);
    if (!v.ok) throw new Error('Could not generate the obfuscation settings: ' + v.errors.join(' '));
    c.obfuscation = p;
    saveWgConfig();
    return wireguard.obfuscationParamsToLines(p);
  }
  return wireguard.obfuscationParamsToLines(c.obfuscation);
}
/* Lines for a stored client config: the set that was in effect when
   the client connected — the server's own set for our invites, the
   imported set for a foreign .conf. A hand-typed foreign connect
   has no set: injecting ours would break its handshake, so it gets
   none and the user must import the server's .conf instead. */
function wgLinesForObfuscation(set) {
  if (!set || typeof set !== 'object') return undefined;
  return wireguard.obfuscationParamsToLines(set);
}
function wgHasObfuscation() {
  const c = getWgConfig();
  return !!c.obfuscation && wireguard.validateObfuscationParams(c.obfuscation).ok;
}

const isDevelopment = !app.isPackaged;

// ONE userData folder for every way of running the app. This was the
// settings bug: Electron picks userData from the app name, which is
// "techvision-backup" when run from source (`electron .`) but
// "TechVision Backup" (productName) once packaged — so settings (and
// jobs) saved in one mode were invisible in the other, and it looked
// like nothing had been saved at all. Pinning the path unifies them.
const USER_DATA_DIR = path.join(app.getPath('appData'), 'TechVision Backup');
try {
  app.setPath('userData', USER_DATA_DIR);
} catch (e) {
  console.error('[Main] Could not pin userData path:', e.message);
}

// Bring over settings/jobs saved under the old per-mode folders
// (techvision-backup or TechVision Backup) into the pinned folder,
// copying only files that are missing there.
function migrateLegacyUserData() {
  try {
    const newBase = path.join(USER_DATA_DIR, '.techvision');
    for (const name of ['techvision-backup', 'TechVision Backup']) {
      const oldBase = path.join(app.getPath('appData'), name, '.techvision');
      if (oldBase === newBase || !fs.existsSync(oldBase)) continue;
      const copyMissing = (srcDir, destDir) => {
        if (!fs.existsSync(srcDir)) return;
        if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
        for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
          const src = path.join(srcDir, entry.name);
          const dest = path.join(destDir, entry.name);
          if (entry.isDirectory()) copyMissing(src, dest);
          else if (!fs.existsSync(dest)) {
            fs.copyFileSync(src, dest);
            console.log(`[Main] Migrated user data file: ${dest}`);
          }
        }
      };
      copyMissing(oldBase, newBase);
    }
  } catch (e) {
    console.error('[Main] User data migration failed:', e.message);
  }
}

// Assets path for icons
const ASSETS_PATH = path.join(__dirname, 'assets');
const APP_ICON = path.join(ASSETS_PATH, 'TechVision_Logo.png');

// System tray + auto-start: the app must keep running (and keep its
// scheduler alive) until the user explicitly quits from the tray.
// Closing the main window only hides it to the tray.
let tray = null;
let isQuitting = false;

// Main window
let mainWindow;
let restoreWindow;
let logViewerWindow;
let jobWizardWindow;
let settingsWindow;
let jobDetailsWindow;
let pendingWizardJob = null;
let pendingRestoreJob = null;

// Active jobs tracking (Map for tracking in-progress operations)
const activeJobs = new Map();
let jobHistory = [];

// Get jobs history file path
function getHistoryPath() {
  return path.join(app.getPath('userData'), '.techvision', 'jobs', 'history.json');
}

// Job paths are stored as plain strings by the wizard
// (source: "C:\\...", destination: "D:\\..."). Keep them as strings
// here too — the renderer displays them directly, so an object
// { path } would render as "[object Object]".
function jobPathValue(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && typeof value.path === 'string') return value.path;
  return '';
}

// Helper function to normalize job objects with uniform defaults
function normalizeJobObject(job, defaultType = 'full') {
  if (!job || typeof job !== 'object') return null;
  const normalized = {
    id: job.id || `job-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    name: job.name || 'Unnamed Job',
    status: job.status || 'pending',
    type: job.type || defaultType,
    source: jobPathValue(job.source || job.sourcePath || job.sourceDirectory),
    destination: jobPathValue(job.destination || job.destPath || job.destinationDirectory || job.dest),
    timestamp: job.timestamp || new Date().toISOString(),
    files: job.files ?? 0,
    size: job.size ?? 0,
    duration: job.duration ?? 0,
    result: job.result || null,
    jobId: job.jobId || null,
    // Settings must survive load/save: the wizard saves compress,
    // compression and schedule, but normalize used to drop them, so
    // a Run from History always ran with the defaults (compressed,
    // no schedule) no matter what the job was created with.
    schedule: job.schedule || { enabled: false },
    compress: job.compress !== undefined ? job.compress : undefined,
    compression: job.compression || (job.compress === false ? 'none' : undefined),
    allowIncremental: job.allowIncremental,
    // Include/exclude patterns used to be dropped here — the wizard
    // saved them and the engine honours them, but every run path
    // (scheduled, dashboard, job-run-backup) goes through normalize,
    // so no run ever used them and every backup took EVERYTHING.
    includePatterns: Array.isArray(job.includePatterns) ? job.includePatterns.filter((p) => typeof p === 'string') : undefined,
    excludePatterns: Array.isArray(job.excludePatterns) ? job.excludePatterns.filter((p) => typeof p === 'string') : undefined,
    sourceVolumeLabel: job.sourceVolumeLabel || null,
    destinationVolumeLabel: job.destinationVolumeLabel || null,
    sourceDriveMatch: job.sourceDriveMatch || null,
    destinationDriveMatch: job.destinationDriveMatch || null,
    waitingForDrive: job.waitingForDrive || null,
    encryptionEnabled: job.encryptionEnabled === true,
    verify: job.verify,
    options: job.options || {},
    lastScheduledRun: job.lastScheduledRun || null,
    runs: Array.isArray(job.runs) ? job.runs : [],
    runCount: job.runCount ?? (Array.isArray(job.runs) ? job.runs.length : 0),
    loaded: job.loaded || false
  };
  // A job with runs is a real job, not a template: showing
  // "TEMPLATE / COMPLETED" is contradictory. Only a job that never
  // ran keeps type TEMPLATE.
  if (normalized.runs.length) {
    const lastRun = normalized.runs[normalized.runs.length - 1];
    normalized.type = lastRun.type === 'incremental' ? 'incremental' : 'full';
    normalized.status = lastRun.status || normalized.status;
  }
  return normalized;
}

// One entry per job in jobHistory: a job template (loaded from its
// <name>.json) plus the runs that belong to it. A run must NEVER create
// a second history entry: recordRun() appends the run to the job's own
// `runs` list and updates the job's latest-run stats in place.
function mergeJobEntries(entries) {
  const byName = new Map();
  const merged = [];
  function runFromRecord(rec) {
    return {
      id: rec.id || `run-${Date.now()}`,
      type: rec.type || 'full',
      status: rec.status || (rec.success ? 'completed' : 'failed'),
      success: rec.success,
      timestamp: rec.timestamp || new Date().toISOString(),
      files: rec.files ?? 0,
      size: rec.size ?? 0,
      duration: rec.duration ?? 0,
      error: rec.error || null,
      result: rec.result || null
    };
  }
  for (const entry of entries) {
    if (!entry) continue;
    const isRunRecord = (entry.type === 'full' || entry.type === 'incremental') && !entry.loaded;
    // Key by id, not by name: two jobs may share a name and must stay
    // two separate tasks. Run records carry jobId; templates carry id.
    const key = (isRunRecord ? (entry.jobId || entry.name) : (entry.id || entry.name) || 'Unnamed Job').toLowerCase();
    let job = byName.get(key);
    if (!job && !isRunRecord) {
      // Legacy run records (saved before jobId existed) key by name,
      // not by the job id — a template for the same job would
      // otherwise create a second, run-less entry. Adopt the
      // name-keyed job instead of duplicating it.
      const byNameKey = (entry.name || '').toLowerCase();
      for (const cand of merged) {
        if (!cand.loaded && (cand.name || '').toLowerCase() === byNameKey) {
          job = cand;
          byName.set(key, job); // the template's id-key points at it too
          break;
        }
      }
    }
    if (!job) {
      // A run record's own id is the RUN's id, not the job's: use the
      // record's jobId when it has one, so the merged job keeps the
      // identity its template file and vault entries use.
      const entryForJob = (isRunRecord && entry.jobId)
        ? Object.assign({}, entry, { id: entry.jobId })
        : entry;
      job = normalizeJobObject(entryForJob, isRunRecord ? 'full' : 'template');
      job.runs = [];
      job.runCount = 0;
      if (isRunRecord) {
        job.type = 'full';
        job.status = 'pending';
      }
      byName.set(key, job);
      merged.push(job);
    }
    if (isRunRecord) {
      const run = runFromRecord(entry);
      job.runs.push(run);
      job.runCount = job.runs.length;
      job.status = run.status;
      job.files = run.files;
      job.size = run.size;
      job.duration = run.duration;
      job.timestamp = run.timestamp;
      job.result = run.result;
      job.type = run.type === 'incremental' ? 'incremental' : 'full';
    } else {
      // Template: keep the job's identity/paths, preserve any runs
      // already merged from history records.
      job.loaded = true;
      if (entry.id) job.id = entry.id; // the template's id is authoritative
      if (entry.source) job.source = entry.source;
      if (entry.destination) job.destination = entry.destination;
      if (entry.schedule) job.schedule = entry.schedule;
      if (entry.compress !== undefined) job.compress = entry.compress;
      if (entry.compression) job.compression = entry.compression;
      if (entry.allowIncremental !== undefined) job.allowIncremental = entry.allowIncremental;
      if (entry.verify !== undefined) job.verify = entry.verify;
      // These used to be lost when a job was rebuilt from its runs
      // after a restart: patterns, drive-match and encryption came
      // only from the template, and the merge never copied them.
      if (Array.isArray(entry.includePatterns)) job.includePatterns = entry.includePatterns.filter((p) => typeof p === 'string');
      if (Array.isArray(entry.excludePatterns)) job.excludePatterns = entry.excludePatterns.filter((p) => typeof p === 'string');
      if (entry.sourceDriveMatch) job.sourceDriveMatch = entry.sourceDriveMatch;
      if (entry.destinationDriveMatch) job.destinationDriveMatch = entry.destinationDriveMatch;
      if (entry.sourceVolumeLabel) job.sourceVolumeLabel = entry.sourceVolumeLabel;
      if (entry.destinationVolumeLabel) job.destinationVolumeLabel = entry.destinationVolumeLabel;
      if (entry.encryptionEnabled !== undefined) job.encryptionEnabled = entry.encryptionEnabled === true;
      if (entry.options) job.options = entry.options;
      if (entry.lastScheduledRun) job.lastScheduledRun = entry.lastScheduledRun;
      if (!job.runs.length) {
        job.status = entry.status || 'pending';
        job.type = 'template';
      }
    }
  }
  return merged;
}

// Tell the main window to reload its jobs/history. Called after every
// change (create, edit, delete, run, clear, scheduled run) so the
// Dashboard refreshes automatically — no manual Refresh needed.
function notifyJobsUpdated() {
  try {
    if (typeof mainWindow !== 'undefined' && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('jobs-updated');
    }
  } catch (e) { /* window not ready yet */ }
}

// Email notification, fire-and-forget: a mail failure must never
// break or delay a backup. Logs the outcome, nothing else.
function notifyEmail(kind, job, extra) {
  try {
    mailer.notify(app.getPath('userData'), kind, job, extra).then(function (r) {
      if (r && !r.sent && r.reason !== 'off') console.log('[Mail] Notification not sent (' + kind + '): ' + r.reason);
      else if (r && r.sent) console.log('[Mail] Notification sent (' + kind + ')');
    }).catch(function (e) { console.log('[Mail] Notification error:', e.message); });
  } catch (e) { console.log('[Mail] Notification error:', e.message); }
}

// Resolve the password for an encrypted job, in order:
//  1. supplied with this call (wizard / run prompt — runtime only),
//  2. the vault, when it is unlocked (so scheduled runs work).
// Returns null when there is no password anywhere. Never throws.
function resolveBackupPassword(jobConfig) {
  if (jobConfig && typeof jobConfig.encryptionPassword === 'string' && jobConfig.encryptionPassword) {
    return jobConfig.encryptionPassword;
  }
  if (jobConfig && jobConfig.encryptionEnabled && vaultKey && jobConfig.id) {
    try { return vault.getJobPassword(app.getPath('userData'), vaultKey, jobConfig.id); } catch (e) { return null; }
  }
  return null;
}

// Central app log: one file for everything the scheduler, the drive
// watcher and the backup runs do, so the Logs view has a full story
// instead of only per-backup files in the destination folder.
function appendAppLog(level, message) {
  try {
    const dir = path.join(app.getPath('userData'), '.techvision');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const logPath = path.join(dir, 'app.log');
    // Keep the file bounded: over 1 MB, keep only the last ~1000 lines.
    try {
      if (fs.existsSync(logPath) && fs.statSync(logPath).size > 1024 * 1024) {
        const lines = fs.readFileSync(logPath, 'utf-8').split(/\r?\n/);
        fs.writeFileSync(logPath, lines.slice(-1000).join('\n') + '\n');
      }
    } catch (e) {}
    fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${String(level).toUpperCase()}: ${message}\n`);
  } catch (e) { /* logging must never break a backup */ }
}

// Last resort: an uncaught exception used to kill the whole app —
// scheduler, tray and Cloud server included — with no message at all.
// Log it and keep running instead; the individual handlers are still
// responsible for their own errors, this only stops one bad request
// from taking everything down.
process.on('uncaughtException', (err) => {
  try {
    console.error('[Main] Uncaught exception:', err);
    appendAppLog('error', '[Main] Uncaught exception: ' + (err && err.stack ? err.stack : String(err)));
  } catch (e) { /* logging must never break the app */ }
});
process.on('unhandledRejection', (reason) => {
  try {
    console.error('[Main] Unhandled rejection:', reason);
    appendAppLog('error', '[Main] Unhandled rejection: ' + (reason && reason.stack ? reason.stack : String(reason)));
  } catch (e) { /* logging must never break the app */ }
});

function recordRun(jobName, jobRecord) {
  const key = (jobName || 'Unnamed Job').toLowerCase();
  let job = jobRecord.jobId ? jobHistory.find(j => j.id === jobRecord.jobId) : null;
  if (!job) job = jobHistory.find(j => (j.name || '').toLowerCase() === key);
  if (!job) {
    job = normalizeJobObject({ name: jobName, type: 'full', status: 'pending' });
    job.runs = [];
    jobHistory.push(job);
  }
  const run = {
    id: jobRecord.id,
    type: jobRecord.type || 'full',
    status: jobRecord.status,
    success: jobRecord.success,
    timestamp: jobRecord.timestamp,
    files: jobRecord.files,
    size: jobRecord.size,
    duration: jobRecord.duration,
    error: jobRecord.error || null,
    result: jobRecord.result || null
  };
  job.runs.push(run);
  job.runCount = job.runs.length;
  job.status = run.status;
  job.files = run.files;
  job.size = run.size;
  job.duration = run.duration;
  job.timestamp = run.timestamp;
  job.result = run.result;
  job.type = run.type === 'incremental' ? 'incremental' : 'full';
  if (jobRecord.source) job.source = jobRecord.source;
  if (jobRecord.destination) job.destination = jobRecord.destination;
  return job;
}

// Load stored jobs from disk on app start
async function loadStoredJobs() {
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  jobHistory = [];
  
  // Load job history from disk
  try {
    const historyPath = getHistoryPath();
    if (fs.existsSync(historyPath)) {
      const historyContent = fs.readFileSync(historyPath, 'utf-8');
      const history = JSON.parse(historyContent);
      if (Array.isArray(history)) {
        for (const rawJob of history) {
          const normalized = normalizeJobObject(rawJob);
          if (normalized) {
            jobHistory.push(normalized);
          } else {
            console.warn('[Main] Skipping malformed job entry in history.json:', rawJob);
          }
        }
      }
      console.log(`[Main] Loaded ${jobHistory.length} job history records on startup`);
    }
  } catch (e) {
    console.error('[Main] Failed to load job history:', e.message);
  }
  
  // Load stored job templates
  try {
    if (!fs.existsSync(jobsDir)) return;
    const files = fs.readdirSync(jobsDir);
    const jsonFiles = files.filter(f => f.endsWith('.json') && f !== 'history.json');
    for (const file of jsonFiles) {
      try {
        const content = fs.readFileSync(path.join(jobsDir, file), 'utf-8');
        const rawJob = JSON.parse(content);
        const normalized = normalizeJobObject(rawJob, 'template');
        if (normalized) {
          normalized.loaded = true;
          jobHistory.push(normalized);
          console.log(`[Main] Loaded stored job template: ${normalized.name}`);
        } else {
          console.warn(`[Main] Skipping malformed job template in ${file}:`, rawJob);
        }
      } catch (e) {
        console.error(`[Main] Failed to load job from ${file}:`, e.message);
      }
    }
    console.log(`[Main] Total jobs loaded: ${jobHistory.length}`);
  } catch (e) {
    console.error('[Main] Failed to load stored jobs:', e.message);
  }
  // Merge templates + run records so History shows one entry per job,
  // with the job's runs attached, instead of a PENDING template row
  // plus a separate row per run.
  jobHistory = mergeJobEntries(jobHistory);
  // Restore any drive-wait in progress from before the restart, so
  // its 2-hour budget continues instead of restarting.
  loadWaitingState();
}

// Save job history to disk
function saveJobHistory() {
  const historyPath = getHistoryPath();
  const jobsDir = path.dirname(historyPath);
  try {
    if (!fs.existsSync(jobsDir)) {
      fs.mkdirSync(jobsDir, { recursive: true });
    }
    // Persist runs as flat records (the on-disk history.json format),
    // one per run, so they survive a restart and merge back into their
    // job on load. Templates with no runs save nothing. Every record
    // carries its jobId: without it, a run record reloaded after a
    // restart was keyed by NAME and gave the job the RUN's id, so
    // Edit opened a blank wizard, vault lookups used the wrong id,
    // and two same-named jobs merged into one.
    const recordsToSave = [];
    for (const j of jobHistory) {
      for (const r of (j.runs || [])) {
        recordsToSave.push({
          id: r.id, jobId: j.id || r.jobId || null, name: j.name, type: r.type, status: r.status,
          success: r.success, source: j.source, destination: j.destination,
          timestamp: r.timestamp, files: r.files, size: r.size,
          duration: r.duration, error: r.error || null, result: r.result || null
        });
      }
    }
    // Atomic write: a torn history.json used to lose every run record.
    const tmpPath = historyPath + '.tmp-' + process.pid;
    fs.writeFileSync(tmpPath, JSON.stringify(recordsToSave, null, 2));
    fs.renameSync(tmpPath, historyPath);
    console.log(`[Main] Saved ${recordsToSave.length} job history records`);
  } catch (e) {
    console.error('[Main] Failed to save job history:', e.message);
  }
}

// Persist the drive-wait state so the 2-hour budget survives an app
// restart: waitingForDrive used to live only in memory, so restarting
// the app while a job was waiting reset its 2h clock to zero.
function getWaitingPath() {
  return path.join(path.dirname(getHistoryPath()), 'waiting.json');
}

function saveWaitingState() {
  try {
    const waiting = [];
    for (const j of jobHistory) {
      if (j.waitingForDrive) {
        waiting.push({
          jobId: j.id || null, name: j.name,
          since: j.waitingForDrive.since, due: j.waitingForDrive.due,
          which: j.waitingForDrive.which, path: j.waitingForDrive.path,
          label: j.waitingForDrive.label || null
        });
      }
    }
    const waitingPath = getWaitingPath();
    const tmpPath = waitingPath + '.tmp-' + process.pid;
    fs.writeFileSync(tmpPath, JSON.stringify(waiting, null, 2));
    fs.renameSync(tmpPath, waitingPath);
  } catch (e) {
    console.error('[Main] Failed to save drive-wait state:', e.message);
  }
}

function loadWaitingState() {
  try {
    const waitingPath = getWaitingPath();
    if (!fs.existsSync(waitingPath)) return;
    const waiting = JSON.parse(fs.readFileSync(waitingPath, 'utf-8'));
    if (!Array.isArray(waiting)) return;
    for (const w of waiting) {
      const job = jobHistory.find(j => (w.jobId && j.id === w.jobId) || j.name === w.name);
      if (job && w.since) {
        job.waitingForDrive = {
          since: w.since, due: w.due || null,
          which: w.which || 'source', path: w.path || null, label: w.label || null
        };
      }
    }
  } catch (e) {
    console.error('[Main] Failed to load drive-wait state:', e.message);
  }
}

function getAutoStartSetting() {
  try {
    const settingsPath = path.join(app.getPath('userData'), '.techvision', 'settings.json');
    if (fs.existsSync(settingsPath)) {
      const s = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      if (s && typeof s.autoStart === 'boolean') return s.autoStart;
    }
  } catch (e) {}
  return true; // default: start with Windows
}

function saveAutoStartSetting(value) {
  try {
    const dir = path.join(app.getPath('userData'), '.techvision');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const settingsPath = path.join(dir, 'settings.json');
    let s = {};
    try { s = JSON.parse(fs.readFileSync(settingsPath, 'utf-8')); } catch (e) {}
    s.autoStart = value;
    fs.writeFileSync(settingsPath, JSON.stringify(s, null, 2));
  } catch (e) {}
}

function applyAutoStart() {
  // Works for the installed app AND the portable exe: Electron
  // registers the current exe path in the Windows Run key, so the
  // app starts at login even when it was never installed.
  try {
    if (process.platform === 'win32' || process.platform === 'darwin') {
      app.setLoginItemSettings({ openAtLogin: getAutoStartSetting(), path: process.execPath });
    }
  } catch (e) {
    console.error('[Tray] Could not set auto-start:', e.message);
  }
}

function createTray() {
  try {
    let icon = nativeImage.createEmpty();
    if (fs.existsSync(APP_ICON)) icon = nativeImage.createFromPath(APP_ICON);
    tray = new Tray(icon);
    tray.setToolTip('TechVision Backup — running in the tray');
    const buildMenu = () => Menu.buildFromTemplate([
      { label: 'Show TechVision Backup', click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } else createMainWindow(); } },
      { type: 'separator' },
      { label: 'Start with Windows', type: 'checkbox', checked: getAutoStartSetting(), click: (item) => { saveAutoStartSetting(item.checked); applyAutoStart(); } },
      { type: 'separator' },
      { label: 'Exit', click: () => { isQuitting = true; app.quit(); } }
    ]);
    tray.setContextMenu(buildMenu());
    tray.on('click', () => {
      if (!mainWindow) { createMainWindow(); return; }
      if (mainWindow.isVisible()) mainWindow.hide(); else { mainWindow.show(); mainWindow.focus(); }
    });
    // Rebuild the menu when it opens so the checkbox reflects the setting.
    tray.on('right-click', () => tray.setContextMenu(buildMenu()));
    console.log('[Tray] System tray icon created');
  } catch (e) {
    console.error('[Tray] Could not create tray icon:', e.message);
    tray = null;
  }
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // The X button hides the window to the tray instead of quitting:
  // the app (and its scheduler) keeps running until Exit from the tray.
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createJobWizardWindow() {
  jobWizardWindow = new BrowserWindow({
    width: 780,
    height: 760,
    minWidth: 700,
    minHeight: 620,
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  jobWizardWindow.loadFile(path.join(__dirname, 'job-wizard.html'));
  jobWizardWindow.show();

  jobWizardWindow.on('closed', () => {
    jobWizardWindow = null;
  });
}

function createRestoreWindow() {
  restoreWindow = new BrowserWindow({
    width: 780,
    height: 760,
    minWidth: 700,
    minHeight: 620,
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  restoreWindow.loadFile(path.join(__dirname, 'restore-wizard.html'));
  restoreWindow.show();

  restoreWindow.on('closed', () => {
    restoreWindow = null;
  });
}

function createLogViewerWindow() {
  logViewerWindow = new BrowserWindow({
    width: 900,
    height: 650,
    icon: APP_ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  logViewerWindow.loadFile(path.join(__dirname, 'log-viewer.html'));

  logViewerWindow.on('closed', () => {
    logViewerWindow = null;
  });
}



// App lifecycle
app.whenReady().then(() => {
  migrateLegacyUserData(); // Bring old settings/jobs into the pinned folder
  loadStoredJobs(); // Load stored jobs on startup
  checkMissedSchedules(); // Email if the app was closed and a schedule was missed
  startScheduler(); // Run scheduled jobs while the app is open
  try { app.setAppUserModelId('com.techvision.backup'); } catch (e) {}
  applyAutoStart(); // Start with Windows, installed or portable
  createMainWindow();
  createTray(); // Keep running in the tray after the window closes
  // Cloud server: start it if it was left enabled — it must keep
  // serving while the app lives in the tray.
  try {
    if (getCloudConfig().server && getCloudConfig().server.enabled) {
      getCloudServer().start().catch((e) => appendAppLog('error', '[Cloud] Auto-start failed: ' + (e && e.message ? e.message : e)));
    }
    // WireGuard control channel: if the tunnel was left running
    // (server or client), the listener starts again so the other
    // gateway can wake this gateway's NAT. Best-effort — a bind
    // failure never blocks the app.
    refreshWgControl();
  } catch (e) {}

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // Do NOT quit when the window closes: the app lives in the tray
  // (and keeps running scheduled backups) until Exit from the tray.
  // Only quit if the tray could not be created at all.
  if (!tray && process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => { isQuitting = true; });

// ---------- Scheduler ----------
// The schedule a job is created with was saved but never executed:
// nothing in the app ever checked it. This timer runs while the app
// is open and fires each enabled job at its scheduled time.
function nextScheduledRun(schedule, fromDate, lastRun) {
  if (!schedule || !schedule.enabled) return null;
  const m = /^([01]?\d|2[0-3]):([0-5]\d)$/.exec(schedule.time || '02:00');
  if (!m) return null;
  const target = new Date(fromDate);
  target.setHours(parseInt(m[1], 10), parseInt(m[2], 10), 0, 0);
  const freq = (schedule.frequency || 'Daily').toLowerCase();
  if (freq === 'weekly') {
    const base = lastRun ? new Date(lastRun) : null;
    if (base && !isNaN(base)) {
      const next = new Date(base); next.setDate(next.getDate() + 7);
      next.setHours(target.getHours(), target.getMinutes(), 0, 0);
      if (next > fromDate) return next;
      return next; // due already; caller fires once then records lastScheduledRun
    }
    if (target > fromDate) return target;
    // No last run and the time already passed today: due now, like
    // daily/monthly — the old code waited a whole week for a brand
    // new weekly job whose time had passed.
    return target;
  }
  if (freq === 'custom') {
    // Custom: run on the picked weekdays (schedule.days, JS day
    // numbers 0=Sun..6=Sat) at the picked time. Scan today + the next
    // 7 days for the first picked weekday; a picked weekday today
    // whose time already passed is due now unless already run for it.
    const days = Array.isArray(schedule.days) ? schedule.days.map((d) => Number(d)).filter((d) => d >= 0 && d <= 6) : [];
    if (!days.length) return null;
    const lastDate = lastRun ? new Date(lastRun) : null;
    for (let i = 0; i < 8; i++) {
      const cand = new Date(fromDate);
      cand.setDate(cand.getDate() + i);
      if (!days.includes(cand.getDay())) continue;
      cand.setHours(target.getHours(), target.getMinutes(), 0, 0);
      if (cand > fromDate) return cand;
      if (i === 0 && (!lastDate || isNaN(lastDate) || lastDate < cand)) return cand;
    }
    return null;
  }
  // A run time that already passed TODAY is due, not tomorrow — but
  // only if we have not already run for it (lastRun at/after target).
  // This is what makes a daily/monthly job actually fire, and what
  // lets a missed job (app was closed) fire on the next tick.
  const lastDate = lastRun ? new Date(lastRun) : null;
  const alreadyRanForTarget = lastDate && !isNaN(lastDate) && lastDate >= target;
  if (freq === 'monthly') {
    if (target > fromDate) return target;
    if (!alreadyRanForTarget) return target; // due already; caller fires once then records lastScheduledRun
    // Clamp to the last day of the next month: Jan 31 + 1 month used
    // to roll over to Mar 3 (setMonth overflows the day).
    const day = target.getDate();
    target.setDate(1);
    target.setMonth(target.getMonth() + 1);
    const lastDay = new Date(target.getFullYear(), target.getMonth() + 1, 0).getDate();
    target.setDate(Math.min(day, lastDay));
    return target;
  }
  // Daily (default)
  if (target > fromDate) return target;
  if (!alreadyRanForTarget) return target; // due already
  target.setDate(target.getDate() + 1);
  return target;
}

async function executeScheduledBackup(job, resolved) {
  if (!job || !job.source || !job.destination) return;
  // Resolved paths from the drive watcher: the source may have moved
  // to another letter (same volume label), or the destination too.
  const sourcePath = (resolved && resolved.source && resolved.source.path) || job.source;
  const destPath = (resolved && resolved.destination && resolved.destination.path) || job.destination;
  if (resolved && resolved.source && resolved.source.remapped) {
    appendAppLog('info', `Job "${job.name}": source drive moved — ${job.source} is now ${sourcePath} (volume "${resolved.source.label}").`);
  }
  if (resolved && resolved.destination && resolved.destination.remapped) {
    appendAppLog('info', `Job "${job.name}": destination drive moved — ${job.destination} is now ${destPath} (volume "${resolved.destination.label}").`);
  }
  if (Array.from(activeJobs.values()).some(a => a.name === job.name && a.status === 'running')) return;
  const jobConfig = {
    name: job.name, source: sourcePath, destination: destPath,
    compress: job.compress, compression: job.compression,
    allowIncremental: job.allowIncremental, schedule: job.schedule,
    includePatterns: job.includePatterns, excludePatterns: job.excludePatterns,
    encryptionEnabled: job.encryptionEnabled === true, id: job.id
  };
  // Encrypted job, vault locked (or no password saved): the schedule
  // cannot run without the password, so skip this run. The skip used
  // to be a single console.log — invisible in the app: no log entry,
  // no history record, and lastScheduledRun never advanced, so the
  // job was retried silently on every 30-second tick forever.
  if (jobConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(jobConfig);
    if (!pw) {
      const msg = `Skipped encrypted job "${job.name}": the vault is locked or no password is saved. Unlock the vault in Settings to let scheduled encrypted backups run.`;
      console.log(`[Scheduler] ${msg}`);
      appendAppLog('warn', msg);
      recordRun(job.name, {
        id: `${job.name}-scheduled-skipped-${Date.now()}`, jobId: job.id || null, name: job.name,
        type: 'full', success: false, status: 'skipped',
        source: jobPathValue(job.source), destination: jobPathValue(job.destination),
        timestamp: new Date().toISOString(), files: 0, size: 0, duration: 0,
        error: msg, result: null
      });
      job.lastScheduledRun = new Date().toISOString();
      saveJobHistory();
      notifyJobsUpdated();
      return;
    }
    jobConfig.encryptionPassword = pw;
  }
  const useIncremental = job.allowIncremental && (job.runCount || 0) > 0;
  const jobId = `${job.name}-scheduled-${Date.now()}`;
  activeJobs.set(jobId, { name: job.name, status: 'running' });
  notifyEmail('started', { name: job.name, type: useIncremental ? 'incremental' : 'full', source: job.source, destination: job.destination });
  try {
    const engine = new BackupEngine(jobConfig);
    engine.logger = true;
    const result = useIncremental ? await engine.run_incremental_backup() : await engine.run_full_backup();
    const jobRecord = {
      id: jobId, name: job.name, type: useIncremental ? 'incremental' : 'full',
      success: result.success, status: result.success ? 'completed' : 'failed',
      source: jobPathValue(jobConfig.source), destination: jobPathValue(jobConfig.destination),
      timestamp: new Date().toISOString(), files: result.files_backed_up,
      size: result.total_bytes, duration: result.duration_seconds, result
    };
    recordRun(job.name, jobRecord);
    job.lastScheduledRun = new Date().toISOString();
    saveJobHistory();
    notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
    console.log(`[Scheduler] Scheduled backup ${useIncremental ? 'incremental' : 'full'} for ${job.name}: ${jobRecord.status}`);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('jobs-updated');
  } catch (e) {
    console.error(`[Scheduler] Scheduled backup failed for ${job.name}:`, e.message);
    const errText = e && e.message ? e.message : 'Unknown error';
    recordRun(job.name, {
      id: jobId, jobId: job.id || null, name: job.name,
      type: useIncremental ? 'incremental' : 'full', success: false, status: 'failed',
      source: jobPathValue(job.source), destination: jobPathValue(job.destination),
      timestamp: new Date().toISOString(), files: 0, size: 0, duration: 0,
      error: errText, result: null
    });
    job.lastScheduledRun = new Date().toISOString();
    saveJobHistory();
    appendAppLog('error', `Job "${job.name}" FAILED (scheduled): ${errText}`);
    notifyEmail('failed', { name: job.name, type: useIncremental ? 'incremental' : 'full', files: 0, size: 0, duration: 0, error: errText });
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('jobs-updated');
  } finally {
    activeJobs.delete(jobId);
  }
}

async function checkSchedules() {
  const now = new Date();
  for (const job of jobHistory) {
    if (!job.schedule || !job.schedule.enabled) continue;
    const next = nextScheduledRun(job.schedule, now, job.lastScheduledRun);
    if (!next) continue;
    const last = job.lastScheduledRun ? new Date(job.lastScheduledRun) : null;
    // Due when the next run time has passed and we have not already
    // fired for it (lastScheduledRun is before that run time).
    // A job already waiting for its drive stays due: the due minute
    // passes while it waits, and it must still run (or time out)
    // instead of being silently dropped until tomorrow.
    const isWaiting = !!job.waitingForDrive;
    if (!isWaiting && !(next <= now && (!last || last < next))) continue;
    // A scheduled run can take longer than the 30s tick: never start
    // the same job again while its scheduled run is still going.
    if ([...activeJobs.values()].some(function (a) { return a.name === job.name; })) continue;

    // Removable drive? Resolve source + destination: the volume may
    // have come back on another letter, or be unplugged right now.
    // A destination folder that does not exist yet is NOT a missing
    // drive — the engine creates it — so the job waits only when the
    // source is missing or the destination's drive is provably absent.
    const resolved = await resolveJobPaths(job);
    if (resolved.source.found && (resolved.destination.found || resolved.destination.drivePresent !== false)) {
      if (job.waitingForDrive) { delete job.waitingForDrive; saveWaitingState(); notifyJobsUpdated(); }
      executeScheduledBackup(job, resolved);
      continue;
    }
    const missing = !resolved.source.found ? 'source' : 'destination';
    const missingPath = !resolved.source.found ? resolved.source.path : resolved.destination.path;
    if (!job.waitingForDrive) {
      // First tick without the drive: wait for it instead of failing.
      // The scheduler retries every 30s; as soon as the disk is back
      // (any letter), the job runs.
      job.waitingForDrive = {
        since: now.toISOString(), due: next.toISOString(),
        which: missing, path: missingPath,
        label: missing === 'source' ? driveMatchLabel(job, 'source') : driveMatchLabel(job, 'destination')
      };
      saveWaitingState();
      appendAppLog('warn', `Job "${job.name}" is due but the ${missing} drive is missing (${missingPath}). Waiting for the drive — the job will run as soon as it appears.`);
      console.log(`[Scheduler] Job ${job.name} waiting for ${missing} drive: ${missingPath}`);
      notifyJobsUpdated();
      continue;
    }
    // Still waiting: give up after DRIVE_WAIT_MS, record the failure
    // and email about it — the user asked for an error, not silence.
    if (now - new Date(job.waitingForDrive.since) >= DRIVE_WAIT_MS) {
      const which = job.waitingForDrive.which || 'source';
      const errText = `${which === 'destination' ? 'Destination' : 'Source'} drive not found: ${job.waitingForDrive.path} (volume "${job.waitingForDrive.label || 'unknown'}") was not available within 2 hours of the scheduled time.`;
      const jobRecord = {
        id: `${job.name}-scheduled-${Date.now()}`, jobId: job.id || null, name: job.name,
        type: 'full', success: false, status: 'failed',
        source: jobPathValue(job.source), destination: jobPathValue(job.destination),
        timestamp: now.toISOString(), files: 0, size: 0, duration: 0,
        error: errText, result: null
      };
      recordRun(job.name, jobRecord);
      job.lastScheduledRun = now.toISOString();
      delete job.waitingForDrive;
      saveWaitingState();
      saveJobHistory();
      notifyJobsUpdated();
      notifyEmail('failed', Object.assign({}, jobRecord, { error: errText }));
      appendAppLog('error', `Job "${job.name}" FAILED: ${errText}`);
      console.log(`[Scheduler] Job ${job.name} failed: drive never appeared.`);
    }
  }
}

// Fill in a job's drive-match record for one side (source/destination)
// from the live drive list: keep the mode the wizard sent (default
// 'label'), read the label and serial automatically. A value already
// stored survives when the drive is unplugged right now.
function captureDriveMatch(jobConfig, which, drives) {
  const pathKey = which === 'source' ? 'source' : 'destination';
  const matchKey = which === 'source' ? 'sourceDriveMatch' : 'destinationDriveMatch';
  const labelKey = which === 'source' ? 'sourceVolumeLabel' : 'destinationVolumeLabel';
  const letter = driveResolver.driveLetterOf(jobPathValue(jobConfig[pathKey]));
  if (!letter) return;
  const prev = (jobConfig[matchKey] && typeof jobConfig[matchKey] === 'object') ? jobConfig[matchKey] : {};
  const mode = (prev.mode === 'letter' || prev.mode === 'serial' || prev.mode === 'label') ? prev.mode : 'label';
  const info = driveResolver.driveInfoForLetter(drives, letter);
  const match = {
    mode: mode,
    // Drive present: take what it reports right now. An empty label
    // means the volume is unlabeled — keeping the previous label
    // would leave a stale match from before a rename. A serial that
    // cannot be read right now keeps the stored one (a hardware
    // serial does not change; unreadable now is not a different disk).
    // Drive absent: keep the stored values; an edit made while the
    // drive is unplugged must not wipe the match.
    label: info ? (info.label || null) : (prev.label || null),
    serial: info ? (info.serial || prev.serial || null) : (prev.serial || null),
    serialKind: info ? (info.serialKind || prev.serialKind || null) : (prev.serialKind || null)
  };
  jobConfig[matchKey] = match;
  if (match.label) jobConfig[labelKey] = match.label;
}

// The human-readable name of a job's drive for logs and messages:
// the match record's label first, then the legacy volume label.
function driveMatchLabel(job, which) {
  const m = which === 'source' ? job.sourceDriveMatch : job.destinationDriveMatch;
  if (m && m.label) return m.label;
  return which === 'source' ? (job.sourceVolumeLabel || null) : (job.destinationVolumeLabel || null);
}

// Resolve a job's source + destination through the drive watcher.
// Returns { source: {...}, destination: {...} } per drive-resolver.
async function resolveJobPaths(job) {
  const source = await driveResolver.resolvePathAsync(jobPathValue(job.source), job.sourceDriveMatch || job.sourceVolumeLabel || null);
  const destination = await driveResolver.resolvePathAsync(jobPathValue(job.destination), job.destinationDriveMatch || job.destinationVolumeLabel || null);
  return { source: source, destination: destination };
}

// The app was closed, so scheduled backups could not run: on startup,
// find enabled schedules whose run time already passed without a run
// and email about them. Only established schedules count (jobs that
// have run at least once), so a brand-new job never spams on day one.
// The scheduler then fires the missed jobs right away.
function checkMissedSchedules() {
  try {
    const now = new Date();
    const missed = [];
    for (const job of jobHistory) {
      if (!job.schedule || !job.schedule.enabled) continue;
      if (!job.lastScheduledRun && !(job.runCount > 0)) continue;
      const next = nextScheduledRun(job.schedule, now, job.lastScheduledRun);
      if (!next) continue;
      const last = job.lastScheduledRun ? new Date(job.lastScheduledRun) : null;
      if (next <= now && (!last || last < next)) missed.push({ job: job, due: next });
    }
    if (missed.length) {
      console.log('[Mail] ' + missed.length + ' scheduled backup(s) missed while the app was closed');
      notifyEmail('missed', null, missed);
    }
  } catch (e) { console.error('[Mail] Missed-schedule check failed:', e.message); }
}

function startScheduler() {
  if (global._schedulerTimer) return;
  checkSchedules().catch(function (e) { console.error('[Scheduler] check failed:', e.message); });
  global._schedulerTimer = setInterval(function () {
    checkSchedules().catch(function (e) { console.error('[Scheduler] check failed:', e.message); });
  }, 30000);
  console.log('[Scheduler] Started (checks every 30s while the app is open)');
}

// IPC Handlers

// Backup operations
ipcMain.handle('backup-run-full', async (event, jobConfig) => {
  const jobName = jobConfig.name || `backup-${Date.now()}`;
  // Removable drive missing? Fail with a clear error (and an email)
  // instead of letting the engine fail on a path that does not exist.
  {
    const src = await driveResolver.resolvePathAsync(jobPathValue(jobConfig.source), jobConfig.sourceDriveMatch || jobConfig.sourceVolumeLabel || null);
    const dst = await driveResolver.resolvePathAsync(jobPathValue(jobConfig.destination), jobConfig.destinationDriveMatch || jobConfig.destinationVolumeLabel || null);
    const missing = !src.found ? { which: 'source', res: src } : (!dst.found ? { which: 'destination', res: dst } : null);
    if (missing) {
      const errText = `${missing.which === 'source' ? 'Source' : 'Destination'} drive not found: ${missing.res.path}` +
        (missing.res.label ? ` (volume "${missing.res.label}")` : '') + ' — plug the disk back in and run again.';
      appendAppLog('error', `Manual backup "${jobName}" FAILED: ${errText}`);
      notifyEmail('failed', { name: jobName, type: 'full', files: 0, size: 0, duration: 0, error: errText });
      return { success: false, error: 'SOURCE_DRIVE_NOT_FOUND', message: errText, name: jobName, status: 'failed', type: 'full' };
    }
    if (src.remapped) jobConfig.source = src.path;
    if (dst.remapped) jobConfig.destination = dst.path;
  }
  // Encrypted job with no password anywhere: refuse up front instead
  // of starting a backup that cannot be written.
  if (jobConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(jobConfig);
    if (!pw) return { success: false, error: 'ENCRYPTION_PASSWORD_REQUIRED', name: jobName, status: 'failed', type: 'full' };
    jobConfig.encryptionPassword = pw;
  }
  // Never run the same job twice at once (manual + scheduled, or a
  // double-click): two engines would write the same backup folder
  // and the same state file.
  for (const [, a] of activeJobs) {
    if (a.name === jobName || (jobConfig.id && a.jobId === jobConfig.id)) {
      return { success: false, error: 'ALREADY_RUNNING', message: `A backup of "${jobName}" is already running.`, name: jobName, status: 'failed', type: 'full' };
    }
  }
  const engine = new BackupEngine(jobConfig);

  // Real progress for the window that started the run: the renderer
  // used to fake the bar (raced to 92% and froze). The engine now
  // reports real bytes; forward them as they arrive.
  engine.onProgress = (p) => {
    try { if (event.sender && !event.sender.isDestroyed()) event.sender.send('backup-progress', p); } catch (e) {}
  };

  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, jobId: jobConfig.id || null, status: 'running' });

  notifyEmail('started', { name: jobName, type: 'full', source: jobPathValue(jobConfig.source), destination: jobPathValue(jobConfig.destination) });

  engine.logger = true; // Enable logging

  // The engine returns failed results instead of throwing, but a
  // setup failure (bad destination, engine bug) must still be
  // recorded as a failed run — not an unhandled IPC rejection with
  // no history entry and no email.
  let result;
  try {
    result = await engine.run_full_backup();
  } catch (e) {
    result = { success: false, files_backed_up: 0, total_bytes: 0, duration_seconds: 0, error_messages: [e.message], backup_path: '' };
    appendAppLog('error', `Manual backup "${jobName}" FAILED: ${e.message}`);
  }
  
  const jobRecord = {
    id: jobId,
    jobId: jobConfig.id || null,
    name: jobName,
    type: 'full',
    success: result.success,
    status: result.success ? 'completed' : 'failed',
    source: jobPathValue(jobConfig.source),
    destination: jobPathValue(jobConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result
  };

  recordRun(jobName, jobRecord);
  saveJobHistory();
  notifyJobsUpdated();
  activeJobs.delete(jobId);

  // The run used a password the user typed: if the vault is unlocked,
  // save it there (encrypted) so scheduled runs of this job work too.
  // A failed store used to be swallowed silently — the job looked
  // encrypted while no password was stored, so scheduled runs were
  // then skipped with no explanation.
  if (jobRecord.success && jobConfig.encryptionEnabled && vaultKey && jobConfig.id && jobConfig.encryptionPassword) {
    try { vault.storeJobPassword(app.getPath('userData'), vaultKey, jobConfig.id, jobConfig.encryptionPassword); } catch (e) { appendAppLog('error', `Could not store the password for job "${jobName}" in the vault: ${e.message}. Scheduled encrypted backups of this job will be skipped until the password is stored.`); }
  }
  notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
  console.log(`[Main] Backup completed: ${jobName}, saved to history`);
  return jobRecord;
});

ipcMain.handle('backup-run-incremental', async (event, jobConfig) => {
  const jobName = jobConfig.name || `incremental-${Date.now()}`;
  {
    const src = await driveResolver.resolvePathAsync(jobPathValue(jobConfig.source), jobConfig.sourceDriveMatch || jobConfig.sourceVolumeLabel || null);
    const dst = await driveResolver.resolvePathAsync(jobPathValue(jobConfig.destination), jobConfig.destinationDriveMatch || jobConfig.destinationVolumeLabel || null);
    const missing = !src.found ? { which: 'source', res: src } : (!dst.found ? { which: 'destination', res: dst } : null);
    if (missing) {
      const errText = `${missing.which === 'source' ? 'Source' : 'Destination'} drive not found: ${missing.res.path}` +
        (missing.res.label ? ` (volume "${missing.res.label}")` : '') + ' — plug the disk back in and run again.';
      appendAppLog('error', `Manual incremental backup "${jobName}" FAILED: ${errText}`);
      notifyEmail('failed', { name: jobName, type: 'incremental', files: 0, size: 0, duration: 0, error: errText });
      return { success: false, error: 'SOURCE_DRIVE_NOT_FOUND', message: errText, name: jobName, status: 'failed', type: 'incremental' };
    }
    if (src.remapped) jobConfig.source = src.path;
    if (dst.remapped) jobConfig.destination = dst.path;
  }
  if (jobConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(jobConfig);
    if (!pw) return { success: false, error: 'ENCRYPTION_PASSWORD_REQUIRED', name: jobName, status: 'failed', type: 'incremental' };
    jobConfig.encryptionPassword = pw;
  }
  // Never run the same job twice at once (see the full backup).
  for (const [, a] of activeJobs) {
    if (a.name === jobName || (jobConfig.id && a.jobId === jobConfig.id)) {
      return { success: false, error: 'ALREADY_RUNNING', message: `A backup of "${jobName}" is already running.`, name: jobName, status: 'failed', type: 'incremental' };
    }
  }
  const engine = new BackupEngine(jobConfig);

  // Real progress for the window that started the run (see full backup).
  engine.onProgress = (p) => {
    try { if (event.sender && !event.sender.isDestroyed()) event.sender.send('backup-progress', p); } catch (e) {}
  };

  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, jobId: jobConfig.id || null, status: 'running' });
  notifyEmail('started', { name: jobName, type: 'incremental', source: jobPathValue(jobConfig.source), destination: jobPathValue(jobConfig.destination) });

  engine.logger = true;

  let result;
  try {
    result = await engine.run_incremental_backup();
  } catch (e) {
    result = { success: false, files_backed_up: 0, total_bytes: 0, duration_seconds: 0, error_messages: [e.message], backup_path: '' };
    appendAppLog('error', `Manual incremental backup "${jobName}" FAILED: ${e.message}`);
  }
  
  const jobRecord = {
    id: jobId,
    jobId: jobConfig.id || null,
    name: jobName,
    type: 'incremental',
    success: result.success,
    status: result.success ? 'completed' : 'failed',
    source: jobPathValue(jobConfig.source),
    destination: jobPathValue(jobConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result
  };
  
  recordRun(jobName, jobRecord);
  saveJobHistory();
  notifyJobsUpdated();
  activeJobs.delete(jobId);

  if (jobRecord.success && jobConfig.encryptionEnabled && vaultKey && jobConfig.id && jobConfig.encryptionPassword) {
    try { vault.storeJobPassword(app.getPath('userData'), vaultKey, jobConfig.id, jobConfig.encryptionPassword); } catch (e) { appendAppLog('error', `Could not store the password for job "${jobName}" in the vault: ${e.message}. Scheduled encrypted backups of this job will be skipped until the password is stored.`); }
  }
  notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
  console.log(`[Main] Incremental backup completed: ${jobName}`);
  return jobRecord;
});

// Restore operations
ipcMain.handle('restore-all', async (event, zipPath, restoreDir, password) => {
  try {
    const restoreEngine = new RestoreEngine();
    const result = await restoreEngine.restore_all(zipPath, restoreDir, password || null);
    // restore_all reports failures in its result object instead of
    // throwing (wrong password, hash mismatch) — honour it, or a
    // failed restore would be reported as success. Its counters are
    // files_restored/total_bytes, not files/size.
    if (result && result.success === false) {
      return { success: false, error: (result.errors && result.errors[0]) || 'Restore failed.' };
    }
    return { success: true, files: (result && result.files_restored) || 0, size: (result && result.total_bytes) || 0 };
  } catch (err) {
    return { success: false, error: err && err.message ? err.message : String(err) };
  }
});

ipcMain.handle('restore-single', async (event, zipPath, entryName, destPath, password) => {
  try {
    const restoreEngine = new RestoreEngine();
    const result = await restoreEngine.restoreFile(zipPath, entryName, destPath, password || null);
    return { success: true, files: result && result.files ? result.files : 0 };
  } catch (err) {
    return { success: false, error: err && err.message ? err.message : String(err) };
  }
});

// File operations
// Use the window that actually called the dialog as its parent.
// Also check for active wizard windows which might be the callers.
function dialogParentWindow(event) {
  try {
    const callerWindow = event && event.sender && BrowserWindow.fromWebContents(event.sender);
    // Return the calling window if found, otherwise try wizard windows, finally mainWindow
    return callerWindow || jobWizardWindow || restoreWindow || mainWindow;
  } catch (e) {
    return jobWizardWindow || mainWindow;
  }
}

ipcMain.handle('dialog-showOpenDialog', async (event, options) => {
  try {
    const result = await dialog.showOpenDialog(dialogParentWindow(event), options);
    return result;
  } catch (e) {
    console.error('[Main] showOpenDialog failed:', e.message);
    return { canceled: true, filePaths: [], error: e.message };
  }
});

ipcMain.handle('dialog-showSaveDialog', async (event, options) => {
  try {
    const result = await dialog.showSaveDialog(dialogParentWindow(event), options);
    return result;
  } catch (e) {
    console.error('[Main] showSaveDialog failed:', e.message);
    return { canceled: true, filePath: '', error: e.message };
  }
});

ipcMain.handle('fs-readdir', async (event, dirPath) => {
  try {
    const items = fs.readdirSync(dirPath, { withFileTypes: true });
    return items.map(item => ({
      name: item.name,
      isDirectory: item.isDirectory(),
      isFile: item.isFile()
    }));
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('fs-stat', async (event, filePath) => {
  try {
    const stats = fs.statSync(filePath);
    return {
      size: stats.size,
      mtime: stats.mtime,
      isDirectory: stats.isDirectory(),
      isFile: stats.isFile()
    };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('fs-mkdir', async (event, dirPath, recursive = true) => {
  try {
    fs.mkdirSync(dirPath, { recursive });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('fs-read-file', async (event, filePath) => {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return { success: true, content };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('fs-write-file', async (event, filePath, content) => {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, content);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('fs-delete', async (event, filePath) => {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      return { success: true };
    }
    return { success: false, error: 'File not found' };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('fs-exists', async (event, filePath) => {
  return { exists: fs.existsSync(filePath) };
});

// ZIP operations
ipcMain.handle('zip-get-info', async (event, zipPath) => {
  // This is handled by the restore engine's getZipInfo method
  const { RestoreEngine } = require('./restore.js');
  const engine = new RestoreEngine();
  try {
    const entries = await engine.getZipInfo(zipPath);
    return { success: true, entries };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// Job management
ipcMain.handle('job-get-all', async () => {
  return jobHistory;
});

ipcMain.handle('job-get-active', async () => {
  return Array.from(activeJobs.values());
});

ipcMain.handle('job-clear-history', async () => {
  jobHistory.length = 0;
  // Persist the clear: before this, the in-memory list was emptied but
  // history.json was never rewritten, so all the history came back
  // after a restart. Job definition files (<id>.json) are untouched,
  // so the jobs themselves survive — only their run history is gone.
  saveJobHistory();
  notifyJobsUpdated();
  return { success: true };
});

ipcMain.handle('job-get-config', async (event, jobId) => {
  if (!jobId || jobId === 'null' || jobId === 'undefined') {
    // Edit opened the wizard with a job object: the wizard asks for the
    // config with no id, so hand it the pending job instead of null.
    const pending = pendingRestoreJob || pendingWizardJob;
    pendingWizardJob = null;
    pendingRestoreJob = null;
    if (pending) return pending;
  }
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  const jobPath = path.join(jobsDir, `${jobId}.json`);
  try {
    if (fs.existsSync(jobPath)) {
      const content = fs.readFileSync(jobPath, 'utf-8');
      return JSON.parse(content);
    }
    // Old configs were saved by name (<name>.json), not by id.
    if (typeof jobId === 'string' && jobId.startsWith('job-')) {
      const byName = path.join(jobsDir, `${jobId.slice(4)}.json`);
      if (fs.existsSync(byName)) return JSON.parse(fs.readFileSync(byName, 'utf-8'));
    }
    return null;
  } catch (e) {
    return null;
  }
});

// Drive list for the job wizard: the wizard shows how each drive can
// be found again (by name / letter / serial) after Browse picks a path.
ipcMain.handle('get-drives', async () => {
  try { return await driveResolver.listDrives(); } catch (e) { return []; }
});

ipcMain.handle('job-save-config', async (event, jobConfig) => {
  // A job password must never reach disk in a job file: strip every
  // password field before writing, whatever the caller sent.
  if (jobConfig) {
    delete jobConfig.encryptionPassword;
    if (jobConfig.encryption && typeof jobConfig.encryption === 'object') delete jobConfig.encryption.password;
    delete jobConfig.password;
  }
  // Removable drives: remember HOW to find the source/destination
  // drive again — by name, by letter, or by serial number. The wizard
  // sends the mode the user picked; the label and serial are read
  // here from the live drive list, so the user never types a serial.
  // Only set when the drive is actually present right now; a stored
  // value survives an edit made while the drive is unplugged.
  try {
    const drives = await driveResolver.listDrives();
    if (jobConfig) {
      captureDriveMatch(jobConfig, 'source', drives);
      captureDriveMatch(jobConfig, 'destination', drives);
    }
  } catch (e) { /* match info stays as it was; literal paths still work */ }
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  if (!fs.existsSync(jobsDir)) {
    fs.mkdirSync(jobsDir, { recursive: true });
  }
  const fileId = jobConfig.id || ('job-' + jobConfig.name);
  jobConfig.id = fileId;
  const jobPath = path.join(jobsDir, `${fileId}.json`);
  try {
    // Atomic write: a torn job file used to load as a corrupt template
    // (or fail to load at all) after a crash mid-save.
    const tmpPath = jobPath + '.tmp-' + process.pid;
    fs.writeFileSync(tmpPath, JSON.stringify(jobConfig, null, 2));
    fs.renameSync(tmpPath, jobPath);
    // Migration: old configs were saved by name (<name>.json). If one
    // exists for this job, remove it so it is not loaded as a second job.
    const oldNamePath = path.join(jobsDir, `${jobConfig.name}.json`);
    if (oldNamePath !== jobPath && fs.existsSync(oldNamePath)) {
      try { fs.unlinkSync(oldNamePath); } catch (e) {}
    }
    console.log(`[Main] Job saved to: ${jobPath}`);
    // The template only entered the list on the next startup before:
    // add it to the in-memory history now so Create Job shows it at once.
    const tpl = normalizeJobObject(Object.assign({}, jobConfig, {
      id: jobConfig.id || ('job-' + jobConfig.name),
      type: 'TEMPLATE', status: 'PENDING', loaded: true
    }));
    if (tpl) {
      let existing = jobHistory.findIndex(j => j.id === tpl.id);
      if (existing < 0) existing = jobHistory.findIndex(j => j.loaded && j.name === tpl.name);
      if (existing >= 0) {
        // Keep the job's run history: a re-save must not wipe its runs.
        tpl.runs = jobHistory[existing].runs || [];
        tpl.runCount = tpl.runs.length;
        if (tpl.runs.length) {
          const last = tpl.runs[tpl.runs.length - 1];
          // The job already ran: it is a FULL/INCREMENTAL job with a
          // COMPLETED status, not a TEMPLATE. Leaving type TEMPLATE
          // here showed the contradictory "TEMPLATE / COMPLETED".
          tpl.type = last.type === 'incremental' ? 'incremental' : 'full';
          tpl.status = last.status; tpl.files = last.files; tpl.size = last.size;
          tpl.duration = last.duration; tpl.timestamp = last.timestamp; tpl.result = last.result;
        }
        jobHistory[existing] = tpl;
      } else jobHistory.push(tpl);
    }
    notifyJobsUpdated();
    return { success: true, path: jobPath };
  } catch (e) {
    console.error(`[Main] Failed to save job config:`, e.message);
    return { success: false, error: e.message };
  }
});

ipcMain.handle('job-list-stored', async () => {
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  try {
    if (!fs.existsSync(jobsDir)) return [];
    const files = fs.readdirSync(jobsDir);
    return files.filter(f => f.endsWith('.json') && f !== 'history.json').map(f => {
      const content = fs.readFileSync(path.join(jobsDir, f), 'utf-8');
      return JSON.parse(content);
    });
  } catch (e) {
    return [];
  }
});

// Window management
ipcMain.handle('window-show-job-wizard', async (event, job) => {
  if (job && typeof job === 'object') pendingWizardJob = job;
  if (!jobWizardWindow) {
    createJobWizardWindow();
  } else {
    // Reload so the wizard always starts fresh: current saved theme,
    // empty fields, and freshly wired buttons (a re-shown window kept
    // the old page, old theme and stale state).
    jobWizardWindow.loadFile(path.join(__dirname, 'job-wizard.html'));
    jobWizardWindow.show();
  }
  return { success: true };
});

ipcMain.handle('window-show-restore-wizard', async (event, job) => {
  if (job && typeof job === 'object') pendingRestoreJob = job;
  if (!restoreWindow) {
    createRestoreWindow();
  } else {
    restoreWindow.loadFile(path.join(__dirname, 'restore-wizard.html'));
    restoreWindow.show();
  }
  return { success: true };
});

ipcMain.handle('window-show-log-viewer', async () => {
  if (!logViewerWindow) {
    createLogViewerWindow();
  } else {
    logViewerWindow.show();
  }
  return { success: true };
});

// Close window handlers
ipcMain.handle('window-close-job-wizard', async () => {
  if (jobWizardWindow) {
    jobWizardWindow.close();
  }
  return { success: true };
});

ipcMain.handle('window-close-restore-wizard', async () => {
  if (restoreWindow) {
    restoreWindow.close();
  }
  return { success: true };
});

ipcMain.handle('window-close-log-viewer', async () => {
  if (logViewerWindow) {
    logViewerWindow.close();
  }
  return { success: true };
});

// Log retrieval
ipcMain.handle('log-get-recent', async () => {
  const logDir = path.join(app.getPath('userData'), '.techvision', 'logs');
  try {
    if (!fs.existsSync(logDir)) return [];
    const files = fs.readdirSync(logDir)
      .filter(f => f.endsWith('.log'))
      .map(f => ({ name: f, path: path.join(logDir, f) }));
    
    if (files.length === 0) return [];
    
    // Get most recent
    const mostRecent = files.reduce((a, b) => {
      const aStat = fs.statSync(a.path);
      const bStat = fs.statSync(b.path);
      return aStat.mtime > bStat.mtime ? a : b;
    });
    
    // Read content and return as array of lines
    const content = fs.readFileSync(mostRecent.path, 'utf-8');
    return content.split(/\r?\n/).filter(l => l.trim());
  } catch (e) {
    console.error('[Main] log-get-recent error:', e);
    return [];
  }
});

// Full app log for the Logs view: the central app.log, newest last.
ipcMain.handle('logs-get', async () => {
  try {
    const logPath = path.join(app.getPath('userData'), '.techvision', 'app.log');
    if (!fs.existsSync(logPath)) return { success: true, lines: [] };
    const content = fs.readFileSync(logPath, 'utf-8');
    const lines = content.split(/\r?\n/).filter(function (l) { return l.trim().length > 0; });
    return { success: true, lines: lines.slice(-500) };
  } catch (e) {
    return { success: false, error: e.message, lines: [] };
  }
});

// Refresh jobs
ipcMain.handle('jobs-refresh', async (event, jobs) => {
  if (!Array.isArray(jobs)) {
    // If jobs parameter is not an array, keep existing jobHistory
    console.log('[Main] jobs-refresh called without valid jobs array, keeping existing history');
    return { success: true };
  }
  jobHistory.length = 0;
  jobHistory.push(...jobs);
  console.log(`[Main] Refreshed ${jobs.length} jobs`);
  return { success: true };
});

// Settings
ipcMain.handle('settings-get', async () => {
  const settingsPath = path.join(app.getPath('userData'), '.techvision', 'settings.json');
  try {
    if (fs.existsSync(settingsPath)) {
      return JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    }
  } catch (e) {}
  return {
    theme: 'dark',
    language: 'en',
    defaultBackupLocation: app.getPath('documents')
  };
});

ipcMain.handle('settings-save', async (event, settings) => {
  const settingsDir = path.join(app.getPath('userData'), '.techvision');
  if (!fs.existsSync(settingsDir)) {
    fs.mkdirSync(settingsDir, { recursive: true });
  }
  const settingsPath = path.join(settingsDir, 'settings.json');
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  // Apply Start-with-Windows right away: saving the setting must
  // register/unregister the app at login without needing a restart.
  applyAutoStart();
  return { success: true };
});

// Send a test notification with the saved email settings.
ipcMain.handle('email-test', async () => {
  const r = await mailer.sendMail(app.getPath('userData'),
    'Test email from TechVision Backup',
    'This is a test notification from TechVision Backup.\n\nIf you got this, email notifications are set up correctly.\nTime: ' + new Date().toLocaleString());
  return { success: r.sent, error: r.sent ? undefined : r.reason };
});

// Master-password vault: the key lives in memory only while unlocked.
ipcMain.handle('vault-status', async () => {
  return { exists: vault.vaultExists(app.getPath('userData')), locked: vaultKey === null };
});
ipcMain.handle('vault-setup', async (event, masterPassword) => {
  try {
    vaultKey = vault.setupVault(app.getPath('userData'), masterPassword);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});
ipcMain.handle('vault-unlock', async (event, masterPassword) => {
  try {
    vaultKey = vault.unlockVault(app.getPath('userData'), masterPassword);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});
ipcMain.handle('vault-lock', async () => {
  if (vaultKey) vault.lockVault(vaultKey);
  vaultKey = null;
  return { success: true };
});

// ---------- TechVision Cloud ----------
// Config + server status. Passwords and the server private key never
// leave main; the renderer only sees public config and user names.
/* The Cloud access mode: how the client reaches the server.
   'normal' = the public address/DDNS + one forwarded port;
   'tailscale' = the Tailscale IP + port, no forwarding; 'wireguard'
   = the WireGuard tunnel address (10.0.0.x) + port, no forwarding
   (the one UDP 51820 forward that brings the tunnel up covers
   everything inside it). Anything else normalises to 'normal' —
   old records that predate the modes have no field at all. */
function cloudAccessMode(v) {
  if (v === 'tailscale') return 'tailscale';
  if (v === 'wireguard') return 'wireguard';
  return 'normal';
}
ipcMain.handle('cloud-get-config', async () => {
  const cfg = getCloudConfig();
  const srv = getCloudServer();
  return {
    server: {
      enabled: !!cfg.server.enabled,
      port: cfg.server.port || 8443,
      running: srv.isRunning(),
      users: srv.listUsers(),
      fingerprint: cfg.server.cert ? cfg.server.cert.fingerprint : null,
      accessMode: cloudAccessMode(cfg.server.accessMode),
    },
    clients: (cfg.clients || []).map((c) => ({ id: c.id, name: c.name, host: c.host, port: c.port, user: c.user, fingerprint: c.fingerprint || null, hasPassword: !!c.password, accessMode: cloudAccessMode(c.accessMode) })),
  };
});

ipcMain.handle('cloud-detect-ip', async () => {
  const [publicIP, lanIPs] = await Promise.all([
    cloudServerMod.detectPublicIP(),
    Promise.resolve(cloudServerMod.lanIPs()),
  ]);
  return { publicIP, lanIPs };
});

ipcMain.handle('cloud-server-save', async (event, opts) => {
  const cfg = getCloudConfig();
  const port = parseInt(opts && opts.port, 10);
  if (!port || port < 1 || port > 65535) return { success: false, error: 'Port must be between 1 and 65535.' };
  const wasRunning = getCloudServer().isRunning();
  const portChanged = cfg.server.port !== port;
  const accessMode = cloudAccessMode(opts && opts.accessMode);
  cfg.server.enabled = !!(opts && opts.enabled);
  cfg.server.port = port;
  cfg.server.accessMode = accessMode;
  saveCloudConfig();
  try {
    if (wasRunning && portChanged) {
      await getCloudServer().stop();
      if (cfg.server.enabled) await getCloudServer().start();
    } else if (cfg.server.enabled && !wasRunning) {
      await getCloudServer().start();
    } else if (!cfg.server.enabled && wasRunning) {
      await getCloudServer().stop();
    }
  } catch (e) {
    // The server is down: do not leave enabled=true in the config.
    try { cfg.server.enabled = false; saveCloudConfig(); } catch (_) {}
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
  return { success: true, status: getCloudServer().status() };
});

ipcMain.handle('cloud-server-start', async () => {
  try {
    const cfg = getCloudConfig();
    cfg.server.enabled = true;
    saveCloudConfig();
    const status = await getCloudServer().start();
    return { success: true, status };
  } catch (e) {
    // Do not leave enabled=true in the config when the server is
    // actually down — the next launch would fail the same way.
    try { const cfg = getCloudConfig(); cfg.server.enabled = false; saveCloudConfig(); } catch (_) {}
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-server-stop', async () => {
  try {
    const cfg = getCloudConfig();
    cfg.server.enabled = false;
    saveCloudConfig();
    return { success: true, status: await getCloudServer().stop() };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-user-add', async (event, u) => {
  try {
    const user = getCloudServer().addUser(u.name, u.password, u.root, u.canWrite);
    return { success: true, user };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-user-remove', async (event, name) => {
  try {
    getCloudServer().removeUser(name);
    return { success: true };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-user-set-password', async (event, name, password) => {
  try {
    getCloudServer().setUserPassword(name, password);
    return { success: true };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Saved servers (client side). The password for a server IS stored on
// this device, in cloud.json next to the server record — the user asked
// for one-click reconnect instead of typing it every time (same choice
// as the SMTP password in settings.json). It never leaves main: the
// renderer only sees hasPassword, and connect uses the stored password
// when none is typed. Remove it any time with "Forget saved password"
// on the server card; changing the password on the server just means
// the next connect asks for the new one.
ipcMain.handle('cloud-client-save', async (event, s) => {
  try {
    const cfg = getCloudConfig();
    const host = String(s.host || '').trim();
    const port = parseInt(s.port, 10);
    if (!host) return { success: false, error: 'Server address is required.' };
    if (!port || port < 1 || port > 65535) return { success: false, error: 'Port must be between 1 and 65535.' };
    const id = s.id || ('srv-' + Date.now());
    // Same host + port + user is the same server: update it in place
    // instead of adding a duplicate row every time it is saved again.
    let i = cfg.clients.findIndex((c) => c.id === id);
    if (i < 0) i = cfg.clients.findIndex((c) => c.host === host && c.port === port && c.user === String(s.user || ''));
    const existing = i >= 0 ? cfg.clients[i] : null;
    // Keep the saved access mode when the caller did not send one
    // (e.g. the trust flow): a Tailscale or WireGuard server must
    // not silently become Normal on re-save.
    const accessMode = s.accessMode ? cloudAccessMode(s.accessMode)
      : (existing ? cloudAccessMode(existing.accessMode) : 'normal');
    const rec = { id, name: String(s.name || host), host, port, user: String(s.user || ''), fingerprint: s.fingerprint || null, certPem: s.certPem || null, accessMode, password: (s.password && String(s.password)) || (existing && existing.password) || null };
    if (i >= 0) { rec.id = cfg.clients[i].id; if (!rec.fingerprint) rec.fingerprint = cfg.clients[i].fingerprint; if (!rec.certPem) rec.certPem = cfg.clients[i].certPem; cfg.clients[i] = rec; }
    else cfg.clients.push(rec);
    saveCloudConfig();
    // Return the id the record is actually stored under: on an
    // update-in-place that is the pre-existing id, NOT the fresh
    // 'srv-…' id generated above — callers (connect, join) look the
    // record up by the returned id, and a wrong one made reconnects
    // fail with "Password needed" on every re-save.
    return { success: true, id: rec.id };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-client-forget-password', async (event, id) => {
  const cfg = getCloudConfig();
  const rec = (cfg.clients || []).find((c) => c.id === id);
  if (!rec) return { success: false, error: 'Server not found.' };
  rec.password = null;
  saveCloudConfig();
  return { success: true };
});

ipcMain.handle('cloud-client-remove', async (event, id) => {
  const cfg = getCloudConfig();
  cfg.clients = cfg.clients.filter((c) => c.id !== id);
  cloudSessions.delete(id);
  saveCloudConfig();
  return { success: true };
});

// First contact: read the presented certificate (nothing sensitive sent).
ipcMain.handle('cloud-client-probe', async (event, host, port) => {
  try {
    const p = await cloudClient.probeServer(String(host), parseInt(port, 10));
    return { success: true, fingerprint: p.fingerprint, certPem: p.certPem };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

/* WireGuard tunnel check for a Cloud server record in 'wireguard'
   mode: the tunnel must actually be up between the two machines
   before any connection is attempted, or the login would wait out
   the 15s probe timeout and fail with a network error. Server role:
   the record's host must be a live peer (a recent handshake);
   client role: the client must be online and the host must be the
   server's tunnel address (.1 of the tunnel subnet). */
async function wgTunnelToPeerCheck(host) {
  try {
    const st = await wireguard.getStatus();
    const c = getWgConfig();
    const liveServerPeers = (st.server && Array.isArray(st.server.peers)) ? st.server.peers : [];
    const livePeer = liveServerPeers.find((p) => {
      const cfgPeer = (c.server.peers || []).find((x) => x.publicKey === p.publicKey);
      return cfgPeer && cfgPeer.tunnelIp === host;
    });
    if (livePeer) {
      if (livePeer.latestHandshake) return { ok: true };
      return { ok: false, error: 'The WireGuard tunnel to ' + host + ' is not up — the peer is known but has not handshaken yet. Start the server on the other machine and check it connects.' };
    }
    const liveClientPeer = (st.client && Array.isArray(st.client.peers) && st.client.peers[0]) || null;
    if (c.client && c.client.tunnelIp && liveClientPeer && liveClientPeer.latestHandshake) {
      const serverIp = wireguard.serverTunnelIpFor(wireguard.tunnelSubnetFor(c.client.tunnelIp));
      if (host === serverIp) return { ok: true };
      return { ok: false, error: 'The WireGuard tunnel is up, but the server address ' + host + ' is not the tunnel server (' + serverIp + '). Pick the server from the WireGuard peer list.' };
    }
    return { ok: false, error: 'The WireGuard tunnel is not up — connect the WireGuard client (or start the server) first, then connect to the Cloud server.' };
  } catch (e) {
    return { ok: false, error: 'Could not check the WireGuard tunnel: ' + (e && e.message ? e.message : String(e)) };
  }
}

ipcMain.handle('cloud-client-connect', async (event, opts) => {
  try {
    // No password typed: use the one saved for this server, so a
    // reconnect is one click. A password the user types wins, and a
    // successful login with it remembers it for next time.
    const cfg = getCloudConfig();
    const rec = (cfg.clients || []).find((c) => c.id === opts.serverId);
    const password = (opts.password && String(opts.password)) || (rec && rec.password) || '';
    if (!password) return { success: false, error: 'Password needed — enter the password for user ' + (opts.user || '') + '.' };
    /* WireGuard mode: the tunnel has to be up first — a down tunnel
       fails fast here with a clear message instead of waiting out
       the 15s probe timeout. The renderer pre-checks the same way
       before probing an untrusted server. */
    if (rec && cloudAccessMode(rec.accessMode) === 'wireguard') {
      const check = await wgTunnelToPeerCheck(String(opts.host || '').trim());
      if (!check.ok) return { success: false, error: check.error };
    }
    const conn = await cloudClient.login(opts.host, parseInt(opts.port, 10), opts.certPem, opts.user, password);
    const info = await cloudClient.info(conn);
    cloudSessions.set(opts.serverId, Object.assign({}, conn, { user: info.user, root: info.root, canWrite: info.canWrite }));
    if (rec && opts.password && String(opts.password)) { rec.password = String(opts.password); saveCloudConfig(); }
    return { success: true, info };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-client-disconnect', async (event, serverId) => {
  const conn = cloudSessions.get(serverId);
  if (conn) {
    try { await cloudClient.logout(conn); } catch (e) { /* local drop is enough */ }
  }
  cloudSessions.delete(serverId);
  return { success: true };
});

ipcMain.handle('cloud-client-list', async (event, serverId, relPath) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.', code: 'auth' };
  try {
    const r = await cloudClient.list(conn, relPath || '');
    return { success: true, path: r.path, entries: r.entries };
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    // The auto-refresh poller needs to tell "server gone" from
    // "session dead" from "something else", without parsing toasts.
    const code = /Not signed in/i.test(msg) ? 'auth'
      : /Cannot reach the server|did not answer in time|ECONNREFUSED|ENOTFOUND|socket hang up|certificate/i.test(msg) ? 'unreachable'
      : 'other';
    return { success: false, error: msg, code };
  }
});

ipcMain.handle('cloud-client-download', async (event, serverId, relPath, destDir) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  const dest = path.join(destDir, path.basename(relPath));
  try {
    const r = await cloudClient.download(conn, relPath, dest, (done, total) => {
      try {
        if (event.sender && !event.sender.isDestroyed()) {
          event.sender.send('cloud-progress', { kind: 'download', pct: total ? Math.min(99, 99 * done / total) : 0, done, total, name: path.basename(relPath) });
        }
      } catch (e) {}
    });
    return { success: true, dest, size: r.size };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-client-upload', async (event, serverId, localPath, remoteDir) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try {
    const r = await cloudClient.upload(conn, localPath, remoteDir || '', (sent, total) => {
      try {
        if (event.sender && !event.sender.isDestroyed()) {
          event.sender.send('cloud-progress', { kind: 'upload', pct: total ? Math.min(99, 99 * sent / total) : 0, done: sent, total, name: path.basename(localPath) });
        }
      } catch (e) {}
    });
    return { success: true, name: r.name };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-client-mkdir', async (event, serverId, relPath) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try { await cloudClient.mkdir(conn, relPath); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : String(e) }; }
});

ipcMain.handle('cloud-client-delete', async (event, serverId, relPath) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try { await cloudClient.remove(conn, relPath); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : String(e) }; }
});

ipcMain.handle('cloud-client-rename', async (event, serverId, from, to) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try { await cloudClient.rename(conn, from, to); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : String(e) }; }
});

ipcMain.handle('cloud-client-copy', async (event, serverId, from, to) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try { await cloudClient.copy(conn, from, to); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : String(e) }; }
});

// Files the user copied in Windows Explorer: the clipboard holds them
// as a "FileNameW" list of local paths. The renderer asks for that list
// when pasting, so a copy in Explorer can land on the server.
ipcMain.handle('cloud-clipboard-files', async () => {
  try {
    const buf = require('electron').clipboard.readBuffer('FileNameW');
    return cloudClient.parseClipboardFiles(buf);
  } catch (e) { return []; }
});

// Upload local paths (files and folders) into a remote folder — the
// other half of pasting from Windows Explorer.
ipcMain.handle('cloud-client-upload-files', async (event, serverId, localPaths, remoteDir) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try {
    const r = await cloudClient.uploadPaths(conn, localPaths || [], remoteDir || '', (name, sent, total) => {
      try {
        if (event.sender && !event.sender.isDestroyed()) {
          event.sender.send('cloud-progress', { kind: 'upload', pct: total ? Math.min(99, 99 * sent / total) : 0, done: sent, total, name });
        }
      } catch (e) {}
    });
    return { success: true, uploaded: r.uploaded, failed: r.failed || [] };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Open a server file with the app Windows would use for it: download a
// copy into the temp folder and hand it to the OS (music plays, pictures
// open, a game runs). The copy lives in the temp folder, so editing it
// does NOT write back to the server — that needs the file mounted as a
// real drive, which is a separate feature.
ipcMain.handle('cloud-client-open', async (event, serverId, relPath) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  const tmpRoot = path.join(os.tmpdir(), 'TechVision-Cloud');
  try { fs.mkdirSync(tmpRoot, { recursive: true }); } catch (e) {}
  // Best-effort cleanup of opened copies older than 7 days, so the temp
  // folder does not grow forever. Never fails the open.
  try {
    const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
    for (const f of fs.readdirSync(tmpRoot)) {
      try {
        const p = path.join(tmpRoot, f);
        const st = fs.statSync(p);
        if (st.isFile() && st.mtimeMs < cutoff) fs.unlinkSync(p);
      } catch (e) {}
    }
  } catch (e) {}
  // The tag keeps two same-named files from different server folders
  // from overwriting each other in the temp folder.
  const tag = require('crypto').createHash('sha1').update(String(relPath)).digest('hex').slice(0, 8);
  const dest = path.join(tmpRoot, tag + '-' + path.basename(relPath));
  try {
    await cloudClient.download(conn, relPath, dest, (done, total) => {
      try {
        if (event.sender && !event.sender.isDestroyed()) {
          event.sender.send('cloud-progress', { kind: 'download', pct: total ? Math.min(99, 99 * done / total) : 0, done, total, name: path.basename(relPath) });
        }
      } catch (e) {}
    });
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
  const err = await require('electron').shell.openPath(dest);
  if (err) return { success: false, error: 'Downloaded to ' + dest + ' but Windows could not open it: ' + err, dest };
  return { success: true, dest };
});

// ---------- TechVision Tailscale VPN (Tailscale client manager) ----------
// The module only shells out to the Tailscale CLI that is already
// installed on the machine; it implements no VPN of its own.
ipcMain.handle('vpn-get-status', async () => {
  try { return await vpn.getStatus(); }
  catch (e) { return { installed: true, connected: false, error: e && e.message ? e.message : 'Could not read Tailscale status.' }; }
});
ipcMain.handle('vpn-set-connected', async (event, on) => {
  try {
    // Open the sign-in page at most once per press, as soon as a login
    // URL is known — never after a 60-second wait for `tailscale up`.
    let openedUrl = null;
    const openOnce = (url) => { if (openedUrl === url) return; openedUrl = url; openLoginUrl(url); };
    if (on) {
      // Fast path: the daemon usually already holds a pending login URL
      // (getStatus reports it), so the browser can open in ~1s without
      // waiting for `tailscale up` to print one.
      try { const st = await vpn.getStatus(); if (st && st.needsLogin && st.authUrl) openOnce(st.authUrl); } catch (e) {}
    }
    const r = await vpn.setConnected(!!on, undefined, (url) => openOnce(url));
    if (r && r.authUrl) openOnce(r.authUrl);
    return r;
  }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not change the VPN connection.' }; }
});
ipcMain.handle('vpn-set-routes', async (event, on, auth) => {
  try { return await vpn.setSubnetRouter(!!on, auth); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not change the subnet router setting.' }; }
});
ipcMain.handle('vpn-get-routes', async (event, auth) => {
  try { return await vpn.getDeviceRoutes(auth); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read routes.' }; }
});
ipcMain.handle('vpn-approve-routes', async (event, auth, routes) => {
  try { return await vpn.approveRoutes(auth, routes); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not approve routes.' }; }
});
ipcMain.handle('vpn-disable-key-expiry', async (event, auth) => {
  try { return await vpn.disableKeyExpiry(auth); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not disable key expiry.' }; }
});
ipcMain.handle('vpn-enable-key-expiry', async (event, auth) => {
  try { return await vpn.enableKeyExpiry(auth); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not enable key expiry.' }; }
});
ipcMain.handle('vpn-key-expiry-state', async (event, auth) => {
  try { return await vpn.getKeyExpiryState(auth); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read key expiry state.' }; }
});
ipcMain.handle('vpn-verify-api', async (event, auth) => {
  try { return await vpn.verifyApiAuth(auth); }
  catch (e) { return { valid: false, error: e && e.message ? e.message : 'Could not check the credentials.' }; }
});
ipcMain.handle('vpn-install-connect', async (event, adminCreds) => {
  try {
    let openedUrl = null;
    const openOnce = (url) => { if (openedUrl === url) return; openedUrl = url; openLoginUrl(url); };
    // Administrator credentials, if the user typed them: used once for
    // this install, never stored, never logged.
    const creds = (adminCreds && typeof adminCreds === 'object' && adminCreds.user && adminCreds.password)
      ? { user: String(adminCreds.user), password: String(adminCreds.password) } : null;
    const r = await vpn.installAndConnect((p) => {
      try { if (!event.sender.isDestroyed()) event.sender.send('vpn-install-progress', p); } catch (e) {}
    }, (url) => openOnce(url), creds);
    if (r && r.authUrl) openOnce(r.authUrl);
    return r;
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not install Tailscale.' }; }
});
ipcMain.handle('vpn-open-download', async () => {
  try { await require('electron').shell.openExternal('https://tailscale.com/download'); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the download page.' }; }
});
// Opens a Tailscale sign-in link in the default browser. Only
// login.tailscale.com URLs are ever opened from here.
function openLoginUrl(url) {
  try {
    if (typeof url === 'string' && /^https:\/\/login\.tailscale\.com\/[A-Za-z0-9/?=&._-]+$/.test(url)) require('electron').shell.openExternal(url);
  } catch (e) {}
}
ipcMain.handle('vpn-open-auth-url', async (event, url) => {
  try {
    if (typeof url !== 'string' || !/^https:\/\/login\.tailscale\.com\/[A-Za-z0-9/?=&._-]+$/.test(url)) return { success: false, error: 'Not a Tailscale sign-in link.' };
    await require('electron').shell.openExternal(url);
    return { success: true };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the sign-in page.' }; }
});
// Opens the Tailscale admin console (Machines page), where subnet routes
// are approved. The app cannot approve its own route — Tailscale requires
// the tailnet admin to do it in the console.
ipcMain.handle('vpn-open-admin', async () => {
  try { await require('electron').shell.openExternal('https://login.tailscale.com/admin/machines'); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the admin console.' }; }
});
ipcMain.handle('vpn-open-keys-page', async () => {
  try { await require('electron').shell.openExternal('https://login.tailscale.com/admin/settings/keys'); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the Keys page.' }; }
});
ipcMain.handle('vpn-open-oauth-page', async () => {
  try { await require('electron').shell.openExternal('https://login.tailscale.com/admin/settings/oauth'); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the OAuth clients page.' }; }
});

// ---------- TechVision WireGuard VPN (self-hosted WireGuard) ----------
// The module shells out to the AmneziaWG CLI (awg / amneziawg.exe);
// when it is missing, the UI offers a one-click install of the
// official MSI (verified signature, one UAC prompt). It implements
// no VPN protocol of its own. Live state comes from `awg show`;
// stored state (keys, peers, client config, obfuscation set) comes
// from wireguard.json. Cloud join is wired below (wg-cloudjoin-*):
// the join routes attach to the Cloud server in getCloudServer().
ipcMain.handle('wg-get-status', async () => {
  try {
    const st = await wireguard.getStatus();
    const c = getWgConfig();
    const liveServerPeers = (st.server && Array.isArray(st.server.peers)) ? st.server.peers : [];
    const liveClientPeer = (st.client && Array.isArray(st.client.peers) && st.client.peers[0]) || null;
    const pub = wgPublicConfig();
    return Object.assign({}, st, {
      transport: wireguard.getTransport(),
      obfuscated: wgHasObfuscation(),
      server: Object.assign({}, pub.server, { publicKey: c.server.publicKey || (st.server && st.server.publicKey), listenPort: c.server.listenPort, address: c.server.address }),
      client: c.client ? Object.assign({}, pub.client, liveClientPeer ? {
        latestHandshake: liveClientPeer.latestHandshake ? liveClientPeer.latestHandshake.getTime() : null,
        transferRx: liveClientPeer.transferRx, transferTx: liveClientPeer.transferTx,
        endpoint: liveClientPeer.endpoint, online: !!liveClientPeer.latestHandshake,
      } : { online: false, latestHandshake: null, transferRx: 0, transferTx: 0 }) : null,
      peers: wgPeersWithLive(liveServerPeers),
      /* The server this machine connects to as a client, as a peer
         candidate (for the NAT peer picker and the Cloud WireGuard
         peer picker): { tunnelIp, online }. Kept separate from
         `peers` on purpose — appending it there would render a
         bogus removable "Server" row in DEVICES. Null when this
         machine is not a client. */
      tunnelServer: c.client && c.client.tunnelIp ? {
        tunnelIp: wireguard.serverTunnelIpFor(wireguard.tunnelSubnetFor(c.client.tunnelIp)),
        online: !!(liveClientPeer && liveClientPeer.latestHandshake),
      } : null,
      nat: natGateway.natService.status(),
      /* The saved site-to-site config (wireguard.json `nat`), or
         null when nothing has been saved yet — the NAT editor form
         prefills from this, and Start stays disabled without it. */
      natConfig: c.nat || null,
    });
  } catch (e) { return { installed: false, serverRunning: false, clientRunning: false, server: null, client: null, peers: [], error: e && e.message ? e.message : 'Could not read WireGuard status.' }; }
});
ipcMain.handle('wg-list-peers', async () => {
  try {
    const st = await wireguard.getStatus();
    const liveServerPeers = (st.server && Array.isArray(st.server.peers)) ? st.server.peers : [];
    return { success: true, peers: wgPeersWithLive(liveServerPeers), serverRunning: !!st.serverRunning };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not list WireGuard peers.' }; }
});
ipcMain.handle('wg-start-server', async () => {
  try {
    const c = getWgConfig();
    if (!c.server.privateKey || !wireguard.isWgKey(c.server.privateKey)) {
      const kp = await wireguard.genkeypair();
      if (!kp.success) return { success: false, error: kp.error };
      c.server.privateKey = kp.privateKey;
      c.server.publicKey = kp.publicKey;
      saveWgConfig();
    }
    if (!c.server.endpoint) {
      // The endpoint clients must reach: the public IP, read the same
      // way the Cloud module reads it. Null means no public IPv4 was
      // found (CGNAT) — the UI then says a VPS is needed instead of
      // showing a wrong address.
      try { const ip = await cloudServerMod.detectPublicIP(); if (ip) { c.server.endpoint = ip; saveWgConfig(); } } catch (e) {}
    }
    const conf = wireguard.buildServerConf({ privateKey: c.server.privateKey, address: c.server.address, listenPort: c.server.listenPort, peers: c.server.peers, extraInterfaceLines: wgObfuscationLines() });
    const r = await wireguard.installTunnelService(wireguard.SERVER_TUNNEL, conf);
    if (!r.success) return { success: false, error: r.error, declined: !!r.declined };
    refreshWgControl();
    return { success: true, publicKey: c.server.publicKey, endpoint: c.server.endpoint || null, listenPort: c.server.listenPort };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not start the WireGuard server.' }; }
});
ipcMain.handle('wg-stop-server', async () => {
  try { const r = await wireguard.uninstallTunnelService(wireguard.SERVER_TUNNEL); refreshWgControl(); return r; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not stop the WireGuard server.' }; }
});
ipcMain.handle('wg-set-endpoint', async (event, endpoint) => {
  try {
    const host = String(endpoint || '').trim();
    if (!host) { getWgConfig().server.endpoint = ''; saveWgConfig(); return { success: true, endpoint: '' }; }
    if (!wireguard.isValidEndpointHost(host)) return { success: false, error: 'Endpoint must be a hostname or an IP address, e.g. myhome.ddns.net or 203.0.113.10.' };
    getWgConfig().server.endpoint = host;
    saveWgConfig();
    return { success: true, endpoint: host };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not save the endpoint.' }; }
});
// Editable server settings (the server card's tunnel address + UDP
// port inputs). Validated by wireguard.validateServerSettings —
// bad input saves nothing. A same-/24 address change is allowed
// anytime (peers keep their tunnel IPs); a move to another /24
// while peers exist is refused there. The port is derived into the
// endpoint (host:port) automatically. If the server is running and
// anything changed, the tunnel service is rebuilt with the new
// config — the same build + install calls wg-start-server uses —
// so the change takes effect at once; a stopped server just picks
// the new values up at the next start.
async function wgApplyServerSettings(opts) {
  const c = getWgConfig();
  const v = wireguard.validateServerSettings(
    { address: c.server.address, listenPort: c.server.listenPort, peerCount: (c.server.peers || []).length },
    opts || {});
  if (!v.ok) return { success: false, error: v.error };
  const changed = v.address !== c.server.address || v.listenPort !== c.server.listenPort;
  c.server.address = v.address;
  c.server.listenPort = v.listenPort;
  saveWgConfig();
  let restarted = false, restartError = null;
  if (changed) {
    try {
      const st = await wireguard.getStatus();
      if (st.serverRunning) {
        const conf = wireguard.buildServerConf({ privateKey: c.server.privateKey, address: c.server.address, listenPort: c.server.listenPort, peers: c.server.peers, extraInterfaceLines: wgObfuscationLines() });
        const r = await wireguard.installTunnelService(wireguard.SERVER_TUNNEL, conf);
        if (!r.success) restartError = r.error;
        else restarted = true;
      }
    } catch (e) { restartError = e && e.message ? e.message : String(e); }
  }
  if (restartError) return { success: false, error: 'Settings saved, but the running server could not be rebuilt: ' + restartError + ' Restart the server to apply them.', address: v.address, listenPort: v.listenPort };
  if (changed) refreshWgControl();
  return { success: true, address: v.address, listenPort: v.listenPort, restarted };
}
ipcMain.handle('wg-set-server-settings', async (event, opts) => {
  try { return await wgApplyServerSettings(opts); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not save the server settings.' }; }
});
/* Import/export, JSON files through the system file dialog.
   Server export is the connection detail only — endpoint host,
   port, tunnel address — and deliberately NOT the public key: the
   key is regenerated when the program is reinstalled, so an
   exported key would be wrong on the new machine. Server import
   validates with validateServerSettings (including the
   cross-subnet-change-with-peers refusal) and applies through the
   same path as the settings form. NAT export/import carries the
   full saved NAT config; import validates with validateNatConfig
   plus the peer-exists and tunnel-clash checks a save does. */
ipcMain.handle('wg-server-export', async () => {
  try {
    const c = getWgConfig();
    const r = await dialog.showSaveDialog({ title: 'Export WireGuard server', defaultPath: 'techvision-server.json', filters: [{ name: 'JSON files', extensions: ['json'] }] });
    if (r.canceled || !r.filePath) return { success: false, canceled: true };
    const data = wireguard.buildServerExport(c.server);
    fs.writeFileSync(r.filePath, JSON.stringify(data, null, 2), 'utf8');
    return { success: true, filePath: r.filePath };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not export the server.' }; }
});
ipcMain.handle('wg-server-import', async () => {
  try {
    const r = await dialog.showOpenDialog({ title: 'Import WireGuard server', filters: [{ name: 'JSON files', extensions: ['json'] }], properties: ['openFile'] });
    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { success: false, canceled: true };
    let data;
    try { data = JSON.parse(fs.readFileSync(r.filePaths[0], 'utf8')); } catch (e) { return { success: false, error: 'That file is not valid JSON.' }; }
    const c = getWgConfig();
    const v = wireguard.validateServerImport(data, { address: c.server.address, listenPort: c.server.listenPort, peerCount: (c.server.peers || []).length });
    if (!v.ok) return { success: false, error: v.error };
    getWgConfig().server.endpoint = v.endpoint;
    const r2 = await wgApplyServerSettings({ address: v.address, listenPort: v.listenPort });
    if (!r2.success) return r2;
    return { success: true, endpoint: v.endpoint, address: v.address, listenPort: v.listenPort, restarted: r2.restarted };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not import the server.' }; }
});
ipcMain.handle('wg-nat-export', async () => {
  try {
    const c = getWgConfig();
    if (!c.nat) return { success: false, error: 'No site-to-site configuration saved yet — nothing to export.' };
    const r = await dialog.showSaveDialog({ title: 'Export site-to-site configuration', defaultPath: 'techvision-site-to-site.json', filters: [{ name: 'JSON files', extensions: ['json'] }] });
    if (r.canceled || !r.filePath) return { success: false, canceled: true };
    fs.writeFileSync(r.filePath, JSON.stringify(Object.assign({ version: 1, kind: 'techvision-nat' }, c.nat), null, 2), 'utf8');
    return { success: true, filePath: r.filePath };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not export the configuration.' }; }
});
ipcMain.handle('wg-nat-import', async () => {
  try {
    const r = await dialog.showOpenDialog({ title: 'Import site-to-site configuration', filters: [{ name: 'JSON files', extensions: ['json'] }], properties: ['openFile'] });
    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { success: false, canceled: true };
    let data;
    try { data = JSON.parse(fs.readFileSync(r.filePaths[0], 'utf8')); } catch (e) { return { success: false, error: 'That file is not valid JSON.' }; }
    if (!data || typeof data !== 'object' || data.kind !== 'techvision-nat') return { success: false, error: 'That file is not a TechVision site-to-site configuration.' };
    const v = natGateway.validateNatConfig(data);
    if (!v.ok) return { success: false, error: v.errors[0], errors: v.errors };
    const cfg = v.config;
    const c = getWgConfig();
    const peer = (c.server.peers || []).find((p) => p.tunnelIp === cfg.remoteTunnelIp);
    const serverIp = wgTunnelServerIp();
    const isClientServer = !peer && !!c.client && c.client.serverPublicKey && serverIp && serverIp === cfg.remoteTunnelIp;
    if (!peer && !isClientServer) return { success: false, error: 'The remote gateway (' + cfg.remoteTunnelIp + ') is not a WireGuard peer here — add it first (invite, Cloud join, or manual), then import.' };
    const tunnelSubnet = wireguard.tunnelSubnetFor(c.server.address);
    const clash = natGateway.tunnelSubnetClashes(cfg, tunnelSubnet);
    if (clash.length > 0) return { success: false, error: clash[0], errors: clash };
    c.nat = cfg;
    saveWgConfig();
    return { success: true, nat: cfg };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not import the configuration.' }; }
});
// Add one peer by hand: the client shows its public key, the user
// pastes it here (one paste, once). The tunnel address is allocated
// by the app — the user never picks an IP. If the server is running,
// the peer is applied live with `wg set`; otherwise it lands in the
// config and applies at the next start.
// Add one peer: the single code path for adding a peer — the
// wg-add-peer handler below and the Cloud-join approve handler both
// call this (the join module's contract: approve MUST use the same
// path wg-add-peer uses). Validate, allocate the next free tunnel
// address with nextTunnelIp, push, save, and apply live with `wg set`
// when the server is running. The tunnel address is allocated here,
// inside this function: the join approve computes the same next free
// address from the same peer list, and between the two there is no
// await, so the two agree.
async function wgAddPeerInternal(name, publicKey) {
  if (!name) return { success: false, error: 'Give the device a name first.' };
  if (!wireguard.isWgKey(publicKey)) return { success: false, error: 'That is not a valid WireGuard public key (44 characters, ending in =).' };
  const c = getWgConfig();
  if ((c.server.peers || []).some((p) => p.publicKey === publicKey)) return { success: false, error: 'This device is already a peer.' };
  const subnet = wireguard.tunnelSubnetFor(c.server.address);
  const tunnelIp = wireguard.nextTunnelIp((c.server.peers || []).map((p) => p.tunnelIp), subnet);
  if (!tunnelIp) { const b = subnet.replace(/\.0\/24$/, ''); return { success: false, error: 'No free tunnel address left (' + b + '.2 – ' + b + '.254 are all taken).' }; }
  const peer = { name, publicKey, tunnelIp, allowedIPs: tunnelIp + '/32', createdAt: new Date().toISOString() };
  c.server.peers.push(peer);
  saveWgConfig();
  let liveApplied = false, liveError = null;
  try {
    const st = await wireguard.getStatus();
    if (st.serverRunning) {
      const r = await wireguard.setPeer(wireguard.SERVER_TUNNEL, publicKey, peer.allowedIPs);
      liveApplied = !!r.success;
      if (!r.success) liveError = r.error;
    }
  } catch (e) { liveError = e && e.message ? e.message : String(e); }
  return { success: true, peer, liveApplied, liveError };
}
ipcMain.handle('wg-add-peer', async (event, opts) => {
  try {
    const name = String((opts && opts.name) || '').trim().replace(/[\r\n]/g, ' ');
    const publicKey = String((opts && opts.publicKey) || '').trim();
    return await wgAddPeerInternal(name, publicKey);
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not add the peer.' }; }
});
ipcMain.handle('wg-remove-peer', async (event, opts) => {
  try {
    const publicKey = String((opts && opts.publicKey) || '').trim();
    if (!wireguard.isWgKey(publicKey)) return { success: false, error: 'Not a valid WireGuard public key.' };
    const c = getWgConfig();
    const before = (c.server.peers || []).length;
    c.server.peers = (c.server.peers || []).filter((p) => p.publicKey !== publicKey);
    if (c.server.peers.length === before) return { success: false, error: 'No such peer.' };
    saveWgConfig();
    let liveApplied = false, liveError = null;
    try {
      const st = await wireguard.getStatus();
      if (st.serverRunning) {
        const r = await wireguard.removePeer(wireguard.SERVER_TUNNEL, publicKey);
        liveApplied = !!r.success;
        if (!r.success) liveError = r.error;
      }
    } catch (e) { liveError = e && e.message ? e.message : String(e); }
    return { success: true, liveApplied, liveError };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not remove the peer.' }; }
});
// Generate a client invite: the server creates the client's keypair
// and config, so the server already holds that client's public key —
// nothing has to travel back. The peer is added to the server config
// (and applied live when the server is running) and the full .conf
// comes back for the QR code, the copy box and the export file. The
// QR is rendered with the `qrcode` package when it is installed;
// without it the invite still works as text + file (qr: null).
ipcMain.handle('wg-generate-invite', async (event, opts) => {
  try {
    const name = String((opts && opts.name) || '').trim().replace(/[\r\n]/g, ' ') || 'device';
    const c = getWgConfig();
    if (!c.server.privateKey || !wireguard.isWgKey(c.server.privateKey) || !wireguard.isWgKey(c.server.publicKey)) return { success: false, error: 'Start the server first — it needs a keypair before it can invite anyone.' };
    if (!c.server.endpoint) {
      try { const ip = await cloudServerMod.detectPublicIP(); if (ip) { c.server.endpoint = ip; saveWgConfig(); } } catch (e) {}
    }
    if (!c.server.endpoint) return { success: false, error: 'No public address for this server yet. Type a DDNS hostname in the Server panel, or check the internet connection.' };
    const subnet = wireguard.tunnelSubnetFor(c.server.address);
    const tunnelIp = wireguard.nextTunnelIp((c.server.peers || []).map((p) => p.tunnelIp), subnet);
    if (!tunnelIp) { const b = subnet.replace(/\.0\/24$/, ''); return { success: false, error: 'No free tunnel address left (' + b + '.2 – ' + b + '.254 are all taken).' }; }
    const kp = await wireguard.genkeypair();
    if (!kp.success) return { success: false, error: kp.error };
    const endpoint = wireguard.serverEndpoint(c.server.endpoint, c.server.listenPort);
    const conf = wireguard.buildClientConf({ privateKey: kp.privateKey, address: tunnelIp + '/32', serverPublicKey: c.server.publicKey, endpoint, allowedIPs: wireguard.tunnelSubnetFor(c.server.address), extraInterfaceLines: wgObfuscationLines() });
    const peer = { name, publicKey: kp.publicKey, tunnelIp, allowedIPs: tunnelIp + '/32', createdAt: new Date().toISOString() };
    c.server.peers.push(peer);
    saveWgConfig();
    let liveApplied = false, liveError = null;
    try {
      const st = await wireguard.getStatus();
      if (st.serverRunning) {
        const r = await wireguard.setPeer(wireguard.SERVER_TUNNEL, peer.publicKey, peer.allowedIPs);
        liveApplied = !!r.success;
        if (!r.success) liveError = r.error;
      }
    } catch (e) { liveError = e && e.message ? e.message : String(e); }
    let qr = null;
    try {
      const QRCode = require('qrcode');
      qr = await QRCode.toDataURL(conf, { errorCorrectionLevel: 'M', margin: 1, width: 256 });
    } catch (e) { qr = null; }
    return { success: true, conf, qr, tunnelIp, name, publicKey: kp.publicKey, liveApplied, liveError };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not generate an invite.' }; }
});
// Import a .conf file (or pasted text): parse it and show what it
// holds. No side effects — wg-connect does the installing.
ipcMain.handle('wg-import-conf', async (event, opts) => {
  try {
    const confText = String((opts && opts.confText) || '');
    if (!confText.trim()) return { success: false, error: 'Nothing to import.' };
    const parsed = wireguard.parseConf(confText);
    let publicKey = null;
    if (parsed.interface.privateKey) {
      const p = await wireguard.pubkey(parsed.interface.privateKey);
      if (p.success) publicKey = p.key;
    }
    const serverPeer = parsed.peers[0] || {};
    return {
      success: true,
      summary: {
        address: parsed.interface.address || null,
        publicKey,
        serverPublicKey: serverPeer.publicKey || null,
        endpoint: serverPeer.endpoint || null,
        allowedIPs: serverPeer.allowedIPs || null,
        hasObfuscation: !!wireguard.obfuscationParamsFromExtra(parsed.interface.extra),
      },
    };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read that config file.' }; }
});
// Connect this machine as a client. Two forms:
//  - { confText }: an imported .conf (invite, file, or paste) —
//    installed as-is, metadata stored from the parse.
//  - { serverPublicKey, endpoint, tunnelIp, fullTunnel }: typed by
//    hand — the app generates this machine's keypair and builds the
//    config. The tunnel address is the one the server assigned (it
//    is in the invite); the app never invents one.
ipcMain.handle('wg-connect', async (event, opts) => {
  try {
    const o = opts || {};
    let confText = null;
    let meta = {};
    // Reconnect with the stored client config (one click — the private
    // key never leaves main, so the renderer cannot rebuild it).
    // The stored obfuscation set rides along, so a reconnect rebuilds
    // exactly the config that connected the first time.
    if (o.reconnect) {
      const stored = getWgConfig().client;
      if (!stored || !wireguard.isWgKey(stored.privateKey) || !wireguard.isWgKey(stored.serverPublicKey)) return { success: false, error: 'No saved client config to reconnect with.' };
      confText = wireguard.buildClientConf({ privateKey: stored.privateKey, address: (stored.tunnelIp || '10.0.0.2') + '/32', serverPublicKey: stored.serverPublicKey, endpoint: stored.endpoint, allowedIPs: stored.allowedIPs || wireguard.TUNNEL_SUBNET, extraInterfaceLines: wgLinesForObfuscation(stored.obfuscation) });
      meta = stored;
    } else if (o.confText && String(o.confText).trim()) {
      const parsed = wireguard.parseConf(String(o.confText));
      if (!parsed.interface.privateKey) return { success: false, error: 'That config has no private key — it cannot connect.' };
      if (!parsed.peers[0] || !parsed.peers[0].publicKey) return { success: false, error: 'That config has no server to connect to.' };
      confText = String(o.confText);
      const p = await wireguard.pubkey(parsed.interface.privateKey);
      meta = {
        privateKey: parsed.interface.privateKey,
        publicKey: p.success ? p.key : null,
        serverPublicKey: parsed.peers[0].publicKey,
        endpoint: parsed.peers[0].endpoint || '',
        tunnelIp: wireguard.tunnelIpOf(parsed.interface.address) || '',
        allowedIPs: parsed.peers[0].allowedIPs || wireguard.TUNNEL_SUBNET,
      };
      // Keep the imported config's obfuscation set (if any) so a later
      // reconnect rebuilds the same config — installing confText as-is
      // already carries it this time.
      const importedObf = wireguard.obfuscationParamsFromExtra(parsed.interface.extra);
      if (importedObf) meta.obfuscation = importedObf;
    } else {
      if (!wireguard.isWgKey(o.serverPublicKey)) return { success: false, error: 'That is not a valid server public key.' };
      if (!o.endpoint || !/^[A-Za-z0-9.-]+:\d{1,5}$/.test(String(o.endpoint).trim())) return { success: false, error: 'Endpoint must be host:port, e.g. myhome.ddns.net:51820.' };
      const tunnelIp = wireguard.tunnelIpOf(o.tunnelIp) || '';
      if (!tunnelIp) return { success: false, error: 'Type the tunnel address the server gave you (from the invite, e.g. 10.0.0.2).' };
      const kp = await wireguard.genkeypair();
      if (!kp.success) return { success: false, error: kp.error };
      const allowedIPs = o.fullTunnel ? '0.0.0.0/0, ::/0' : wireguard.TUNNEL_SUBNET;
      // No obfuscation lines here on purpose: this is a foreign
      // server typed by hand, and its obfuscation set is unknown —
      // injecting ours would break the handshake. Import the
      // server's .conf instead (wg-import-conf keeps its set).
      confText = wireguard.buildClientConf({ privateKey: kp.privateKey, address: tunnelIp + '/32', serverPublicKey: String(o.serverPublicKey).trim(), endpoint: String(o.endpoint).trim(), allowedIPs });
      meta = { privateKey: kp.privateKey, publicKey: kp.publicKey, serverPublicKey: String(o.serverPublicKey).trim(), endpoint: String(o.endpoint).trim(), tunnelIp, allowedIPs };
    }
    const c = getWgConfig();
    try {
      const st = await wireguard.getStatus();
      if (st.clientRunning) await wireguard.uninstallTunnelService(wireguard.CLIENT_TUNNEL);
    } catch (e) { /* installing over it is attempted below anyway */ }
    const r = await wireguard.installTunnelService(wireguard.CLIENT_TUNNEL, confText);
    if (!r.success) return { success: false, error: r.error, declined: !!r.declined };
    c.client = Object.assign({ createdAt: new Date().toISOString() }, meta);
    saveWgConfig();
    refreshWgControl();
    return { success: true, tunnelIp: meta.tunnelIp, endpoint: meta.endpoint };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not connect.' }; }
});
ipcMain.handle('wg-disconnect', async () => {
  try { const r = await wireguard.uninstallTunnelService(wireguard.CLIENT_TUNNEL); refreshWgControl(); return r; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not disconnect.' }; }
});
ipcMain.handle('wg-open-download', async () => {
  // Manual fallback for the one-click install: the official
  // AmneziaWG releases page (same MSI the installer downloads).
  try { await require('electron').shell.openExternal(wireguard.AMNEZIAWG_RELEASES_URL); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the download page.' }; }
});
// ---------- TechVision WireGuard VPN — Cloud join ----------
// The third key-exchange option (spec: "Join via Cloud"). The client
// sends a join request through its own Cloud connection — same
// username/password, same TLS-pinned channel, no third party — and
// this machine, as the server, shows the request in its peer list;
// Approve sends the server public key + endpoint + tunnel IP back
// over the same channel, and the client connects by itself.
// Server side (this machine is the hub): list / approve / reject.
// The approve uses wgAddPeerInternal — the same code path wg-add-peer
// uses — and hands the client the server's obfuscation set
// (extraInterfaceLines), so the joined client speaks AmneziaWG with
// the same S1–S4/H1–H4; without them its handshake would fail.
// A live Cloud session for a saved server: reuse the session the
// Cloud view already opened, or log in with the saved password the
// way cloud-client-connect does (one click, no typing). Only used
// when the user SENDS a join request — polling never logs in by
// itself (a dead session after a server restart must surface as
// 'server-restarted' and stop, not silently re-login).
async function wgEnsureCloudSession(serverId) {
  const existing = cloudSessions.get(serverId);
  if (existing && existing.token) return { success: true, conn: existing };
  const cfg = getCloudConfig();
  const rec = (cfg.clients || []).find((c) => c.id === serverId);
  if (!rec) return { success: false, error: 'Cloud server not found.' };
  if (!rec.certPem) return { success: false, error: 'Not connected to this Cloud server — open the Cloud view and connect first.' };
  if (!rec.password) return { success: false, error: 'Not connected to this Cloud server — open the Cloud view and connect first (or save the password for one-click reconnect).' };
  try {
    const conn = await cloudClient.login(rec.host, parseInt(rec.port, 10), rec.certPem, rec.user, rec.password);
    const info = await cloudClient.info(conn);
    cloudSessions.set(serverId, Object.assign({}, conn, { user: info.user, root: info.root, canWrite: info.canWrite }));
    return { success: true, conn: cloudSessions.get(serverId) };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not connect to the Cloud server.' }; }
}
ipcMain.handle('wg-cloudjoin-list', async () => {
  try {
    if (!wgJoinStoreInstance) { getCloudServer(); }
    if (!wgJoinStoreInstance) return { success: false, error: 'Cloud join is not set up yet.' };
    return { success: true, requests: cloudJoin.listJoinRequests(wgJoinStoreInstance) };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not list join requests.' }; }
});
ipcMain.handle('wg-cloudjoin-approve', async (event, opts) => {
  try {
    if (!wgJoinStoreInstance) { getCloudServer(); }
    if (!wgJoinStoreInstance) return { success: false, error: 'Cloud join is not set up yet.' };
    const c = getWgConfig();
    let extraInterfaceLines = [];
    try { extraInterfaceLines = wgObfuscationLines(); }
    catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read the obfuscation settings.' }; }
    const endpoint = wireguard.serverEndpoint(c.server.endpoint, c.server.listenPort);
    return await cloudJoin.approveJoinRequest(wgJoinStoreInstance, String((opts && opts.id) || ''), {
      serverPublicKey: c.server.publicKey,
      endpoint,
      getPeers: () => (getWgConfig().server.peers || []).slice(),
      addPeer: (peer) => wgAddPeerInternal(peer.name, peer.publicKey),
      extraInterfaceLines,
    });
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not approve the join request.' }; }
});
ipcMain.handle('wg-cloudjoin-reject', async (event, opts) => {
  try {
    if (!wgJoinStoreInstance) { getCloudServer(); }
    if (!wgJoinStoreInstance) return { success: false, error: 'Cloud join is not set up yet.' };
    return cloudJoin.rejectJoinRequest(wgJoinStoreInstance, String((opts && opts.id) || ''));
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not reject the join request.' }; }
});
ipcMain.handle('wg-cloudjoin-request', async (event, opts) => {
  try {
    const serverId = String((opts && opts.serverId) || '');
    const deviceName = String((opts && opts.deviceName) || '');
    if (!serverId) return { success: false, error: 'Pick a saved Cloud server first.' };
    const sess = await wgEnsureCloudSession(serverId);
    if (!sess.success) return sess;
    const r = await cloudJoin.submitJoinRequest(sess.conn, deviceName, {});
    if (!r.success) return r;
    // The private key stays in main memory only — the renderer gets
    // the request id, never the key.
    wgPendingJoins.set(r.requestId, { serverId, deviceName: r.deviceName, privateKey: r.privateKey, createdAt: Date.now() });
    return { success: true, requestId: r.requestId, deviceName: r.deviceName, status: 'pending', expiresAt: r.expiresAt || null };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not send the join request.' }; }
});
ipcMain.handle('wg-cloudjoin-poll', async (event, opts) => {
  try {
    const requestId = String((opts && opts.requestId) || '');
    const pending = wgPendingJoins.get(requestId);
    if (!pending) return { success: false, code: 'not-found', retryable: false, error: 'Join request not found — it may have expired, or the app was restarted. Send a new join request.' };
    // Existing session only: a dead session must surface as
    // 'server-restarted', never trigger a silent re-login here.
    const conn = cloudSessions.get(pending.serverId);
    if (!conn || !conn.token) { wgPendingJoins.delete(requestId); return { success: false, code: 'not-connected', retryable: false, error: 'Not connected to the Cloud server any more. Send the join request again.' }; }
    const r = await cloudJoin.pollJoinStatus(conn, requestId, { privateKey: pending.privateKey });
    if (!r.success) {
      if (r.code === 'server-restarted' || r.code === 'expired') wgPendingJoins.delete(requestId);
      return r;
    }
    if (r.status === 'approved') {
      wgPendingJoins.delete(requestId);
      // confText carries the private key (the same precedent as the
      // invite conf the renderer already receives for QR/copy) — the
      // renderer hands it straight to wg-connect, nothing else.
      return { success: true, status: 'approved', confText: r.confText, tunnelIp: r.tunnelIp, endpoint: r.endpoint };
    }
    return { success: true, status: r.status };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not check the join request.' }; }
});
ipcMain.handle('wg-cloudjoin-cancel', async (event, opts) => {
  try {
    const requestId = String((opts && opts.requestId) || '');
    const pending = wgPendingJoins.get(requestId);
    wgPendingJoins.delete(requestId);
    if (pending) {
      const conn = cloudSessions.get(pending.serverId);
      if (conn && conn.token) {
        try { await cloudJoin.cancelJoinRequest(conn, requestId); } catch (e) { /* local drop is enough */ }
      }
    }
    return { success: true };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not cancel the join request.' }; }
});
// ---------- TechVision WireGuard VPN — gateway NAT service ----------
// One TechVision PC per site is the gateway (see src/nat-gateway.js):
// it forwards + NATs for its whole LAN, so printers/cameras/PCs need
// no install. The config is stored in wireguard.json under `nat`
// (IPs and names only, no secrets). A config passed here is
// validated and saved; with no config, the stored one is used.
// On non-Windows the service validates the config and then fails
// cleanly with "Windows only" — it never pretends to run.
/* ---------- WireGuard control channel (remote NAT start) ----------
   The two gateways talk over the tunnel (wg-control.js): when the
   user presses Start NAT on one gateway, the other gateway's NAT
   service starts by itself. The listener binds to the local tunnel
   address only and starts when the tunnel comes up, stops when it
   goes down. Best-effort: a bind failure never breaks the tunnel. */
const wgControlServer = wgControl.createControlServer({ logger: (m) => console.error('[Main] ' + m) });
async function wgOwnTunnelIp() {
  try {
    const st = await wireguard.getStatus();
    const c = getWgConfig();
    if (st.serverRunning) return c.server.address;
    if (st.clientRunning && c.client && c.client.tunnelIp) return c.client.tunnelIp;
  } catch (e) {}
  const c = getWgConfig();
  return c.server.address || (c.client && c.client.tunnelIp) || null;
}
/* The server's tunnel address from this machine's client config
   (the .1 of the tunnel subnet — the app's convention). Null when
   this machine is not a client. */
function wgTunnelServerIp() {
  const c = getWgConfig();
  if (!c.client || !c.client.tunnelIp) return null;
  return wireguard.serverTunnelIpFor(wireguard.tunnelSubnetFor(c.client.tunnelIp));
}
async function refreshWgControl() {
  try {
    const tunnelIp = await wgOwnTunnelIp();
    if (!tunnelIp) { wgControlServer.stop(); return; }
    const c = getWgConfig();
    const r = await wgControlServer.start({
      tunnelIp,
      tunnelSubnet: wireguard.tunnelSubnetFor(tunnelIp),
      peerTunnelIps: (c.server.peers || []).map((p) => p.tunnelIp).filter(Boolean),
      handleNatStart: handleRemoteNatStart,
    });
    if (r && !r.success && !r.alreadyRunning) console.error('[Main] WireGuard control channel: ' + r.error);
  } catch (e) { /* best-effort: the tunnel still works without it */ }
}
/* The other gateway asked this machine to start its NAT service
   (a command over the tunnel — see wg-control.js). This side needs
   no configuration typed by anyone: the LAN address/subnet are
   auto-detected, the farVirtIp is verified/adjusted on this LAN,
   and the rest comes in the command. Idempotent: an already-running
   service answers "already running" instead of restarting. */
async function handleRemoteNatStart(command) {
  try {
    if (!command || command.type !== 'nat-start') return { ok: false, error: 'Unknown command.' };
    const mode = command.mode === 'different-subnet' ? 'different-subnet' : 'same-subnet';
    const running = natGateway.natService.status();
    if (running.running) {
      const c0 = getWgConfig();
      return { ok: true, alreadyRunning: true, mode: running.mode, farVirtIp: (c0.nat && c0.nat.farVirtIp) || '', remoteLanSubnet: (c0.nat && c0.nat.localSubnet) || '', remoteLanIp: (c0.nat && c0.nat.gatewayLanIp) || '' };
    }
    if (process.platform !== 'win32') return { ok: false, error: 'The gateway NAT service runs on Windows only.' };
    const ownTunnelIp = await wgOwnTunnelIp();
    if (!ownTunnelIp) return { ok: false, error: 'The WireGuard tunnel is not up on this computer.' };
    const c = getWgConfig();
    const tunnelSubnet = wireguard.tunnelSubnetFor(ownTunnelIp);
    const own = natGateway.detectLanAddress(undefined, [tunnelSubnet]);
    if (!own) return { ok: false, error: 'Could not detect this gateway\'s LAN address.' };
    const initiatorIp = command.initiatorTunnelIp;
    let farVirtIp = '';
    if (mode === 'same-subnet') {
      const adj = await natGateway.adjustFarVirtIp(command.farVirtIp, own.subnet, (ip) => natGateway.isIpFreeOnLan(ip));
      if (!adj) return { ok: false, error: 'No free address in ' + own.subnet + ' for the gateway\'s virtual address.' };
      farVirtIp = adj.farVirtIp;
    }
    /* Which config this side runs: if the rows were added HERE,
       start with them (this machine owns the pair — the helper
       translates the mapped devices); otherwise run the empty
       remote config (remote: true) — the helper only needs
       farVirtIp + the tunnel IPs for the return path, and the
       rows live on the initiating gateway. Either way the
       farVirtIp is the adjusted proposal from the command: the
       address the initiating gateway is known by on THIS lan. */
    let remoteCfg;
    const savedNat = c.nat;
    if (mode === 'same-subnet' && savedNat && savedNat.mode === 'same-subnet' && Array.isArray(savedNat.mappings) && savedNat.mappings.length > 0 && savedNat.remoteTunnelIp === initiatorIp) {
      remoteCfg = {
        mode: 'same-subnet',
        localSubnet: own.subnet,
        remoteSubnet: own.subnet,
        gatewayLanIp: own.address,
        gatewayTunnelIp: ownTunnelIp,
        remoteTunnelIp: initiatorIp,
        farVirtIp,
        interfaceName: '',
        mappings: savedNat.mappings,
      };
    } else {
      remoteCfg = natGateway.buildRemoteNatConfig(command, { address: own.address, subnet: own.subnet, tunnelIp: ownTunnelIp }, farVirtIp);
    }
    const v = natGateway.validateNatConfig(remoteCfg);
    if (!v.ok) return { ok: false, error: v.errors[0], errors: v.errors };
    const clash = natGateway.tunnelSubnetClashes(v.config, tunnelSubnet);
    if (clash.length > 0) return { ok: false, error: clash[0] };
    /* The initiator must be a peer (its AllowedIPs get extended):
       a server peer, or — when this machine is a client — the
       server it connects to. */
    const peer = (c.server.peers || []).find((p) => p.tunnelIp === initiatorIp);
    const serverIp = wgTunnelServerIp();
    const isClientServer = !peer && !!c.client && c.client.serverPublicKey && serverIp && serverIp === initiatorIp;
    if (!peer && !isClientServer) return { ok: false, error: 'The initiating gateway (' + initiatorIp + ') is not a WireGuard peer here.' };
    const r = await natGateway.natService.start(v.config, buildNatHooks());
    if (!r.success) return { ok: false, error: r.error };
    c.nat = v.config;
    saveWgConfig();
    return { ok: true, farVirtIp, remoteLanSubnet: own.subnet, remoteLanIp: own.address, mode };
  } catch (e) { return { ok: false, error: e && e.message ? e.message : 'Remote NAT start failed.' }; }
}
/* The peer-route wiring for the NAT service (AllowedIPs): the remote
   gateway peer's routes are extended while the service runs and put
   back on stop. Two roles: server (the remote gateway is one of our
   peers) and client (the remote gateway is the server this client
   connects to — its routes live in the client config). The service
   cannot translate without it, so a start with no resolvable peer
   is refused rather than silently broken. */
function buildNatHooks() {
  const applyOne = async (remoteTunnelIp, allowedIPs, previous, forRestore) => {
    const cc = getWgConfig();
    const p = (cc.server.peers || []).find((x) => x.tunnelIp === remoteTunnelIp);
    if (p) {
      let live = null;
      try { live = await wireguard.getStatus(); } catch (e) {}
      if (live && live.serverRunning) {
        const r = await wireguard.setPeer(wireguard.SERVER_TUNNEL, p.publicKey, allowedIPs);
        if (!r.success) return { success: false, error: 'Could not extend the remote gateway peer\'s routes live: ' + (r.error || 'wireguard set failed') };
      }
      p.allowedIPs = allowedIPs;
      saveWgConfig();
      return { success: true, previousAllowedIPs: previous };
    }
    const serverIp = wgTunnelServerIp();
    if (cc.client && cc.client.serverPublicKey && serverIp && serverIp === remoteTunnelIp) {
      let live = null;
      try { live = await wireguard.getStatus(); } catch (e) {}
      if (live && live.clientRunning) {
        const r = await wireguard.setPeer(wireguard.CLIENT_TUNNEL, cc.client.serverPublicKey, allowedIPs);
        if (!r.success) return { success: false, error: 'Could not extend the server peer\'s routes live: ' + (r.error || 'wireguard set failed') };
      }
      cc.client.allowedIPs = allowedIPs;
      saveWgConfig();
      return { success: true, previousAllowedIPs: previous };
    }
    /* Restore is best-effort: the peer is gone, so there is nothing
       left to put back — report success rather than failing the
       stop. An apply to a missing peer is a real failure. */
    if (forRestore) return { success: true };
    return { success: false, error: 'The remote gateway peer (' + remoteTunnelIp + ') was removed.' };
  };
  return {
    applyPeerAllowedIPs: async (remoteTunnelIp, allowedIPs) => {
      const cc = getWgConfig();
      const p = (cc.server.peers || []).find((x) => x.tunnelIp === remoteTunnelIp);
      const previous = p ? (p.allowedIPs || (p.tunnelIp + '/32'))
        : (cc.client ? (cc.client.allowedIPs || wireguard.TUNNEL_SUBNET) : (remoteTunnelIp + '/32'));
      return applyOne(remoteTunnelIp, allowedIPs, previous, false);
    },
    restorePeerAllowedIPs: async (remoteTunnelIp, previousAllowedIPs) => {
      return applyOne(remoteTunnelIp, previousAllowedIPs, previousAllowedIPs, true);
    },
  };
}
ipcMain.handle('wg-nat-start', async (event, opts) => {
  try {
    const c = getWgConfig();
    const saved = c.nat;
    const mode = (opts && opts.mode) || (saved && saved.mode) || 'same-subnet';
    const peerTunnelIp = (opts && opts.peerTunnelIp) || (saved && saved.remoteTunnelIp) || null;
    if (!peerTunnelIp) return { success: false, error: 'Pick the other gateway first — the remote gateway peer has to be set up before the NAT service can start.' };
    /* The remote gateway peer must exist before the NAT service can
       run: its AllowedIPs are extended with the mapped remote
       addresses (same-subnet) or the remote subnet (different-
       subnet), so translated packets actually enter the tunnel.
       Checked here, before any UAC prompt or network attempt, so a
       missing peer is a clean error instead of a half-started
       gateway. Either role counts: a server peer, or — when this
       machine is a client — the server it connects to. */
    const peer = (c.server.peers || []).find((p) => p.tunnelIp === peerTunnelIp);
    const serverIp = wgTunnelServerIp();
    const isClientServer = !peer && !!c.client && c.client.serverPublicKey && serverIp && serverIp === peerTunnelIp;
    if (!peer && !isClientServer) return { success: false, error: 'The remote gateway (' + peerTunnelIp + ') is not a WireGuard peer yet — add it first (invite, Cloud join, or manual), then start the NAT service.' };
    /* This gateway's own LAN, auto-detected (the tunnel subnet is
       excluded — the AmneziaWG adapter is not a LAN address). The
       form no longer asks for any of this: the user only adds
       devices (name + real IP + alias IP). */
    const ownTunnelIp = await wgOwnTunnelIp();
    if (!ownTunnelIp) return { success: false, error: 'The WireGuard tunnel is not up on this computer — start the server or connect the client first, then start the NAT service.' };
    const tunnelSubnet = wireguard.tunnelSubnetFor(ownTunnelIp);
    const own = natGateway.detectLanAddress(undefined, [tunnelSubnet]);
    if (!own) return { success: false, error: 'Could not detect this gateway PC\'s LAN address — check it is connected to the local network.' };
    let config;
    if (mode === 'same-subnet') {
      /* Rows live on one side of the pair only: when this gateway
         has none saved, it starts as the remote side (remote: true
         — the helper only needs farVirtIp + the tunnel IPs for the
         return path) and the other gateway runs the rows. The
         command below wakes the other side, which starts with its
         own rows if it has them. */
      const hasMappings = saved && Array.isArray(saved.mappings) && saved.mappings.length > 0;
      config = {
        mode: 'same-subnet',
        localSubnet: own.subnet,
        remoteSubnet: own.subnet,
        gatewayLanIp: own.address,
        gatewayTunnelIp: ownTunnelIp,
        remoteTunnelIp: peerTunnelIp,
        farVirtIp: (saved && saved.farVirtIp) || '',
        interfaceName: (saved && saved.interfaceName) || '',
        mappings: hasMappings ? saved.mappings : [],
        remote: !hasMappings,
      };
      /* farVirtIp (the address the remote gateway is known by on
         this LAN): reuse the saved one while it is still free here,
         else pick a fresh free address in the LAN. */
      if (!config.farVirtIp || !(await natGateway.isIpFreeOnLan(config.farVirtIp))) {
        const picked = await natGateway.pickFreeAddress(own.subnet, [own.address, ...(config.mappings || []).map((m) => m.real)], undefined, (ip) => natGateway.isIpFreeOnLan(ip));
        if (!picked) return { success: false, error: 'No free address in ' + own.subnet + ' for the gateway\'s virtual address.' };
        config.farVirtIp = picked;
      }
      const v = natGateway.validateNatConfig(config);
      if (!v.ok) return { success: false, error: v.errors[0], errors: v.errors };
      const clash = natGateway.tunnelSubnetClashes(v.config, tunnelSubnet);
      if (clash.length > 0) return { success: false, error: clash[0], errors: clash };
      config = v.config;
    } else {
      config = {
        mode: 'different-subnet',
        localSubnet: own.subnet,
        remoteSubnet: '',
        gatewayLanIp: own.address,
        gatewayTunnelIp: ownTunnelIp,
        remoteTunnelIp: peerTunnelIp,
        farVirtIp: '',
        interfaceName: '',
        mappings: [],
      };
    }
    /* Fail fast on a non-Windows machine, before any network
       attempt: the service needs WinDivert and admin rights. */
    if (process.platform !== 'win32') return { success: false, error: 'The gateway NAT service runs on Windows only (it needs WinDivert and administrator permission once). The configuration itself is valid.' };
    /* Remote start first: the other gateway must be translating
       too, or the return path has nowhere to go. The command
       carries the mode, this gateway's subnet, and the farVirtIp
       this gateway proposes as its source identity on the remote
       LAN; the remote side verifies/adjusts it and starts with
       zero configuration typed there. */
    const farVirtProposal = mode === 'same-subnet' ? (await natGateway.pickFreeAddress(own.subnet, [own.address, config.farVirtIp, ...(config.mappings || []).map((m) => m.real)], undefined, (ip) => natGateway.isIpFreeOnLan(ip))) : '';
    const command = natGateway.buildRemoteStartCommand({
      mode, localSubnet: own.subnet, gatewayLanIp: own.address, gatewayTunnelIp: ownTunnelIp, farVirtIpProposal: farVirtProposal || '',
    });
    const ack = await wgControl.sendRemoteNatStart(peerTunnelIp, command);
    if (!ack || !ack.ok) return { success: false, error: 'The other gateway did not start the NAT service: ' + ((ack && ack.error) || 'no answer') + ' Start it there by hand, or check its tunnel is up, then try again.' };
    /* Finalise the config from the ack: the remote side reports its
       own LAN subnet (the remote subnet in different-subnet mode;
       in same-subnet mode it must equal this LAN, or the pair is
       not actually on the same subnet). */
    if (mode === 'same-subnet') {
      if (ack.remoteLanSubnet && ack.remoteLanSubnet !== own.subnet) return { success: false, error: 'The other network is ' + ack.remoteLanSubnet + ', not ' + own.subnet + ' — the two networks are not on the same subnet. Use different-subnet mode for this pair.' };
    } else {
      config.remoteSubnet = ack.remoteLanSubnet || '';
      if (!config.remoteSubnet) return { success: false, error: 'The other gateway did not report its network — try starting again.' };
      const v = natGateway.validateNatConfig(config);
      if (!v.ok) return { success: false, error: v.errors[0], errors: v.errors };
      const clash = natGateway.tunnelSubnetClashes(v.config, tunnelSubnet);
      if (clash.length > 0) return { success: false, error: clash[0], errors: clash };
      config = v.config;
    }
    /* Persist the negotiated config in same-subnet mode (so the UI
       shows it and a later start reuses the same farVirtIp). A
       different-subnet start is ephemeral — it must not clobber
       the saved mappings. */
    if (mode === 'same-subnet') { c.nat = config; saveWgConfig(); }
    const r = await natGateway.natService.start(config, buildNatHooks());
    if (!r.success) return { success: false, error: r.error, declined: !!r.declined, remoteStarted: true };
    return Object.assign({}, r, { remoteStarted: true, remoteNote: ack.alreadyRunning ? 'The other gateway was already running its NAT service.' : 'The other gateway started its NAT service too.' });
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not start the NAT service.' }; }
});
ipcMain.handle('wg-nat-stop', async () => {
  try { return await natGateway.natService.stop(); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not stop the NAT service.' }; }
});
ipcMain.handle('wg-nat-status', async () => {
  try { return { success: true, nat: natGateway.natService.status() }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read the NAT status.' }; }
});
/* Save the site-to-site config only — the NAT editor form calls
   this; Start reads the saved config back. The form sends just
   { mode, mappings, peerTunnelIp }: the subnets, the gateway LAN
   address and the farVirtIp are auto-detected / auto-picked here
   and validated with validateNatConfig, plus the remote gateway
   must be an existing peer and no virtual address may sit inside
   the tunnel subnet. Nothing is written unless every check passes.
   Different-subnet mode has no form at all, so there is nothing
   to save for it — Start builds that config from scratch. */
ipcMain.handle('wg-nat-save', async (event, input) => {
  try {
    const mode = (input && input.mode) || 'same-subnet';
    if (mode !== 'same-subnet') return { success: false, error: 'Different-subnet mode needs no configuration — just pick the other gateway and press Start NAT service.' };
    const c = getWgConfig();
    const peerTunnelIp = (input && (input.peerTunnelIp || input.remoteTunnelIp)) || '';
    const peer = (c.server.peers || []).find((p) => p.tunnelIp === peerTunnelIp);
    const serverIp = wgTunnelServerIp();
    const isClientServer = !peer && !!c.client && c.client.serverPublicKey && serverIp && serverIp === peerTunnelIp;
    if (!peer && !isClientServer) return { success: false, error: 'The remote gateway (' + (peerTunnelIp || '—') + ') is not a WireGuard peer yet — add it first (invite, Cloud join, or manual), then save the NAT configuration.', errors: ['The remote gateway (' + (peerTunnelIp || '—') + ') is not a WireGuard peer yet — add it first (invite, Cloud join, or manual), then save the NAT configuration.'] };
    const ownTunnelIp = await wgOwnTunnelIp();
    const tunnelSubnet = wireguard.tunnelSubnetFor(ownTunnelIp || c.server.address);
    const own = natGateway.detectLanAddress(undefined, [tunnelSubnet]);
    if (!own) return { success: false, error: 'Could not detect this gateway PC\'s LAN address — check it is connected to the local network.' };
    const mappings = Array.isArray(input.mappings) ? input.mappings : [];
    /* farVirtIp (the address the remote gateway is known by on
       this LAN): reuse the saved one while it is still free here,
       else pick a fresh free address. It is replaced by the
       negotiated value at start time. */
    let farVirtIp = (c.nat && c.nat.farVirtIp) || '';
    if (!farVirtIp || !(await natGateway.isIpFreeOnLan(farVirtIp))) {
      farVirtIp = (await natGateway.pickFreeAddress(own.subnet, [own.address, ...mappings.map((m) => m.real)], undefined, (ip) => natGateway.isIpFreeOnLan(ip))) || '';
    }
    const full = {
      mode: 'same-subnet',
      localSubnet: own.subnet,
      remoteSubnet: own.subnet,
      gatewayLanIp: own.address,
      gatewayTunnelIp: ownTunnelIp || c.server.address,
      remoteTunnelIp: peerTunnelIp,
      farVirtIp,
      interfaceName: '',
      mappings,
    };
    const v = natGateway.validateNatConfig(full);
    if (!v.ok) return { success: false, error: v.errors[0], errors: v.errors };
    const clash = natGateway.tunnelSubnetClashes(v.config, tunnelSubnet);
    if (clash.length > 0) return { success: false, error: clash[0], errors: clash };
    c.nat = v.config;
    saveWgConfig();
    return { success: true, nat: v.config };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not save the NAT configuration.' }; }
});
// One-click AmneziaWG install: download the official MSI, verify its
// Authenticode signature, install silently (one UAC prompt). Progress
// mirrors vpn-install-connect: { phase, pct, text } on
// 'wg-install-progress'. On Windows only — anywhere else the wrapper
// refuses before fetching anything.
ipcMain.handle('wg-install-amneziawg', async (event) => {
  try {
    return await wireguard.downloadAndInstallAmnezia((p) => {
      try { if (!event.sender.isDestroyed()) event.sender.send('wg-install-progress', p); } catch (e) {}
    });
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not install AmneziaWG.' }; }
});
ipcMain.handle('vault-change-password', async (event, oldPassword, newPassword) => {
  try {
    vaultKey = vault.changeMasterPassword(app.getPath('userData'), oldPassword, newPassword);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});
ipcMain.handle('vault-has-job-password', async (event, jobId) => {
  if (!vaultKey || !jobId) return { has: false };
  try { return { has: vault.hasJobPassword(app.getPath('userData'), vaultKey, jobId) }; }
  catch (e) { return { has: false }; }
});
ipcMain.handle('vault-store-job-password', async (event, jobId, jobPassword) => {
  if (!vaultKey) return { success: false, error: 'Vault is locked.' };
  try {
    vault.storeJobPassword(app.getPath('userData'), vaultKey, jobId, jobPassword);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

// Settings window
ipcMain.handle('window-show-settings', async () => {
  if (!settingsWindow) {
    settingsWindow = new BrowserWindow({
      width: 400,
      height: 500,
      icon: APP_ICON,
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false
      }
    });
    settingsWindow.loadFile(path.join(__dirname, 'settings.html'));
    settingsWindow.on('closed', () => {
      settingsWindow = null;
    });
  } else {
    settingsWindow.show();
  }
  return { success: true };
});

ipcMain.handle('window-close-settings', async () => {
  if (settingsWindow) {
    settingsWindow.close();
  }
  return { success: true };
});

// Job detail actions
ipcMain.handle('job-open-edit', async (event, jobId) => {
  // This will open the job edit modal - for now just return the job
  const job = jobHistory.find(j => j.id === jobId);
  if (job) {
    // Open edit wizard or modal
    return { success: true, job: job };
  }
  return { success: false, error: 'Job not found' };
});

ipcMain.handle('job-run-backup', async (event, jobId) => {
  const job = jobHistory.find(j => j.id === jobId);
  if (!job) {
    return { success: false, error: 'Job not found' };
  }
  const jobName = job.name || 'Unnamed Job';
  // Never run the same job twice at once (see backup-run-full).
  for (const [, a] of activeJobs) {
    if (a.name === jobName || a.jobId === job.id) {
      return { success: false, error: 'ALREADY_RUNNING', message: `A backup of "${jobName}" is already running.`, name: jobName };
    }
  }
  // Resolve removable drives first (the old handler skipped this
  // entirely, so a job whose disk had moved letters failed inside
  // the engine with a confusing error).
  const src = await driveResolver.resolvePathAsync(jobPathValue(job.source), job.sourceDriveMatch || job.sourceVolumeLabel || null);
  const dst = await driveResolver.resolvePathAsync(jobPathValue(job.destination), job.destinationDriveMatch || job.destinationVolumeLabel || null);
  // A missing SOURCE always blocks the run. A missing DESTINATION
  // blocks it only when its drive is provably absent: a destination
  // folder that does not exist yet is created by the engine, so
  // reporting "drive not found" for it was wrong.
  const missing = !src.found ? { which: 'source', res: src } : ((!dst.found && dst.drivePresent === false) ? { which: 'destination', res: dst } : null);
  if (missing) {
    const errText = `${missing.which === 'source' ? 'Source' : 'Destination'} drive not found: ${missing.res.path} — plug the disk back in and run again.`;
    appendAppLog('error', `Manual backup "${jobName}" FAILED: ${errText}`);
    notifyEmail('failed', { name: jobName, type: 'full', files: 0, size: 0, duration: 0, error: errText });
    return { success: false, error: 'SOURCE_DRIVE_NOT_FOUND', message: errText, name: jobName, status: 'failed' };
  }

  // Use the job's full configuration — the old handler rebuilt a
  // partial config that dropped the include/exclude patterns, ran
  // FULL every time, and never passed the compression setting.
  const backupConfig = {
    name: job.name,
    source: src.remapped ? src.path : job.source,
    destination: dst.remapped ? dst.path : job.destination,
    compression: job.compression,
    compress: job.compress,
    encryptionEnabled: job.encryptionEnabled === true,
    allowIncremental: job.allowIncremental,
    includePatterns: job.includePatterns,
    excludePatterns: job.excludePatterns,
    id: job.id,
    options: job.options || {}
  };
  if (backupConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(backupConfig);
    if (!pw) return { success: false, error: 'ENCRYPTION_PASSWORD_REQUIRED' };
    backupConfig.encryptionPassword = pw;
  }

  const useIncremental = backupConfig.allowIncremental === true && (job.runCount > 0 || (job.runs && job.runs.length > 0));
  const runType = useIncremental ? 'incremental' : 'full';
  const runJobId = `${jobName}-${Date.now()}`;
  activeJobs.set(runJobId, { name: jobName, jobId: job.id, status: 'running' });
  notifyEmail('started', { name: jobName, type: runType, source: jobPathValue(backupConfig.source), destination: jobPathValue(backupConfig.destination) });

  let result;
  try {
    const engine = new BackupEngine(backupConfig);
    engine.logger = true;
    result = useIncremental ? await engine.run_incremental_backup() : await engine.run_full_backup();
  } catch (e) {
    result = { success: false, files_backed_up: 0, total_bytes: 0, duration_seconds: 0, error_messages: [e.message], backup_path: '' };
    appendAppLog('error', `Manual backup "${jobName}" FAILED: ${e.message}`);
  }

  const jobRecord = {
    id: runJobId,
    jobId: job.id || null,
    name: jobName,
    type: runType,
    success: result.success,
    status: result.success ? 'completed' : 'failed',
    source: jobPathValue(backupConfig.source),
    destination: jobPathValue(backupConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result
  };
  recordRun(jobName, jobRecord);
  saveJobHistory();
  notifyJobsUpdated();
  activeJobs.delete(runJobId);
  notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
  return { success: result.success, job: job, result: result };
});

ipcMain.handle('job-restore', async (event, jobId) => {
  const job = jobHistory.find(j => j.id === jobId);
  if (!job) {
    return { success: false, error: 'Job not found' };
  }
  
  if (!job.result || !job.result.backup_path) {
    return { success: false, error: 'Job has no backup to restore' };
  }
  
  const restoreDir = promptRestoreDir();
  if (!restoreDir) {
    return { success: false, error: 'Restore cancelled' };
  }

  // An encrypted job's restore used to call restore_all with no
  // password at all, so it always failed with "password required".
  // Resolve it the same way a backup run does (typed password, then
  // the vault when unlocked).
  let restorePassword = null;
  if (job.encryptionEnabled === true) {
    restorePassword = resolveBackupPassword({ id: job.id, encryptionEnabled: true });
    if (!restorePassword) return { success: false, error: 'ENCRYPTION_PASSWORD_REQUIRED', message: 'This backup is encrypted. Unlock the vault (or enter the backup password) and try again.' };
  }
  const restoreEngine = new RestoreEngine();
  const result = await restoreEngine.restore_all(job.result.backup_path, restoreDir, restorePassword);

  return { success: result.success, files_restored: result.files_restored || 0, errors: result.errors || [] };
});

ipcMain.handle('job-delete', async (event, jobId) => {
  // Templates are saved by NAME (<name>.json) but their in-memory id is
  // generated, so deleting by id alone never removed the file. Try id,
  // then name, then a config file named after the id.
  let idx = jobHistory.findIndex(j => j.id === jobId);
  if (idx < 0) idx = jobHistory.findIndex(j => j.name === jobId);
  if (idx >= 0) {
    const job = jobHistory[idx];
    for (const fileName of [`${jobId}.json`, `${job.name}.json`]) {
      try {
        const jobPath = path.join(app.getPath('userData'), '.techvision', 'jobs', fileName);
        if (fs.existsSync(jobPath)) { fs.unlinkSync(jobPath); console.log(`[Main] Deleted job config file: ${jobPath}`); }
      } catch (e) { console.error(`[Main] Failed to delete job config file:`, e.message); }
    }
    jobHistory.splice(idx, 1);
    saveJobHistory();
    notifyJobsUpdated();
    return { success: true };
  }
  const orphanPath = path.join(app.getPath('userData'), '.techvision', 'jobs', `${jobId}.json`);
  try {
    if (jobId && fs.existsSync(orphanPath)) { fs.unlinkSync(orphanPath); return { success: true }; }
  } catch (e) { /* fall through to not found */ }
  return { success: false, error: 'Job not found' };
});

function promptRestoreDir() {
  // Return a default restore directory
  return path.join(app.getPath('documents'), 'TechVision Restores');
}