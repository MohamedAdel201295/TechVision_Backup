/**
 * TechVision Backup - Main Process
 * Electron main process for backup application
 */

const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } = require('electron');
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
  }
  return cloudServer;
}
// Client sessions live in main only (tokens never reach the renderer):
// serverId -> { host, port, certPem, token, user, root, canWrite }
const cloudSessions = new Map();

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
    if (!job) {
      job = normalizeJobObject(entry, isRunRecord ? 'full' : 'template');
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
      if (entry.source) job.source = entry.source;
      if (entry.destination) job.destination = entry.destination;
      if (entry.schedule) job.schedule = entry.schedule;
      if (entry.compress !== undefined) job.compress = entry.compress;
      if (entry.compression) job.compression = entry.compression;
      if (entry.allowIncremental !== undefined) job.allowIncremental = entry.allowIncremental;
      if (entry.verify !== undefined) job.verify = entry.verify;
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
    // job on load. Templates with no runs save nothing.
    const recordsToSave = [];
    for (const j of jobHistory) {
      for (const r of (j.runs || [])) {
        recordsToSave.push({
          id: r.id, name: j.name, type: r.type, status: r.status,
          success: r.success, source: j.source, destination: j.destination,
          timestamp: r.timestamp, files: r.files, size: r.size,
          duration: r.duration, error: r.error || null, result: r.result || null
        });
      }
    }
    fs.writeFileSync(historyPath, JSON.stringify(recordsToSave, null, 2));
    console.log(`[Main] Saved ${recordsToSave.length} job history records`);
  } catch (e) {
    console.error('[Main] Failed to save job history:', e.message);
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
    target.setDate(target.getDate() + 7);
    return target;
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
    target.setMonth(target.getMonth() + 1);
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
  // cannot run without the password, so skip this run and say so in
  // the log instead of failing silently or running unencrypted.
  if (jobConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(jobConfig);
    if (!pw) {
      console.log(`[Scheduler] Skipped encrypted job ${job.name}: vault is locked or no password is saved. Unlock the vault in Settings to let scheduled encrypted backups run.`);
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
    const resolved = await resolveJobPaths(job);
    if (resolved.source.found && resolved.destination.found) {
      if (job.waitingForDrive) { delete job.waitingForDrive; notifyJobsUpdated(); }
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
      appendAppLog('warn', `Job "${job.name}" is due but the ${missing} drive is missing (${missingPath}). Waiting for the drive — the job will run as soon as it appears.`);
      console.log(`[Scheduler] Job ${job.name} waiting for ${missing} drive: ${missingPath}`);
      notifyJobsUpdated();
      continue;
    }
    // Still waiting: give up after DRIVE_WAIT_MS, record the failure
    // and email about it — the user asked for an error, not silence.
    if (now - new Date(job.waitingForDrive.since) >= DRIVE_WAIT_MS) {
      const errText = `Source drive not found: ${job.waitingForDrive.path} (volume "${job.waitingForDrive.label || 'unknown'}") was not available within 2 hours of the scheduled time.`;
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
    label: (info && info.label) || prev.label || null,
    serial: (info && info.serial) || prev.serial || null,
    serialKind: (info && info.serialKind) || prev.serialKind || null
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
  const engine = new BackupEngine(jobConfig);

  // Real progress for the window that started the run: the renderer
  // used to fake the bar (raced to 92% and froze). The engine now
  // reports real bytes; forward them as they arrive.
  engine.onProgress = (p) => {
    try { if (event.sender && !event.sender.isDestroyed()) event.sender.send('backup-progress', p); } catch (e) {}
  };

  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, status: 'running' });

  notifyEmail('started', { name: jobName, type: 'full', source: jobPathValue(jobConfig.source), destination: jobPathValue(jobConfig.destination) });

  engine.logger = true; // Enable logging

  const result = await engine.run_full_backup();
  
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
  if (jobRecord.success && jobConfig.encryptionEnabled && vaultKey && jobConfig.id && jobConfig.encryptionPassword) {
    try { vault.storeJobPassword(app.getPath('userData'), vaultKey, jobConfig.id, jobConfig.encryptionPassword); } catch (e) {}
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
  const engine = new BackupEngine(jobConfig);

  // Real progress for the window that started the run (see full backup).
  engine.onProgress = (p) => {
    try { if (event.sender && !event.sender.isDestroyed()) event.sender.send('backup-progress', p); } catch (e) {}
  };

  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, status: 'running' });
  notifyEmail('started', { name: jobName, type: 'incremental', source: jobPathValue(jobConfig.source), destination: jobPathValue(jobConfig.destination) });

  engine.logger = true;

  const result = await engine.run_incremental_backup();
  
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
    try { vault.storeJobPassword(app.getPath('userData'), vaultKey, jobConfig.id, jobConfig.encryptionPassword); } catch (e) {}
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
    fs.writeFileSync(jobPath, JSON.stringify(jobConfig, null, 2));
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
  vaultKey = null;
  return { success: true };
});

// ---------- TechVision Cloud ----------
// Config + server status. Passwords and the server private key never
// leave main; the renderer only sees public config and user names.
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
      accessMode: cfg.server.accessMode === 'tailscale' ? 'tailscale' : 'normal',
    },
    clients: (cfg.clients || []).map((c) => ({ id: c.id, name: c.name, host: c.host, port: c.port, user: c.user, fingerprint: c.fingerprint || null, accessMode: c.accessMode === 'tailscale' ? 'tailscale' : 'normal' })),
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
  const accessMode = (opts && opts.accessMode === 'tailscale') ? 'tailscale' : 'normal';
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

// Saved servers (client side). Passwords are never stored here.
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
    // (e.g. the trust flow): a Tailscale server must not silently
    // become Normal on re-save.
    const accessMode = s.accessMode === 'tailscale' ? 'tailscale'
      : s.accessMode === 'normal' ? 'normal'
      : (existing && existing.accessMode === 'tailscale' ? 'tailscale' : 'normal');
    const rec = { id, name: String(s.name || host), host, port, user: String(s.user || ''), fingerprint: s.fingerprint || null, certPem: s.certPem || null, accessMode };
    if (i >= 0) { rec.id = cfg.clients[i].id; if (!rec.fingerprint) rec.fingerprint = cfg.clients[i].fingerprint; if (!rec.certPem) rec.certPem = cfg.clients[i].certPem; cfg.clients[i] = rec; }
    else cfg.clients.push(rec);
    saveCloudConfig();
    return { success: true, id };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
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

ipcMain.handle('cloud-client-connect', async (event, opts) => {
  try {
    const conn = await cloudClient.login(opts.host, parseInt(opts.port, 10), opts.certPem, opts.user, opts.password);
    const info = await cloudClient.info(conn);
    cloudSessions.set(opts.serverId, Object.assign({}, conn, { user: info.user, root: info.root, canWrite: info.canWrite }));
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
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  try {
    const r = await cloudClient.list(conn, relPath || '');
    return { success: true, path: r.path, entries: r.entries };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
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

// ---------- TechVision VPN (Tailscale client manager) ----------
// The module only shells out to the Tailscale CLI that is already
// installed on the machine; it implements no VPN of its own.
ipcMain.handle('vpn-get-status', async () => {
  try { return await vpn.getStatus(); }
  catch (e) { return { installed: true, connected: false, error: e && e.message ? e.message : 'Could not read Tailscale status.' }; }
});
ipcMain.handle('vpn-set-connected', async (event, on) => {
  try { return await vpn.setConnected(!!on); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not change the VPN connection.' }; }
});
ipcMain.handle('vpn-set-routes', async (event, on) => {
  try { return await vpn.setSubnetRouter(!!on); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not change the subnet router setting.' }; }
});
ipcMain.handle('vpn-disable-key-expiry', async () => {
  try { return await vpn.disableKeyExpiry(); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not disable key expiry.' }; }
});
ipcMain.handle('vpn-install-connect', async (event) => {
  try {
    return await vpn.installAndConnect((p) => {
      try { if (!event.sender.isDestroyed()) event.sender.send('vpn-install-progress', p); } catch (e) {}
    });
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not install Tailscale.' }; }
});
ipcMain.handle('vpn-open-download', async () => {
  try { await require('electron').shell.openExternal('https://tailscale.com/download'); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the download page.' }; }
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
  
  // Use job configuration for backup
  const backupConfig = {
    name: job.name,
    source: job.source,
    destination: job.destination,
    compression: job.compression,
    encryptionEnabled: job.encryptionEnabled === true,
    id: job.id,
    options: job.options || { incremental: false, compress: true, verify: true }
  };
  if (backupConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(backupConfig);
    if (!pw) return { success: false, error: 'ENCRYPTION_PASSWORD_REQUIRED' };
    backupConfig.encryptionPassword = pw;
  }
  
  const engine = new BackupEngine(backupConfig);
  engine.logger = true;
  
  const result = await engine.run_full_backup();
  
  job.status = result.success ? 'completed' : 'failed';
  job.timestamp = new Date().toISOString();
  job.files = result.files_backed_up;
  job.size = result.total_bytes;
  job.duration = result.duration_seconds;
  job.result = result;
  
  // Update history
  const idx = jobHistory.findIndex(j => j.id === jobId);
  if (idx >= 0) {
    jobHistory[idx] = job;
  }
  saveJobHistory();
  
  return { success: true, job: job };
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
  
  const restoreEngine = new RestoreEngine();
  const result = await restoreEngine.restore_all(job.result.backup_path, restoreDir);
  
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