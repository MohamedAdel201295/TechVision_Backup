/**
 * TechVision Backup - Main Process
 * Electron main process for backup application
 */

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { BackupEngine, JobConfig, BackupResult } = require('./techvision-core.js');
const { RestoreEngine } = require('./restore.js');

const isDevelopment = !app.isPackaged;

// Assets path for icons
const ASSETS_PATH = path.join(__dirname, 'assets');
const APP_ICON = path.join(ASSETS_PATH, 'TechVision_Logo.png');

// Main window
let mainWindow;
let restoreWindow;
let logViewerWindow;
let jobWizardWindow;
let settingsWindow;
let jobDetailsWindow;

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
  return {
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
    loaded: job.loaded || false
  };
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
}

// Save job history to disk
function saveJobHistory() {
  const historyPath = getHistoryPath();
  const jobsDir = path.dirname(historyPath);
  try {
    if (!fs.existsSync(jobsDir)) {
      fs.mkdirSync(jobsDir, { recursive: true });
    }
    // Filter out loaded templates and keep only actual job records
    const recordsToSave = jobHistory.filter(j => !j.loaded);
    fs.writeFileSync(historyPath, JSON.stringify(recordsToSave, null, 2));
    console.log(`[Main] Saved ${recordsToSave.length} job history records`);
  } catch (e) {
    console.error('[Main] Failed to save job history:', e.message);
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
  loadStoredJobs(); // Load stored jobs on startup
  createMainWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC Handlers

// Backup operations
ipcMain.handle('backup-run-full', async (event, jobConfig) => {
  const jobName = jobConfig.name || `backup-${Date.now()}`;
  const engine = new BackupEngine(jobConfig);
  
  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, status: 'running' });
  
  engine.logger = true; // Enable logging
  
  const result = await engine.run_full_backup();
  
  const jobRecord = {
    id: jobId,
    name: jobName,
    type: 'full',
    status: result.success ? 'completed' : 'failed',
    source: jobPathValue(jobConfig.source),
    destination: jobPathValue(jobConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result
  };

  jobHistory.push(jobRecord);
  saveJobHistory();
  activeJobs.delete(jobId);

  console.log(`[Main] Backup completed: ${jobName}, saved to history`);
  return jobRecord;
});

ipcMain.handle('backup-run-incremental', async (event, jobConfig) => {
  const jobName = jobConfig.name || `incremental-${Date.now()}`;
  const engine = new BackupEngine(jobConfig);
  
  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, status: 'running' });
  
  engine.logger = true;
  
  const result = await engine.run_incremental_backup();
  
  const jobRecord = {
    id: jobId,
    name: jobName,
    type: 'incremental',
    status: result.success ? 'completed' : 'failed',
    source: jobPathValue(jobConfig.source),
    destination: jobPathValue(jobConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result
  };
  
  jobHistory.push(jobRecord);
  saveJobHistory();
  activeJobs.delete(jobId);
  
  console.log(`[Main] Incremental backup completed: ${jobName}`);
  return jobRecord;
});

// Restore operations
ipcMain.handle('restore-all', async (event, zipPath, restoreDir) => {
  try {
    const restoreEngine = new RestoreEngine();
    const result = await restoreEngine.restore_all(zipPath, restoreDir);
    return { success: true, files: result.files || 0, size: result.size || 0 };
  } catch (err) {
    return { success: false, error: err && err.message ? err.message : String(err) };
  }
});

ipcMain.handle('restore-single', async (event, zipPath, entryName, destPath) => {
  const restoreEngine = new RestoreEngine();
  const result = await restoreEngine.restoreFile(zipPath, entryName, destPath);
  return { success: true };
});

// File operations
// Use the window that actually called the dialog as its parent.
// Using mainWindow here made the picker open behind the job/restore
// wizard, which looked like "Browse does nothing".
function dialogParentWindow(event) {
  try {
    return (event && event.sender && BrowserWindow.fromWebContents(event.sender)) || mainWindow;
  } catch (e) {
    return mainWindow;
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
  return { success: true };
});

ipcMain.handle('job-get-config', async (event, jobId) => {
  const jobPath = path.join(app.getPath('userData'), '.techvision', 'jobs', `${jobId}.json`);
  try {
    if (fs.existsSync(jobPath)) {
      const content = fs.readFileSync(jobPath, 'utf-8');
      return JSON.parse(content);
    }
    return null;
  } catch (e) {
    return null;
  }
});

ipcMain.handle('job-save-config', async (event, jobConfig) => {
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  if (!fs.existsSync(jobsDir)) {
    fs.mkdirSync(jobsDir, { recursive: true });
  }
  const jobPath = path.join(jobsDir, `${jobConfig.name}.json`);
  try {
    fs.writeFileSync(jobPath, JSON.stringify(jobConfig, null, 2));
    console.log(`[Main] Job saved to: ${jobPath}`);
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
ipcMain.handle('window-show-job-wizard', async () => {
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

ipcMain.handle('window-show-restore-wizard', async () => {
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
  return { success: true };
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
    options: job.options || { incremental: false, compress: true, verify: true }
  };
  
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
  const idx = jobHistory.findIndex(j => j.id === jobId);
  if (idx >= 0) {
    jobHistory.splice(idx, 1);
    saveJobHistory();
    return { success: true };
  }
  return { success: false, error: 'Job not found' };
});

function promptRestoreDir() {
  // Return a default restore directory
  return path.join(app.getPath('documents'), 'TechVision Restores');
}