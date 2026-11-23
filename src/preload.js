/**
 * TechVision Backup - Preload Script
 * Context bridge for IPC between renderer and main process
 * No nodeIntegration - all privileged operations go through this bridge
 */

const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// specific node.js APIs without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Backup operations
  runFullBackup: (jobConfig) => ipcRenderer.invoke('backup-run-full', jobConfig),
  runIncrementalBackup: (jobConfig) => ipcRenderer.invoke('backup-run-incremental', jobConfig),

  // Restore operations
  restoreAll: (zipPath, restoreDir) => ipcRenderer.invoke('restore-all', zipPath, restoreDir),
  restoreSingle: (zipPath, entryName, destPath) => ipcRenderer.invoke('restore-single', zipPath, entryName, destPath),

  // File system operations
    readDir: (dirPath) => ipcRenderer.invoke('fs-readdir', dirPath),
    statFile: (filePath) => ipcRenderer.invoke('fs-stat', filePath),
    readFile: (filePath) => ipcRenderer.invoke('fs-read-file', filePath),
    mkdir: (dirPath, recursive) => ipcRenderer.invoke('fs-mkdir', dirPath, recursive),
    writeFile: (filePath, content) => ipcRenderer.invoke('fs-write-file', filePath, content),
    deleteFile: (filePath) => ipcRenderer.invoke('fs-delete', filePath),
    fileExists: (filePath) => ipcRenderer.invoke('fs-exists', filePath),
    getZipInfo: (zipPath) => ipcRenderer.invoke('zip-get-info', zipPath),

    // Dialog operations
    showOpenDialog: (options) => ipcRenderer.invoke('dialog-showOpenDialog', options),
    showSaveDialog: (options) => ipcRenderer.invoke('dialog-showSaveDialog', options),

    // Job management
    getJobHistory: () => ipcRenderer.invoke('job-get-all'),
    getActiveJobs: () => ipcRenderer.invoke('job-get-active'),
    clearJobHistory: () => ipcRenderer.invoke('job-clear-history'),
    getStoredJobs: () => ipcRenderer.invoke('job-list-stored'),
    getJobConfig: (jobId) => ipcRenderer.invoke('job-get-config', jobId),
    saveJobConfig: (jobConfig) => ipcRenderer.invoke('job-save-config', jobConfig),

    // Settings
    getSettings: () => ipcRenderer.invoke('settings-get'),
    saveSettings: (settings) => ipcRenderer.invoke('settings-save', settings),
    sendTestEmail: () => ipcRenderer.invoke('email-test'),
    showSettingsWindow: () => ipcRenderer.invoke('window-show-settings'),
    closeSettings: () => ipcRenderer.invoke('window-close-settings'),

  // Job detail actions
  openEditJob: (jobId) => ipcRenderer.invoke('job-open-edit', jobId),
  runBackupForJob: (jobId) => ipcRenderer.invoke('job-run-backup', jobId),
  restoreJob: (jobId) => ipcRenderer.invoke('job-restore', jobId),
  deleteJob: (jobId) => ipcRenderer.invoke('job-delete', jobId),

  // Window management
    showJobWizard: (job) => ipcRenderer.invoke('window-show-job-wizard', job || null),
    showRestoreWizard: (job) => ipcRenderer.invoke('window-show-restore-wizard', job || null),
    showLogViewer: () => ipcRenderer.invoke('window-show-log-viewer'),
    closeLogViewer: () => ipcRenderer.invoke('window-close-log-viewer'),
    closeJobWizard: () => ipcRenderer.invoke('window-close-job-wizard'),
    closeRestoreWizard: () => ipcRenderer.invoke('window-close-restore-wizard'),
    getRecentLog: () => ipcRenderer.invoke('log-get-recent'),

  // Refresh jobs list
  refreshJobs: (jobs) => ipcRenderer.invoke('jobs-refresh', jobs),

  // Event listeners for real-time updates
  onBackupProgress: (callback) => ipcRenderer.on('backup-progress', (event, ...args) => callback(...args)),
  onBackupComplete: (callback) => ipcRenderer.on('backup-complete', (event, ...args) => callback(...args)),
  onJobsUpdated: (callback) => ipcRenderer.on('jobs-updated', () => callback()),

  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});
