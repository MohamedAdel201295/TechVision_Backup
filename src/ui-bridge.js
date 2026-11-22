/**
 * TechVision Backup - Phase 2 UI Integration
 * This file bridges the Electron UI with the backup engine
 * 
 * VSS Status: DEFERRED - locked files skipped in MVP
 * Full VSS via vssadmin/PowerShell will be implemented in a future phase
 */

// IPC event handlers for UI feedback
const { ipcMain } = require('electron');

class UIBridge {
  constructor(win, backupEngine, restoreEngine) {
    this.win = win;
    this.backupEngine = backupEngine;
    this.restoreEngine = restoreEngine;
    this.setupIPC();
  }

  setupIPC() {
    // Backup progress
    ipcMain.on('ui-backup-progress', (event, jobId, entry) => {
      this.win?.webContents.send('backup-progress', jobId, entry);
    });

    // Backup complete
    ipcMain.on('ui-backup-complete', (event, jobId, result) => {
      this.win?.webContents.send('backup-complete', jobId, result);
    });

    // Log output
    ipcMain.on('ui-log-output', (event, level, message) => {
      this.win?.webContents.send('log-output', level, message);
    });
  }

  sendProgress(jobId, progress) {
    this.win?.webContents.send('backup-progress', jobId, progress);
  }

  sendComplete(jobId, result) {
    this.win?.webContents.send('backup-complete', jobId, result);
  }
}

module.exports = { UIBridge };