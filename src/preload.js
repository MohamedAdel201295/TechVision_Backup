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
  restoreAll: (zipPath, restoreDir, password) => ipcRenderer.invoke('restore-all', zipPath, restoreDir, password),
  restoreSingle: (zipPath, entryName, destPath, password) => ipcRenderer.invoke('restore-single', zipPath, entryName, destPath, password),

  // File system operations
    readDir: (dirPath) => ipcRenderer.invoke('fs-readdir', dirPath),
    statFile: (filePath) => ipcRenderer.invoke('fs-stat', filePath),
    readFile: (filePath) => ipcRenderer.invoke('fs-read-file', filePath),
    mkdir: (dirPath, recursive) => ipcRenderer.invoke('fs-mkdir', dirPath, recursive),
    writeFile: (filePath, content) => ipcRenderer.invoke('fs-write-file', filePath, content),
    deleteFile: (filePath) => ipcRenderer.invoke('fs-delete', filePath),
    fileExists: (filePath) => ipcRenderer.invoke('fs-exists', filePath),
    getZipInfo: (zipPath) => ipcRenderer.invoke('zip-get-info', zipPath),
    getAppLog: () => ipcRenderer.invoke('logs-get'),

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
    getDrives: () => ipcRenderer.invoke('get-drives'),

    // Settings
    getSettings: () => ipcRenderer.invoke('settings-get'),
    saveSettings: (settings) => ipcRenderer.invoke('settings-save', settings),
    sendTestEmail: () => ipcRenderer.invoke('email-test'),

    // Master-password vault (job passwords for encrypted backups)
    vaultStatus: () => ipcRenderer.invoke('vault-status'),
    vaultSetup: (masterPassword) => ipcRenderer.invoke('vault-setup', masterPassword),
    vaultUnlock: (masterPassword) => ipcRenderer.invoke('vault-unlock', masterPassword),
    vaultLock: () => ipcRenderer.invoke('vault-lock'),
    vaultChangePassword: (oldPassword, newPassword) => ipcRenderer.invoke('vault-change-password', oldPassword, newPassword),
    vaultHasJobPassword: (jobId) => ipcRenderer.invoke('vault-has-job-password', jobId),
    vaultStoreJobPassword: (jobId, jobPassword) => ipcRenderer.invoke('vault-store-job-password', jobId, jobPassword),
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
  // onBackupProgress returns an unsubscribe function so a run can stop
  // listening when it finishes (no duplicate listeners on repeat runs).
  onBackupProgress: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('backup-progress', h); return () => ipcRenderer.removeListener('backup-progress', h); },
  onCloudProgress: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('cloud-progress', h); return () => ipcRenderer.removeListener('cloud-progress', h); },

  // TechVision Cloud — server
  cloudGetConfig: () => ipcRenderer.invoke('cloud-get-config'),
  cloudDetectIP: () => ipcRenderer.invoke('cloud-detect-ip'),
  cloudServerSave: (cfg) => ipcRenderer.invoke('cloud-server-save', cfg),
  cloudServerStart: () => ipcRenderer.invoke('cloud-server-start'),
  cloudServerStop: () => ipcRenderer.invoke('cloud-server-stop'),
  cloudUserAdd: (u) => ipcRenderer.invoke('cloud-user-add', u),
  cloudUserRemove: (name) => ipcRenderer.invoke('cloud-user-remove', name),
  cloudUserSetPassword: (name, password) => ipcRenderer.invoke('cloud-user-set-password', name, password),
  // TechVision Cloud — client (passwords are never stored)
  cloudClientSave: (s) => ipcRenderer.invoke('cloud-client-save', s),
  cloudClientRemove: (id) => ipcRenderer.invoke('cloud-client-remove', id),
  cloudClientForgetPassword: (id) => ipcRenderer.invoke('cloud-client-forget-password', id),
  cloudClientProbe: (host, port) => ipcRenderer.invoke('cloud-client-probe', host, port),
  cloudClientConnect: (opts) => ipcRenderer.invoke('cloud-client-connect', opts),
  cloudClientDisconnect: (serverId) => ipcRenderer.invoke('cloud-client-disconnect', serverId),
  cloudClientList: (serverId, relPath) => ipcRenderer.invoke('cloud-client-list', serverId, relPath),
  cloudClientDownload: (serverId, relPath, destDir) => ipcRenderer.invoke('cloud-client-download', serverId, relPath, destDir),
  cloudClientUpload: (serverId, localPath, remoteDir) => ipcRenderer.invoke('cloud-client-upload', serverId, localPath, remoteDir),
  cloudClientUploadFiles: (serverId, localPaths, remoteDir) => ipcRenderer.invoke('cloud-client-upload-files', serverId, localPaths, remoteDir),
  cloudClientOpen: (serverId, relPath) => ipcRenderer.invoke('cloud-client-open', serverId, relPath),
  cloudClipboardFiles: () => ipcRenderer.invoke('cloud-clipboard-files'),
  cloudClientMkdir: (serverId, relPath) => ipcRenderer.invoke('cloud-client-mkdir', serverId, relPath),
  cloudClientDelete: (serverId, relPath) => ipcRenderer.invoke('cloud-client-delete', serverId, relPath),
  cloudClientRename: (serverId, from, to) => ipcRenderer.invoke('cloud-client-rename', serverId, from, to),
  cloudClientCopy: (serverId, from, to) => ipcRenderer.invoke('cloud-client-copy', serverId, from, to),
  // TechVision WireGuard VPN — self-hosted WireGuard (no coordination server)
  wgGetStatus: () => ipcRenderer.invoke('wg-get-status'),
  wgListPeers: () => ipcRenderer.invoke('wg-list-peers'),
  wgStartServer: () => ipcRenderer.invoke('wg-start-server'),
  wgStopServer: () => ipcRenderer.invoke('wg-stop-server'),
  wgSetEndpoint: (endpoint) => ipcRenderer.invoke('wg-set-endpoint', endpoint),
  wgAddPeer: (opts) => ipcRenderer.invoke('wg-add-peer', opts),
  wgRemovePeer: (opts) => ipcRenderer.invoke('wg-remove-peer', opts),
  wgGenerateInvite: (opts) => ipcRenderer.invoke('wg-generate-invite', opts),
  wgImportConf: (opts) => ipcRenderer.invoke('wg-import-conf', opts),
  wgConnect: (opts) => ipcRenderer.invoke('wg-connect', opts),
  wgDisconnect: () => ipcRenderer.invoke('wg-disconnect'),
  wgOpenDownload: () => ipcRenderer.invoke('wg-open-download'),
  // TechVision VPN — Tailscale client manager (no VPN of its own)
  vpnGetStatus: () => ipcRenderer.invoke('vpn-get-status'),
  vpnSetConnected: (on) => ipcRenderer.invoke('vpn-set-connected', on),
  vpnSetRoutes: (on, auth) => ipcRenderer.invoke('vpn-set-routes', on, auth),
  vpnInstallConnect: (adminCreds) => ipcRenderer.invoke('vpn-install-connect', adminCreds || null),
  vpnDisableKeyExpiry: (auth) => ipcRenderer.invoke('vpn-disable-key-expiry', auth),
  vpnEnableKeyExpiry: (auth) => ipcRenderer.invoke('vpn-enable-key-expiry', auth),
  vpnKeyExpiryState: (auth) => ipcRenderer.invoke('vpn-key-expiry-state', auth),
  vpnVerifyApi: (auth) => ipcRenderer.invoke('vpn-verify-api', auth),
  vpnGetRoutes: (auth) => ipcRenderer.invoke('vpn-get-routes', auth),
  vpnApproveRoutes: (auth, routes) => ipcRenderer.invoke('vpn-approve-routes', auth, routes),
  vpnOpenKeysPage: () => ipcRenderer.invoke('vpn-open-keys-page'),
  vpnOpenOauthPage: () => ipcRenderer.invoke('vpn-open-oauth-page'),
  onVpnInstallProgress: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('vpn-install-progress', h); return () => ipcRenderer.removeListener('vpn-install-progress', h); },
  vpnOpenDownload: () => ipcRenderer.invoke('vpn-open-download'),
  vpnOpenAuthUrl: (url) => ipcRenderer.invoke('vpn-open-auth-url', url),
  vpnOpenAdmin: () => ipcRenderer.invoke('vpn-open-admin'),
  onBackupComplete: (callback) => ipcRenderer.on('backup-complete', (event, ...args) => callback(...args)),
  onJobsUpdated: (callback) => ipcRenderer.on('jobs-updated', () => callback()),

  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});
