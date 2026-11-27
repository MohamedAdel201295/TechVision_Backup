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
  restoreAll: (zipPath, restoreDir, password, options) => ipcRenderer.invoke('restore-all', zipPath, restoreDir, password, options),
  restoreSingle: (zipPath, entryName, destPath, password, options) => ipcRenderer.invoke('restore-single', zipPath, entryName, destPath, password, options),

  // File system operations
    readDir: (dirPath) => ipcRenderer.invoke('fs-readdir', dirPath),
    statFile: (filePath) => ipcRenderer.invoke('fs-stat', filePath),
    readFile: (filePath) => ipcRenderer.invoke('fs-read-file', filePath),
    mkdir: (dirPath, recursive) => ipcRenderer.invoke('fs-mkdir', dirPath, recursive),
    writeFile: (filePath, content) => ipcRenderer.invoke('fs-write-file', filePath, content),
    deleteFile: (filePath) => ipcRenderer.invoke('fs-delete', filePath),
    fileExists: (filePath) => ipcRenderer.invoke('fs-exists', filePath),
    getZipInfo: (zipPath) => ipcRenderer.invoke('zip-get-info', zipPath),
    getDriveUsage: (targetPath) => ipcRenderer.invoke('fs-drive-usage', targetPath),
    openPath: (targetPath) => ipcRenderer.invoke('fs-open-path', targetPath),
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
    vaultReset: (masterPassword) => ipcRenderer.invoke('vault-reset', masterPassword),
    vaultUnlock: (masterPassword) => ipcRenderer.invoke('vault-unlock', masterPassword),
    vaultLock: () => ipcRenderer.invoke('vault-lock'),
    vaultChangePassword: (oldPassword, newPassword) => ipcRenderer.invoke('vault-change-password', oldPassword, newPassword),
    vaultHasJobPassword: (jobId) => ipcRenderer.invoke('vault-has-job-password', jobId),
    vaultStoreJobPassword: (jobId, jobPassword) => ipcRenderer.invoke('vault-store-job-password', jobId, jobPassword),

  // Job detail actions
  openEditJob: (jobId) => ipcRenderer.invoke('job-open-edit', jobId),
  runBackupForJob: (jobId) => ipcRenderer.invoke('job-run-backup', jobId),
  stopBackup: (jobId) => ipcRenderer.invoke('job-stop-backup', jobId),
  restoreJob: (jobId) => ipcRenderer.invoke('job-restore', jobId),
  deleteJob: (jobId) => ipcRenderer.invoke('job-delete', jobId),

  // Window management — the wizard and restore are in-place views in
  // the main window now (no second window). These two calls only hand
  // the pending job to main; the wizard scripts read it back with
  // getJobConfig(null) when the view opens.
    setWizardPending: (job) => ipcRenderer.invoke('wizard-set-pending', job || null),
    setRestorePending: (job) => ipcRenderer.invoke('restore-set-pending', job || null),

  // Refresh jobs list
  refreshJobs: (jobs) => ipcRenderer.invoke('jobs-refresh', jobs),

  // Event listeners for real-time updates
  // onBackupProgress returns an unsubscribe function so a run can stop
  // listening when it finishes (no duplicate listeners on repeat runs).
  onBackupProgress: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('backup-progress', h); return () => ipcRenderer.removeListener('backup-progress', h); },
  onCloudProgress: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('cloud-progress', h); return () => ipcRenderer.removeListener('cloud-progress', h); },
  // Temp + save-back results from main (saved-back / conflict / error)
  onCloudSaveback: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('cloud-saveback', h); return () => ipcRenderer.removeListener('cloud-saveback', h); },

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
  // TechVision Cloud — open mode + Office direct open (spec v2)
  cloudSetOpenMode: (mode) => ipcRenderer.invoke('cloud-set-open-mode', mode),
  cloudOfficeOpen: (serverId, relPath) => ipcRenderer.invoke('cloud-office-open', serverId, relPath),
  cloudMediaOpen: (serverId, relPath) => ipcRenderer.invoke('cloud-media-open', serverId, relPath),
  cloudClipboardFiles: () => ipcRenderer.invoke('cloud-clipboard-files'),
  cloudClientMkdir: (serverId, relPath) => ipcRenderer.invoke('cloud-client-mkdir', serverId, relPath),
  cloudClientDelete: (serverId, relPath) => ipcRenderer.invoke('cloud-client-delete', serverId, relPath),
  cloudClientRename: (serverId, from, to) => ipcRenderer.invoke('cloud-client-rename', serverId, from, to),
  cloudClientCopy: (serverId, from, to) => ipcRenderer.invoke('cloud-client-copy', serverId, from, to),
  // TechVision Cloud — Map network drive
  cloudMapdriveStatus: () => ipcRenderer.invoke('cloud-mapdrive-status'),
  cloudMapdriveMap: (serverId, letter, reconnect) => ipcRenderer.invoke('cloud-mapdrive-map', serverId, letter, reconnect),
  cloudMapdriveDisconnect: (serverId) => ipcRenderer.invoke('cloud-mapdrive-disconnect', serverId),
  cloudMapdriveOpenExplorer: (letter) => ipcRenderer.invoke('cloud-mapdrive-open-explorer', letter),
  cloudMapdriveOpenMapped: (serverId, relPath) => ipcRenderer.invoke('cloud-mapdrive-open-mapped', serverId, relPath),
  // TechVision WireGuard VPN — self-hosted WireGuard (no coordination server)
  wgGetStatus: () => ipcRenderer.invoke('wg-get-status'),
  wgListPeers: () => ipcRenderer.invoke('wg-list-peers'),
  wgStartServer: () => ipcRenderer.invoke('wg-start-server'),
  wgStopServer: () => ipcRenderer.invoke('wg-stop-server'),
  wgSetEndpoint: (endpoint) => ipcRenderer.invoke('wg-set-endpoint', endpoint),
  wgSetServerSettings: (opts) => ipcRenderer.invoke('wg-set-server-settings', opts),
  wgServerExport: () => ipcRenderer.invoke('wg-server-export'),
  wgServerImport: () => ipcRenderer.invoke('wg-server-import'),
  wgNatExport: () => ipcRenderer.invoke('wg-nat-export'),
  wgNatImport: () => ipcRenderer.invoke('wg-nat-import'),
  wgAddPeer: (opts) => ipcRenderer.invoke('wg-add-peer', opts),
  wgRemovePeer: (opts) => ipcRenderer.invoke('wg-remove-peer', opts),
  wgOpenDownload: () => ipcRenderer.invoke('wg-open-download'),
  // TechVision WireGuard VPN — gateway NAT service (site-to-site)
  wgNatStart: (opts) => ipcRenderer.invoke('wg-nat-start', opts || null),
  wgNatStop: () => ipcRenderer.invoke('wg-nat-stop'),
  wgNatStatus: () => ipcRenderer.invoke('wg-nat-status'),
  wgNatSave: (config) => ipcRenderer.invoke('wg-nat-save', config),
  wgInstallAmneziawg: () => ipcRenderer.invoke('wg-install-amneziawg'),
  // TechVision Tailscale VPN — Tailscale client manager (no VPN of its own)
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
  onWgInstallProgress: (callback) => { const h = (event, ...args) => callback(...args); ipcRenderer.on('wg-install-progress', h); return () => ipcRenderer.removeListener('wg-install-progress', h); },
  vpnOpenDownload: () => ipcRenderer.invoke('vpn-open-download'),
  vpnOpenAuthUrl: (url) => ipcRenderer.invoke('vpn-open-auth-url', url),
  vpnOpenAdmin: () => ipcRenderer.invoke('vpn-open-admin'),
  onBackupComplete: (callback) => ipcRenderer.on('backup-complete', (event, ...args) => callback(...args)),
  onJobsUpdated: (callback) => ipcRenderer.on('jobs-updated', () => callback()),

  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});
