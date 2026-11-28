/**
 * TechVision Backup - Main Process
 * Electron main process for backup application
 */

const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } = require('electron');
const os = require('os');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { BackupEngine, JobConfig, BackupResult } = require('./techvision-core.js');
const { RestoreEngine } = require('./restore.js');
const mailer = require('./mailer.js');
const vault = require('./vault.js');
const driveResolver = require('./drive-resolver.js');
const cloudServerMod = require('./cloud-server.js');
const cloudClient = require('./cloud-client.js');
const cloudMapDrive = require('./cloud-mapdrive.js');
const cloudSavebackMod = require('./cloud-saveback.js');
const vpn = require('./vpn.js');
const wireguard = require('./wireguard.js');
const natGateway = require('./nat-gateway.js');
const wgControl = require('./wg-control.js');
// How long a due scheduled job waits for a missing removable drive
// before it is recorded as failed (and emailed about): 2 hours.
const DRIVE_WAIT_MS = 2 * 60 * 60 * 1000;
// Master-password vault: the derived key lives ONLY in memory while
// the vault is unlocked. Nothing about the master password or any job
// password is ever written to disk in the clear.
let vaultKey = null;

// Round 3 — vault overhaul: the vault now also holds the Cloud
// client, SMTP and Tailscale secrets (generic secrets), and legacy
// plaintext passwords are migrated into the vault on first unlock.
// Machine keys (Cloud TLS private key, WireGuard private keys) stay
// plaintext by design — auto-start — and are NOT vault secrets.
//
// Master-password model (changed 2026-11-27, replaces the round-3
// "remember-me" agreement): the program asks for the master
// password at EVERY startup — there is NO silent auto-unlock and no
// remember-me blob is written. Typing the existing key unlocks the
// vault and all saved passwords work again. Creating a NEW key at
// startup (without the old one) REPLACES the vault: every saved
// password is lost, so the UI warns first and requires a
// confirmation. Changing the key in Settings (old key known) is the
// opposite: it re-encrypts the vault and saved passwords are KEPT.

// After any successful unlock: migrate any plaintext passwords still
// sitting in cloud.json / settings.json into the vault. Never
// throws — a failure here must never block the app.
function afterVaultUnlocked() {
  try {
    if (vaultKey) {
      const moved = vault.migrateLegacySecrets(app.getPath('userData'), vaultKey);
      if (moved.cloud || moved.smtp || moved.apiToken || moved.oauthSecret) {
        console.log('[Vault] Migrated plaintext passwords into the vault: ' + JSON.stringify(moved));
        appendAppLog('info', 'Moved saved passwords (Cloud, email, Tailscale) into the encrypted vault — they no longer sit in plain text in the settings files.');
        // The in-memory cloud config may still hold a legacy password
        // field that migration just deleted from disk: drop it so the
        // record reads from the vault from now on.
        try { const cfg = getCloudConfig(); for (const c of (cfg.clients || [])) { if (c.passwordInVault) delete c.password; } } catch (e) {}
      }
    }
  } catch (e) { console.log('[Vault] Migration failed: ' + (e && e.message ? e.message : e)); }
}

// Saved password for a Cloud server record: the vault secret when the
// record was migrated (passwordInVault), else the legacy plaintext
// field until migration runs. Never throws.
function getClientPassword(rec) {
  if (!rec) return null;
  try {
    if (rec.passwordInVault && vaultKey) {
      const pw = vault.getSecret(app.getPath('userData'), vaultKey, 'cloud-client:' + rec.id);
      if (pw) return pw;
    }
  } catch (e) {}
  return rec.password || null;
}

function readSettingsFile() {
  try {
    const p = path.join(app.getPath('userData'), '.techvision', 'settings.json');
    if (fs.existsSync(p)) { const s = JSON.parse(fs.readFileSync(p, 'utf-8')); return (s && typeof s === 'object') ? s : {}; }
  } catch (e) {}
  return {};
}

// Tailscale credentials for the vpn.* API calls: the renderer only
// ever sends the non-secret client id (secrets no longer reach it).
// Fill the secrets in here, from the vault when unlocked, else from
// the legacy plaintext fields until migration runs. The renderer
// value wins when it actually carries a secret (it never should).
function resolveVpnAuth(auth) {
  const a = (auth && typeof auth === 'object') ? Object.assign({}, auth) : {};
  const settings = readSettingsFile();
  const legacy = (settings.vpn && typeof settings.vpn === 'object') ? settings.vpn : {};
  try {
    if (vaultKey) {
      if (!a.apiToken) a.apiToken = vault.getSecret(app.getPath('userData'), vaultKey, 'tailscale-api-token') || a.apiToken;
      if (!a.clientSecret) a.clientSecret = vault.getSecret(app.getPath('userData'), vaultKey, 'tailscale-oauth-secret') || a.clientSecret;
    }
  } catch (e) {}
  if (!a.apiToken && legacy.apiToken) a.apiToken = legacy.apiToken;
  if (!a.clientSecret && legacy.oauthClientSecret) a.clientSecret = legacy.oauthClientSecret;
  if (!a.clientId && legacy.oauthClientId) a.clientId = legacy.oauthClientId;
  return a;
}

// Email settings with the SMTP password resolved: vault secret when
// unlocked, else the legacy plaintext field until migration runs.
// mailer.js itself only ever reads the file — it never touches the
// vault — so callers that send mail go through here.
function resolveEmailSettings() {
  const settings = readSettingsFile();
  const email = (settings.email && typeof settings.email === 'object') ? Object.assign({}, settings.email) : {};
  try {
    if (vaultKey) {
      const pw = vault.getSecret(app.getPath('userData'), vaultKey, 'smtp');
      if (pw) email.smtpPass = pw;
    }
  } catch (e) {}
  return email;
}

// Strip plaintext secrets out of a settings object before it leaves
// main (settings-get): the renderer never receives a password or
// token. Instead it gets *InVault flags so the fields can show
// "saved — leave blank to keep it". A legacy plaintext field still
// on disk also counts as saved until migration moves it.
function stripSecretsFromSettings(settings) {
  const s = (settings && typeof settings === 'object') ? JSON.parse(JSON.stringify(settings)) : {};
  if (!s.email || typeof s.email !== 'object') s.email = {};
  if (!s.vpn || typeof s.vpn !== 'object') s.vpn = {};
  let smtpSaved = false, tokenSaved = false, oauthSaved = false;
  try {
    if (vaultKey) {
      smtpSaved = vault.hasSecret(app.getPath('userData'), vaultKey, 'smtp');
      tokenSaved = vault.hasSecret(app.getPath('userData'), vaultKey, 'tailscale-api-token');
      oauthSaved = vault.hasSecret(app.getPath('userData'), vaultKey, 'tailscale-oauth-secret');
    }
  } catch (e) {}
  if (s.email.smtpPass) smtpSaved = true;
  if (s.vpn.apiToken) tokenSaved = true;
  if (s.vpn.oauthClientSecret) oauthSaved = true;
  // A flag already on disk stays true even while the vault is locked
  // (the secret is in the vault, just unreadable right now).
  if (s.email.smtpPassInVault) smtpSaved = true;
  if (s.vpn.apiTokenInVault) tokenSaved = true;
  if (s.vpn.oauthClientSecretInVault) oauthSaved = true;
  delete s.email.smtpPass;
  delete s.vpn.apiToken;
  delete s.vpn.oauthClientSecret;
  s.email.smtpPassInVault = smtpSaved;
  s.vpn.apiTokenInVault = tokenSaved;
  s.vpn.oauthClientSecretInVault = oauthSaved;
  return s;
}

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
  // Open mode: how a double-click opens a file — 'direct' (mapped
  // drive, then Office direct, then temp + save-back) or 'temp'
  // (always temp + save-back). The user picks it in the browser
  // toolbar; no mode ever creates a drive letter.
  if (cloudConfig.openMode !== 'temp' && cloudConfig.openMode !== 'direct') cloudConfig.openMode = 'direct';
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

// App-owned credential prompt (2026-11-28): serverIds whose direct-open
// credentials were verified this session. A verified server never
// prompts again until the next launch (or a disconnect / forget /
// vault reset, which all clear the entry). The SET holds ids only —
// never a password.
const openCredResolved = new Set();

// ---------- TechVision Cloud — Map network drive ----------
// State file: <userData>/.techvision/mapdrive.json —
// { mappings: [{ serverId, letter, host, port, user, reconnect }] }.
let mapdriveState = null;
function mapdriveConfigPath() {
  return path.join(app.getPath('userData'), '.techvision', 'mapdrive.json');
}
function getMapdriveState() {
  if (mapdriveState) return mapdriveState;
  mapdriveState = cloudMapDrive.loadState(mapdriveConfigPath());
  return mapdriveState;
}
function saveMapdriveState(state) {
  if (state) mapdriveState = state;
  cloudMapDrive.saveState(mapdriveConfigPath(), mapdriveState);
}

// ---------- TechVision Cloud — temp + save-back ----------
// After a server file is opened from a temp copy, watch the copy
// while the app is open; edits upload back to the same server path.
// Session-only: the watches live in this process, so a restart never
// re-uploads a stale temp file. See src/cloud-saveback.js.
async function cloudSavebackSnapshot(serverId, relPath) {
  const conn = cloudSessions.get(serverId);
  if (!conn) return null;
  try {
    const dir = String(relPath).split('/').slice(0, -1).join('/');
    const base = path.basename(relPath);
    const r = await cloudClient.list(conn, dir);
    const e = (r.entries || []).find((x) => x.name === base);
    return e ? { size: e.size, mtime: e.mtime } : null;
  } catch (e) { return null; }
}
const cloudSaveback = cloudSavebackMod.createSaveback({
  listEntry: (serverId, relPath) => cloudSavebackSnapshot(serverId, relPath),
  uploadFile: async (serverId, relPath, localPath) => {
    const conn = cloudSessions.get(serverId);
    if (!conn) throw new Error('Not connected to this server.');
    const dir = String(relPath).split('/').slice(0, -1).join('/');
    await cloudClient.upload(conn, localPath, dir, undefined, path.basename(relPath));
  },
  notify: (ev) => {
    const name = ev.name || path.basename(ev.relPath || '');
    if (ev.kind === 'saved-back') appendAppLog('info', '[Cloud] Saved back to the server: ' + name);
    else if (ev.kind === 'conflict') appendAppLog('warn', '[Cloud] Not overwritten — the server copy of ' + name + ' changed since the download. Your edits are still in the temp copy.');
    else appendAppLog('error', '[Cloud] Save-back failed for ' + name + ': ' + (ev.error || ''));
    try { if (typeof mainWindow !== 'undefined' && mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('cloud-saveback', ev); } catch (e) {}
  },
});

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
      // The live endpoint is where the peer was last seen from — it
      // is reported separately so it never overwrites the endpoint
      // the operator typed (the address the server dials).
      liveEndpoint: l.endpoint,
      latestHandshake: l.latestHandshake ? l.latestHandshake.getTime() : null,
      transferRx: l.transferRx, transferTx: l.transferTx,
      online: !!l.latestHandshake,
    } : { online: false, latestHandshake: null, transferRx: 0, transferTx: 0 });
  });
}
// The config as the renderer may see it: private keys stripped.
function wgPublicConfig() {
  const c = getWgConfig();
  const server = Object.assign({}, c.server);
  delete server.privateKey;
  const client = c.client ? Object.assign({}, c.client) : null;
  if (client) { delete client.privateKey; delete client.obfuscation; }
  return { server, client };
}
/* The obfuscation set every server/client config carries, as the
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
   the client connected — the server's own set for our own clients, the
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
// (techvision-backup or TechVision Backup) into the pinned folder.
// MOVE, don't copy: the old code copied only files missing in the
// pinned folder and left the source behind forever — so a job the
// user deleted from the pinned folder was copied BACK on the next
// startup (it was "missing" there again), loaded as a template, and
// its missed schedule fired it the moment the app started. A deleted
// job came back RUNNING after a full Exit and reopen. Moving closes
// that hole: once adopted, nothing is left behind to resurrect
// anything. A file whose destination already exists is a stale
// duplicate of the live copy — it is removed too (the pinned folder
// is authoritative; nothing writes to the legacy folders anymore, so
// nothing live can be lost). A file that cannot be removed is logged
// loudly and left for the next startup to retry.
function migrateLegacyUserData() {
  try {
    const newBase = path.join(USER_DATA_DIR, '.techvision');
    for (const name of ['techvision-backup', 'TechVision Backup']) {
      const oldBase = path.join(app.getPath('appData'), name, '.techvision');
      if (oldBase === newBase || !fs.existsSync(oldBase)) continue;
      const moveMissing = (srcDir, destDir) => {
        if (!fs.existsSync(srcDir)) return;
        if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
        for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
          const src = path.join(srcDir, entry.name);
          const dest = path.join(destDir, entry.name);
          if (entry.isDirectory()) {
            moveMissing(src, dest);
            try { fs.rmdirSync(src); } catch (e) {} // best effort: drop emptied legacy dirs
          } else {
            if (!fs.existsSync(dest)) {
              fs.copyFileSync(src, dest);
              console.log(`[Main] Migrated user data file: ${dest}`);
            }
            try { fs.unlinkSync(src); }
            catch (e) { console.error(`[Main] Could not remove migrated legacy file ${src} — it may resurrect deleted jobs on the next start: ${e.message}`); }
          }
        }
      };
      moveMissing(oldBase, newBase);
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

// Main window — the only window. The job wizard, restore wizard, log
// viewer and settings used to be separate BrowserWindows; they are
// in-place views in index.html now, so no other window exists.
let mainWindow;
let pendingWizardJob = null;
let pendingRestoreJob = null;

// Single instance: a second launch must NOT open a second copy of
// the app — two processes would write the same jobs/history/vault
// files, both schedulers could fire the same backup at once, and the
// Cloud server port would clash. The lock is keyed by the userData
// folder, which was pinned to %APPDATA%\TechVision Backup above, so
// it covers both source and packaged runs. Requested here — early,
// before app.whenReady() creates any state — so a second process
// quits before it can touch anything. A second launch just brings
// the running window forward.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    // The window may be minimized, hidden to the tray (X hides it),
    // or gone — bring it back in front in every case. Never open a
    // second window.
    console.log('[Main] Second instance launch — bringing the running window forward');
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
    } else {
      createMainWindow();
    }
  });
}

// Active jobs tracking (Map for tracking in-progress operations)
const activeJobs = new Map();
// Live engine per active run, keyed the same way as activeJobs, so
// job-stop-backup can cancel the exact run that is going. Entries
// are removed together with the activeJobs entry (finally in the
// scheduled path, after the record in the manual paths) so a
// finished run never stays registered.
const activeEngines = new Map();
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
    loaded: job.loaded || false,
    // Name of the template file this job was loaded from, when it
    // was loaded from one (set by loadStoredJobs / job-save-config).
    // Delete uses it to remove the job's own file BY NAME instead of
    // relying only on the content scan — a file the scan skips
    // (unreadable under an odd filename, content that matches
    // nothing) used to survive while delete still reported success.
    templateFile: job.templateFile || null
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
      if (entry.templateFile) job.templateFile = entry.templateFile;
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
    // Pass the vault-resolved SMTP settings so notifications keep
    // working after the password moved out of settings.json.
    mailer.notify(app.getPath('userData'), kind, job, extra, resolveEmailSettings()).then(function (r) {
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

// Resolve the ZIP password for a job, in the same order as the
// backup password above. The ZIP password lives in the vault's
// generic secrets namespace under 'job-zip-password:<jobId>' — a
// separate secret from the backup password, never the same value
// unless the user typed the same string twice.
function resolveZipPassword(jobConfig) {
  if (jobConfig && typeof jobConfig.zipPassword === 'string' && jobConfig.zipPassword) {
    return jobConfig.zipPassword;
  }
  if (jobConfig && jobConfig.zipPasswordEnabled && vaultKey && jobConfig.id) {
    try { return vault.getSecret(app.getPath('userData'), vaultKey, 'job-zip-password:' + jobConfig.id); } catch (e) { return null; }
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

// One-line failure reason for a run record. The Logs view only
// shows run.error under a failed run, and the failure email only
// prints job.error — but the engine's detailed reasons live in
// result.error_messages, which neither surface read. The LAST
// message is the summary line ("N file(s) failed to back up..." /
// "N file(s) skipped because they were locked..."), which reads
// best as a single line; the full per-file list stays in the log
// file. Returns null for a successful run.
function runErrorLine(result) {
  if (!result || result.success) return null;
  const msgs = result.error_messages;
  if (Array.isArray(msgs) && msgs.length) return String(msgs[msgs.length - 1]);
  return 'Backup failed — see the log for details.';
}

// A stopped run is recorded as 'cancelled' — not 'failed' (it is not
// an error) and not 'completed'. The Logs failed tab and the failure
// email both key off this status, so a stop stays out of both.
function runStatusOf(result) {
  if (result && result.cancelled) return 'cancelled';
  return result && result.success ? 'completed' : 'failed';
}

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
    const jsonFiles = files.filter(f => f.endsWith('.json') && f !== 'history.json' && f !== 'waiting.json');
    for (const file of jsonFiles) {
      try {
        const content = fs.readFileSync(path.join(jobsDir, file), 'utf-8');
        const rawJob = JSON.parse(content);
        const normalized = normalizeJobObject(rawJob, 'template');
        if (normalized) {
          normalized.loaded = true;
          // Remember which file this template came from, so delete
          // can remove it by name (see deleteTemplateFiles).
          normalized.templateFile = file;
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
    return true;
  } catch (e) {
    console.error('[Main] Failed to save job history:', e.message);
    return false;
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

/* The job wizard, restore wizard and log viewer used to be separate
   BrowserWindows (createJobWizardWindow / createRestoreWindow /
   createLogViewerWindow). They are in-place views in the main window
   now, so those functions are gone — the main window is the only one. */



// App lifecycle
app.whenReady().then(() => {
  migrateLegacyUserData(); // Bring old settings/jobs into the pinned folder
  // Master-password model (2026-11-27): NO auto-unlock at startup.
  // The renderer asks for the master password on every launch. Any
  // remember-me blob left over from the old build is deleted here
  // so it can never silently unlock the vault — and is never read.
  try { vault.clearUnlockBlob(app.getPath('userData')); } catch (e) {}
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
    // Map network drives: reconnect the ones the user asked to keep.
    // Best-effort and silent — a missing server never blocks startup.
    reconnectMapDrives().catch(() => {});
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
  if (!jobHistory.includes(job)) return; // deleted/replaced while resolving drives
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
    encryptionEnabled: job.encryptionEnabled === true,
    zipPasswordEnabled: job.zipPasswordEnabled === true, id: job.id
  };
  // Encrypted job, vault locked (or no password saved): the schedule
  // cannot run without the password, so skip this run. The skip used
  // to be a single console.log — invisible in the app: no log entry,
  // no history record, and lastScheduledRun never advanced, so the
  // job was retried silently on every 30-second tick forever.
  if (jobConfig.encryptionEnabled) {
    const pw = resolveBackupPassword(jobConfig);
    if (!pw) {
      const msg = `Skipped encrypted job "${job.name}": the vault is locked or no password is saved. Open the app and unlock the vault with your master password to let scheduled encrypted backups run.`;
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
  // ZIP-password job, vault locked (or no ZIP password saved): the
  // schedule cannot run without it — same skip rule as the
  // encryption password above, naming which password is missing.
  if (jobConfig.zipPasswordEnabled) {
    const zpw = resolveZipPassword(jobConfig);
    if (!zpw) {
      const msg = `Skipped job "${job.name}": the ZIP password is not saved (the vault is locked or no ZIP password is stored). Open the app and unlock the vault with your master password to let scheduled backups of this job run.`;
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
    jobConfig.zipPassword = zpw;
  }
  const useIncremental = job.allowIncremental && (job.runCount || 0) > 0;
  const jobId = `${job.name}-scheduled-${Date.now()}`;
  activeJobs.set(jobId, { name: job.name, jobId: job.id, status: 'running' });
  // The UI shows the job as RUNNING (with its Stop button) while the
  // run goes — it used to learn about the run only when it ended.
  notifyJobsUpdated();
  notifyEmail('started', { name: job.name, type: useIncremental ? 'incremental' : 'full', source: job.source, destination: job.destination });
  try {
    const engine = new BackupEngine(jobConfig);
    activeEngines.set(jobId, engine);
    engine.logger = true;
    const result = useIncremental ? await engine.run_incremental_backup() : await engine.run_full_backup();
    const jobRecord = {
      id: jobId, name: job.name, type: useIncremental ? 'incremental' : 'full',
      success: result.success, status: runStatusOf(result),
      source: jobPathValue(jobConfig.source), destination: jobPathValue(jobConfig.destination),
      timestamp: new Date().toISOString(), files: result.files_backed_up,
      size: result.total_bytes, duration: result.duration_seconds, result,
      error: runErrorLine(result)
    };
    recordRun(job.name, jobRecord);
    job.lastScheduledRun = new Date().toISOString();
    saveJobHistory();
    // A stopped run sends no finished/failed email — the user asked
    // for the stop, it is not a failure.
    if (!result.cancelled) notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
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
    activeEngines.delete(jobId);
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
    if (!jobHistory.includes(job)) continue;
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
  // A ZIP-password job with no ZIP password anywhere: refuse up
  // front, like the encryption password above. The renderer asks
  // for it (askJobPassword) and retries.
  if (jobConfig.zipPasswordEnabled) {
    const zpw = resolveZipPassword(jobConfig);
    if (!zpw) return { success: false, error: 'ZIP_PASSWORD_REQUIRED', name: jobName, status: 'failed', type: 'full' };
    jobConfig.zipPassword = zpw;
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
  // reports real bytes; forward them as they arrive. The payload
  // carries the job id/name so the Jobs details progress bar can
  // match the event to the running job (dictation #2).
  engine.onProgress = (p) => {
    try { if (event.sender && !event.sender.isDestroyed()) event.sender.send('backup-progress', Object.assign({}, p, { jobId: jobConfig.id || null, jobName })); } catch (e) {}
  };

  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, jobId: jobConfig.id || null, status: 'running' });
  activeEngines.set(jobId, engine);
  // The UI shows the job as RUNNING (with its Stop button) while the
  // run goes — it used to learn about the run only when it ended.
  notifyJobsUpdated();

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
    status: runStatusOf(result),
    source: jobPathValue(jobConfig.source),
    destination: jobPathValue(jobConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result,
    error: runErrorLine(result)
  };

  recordRun(jobName, jobRecord);
  saveJobHistory();
  notifyJobsUpdated();
  activeJobs.delete(jobId);
  activeEngines.delete(jobId);

  // The run used a password the user typed: if the vault is unlocked,
  // save it there (encrypted) so scheduled runs of this job work too.
  // A failed store used to be swallowed silently — the job looked
  // encrypted while no password was stored, so scheduled runs were
  // then skipped with no explanation.
  if (jobRecord.success && jobConfig.encryptionEnabled && vaultKey && jobConfig.id && jobConfig.encryptionPassword) {
    try { vault.storeJobPassword(app.getPath('userData'), vaultKey, jobConfig.id, jobConfig.encryptionPassword); } catch (e) { appendAppLog('error', `Could not store the password for job "${jobName}" in the vault: ${e.message}. Scheduled encrypted backups of this job will be skipped until the password is stored.`); }
  }
  // After a successful manual run, store a typed ZIP password in
  // the vault (same rule as the backup password above) so scheduled
  // runs of this job work too.
  if (jobRecord.success && jobConfig.zipPasswordEnabled && vaultKey && jobConfig.id && jobConfig.zipPassword) {
    try { vault.storeSecret(app.getPath('userData'), vaultKey, 'job-zip-password:' + jobConfig.id, jobConfig.zipPassword); } catch (e) { appendAppLog('error', `Could not store the ZIP password for job "${jobName}" in the vault: ${e.message}. Scheduled backups of this job will be skipped until the ZIP password is stored.`); }
  }
  // A stopped run sends no finished/failed email — the user asked
  // for the stop, it is not a failure.
  if (!result.cancelled) notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
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
  // A ZIP-password job with no ZIP password anywhere: refuse up
  // front, like the encryption password above.
  if (jobConfig.zipPasswordEnabled) {
    const zpw = resolveZipPassword(jobConfig);
    if (!zpw) return { success: false, error: 'ZIP_PASSWORD_REQUIRED', name: jobName, status: 'failed', type: 'incremental' };
    jobConfig.zipPassword = zpw;
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
    try { if (event.sender && !event.sender.isDestroyed()) event.sender.send('backup-progress', Object.assign({}, p, { jobId: jobConfig.id || null, jobName })); } catch (e) {}
  };

  const jobId = `${jobName}-${Date.now()}`;
  activeJobs.set(jobId, { name: jobName, jobId: jobConfig.id || null, status: 'running' });
  activeEngines.set(jobId, engine);
  // The UI shows the job as RUNNING (with its Stop button) while the
  // run goes — it used to learn about the run only when it ended.
  notifyJobsUpdated();
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
    status: runStatusOf(result),
    source: jobPathValue(jobConfig.source),
    destination: jobPathValue(jobConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result,
    error: runErrorLine(result)
  };
  
  recordRun(jobName, jobRecord);
  saveJobHistory();
  notifyJobsUpdated();
  activeJobs.delete(jobId);
  activeEngines.delete(jobId);

  if (jobRecord.success && jobConfig.encryptionEnabled && vaultKey && jobConfig.id && jobConfig.encryptionPassword) {
    try { vault.storeJobPassword(app.getPath('userData'), vaultKey, jobConfig.id, jobConfig.encryptionPassword); } catch (e) { appendAppLog('error', `Could not store the password for job "${jobName}" in the vault: ${e.message}. Scheduled encrypted backups of this job will be skipped until the password is stored.`); }
  }
  // After a successful manual run, store a typed ZIP password in
  // the vault (same rule as the backup password above) so scheduled
  // runs of this job work too.
  if (jobRecord.success && jobConfig.zipPasswordEnabled && vaultKey && jobConfig.id && jobConfig.zipPassword) {
    try { vault.storeSecret(app.getPath('userData'), vaultKey, 'job-zip-password:' + jobConfig.id, jobConfig.zipPassword); } catch (e) { appendAppLog('error', `Could not store the ZIP password for job "${jobName}" in the vault: ${e.message}. Scheduled backups of this job will be skipped until the ZIP password is stored.`); }
  }
  // A stopped run sends no finished/failed email — the user asked
  // for the stop, it is not a failure.
  if (!result.cancelled) notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
  console.log(`[Main] Incremental backup completed: ${jobName}`);
  return jobRecord;
});

// Restore operations
// options is optional: { overwrite: true } replaces existing files;
// default (no option) leaves them alone and reports files_skipped.
ipcMain.handle('restore-all', async (event, zipPath, restoreDir, password, options) => {
  try {
    const restoreEngine = new RestoreEngine();
    // Live progress: the engine reports every file it settles
    // (restored, skipped or failed) through onProgress, forwarded
    // to the calling window as 'restore-progress' — the wizard bar
    // shows files done / files total, never a timer.
    const sender = event.sender;
    const result = await restoreEngine.restore_all(zipPath, restoreDir, password || null, Object.assign({}, options || {}, {
      onProgress: (p) => { try { if (sender && !sender.isDestroyed()) sender.send('restore-progress', p); } catch (e) {} },
    }));
    // restore_all reports failures in its result object instead of
    // throwing (wrong password, hash mismatch) — honour it, or a
    // failed restore would be reported as success. Its counters are
    // files_restored/total_bytes, not files/size.
    if (result && result.success === false) {
      return { success: false, error: (result.errors && result.errors[0]) || 'Restore failed.', files_skipped: (result && result.files_skipped) || 0 };
    }
    return { success: true, files: (result && result.files_restored) || 0, size: (result && result.total_bytes) || 0, files_skipped: (result && result.files_skipped) || 0 };
  } catch (err) {
    return { success: false, error: err && err.message ? err.message : String(err) };
  }
});

ipcMain.handle('restore-single', async (event, zipPath, entryName, destPath, password, options) => {
  try {
    const restoreEngine = new RestoreEngine();
    const result = await restoreEngine.restoreFile(zipPath, entryName, destPath, password || null, options || {});
    return { success: true, files: result && result.files ? result.files : 0, skipped: result && result.skipped ? result.skipped : 0 };
  } catch (err) {
    return { success: false, error: err && err.message ? err.message : String(err) };
  }
});

// File operations
// Use the window that actually called the dialog as its parent.
// (The wizard windows used to be callers too; they are in-place views
// in the main window now, so the caller is always the main window.)
function dialogParentWindow(event) {
  try {
    const callerWindow = event && event.sender && BrowserWindow.fromWebContents(event.sender);
    return callerWindow || mainWindow;
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

// Drive usage + open a path in Explorer (Dashboard storage card)
ipcMain.handle('fs-drive-usage', async (event, targetPath) => {
  try {
    if (typeof targetPath !== 'string' || !targetPath) return { success: false, error: 'No path' };
    // Async on purpose (round 3): the sync statfs ran on the main
    // process, so a dead network share / removed USB / sleeping drive
    // blocked everything and the window went "Not Responding". The
    // async call still waits for a slow drive, but the UI stays alive
    // — and it gives up after 8s instead of hanging the hover forever.
    var st = await Promise.race([
      fs.promises.statfs(targetPath),
      new Promise(function (_, reject) { setTimeout(function () { reject(new Error('Drive read timed out')); }, 8000); })
    ]);
    var total = st.blocks * st.bsize;
    var free = st.bfree * st.bsize;
    if (!Number.isFinite(total) || total <= 0) return { success: false, error: 'Unknown drive' };
    return { success: true, total: total, free: free };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read drive' }; }
});

ipcMain.handle('fs-open-path', async (event, targetPath) => {
  try {
    if (typeof targetPath !== 'string' || !targetPath) return { success: false, error: 'No path' };
    var err = await require('electron').shell.openPath(targetPath);
    if (err) return { success: false, error: err };
    return { success: true };
  } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open path' }; }
});

// ZIP operations
ipcMain.handle('zip-get-info', async (event, zipPath) => {
  // This is handled by the restore engine's getZipInfo method
  const { RestoreEngine } = require('./restore.js');
  const engine = new RestoreEngine();
  try {
    const entries = await engine.getZipInfo(zipPath);
    return { success: true, entries, layered: !!(entries && entries.layered) };
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
  // Delete means delete: clearing history used to empty the run
  // records while leaving every job template (and its schedule) on
  // disk, so the jobs came back on the next start and their missed
  // schedules fired them. A clear now removes EVERYTHING: template
  // files, run history and drive-wait state. A running backup blocks
  // the clear — its completion would re-create history for a job the
  // user just deleted. A template file that cannot be removed fails
  // the clear loudly instead of claiming success.
  if ([...activeJobs.values()].some(a => a.status === 'running')) {
    return { success: false, error: 'A backup is running. Wait for it to finish before clearing history.' };
  }
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  try {
    if (fs.existsSync(jobsDir)) {
      for (const file of fs.readdirSync(jobsDir)) {
        if (!file.endsWith('.json') || file === 'history.json' || file === 'waiting.json') continue;
        const p = path.join(jobsDir, file);
        try { fs.unlinkSync(p); console.log(`[Main] Deleted job template file: ${p}`); }
        catch (e) { return { success: false, error: `Cannot delete job template ${file}: ${e.message}` }; }
      }
    }
  } catch (e) { return { success: false, error: e.message }; }
  const previous = jobHistory;
  jobHistory = [];
  // saveWaitingState() derives waiting.json from jobHistory, so an
  // empty jobHistory writes an empty waiting file — the drive-wait
  // state for every job is gone too.
  saveWaitingState();
  if (!saveJobHistory()) {
    jobHistory = previous;
    saveWaitingState();
    return { success: false, error: 'Could not save cleared history. Deletion is incomplete; please retry.' };
  }
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
    delete jobConfig.zipPassword;
    delete jobConfig.password;
    // templateFile is derived state (which file the job was loaded
    // from), not config — it is re-set from the written filename
    // below and must not be persisted into the file itself.
    delete jobConfig.templateFile;
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
    // Same-name guard: <name>.json may be ANOTHER live job's legacy
    // template (same name, different id) — only remove it when its
    // stored id is this job's, or it carries no id and no other live
    // job shares the name. An unreadable file is left alone.
    const oldNamePath = path.join(jobsDir, `${jobConfig.name}.json`);
    if (oldNamePath !== jobPath && fs.existsSync(oldNamePath)) {
      let ownLegacy = true;
      try {
        const old = JSON.parse(fs.readFileSync(oldNamePath, 'utf-8'));
        const oldId = old && old.id;
        if (oldId && oldId !== fileId) ownLegacy = false;
        else if (!oldId && jobHistory.some(j => j.loaded && j.name === jobConfig.name && j.id !== fileId)) ownLegacy = false;
      } catch (e) { ownLegacy = false; console.error(`[Main] Skipping unreadable legacy job file during save: ${oldNamePath} (${e.message})`); }
      if (ownLegacy) { try { fs.unlinkSync(oldNamePath); } catch (e) {} }
    }
    console.log(`[Main] Job saved to: ${jobPath}`);
    // The template only entered the list on the next startup before:
    // add it to the in-memory history now so Create Job shows it at once.
    const tpl = normalizeJobObject(Object.assign({}, jobConfig, {
      id: jobConfig.id || ('job-' + jobConfig.name),
      type: 'TEMPLATE', status: 'PENDING', loaded: true,
      templateFile: `${fileId}.json`
    }));
    if (tpl) {
      let existing = jobHistory.findIndex(j => j.id === tpl.id);
      // Same-name jobs are separate tasks: a save carrying a real id
      // must never fall through to the name match, or saving job B
      // (name X, id B) would replace job A (name X, id A) in the
      // list. The name fallback is only for a legacy template that
      // genuinely has no id: its id IS the fallback form 'job-<name>'
      // (fileId above), so a save carrying that id may still adopt
      // the loaded template — e.g. one whose in-memory id came from
      // a run record instead — and keep its run history.
      if (existing < 0 && tpl.id === ('job-' + tpl.name)) existing = jobHistory.findIndex(j => j.loaded && j.name === tpl.name);
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
    return files.filter(f => f.endsWith('.json') && f !== 'history.json' && f !== 'waiting.json').map(f => {
      const content = fs.readFileSync(path.join(jobsDir, f), 'utf-8');
      return JSON.parse(content);
    });
  } catch (e) {
    return [];
  }
});

// Pending job for the in-place wizard / restore views. The renderer
// hands the job here before opening the view; the wizard scripts read
// it back with job-get-config (no id) when the view resets. No window
// is created — the wizard and restore live in the main window now.
ipcMain.handle('wizard-set-pending', async (event, job) => {
  if (job && typeof job === 'object') pendingWizardJob = job;
  return { success: true };
});

ipcMain.handle('restore-set-pending', async (event, job) => {
  if (job && typeof job === 'object') pendingRestoreJob = job;
  return { success: true };
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
      // Secrets never leave main: the renderer gets *InVault flags
      // instead of the passwords/tokens themselves.
      return stripSecretsFromSettings(JSON.parse(fs.readFileSync(settingsPath, 'utf-8')));
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
  // Round 3: a typed password/token must never land in settings.json
  // in plain text. When the vault is unlocked it goes straight into
  // the vault; when there is NO master password yet the rest of the
  // settings still save, the secret is dropped, and the renderer is
  // told (needsMasterKey) so it can offer "Create a master key" and
  // retry. A blank field means "keep whatever is already saved" —
  // the renderer never sends a stored secret back, so blank cannot
  // mean "delete" here.
  const notSaved = [];
  let needsMasterKey = false;
  let needsUnlock = false;
  const next = (settings && typeof settings === 'object') ? JSON.parse(JSON.stringify(settings)) : {};
  if (!next.email || typeof next.email !== 'object') next.email = {};
  if (!next.vpn || typeof next.vpn !== 'object') next.vpn = {};
  // Carry the saved-secret flags from disk: a save while the vault
  // is locked sends blank password fields ("keep what is saved"),
  // and the flags must not be lost just because nothing was typed.
  const prevSettings = readSettingsFile();
  if (prevSettings.email && prevSettings.email.smtpPassInVault) next.email.smtpPassInVault = true;
  if (prevSettings.vpn) {
    if (prevSettings.vpn.apiTokenInVault) next.vpn.apiTokenInVault = true;
    if (prevSettings.vpn.oauthClientSecretInVault) next.vpn.oauthClientSecretInVault = true;
  }
  const vaultExists = vault.vaultExists(app.getPath('userData'));
  function takeSecret(obj, field, secretName, label) {
    const value = obj[field];
    delete obj[field];
    if (typeof value === 'string' && value) {
      if (vaultKey) {
        try {
          vault.storeSecret(app.getPath('userData'), vaultKey, secretName, value);
          obj[field + 'InVault'] = true;
        } catch (e) { notSaved.push(label); needsUnlock = true; }
      } else {
        notSaved.push(label);
        if (!vaultExists) needsMasterKey = true; else needsUnlock = true;
      }
    } else if (vaultKey) {
      // Blank field, secret already in the vault: keep the flag so
      // the renderer still shows it as saved.
      try { if (vault.hasSecret(app.getPath('userData'), vaultKey, secretName)) obj[field + 'InVault'] = true; } catch (e) {}
    }
  }
  takeSecret(next.email, 'smtpPass', 'smtp', 'smtp');
  takeSecret(next.vpn, 'apiToken', 'tailscale-api-token', 'apiToken');
  takeSecret(next.vpn, 'oauthClientSecret', 'tailscale-oauth-secret', 'oauthSecret');
  fs.writeFileSync(settingsPath, JSON.stringify(next, null, 2));
  // Apply Start-with-Windows right away: saving the setting must
  // register/unregister the app at login without needing a restart.
  applyAutoStart();
  return { success: true, secretsNotSaved: notSaved, needsMasterKey, needsUnlock };
});

// Send a test notification with the saved email settings — the SMTP
// password is resolved from the vault (or the legacy field) here, so
// mailer never sees a settings object without it.
ipcMain.handle('email-test', async () => {
  const r = await mailer.sendMail(app.getPath('userData'),
    'Test email from TechVision Backup',
    'This is a test notification from TechVision Backup.\n\nIf you got this, email notifications are set up correctly.\nTime: ' + new Date().toLocaleString(), resolveEmailSettings());
  return { success: r.sent, error: r.sent ? undefined : r.reason };
});

// Master-password vault: the key lives in memory only while unlocked.
ipcMain.handle('vault-status', async () => {
  return { exists: vault.vaultExists(app.getPath('userData')), locked: vaultKey === null };
});
ipcMain.handle('vault-setup', async (event, masterPassword) => {
  try {
    vaultKey = vault.setupVault(app.getPath('userData'), masterPassword);
    afterVaultUnlocked();
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

/* Replace the vault with a fresh one (the startup "I forgot my
   master password" path). Everything the old vault encrypted is
   LOST — the renderer warns and confirms before calling this. The
   "saved in the vault" flags in settings.json / cloud.json are
   cleared with it, so the app stops claiming passwords are saved
   when they no longer are. Legacy PLAINTEXT passwords are NOT
   touched: they are not in the vault, and migration moves them into
   the new vault on unlock. */
ipcMain.handle('vault-reset', async (event, masterPassword) => {
  try {
    const hadVault = vault.vaultExists(app.getPath('userData'));
    vaultKey = vault.resetVault(app.getPath('userData'), masterPassword);
    if (hadVault) clearVaultSecretFlags();
    // The old vault is gone, so every saved password with it: direct
    // opens must prompt again (see the app-owned credential prompt).
    openCredResolved.clear();
    afterVaultUnlocked();
    return { success: true, replaced: hadVault };
  } catch (e) { return { success: false, error: e.message }; }
});

/* Drop every "password is saved in the vault" flag after a vault
   reset — the passwords they point at no longer exist. On disk AND
   in main's in-memory cloud config (getCloudConfig caches it). Never
   throws. */
function clearVaultSecretFlags() {
  try {
    const sp = path.join(app.getPath('userData'), '.techvision', 'settings.json');
    if (fs.existsSync(sp)) {
      const s = JSON.parse(fs.readFileSync(sp, 'utf-8'));
      if (s.email) delete s.email.smtpPassInVault;
      if (s.vpn) { delete s.vpn.apiTokenInVault; delete s.vpn.oauthClientSecretInVault; }
      fs.writeFileSync(sp, JSON.stringify(s, null, 2));
    }
  } catch (e) { console.log('[Vault] Could not clear settings vault flags: ' + (e && e.message ? e.message : e)); }
  try {
    const cfg = getCloudConfig();
    for (const c of (cfg.clients || [])) delete c.passwordInVault;
    saveCloudConfig();
  } catch (e) { console.log('[Vault] Could not clear cloud vault flags: ' + (e && e.message ? e.message : e)); }
}
ipcMain.handle('vault-unlock', async (event, masterPassword) => {
  try {
    vaultKey = vault.unlockVault(app.getPath('userData'), masterPassword);
    afterVaultUnlocked();
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});
ipcMain.handle('vault-lock', async () => {
  if (vaultKey) vault.lockVault(vaultKey);
  vaultKey = null;
  // A locked vault cannot read saved passwords: direct opens must
  // prompt again until the vault is unlocked (see the app-owned
  // credential prompt).
  openCredResolved.clear();
  // Also drop any leftover remember-me blob from the old build, so
  // the next launch asks for the master password again.
  try { vault.clearUnlockBlob(app.getPath('userData')); } catch (e) {}
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
    openMode: cfg.openMode || 'direct',
    server: {
      enabled: !!cfg.server.enabled,
      port: cfg.server.port || 8443,
      running: srv.isRunning(),
      users: srv.listUsers(),
      fingerprint: cfg.server.cert ? cfg.server.cert.fingerprint : null,
      accessMode: cloudAccessMode(cfg.server.accessMode),
      ddnsHostname: cfg.server.ddnsHostname || '',
    },
    clients: (cfg.clients || []).map((c) => ({ id: c.id, name: c.name, host: c.host, port: c.port, user: c.user, fingerprint: c.fingerprint || null, hasPassword: !!c.password || !!c.passwordInVault, accessMode: cloudAccessMode(c.accessMode) })),
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
  // DDNS hostname (round 2 #9): recorded for clients — the server
  // itself listens on 0.0.0.0 and never consumes it. Also feeds the
  // certificate SANs (round 2 #12).
  const ddnsHostname = String((opts && opts.ddnsHostname) || '').trim().slice(0, 253);
  // A DDNS change feeds the cert SANs, so a running server must
  // restart for the new cert to take effect — same as a port change.
  const ddnsChanged = ddnsHostname.toLowerCase() !== String(cfg.server.ddnsHostname || '').trim().toLowerCase();
  cfg.server.enabled = !!(opts && opts.enabled);
  cfg.server.port = port;
  cfg.server.accessMode = accessMode;
  cfg.server.ddnsHostname = ddnsHostname;
  saveCloudConfig();
  try {
    if (wasRunning && (portChanged || ddnsChanged)) {
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

// Edit a user (rename / new password / roots list / read-write).
// A rename follows saved client records that point at THIS server:
// they log in as the new name, or they would keep logging in as a
// user that no longer exists. This server is local, so a record
// matches when its host is one of this machine's own addresses
// (LAN, Tailscale, DDNS, localhost) on the same port. Records
// pointing at other servers are left alone, and a rename with no
// matching record reports updatedRecords: 0 — the user then has to
// reconnect that record by hand. A changed password is written into
// the vault for the matched records too (same secret key the
// connect flow reads), so saved logins keep working silently.
function localServerHosts(cfg) {
  const hosts = new Set(['localhost', '127.0.0.1']);
  try { for (const a of cloudServerMod.lanIPs()) hosts.add(String(a).toLowerCase()); } catch (e) {}
  try {
    const ddns = String((cfg.server && cfg.server.ddnsHostname) || '').trim().toLowerCase();
    if (ddns) hosts.add(ddns);
  } catch (e) {}
  return hosts;
}

ipcMain.handle('cloud-user-edit', async (event, name, updates) => {
  try {
    const result = getCloudServer().editUser(name, updates);
    let updatedRecords = 0;
    let passwordUpdatedRecords = 0;
    if (result.renamed || result.passwordChanged) {
      const cfg = getCloudConfig();
      const localHosts = localServerHosts(cfg);
      const serverPort = cfg.server.port || 8443;
      for (const rec of (cfg.clients || [])) {
        if (rec.user !== name) continue;
        if (rec.port !== serverPort) continue;
        if (!localHosts.has(String(rec.host || '').toLowerCase())) continue;
        if (result.renamed) rec.user = result.name;
        updatedRecords++;
        if (result.passwordChanged && vaultKey && updates && updates.password) {
          try {
            vault.storeSecret(app.getPath('userData'), vaultKey, 'cloud-client:' + rec.id, String(updates.password));
            rec.passwordInVault = true;
            delete rec.password;
            passwordUpdatedRecords++;
          } catch (e) {}
        }
      }
      if (updatedRecords > 0) saveCloudConfig();
      // A live session keeps the old user name in main's session
      // map — drop it so the next request re-logs in with the new
      // name (the vault password above makes that silent).
      if (result.renamed) {
        for (const [id, s] of cloudSessions) {
          if (s && s.user === name) cloudSessions.delete(id);
        }
      }
    }
    return { success: true, user: result, updatedRecords, passwordUpdatedRecords };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Saved servers (client side). The password for a server is stored
// in the master-password vault (secret 'cloud-client:<id>') when the
// vault is unlocked — never in plain text in cloud.json. The record
// keeps passwordInVault:true so the connect flow reads the vault.
// A legacy plaintext `password` still in the file is honoured until
// migration moves it (first unlock). It never leaves main: the
// renderer only sees hasPassword, and connect uses the stored password
// when none is typed. Remove it any time with "Forget saved password"
// on the server card; changing the password on the server just means
// the next connect asks for the new one. When there is NO master
// password yet, the server still saves — just without the password —
// and the renderer is told (needsMasterKey) so it can offer to
// create one and retry; the app is never blocked on this.
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
    const rec = { id, name: String(s.name || host), host, port, user: String(s.user || ''), fingerprint: s.fingerprint || null, certPem: s.certPem || null, accessMode };
    // Update-in-place keeps the pre-existing id — resolve it BEFORE
    // storing any secret, or the vault key would name a fresh id the
    // record is never stored under.
    if (i >= 0) rec.id = cfg.clients[i].id;
    // Keep a previously migrated/vault password marker, and a legacy
    // plaintext password, when no new password was sent.
    if (existing && existing.passwordInVault) rec.passwordInVault = true;
    if (existing && existing.password) rec.password = existing.password;
    let passwordNotSaved = false;
    let needsMasterKey = false;
    let needsUnlock = false;
    const newPassword = (s.password && String(s.password)) || '';
    if (newPassword) {
      if (vaultKey) {
        try {
          vault.storeSecret(app.getPath('userData'), vaultKey, 'cloud-client:' + rec.id, newPassword);
          rec.passwordInVault = true;
          delete rec.password;
        } catch (e) { passwordNotSaved = true; needsUnlock = true; }
      } else {
        // No vault to store it in: save the server without the
        // password and let the renderer offer to create a master key.
        passwordNotSaved = true;
        if (!vault.vaultExists(app.getPath('userData'))) needsMasterKey = true; else needsUnlock = true;
      }
    }
    if (i >= 0) { if (!rec.fingerprint) rec.fingerprint = cfg.clients[i].fingerprint; if (!rec.certPem) rec.certPem = cfg.clients[i].certPem; cfg.clients[i] = rec; }
    else cfg.clients.push(rec);
    saveCloudConfig();
    // Return the id the record is actually stored under: on an
    // update-in-place that is the pre-existing id, NOT the fresh
    // 'srv-…' id generated above — callers (connect, join) look the
    // record up by the returned id, and a wrong one made reconnects
    // fail with "Password needed" on every re-save.
    return { success: true, id: rec.id, passwordNotSaved, needsMasterKey, needsUnlock };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-client-forget-password', async (event, id) => {
  const cfg = getCloudConfig();
  const rec = (cfg.clients || []).find((c) => c.id === id);
  if (!rec) return { success: false, error: 'Server not found.' };
  rec.password = null;
  rec.passwordInVault = false;
  openCredResolved.delete(id);
  try { if (vaultKey) vault.removeSecret(app.getPath('userData'), vaultKey, 'cloud-client:' + id); } catch (e) {}
  saveCloudConfig();
  return { success: true };
});

ipcMain.handle('cloud-client-remove', async (event, id) => {
  const cfg = getCloudConfig();
  cfg.clients = cfg.clients.filter((c) => c.id !== id);
  cloudSessions.delete(id);
  openCredResolved.delete(id);
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
    const password = (opts.password && String(opts.password)) || getClientPassword(rec) || '';
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
    // Keep the password that just authenticated in the session
    // (memory only, never written to disk): the record may not have
    // one — e.g. after "Forget password" while still connected — and
    // Office/media opens need a password to seed or they prompt.
    cloudSessions.set(opts.serverId, Object.assign({}, conn, { user: info.user, root: info.root, roots: info.roots || [info.root], canWrite: info.canWrite, password }));
    // Alternate addresses of this server (LAN addresses + DDNS from
    // /api/info): a second user mapping the same host hits Windows
    // error 1219, and the Map tab retries under one of these.
    if (rec && Array.isArray(info.addrs) && info.addrs.length) {
      const host = String(rec.host || '').toLowerCase();
      rec.altHosts = info.addrs.map((a) => String(a || '').trim()).filter((a) => a && a.toLowerCase() !== host);
      saveCloudConfig();
    }
    // Seed the login into Windows Credential Manager NOW, at connect
    // time, automatically and without asking: the first direct open
    // (Office, media player) must not prompt — seeding only at open
    // time used to be too late for a player that had already asked.
    // Best-effort: a failure never blocks the connect.
    if (rec) { try { await seedCloudCredentialsForOpen(opts.serverId, rec); } catch (e) {} }
    // A typed password that just authenticated is remembered for next
    // time — in the vault when it is unlocked. When there is no
    // master password yet it is NOT written to cloud.json in plain
    // text; the renderer is told so it can offer to create one.
    let passwordNotSaved = false;
    let needsMasterKey = false;
    if (rec && opts.password && String(opts.password)) {
      if (vaultKey) {
        try {
          vault.storeSecret(app.getPath('userData'), vaultKey, 'cloud-client:' + rec.id, String(opts.password));
          rec.passwordInVault = true;
          delete rec.password;
          saveCloudConfig();
        } catch (e) { passwordNotSaved = true; }
      } else {
        passwordNotSaved = true;
        if (!vault.vaultExists(app.getPath('userData'))) needsMasterKey = true;
      }
    }
    return { success: true, info, passwordNotSaved, needsMasterKey };
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
  openCredResolved.delete(serverId);
  // No session, no save-back: a disconnected server's temp copies
  // stop being watched (their edits stay in the temp copy).
  try { cloudSaveback.stop(serverId); } catch (e) {}
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
// open). The copy is then WATCHED while the app is open: edits save
// back to the same server path (temp + save-back). Programs (.exe and
// friends) never come through here — the renderer blocks them, and
// this guard stops any other caller too: a game is a whole folder of
// files, and one temp file can never run it.
const CLOUD_PROGRAM_EXTS = new Set(['exe', 'msi', 'bat', 'cmd', 'com', 'scr']);
ipcMain.handle('cloud-client-open', async (event, serverId, relPath) => {
  const conn = cloudSessions.get(serverId);
  if (!conn) return { success: false, error: 'Not connected to this server.' };
  const openExt = String(path.basename(relPath || '')).split('.').pop().toLowerCase();
  if (CLOUD_PROGRAM_EXTS.has(openExt)) return { success: false, error: 'program-needs-drive' };
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
  // Temp + save-back: snapshot the server copy now, then watch the
  // temp copy. A later edit uploads back silently; a server-side
  // change since the download blocks the overwrite instead.
  try {
    const snap = await cloudSavebackSnapshot(serverId, relPath);
    if (snap) cloudSaveback.watch(serverId, relPath, dest, snap);
  } catch (e) {}
  return { success: true, dest, mode: 'temp' };
});

// ---------- TechVision Cloud — Map network drive ----------
ipcMain.handle('cloud-mapdrive-status', async () => {
  try {
    const state = getMapdriveState();
    const cfg = getCloudConfig();
    const free = await cloudMapDrive.listFreeLetters();
    // Whether the app itself runs elevated: the mapping belongs to
    // the session the app runs in, so the panel says which one.
    let elevated = null;
    try { const el = await cloudMapDrive.isElevated(); if (el && el.success) elevated = !!el.elevated; } catch (e) {}
    const out = [];
    for (const m of state.mappings) {
      const rec = cfg.clients.find((c) => c.id === m.serverId);
      let status = 'not-mapped';
      let error = null;
      let remote = null;
      if (!rec) { status = 'error'; error = 'This server was removed from the Client tab.'; }
      else if (!getClientPassword(rec)) { status = 'password-needed'; }
      else {
        const st = await cloudMapDrive.getDriveStatus(m.letter);
        if (st.success && st.mapped) {
          // Windows reports the remote as \\host@SSL@port\dav, never
          // as the https URL — compare with remoteMatchesDav, or the
          // app keeps saying "Not mapped" about its own mapping.
          status = cloudMapDrive.remoteMatchesDav(st.remote, m.host, m.port) ? 'mapped' : 'not-mapped';
          remote = st.remote || null;
        } else if (!st.success) { status = 'error'; error = st.error; }
      }
      out.push({
        serverId: m.serverId, letter: m.letter, host: m.host, port: m.port, user: m.user,
        reconnect: !!m.reconnect, status, error, remote,
        name: rec ? rec.name : m.serverId, hasPassword: !!(rec && getClientPassword(rec)),
      });
    }
    return { success: true, mappings: out, freeLetters: free.success ? free.letters : [], elevated };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-mapdrive-map', async (event, serverId, letter, reconnect) => {
  try {
    const cfg = getCloudConfig();
    const rec = cfg.clients.find((c) => c.id === serverId);
    if (!rec) return { success: false, error: 'Server not found.' };
    // Client-connection guard (the user asked for this, 2026-11-27):
    // never attempt a mapping when the Client is not connected to
    // THIS server. A live session proves the server answers, the
    // password is right and the certificate is the pinned one —
    // without it, `net use` fails with a cryptic error (e.g. 1244)
    // for a problem the Client tab would have shown plainly. The
    // renderer answers 'not-connected' with a message and a jump to
    // the Client tab. (Startup auto-reconnect is separate and keeps
    // working without a session — see reconnectMapDrives.)
    if (!cloudSessions.get(serverId)) return { success: false, error: 'not-connected' };
    if (!getClientPassword(rec)) return { success: false, error: 'password-needed' };
    const l = String(letter || '').toUpperCase();
    if (!/^[A-Z]$/.test(l)) return { success: false, error: 'Pick a drive letter (A–Z).' };
    const state = getMapdriveState();
    // One server per letter, one mapping per server: disconnect the
    // old letter (or the old mapping on this letter) first.
    const sameLetter = state.mappings.find((m) => m.letter === l && m.serverId !== serverId);
    if (sameLetter) {
      await cloudMapDrive.unmapDrive(l);
      state.mappings = state.mappings.filter((m) => m.serverId !== sameLetter.serverId);
    }
    const sameServer = state.mappings.find((m) => m.serverId === serverId);
    if (sameServer && sameServer.letter !== l) await cloudMapDrive.unmapDrive(sameServer.letter);
    // Certificate trust (once per server, admin): the saved record
    // holds certPem from the probe/trust flow. The fingerprint must
    // match the saved record before anything is installed — never
    // install any other certificate.
    if (rec.certPem) {
      const fp = cloudServerMod.fingerprintOfCertPem(rec.certPem);
      if (rec.fingerprint && rec.fingerprint !== fp) {
        return { success: false, error: 'The saved certificate does not match this server. Remove the server in the Client tab and add it again.' };
      }
      const trusted = await cloudMapDrive.isCertTrusted(rec.certPem);
      if (!trusted.success) return { success: false, error: trusted.error };
      if (!trusted.trusted) {
        const inst = await cloudMapDrive.installCert(rec.certPem);
        if (!inst.success) return { success: false, declined: !!inst.declined, error: inst.error };
      }
    } else {
      // No trusted certificate saved for this server at all: the
      // install step used to be skipped silently here and `net use`
      // then failed with System error 1244. Say so plainly instead
      // — connecting once in the Client tab trusts the certificate
      // and saves it. (Unreachable from the Map button itself now
      // that the connection guard above requires a live session,
      // which implies a trusted certificate — kept as a loud guard
      // for direct IPC callers.)
      return { success: false, error: 'This server has no trusted certificate saved yet — connect once in the Client tab first (it trusts the certificate), then map the drive.' };
    }
    // Windows hostname validation: `net use` only sends the login
    // when the certificate covers the mapped host (IP SAN for an IP,
    // DNS SAN for a name). A certificate issued before this address
    // existed on the server (e.g. Tailscale came up after the server
    // first started) never gains the SAN — certNeedsRegen
    // deliberately does not churn on interface changes — so check
    // here and fail with the actual cause instead of letting
    // `net use` answer with System error 1244. (null = host form
    // this check cannot judge, e.g. IPv6: proceed as before.)
    const covers = cloudServerMod.certCoversHost(rec.certPem, rec.host);
    if (covers === false) {
      return { success: false, error: 'The server certificate does not cover this address (' + rec.host + '). It was issued before this address existed on the server — restart the Cloud server on the server machine so it issues a new certificate covering it, then connect again in the Client tab (Trust & connect) and map the drive.' };
    }
    // Alternate addresses for the same server (saved at connect time
    // from /api/info): when a second user maps the same host, Windows
    // refuses with error 1219 — one credential set per server NAME
    // per logon session. mapDrive retries under another address for
    // the same physical server, skipping any the cert does not cover.
    const altHosts = Array.isArray(rec.altHosts) ? rec.altHosts.filter((h) => h && String(h).toLowerCase() !== String(rec.host).toLowerCase()) : [];
    const mapped = await cloudMapDrive.mapDrive({ letter: l, host: rec.host, port: rec.port, user: rec.user, password: getClientPassword(rec), altHosts, coversHost: (h) => cloudServerMod.certCoversHost(rec.certPem, h) });
    if (!mapped.success) return { success: false, error: mapped.error };
    // mapDrive verifies the drive exists in this session before
    // reporting success, so this record means a real, visible drive.
    state.mappings = state.mappings.filter((m) => m.serverId !== serverId && m.letter !== l);
    state.mappings.push({ serverId, letter: l, host: mapped.host || rec.host, port: rec.port, user: rec.user, reconnect: !!reconnect });
    saveMapdriveState(state);
    appendAppLog('info', '[Cloud] Mapped ' + (mapped.host || rec.host) + ':' + rec.port + ' as drive ' + l + ':' + (mapped.viaAltHost ? ' (via alternate address ' + mapped.host + ')' : ''));
    // Seed the credentials now, automatically and without asking:
    // a mapped drive never prompts (the redirector uses the `net
    // use` login), and a direct open of the same server afterwards
    // finds the login already stored. Best-effort — a failure never
    // blocks the mapping.
    try { await seedCloudCredentialsForOpen(serverId, rec); } catch (e) {}
    return { success: true, letter: l, host: mapped.host || rec.host, viaAltHost: !!mapped.viaAltHost };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-mapdrive-disconnect', async (event, serverId) => {
  try {
    const state = getMapdriveState();
    const m = state.mappings.find((x) => x.serverId === serverId);
    if (!m) return { success: true, alreadyGone: true };
    const r = await cloudMapDrive.unmapDrive(m.letter);
    state.mappings = state.mappings.filter((x) => x.serverId !== serverId);
    saveMapdriveState(state);
    if (!r.success) return { success: false, error: r.error };
    return { success: true, letter: m.letter };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-mapdrive-open-explorer', async (event, letter) => {
  try {
    return await cloudMapDrive.openExplorer(letter);
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Open a file straight from the mapped drive: no download, no temp
// copy. The path is joined onto the letter in cloud-mapdrive.js and
// proven to stay under the letter root.
ipcMain.handle('cloud-mapdrive-open-mapped', async (event, serverId, relPath) => {
  try {
    const state = getMapdriveState();
    const m = state.mappings.find((x) => x.serverId === serverId);
    if (!m) return { success: false, error: 'not-mapped' };
    const joined = cloudMapDrive.mappedPathFor(m.letter, relPath);
    if (!joined.success) return { success: false, error: joined.error };
    const st = await cloudMapDrive.getDriveStatus(m.letter);
    if (!st.success || !st.mapped) return { success: false, error: 'not-mapped' };
    if (st.remote && !cloudMapDrive.remoteMatchesDav(st.remote, m.host, m.port)) return { success: false, error: 'not-mapped' };
    let exists = false;
    try { exists = fs.existsSync(joined.path); } catch (e) {}
    if (!exists) return { success: false, error: 'File not found on the mapped drive.' };
    const err = await require('electron').shell.openPath(joined.path);
    if (err) return { success: false, error: 'Windows could not open it: ' + err };
    return { success: true, path: joined.path };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Open mode (browser toolbar): how a double-click opens a file.
// 'direct' = mapped drive, then Office direct, then temp + save-back;
// 'temp' = always temp + save-back. Persisted in cloud.json.
ipcMain.handle('cloud-set-open-mode', async (event, mode) => {
  try {
    const m = mode === 'temp' ? 'temp' : 'direct';
    const cfg = getCloudConfig();
    cfg.openMode = m;
    saveCloudConfig();
    return { success: true, openMode: m };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Open an Office document straight from the server: ms-word:ofe|u|
// (and friends) hand the WebDAV URL to Word/Excel/PowerPoint, which
// opens it read-write with no temp copy; saves go back through
// WebDAV. The server cert must be trusted first — the same one-time
// install as the Map network tab (admin once); a decline falls
// through to the temp open (the renderer tries the next method).
// Returns { success: false } on any failure so the caller can fall
// through silently — only the temp path shows an error to the user.
// Round 2 #14: seed the Cloud credentials for an Office/media open
// so no login prompt appears. The password comes from the live
// session first (it is the one that just authenticated) and the
// saved record second — a connected session may have no stored
// password (e.g. after "Forget password"), and seeding with nothing
// used to fail silently and leave Office prompting. The result is
// LOGGED, never swallowed: a silent seed failure used to look
// exactly like "the prompt is unavoidable". Best-effort: a failure
// never blocks the open — Office then prompts once and Windows can
// remember it. Never throws.
async function seedCloudCredentialsForOpen(serverId, rec) {
  try {
    const conn = cloudSessions.get(serverId);
    const user = (conn && conn.user) || rec.user;
    const password = (conn && conn.password) || getClientPassword(rec);
    if (!user || !password) {
      console.log(`[Cloud] No saved password for ${rec.host} — Office/media will prompt for the Cloud login once.`);
      appendAppLog('warn', `[Cloud] Opening a file on ${rec.host} without a saved password — Windows will ask for the Cloud login.`);
      return { success: false, error: 'No password saved for this server.' };
    }
    const r = await cloudMapDrive.seedCredentials(rec.host, rec.port, user, password);
    if (r.success) console.log(`[Cloud] Credentials seeded for ${rec.host}:${rec.port} (${r.seeded || '?'} targets).`);
    else {
      console.log(`[Cloud] Credential seeding failed for ${rec.host}:${rec.port}: ${r.error}`);
      appendAppLog('warn', `[Cloud] Could not store the login for ${rec.host} in Windows Credential Manager (${r.error || 'unknown error'}) — Office may ask for the Cloud user and password.`);
    }
    return r;
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
}

// App-owned credential prompt (2026-11-28): check a typed user name +
// password against the Cloud server WITHOUT creating a session and
// WITHOUT opening anything. A DAV PROPFIND on /dav/ with HTTP Basic
// auth exercises the exact credential path the players and Office
// use, pinned to the record's certificate. The password travels only
// in the Authorization header over pinned TLS — never in the URL,
// never in a log line. 2xx = the credentials are right; 401 = wrong
// user name or password; 429 = locked out after too many failures.
function davProbeCredentials(host, port, certPem, user, password) {
  return new Promise((resolve) => {
    if (!certPem) return resolve({ error: 'No trusted certificate for this server.' });
    let req;
    try {
      req = https.request({
        host, port, path: '/dav/', method: 'PROPFIND',
        ca: [certPem], checkServerIdentity: () => undefined,
        headers: {
          Authorization: 'Basic ' + Buffer.from(String(user) + ':' + String(password)).toString('base64'),
          Depth: '0',
        },
        timeout: 15000,
      }, (res) => {
        res.resume();
        resolve({ status: res.statusCode });
      });
    } catch (e) { return resolve({ error: e && e.message ? e.message : String(e) }); }
    req.on('timeout', () => { try { req.destroy(); } catch (e) {} resolve({ error: 'The server did not answer in time.' }); });
    req.on('error', (e) => {
      const msg = e && e.message ? e.message : String(e);
      if (e && e.code === 'ECONNREFUSED') return resolve({ error: 'Cannot reach the server at ' + host + ':' + port + '.' });
      if (/certificate/i.test(msg)) return resolve({ error: 'The server certificate could not be verified.' });
      resolve({ error: msg });
    });
    req.end();
  });
}

ipcMain.handle('cloud-open-verify-password', async (event, serverId, user, password) => {
  try {
    const cfg = getCloudConfig();
    const rec = (cfg.clients || []).find((c) => c.id === serverId);
    if (!rec) return { ok: false, code: 'no-server', error: 'Server not found.' };
    const u = String(user || '').trim();
    const pw = String(password || '');
    if (!u || !pw) return { ok: false, code: 'missing', error: 'Enter the user name and password.' };
    const probe = await davProbeCredentials(rec.host, rec.port, rec.certPem, u, pw);
    if (probe.status === 401) return { ok: false, code: 'wrong-password', error: 'Wrong user name or password. Try again.' };
    if (probe.status === 429) return { ok: false, code: 'locked', error: 'Too many failed logins. Try again later.' };
    if (probe.error) return { ok: false, code: 'unreachable', error: probe.error };
    if (probe.status >= 200 && probe.status < 300) {
      // Verified: the live session now uses these credentials, the
      // server stops prompting for this server this session, and
      // players get the login seeded so they open without asking.
      const conn = cloudSessions.get(serverId);
      if (conn) cloudSessions.set(serverId, Object.assign({}, conn, { user: u, password: pw }));
      openCredResolved.add(serverId);
      try { await cloudMapDrive.seedCredentials(rec.host, rec.port, u, pw); } catch (e) {}
      return { ok: true };
    }
    return { ok: false, code: 'unreachable', error: 'Server error ' + probe.status + '.' };
  } catch (e) {
    return { ok: false, code: 'unreachable', error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('cloud-office-open', async (event, serverId, relPath) => {
  try {
    const conn = cloudSessions.get(serverId);
    if (!conn) return { success: false, error: 'Not connected to this server.' };
    const cfg = getCloudConfig();
    const rec = (cfg.clients || []).find((c) => c.id === serverId);
    if (!rec) return { success: false, error: 'Server not found.' };
    // App-owned credential prompt (2026-11-28): a direct open with
    // no SAVED password must not reach the browser/Office prompt.
    // The renderer shows the app's own window instead; this handler
    // reports the need and opens nothing. Mapped-drive opens never
    // call this handler, so they never prompt.
    if (!getClientPassword(rec) && !openCredResolved.has(serverId)) {
      return { success: false, code: 'password-needed', user: rec.user };
    }
    const uri = cloudMapDrive.officeUriFor(rec.host, rec.port, relPath);
    if (!uri) return { success: false, error: 'not-office' };
    if (rec.certPem) {
      const fp = cloudServerMod.fingerprintOfCertPem(rec.certPem);
      if (rec.fingerprint && rec.fingerprint !== fp) {
        return { success: false, error: 'The saved certificate does not match this server. Remove the server in the Client tab and add it again.' };
      }
      const trusted = await cloudMapDrive.isCertTrusted(rec.certPem);
      if (!trusted.success) return { success: false, error: trusted.error };
      if (!trusted.trusted) {
        const inst = await cloudMapDrive.installCert(rec.certPem);
        if (!inst.success) return { success: false, declined: !!inst.declined, error: inst.error };
      }
    }
    // Seed the credentials so Office does not prompt for a login
    // (round 2 #14: generic URL targets + session-password fallback,
    // result logged — see seedCloudCredentialsForOpen).
    await seedCloudCredentialsForOpen(serverId, rec);
    const err = await require('electron').shell.openExternal(uri);
    if (err) return { success: false, error: String(err) };
    return { success: true, mode: 'direct' };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Media in direct mode (round 2 #11): same shape as the Office open
// above — the default player streams the WebDAV URL with Range
// requests, so a video starts playing without downloading first.
// Cert trust + credential seeding are identical to Office: the
// player must trust the server cert, and must not be asked for a
// login it cannot answer. Returns { success: false } on any failure
// so the caller falls through to temp silently — only the temp path
// shows an error. The built URL is returned even on failure (the
// sandbox has no player, so the Windows-only cert step blocks the
// open there — the caller/driver can still assert the exact URL).
ipcMain.handle('cloud-media-open', async (event, serverId, relPath) => {
  try {
    const conn = cloudSessions.get(serverId);
    if (!conn) return { success: false, error: 'Not connected to this server.' };
    const cfg = getCloudConfig();
    const rec = (cfg.clients || []).find((c) => c.id === serverId);
    if (!rec) return { success: false, error: 'Server not found.' };
    // App-owned credential prompt (2026-11-28): see cloud-office-open.
    if (!getClientPassword(rec) && !openCredResolved.has(serverId)) {
      return { success: false, code: 'password-needed', user: rec.user };
    }
    const url = cloudMapDrive.mediaUrlFor(rec.host, rec.port, relPath);
    if (!url) return { success: false, error: 'not-media' };
    if (rec.certPem) {
      const fp = cloudServerMod.fingerprintOfCertPem(rec.certPem);
      if (rec.fingerprint && rec.fingerprint !== fp) {
        return { success: false, url, error: 'The saved certificate does not match this server. Remove the server in the Client tab and add it again.' };
      }
      const trusted = await cloudMapDrive.isCertTrusted(rec.certPem);
      if (!trusted.success) return { success: false, url, error: trusted.error };
      if (!trusted.trusted) {
        const inst = await cloudMapDrive.installCert(rec.certPem);
        if (!inst.success) return { success: false, url, declined: !!inst.declined, error: inst.error };
      }
    }
    // Seed the credentials so the player does not prompt for a login
    // (round 2 #14: same generic URL targets as Office — players
    // fetch over HTTPS the same way; result logged).
    await seedCloudCredentialsForOpen(serverId, rec);
    // Open in the device's media player, not the browser:
    // shell.openExternal('https://…') always hands an https URL to
    // the default browser. The registered player for the extension
    // is launched with the DAV URL instead; it streams with Range
    // requests and consults the seeded Credential Manager login, so
    // it plays without a prompt. No association, or a failed launch,
    // falls back to the browser exactly as before.
    const ext = (relPath.split('.').pop() || '').toLowerCase();
    const played = await cloudMapDrive.openMediaInPlayer(url, ext);
    if (played.success) return { success: true, mode: 'direct', url, player: played.player };
    if (played.error) console.log('[Cloud] Media player open failed, falling back to the browser: ' + played.error);
    const err = await require('electron').shell.openExternal(url);
    if (err) return { success: false, url, error: String(err) };
    return { success: true, mode: 'direct', url, playerFallback: true };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
});

// Reconnect at app start: only mappings the user marked "reconnect",
// only when the password is saved, the letter is free and the server
// answers a probe. Never installs a certificate at startup (no
// surprise UAC prompt when the app opens) — a mapping whose cert is
// not trusted yet simply waits for the user to map it by hand.
async function reconnectMapDrives() {
  try {
    const state = getMapdriveState();
    if (!state.mappings.length) return;
    const cfg = getCloudConfig();
    for (const m of state.mappings) {
      if (!m.reconnect) continue;
      const rec = cfg.clients.find((c) => c.id === m.serverId);
      if (!rec || !getClientPassword(rec)) continue;
      const st = await cloudMapDrive.getDriveStatus(m.letter);
      if (st.success && st.mapped) continue;
      let probeOk = true;
      try { await cloudClient.probeServer(String(rec.host), parseInt(rec.port, 10)); }
      catch (e) { probeOk = false; }
      if (!probeOk) { appendAppLog('info', '[Cloud] Map drive ' + m.letter + ': server did not answer, skipping reconnect.'); continue; }
      if (rec.certPem) {
        const trusted = await cloudMapDrive.isCertTrusted(rec.certPem);
        if (trusted.success && !trusted.trusted) { appendAppLog('info', '[Cloud] Map drive ' + m.letter + ': certificate is not trusted yet, skipping reconnect.'); continue; }
      }
      const r = await cloudMapDrive.mapDrive({ letter: m.letter, host: rec.host, port: rec.port, user: rec.user, password: getClientPassword(rec) });
      appendAppLog(r.success ? 'info' : 'error', '[Cloud] Map drive ' + m.letter + ': reconnect ' + (r.success ? 'ok' : ('failed — ' + (r.error || ''))));
    }
  } catch (e) {}
}

// ---------- TechVision Tailscale VPN (Tailscale client manager) ----------
// The module only shells out to the Tailscale CLI that is already
// installed on the machine; it implements no VPN of its own.
ipcMain.handle('vpn-get-status', async () => {
  try { vpn.setTunnelAddress(getWgConfig().server.address); return await vpn.getStatus(); }
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
  // Secrets come from the vault here, not the renderer: the renderer
  // only ever sends the OAuth client id.
  try { vpn.setTunnelAddress(getWgConfig().server.address); return await vpn.setSubnetRouter(!!on, resolveVpnAuth(auth)); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not change the subnet router setting.' }; }
});
// Re-advertise the home LAN when the advertised route went stale
// (2026-11-27: the router advertised the 10.0.0.0/24 tunnel subnet).
// `status` is the renderer's already-fetched status, so no second
// status read is needed; without it the module reads its own.
ipcMain.handle('vpn-reconcile-subnet', async (event, auth, status) => {
  try { vpn.setTunnelAddress(getWgConfig().server.address); return await vpn.reconcileSubnetRouter(resolveVpnAuth(auth), status || null); }
  catch (e) { return { success: false, reconciled: false, error: e && e.message ? e.message : 'Could not check the subnet router.' }; }
});
ipcMain.handle('vpn-get-routes', async (event, auth) => {
  try { return await vpn.getDeviceRoutes(resolveVpnAuth(auth)); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read routes.' }; }
});
ipcMain.handle('vpn-approve-routes', async (event, auth, routes) => {
  try { return await vpn.approveRoutes(resolveVpnAuth(auth), routes); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not approve routes.' }; }
});
ipcMain.handle('vpn-disable-key-expiry', async (event, auth) => {
  try { return await vpn.disableKeyExpiry(resolveVpnAuth(auth)); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not disable key expiry.' }; }
});
ipcMain.handle('vpn-enable-key-expiry', async (event, auth) => {
  try { return await vpn.enableKeyExpiry(resolveVpnAuth(auth)); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not enable key expiry.' }; }
});
ipcMain.handle('vpn-key-expiry-state', async (event, auth) => {
  try { return await vpn.getKeyExpiryState(resolveVpnAuth(auth)); }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not read key expiry state.' }; }
});
ipcMain.handle('vpn-verify-api', async (event, auth) => {
  try {
    // A credential IS saved but the vault is locked: say so plainly
    // instead of "No API credential saved" — the token exists, the
    // app just cannot read it until the vault is unlocked. (A legacy
    // plaintext credential still verifies fine, so it is not blocked.)
    if (!vaultKey && vault.vaultExists(app.getPath('userData'))) {
      const s = readSettingsFile();
      if (s.vpn && (s.vpn.apiTokenInVault || s.vpn.oauthClientSecretInVault) && !s.vpn.apiToken && !s.vpn.oauthClientSecret) {
        return { valid: false, error: 'The vault is locked — unlock it with your master password to use the saved credential.' };
      }
    }
    return await vpn.verifyApiAuth(resolveVpnAuth(auth));
  } catch (e) { return { valid: false, error: e && e.message ? e.message : 'Could not check the credentials.' }; }
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
// from wireguard.json.
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
    if (!peer && !isClientServer) return { success: false, error: 'The remote gateway (' + cfg.remoteTunnelIp + ') is not a WireGuard peer here — add it first (with the add-peer form, or over Cloud join), then import.' };
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
async function wgAddPeerInternal(name, publicKey, endpoint) {
  if (!name) return { success: false, error: 'Give the device a name first.' };
  if (!wireguard.isWgKey(publicKey)) return { success: false, error: 'That is not a valid WireGuard public key (44 characters, ending in =).' };
  // The endpoint is optional here — the Cloud-join approval path
  // has none (the client initiates, so the server needs no address
  // for it). The manual form requires it (see the wg-add-peer
  // handler below): without an endpoint the server can never start
  // a handshake with this peer.
  let ep = null;
  if (endpoint !== undefined && endpoint !== null && String(endpoint).trim() !== '') {
    ep = String(endpoint).trim();
    if (!wireguard.isValidEndpoint(ep)) return { success: false, error: 'Endpoint must be host:port, e.g. 192.168.1.49:51820 or myhome.ddns.net:51820.' };
  }
  const c = getWgConfig();
  if ((c.server.peers || []).some((p) => p.publicKey === publicKey)) return { success: false, error: 'This device is already a peer.' };
  const subnet = wireguard.tunnelSubnetFor(c.server.address);
  const tunnelIp = wireguard.nextTunnelIp((c.server.peers || []).map((p) => p.tunnelIp), subnet);
  if (!tunnelIp) { const b = subnet.replace(/\.0\/24$/, ''); return { success: false, error: 'No free tunnel address left (' + b + '.2 – ' + b + '.254 are all taken).' }; }
  const peer = { name, publicKey, tunnelIp, allowedIPs: tunnelIp + '/32', endpoint: ep, createdAt: new Date().toISOString() };
  c.server.peers.push(peer);
  saveWgConfig();
  let liveApplied = false, liveError = null;
  try {
    const st = await wireguard.getStatus();
    if (st.serverRunning) {
      const r = await wireguard.setPeer(wireguard.SERVER_TUNNEL, publicKey, peer.allowedIPs, ep);
      liveApplied = !!r.success;
      if (!r.success) liveError = r.error;
    }
  } catch (e) { liveError = e && e.message ? e.message : String(e); }
  return { success: true, peer, liveApplied, liveError };
}
ipcMain.handle('wg-add-peer', async (event, opts) => {
  try {
    // The one way to add a peer: exactly three fields — the public
    // key, the real IP or DDNS hostname, and the port. The device
    // name is just a label, so the endpoint host is the display
    // name (the form has no separate name field).
    const publicKey = String((opts && opts.publicKey) || '').trim();
    const host = String((opts && opts.endpointHost) || '').trim();
    const portRaw = String((opts && opts.endpointPort) || '').trim();
    if (!host) return { success: false, error: 'Type the real IP or DDNS hostname of this device.' };
    if (!wireguard.isValidEndpointHost(host)) return { success: false, error: 'That is not a valid IP address or hostname.' };
    if (!portRaw) return { success: false, error: 'Type the port of this device (usually 51820).' };
    if (!/^\d+$/.test(portRaw)) return { success: false, error: 'Port must be a number from 1 to 65535.' };
    const port = Number(portRaw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return { success: false, error: 'Port must be a number from 1 to 65535.' };
    return await wgAddPeerInternal(host, publicKey, host + ':' + port);
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
ipcMain.handle('wg-open-download', async () => {
  // Manual fallback for the one-click install: the official
  // AmneziaWG releases page (same MSI the installer downloads).
  try { await require('electron').shell.openExternal(wireguard.AMNEZIAWG_RELEASES_URL); return { success: true }; }
  catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not open the download page.' }; }
});
// ---------- TechVision WireGuard VPN — Cloud join ----------
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
    if (!peer && !isClientServer) return { success: false, error: 'The remote gateway (' + peerTunnelIp + ') is not a WireGuard peer yet — add it first (with the add-peer form, or over Cloud join), then start the NAT service.' };
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
    if (!peer && !isClientServer) return { success: false, error: 'The remote gateway (' + (peerTunnelIp || '—') + ') is not a WireGuard peer yet — add it first (with the add-peer form, or over Cloud join), then save the NAT configuration.', errors: ['The remote gateway (' + (peerTunnelIp || '—') + ') is not a WireGuard peer yet — add it first (with the add-peer form, or over Cloud join), then save the NAT configuration.'] };
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
    // Change re-encrypts the vault with the new key: saved passwords
    // are KEPT (unlike the startup reset, which replaces the vault).
    // afterVaultUnlocked only migrates leftover plaintext now — there
    // is no remember-me blob any more, and the next launch still
    // asks for the master password.
    afterVaultUnlocked();
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
// ZIP password: the same vault flow, but a separate secret
// ('job-zip-password:<jobId>') — never the backup password.
ipcMain.handle('vault-has-job-zip-password', async (event, jobId) => {
  if (!vaultKey || !jobId) return { has: false };
  try { return { has: vault.hasSecret(app.getPath('userData'), vaultKey, 'job-zip-password:' + jobId) }; }
  catch (e) { return { has: false }; }
});
ipcMain.handle('vault-store-job-zip-password', async (event, jobId, jobPassword) => {
  if (!vaultKey) return { success: false, error: 'Vault is locked.' };
  try {
    vault.storeSecret(app.getPath('userData'), vaultKey, 'job-zip-password:' + jobId, jobPassword);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

// Settings is a full page in the main window now (view-settings) —
// the old separate settings window is gone.

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
  if (!jobHistory.includes(job)) return { success: false, error: 'Job was deleted or changed before the backup started.' };
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
    zipPasswordEnabled: job.zipPasswordEnabled === true,
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
  if (backupConfig.zipPasswordEnabled) {
    const zpw = resolveZipPassword(backupConfig);
    if (!zpw) return { success: false, error: 'ZIP_PASSWORD_REQUIRED' };
    backupConfig.zipPassword = zpw;
  }

  const useIncremental = backupConfig.allowIncremental === true && (job.runCount > 0 || (job.runs && job.runs.length > 0));
  const runType = useIncremental ? 'incremental' : 'full';
  const runJobId = `${jobName}-${Date.now()}`;
  activeJobs.set(runJobId, { name: jobName, jobId: job.id, status: 'running' });
  // The UI shows the job as RUNNING (with its Stop button) while the
  // run goes — it used to learn about the run only when it ended.
  notifyJobsUpdated();
  notifyEmail('started', { name: jobName, type: runType, source: jobPathValue(backupConfig.source), destination: jobPathValue(backupConfig.destination) });

  let result;
  try {
    const engine = new BackupEngine(backupConfig);
    activeEngines.set(runJobId, engine);
    // Scheduled runs never reported progress to the window, so a
    // running job showed no % anywhere. Broadcast the engine's
    // progress with the job id (dictation #2) — the Jobs details
    // progress bar matches it to the selected job. Same payload
    // shape as the manual runs, plus the identity.
    engine.onProgress = (p) => {
      try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('backup-progress', Object.assign({}, p, { jobId: job.id || null, jobName })); } catch (e) {}
    };
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
    status: runStatusOf(result),
    source: jobPathValue(backupConfig.source),
    destination: jobPathValue(backupConfig.destination),
    timestamp: new Date().toISOString(),
    files: result.files_backed_up,
    size: result.total_bytes,
    duration: result.duration_seconds,
    result: result,
    error: runErrorLine(result)
  };
  recordRun(jobName, jobRecord);
  saveJobHistory();
  notifyJobsUpdated();
  activeJobs.delete(runJobId);
  activeEngines.delete(runJobId);
  // A stopped run sends no finished/failed email — the user asked
  // for the stop, it is not a failure.
  if (!result.cancelled) notifyEmail(jobRecord.success ? 'finished' : 'failed', jobRecord);
  return { success: result.success, job: job, result: result };
});

// Stop a running backup. jobId is the job's id (job.id); the name is
// used as a fallback so runs started without a stored id (ad-hoc
// runs) stop too. Returns promptly — the run's own await unwinds
// through the engine's cancel flag, deletes the partial artifact
// and records the run as 'cancelled'. Stopping a job that is not
// running is NOT_RUNNING, not an error.
ipcMain.handle('job-stop-backup', async (event, jobId) => {
  let name = null;
  if (jobId) {
    const job = jobHistory.find((j) => j.id === jobId);
    if (job) name = job.name;
  }
  let stopped = 0;
  for (const [key, engine] of activeEngines) {
    const a = activeJobs.get(key);
    if (!a) continue;
    if ((jobId && a.jobId === jobId) || (name && a.name === name)) {
      try { engine.requestCancel(); stopped++; } catch (e) {}
    }
  }
  if (!stopped) return { success: false, error: 'NOT_RUNNING' };
  return { success: true, stopped: stopped };
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
  // A job with a ZIP password needs that password too (a layered
  // backup's inner ZIP, or a plain password-protected ZIP). Resolve
  // it the same way; when it is missing the restore reports
  // ZIP_PASSWORD_REQUIRED and the Restore page asks for it.
  let restoreZipPassword = null;
  if (job.zipPasswordEnabled === true) {
    restoreZipPassword = resolveZipPassword({ id: job.id, zipPasswordEnabled: true });
    if (!restoreZipPassword) return { success: false, error: 'ZIP_PASSWORD_REQUIRED', message: 'This backup is also password-protected (ZIP). Unlock the vault (or enter the ZIP password on the Restore page) and try again.' };
  }
  const restoreEngine = new RestoreEngine();
  const result = await restoreEngine.restore_all(job.result.backup_path, restoreDir, restorePassword, { zipPassword: restoreZipPassword });

  return { success: result.success, files_restored: result.files_restored || 0, errors: result.errors || [] };
});

ipcMain.handle('job-delete', async (event, jobId) => {
  // Round 2 #13: the template file is NOT always named after the
  // job's id or name. job-save-config names it <fileId>.json where
  // fileId is the id the wizard generated — but a job folded from
  // legacy run records (no jobId) carries the RUN's id, so neither
  // `<id>.json` nor `<name>.json` matches and the template survived
  // the delete, came back on the next start as a PENDING template,
  // and the scheduler fired it for the missed daily slot. Scan the
  // jobs dir and delete every template whose content matches this
  // job by id or by name — except one that belongs to a different
  // job still listed (same-name jobs stay separate tasks).
  const jobsDir = path.join(app.getPath('userData'), '.techvision', 'jobs');
  function deleteTemplateFiles(id, name, source, destination, knownFiles) {
    const removed = [];
    try {
      if (!fs.existsSync(jobsDir)) return removed;
      // A loaded template's own file is known by name from load time
      // (job.templateFile) — delete it directly instead of relying
      // only on the content scan below. This closes the silent-
      // success hole: a file the scan skips (unreadable under an odd
      // filename, content that matches nothing) used to survive
      // while delete still reported success, so the row vanished and
      // the template came back on the next start. Unlink needs no
      // read, so even a corrupt or read-locked file is removed; a
      // file that cannot be unlinked fails the delete loudly instead
      // of lying about it. A known file already gone from disk is
      // simply skipped — the job is already gone for good.
      for (const known of new Set(knownFiles || [])) {
        if (!known) continue;
        const kp = path.join(jobsDir, known);
        if (!fs.existsSync(kp)) continue;
        try { fs.unlinkSync(kp); removed.push(known); console.log(`[Main] Deleted job template file: ${kp}`); }
        catch (e) { throw new Error(`Cannot delete job template ${known}: ${e.message}`); }
      }
      // Ids of jobs other than the one being deleted: a template
      // whose content id is one of these belongs to that other job
      // and must survive even if the name matches.
      const otherIds = new Set(jobHistory.filter(j => j.id !== id).map(j => j.id).filter(Boolean));
      for (const file of fs.readdirSync(jobsDir)) {
        if (!file.endsWith('.json') || file === 'history.json' || file === 'waiting.json') continue;
        const p = path.join(jobsDir, file);
        // Read the template FIRST: the filename alone cannot tell
        // whose job it is — a legacy <name>.json may belong to a
        // different live job that happens to share the name, and a
        // file named <id>.json may carry another job's content.
        // An unreadable file that could be this job's own template
        // (<id>.json / <name>.json) makes deletion inconclusive:
        // report failure instead of claiming success with a live
        // template. Any other unreadable file is skipped (logged) —
        // it belongs to another job or is junk, and must not block
        // every delete forever.
        let content;
        try {
          content = JSON.parse(fs.readFileSync(p, 'utf-8'));
        } catch (e) {
          console.error(`[Main] Skipping unreadable job template file during delete: ${p} (${e.message})`);
          if (file === id + '.json' || file === name + '.json') {
            throw new Error(`Cannot verify job template ${file}: ${e.message}`);
          }
          continue;
        }
        const cid = content && content.id;
        const cname = content && content.name;
        let match = false;
        if (cid && cid === id) match = true;
        else if (cname && cname === name) {
          // Same name, but the file may belong to a different job
          // that happens to share the name — keep it, unless it
          // is the same job by paths (a stale second template
          // file for this job: an old <name>.json plus the
          // current <id>.json both survive a delete otherwise).
          const samePaths = source && destination && content.source && content.destination
            && jobPathValue(content.source) === jobPathValue(source)
            && jobPathValue(content.destination) === jobPathValue(destination);
          if (!(cid && otherIds.has(cid)) || samePaths) match = true;
        }
        if (match) {
          try { fs.unlinkSync(p); removed.push(file); console.log(`[Main] Deleted job template file: ${p}`); }
          catch (e) { throw new Error(`Cannot delete job template ${file}: ${e.message}`); }
        }
      }
    } catch (e) { console.error('[Main] Failed to scan jobs dir for templates:', e.message); throw e; }
    return removed;
  }
  let idx = jobHistory.findIndex(j => j.id === jobId);
  if (idx < 0) idx = jobHistory.findIndex(j => j.name === jobId);
  if (idx >= 0) {
    const job = jobHistory[idx];
    // Old name/id files can represent the same task. Remove their
    // in-memory entries too, or a remaining schedule recreates history.
    const sameTask = j => j.id === job.id || (j.name === job.name
      && job.source && job.destination
      && jobPathValue(j.source) === jobPathValue(job.source)
      && jobPathValue(j.destination) === jobPathValue(job.destination));
    const deleting = jobHistory.filter(sameTask);
    if ([...activeJobs.values()].some(a => deleting.some(j => a.jobId ? a.jobId === j.id : a.name === j.name))) {
      return { success: false, error: 'This backup is running. Wait for it to finish before deleting the job.' };
    }
    try { deleteTemplateFiles(job.id, job.name, job.source, job.destination, deleting.filter(j => j.loaded).map(j => j.templateFile)); }
    catch (e) { return { success: false, error: e.message }; }
    const previous = jobHistory;
    jobHistory = jobHistory.filter(j => !sameTask(j));
    if (!saveJobHistory()) {
      jobHistory = previous;
      return { success: false, error: 'Could not save deleted job history. Deletion is incomplete; please retry.' };
    }
    saveWaitingState();
    notifyJobsUpdated();
    return { success: true };
  }
  // Orphan: no job in memory matches, but a template file may still
  // exist on disk. Delete it (by content match) and persist the
  // history — before this the handler returned success without ever
  // saving, so any run records on disk came back on the next start.
  let removed;
  try { removed = deleteTemplateFiles(jobId, jobId); }
  catch (e) { return { success: false, error: e.message }; }
  // No blind fallback unlink of <jobId>.json here: if the content
  // scan skipped that file it either belongs to a different live job
  // or is unreadable, and both must survive the delete.
  if (removed.length) {
    if (!saveJobHistory()) return { success: false, error: 'Could not save deleted job history.' };
    saveWaitingState(); notifyJobsUpdated(); return { success: true };
  }
  return { success: false, error: 'Job not found' };
});

function promptRestoreDir() {
  // Return a default restore directory
  return path.join(app.getPath('documents'), 'TechVision Restores');
}
