/**
 * TechVision Backup — master-password vault (main process only).
 *
 * Job passwords for encrypted backups are stored here, encrypted with
 * a key derived from ONE master password the user types when the app
 * starts. The vault file lives in the app's own data folder
 * (<userData>/.techvision/vault.json) — NOT in Windows Credential
 * Manager / DPAPI, by the user's choice.
 *
 * File format:
 *   { version: 1,
 *     salt: base64 (16 bytes, scrypt salt),
 *     check: base64 (AES-256-GCM of "techvision-vault-check"),
 *     jobs: { "<jobId>": base64("iv:ciphertext:tag") },
 *     secrets: { "<namespaced-key>": base64("iv:ciphertext:tag") } }
 *
 * Generic secrets live under `secrets` with namespaced keys, e.g.
 *   'cloud-client:<serverId>' — saved password for a Cloud server
 *   'smtp'                   — SMTP / Gmail App Password
 *   'tailscale-api-token'    — Tailscale API access token
 *   'tailscale-oauth-secret' — Tailscale OAuth client secret
 * Job passwords stay under `jobs` exactly as before.
 *
 * Remember-me: after the master password is entered once, the derived
 * key can be persisted with Electron safeStorage (DPAPI on Windows)
 * in .techvision/vault-unlock.json, so the vault auto-unlocks on
 * startup and the master password is never asked again while the app
 * is installed. The master password itself is NEVER written anywhere.
 * safeStorage is injected by the caller (main.js passes Electron's);
 * this module never requires Electron, so it stays testable in plain
 * node. When safeStorage is unavailable the vault simply asks each
 * launch, as before.
 *
 * Machine keys stay OUT of the vault by design (auto-start): the
 * Cloud server TLS private key and the WireGuard private keys remain
 * plaintext in their config files — they are not user passwords.
 *
 * The derived key is held in memory only (main.js keeps it while the
 * vault is unlocked). Forgetting the master password means the stored
 * job passwords are unrecoverable — the backups themselves are
 * unaffected and still open with their own backup password.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CHECK_PLAINTEXT = 'techvision-vault-check';
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function getVaultPath(userDataDir) {
  return path.join(userDataDir, '.techvision', 'vault.json');
}

function vaultExists(userDataDir) {
  try { return fs.existsSync(getVaultPath(userDataDir)); } catch (e) { return false; }
}

function readVault(userDataDir) {
  const p = getVaultPath(userDataDir);
  if (!fs.existsSync(p)) return null;
  const data = JSON.parse(fs.readFileSync(p, 'utf-8'));
  // jobs must be a plain object: a torn write that left `jobs: []`
  // (or null) used to pass the typeof check and then either throw a
  // TypeError on store or silently lose every stored password.
  if (!data || data.version !== 1 || !data.salt || !data.check || !data.jobs || typeof data.jobs !== 'object' || Array.isArray(data.jobs)) {
    throw new Error('Vault file is corrupt or from an unknown version.');
  }
  // `secrets` is new (generic secrets, round 3): vaults written before
  // it existed simply have none — normalise instead of rejecting.
  if (!data.secrets || typeof data.secrets !== 'object' || Array.isArray(data.secrets)) data.secrets = {};
  return data;
}

function writeVault(userDataDir, data) {
  const dir = path.join(userDataDir, '.techvision');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  // Atomic write: a direct overwrite used to leave a truncated
  // vault.json after a crash/power loss/disk-full mid-write, losing
  // EVERY stored job password unrecoverably. Write to a temp file,
  // keep the previous good copy as vault.json.bak, then rename.
  const vaultPath = getVaultPath(userDataDir);
  const tmpPath = vaultPath + '.tmp-' + process.pid;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2));
  try {
    if (fs.existsSync(vaultPath)) fs.copyFileSync(vaultPath, vaultPath + '.bak');
  } catch (e) { /* backup copy is best-effort; the rename still proceeds */ }
  fs.renameSync(tmpPath, vaultPath);
}

// Wipe derived key material from memory when the vault is locked.
// Assigning the reference to null alone leaves the bytes in the heap.
function lockVault(key) {
  if (key && Buffer.isBuffer(key)) key.fill(0);
}

function deriveKey(masterPassword, saltB64) {
  return crypto.scryptSync(masterPassword, Buffer.from(saltB64, 'base64'), 32, SCRYPT_OPTS);
}

// Password strength rule (batch 3, the user's decision): a password
// that protects anything must be at least 12 characters and contain
// an uppercase letter, a lowercase letter, a digit AND a symbol.
// Applies to the Master Password (creation/change) and to the
// encryption (backup) password in the wizard — enforced at
// CREATION/CHANGE only, never at unlock (an old, weaker password
// must still unlock what it locked). Returns null when the password
// is strong enough, or a plain-English reason it is not.
// The same rule lives in the renderer (job-wizard.js, renderer.js)
// because those run without require() — keep the three in sync.
function validateStrongPassword(pw) {
  if (!pw || typeof pw !== 'string') return 'Enter a password of at least 12 characters with uppercase, lowercase, numbers and symbols.';
  if (pw.length < 12) return 'Password must be at least 12 characters long.';
  if (!/[A-Z]/.test(pw)) return 'Password must contain at least one uppercase letter.';
  if (!/[a-z]/.test(pw)) return 'Password must contain at least one lowercase letter.';
  if (!/[0-9]/.test(pw)) return 'Password must contain at least one number.';
  if (!/[^A-Za-z0-9]/.test(pw)) return 'Password must contain at least one symbol.';
  return null;
}

function encryptWithKey(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString('base64');
}

function decryptWithKey(key, blobB64) {
  const blob = Buffer.from(blobB64, 'base64');
  if (blob.length < 12 + 16) throw new Error('Bad vault entry.');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

function setupVault(userDataDir, masterPassword) {
  const weak = validateStrongPassword(masterPassword);
  if (weak) throw new Error(weak);
  if (vaultExists(userDataDir)) throw new Error('A vault already exists. Use change instead.');
  const salt = crypto.randomBytes(16).toString('base64');
  const key = deriveKey(masterPassword, salt);
  const data = { version: 1, salt: salt, check: encryptWithKey(key, CHECK_PLAINTEXT), jobs: {}, secrets: {} };
  writeVault(userDataDir, data);
  return key;
}

/* Replace the vault with a fresh one (the "I forgot my master
   password" path at startup). The old vault file is deleted first,
   so every secret the old key encrypted is GONE for good — the
   caller must warn the user and get a confirmation before calling
   this. The old remember-me blob (if any) is deleted too, since it
   unlocks the old vault only. setupVault's "already exists" guard is
   bypassed here on purpose: replacing is the whole point. */
function resetVault(userDataDir, masterPassword) {
  const weak = validateStrongPassword(masterPassword);
  if (weak) throw new Error(weak);
  try { fs.unlinkSync(getVaultPath(userDataDir)); } catch (e) { /* no old vault */ }
  try { clearUnlockBlob(userDataDir); } catch (e) { /* no old blob */ }
  return setupVault(userDataDir, masterPassword);
}

function unlockVault(userDataDir, masterPassword) {
  const data = readVault(userDataDir);
  if (!data) throw new Error('No vault has been set up yet.');
  const key = deriveKey(masterPassword, data.salt);
  let check;
  try { check = decryptWithKey(key, data.check); } catch (e) { throw new Error('Wrong master password.'); }
  if (check !== CHECK_PLAINTEXT) throw new Error('Wrong master password.');
  return key;
}

function storeJobPassword(userDataDir, key, jobId, jobPassword) {
  if (!key) throw new Error('Vault is locked.');
  if (!jobId || !jobPassword) throw new Error('Job id and password are required.');
  const data = readVault(userDataDir);
  if (!data) throw new Error('No vault has been set up yet.');
  data.jobs[jobId] = encryptWithKey(key, jobPassword);
  writeVault(userDataDir, data);
}

function getJobPassword(userDataDir, key, jobId) {
  if (!key) return null;
  const data = readVault(userDataDir);
  if (!data || !data.jobs[jobId]) return null;
  try { return decryptWithKey(key, data.jobs[jobId]); } catch (e) { return null; }
}

function hasJobPassword(userDataDir, key, jobId) {
  return getJobPassword(userDataDir, key, jobId) !== null;
}

function removeJobPassword(userDataDir, key, jobId) {
  if (!key) throw new Error('Vault is locked.');
  const data = readVault(userDataDir);
  if (!data) return;
  delete data.jobs[jobId];
  writeVault(userDataDir, data);
}

// ---------- generic secrets (namespaced keys) ----------
// Same AES-256-GCM envelope as job passwords, under `secrets`.
// Names are caller-chosen namespaces, e.g. 'cloud-client:<serverId>',
// 'smtp', 'tailscale-api-token', 'tailscale-oauth-secret'.
function storeSecret(userDataDir, key, name, value) {
  if (!key) throw new Error('Vault is locked.');
  if (!name || typeof name !== 'string') throw new Error('Secret name is required.');
  if (!value) throw new Error('Secret value is required.');
  const data = readVault(userDataDir);
  if (!data) throw new Error('No vault has been set up yet.');
  data.secrets[name] = encryptWithKey(key, String(value));
  writeVault(userDataDir, data);
}

function getSecret(userDataDir, key, name) {
  if (!key || !name) return null;
  const data = readVault(userDataDir);
  if (!data || !data.secrets[name]) return null;
  try { return decryptWithKey(key, data.secrets[name]); } catch (e) { return null; }
}

function hasSecret(userDataDir, key, name) {
  return getSecret(userDataDir, key, name) !== null;
}

function removeSecret(userDataDir, key, name) {
  if (!key) throw new Error('Vault is locked.');
  const data = readVault(userDataDir);
  if (!data) return;
  delete data.secrets[name];
  writeVault(userDataDir, data);
}

// ---------- migration of legacy plaintext passwords ----------
// Moves passwords that used to sit in plain text in the JSON config
// files into the vault, then writes the files back WITHOUT them:
//   cloud.json clients[].password  -> secret 'cloud-client:<id>',
//     record keeps passwordInVault:true so the connect flow reads
//     the vault instead (a legacy `password` field is still honoured
//     as a fallback until migration has run);
//   settings.json email.smtpPass   -> secret 'smtp'
//   settings.json vpn.apiToken     -> secret 'tailscale-api-token'
//   settings.json vpn.oauthClientSecret -> secret 'tailscale-oauth-secret'
// Idempotent: a second run finds nothing to move and changes nothing.
// Returns { cloud, smtp, apiToken, oauthSecret } counts. Never throws
// for a missing or unreadable file — there is simply nothing to move.
function migrateLegacySecrets(userDataDir, key) {
  const moved = { cloud: 0, smtp: false, apiToken: false, oauthSecret: false };
  if (!key) return moved;
  const dir = path.join(userDataDir, '.techvision');
  // Cloud client passwords (cloud.json).
  try {
    const p = path.join(dir, 'cloud.json');
    if (fs.existsSync(p)) {
      const cfg = JSON.parse(fs.readFileSync(p, 'utf-8'));
      if (cfg && Array.isArray(cfg.clients)) {
        let changed = false;
        for (const c of cfg.clients) {
          if (c && typeof c.password === 'string' && c.password) {
            storeSecret(userDataDir, key, 'cloud-client:' + c.id, c.password);
            delete c.password;
            c.passwordInVault = true;
            moved.cloud++;
            changed = true;
          }
        }
        if (changed) fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
      }
    }
  } catch (e) { /* a torn config is not migration's job to fix */ }
  // SMTP + Tailscale secrets (settings.json).
  try {
    const p = path.join(dir, 'settings.json');
    if (fs.existsSync(p)) {
      const s = JSON.parse(fs.readFileSync(p, 'utf-8'));
      let changed = false;
      if (s && s.email && typeof s.email.smtpPass === 'string' && s.email.smtpPass) {
        storeSecret(userDataDir, key, 'smtp', s.email.smtpPass);
        delete s.email.smtpPass;
        s.email.smtpPassInVault = true;
        moved.smtp = true;
        changed = true;
      }
      if (s && s.vpn && typeof s.vpn === 'object') {
        if (typeof s.vpn.apiToken === 'string' && s.vpn.apiToken) {
          storeSecret(userDataDir, key, 'tailscale-api-token', s.vpn.apiToken);
          delete s.vpn.apiToken;
          s.vpn.apiTokenInVault = true;
          moved.apiToken = true;
          changed = true;
        }
        if (typeof s.vpn.oauthClientSecret === 'string' && s.vpn.oauthClientSecret) {
          storeSecret(userDataDir, key, 'tailscale-oauth-secret', s.vpn.oauthClientSecret);
          delete s.vpn.oauthClientSecret;
          s.vpn.oauthClientSecretInVault = true;
          moved.oauthSecret = true;
          changed = true;
        }
      }
      if (changed) fs.writeFileSync(p, JSON.stringify(s, null, 2));
    }
  } catch (e) { /* same as above */ }
  return moved;
}

// ---------- remember-me (safeStorage unlock blob) ----------
// The blob file holds ONLY the derived vault key, encrypted by the
// OS keychain (DPAPI on Windows) via safeStorage — never the master
// password, never a plaintext key. Uninstall removes the app-data
// folder (vault + blob), so a reinstall starts fresh and asks again.
function getUnlockBlobPath(userDataDir) {
  return path.join(userDataDir, '.techvision', 'vault-unlock.json');
}

function safeStorageAvailable(safeStorage) {
  try {
    return !!(safeStorage && typeof safeStorage.isEncryptionAvailable === 'function' && safeStorage.isEncryptionAvailable());
  } catch (e) { return false; }
}

// Persist the unlock for this device. Returns { saved: true } or
// { saved: false, reason } — a missing/unavailable safeStorage is a
// normal fallback (Linux sandbox, old OS), never an error.
function saveUnlockBlob(userDataDir, safeStorage, key) {
  if (!key || !Buffer.isBuffer(key)) return { saved: false, reason: 'No vault key.' };
  if (!safeStorageAvailable(safeStorage)) return { saved: false, reason: 'safeStorage is not available on this system.' };
  try {
    const blob = safeStorage.encryptString(key.toString('base64'));
    const dir = path.join(userDataDir, '.techvision');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(getUnlockBlobPath(userDataDir), JSON.stringify({ version: 1, blob: Buffer.from(blob).toString('base64') }));
    return { saved: true };
  } catch (e) { return { saved: false, reason: e && e.message ? e.message : String(e) }; }
}

// Try to auto-unlock from the saved blob. Returns the derived key
// (Buffer) when the blob decrypts AND the key opens the vault check,
// otherwise null. A stale blob (master password changed elsewhere,
// blob tampered with) simply does not unlock — the user is asked.
function tryAutoUnlock(userDataDir, safeStorage) {
  if (!safeStorageAvailable(safeStorage)) return null;
  try {
    const p = getUnlockBlobPath(userDataDir);
    if (!fs.existsSync(p)) return null;
    const data = JSON.parse(fs.readFileSync(p, 'utf-8'));
    if (!data || data.version !== 1 || !data.blob) return null;
    const keyB64 = safeStorage.decryptString(Buffer.from(data.blob, 'base64'));
    if (!keyB64 || typeof keyB64 !== 'string') return null;
    const key = Buffer.from(keyB64, 'base64');
    if (key.length !== 32) return null;
    const vaultData = readVault(userDataDir);
    if (!vaultData) { lockVault(key); return null; }
    if (decryptWithKey(key, vaultData.check) !== CHECK_PLAINTEXT) { lockVault(key); return null; }
    return key;
  } catch (e) { return null; }
}

function clearUnlockBlob(userDataDir) {
  try { const p = getUnlockBlobPath(userDataDir); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (e) {}
}

function changeMasterPassword(userDataDir, oldPassword, newPassword) {
  const weak = validateStrongPassword(newPassword);
  if (weak) throw new Error(weak);
  const oldKey = unlockVault(userDataDir, oldPassword); // throws on wrong old password
  try {
    const data = readVault(userDataDir);
    const newSalt = crypto.randomBytes(16).toString('base64');
    const newKey = deriveKey(newPassword, newSalt);
    // Re-encrypt every stored job password AND generic secret under
    // the new key. A corrupt entry throws here BEFORE anything is
    // written, so the vault is never left half-re-encrypted.
    const jobs = {};
    for (const jobId of Object.keys(data.jobs)) {
      const pw = decryptWithKey(oldKey, data.jobs[jobId]);
      jobs[jobId] = encryptWithKey(newKey, pw);
    }
    const secrets = {};
    for (const name of Object.keys(data.secrets || {})) {
      const value = decryptWithKey(oldKey, data.secrets[name]);
      secrets[name] = encryptWithKey(newKey, value);
    }
    writeVault(userDataDir, { version: 1, salt: newSalt, check: encryptWithKey(newKey, CHECK_PLAINTEXT), jobs: jobs, secrets: secrets });
    return newKey;
  } finally {
    lockVault(oldKey);
  }
}

module.exports = {
  getVaultPath, vaultExists, setupVault, resetVault, unlockVault, lockVault,
  validateStrongPassword,
  storeJobPassword, getJobPassword, hasJobPassword,
  removeJobPassword, changeMasterPassword,
  storeSecret, getSecret, hasSecret, removeSecret,
  migrateLegacySecrets,
  getUnlockBlobPath, saveUnlockBlob, tryAutoUnlock, clearUnlockBlob
};
