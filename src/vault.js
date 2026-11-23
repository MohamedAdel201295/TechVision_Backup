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
 *     jobs: { "<jobId>": base64("iv:ciphertext:tag") } }
 *
 * The derived key is held in memory only (main.js keeps it while the
 * vault is unlocked). Forgetting the master password means the stored
 * job passwords are unrecoverable — the backup ZIPs themselves are
 * unaffected and still open with their own job password.
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
  if (!data || data.version !== 1 || !data.salt || !data.check || typeof data.jobs !== 'object') {
    throw new Error('Vault file is corrupt or from an unknown version.');
  }
  return data;
}

function writeVault(userDataDir, data) {
  const dir = path.join(userDataDir, '.techvision');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(getVaultPath(userDataDir), JSON.stringify(data, null, 2));
}

function deriveKey(masterPassword, saltB64) {
  return crypto.scryptSync(masterPassword, Buffer.from(saltB64, 'base64'), 32, SCRYPT_OPTS);
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
  if (!masterPassword || masterPassword.length < 8) {
    throw new Error('Master password must be at least 8 characters.');
  }
  if (vaultExists(userDataDir)) throw new Error('A vault already exists. Use change instead.');
  const salt = crypto.randomBytes(16).toString('base64');
  const key = deriveKey(masterPassword, salt);
  const data = { version: 1, salt: salt, check: encryptWithKey(key, CHECK_PLAINTEXT), jobs: {} };
  writeVault(userDataDir, data);
  return key;
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

function changeMasterPassword(userDataDir, oldPassword, newPassword) {
  if (!newPassword || newPassword.length < 8) {
    throw new Error('New master password must be at least 8 characters.');
  }
  const oldKey = unlockVault(userDataDir, oldPassword); // throws on wrong old password
  const data = readVault(userDataDir);
  const newSalt = crypto.randomBytes(16).toString('base64');
  const newKey = deriveKey(newPassword, newSalt);
  // Re-encrypt every stored job password under the new key.
  const jobs = {};
  for (const jobId of Object.keys(data.jobs)) {
    const pw = decryptWithKey(oldKey, data.jobs[jobId]);
    jobs[jobId] = encryptWithKey(newKey, pw);
  }
  writeVault(userDataDir, { version: 1, salt: newSalt, check: encryptWithKey(newKey, CHECK_PLAINTEXT), jobs: jobs });
  return newKey;
}

module.exports = {
  getVaultPath, vaultExists, setupVault, unlockVault,
  storeJobPassword, getJobPassword, hasJobPassword,
  removeJobPassword, changeMasterPassword
};
