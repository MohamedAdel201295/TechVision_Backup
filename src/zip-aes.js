/**
 * TechVision Backup — WinZip AES (AE-1 / AE-2) ZIP reader (main process).
 *
 * yauzl (used for normal restores) cannot decrypt, and no pure-JS
 * library in the project reads WinZip AES-256. So this module parses
 * the ZIP central directory itself and decrypts entries with Node's
 * built-in crypto — no extra binary, no 7-Zip dependency, works the
 * same in the packaged app.
 *
 * Format (WinZip AES, standard, readable by 7-Zip / WinRAR):
 *   extra field 0x9901: AE version (1 or 2), vendor "AE",
 *   strength (1=128, 2=192, 3=256), real compression method.
 *   encrypted blob: salt (8/12/16 bytes) + 2-byte password check
 *   + AES-CTR ciphertext + 10-byte HMAC-SHA1 auth code.
 *   keys: PBKDF2-HMAC-SHA1, 1000 rounds, key length 2*keyLen + 2.
 *   AES-CTR counter is a little-endian 16-byte integer starting at 1.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const AES_EXTRA_ID = 0x9901;

// --- CRC32 (for AE-1 entries, whose central-directory CRC is real) ---
const CRC_TABLE = (function () {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c;
  }
  return table;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// --- Central directory parsing ---
function findEOCD(buf) {
  const min = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new Error('Not a ZIP file (end-of-central-directory record not found).');
}

function parseExtra(extra, wantId) {
  let off = 0;
  while (off + 4 <= extra.length) {
    const id = extra.readUInt16LE(off);
    const size = extra.readUInt16LE(off + 2);
    if (off + 4 + size > extra.length) break;
    if (id === wantId) return extra.subarray(off + 4, off + 4 + size);
    off += 4 + size;
  }
  return null;
}

function parseCentralDirectory(buf) {
  const eocd = findEOCD(buf);
  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xFFFF || cdOffset === 0xFFFFFFFF) {
    throw new Error('Zip64 archives are not supported by the AES reader.');
  }
  const entries = [];
  let off = cdOffset;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== CD_SIG) throw new Error('Central directory is corrupt.');
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const crc = buf.readUInt32LE(off + 16);
    const compressedSize = buf.readUInt32LE(off + 20);
    const uncompressedSize = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOffset = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    const extra = buf.subarray(off + 46 + nameLen, off + 46 + nameLen + extraLen);
    const aes = parseExtra(extra, AES_EXTRA_ID);
    let aesStrength = 0; let realMethod = method; let aeVersion = 0;
    if (aes && aes.length >= 7) {
      aeVersion = aes.readUInt16LE(0);
      aesStrength = aes.readUInt8(4);
      realMethod = aes.readUInt16LE(5);
    }
    entries.push({
      name: name,
      isDir: name.endsWith('/'),
      size: uncompressedSize,
      compressedSize: compressedSize,
      method: method,
      realMethod: realMethod,
      crc: crc,
      flags: flags,
      encrypted: (flags & 0x01) !== 0,
      aesStrength: aesStrength,
      aeVersion: aeVersion,
      localOffset: localOffset
    });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** List entries + whether the archive is encrypted. Throws on bad ZIPs. */
function inspectZip(zipPath) {
  const buf = fs.readFileSync(zipPath);
  const entries = parseCentralDirectory(buf);
  return {
    entries: entries.map(function (e) {
      return { name: e.name, isDir: e.isDir, size: e.size, method: e.realMethod,
               encrypted: e.encrypted, aesStrength: e.aesStrength };
    }),
    encrypted: entries.some(function (e) { return e.encrypted; })
  };
}

function aesKeyLength(strength) {
  if (strength === 1) return 16;
  if (strength === 2) return 24;
  return 32; // strength 3 = AES-256
}

function aesCtrDecrypt(key, data) {
  const cipher = crypto.createCipheriv('aes-' + (key.length * 8) + '-ecb', key, null);
  cipher.setAutoPadding(false);
  const out = Buffer.alloc(data.length);
  const counter = Buffer.alloc(16);
  counter[0] = 1;
  for (let off = 0; off < data.length; off += 16) {
    const keystream = cipher.update(counter);
    const end = Math.min(off + 16, data.length);
    for (let i = off; i < end; i++) out[i] = data[i] ^ keystream[i - off];
    // Little-endian counter increment (WinZip AES spec).
    let j = 0;
    while (j < 16) { counter[j]++; if (counter[j] !== 0) break; j++; }
  }
  return out;
}

/** Decrypt + inflate one entry. Throws Error('Wrong password ...') on a bad password. */
function decryptEntry(zipPath, entry, password) {
  if (!entry.encrypted) throw new Error('Entry is not encrypted: ' + entry.name);
  if (!entry.aesStrength) throw new Error('Unsupported encryption (not WinZip AES): ' + entry.name);
  if (typeof password !== 'string' || !password) throw new Error('A password is required for this encrypted backup.');
  const buf = fs.readFileSync(zipPath);
  // Local header: skip name + extra to reach the encrypted blob.
  if (buf.readUInt32LE(entry.localOffset) !== LFH_SIG) throw new Error('Local file header not found for ' + entry.name);
  const nameLen = buf.readUInt16LE(entry.localOffset + 26);
  const extraLen = buf.readUInt16LE(entry.localOffset + 28);
  const dataStart = entry.localOffset + 30 + nameLen + extraLen;
  const keyLen = aesKeyLength(entry.aesStrength);
  const saltLen = keyLen === 16 ? 8 : (keyLen === 24 ? 12 : 16);
  const salt = buf.subarray(dataStart, dataStart + saltLen);
  const verify = buf.subarray(dataStart + saltLen, dataStart + saltLen + 2);
  const cipherStart = dataStart + saltLen + 2;
  const cipherEnd = dataStart + entry.compressedSize - 10; // last 10 bytes = auth code
  const ciphertext = buf.subarray(cipherStart, cipherEnd);
  const authCode = buf.subarray(dataStart + entry.compressedSize - 10, dataStart + entry.compressedSize);
  const derived = crypto.pbkdf2Sync(password, salt, 1000, 2 * keyLen + 2, 'sha1');
  const aesKey = derived.subarray(0, keyLen);
  const macKey = derived.subarray(keyLen, 2 * keyLen);
  const expectedVerify = derived.subarray(2 * keyLen, 2 * keyLen + 2);
  if (!expectedVerify.equals(verify)) throw new Error('Wrong password for this encrypted backup.');
  const hmac = crypto.createHmac('sha1', macKey).update(ciphertext).digest().subarray(0, 10);
  if (!hmac.equals(authCode)) throw new Error('Backup is corrupt (authentication failed for ' + entry.name + ').');
  const decrypted = aesCtrDecrypt(aesKey, ciphertext);
  let plain;
  if (entry.realMethod === 8) plain = zlib.inflateRawSync(decrypted);
  else if (entry.realMethod === 0) plain = decrypted;
  else throw new Error('Unsupported compression method ' + entry.realMethod + ' in ' + entry.name);
  // AE-1 stores a real CRC; AE-2 stores 0 and relies on the auth code.
  if (entry.aeVersion === 1 && entry.crc !== 0 && crc32(plain) !== entry.crc) {
    throw new Error('Backup is corrupt (CRC mismatch for ' + entry.name + ').');
  }
  return plain;
}

/** Restore every file from an encrypted ZIP into destDir. */
function extractEncrypted(zipPath, destDir, password, onFile) {
  const buf = fs.readFileSync(zipPath);
  const entries = parseCentralDirectory(buf);
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
  let files = 0; let bytes = 0; const errors = [];
  for (const entry of entries) {
    if (entry.isDir) continue;
    // Zip-slip guard: entry names must stay inside destDir.
    const dest = path.join(destDir, entry.name.split('/').join(path.sep));
    if (!dest.startsWith(path.resolve(destDir) + path.sep) && dest !== path.resolve(destDir)) {
      errors.push('Skipped unsafe path: ' + entry.name);
      continue;
    }
    try {
      const content = decryptEntry(zipPath, entry, password);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, content);
      files++; bytes += content.length;
      if (typeof onFile === 'function') onFile(entry.name, content.length);
    } catch (e) {
      errors.push(entry.name + ': ' + e.message);
      if (e.message.indexOf('Wrong password') === 0) throw e; // one wrong password fails the whole restore
    }
  }
  return { files: files, bytes: bytes, errors: errors };
}

module.exports = { inspectZip, decryptEntry, extractEncrypted, parseCentralDirectory, crc32 };
