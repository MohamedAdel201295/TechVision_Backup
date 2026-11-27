/**
 * TechVision Backup — WinZip AES (AE-1 / AE-2) ZIP reader (main process).
 *
 * yauzl (used for normal restores) cannot decrypt, and no pure-JS
 * library in the project reads WinZip AES-256. So this module parses
 * the ZIP central directory itself and decrypts entries with Node's
 * built-in crypto — no extra binary, no 7-Zip dependency, works the
 * same in the packaged app.
 *
 * Role: the ZIP-PASSWORD layer. A job with a ZIP password writes a
 * WinZip AES ZIP (archiver-zip-encrypted, the writer); this module
 * reads it back. The format is the standard one, so 7-Zip / WinRAR
 * open the same file with the same password — that is deliberate,
 * unlike the .tvb layer (src/tvb.js), which no outside program can
 * open. A .tvb whose single entry is a password-protected ZIP (the
 * layered case, both passwords) is decrypted by the TVB reader
 * first, then restored through this module.
 *
 * Format (WinZip AES, standard, readable by 7-Zip / WinRAR):
 *   extra field 0x9901: AE version (1 or 2), vendor "AE",
 *   strength (1=128, 2=192, 3=256), real compression method.
 *   encrypted blob: salt (8/12/16 bytes) + 2-byte password check
 *   + AES-CTR ciphertext + 10-byte HMAC-SHA1 auth code.
 *   keys: PBKDF2-HMAC-SHA1, 1000 rounds, key length 2*keyLen + 2.
 *   AES-CTR counter is a little-endian 16-byte integer starting at 1.
 *
 * Memory discipline (P1-5): the restore paths in this module NEVER
 * hold a whole archive or a whole entry in memory. The central
 * directory is read with bounded file-descriptor reads (tail +
 * central-directory region only); entries are decrypted by streaming
 * the ciphertext through a Transform into a temp file, with the HMAC
 * checked incrementally and the rename committed only after it (and
 * the AE-1 CRC) pass. The old synchronous `decryptEntry` is kept for
 * compatibility but is documented as buffering the whole entry — the
 * restore engine must not use it; use `decryptEntryToFile` instead.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const AES_EXTRA_ID = 0x9901;
const ZIP64_EOCD_SIG = 0x06064b50;
const ZIP64_LOC_SIG = 0x07064b50;
const ZIP64_EXTRA_ID = 0x0001;
// Ciphertext bytes read per stream chunk while decrypting.
const DECRYPT_CHUNK = 64 * 1024;
let tmpCounter = 0;

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
function crc32(buf, prev) {
  // Chainable: crc32(chunk2, crc32(chunk1)) === crc32(Buffer.concat([chunk1, chunk2])).
  // `prev` is a previously returned value; with no prev it behaves
  // exactly as before (single-shot CRC of the whole buffer).
  let c = (prev === undefined ? 0xFFFFFFFF : (prev ^ 0xFFFFFFFF)) >>> 0;
  for (let i = 0; i < buf.length; i++) c = (CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8)) >>> 0;
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// Constant-time buffer comparison (for password-check and auth-code
// values): Buffer.equals leaks the comparison through timing.
function timingSafeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Read exactly `length` bytes from `fd` at `position` (loops over
// short reads); throws when the file ends first.
function readFully(fd, length, position) {
  const buf = Buffer.alloc(length);
  let got = 0;
  while (got < length) {
    const n = fs.readSync(fd, buf, got, length - got, position + got);
    if (n === 0) throw new Error('Unexpected end of file while reading ZIP structure.');
    got += n;
  }
  return buf;
}

// --- Central directory parsing ---
// Returns the offset of the end-of-central-directory record in `buf`,
// or -1 when there is none. A signature inside file data is a false
// positive unless the comment length matches the distance to the end
// of the buffer.
function findEOCD(buf) {
  const min = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      if (i + 22 + buf.readUInt16LE(i + 20) === buf.length) return i;
    }
  }
  return -1;
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

// --- Zip64 support (P1-6) ---
// A Zip64 archive stores the real values where the 32-bit fields
// hold sentinels: the end-of-central-directory record holds
// 0xFFFF counts / 0xFFFFFFFF sizes and offsets (resolved through
// the Zip64 EOCD record + locator just before it), and a central
// directory entry holds 0xFFFFFFFF sizes / local offset (resolved
// through its Zip64 extra field 0x0001). Multi-disk archives are
// still rejected — TechVision never writes them and the reader
// cannot fetch entries from another disk.

// The Zip64 extra field stores the values that are sentinels in the
// central directory, in this fixed order: uncompressed size (8),
// compressed size (8), local header offset (8), disk start (4) —
// only the sentinel fields appear. `need` says which ones to read.
function parseZip64Extra(extra, need) {
  const raw = parseExtra(extra, ZIP64_EXTRA_ID);
  if (!raw) throw new Error('Zip64 entry is missing its Zip64 extra field.');
  let off = 0;
  const out = {};
  const take64 = () => {
    if (off + 8 > raw.length) throw new Error('Zip64 entry has a truncated Zip64 extra field.');
    const v = raw.readBigUInt64LE(off); off += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Zip64 entry value is too large.');
    return Number(v);
  };
  const take32 = () => {
    if (off + 4 > raw.length) throw new Error('Zip64 entry has a truncated Zip64 extra field.');
    const v = raw.readUInt32LE(off); off += 4;
    return v;
  };
  if (need.size) out.size = take64();
  if (need.compressedSize) out.compressedSize = take64();
  if (need.localOffset) out.localOffset = take64();
  if (need.diskStart) out.diskStart = take32();
  return out;
}

// Zip64 EOCD locator (20 bytes, immediately before the EOCD):
// signature, disk holding the Zip64 record, offset of the record,
// total disks. Returns the record's absolute file offset.
function parseZip64Locator(locBuf) {
  if (locBuf.length < 20 || locBuf.readUInt32LE(0) !== ZIP64_LOC_SIG) {
    throw new Error('Zip64 archive is missing its end-of-central-directory locator.');
  }
  const recOff = locBuf.readBigUInt64LE(8);
  if (recOff > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Zip64 archive end-of-central-directory offset is too large.');
  return Number(recOff);
}

// Zip64 EOCD record (fixed part 56 bytes): signature, record size
// (8), version made by (2), version needed (2), disk (4), CD start
// disk (4), entries on this disk (8), total entries (8), CD size
// (8), CD offset (8). Returns the real EOCD values.
function parseZip64Record(recBuf) {
  if (recBuf.length < 56 || recBuf.readUInt32LE(0) !== ZIP64_EOCD_SIG) {
    throw new Error('Zip64 archive has a corrupt end-of-central-directory record.');
  }
  const disk = recBuf.readUInt32LE(16);
  const cdDisk = recBuf.readUInt32LE(20);
  if (disk !== 0 || cdDisk !== 0) throw new Error('Multi-disk archives are not supported by the AES reader.');
  const total = recBuf.readBigUInt64LE(32);
  const cdSize = recBuf.readBigUInt64LE(40);
  const cdOffset = recBuf.readBigUInt64LE(48);
  for (const pair of [['entry count', total], ['central directory size', cdSize], ['central directory offset', cdOffset]]) {
    if (pair[1] > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Zip64 archive ' + pair[0] + ' is too large.');
  }
  return { count: Number(total), cdSize: Number(cdSize), cdOffset: Number(cdOffset) };
}

// Resolve the EOCD's count/size/offset when any of them is a Zip64
// sentinel. `readAt` reads `length` bytes at an absolute file
// offset (buffer slice or fd pread) — the locator sits immediately
// before the EOCD and the record at the offset it names.
function resolveZip64EOCD(eocd, readAt) {
  const count = eocd.count;
  const cdSize = eocd.cdSize;
  const cdOffset = eocd.cdOffset;
  if (count !== 0xFFFF && cdSize !== 0xFFFFFFFF && cdOffset !== 0xFFFFFFFF) {
    return { count: count, cdSize: cdSize, cdOffset: cdOffset };
  }
  const locBuf = readAt(eocd.eocdOff - 20, 20);
  const recOff = parseZip64Locator(locBuf);
  const recBuf = readAt(recOff, 56);
  return parseZip64Record(recBuf);
}

// Walk `count` central-directory entries starting at `startOff` in
// `buf` (which holds the central-directory bytes). Shared by the
// whole-buffer parser and the file-descriptor reader below.
function parseEntriesAt(buf, startOff, count) {
  const entries = [];
  let off = startOff;
  for (let i = 0; i < count; i++) {
    if (off + 46 > buf.length) throw new Error('Central directory is corrupt (truncated entry).');
    if (buf.readUInt32LE(off) !== CD_SIG) throw new Error('Central directory is corrupt.');
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const crc = buf.readUInt32LE(off + 16);
    let compressedSize = buf.readUInt32LE(off + 20);
    let uncompressedSize = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const diskStart = buf.readUInt16LE(off + 34);
    let localOffset = buf.readUInt32LE(off + 42);
    if (off + 46 + nameLen + extraLen + commentLen > buf.length) throw new Error('Central directory is corrupt (entry overruns the file).');
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    const extra = buf.subarray(off + 46 + nameLen, off + 46 + nameLen + extraLen);
    // Zip64 per-entry sentinels: a value of 0xFFFFFFFF means the real
    // value lives in the Zip64 extra field (0x0001) — read it there
    // instead of reporting a bogus 4 GB size.
    if (compressedSize === 0xFFFFFFFF || uncompressedSize === 0xFFFFFFFF || localOffset === 0xFFFFFFFF || diskStart === 0xFFFF) {
      const resolved = parseZip64Extra(extra, {
        size: uncompressedSize === 0xFFFFFFFF,
        compressedSize: compressedSize === 0xFFFFFFFF,
        localOffset: localOffset === 0xFFFFFFFF,
        diskStart: diskStart === 0xFFFF
      });
      if (resolved.size !== undefined) uncompressedSize = resolved.size;
      if (resolved.compressedSize !== undefined) compressedSize = resolved.compressedSize;
      if (resolved.localOffset !== undefined) localOffset = resolved.localOffset;
      if (resolved.diskStart !== undefined && resolved.diskStart !== 0) {
        throw new Error('Multi-disk archives are not supported by the AES reader.');
      }
    }
    if (diskStart !== 0 && diskStart !== 0xFFFF) {
      throw new Error('Multi-disk archives are not supported by the AES reader.');
    }
    const aes = parseExtra(extra, AES_EXTRA_ID);
    let aesStrength = 0; let realMethod = method; let aeVersion = 0;
    if (aes) {
      // A real WinZip AES extra field is 7 bytes: version (2), vendor
      // "AE" (2), strength (1), real method (2). An unknown strength
      // used to be silently treated as AES-256 and reported as
      // "Wrong password" — reject it here with the real reason.
      if (aes.length < 7 || aes.toString('ascii', 2, 4) !== 'AE') throw new Error('Unsupported encryption (bad AES extra field) in ' + name);
      aeVersion = aes.readUInt16LE(0);
      aesStrength = aes.readUInt8(4);
      realMethod = aes.readUInt16LE(5);
      if (aeVersion !== 1 && aeVersion !== 2) throw new Error('Unsupported WinZip AES version ' + aeVersion + ' in ' + name);
      if (aesStrength < 1 || aesStrength > 3) throw new Error('Unsupported WinZip AES strength ' + aesStrength + ' in ' + name);
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

function parseCentralDirectory(buf) {
  const eocd = findEOCD(buf);
  if (eocd < 0) throw new Error('Not a ZIP file (end-of-central-directory record not found).');
  const resolved = resolveZip64EOCD({
    count: buf.readUInt16LE(eocd + 10),
    cdSize: buf.readUInt32LE(eocd + 12),
    cdOffset: buf.readUInt32LE(eocd + 16),
    eocdOff: eocd
  }, function (offset, length) {
    if (offset < 0 || offset + length > buf.length) throw new Error('Zip64 end-of-central-directory record is out of bounds.');
    return buf.subarray(offset, offset + length);
  });
  const count = resolved.count;
  const cdSize = resolved.cdSize;
  const cdOffset = resolved.cdOffset;
  if (cdOffset + cdSize > buf.length) throw new Error('Central directory is corrupt (extends past the end of the file).');
  return parseEntriesAt(buf, cdOffset, count);
}

// Read only the central directory of a ZIP from disk: the last
// 64 KiB + 22 bytes (the EOCD search window) to locate the EOCD,
// then exactly the central-directory region. The file's data is
// never loaded — this is what keeps inspectZip bounded on multi-GB
// archives. Returns the full parsed entries (same objects as
// parseCentralDirectory).
function readEntries(zipPath) {
  const fd = fs.openSync(zipPath, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    if (size < 22) throw new Error('Not a ZIP file (end-of-central-directory record not found).');
    const tailLen = Math.min(size, 65557);
    const tail = readFully(fd, tailLen, size - tailLen);
    const eocdRel = findEOCD(tail);
    if (eocdRel < 0) throw new Error('Not a ZIP file (end-of-central-directory record not found).');
    const eocdAbs = size - tailLen + eocdRel;
    const resolved = resolveZip64EOCD({
      count: tail.readUInt16LE(eocdRel + 10),
      cdSize: tail.readUInt32LE(eocdRel + 12),
      cdOffset: tail.readUInt32LE(eocdRel + 16),
      eocdOff: eocdAbs
    }, function (offset, length) {
      if (offset < 0) throw new Error('Zip64 end-of-central-directory record is out of bounds.');
      return readFully(fd, length, offset);
    });
    const count = resolved.count;
    const cdSize = resolved.cdSize;
    const cdOffset = resolved.cdOffset;
    if (cdOffset + cdSize > size) throw new Error('Central directory is corrupt (extends past the end of the file).');
    const cdBuf = cdSize > 0 ? readFully(fd, cdSize, cdOffset) : Buffer.alloc(0);
    return parseEntriesAt(cdBuf, 0, count);
  } finally {
    fs.closeSync(fd);
  }
}

/** List entries + whether the archive is encrypted. Throws on bad ZIPs. */
function inspectZip(zipPath) {
  const entries = readEntries(zipPath);
  return {
    entries: entries.map(function (e) {
      return { name: e.name, isDir: e.isDir, size: e.size, method: e.realMethod,
               encrypted: e.encrypted, aesStrength: e.aesStrength,
               // Full entry fields, for the streaming decrypt path
               // (restoreFile reuses the inspected entry directly
               // instead of re-reading the archive).
               localOffset: e.localOffset, compressedSize: e.compressedSize,
               crc: e.crc, flags: e.flags, aeVersion: e.aeVersion,
               realMethod: e.realMethod };
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

// --- Streaming AES-CTR decryption ---
// WinZip AES uses AES-CTR with a LITTLE-endian 16-byte counter
// starting at 1. Node's built-in CTR mode increments the counter
// big-endian, so it cannot reproduce this counter — decrypt
// block-by-block with AES-ECB keystream blocks instead, in bounded
// chunks. `onCiphertext` (if given) is called with every raw
// ciphertext chunk exactly once, so the caller can feed the HMAC
// incrementally without buffering the ciphertext.
function createAesCtrDecryptStream(key, onCiphertext) {
  const ecb = crypto.createCipheriv('aes-' + (key.length * 8) + '-ecb', key, null);
  ecb.setAutoPadding(false);
  const counter = Buffer.alloc(16);
  counter[0] = 1;
  let leftover = Buffer.alloc(0); // carried partial block (< 16 bytes)
  // Encrypt `blockCount` successive counter values in one call, and
  // advance the counter past them.
  function keystream(blockCount) {
    const counters = Buffer.alloc(blockCount * 16);
    for (let b = 0; b < blockCount; b++) {
      counter.copy(counters, b * 16);
      let j = 0;
      while (j < 16) { counter[j]++; if (counter[j] !== 0) break; j++; }
    }
    return ecb.update(counters);
  }
  return new Transform({
    transform(chunk, encoding, callback) {
      try {
        if (typeof onCiphertext === 'function') onCiphertext(chunk);
        const data = leftover.length ? Buffer.concat([leftover, chunk]) : chunk;
        const fullLen = data.length - (data.length % 16);
        leftover = data.subarray(fullLen);
        if (fullLen === 0) return callback();
        const out = Buffer.alloc(fullLen);
        // Work in bounded sub-chunks so the keystream buffer stays
        // small (4096 blocks = 64 KiB of keystream at a time).
        const BLOCKS_PER_CHUNK = 4096;
        for (let off = 0; off < fullLen; off += BLOCKS_PER_CHUNK * 16) {
          const len = Math.min(BLOCKS_PER_CHUNK * 16, fullLen - off);
          const ks = keystream(len / 16);
          for (let i = 0; i < len; i++) out[off + i] = data[off + i] ^ ks[i];
        }
        callback(null, out);
      } catch (e) { callback(e); }
    },
    flush(callback) {
      try {
        if (leftover.length) {
          const ks = keystream(1);
          const out = Buffer.alloc(leftover.length);
          for (let i = 0; i < leftover.length; i++) out[i] = leftover[i] ^ ks[i];
          this.push(out);
        }
        callback();
      } catch (e) { callback(e); }
    }
  });
}

// Stream the SHA-256 of a file without loading it.
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const rs = fs.createReadStream(filePath);
    rs.on('error', reject);
    rs.on('data', (chunk) => hash.update(chunk));
    rs.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Stream-decrypt one entry to `tmpPath`. The plaintext is never held
 * in memory: ciphertext streams from the archive through the CTR
 * decryptor (and the inflater for deflated entries) into the file,
 * while the HMAC (over the ciphertext) and the AE-1 CRC (over the
 * plaintext) are computed incrementally. The HMAC and CRC are
 * compared only once the stream has finished — on mismatch the temp
 * file is deleted and the call rejects, so a tampered entry never
 * reaches the destination. Resolves { bytes, sha256 } (the SHA-256
 * of the plaintext written). Throws Error('Wrong password ...') on
 * a bad password, before any byte is written.
 */
async function decryptEntryToFile(zipPath, entry, password, tmpPath) {
  if (!entry.encrypted) throw new Error('Entry is not encrypted: ' + entry.name);
  if (!entry.aesStrength) throw new Error('Unsupported encryption (not WinZip AES): ' + entry.name);
  if (typeof password !== 'string' || !password) throw new Error('A password is required for this encrypted backup.');
  // inspectZip exposes the real method as `method`; full entries
  // carry it as `realMethod` — accept either shape.
  const realMethod = entry.realMethod !== undefined ? entry.realMethod : entry.method;
  if (realMethod !== 8 && realMethod !== 0) {
    throw new Error('Unsupported compression method ' + realMethod + ' in ' + entry.name);
  }
  const fd = fs.openSync(zipPath, 'r');
  try {
    const fileSize = fs.fstatSync(fd).size;
    // Local header: skip name + extra to reach the encrypted blob.
    if (entry.localOffset + 30 > fileSize) throw new Error('Local file header not found for ' + entry.name);
    const head = readFully(fd, 30, entry.localOffset);
    if (head.readUInt32LE(0) !== LFH_SIG) throw new Error('Local file header not found for ' + entry.name);
    const nameLen = head.readUInt16LE(26);
    const extraLen = head.readUInt16LE(28);
    const dataStart = entry.localOffset + 30 + nameLen + extraLen;
    const keyLen = aesKeyLength(entry.aesStrength);
    const saltLen = keyLen === 16 ? 8 : (keyLen === 24 ? 12 : 16);
    // A truncated entry used to be misreported as "Wrong password":
    // check the sizes first.
    if (dataStart + saltLen + 2 + 10 > dataStart + entry.compressedSize) throw new Error('Backup is corrupt (truncated entry ' + entry.name + ').');
    if (dataStart + entry.compressedSize > fileSize) throw new Error('Backup is corrupt (truncated entry ' + entry.name + ').');
    const saltVerify = readFully(fd, saltLen + 2, dataStart);
    const authCode = readFully(fd, 10, dataStart + entry.compressedSize - 10);
    const salt = saltVerify.subarray(0, saltLen);
    const verify = saltVerify.subarray(saltLen, saltLen + 2);
    const derived = crypto.pbkdf2Sync(password, salt, 1000, 2 * keyLen + 2, 'sha1');
    const aesKey = derived.subarray(0, keyLen);
    const macKey = derived.subarray(keyLen, 2 * keyLen);
    const expectedVerify = derived.subarray(2 * keyLen, 2 * keyLen + 2);
    if (!timingSafeEqual(expectedVerify, verify)) throw new Error('Wrong password for this encrypted backup.');
    const hmac = crypto.createHmac('sha1', macKey);
    const cipherStart = dataStart + saltLen + 2;
    const cipherEnd = dataStart + entry.compressedSize - 10; // exclusive
    const decrypt = createAesCtrDecryptStream(aesKey, (chunk) => hmac.update(chunk));
    const ws = fs.createWriteStream(tmpPath);
    let crc = 0;
    let bytes = 0;
    const plainHash = crypto.createHash('sha256');
    const tee = new Transform({
      transform(chunk, encoding, callback) {
        crc = crc32(chunk, crc);
        bytes += chunk.length;
        plainHash.update(chunk);
        callback(null, chunk);
      }
    });
    // An empty entry has no ciphertext bytes: stream from an empty
    // source instead of a file range (createReadStream with
    // end < start reads nothing, but only by accident — be explicit).
    const { Readable } = require('stream');
    const src = cipherEnd > cipherStart
      ? fs.createReadStream(zipPath, { start: cipherStart, end: cipherEnd - 1, highWaterMark: DECRYPT_CHUNK })
      : Readable.from([]);
    try {
      if (realMethod === 8) {
        await pipeline(src, decrypt, zlib.createInflateRaw(), tee, ws);
      } else {
        await pipeline(src, decrypt, tee, ws);
      }
    } catch (e) {
      try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e2) {}
      throw e;
    }
    // The HMAC covers the ciphertext and can only be checked once
    // every byte has streamed past; same for the AE-1 CRC over the
    // plaintext. A failure here deletes the temp file — the
    // destination is never touched.
    const auth = hmac.digest().subarray(0, 10);
    if (!timingSafeEqual(auth, authCode)) {
      try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
      throw new Error('Backup is corrupt (authentication failed for ' + entry.name + ').');
    }
    // AE-1 stores a real CRC; AE-2 stores 0 and relies on the auth code.
    if (entry.aeVersion === 1 && entry.crc !== 0 && crc !== entry.crc) {
      try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
      throw new Error('Backup is corrupt (CRC mismatch for ' + entry.name + ').');
    }
    return { bytes: bytes, sha256: plainHash.digest('hex') };
  } finally {
    fs.closeSync(fd);
  }
}

/** Decrypt + inflate one entry. Throws Error('Wrong password ...') on a bad password. */
function decryptEntry(zipPath, entry, password, zipBuf) {
  if (!entry.encrypted) throw new Error('Entry is not encrypted: ' + entry.name);
  if (!entry.aesStrength) throw new Error('Unsupported encryption (not WinZip AES): ' + entry.name);
  if (typeof password !== 'string' || !password) throw new Error('A password is required for this encrypted backup.');
  // Callers that already hold the whole ZIP pass it in (extractEncrypted
  // reads it once); otherwise read it here. Re-reading the whole file
  // per entry used to make restores O(entries x archive-size) I/O.
  const buf = zipBuf || fs.readFileSync(zipPath);
  // Local header: skip name + extra to reach the encrypted blob.
  if (entry.localOffset + 30 > buf.length || buf.readUInt32LE(entry.localOffset) !== LFH_SIG) throw new Error('Local file header not found for ' + entry.name);
  const nameLen = buf.readUInt16LE(entry.localOffset + 26);
  const extraLen = buf.readUInt16LE(entry.localOffset + 28);
  const dataStart = entry.localOffset + 30 + nameLen + extraLen;
  const keyLen = aesKeyLength(entry.aesStrength);
  const saltLen = keyLen === 16 ? 8 : (keyLen === 24 ? 12 : 16);
  // A truncated entry used to be misreported as "Wrong password":
  // the slices below clamp silently, so check the sizes first.
  if (dataStart + saltLen + 2 + 10 > dataStart + entry.compressedSize) throw new Error('Backup is corrupt (truncated entry ' + entry.name + ').');
  if (dataStart + entry.compressedSize > buf.length) throw new Error('Backup is corrupt (truncated entry ' + entry.name + ').');
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
  if (!timingSafeEqual(expectedVerify, verify)) throw new Error('Wrong password for this encrypted backup.');
  const hmac = crypto.createHmac('sha1', macKey).update(ciphertext).digest().subarray(0, 10);
  if (!timingSafeEqual(hmac, authCode)) throw new Error('Backup is corrupt (authentication failed for ' + entry.name + ').');
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
async function extractEncrypted(zipPath, destDir, password, onFile, options) {
  // Overwrite OFF (default): an existing destination file is skipped,
  // never replaced. The entry is still decrypted and hash-verified
  // first, so a wrong password or corrupt entry is reported instead
  // of silently skipping — only the final rename is withheld.
  const overwrite = !!(options && options.overwrite);
  // Chain restores share one written-set (see restore.js): a later
  // artifact must overwrite files this chain wrote, while files that
  // existed before the restore are still skipped.
  const chainWritten = (options && options.chainWritten) || null;
  const entries = readEntries(zipPath);
  const base = path.resolve(destDir);
  if (!fs.existsSync(base)) fs.mkdirSync(base, { recursive: true });
  const realBase = fs.realpathSync(base);
  let files = 0; let bytes = 0; const errors = [];
  let skipped = 0; const skipped_files = [];
  for (const entry of entries) {
    if (entry.isDir) continue;
    // Zip-slip guard: entry names must stay inside destDir. (The
    // lexical check below uses the resolved base; the realpath check
    // after mkdir catches a pre-existing symlink inside it.)
    const dest = path.join(base, entry.name.split('/').join(path.sep));
    if (dest !== base && !dest.startsWith(base + path.sep)) {
      errors.push('Skipped unsafe path: ' + entry.name);
      continue;
    }
    try {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const realParent = fs.realpathSync(path.dirname(dest));
      if (realParent !== realBase && !realParent.startsWith(realBase + path.sep)) {
        errors.push('Skipped unsafe path: ' + entry.name);
        continue;
      }
      const realDest = path.join(realParent, path.basename(dest));
      // Write-then-rename: a failed verification must not destroy a
      // good file already at the destination (the old code wrote
      // straight to it and deleted it on mismatch). The decrypt
      // streams straight into the temp file — no whole-entry buffer.
      const tmpDest = realDest + '.tvtmp-' + process.pid + '-' + (++tmpCounter);
      const out = await decryptEntryToFile(zipPath, entry, password, tmpDest);
      // Verify the write: stream-hash the temp file and compare with
      // the hash of the plaintext the decrypt stream produced
      // (catches a bad disk write). On mismatch, delete the TEMP
      // file and record the error.
      let ok = false;
      try {
        ok = (await hashFile(tmpDest)) === out.sha256;
      } catch (e) { ok = false; }
      if (!ok) {
        try { fs.unlinkSync(tmpDest); } catch (e) {}
        errors.push(entry.name + ': written file failed verification');
        continue;
      }
      // Only an existing regular FILE is skipped — a directory at the
      // destination path (zip holding both `a` and `a/b.txt`) must
      // fail on the rename and be reported, not vanish as "skipped".
      // A file this chain restore wrote itself is NOT skipped: the
      // newer artifact's version must replace it.
      let destIsFile = false;
      try { destIsFile = fs.statSync(realDest).isFile(); } catch (e) { destIsFile = false; }
      if (!overwrite && destIsFile && !(chainWritten && chainWritten.has(path.resolve(realDest)))) {
        // Verified but the destination already exists: leave the
        // good file alone, drop the temp copy, count the skip.
        try { fs.unlinkSync(tmpDest); } catch (e) {}
        skipped++;
        skipped_files.push(entry.name);
        continue;
      }
      fs.renameSync(tmpDest, realDest);
      if (chainWritten) chainWritten.add(path.resolve(realDest));
      files++; bytes += out.bytes;
      if (typeof onFile === 'function') onFile(entry.name, out.bytes);
    } catch (e) {
      errors.push(entry.name + ': ' + e.message);
      if (e.message.indexOf('Wrong password') === 0) throw e; // one wrong password fails the whole restore
    }
  }
  return { files: files, bytes: bytes, errors: errors, skipped: skipped, skipped_files: skipped_files };
}

module.exports = { inspectZip, decryptEntry, decryptEntryToFile, extractEncrypted, parseCentralDirectory, crc32 };
