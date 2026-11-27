/**
 * TechVision Backup — TVB container (TechVision-only encrypted backups).
 *
 * A backup made with a password is a .tvb file. NO outside program
 * can open it: it is not a ZIP, not WinZip AES, not anything standard.
 * Only this program, with the right password, can restore it.
 *
 * Format (all integers little-endian, all offsets absolute):
 *   Header (28 bytes):
 *     magic 'TVB1' (4), version u16 = 2, flags u16 (bit 0 = encrypted,
 *     bit 1 = layered: the single entry is a whole ZIP — see below)
 *     salt (16 bytes, scrypt salt), reserved u32 = 0.
 *   Entries (data only, in the order they were written):
 *     ciphertext || GCM tag (16 bytes). Plaintext = the file's bytes,
 *     deflated first when the job compresses, stored raw otherwise.
 *   Index (after the last entry):
 *     entryCount u32, then one record per entry:
 *       nameLen u16, name (UTF-8, '/' separators),
 *       originalSize u64, storedSize u64 (ciphertext + tag),
 *       dataOffset u64, mtimeMs u64, method u8 (0 = stored, 1 = deflate),
 *       iv (12 bytes), sha256 (32 bytes, of the ORIGINAL content).
 *   Trailer (48 bytes):
 *     indexOffset u64, indexLen u32, indexTag (32 bytes), magic 'TVBX' (4).
 *
 * Version 2 authenticates the index: indexTag is HMAC-SHA256 over
 * (indexOffset || indexLen || index bytes) under a domain-separated
 * key derived from the backup key, so renaming, removing, reordering
 * or altering any index entry is detected before any restore uses
 * it. Names stay readable without a password (like a ZIP central
 * directory); inspectTvb verifies the tag whenever a password is
 * given, and the restore paths always give it. Version 1 files
 * (unauthenticated index, 16-byte trailer) are rejected as
 * unsupported — no old .tvb is silently trusted.
 *
 * Layered backups (both passwords): when a job ALSO has a ZIP
 * password, the backup is a password-protected ZIP (WinZip AES)
 * encrypted inside the .tvb as a SINGLE entry named 'archive.zip'
 * (TVB_LAYERED_ENTRY), stored uncompressed — the ZIP is already
 * compressed and encrypted. The header flag bit 1 (TVB_FLAG_LAYERED)
 * marks it, so a restore can tell a layered .tvb from a per-file
 * .tvb that happens to hold one file of that name. The .tvb layer
 * is still streamed (the archiver output feeds addFile as a stream,
 * never a temp file) and the index is still authenticated the same
 * way. Restore: the encryption password decrypts the .tvb, the
 * inner ZIP is then restored with the ZIP password (see restore.js).
 *
 * The key is scrypt(password, salt, N=16384, r=8, p=1, 32 bytes) —
 * the same parameters as the vault. Every entry gets its own random
 * 12-byte IV and its own AES-256-GCM tag, so a wrong password fails
 * on the first entry and a flipped byte anywhere fails that entry
 * (the GCM tag), never silently. The per-entry SHA-256 of the
 * original content is a second check after decrypt + decompress.
 *
 * The layout mirrors a ZIP (data first, index at the end) so the
 * writer streams in one pass with bounded memory: no temp files, no
 * buffering a whole file. A truncated file has no valid trailer, so
 * it fails at inspect time with "corrupt or truncated" — never with
 * "wrong password".
 *
 * Nothing here is a home-made cipher: AES-256-GCM + scrypt from Node
 * crypto, and zlib deflate for compression. What is proprietary is
 * only the container around them.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { pipeline } = require('stream/promises');
const { Transform } = require('stream');

const TVB_MAGIC = Buffer.from('TVB1', 'ascii');
const TVB_TRAILER_MAGIC = Buffer.from('TVBX', 'ascii');
const TVB_VERSION = 2;
const TVB_FLAG_ENCRYPTED = 0x0001;
const TVB_FLAG_LAYERED = 0x0002; // single entry is a whole ZIP (see the doc comment)
const TVB_LAYERED_ENTRY = 'archive.zip'; // the inner ZIP's name inside a layered .tvb
const TVB_HEADER_SIZE = 28; // magic(4) + version(2) + flags(2) + salt(16) + reserved(4)
const TVB_TRAILER_SIZE = 48; // indexOffset(8) + indexLen(4) + indexTag HMAC-SHA256(32) + magic(4)
const TVB_INDEX_TAG_LEN = 32;
const TVB_TAG_LEN = 16;
const TVB_IV_LEN = 12;
const TVB_SALT_LEN = 16;
const TVB_SHA_LEN = 32;
const TVB_SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function deriveTvbKey(password, salt) {
  return crypto.scryptSync(password, salt, 32, TVB_SCRYPT_OPTS);
}

// Read exactly `length` bytes from `fd` at `position` (loops over
// short reads); throws when the file ends first.
function readFully(fd, buf, length, position) {
  let got = 0;
  while (got < length) {
    const n = fs.readSync(fd, buf, got, length - got, position + got);
    if (n === 0) throw new Error('Backup file is corrupt or truncated (unexpected end of file).');
    got += n;
  }
}

// Write a buffer to a stream, resolving when it is flushed.
function writeToStream(stream, buf) {
  return new Promise((resolve, reject) => {
    stream.write(buf, (err) => { if (err) reject(err); else resolve(); });
  });
}

function authError(message) {
  const e = new Error(message);
  e.code = 'TVB_AUTH_FAILED';
  return e;
}

// Cancellation: a recognizable condition the engine already treats
// as "stopped by user" (result.cancelled, partial artifact deleted).
function cancelledError() {
  const e = new Error('Backup stopped by user');
  e.code = 'BACKUP_CANCELLED';
  return e;
}

// Index authentication (v2): HMAC-SHA256 over (indexOffset ||
// indexLen || index bytes) under a domain-separated key — the entry
// cipher key must never double as the MAC key.
function indexMacKey(key) {
  return crypto.createHmac('sha256', key).update('tvb-index-auth-v2').digest();
}
function indexTag(key, indexOffset, indexLen, indexBuf) {
  const h = crypto.createHmac('sha256', indexMacKey(key));
  const head = Buffer.alloc(12);
  head.writeBigUInt64LE(BigInt(indexOffset), 0);
  head.writeUInt32LE(indexLen, 8);
  h.update(head);
  h.update(indexBuf);
  return h.digest();
}

/**
 * Writer: streams one .tvb file. One entry per file, in the order
 * addFile is called; finish() writes the index + trailer and closes.
 *
 * Failure contract (the engine relies on this):
 * - A SOURCE error (file unreadable mid-read) fails ONE file: the
 *   bytes already streamed for that entry are accounted for in the
 *   file offset, the partial entry is never indexed, and the
 *   container stays valid for the entries that did complete.
 * - An OUTPUT error (disk full, dead drive) fails the WHOLE run:
 *   addFile/finish throw with code 'TVB_OUTPUT_FAILED' and the
 *   engine rethrows it past the per-file handler.
 */
class TvbWriter {
  constructor(outPath, password, compression, options) {
    if (!password) throw new Error('Encryption is on but no password was provided for this job.');
    this.outPath = outPath;
    this.compress = compression !== 'none';
    this.level = compression === 'advanced' ? 9 : 6;
    // Layered backup (both passwords): the .tvb holds ONE entry —
    // a whole password-protected ZIP streamed in as a source stream
    // (see addFile). The flag marks it so a restore never mistakes
    // a per-file .tvb of one file called 'archive.zip' for a
    // layered one.
    this._layered = !!(options && options.layered);
    this.salt = crypto.randomBytes(TVB_SALT_LEN);
    this.key = deriveTvbKey(password, this.salt);
    this.output = fs.createWriteStream(outPath);
    this._outputError = null;
    this.output.on('error', (e) => { if (!this._outputError) this._outputError = e; });
    this.entries = [];
    this.position = 0; // logical bytes handed to the output stream
    this._currentStored = 0; // ciphertext bytes streamed for the entry in progress
    this._active = null; // streams of the entry in progress (for destroy)
    this._destroyed = false;
    // Settles the moment destroy() runs: every await in this writer
    // races against it, so a stop can never leave a promise pending
    // (a destroyed stream emits 'close', not 'error'/'end' — the
    // waits below used to listen for those only, and a stop
    // mid-file hung the run forever).
    this._destroyResolve = null;
    this._destroyedPromise = new Promise((resolve) => { this._destroyResolve = resolve; });
    this._headerWritten = false;
  }

  // Write a buffer to the output, resolving when it is flushed —
  // and rejecting with the cancel error if the writer is destroyed
  // while the write is in flight (a destroyed stream's write
  // callback alone is not a reliable settler).
  _write(buf) {
    if (this._destroyed) return Promise.reject(cancelledError());
    return new Promise((resolve, reject) => {
      let settled = false;
      this._destroyedPromise.then(() => {
        if (!settled) { settled = true; reject(cancelledError()); }
      });
      this.output.write(buf, (err) => {
        if (settled) return;
        settled = true;
        if (err) reject(err); else resolve();
      });
    });
  }

  async _writeHeader() {
    if (this._headerWritten) return;
    const header = Buffer.alloc(TVB_HEADER_SIZE);
    TVB_MAGIC.copy(header, 0);
    header.writeUInt16LE(TVB_VERSION, 4);
    header.writeUInt16LE(TVB_FLAG_ENCRYPTED | (this._layered ? TVB_FLAG_LAYERED : 0), 6);
    this.salt.copy(header, 8);
    header.writeUInt32LE(0, 24);
    await this._write(header);
    this.position += TVB_HEADER_SIZE;
    this._headerWritten = true;
  }

  /**
   * Add one file. `onBytes(n)` reports original bytes read (progress).
   * `filePath` is normally a file path; for a layered backup it is a
   * readable stream (the archiver output) and `stats` is null — the
   * entry size then comes from the bytes actually read (bytesIn),
   * and mtime is 0. Resolves { hash, size } — the SHA-256 of the
   * ORIGINAL bytes and the original size, for the engine's backup
   * state. Throws on a source error (one failed file) or
   * TVB_OUTPUT_FAILED (whole run).
   */
  async addFile(name, filePath, stats, onBytes) {
    await this._writeHeader();
    if (this._destroyed) throw cancelledError();
    if (this._outputError) throw outputFailed(this._outputError);
    const method = this.compress ? 1 : 0;
    const iv = crypto.randomBytes(TVB_IV_LEN);
    const dataOffset = this.position;
    const hash = crypto.createHash('sha256');
    const hashState = { hash: null };
    let bytesIn = 0;
    this._currentStored = 0;
    const tee = new Transform({
      transform(chunk, encoding, callback) {
        hash.update(chunk);
        bytesIn += chunk.length;
        if (typeof onBytes === 'function') { try { onBytes(chunk.length); } catch (e) {} }
        callback(null, chunk);
      },
      flush(callback) { hashState.hash = hash.digest('hex'); callback(); }
    });
    const countOut = new Transform({
      transform(chunk, encoding, callback) {
        // Bytes handed to the output stream for this entry
        // (ciphertext). Read by addFile after the pipeline ends, and
        // by its catch when a file fails mid-stream.
        this._stored = (this._stored || 0) + chunk.length;
        callback(null, chunk);
      }
    });
    countOut._stored = 0;
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    // Layered case: the source is a readable stream (the archiver),
    // not a path. The gate below works the same on either — a stream
    // emits readable/error/end/close just like a file stream.
    const rs = (filePath && typeof filePath === 'object' && typeof filePath.pipe === 'function')
      ? filePath
      : fs.createReadStream(filePath);
    const deflate = this.compress ? zlib.createDeflate({ level: this.level }) : null;
    this._active = { rs: rs, tee: tee, deflate: deflate, cipher: cipher, countOut: countOut };
    try {
      // Gate: wait until the stream has its first chunk (or EOF)
      // BEFORE piping it anywhere. A file that fails to open at all
      // is then one failed file, not a stalled pipeline.
      let gateError = null;
      const onGateError = (err) => { if (!gateError) gateError = err; };
      rs.on('error', onGateError);
      // 'close' is the backstop: a destroyed stream emits 'close',
      // not 'readable'/'error'/'end', so without it a stop during
      // the gate would hang this await forever.
      await new Promise((resolve) => {
        rs.once('readable', resolve);
        rs.once('error', resolve);
        rs.once('end', resolve);
        rs.once('close', resolve);
      });
      rs.removeListener('error', onGateError);
      if (this._destroyed) throw cancelledError();
      if (gateError) throw gateError;
      // Pipe the chain into the shared output stream (never ending
      // it — the writer owns it until finish()). This is a manual
      // pipe, not stream.pipeline: pipeline() adds per-call
      // listeners to the destination and only removes them when the
      // destination ends, so a shared output would accumulate one
      // set per file (2000 files = thousands of listeners and a
      // MaxListeners warning). Here every per-file listener is
      // removed in `done` below, and the chain is torn down on
      // error — on success the finished stages are left alone (the
      // readable side may still hold bytes the output has not
      // drained yet; destroying them would lose data).
      // Completion is countOut's readable 'end' — NOT its writable
      // 'finish': 'finish' can fire while the readable buffer still
      // holds bytes the output has not drained, and the tag written
      // right after would land in the middle of the ciphertext.
      // 'end' fires only once every byte has flowed into the output.
      const stages = deflate ? [rs, tee, deflate, cipher, countOut] : [rs, tee, cipher, countOut];
      for (let i = 0; i < stages.length - 1; i++) stages[i].pipe(stages[i + 1]);
      stages[stages.length - 1].pipe(this.output, { end: false });
      await new Promise((resolve, reject) => {
        let settled = false;
        const cleanup = () => {
          for (const s of stages) { s.removeListener('error', onErr); s.removeListener('close', onClosed); }
          this.output.removeListener('error', onErr);
          this.output.removeListener('close', onClosed);
          countOut.removeListener('end', onDrained);
        };
        const done = (err) => {
          if (settled) return;
          settled = true;
          cleanup();
          if (err) {
            // A broken chain must stop flowing into the output.
            for (const s of stages) { try { s.destroy(); } catch (e) {} }
            reject(err);
          } else resolve();
        };
        const onErr = (err) => done(err);
        const onDrained = () => done(null);
        // 'close' settles a stop: destroy() tears the stages down
        // without an error, so 'error'/'end' alone never fire. The
        // _destroyed guard keeps normal closes (a stage ending and
        // auto-destroying while bytes are still flowing downstream)
        // from ending the wait early — 'end' always settles first.
        const onClosed = () => { if (this._destroyed) done(cancelledError()); };
        for (const s of stages) { s.on('error', onErr); s.on('close', onClosed); }
        this.output.on('error', onErr);
        this.output.on('close', onClosed);
        countOut.on('end', onDrained);
      });
      this._currentStored = countOut._stored;
      // The GCM tag goes right after the ciphertext, inside the entry.
      const tag = cipher.getAuthTag();
      await this._write(tag);
      this.position += this._currentStored + TVB_TAG_LEN;
      const storedSize = this._currentStored + TVB_TAG_LEN;
      this._currentStored = 0;
      this.entries.push({
        name: name,
        size: stats ? stats.size : bytesIn,
        storedSize: storedSize,
        dataOffset: dataOffset,
        mtimeMs: stats ? stats.mtimeMs : 0,
        method: method,
        iv: iv,
        sha256: hashState.hash
      });
      this._active = null;
      return { hash: hashState.hash, size: stats ? stats.size : bytesIn };
    } catch (e) {
      // Bytes already streamed for this entry stay in the file as an
      // unreachable gap (the entry is never indexed): account for
      // them so the NEXT entry's offset is still correct. The count
      // lives on the countOut transform — _currentStored is only set
      // on the success path, so it is still 0 here.
      this.position += (countOut && countOut._stored) || 0;
      this._currentStored = 0;
      this._active = null;
      if (this._destroyed) throw cancelledError();
      if (this._outputError) throw outputFailed(this._outputError);
      throw e;
    }
  }

  async finish() {
    if (this._destroyed) throw cancelledError();
    if (this._outputError) throw outputFailed(this._outputError);
    await this._writeHeader();
    const indexOffset = this.position;
    const index = buildIndexBuffer(this.entries);
    // Authenticate the whole index before it is written: a later
    // rename/remove/reorder of any entry must fail verification.
    const tag = indexTag(this.key, indexOffset, index.length, index);
    await this._write(index);
    const trailer = Buffer.alloc(TVB_TRAILER_SIZE);
    trailer.writeBigUInt64LE(BigInt(indexOffset), 0);
    trailer.writeUInt32LE(index.length, 8);
    tag.copy(trailer, 12);
    TVB_TRAILER_MAGIC.copy(trailer, 12 + TVB_INDEX_TAG_LEN);
    await this._write(trailer);
    // A stop during finalization must settle too: race the end
    // against the destroy signal (the .catch() swallows the late
    // rejection when the end wins and destroy comes later).
    const onDestroy = this._destroyedPromise.then(() => { throw cancelledError(); });
    onDestroy.catch(() => {});
    await Promise.race([
      new Promise((resolve, reject) => {
        this.output.end((err) => { if (err) reject(err); else resolve(); });
      }),
      onDestroy
    ]);
    if (this._outputError) throw outputFailed(this._outputError);
  }

  // Stop support: tear down the live streams so a stop lands
  // promptly. The engine deletes the partial .tvb afterwards.
  // The stages are destroyed WITHOUT an error on purpose: destroying
  // with an error would emit 'error' on a stage whose listeners the
  // completion promise already removed (the tag-write window after
  // it settles) — an unhandled 'error' event that crashes the
  // process. A plain destroy emits 'close', which every wait in
  // this writer listens for (gate, completion, _write race), so the
  // stop still settles everywhere with the cancel error.
  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    if (this._destroyResolve) { try { this._destroyResolve(); } catch (e) {} }
    const a = this._active;
    this._active = null;
    try { if (a && a.rs) a.rs.destroy(); } catch (e) {}
    try { if (a && a.tee) a.tee.destroy(); } catch (e) {}
    try { if (a && a.deflate) a.deflate.destroy(); } catch (e) {}
    try { if (a && a.cipher) a.cipher.destroy(); } catch (e) {}
    try { if (a && a.countOut) a.countOut.destroy(); } catch (e) {}
    try { if (this.output) this.output.destroy(); } catch (e) {}
  }
}

function outputFailed(cause) {
  const e = new Error('Cannot write the backup file: ' + (cause && cause.message ? cause.message : String(cause)));
  e.code = 'TVB_OUTPUT_FAILED';
  return e;
}

function buildIndexBuffer(entries) {
  let size = 4;
  const names = entries.map((e) => Buffer.from(e.name, 'utf8'));
  for (let i = 0; i < entries.length; i++) size += 2 + names[i].length + 8 + 8 + 8 + 8 + 1 + TVB_IV_LEN + TVB_SHA_LEN;
  const buf = Buffer.alloc(size);
  let off = 0;
  buf.writeUInt32LE(entries.length, off); off += 4;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    buf.writeUInt16LE(names[i].length, off); off += 2;
    names[i].copy(buf, off); off += names[i].length;
    buf.writeBigUInt64LE(BigInt(e.size), off); off += 8;
    buf.writeBigUInt64LE(BigInt(e.storedSize), off); off += 8;
    buf.writeBigUInt64LE(BigInt(e.dataOffset), off); off += 8;
    buf.writeBigUInt64LE(BigInt(Math.round(e.mtimeMs || 0)), off); off += 8;
    buf[off] = e.method; off += 1;
    Buffer.from(e.iv).copy(buf, off); off += TVB_IV_LEN;
    Buffer.from(e.sha256, 'hex').copy(buf, off); off += TVB_SHA_LEN;
  }
  return buf;
}

/**
 * Read a .tvb file's header + index. No password needed (names and
 * sizes are metadata, like a ZIP central directory); the CONTENT is
 * what is encrypted. Throws on a file that is not a .tvb, an
 * unsupported version, or a corrupt/truncated index — never with
 * "wrong password".
 * With a password, the index tag is verified FIRST: a renamed,
 * removed, reordered or otherwise altered index entry is rejected
 * here, before any restore trusts it. A wrong password and a
 * tampered index fail the same way ("Wrong password or the backup
 * file is damaged") — the two cannot be told apart by design, and
 * neither reveals which it was.
 * Returns { encrypted: true, version, salt, entries, indexVerified }
 * where each entry is { name, size, storedSize, dataOffset, mtimeMs,
 * method, iv (Buffer), sha256 (hex) }.
 */
function inspectTvb(filePath, password) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const fileSize = fs.fstatSync(fd).size;
    if (fileSize < TVB_HEADER_SIZE + TVB_TRAILER_SIZE) {
      throw new Error('Not a TechVision backup file (too small).');
    }
    const header = Buffer.alloc(TVB_HEADER_SIZE);
    readFully(fd, header, TVB_HEADER_SIZE, 0);
    if (!header.subarray(0, 4).equals(TVB_MAGIC)) {
      throw new Error('Not a TechVision backup file (bad header).');
    }
    const version = header.readUInt16LE(4);
    if (version !== TVB_VERSION) {
      throw new Error('Unsupported TechVision backup version: ' + version + '.');
    }
    const flags = header.readUInt16LE(6);
    if ((flags & TVB_FLAG_ENCRYPTED) === 0) {
      throw new Error('TechVision backup is not encrypted.');
    }
    const salt = Buffer.from(header.subarray(8, 24));
    const trailer = Buffer.alloc(TVB_TRAILER_SIZE);
    readFully(fd, trailer, TVB_TRAILER_SIZE, fileSize - TVB_TRAILER_SIZE);
    if (!trailer.subarray(12 + TVB_INDEX_TAG_LEN, TVB_TRAILER_SIZE).equals(TVB_TRAILER_MAGIC)) {
      throw new Error('Backup file is corrupt or truncated (missing index).');
    }
    const indexOffset = Number(trailer.readBigUInt64LE(0));
    const indexLen = trailer.readUInt32LE(8);
    if (indexOffset < TVB_HEADER_SIZE || indexLen < 4 || indexOffset + indexLen > fileSize - TVB_TRAILER_SIZE) {
      throw new Error('Backup file is corrupt or truncated (bad index).');
    }
    const indexBuf = Buffer.alloc(indexLen);
    readFully(fd, indexBuf, indexLen, indexOffset);
    if (password) {
      // The tag covers the complete index (and its position/length):
      // any rename, removal, reorder or altered field fails here.
      // Without a password the index is display-only — the restore
      // paths always pass one, so unverified entries are never used
      // to write files.
      const key = deriveTvbKey(password, salt);
      const expected = indexTag(key, indexOffset, indexLen, indexBuf);
      const stored = Buffer.from(trailer.subarray(12, 12 + TVB_INDEX_TAG_LEN));
      if (!crypto.timingSafeEqual(expected, stored)) {
        throw authError('Wrong password or the backup file is damaged.');
      }
    }
    let off = 0;
    const count = indexBuf.readUInt32LE(off); off += 4;
    const entries = [];
    for (let i = 0; i < count; i++) {
      if (off + 2 > indexBuf.length) throw new Error('Backup file is corrupt or truncated (bad index).');
      const nameLen = indexBuf.readUInt16LE(off); off += 2;
      if (off + nameLen + 8 + 8 + 8 + 8 + 1 + TVB_IV_LEN + TVB_SHA_LEN > indexBuf.length) {
        throw new Error('Backup file is corrupt or truncated (bad index).');
      }
      const name = indexBuf.subarray(off, off + nameLen).toString('utf8'); off += nameLen;
      const originalSize = Number(indexBuf.readBigUInt64LE(off)); off += 8;
      const storedSize = Number(indexBuf.readBigUInt64LE(off)); off += 8;
      const dataOffset = Number(indexBuf.readBigUInt64LE(off)); off += 8;
      const mtimeMs = Number(indexBuf.readBigUInt64LE(off)); off += 8;
      const method = indexBuf[off]; off += 1;
      const iv = Buffer.from(indexBuf.subarray(off, off + TVB_IV_LEN)); off += TVB_IV_LEN;
      const sha256 = Buffer.from(indexBuf.subarray(off, off + TVB_SHA_LEN)).toString('hex'); off += TVB_SHA_LEN;
      if (method !== 0 && method !== 1) throw new Error('Backup file is corrupt or truncated (bad entry).');
      if (storedSize < TVB_TAG_LEN || dataOffset < TVB_HEADER_SIZE || dataOffset + storedSize > indexOffset) {
        throw new Error('Backup file is corrupt or truncated (entry out of range).');
      }
      entries.push({ name: name, size: originalSize, storedSize: storedSize, dataOffset: dataOffset, mtimeMs: mtimeMs, method: method, iv: iv, sha256: sha256 });
    }
    if (off !== indexBuf.length) throw new Error('Backup file is corrupt or truncated (bad index).');
    // A layered .tvb's single entry is a whole ZIP, not a file —
    // the restore needs to know before it treats archive.zip as a
    // file to extract. The flag is part of the header (not the
    // index), so it is covered by the index tag only indirectly —
    // but a flipped flag is harmless either way: with the flag
    // cleared the inner ZIP restores as a plain file (the user gets
    // archive.zip, still decryptable with the same password), and
    // with the flag set on a per-file .tvb the restore fails
    // cleanly because the entry is not a ZIP.
    return { encrypted: true, version: version, salt: salt, entries: entries, indexVerified: !!password, layered: (flags & TVB_FLAG_LAYERED) !== 0 };
  } finally {
    fs.closeSync(fd);
  }
}

// Transform that holds back the last TVB_TAG_LEN bytes of a stream
// (the GCM tag) and pushes everything else: the decipher must get
// the tag via setAuthTag before final(), and the tag only arrives at
// the very end of the ciphertext.
class TagSplit extends Transform {
  constructor() {
    super();
    this.tail = Buffer.alloc(0);
    this.tag = null;
  }
  _transform(chunk, encoding, callback) {
    const buf = Buffer.concat([this.tail, chunk]);
    if (buf.length <= TVB_TAG_LEN) { this.tail = buf; callback(); return; }
    this.push(buf.subarray(0, buf.length - TVB_TAG_LEN));
    this.tail = Buffer.from(buf.subarray(buf.length - TVB_TAG_LEN));
    callback();
  }
  _flush(callback) { this.tag = this.tail; callback(); }
}

// Decrypt ONE entry from an already-open fd to a write stream,
// verifying the SHA-256 of the restored bytes. `key` is the derived
// key for this backup. Throws TVB_AUTH_FAILED when the GCM tag does
// not verify (wrong password, or bytes tampered with after creation)
// and a plain Error on a hash/size mismatch or a short read.
async function decryptEntryStream(fd, entry, key, ws) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, entry.iv);
  const rs = fs.createReadStream(null, { fd: fd, start: entry.dataOffset, end: entry.dataOffset + entry.storedSize - 1, autoClose: false });
  const tagSplit = new TagSplit();
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  const hashTee = new Transform({
    transform(chunk, encoding, callback) {
      hash.update(chunk);
      bytes += chunk.length;
      callback(null, chunk);
    }
  });
  const stages = entry.method === 1
    ? [rs, tagSplit, decipher, zlib.createInflate(), hashTee, ws]
    : [rs, tagSplit, decipher, hashTee, ws];
  // The tag is only known once the whole ciphertext has flowed: set
  // it on the decipher when the split flushes, before the decipher
  // finalises. The decipher is a Transform, so its own flush runs
  // after the tag is set — a wrong tag fails there, not earlier.
  const origFlush = decipher._flush.bind(decipher);
  decipher._flush = function (callback) {
    try { decipher.setAuthTag(tagSplit.tag); } catch (e) { callback(e); return; }
    origFlush(callback);
  };
  try {
    await pipeline(stages);
  } catch (e) {
    // A tampered ciphertext fails the GCM tag at the end — but for a
    // COMPRESSED entry the inflate step sees the garbage plaintext
    // first and throws a zlib error instead. Either way the entry
    // cannot be trusted: both mean "wrong password or tampered".
    // (A valid tag with a corrupt deflate stream cannot happen —
    // the writer only ever stores zlib output.)
    if (e && (/unable to authenticate|Unsupported state/i.test(e.message || '') ||
        (e.code && /^Z_/.test(String(e.code))) ||
        /incorrect header check/i.test(e.message || ''))) {
      e.code = 'TVB_AUTH_FAILED';
    }
    throw e;
  }
  if (bytes !== entry.size) {
    throw new Error('Size mismatch (truncated data): ' + entry.name);
  }
  if (hash.digest('hex') !== entry.sha256) {
    throw new Error('Hash mismatch (corrupt backup file): ' + entry.name);
  }
}

/**
 * Decrypt one entry (from inspectTvb) straight into a temp file,
 * verifying it. Used by single-file restore. Throws TVB_AUTH_FAILED
 * on a wrong password / tampered ciphertext, a plain Error otherwise.
 */
async function decryptEntryToFile(tvbPath, entry, password, tmpPath) {
  // The password is passed so the index tag is verified BEFORE the
  // entry is trusted for a restore.
  const info = inspectTvb(tvbPath, password);
  if (!password) throw new Error('This backup is encrypted — a password is required to restore it.');
  const key = deriveTvbKey(password, info.salt);
  const fd = fs.openSync(tvbPath, 'r');
  const ws = fs.createWriteStream(tmpPath);
  try {
    await decryptEntryStream(fd, entry, key, ws);
  } catch (e) {
    if (e && e.code === 'TVB_AUTH_FAILED') throw authError('Wrong password or the backup file is damaged.');
    if (e && /unable to authenticate|Unsupported state/i.test(e.message)) throw authError('Wrong password or the backup file is damaged.');
    throw e;
  } finally {
    try { fs.closeSync(fd); } catch (e) {}
  }
}

/**
 * Extract a whole .tvb into restoreDir.
 * callbacks: { onFile(name, size), commit(rel, tmpPath, destPath) }.
 * commit() decides skip-vs-rename (the caller's overwrite rules) and
 * returns true when the file was committed, false when skipped (it
 * must have removed the temp file itself). Returns { errors }.
 * A wrong password fails fast on the first entry; a later entry that
 * fails authentication is recorded as a tampered-file error and the
 * rest still extracts.
 */
let extractCounter = 0;
async function extractTvb(tvbPath, restoreDir, password, callbacks) {
  const onFile = (callbacks && callbacks.onFile) || function () {};
  const commit = (callbacks && callbacks.commit) || null;
  const errors = [];
  // The password is passed so the index tag is verified BEFORE any
  // entry is trusted for a restore.
  const info = inspectTvb(tvbPath, password);
  if (!password) throw new Error('This backup is encrypted — a password is required to restore it.');
  const key = deriveTvbKey(password, info.salt);
  const fd = fs.openSync(tvbPath, 'r');
  const restoreBase = path.resolve(restoreDir);
  try {
    let attempted = 0;
    for (const entry of info.entries) {
      const rel = entry.name;
      // Zip-slip guard (same rule as the ZIP restore path): the
      // entry name must stay inside the restore folder.
      const dest = path.resolve(restoreBase, rel.replace(/\//g, path.sep));
      if (dest !== restoreBase && !dest.startsWith(restoreBase + path.sep)) {
        errors.push('Skipped unsafe path: ' + rel);
        continue;
      }
      try { fs.mkdirSync(path.dirname(dest), { recursive: true }); } catch (e) {
        errors.push('Failed to create folder for ' + rel + ': ' + e.message);
        continue;
      }
      // A pre-existing symlink (or Windows junction) inside the
      // restore folder could redirect this write outside it — the
      // lexical check above cannot see it. Resolve the REAL parent
      // and check it against the REAL restore root before writing
      // anything (same policy as the plain-ZIP restore path), and
      // write the temp file and the commit through the real path, so
      // a link swapped after this check cannot redirect the write.
      let realDest = dest;
      try {
        const realBase = fs.realpathSync(restoreBase);
        const realParent = fs.realpathSync(path.dirname(dest));
        if (realParent !== realBase && !realParent.startsWith(realBase + path.sep)) {
          errors.push('Skipped unsafe path: ' + rel);
          continue;
        }
        realDest = path.join(realParent, path.basename(dest));
      } catch (e) {
        errors.push('Failed to create folder for ' + rel + ': ' + e.message);
        continue;
      }
      const tmp = realDest + '.tvtmp-' + process.pid + '-' + (++extractCounter);
      const ws = fs.createWriteStream(tmp);
      attempted++;
      try {
        await decryptEntryStream(fd, entry, key, ws);
        let committed = true;
        if (commit) committed = commit(rel, tmp, realDest);
        if (committed) onFile(rel, entry.size);
      } catch (e) {
        try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch (e2) {}
        if (e && e.code === 'TVB_AUTH_FAILED') {
          // Wrong password fails on the FIRST entry (every entry
          // would fail the same way); a later entry failing means
          // the file was tampered with after creation — record it
          // and keep extracting the rest.
          if (attempted === 1) throw authError('Wrong password or the backup file is damaged.');
          errors.push('Authentication failed (tampered backup file): ' + rel);
        } else {
          errors.push(e && e.message ? e.message : String(e));
        }
      }
    }
  } finally {
    try { fs.closeSync(fd); } catch (e) {}
  }
  return { errors: errors };
}

module.exports = {
  TvbWriter,
  inspectTvb,
  extractTvb,
  decryptEntryToFile,
  deriveTvbKey,
  TVB_MAGIC,
  TVB_TRAILER_MAGIC,
  TVB_VERSION,
  TVB_FLAG_LAYERED,
  TVB_LAYERED_ENTRY
};
