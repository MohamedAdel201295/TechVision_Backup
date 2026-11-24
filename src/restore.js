/**
 * TechVision Restore Engine
 * Restore from ZIP with hash verification
 * Uses yauzl for streaming extraction (memory efficient)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const yauzl = require('yauzl');
const EventEmitter = require('events');
const { Transform } = require('stream');
// WinZip AES-256 reader (pure JS, Node crypto). yauzl cannot decrypt,
// so encrypted backups go through this module instead.
const zipAes = require('./zip-aes.js');

/**
 * Restore Result Class
 */
class RestoreResult extends EventEmitter {
  constructor() {
    super();
    this.success = false;
    this.files_restored = 0;
    this.files_verified = 0;
    this.files_mismatched = 0;
    this.total_bytes = 0;
    this.duration_seconds = 0;
    this.errors = [];
  }
}

/**
 * Restore Engine Class
 * Uses streaming extraction with yauzl for memory efficiency
 */
class RestoreEngine {
  constructor() {
    this.errors = [];
  }

  /**
   * Calculate SHA-256 hash of content
   */
  calculateHash(content) {
    if (Buffer.isBuffer(content)) {
      return crypto.createHash('sha256').update(content).digest('hex');
    } else if (typeof content === 'string') {
      return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    }
    return null;
  }

  /**
   * Restore all files from ZIP using streaming (yauzl)
   */
  async restore_all(zipPath, restoreDir, password) {
    const result = new RestoreResult();
    const startTime = Date.now();
    // Encrypted backup (WinZip AES-256): yauzl cannot decrypt, so the
    // AES reader handles the whole restore. Wrong password fails fast.
    // Only the INSPECT may fall through to the yauzl path below (a
    // Zip64 or otherwise unreadable central directory is still a ZIP
    // yauzl can open); a failure inside the AES extraction itself is
    // a real failure and is reported, not retried through yauzl.
    let encryptedInfo = null;
    try {
      if (zipPath && fs.existsSync(zipPath) && !fs.statSync(zipPath).isDirectory()) {
        encryptedInfo = zipAes.inspectZip(zipPath);
      }
    } catch (e) {
      encryptedInfo = null; // fall through to the yauzl path below
    }
    if (encryptedInfo && encryptedInfo.encrypted) {
      try {
        if (!password) throw new Error('This backup is encrypted — a password is required to restore it.');
        if (!fs.existsSync(restoreDir)) fs.mkdirSync(restoreDir, { recursive: true });
        const extracted = zipAes.extractEncrypted(zipPath, restoreDir, password, function (name, size) {
          result.files_restored++;
          result.total_bytes += size;
        });
        result.errors = extracted.errors;
        // Every file was authenticated by HMAC at decrypt time and
        // verified after writing, so restored == verified here.
        result.files_verified = result.files_restored;
        result.success = result.files_mismatched === 0 && result.errors.length === 0 && result.files_restored > 0;
        result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
        return result;
      } catch (e) {
        result.success = false;
        result.errors.push(e.message);
        result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
        return result;
      }
    }
    // Plain-copy backup: backup_path is a folder with the same files,
    // not a ZIP. Restore is a straight copy back, same structure.
    try {
      if (zipPath && fs.existsSync(zipPath) && fs.statSync(zipPath).isDirectory()) {
        if (!fs.existsSync(restoreDir)) fs.mkdirSync(restoreDir, { recursive: true });
        // Never restore a folder into itself: the copy would re-copy
        // its own output as it walks.
        const srcAbs = path.resolve(zipPath);
        const dstAbs = path.resolve(restoreDir);
        if (dstAbs === srcAbs || dstAbs.startsWith(srcAbs + path.sep)) {
          throw new Error('Cannot restore into the backup folder itself.');
        }
        const walk = (dir) => {
          for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const src = path.join(dir, entry.name);
            const rel = path.relative(zipPath, src);
            const dest = path.join(restoreDir, rel);
            try {
              if (entry.isDirectory()) { fs.mkdirSync(dest, { recursive: true }); walk(src); }
              else if (entry.isSymbolicLink()) { result.errors.push('Skipped symbolic link: ' + rel); }
              else { fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.copyFileSync(src, dest); result.files_restored++; result.total_bytes += fs.statSync(src).size; }
            } catch (e) {
              result.errors.push('Failed to restore ' + rel + ': ' + e.message);
            }
          }
        };
        walk(zipPath);
        result.success = result.files_restored > 0 && result.errors.length === 0;
        if (result.files_restored === 0 && result.errors.length === 0) {
          result.errors.push('Nothing to restore: the backup folder is empty.');
        }
        result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
        return result;
      }
    } catch (e) {
      result.success = false;
      result.errors.push(e.message);
      result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
      return result;
    }
    return new Promise((resolve, reject) => {
      let pendingEntries = 0;
      let ended = false;      // the zipfile emitted 'end' (all entries seen)
      let finished = false;   // the result was already resolved
      const seenNames = new Set();

      // Ensure restore directory exists
      if (!fs.existsSync(restoreDir)) {
        fs.mkdirSync(restoreDir, { recursive: true });
      }
      const restoreBase = path.resolve(restoreDir);

      const maybeFinish = () => {
        if (finished) return;
        // Finish only once enumeration is done AND every entry stream
        // has settled — pendingEntries===0 alone does not prove that
        // (unread entries have not incremented it yet).
        if (!ended || pendingEntries !== 0) return;
        finished = true;
        try { if (zipfileRef) zipfileRef.close(); } catch (e) {}
        result.errors = [...new Set(result.errors)];
        result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
        // A restore that restored nothing, or failed on any entry, is
        // a failure — the old code reported success whenever no hash
        // mismatched, even with 0 files and a list of errors.
        if (result.files_restored === 0 && result.errors.length === 0) {
          result.errors.push('Nothing to restore: the backup contains no files.');
        }
        result.success = result.files_restored > 0 && result.errors.length === 0 && result.files_mismatched === 0;
        resolve(result);
      };
      // A zipfile-level error (bad entry name, corrupt central
      // directory mid-read) must not hang the restore: record it and
      // finish with what was restored so far.
      const failZip = (err) => {
        if (finished) return;
        result.errors.push(err && err.message ? err.message : String(err));
        ended = true;
        pendingEntries = 0;
        maybeFinish();
      };

      let zipfileRef = null;
      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          result.success = false;
          result.errors.push(err.message);
          result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
          return resolve(result);
        }
        zipfileRef = zipfile;
        zipfile.on('error', failZip);
        zipfile.on('end', () => { ended = true; maybeFinish(); });

        zipfile.readEntry();

        zipfile.on('entry', (entry) => {
          zipfile.readEntry();

          // Directory entries: the DOS directory bit (0x10) lives in
          // the LOW byte of externalAttributes — the old check shifted
          // the Unix mode down and compared it with 0x10, so a real
          // `subdir/` was written as an empty FILE named `subdir`
          // and `subdir/a.txt` then failed with ENOTDIR. A trailing
          // slash is the reliable test (same as zip-aes).
          if (entry.fileName.endsWith('/') || (entry.externalAttributes & 0x10) !== 0) {
            return;
          }

          // Duplicate entry names: only the first copy is restored;
          // a second copy would silently overwrite it while both
          // were counted as restored.
          if (seenNames.has(entry.fileName)) {
            result.errors.push(`Duplicate entry skipped: ${entry.fileName}`);
            return;
          }
          seenNames.add(entry.fileName);

          // Zip-slip guard (defence in depth — yauzl already rejects
          // '..', absolute and '\' names, but this is the check that
          // also catches a pre-existing symlink inside restoreDir).
          const entryPath = path.resolve(restoreBase, entry.fileName.replace(/\//g, path.sep));
          if (entryPath !== restoreBase && !entryPath.startsWith(restoreBase + path.sep)) {
            result.errors.push(`Skipped unsafe path: ${entry.fileName}`);
            return;
          }

          pendingEntries++;

          // Create directories (an uncaught throw here used to crash
          // the whole process).
          const dirName = path.dirname(entryPath);
          try {
            if (!fs.existsSync(dirName)) fs.mkdirSync(dirName, { recursive: true });
          } catch (e) {
            result.errors.push(`Failed to create folder for ${entry.fileName}: ${e.message}`);
            pendingEntries--;
            maybeFinish();
            return;
          }
          // A pre-existing symlink inside the restore folder could
          // redirect this write outside it — resolve the parent and
          // check the real location before writing.
          let writePath = entryPath;
          try {
            const realBase = fs.realpathSync(restoreBase);
            const realParent = fs.realpathSync(dirName);
            if (realParent !== realBase && !realParent.startsWith(realBase + path.sep)) {
              result.errors.push(`Skipped unsafe path: ${entry.fileName}`);
              pendingEntries--;
              maybeFinish();
              return;
            }
            writePath = path.join(realParent, path.basename(entryPath));
          } catch (e) {
            result.errors.push(`Failed to create folder for ${entry.fileName}: ${e.message}`);
            pendingEntries--;
            maybeFinish();
            return;
          }

          // Read the entry and stream it straight to disk — the old
          // code buffered every file's content in a Map until the
          // end, so a multi-GB restore held the whole backup in RAM.
          // The ZIP's stored CRC32 is the independent check: yauzl
          // does NOT verify it (verified: a flipped byte in a STORED
          // entry restores silently), so compute it while streaming
          // and compare with entry.crc32 at the end.
          zipfile.openReadStream(entry, (err, ReadStream) => {
            if (err) {
              result.errors.push(`Failed to open ${entry.fileName}: ${err.message}`);
              pendingEntries--;
              maybeFinish();
              return;
            }

            const ws = fs.createWriteStream(writePath);
            let crc = 0;
            let bytes = 0;
            let failed = false;
            const failEntry = (msg) => {
              if (failed) return;
              failed = true;
              try { ReadStream.destroy(); } catch (e) {}
              try { ws.destroy(); } catch (e) {}
              try { if (fs.existsSync(writePath)) fs.unlinkSync(writePath); } catch (e) {}
              result.errors.push(msg);
              pendingEntries--;
              maybeFinish();
            };
            // CRC through a Transform so backpressure is honoured
            // (a 'data' listener + pipe would buffer unboundedly).
            const crcStream = new Transform({
              transform(chunk, encoding, callback) {
                crc = zipAes.crc32(chunk, crc);
                bytes += chunk.length;
                callback(null, chunk);
              }
            });
            crcStream.on('error', (e) => failEntry(`Read error for ${entry.fileName}: ${e.message}`));
            ReadStream.on('error', (e) => failEntry(`Read error for ${entry.fileName}: ${e.message}`));
            ws.on('error', (e) => failEntry(`Failed to write ${entry.fileName}: ${e.message}`));
            ws.on('finish', () => {
              if (failed) return;
              if ((crc >>> 0) !== (entry.crc32 >>> 0)) {
                try { if (fs.existsSync(writePath)) fs.unlinkSync(writePath); } catch (e) {}
                result.errors.push(`CRC mismatch (corrupt data): ${entry.fileName}`);
                result.files_mismatched++;
              } else {
                result.files_restored++;
                result.files_verified++;
                result.total_bytes += bytes;
              }
              pendingEntries--;
              maybeFinish();
            });
            ReadStream.pipe(crcStream).pipe(ws);
          });
        });
      });
    });
  }

  /**
   * Get ZIP file info (streaming)
   */
  async getZipInfo(zipPath) {
    // Plain-copy backup folder: list its files instead of opening a ZIP.
    if (zipPath && fs.existsSync(zipPath) && fs.statSync(zipPath).isDirectory()) {
      const entries = [];
      const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) walk(full);
          else entries.push({ path: path.relative(zipPath, full), size: fs.statSync(full).size, isDir: false, encrypted: false });
        }
      };
      walk(zipPath);
      return entries;
    }
    // ZIP: the AES inspector lists entries AND flags encrypted ones, so
    // the restore wizard knows when to ask for a password. If its
    // parser cannot read the file, fall back to yauzl (no flag).
    try {
      const info = zipAes.inspectZip(zipPath);
      return info.entries.filter(function (e) { return !e.isDir; }).map(function (e) {
        return { path: e.name.replace(/\//g, path.sep), size: e.size, isDir: false, encrypted: e.encrypted };
      });
    } catch (e) { /* fall through to yauzl below */ }
    return new Promise((resolve, reject) => {
      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);

        const entries = [];

        zipfile.readEntry();

        zipfile.on('entry', (entry) => {
          zipfile.readEntry();

          // Same directory test as the restore path (trailing slash,
          // not the shifted Unix mode).
          if (!entry.fileName.endsWith('/')) {
            entries.push({
              path: entry.fileName.replace(/\//g, path.sep),
              size: entry.uncompressedSize,
              isDir: false,
              // yauzl does not expose an `encrypted` flag, but bit 0
              // of the general-purpose flag is the encryption bit.
              // Without it a Zip64 encrypted backup was listed as
              // unencrypted and the wizard never asked for a password.
              encrypted: (entry.generalPurposeBitFlag & 0x01) !== 0
            });
          }
        });

        zipfile.on('end', () => {
          try { zipfile.close(); } catch (e) {}
          resolve(entries);
        });
        zipfile.on('error', (e) => reject(e));
      });
    });
  }

  /**
   * Restore single file to specific location
   */
  async restoreFile(zipPath, entryName, destPath, password) {
    // Encrypted entry: decrypt it directly with the AES reader.
    // Only an unreadable central directory falls through to yauzl
    // (e.g. Zip64); a decrypt failure (wrong password, tampered
    // ciphertext, bad CRC) is reported as-is, never retried through
    // yauzl — which cannot decrypt and would either fail confusingly
    // or write garbage.
    let inspected = false;
    try {
      if (zipPath && fs.existsSync(zipPath) && !fs.statSync(zipPath).isDirectory()) {
        const info = zipAes.inspectZip(zipPath);
        inspected = true;
        const wanted = entryName.replace(/\\/g, '/');
        const hit = info.entries.find(function (e) { return e.name === wanted; });
        if (hit && hit.encrypted) {
          if (!password) throw new Error('This backup is encrypted — a password is required to restore it.');
          const all = zipAes.parseCentralDirectory(fs.readFileSync(zipPath));
          const full = all.find(function (e) { return e.name === wanted; });
          const content = zipAes.decryptEntry(zipPath, full, password);
          const dir = path.dirname(destPath);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(destPath, content);
          return { files: 1 };
        }
        // The entry is plain (or not in this ZIP at all): the yauzl
        // path below handles both — a missing entry rejects there.
      }
    } catch (e) {
      if (inspected) throw e; // the inspector read the file; the failure is real
      // Inspector could not read the file: fall through to yauzl.
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let zipfileRef = null;
      const done = (err, value) => {
        if (settled) return;
        settled = true;
        try { if (zipfileRef) zipfileRef.close(); } catch (e) {}
        if (err) reject(err);
        else resolve(value);
      };
      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return done(err);
        zipfileRef = zipfile;
        let found = false;
        zipfile.on('error', (e) => done(e));
        zipfile.on('end', () => {
          if (!found) done(new Error('Entry not found in backup: ' + entryName));
        });
        zipfile.readEntry();

        zipfile.on('entry', (entry) => {
          zipfile.readEntry();

          if (entry.fileName === entryName.replace(/\\/g, '/')) {
            found = true;
            zipfile.openReadStream(entry, (err, ReadStream) => {
              if (err) return done(err);

              const dir = path.dirname(destPath);
              try {
                if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
              } catch (e) { return done(e); }

              const file = fs.createWriteStream(destPath);
              ReadStream.on('error', (e) => done(e));
              file.on('error', (e) => done(e));
              file.on('finish', () => done(null, { files: 1 }));
              ReadStream.pipe(file);
            });
          }
        });
      });
    });
  }
}

module.exports = {
  RestoreEngine,
  RestoreResult
};
