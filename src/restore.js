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
    // Destination files left untouched because they already exist
    // and overwrite was OFF (the default) — never replaced, counted
    // here and listed in skipped_files (entry paths, '/'-separated).
    this.files_skipped = 0;
    this.skipped_files = [];
    this.total_bytes = 0;
    this.duration_seconds = 0;
    this.errors = [];
    // Non-fatal notes (e.g. a legacy backup restored without a
    // manifest): the restore succeeded, but the user should know
    // what was NOT verified.
    this.warnings = [];
    // The backup chain that was applied, oldest first (basenames) —
    // empty for a plain single-artifact restore.
    this.chain = [];
  }
}

// Name of the SHA-256 integrity manifest the engine writes into
// plain-folder backups (see techvision-core.js). It is metadata, not
// user data: never restored as a file, never listed in getZipInfo.
const MANIFEST_NAME = '.techvision-manifest.json';

// Overwrite option (restore): default OFF — an existing destination
// file is SKIPPED, never replaced, unless the caller passes
// { overwrite: true }. The option is optional everywhere so older
// callers keep the safe default.
function restoreOptions(options) {
  // chainWritten (a Set of resolved destination paths written by
  // earlier artifacts of THIS chain restore) passes through: a
  // later artifact must overwrite files the chain itself wrote,
  // while files that existed before the restore are still skipped.
  return { overwrite: !!(options && options.overwrite), chainWritten: (options && options.chainWritten) || null };
}

// Skip decision for overwrite OFF: only an existing regular FILE is
// skipped. A directory at the destination path must NOT count as a
// skip — e.g. a zip holding both `a` and `a/b.txt`: the `a/b.txt`
// entry creates dir `a`, and the `a` entry must fail on the rename
// (reported as an error), not vanish silently as "skipped".
function destIsFile(dest) {
  try { return fs.statSync(dest).isFile(); } catch (e) { return false; }
}

// Write-then-commit: stream to a temp file in the SAME directory as the
// final path (so the rename stays on one filesystem), then rename over
// the destination only after verification. A failed write or verify
// removes the TEMP file — the destination, and any good file already
// there, is never touched. (A restore used to write straight to the
// destination and delete it on a CRC mismatch, destroying a good file
// that was already there.)
let tempCounter = 0;
function tempPathFor(dest) {
  return dest + '.tvtmp-' + process.pid + '-' + (++tempCounter);
}

// Read a backup folder's integrity manifest, or null when there is
// none (backups made before manifests were added) or it is unreadable
// — a bad manifest must never fail a restore, it just means the files
// are restored unverified.
function readManifest(backupDir) {
  try {
    const raw = fs.readFileSync(path.join(backupDir, MANIFEST_NAME), 'utf8');
    const m = JSON.parse(raw);
    if (m && m.version === 1 && m.files && typeof m.files === 'object') return m;
  } catch (e) {}
  return null;
}

// Stream-copy src -> dest while computing the SHA-256 of the bytes
// actually written. Resolves { hash, size }. A failed copy removes
// the partial destination.
function copyFileHashed(src, dest) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    let size = 0;
    const rs = fs.createReadStream(src);
    const ws = fs.createWriteStream(dest);
    let failed = false;
    const fail = (err) => {
      if (failed) return;
      failed = true;
      try { rs.destroy(); } catch (e) {}
      try { ws.destroy(); } catch (e) {}
      try { if (fs.existsSync(dest)) fs.unlinkSync(dest); } catch (e) {}
      reject(err);
    };
    const tee = new Transform({
      transform(chunk, encoding, callback) {
        hash.update(chunk);
        size += chunk.length;
        callback(null, chunk);
      }
    });
    rs.on('error', fail);
    tee.on('error', fail);
    ws.on('error', fail);
    ws.on('finish', () => resolve({ hash: hash.digest('hex'), size: size }));
    rs.pipe(tee).pipe(ws);
  });
}

/**
 * Incremental chain restore (P1-8).
 *
 * A job's artifacts live side by side in one folder as
 * `<job>_full_<ISO-stamp>.zip` (or a plain folder without .zip)
 * and `<job>_incremental_<ISO-stamp>.zip` (or folder). The ISO
 * stamps sort lexicographically in chronological order. An
 * incremental on its own is only a DELTA — restoring it alone
 * silently drops every unchanged file (they live only in the
 * base Full). So restoring any artifact restores its whole chain:
 * the newest Full at or before it, then every incremental after
 * that Full up to and including it, oldest first, so newer files
 * overwrite older ones.
 *
 * Deletions are a known limitation: an incremental records no
 * tombstones, so a file deleted from the source after the Full is
 * still restored from the Full. Removing it would need deletion
 * records in the backup state, which do not exist yet.
 */

// `<job>_full_<stamp>` / `<job>_incremental_<stamp>`, stamp =
// new Date().toISOString().replace(/[:.]/g, '-') (see
// techvision-core.js). The job name is greedy: a job literally
// named `my_full_job` still parses as job `my_full_job`.
const ARTIFACT_RE = /^(.*)_(full|incremental)_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)(\.zip)?$/;

function parseArtifactName(fileName) {
  const m = ARTIFACT_RE.exec(fileName);
  if (!m) return null;
  return { jobName: m[1], kind: m[2], stamp: m[3] };
}

// Resolve the chain for one artifact. Returns null when the path
// is not a job artifact (or does not exist) — the caller then
// restores just that artifact, as before. Otherwise returns
// { chain, baseMissing }: `chain` is the artifact paths oldest
// first ending with the selected one; `baseMissing` is true when
// the selected artifact is an incremental whose base Full is not
// in the folder (the chain is then just the selected artifact).
function findBackupChain(artifactPath) {
  let stat = null;
  try { stat = fs.statSync(artifactPath); } catch (e) { return null; }
  if (!stat.isFile() && !stat.isDirectory()) return null;
  const dir = path.dirname(artifactPath);
  const selected = parseArtifactName(path.basename(artifactPath));
  if (!selected) return null;
  let names = null;
  try { names = fs.readdirSync(dir); } catch (e) { return null; }
  const siblings = [];
  for (const name of names) {
    const parsed = parseArtifactName(name);
    if (!parsed || parsed.jobName !== selected.jobName) continue;
    const full = path.join(dir, name);
    try {
      const s = fs.statSync(full);
      if (!s.isFile() && !s.isDirectory()) continue;
    } catch (e) { continue; }
    siblings.push({ path: full, kind: parsed.kind, stamp: parsed.stamp });
  }
  siblings.sort((a, b) => (a.stamp < b.stamp ? -1 : (a.stamp > b.stamp ? 1 : 0)));
  const selIdx = siblings.findIndex((s) => path.resolve(s.path) === path.resolve(artifactPath));
  if (selIdx < 0) return null;
  if (selected.kind === 'full') return { chain: [artifactPath], baseMissing: false };
  // Newest Full at or before the selected incremental is the base.
  let baseIdx = -1;
  for (let i = selIdx; i >= 0; i--) {
    if (siblings[i].kind === 'full') { baseIdx = i; break; }
  }
  if (baseIdx < 0) return { chain: [artifactPath], baseMissing: true };
  const chain = siblings.slice(baseIdx, selIdx + 1).map((s) => s.path);
  return { chain: chain, baseMissing: false };
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
   * Restore all files from one backup artifact, or from its whole
   * incremental chain when it is an incremental (see findBackupChain
   * above): the base Full plus every incremental up to it, oldest
   * first. A Full on its own restores exactly as before.
   */
  async restore_all(zipPath, restoreDir, password, options) {
    const opts = restoreOptions(options);
    const chain = findBackupChain(zipPath);
    if (!chain || (chain.chain.length === 1 && !chain.baseMissing)) {
      return this._restoreSingle(zipPath, restoreDir, password, opts);
    }
    const result = new RestoreResult();
    const startTime = Date.now();
    result.chain = chain.chain.map((p) => path.basename(p));
    const skippedNames = new Set();
    // Files this chain restore writes itself: a later artifact must
    // overwrite them (newest version wins), while files that existed
    // before the restore started are still skipped when overwrite is
    // OFF. Without this set the incremental's changed files were
    // skipped as "already exist" and the restore came back stale.
    const chainWritten = new Set();
    const chainOpts = Object.assign({}, opts, { chainWritten: chainWritten });
    for (const artifact of chain.chain) {
      const one = await this._restoreSingle(artifact, restoreDir, password, chainOpts);
      result.files_restored += one.files_restored;
      result.files_verified += one.files_verified;
      result.files_mismatched += one.files_mismatched;
      result.total_bytes += one.total_bytes;
      result.errors.push(...one.errors);
      result.warnings.push(...one.warnings);
      // A file skipped in two chain artifacts is one skipped file,
      // not two — dedupe by entry name.
      for (const name of (one.skipped_files || [])) skippedNames.add(name);
    }
    result.skipped_files = [...skippedNames];
    result.files_skipped = result.skipped_files.length;
    if (chain.baseMissing) {
      result.errors.push('Base full backup not found — this incremental backup is only a delta; files that did not change are missing from this restore.');
    } else {
      result.warnings.push('Restored a backup chain, oldest first: ' + result.chain.join(' + ') + '.');
    }
    result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
    // A restore that only skipped (every file already exists) still
    // succeeded — nothing was lost and nothing failed.
    result.success = (result.files_restored > 0 || result.files_skipped > 0) && result.errors.length === 0 && result.files_mismatched === 0;
    return result;
  }

  /**
   * Restore all files from a SINGLE artifact (one ZIP or one plain
   * folder). This is the old restore_all body, unchanged — the chain
   * wrapper above calls it once per artifact.
   */
  async _restoreSingle(zipPath, restoreDir, password, options) {
    const opts = restoreOptions(options);
    const result = new RestoreResult();
    const startTime = Date.now();
    // Overwrite OFF (default): an existing destination file is
    // skipped, never replaced. Callers check this AFTER the entry
    // verified (CRC / manifest hash) — a corrupt backup file still
    // errors instead of silently skipping. Returns true when the
    // entry was counted as skipped (temp file already removed).
    function skipIfExists(tmp, dest, rel) {
      if (opts.overwrite || !destIsFile(dest)) return false;
      // Written by an earlier artifact of this same chain restore:
      // the newer version must replace it, not be skipped.
      if (opts.chainWritten && opts.chainWritten.has(path.resolve(dest))) return false;
      try { fs.unlinkSync(tmp); } catch (e) {}
      result.files_skipped++;
      result.skipped_files.push(rel);
      return true;
    }
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
        const extracted = await zipAes.extractEncrypted(zipPath, restoreDir, password, function (name, size) {
          result.files_restored++;
          result.total_bytes += size;
        }, opts);
        result.errors = extracted.errors;
        result.files_skipped = extracted.skipped || 0;
        result.skipped_files = extracted.skipped_files || [];
        // Every file was authenticated by HMAC at decrypt time and
        // verified after writing, so restored == verified here.
        result.files_verified = result.files_restored;
        result.success = result.files_mismatched === 0 && result.errors.length === 0 && (result.files_restored > 0 || result.files_skipped > 0);
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
        const walk = async (dir) => {
          for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const src = path.join(dir, entry.name);
            const rel = path.relative(zipPath, src);
            const dest = path.join(restoreDir, rel);
            try {
              if (entry.isDirectory()) { fs.mkdirSync(dest, { recursive: true }); await walk(src); }
              else if (entry.isSymbolicLink()) { result.errors.push('Skipped symbolic link: ' + rel); }
              else if (rel === MANIFEST_NAME) {
                // The integrity manifest is metadata, not user data —
                // never restored as a file.
                continue;
              }
              else {
                fs.mkdirSync(path.dirname(dest), { recursive: true });
                // Copy to a temp file, verify against the manifest,
                // then rename: a corrupt backup file must never
                // overwrite a good file at the destination.
                const tmp = tempPathFor(dest);
                const copied = await copyFileHashed(src, tmp);
                if (manifest) {
                  const want = manifest.files[rel.replace(/\\/g, '/')];
                  if (!want) {
                    try { fs.unlinkSync(tmp); } catch (e) {}
                    result.errors.push(`No manifest entry for ${rel} — refusing to restore an unverified file`);
                    result.files_mismatched++;
                  } else if (copied.hash !== want.sha256 || copied.size !== want.size) {
                    try { fs.unlinkSync(tmp); } catch (e) {}
                    result.errors.push(`Hash mismatch (corrupt backup file): ${rel}`);
                    result.files_mismatched++;
                  } else {
                    // Verified: rename over the destination — unless
                    // it already exists and overwrite is OFF, in
                    // which case the good file there is left alone.
                    if (!skipIfExists(tmp, dest, rel.replace(/\\/g, '/'))) {
                      fs.renameSync(tmp, dest);
                      if (opts.chainWritten) opts.chainWritten.add(path.resolve(dest));
                      result.files_restored++; result.files_verified++; result.total_bytes += copied.size;
                    }
                  }
                } else {
                  if (!skipIfExists(tmp, dest, rel.replace(/\\/g, '/'))) {
                    fs.renameSync(tmp, dest);
                    if (opts.chainWritten) opts.chainWritten.add(path.resolve(dest));
                    result.files_restored++; result.total_bytes += copied.size;
                  }
                }
              }
            } catch (e) {
              result.errors.push('Failed to restore ' + rel + ': ' + e.message);
            }
          }
        };
        const manifest = readManifest(zipPath);
        await walk(zipPath);
        if (!manifest) {
          result.warnings.push('This backup has no integrity manifest (created before verification was added) — files were copied without hash verification.');
        }
        result.success = (result.files_restored > 0 || result.files_skipped > 0) && result.errors.length === 0;
        if (result.files_restored === 0 && result.files_skipped === 0 && result.errors.length === 0) {
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
        // mismatched, even with 0 files and a list of errors. (A
        // restore that only skipped existing files still succeeded.)
        if (result.files_restored === 0 && result.files_skipped === 0 && result.errors.length === 0) {
          result.errors.push('Nothing to restore: the backup contains no files.');
        }
        result.success = (result.files_restored > 0 || result.files_skipped > 0) && result.errors.length === 0 && result.files_mismatched === 0;
        resolve(result);
      };
      // A zipfile-level error (bad entry name, corrupt central
      // directory mid-read) must not hang the restore: record it and
      // finish with what was restored so far.
      const failZip = (err) => {
        if (finished) return;
        result.errors.push(err && err.message ? err.message : String(err));
        ended = true;
        // Do NOT zero pendingEntries or close the zipfile here: an
        // entry whose stream is already open must be allowed to
        // settle (verify + rename) instead of being discarded — a
        // traversal entry later in the archive must not throw away a
        // good file that was already streaming. maybeFinish fires
        // once the in-flight entries settle; every opened stream
        // settles on its own (finish or error), so this cannot hang
        // the restore.
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

            // Write to a temp file in the same folder and rename over
            // the destination only after the CRC passes — a failed
            // restore must never destroy a good file that was already
            // at the destination.
            const tmpPath = tempPathFor(writePath);
            const ws = fs.createWriteStream(tmpPath);
            let crc = 0;
            let bytes = 0;
            let failed = false;
            const failEntry = (msg) => {
              if (failed) return;
              failed = true;
              try { ReadStream.destroy(); } catch (e) {}
              try { ws.destroy(); } catch (e) {}
              try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
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
                try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
                result.errors.push(`CRC mismatch (corrupt data): ${entry.fileName}`);
                result.files_mismatched++;
              } else if (bytes !== entry.uncompressedSize) {
                try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
                result.errors.push(`Size mismatch (truncated data): ${entry.fileName}`);
                result.files_mismatched++;
              } else {
                // CRC and size passed: rename over the destination —
                // unless it already exists and overwrite is OFF, in
                // which case the good file there is left alone.
                if (skipIfExists(tmpPath, writePath, entry.fileName)) {
                  pendingEntries--;
                  maybeFinish();
                  return;
                }
                try { fs.renameSync(tmpPath, writePath); } catch (e) {
                  try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e2) {}
                  result.errors.push(`Failed to write ${entry.fileName}: ${e.message}`);
                  pendingEntries--;
                  maybeFinish();
                  return;
                }
                if (opts.chainWritten) opts.chainWritten.add(path.resolve(writePath));
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
          if (path.relative(zipPath, full) === MANIFEST_NAME) continue; // integrity manifest: metadata, not a restorable file
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
   * Restore a single file to a specific location. When the file is
   * not in the picked artifact, the chain is searched backwards:
   * an unchanged file lives only in the base Full, not in the
   * incremental that was picked.
   */
  async restoreFile(zipPath, entryName, destPath, password, options) {
    const opts = restoreOptions(options);
    const chain = findBackupChain(zipPath);
    try {
      return await this._restoreFileSingle(zipPath, entryName, destPath, password, opts);
    } catch (e) {
      if (e.code !== 'ENTRY_NOT_FOUND' || !chain || chain.chain.length < 2) throw e;
      const earlier = chain.chain.slice(0, -1).reverse();
      for (const artifact of earlier) {
        try {
          return await this._restoreFileSingle(artifact, entryName, destPath, password, opts);
        } catch (e2) {
          if (e2.code !== 'ENTRY_NOT_FOUND') throw e2;
          // Not in this one either — keep looking backwards.
        }
      }
      throw e; // not in any artifact of the chain
    }
  }

  /**
   * Restore a single file from ONE artifact (ZIP or plain folder).
   * Rejects with code 'ENTRY_NOT_FOUND' when the file is not in
   * this artifact, so the chain wrapper above can keep looking.
   */
  async _restoreFileSingle(zipPath, entryName, destPath, password, options) {
    const opts = restoreOptions(options);
    // Overwrite OFF (default): an existing destination file is
    // skipped, never replaced — reported as { files: 0, skipped: 1 }.
    // Checked AFTER the entry verified, like the bulk path.
    function skippedResult(tmp) {
      if (!opts.overwrite && destIsFile(destPath)) {
        try { if (tmp && fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch (e2) {}
        return { files: 0, skipped: 1 };
      }
      return null;
    }
    // Plain-copy backup folder: the entry is a plain file inside
    // it. (Single-file restore never supported folders before —
    // yauzl cannot open a directory — so this branch also fixes
    // that gap. The manifest check mirrors the bulk folder path.)
    if (zipPath && fs.existsSync(zipPath) && fs.statSync(zipPath).isDirectory()) {
      const rel = entryName.replace(/\\/g, '/');
      const src = path.join(zipPath, rel);
      if (rel === MANIFEST_NAME || rel.startsWith('../') || path.isAbsolute(rel) ||
          !fs.existsSync(src) || !fs.statSync(src).isFile()) {
        const e = new Error('Entry not found in backup: ' + entryName);
        e.code = 'ENTRY_NOT_FOUND';
        throw e;
      }
      const manifest = readManifest(zipPath);
      const dir = path.dirname(destPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const tmpPath = tempPathFor(destPath);
      const copied = await copyFileHashed(src, tmpPath);
      if (manifest) {
        const want = manifest.files[rel];
        if (!want || copied.hash !== want.sha256 || copied.size !== want.size) {
          try { fs.unlinkSync(tmpPath); } catch (e2) {}
          throw new Error('Hash mismatch (corrupt backup file): ' + rel);
        }
      }
      const skipped = skippedResult(tmpPath);
      if (skipped) return skipped;
      fs.renameSync(tmpPath, destPath);
      return { files: 1 };
    }
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
          // The inspected entry already carries the full fields
          // (localOffset, compressedSize, crc, ...) — stream-decrypt
          // it straight into the temp file, never buffering the
          // entry (see zip-aes.js decryptEntryToFile).
          const dir = path.dirname(destPath);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          // Write-then-rename (same rule as the plain path): a failed
          // write must not leave a partial file at the destination.
          const tmpPath = tempPathFor(destPath);
          try {
            await zipAes.decryptEntryToFile(zipPath, hit, password, tmpPath);
            const skipped = skippedResult(tmpPath);
            if (skipped) return skipped;
            fs.renameSync(tmpPath, destPath);
          } catch (e) {
            try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e2) {}
            throw e;
          }
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
          if (!found) {
            const e = new Error('Entry not found in backup: ' + entryName);
            e.code = 'ENTRY_NOT_FOUND';
            done(e);
          }
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

              // Stream through a CRC check into a temp file and rename
              // over the destination only when the CRC (and size)
              // match: the old code piped straight to the destination
              // and reported success on 'finish' with no check at
              // all, so a corrupt entry was restored as if it were
              // good — and a good file at the destination was
              // overwritten with corrupt bytes.
              const tmpPath = tempPathFor(destPath);
              const file = fs.createWriteStream(tmpPath);
              let crc = 0;
              let bytes = 0;
              let settled2 = false;
              const fail = (e) => {
                if (settled2) return;
                settled2 = true;
                try { ReadStream.destroy(); } catch (e2) {}
                try { file.destroy(); } catch (e2) {}
                try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e2) {}
                done(e);
              };
              const crcStream = new Transform({
                transform(chunk, encoding, callback) {
                  crc = zipAes.crc32(chunk, crc);
                  bytes += chunk.length;
                  callback(null, chunk);
                }
              });
              crcStream.on('error', fail);
              ReadStream.on('error', fail);
              file.on('error', fail);
              file.on('finish', () => {
                if (settled2) return;
                settled2 = true;
                if ((crc >>> 0) !== (entry.crc32 >>> 0)) {
                  try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
                  return done(new Error(`CRC mismatch (corrupt data): ${entry.fileName}`));
                }
                if (bytes !== entry.uncompressedSize) {
                  try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
                  return done(new Error(`Size mismatch (truncated data): ${entry.fileName}`));
                }
                // Verified: rename over the destination — unless it
                // already exists and overwrite is OFF.
                if (!opts.overwrite && destIsFile(destPath)) {
                  try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e) {}
                  return done(null, { files: 0, skipped: 1 });
                }
                try { fs.renameSync(tmpPath, destPath); } catch (e) {
                  try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (e2) {}
                  return done(e);
                }
                done(null, { files: 1 });
              });
              ReadStream.pipe(crcStream).pipe(file);
            });
          }
        });
      });
    });
  }
}

module.exports = {
  RestoreEngine,
  RestoreResult,
  findBackupChain
};
