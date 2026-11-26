/**
 * TechVision.Core - Backup Engine for Node.js
 * Ported from Python implementation
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const archiver = require('archiver');
// WinZip AES-256 ZIPs, standard format (7-Zip / WinRAR can open them
// with the same password). Guarded: if the user has not run
// `npm install` yet, the app still starts and encryption just reports
// a clear error instead of crashing the backup engine.
let zipEncryptedAvailable = false;
try {
  archiver.registerFormat('zip-encrypted', require('archiver-zip-encrypted'));
  zipEncryptedAvailable = true;
} catch (e) { /* encryption unavailable until npm install */ }
const { EventEmitter } = require('events');
const { Transform } = require('stream');

/**
 * Job Configuration Class
 */
function normalizePathValue(value) {
  // Accept a plain string ("C:\\..."), an object { path: "C:\\..." },
  // or nothing. The job wizard saves flat strings, the engine used to
  // expect { path } objects — normalize both shapes here so a string
  // source/destination can never silently become undefined.
  if (typeof value === 'string') return { path: value };
  if (value && typeof value === 'object') return value;
  return { path: '' };
}

class JobConfig {
  constructor(data = {}) {
    this.name = data.name || 'DefaultJob';
    this.source = normalizePathValue(data.source || data.sourcePath || data.sourceDirectory);
    this.destination = normalizePathValue(data.destination || data.destPath || data.destinationDirectory || data.dest);
    // The job wizard saves include patterns at the top level
    // (includePatterns: ["*.txt"]), not under source.include.
    if (Array.isArray(data.includePatterns) && data.includePatterns.length && !this.source.include) {
      this.source.include = data.includePatterns;
    }
    if (Array.isArray(data.excludePatterns) && data.excludePatterns.length && !this.source.exclude) {
      this.source.exclude = data.excludePatterns;
    }
    this.schedule = data.schedule || { enabled: false };
    // Compression: the wizard saves `compress` (boolean) and/or
    // `compression` ('none' | 'standard' | 'advanced'). The engine used
    // to ignore both and always used zlib level 9, so "no compression"
    // still produced a compressed ZIP. Honour the setting here.
    if (typeof data.compression === 'string') {
      this.compression = data.compression;
    } else if (data.options && typeof data.options.compression === 'string') {
      this.compression = data.options.compression;
    } else if (data.compress === false) {
      this.compression = 'none';
    } else {
      this.compression = 'standard';
    }
    this.options = data.options || {};
    // Encryption is INDEPENDENT of compression: encrypt only (stored,
    // level 0) or compression + encryption. `encryptionEnabled` is a
    // job setting and may be saved; `encryptionPassword` is runtime-only
    // and must NEVER be written to a job file or history — the vault
    // holds it encrypted, main.js strips it before any save.
    this.encryptionEnabled = data.encryptionEnabled === true ||
      (data.encryption && data.encryption.enabled === true);
    this.encryptionPassword = typeof data.encryptionPassword === 'string' ? data.encryptionPassword :
      (data.encryption && typeof data.encryption.password === 'string' ? data.encryption.password : null);
  }

  static fromJson(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const data = JSON.parse(content);
    return new JobConfig(data);
  }

  toJson() {
    return JSON.stringify({
      name: this.name,
      source: this.source,
      destination: this.destination,
      schedule: this.schedule,
      compression: this.compression,
      encryptionEnabled: this.encryptionEnabled,
      options: this.options
    }, null, 2);
  }

  /**
   * archiver options for the configured compression.
   * 'none' = store entries uncompressed (zlib level 0),
   * 'standard' = deflate level 6, 'advanced' = deflate level 9.
   */
  getArchiveOptions() {
    if (this.compression === 'none') return { zlib: { level: 0 } };
    if (this.compression === 'advanced') return { zlib: { level: 9 } };
    return { zlib: { level: 6 } };
  }

  /**
   * Build the archiver for this job: plain 'zip', or 'zip-encrypted'
   * (WinZip AES-256) when encryption is on. Encryption always makes a
   * ZIP — even with compression 'none' (stored entries + AES), because
   * a plain folder copy cannot be encrypted.
   */
  createArchive() {
    if (this.encryptionEnabled) {
      if (!zipEncryptedAvailable) {
        throw new Error('Encryption needs archiver-zip-encrypted — run `npm install` in the project folder first.');
      }
      if (!this.encryptionPassword) {
        throw new Error('Encryption is on but no password was provided for this job.');
      }
      return archiver('zip-encrypted', Object.assign({}, this.getArchiveOptions(), {
        encryptionMethod: 'aes256',
        password: this.encryptionPassword
      }));
    }
    return archiver('zip', this.getArchiveOptions());
  }

  /**
   * Get include patterns (minimum 1 char)
   */
  getIncludePatterns() {
    const patterns = this.source && this.source.include;
    if (!Array.isArray(patterns) || patterns.length === 0) {
      return ['*.*'];
    }
    const clean = patterns.filter((p) => typeof p === 'string' && p.length > 0);
    // A list that filters down to nothing (['', 123]) used to match
    // NO file at all — treat it as "no filter", like an empty list.
    return clean.length ? clean : ['*.*'];
  }

  /**
   * Get exclude patterns
   */
  getExcludePatterns() {
    if (!this.source.exclude) {
      return [];
    }
    // Same filter as include patterns: a non-string entry (e.g. a
    // number from a hand-edited job file) used to throw TypeError
    // inside shouldExclude and fail EVERY file in the run.
    if (!Array.isArray(this.source.exclude)) return [];
    return this.source.exclude.filter((p) => typeof p === 'string' && p.length > 0);
  }

  /**
   * Match one pattern against a file. Patterns are case-insensitive
   * (Windows paths are): `*.txt` matches the extension, `report.pdf`
   * matches that exact file name, and a bare word like `temp` matches
   * any file under a folder of that name (or a file of that name).
   */
  _matchPattern(filePath, pattern) {
    const p = String(pattern).toLowerCase();
    if (p === '*' || p === '*.*') return true;
    const fileName = path.basename(filePath).toLowerCase();
    const rel = path.relative(
      (this.source && this.source.path) || '', filePath).replace(/\\/g, '/').toLowerCase();
    if (p.indexOf('*') !== -1) {
      // `*.ext` — extension match; anything else with a `*` is a
      // simple "ends with the part after the star" match.
      if (p.startsWith('*')) return fileName.endsWith(p.substring(1));
      return fileName.indexOf(p.replace(/\*/g, '')) !== -1;
    }
    if (p.indexOf('/') !== -1) return rel === p || rel.endsWith('/' + p);
    if (fileName === p) return true;
    // Bare word: a folder segment of that name anywhere in the path.
    return rel.split('/').indexOf(p) !== -1;
  }

  /**
   * Check if path should be included
   */
  shouldInclude(filePath) {
    const patterns = this.getIncludePatterns();
    for (const pattern of patterns) {
      if (this._matchPattern(filePath, pattern)) return true;
    }
    return false;
  }

  /**
   * Check if path should be excluded
   */
  shouldExclude(filePath) {
    const patterns = this.getExcludePatterns();
    for (const pattern of patterns) {
      if (this._matchPattern(filePath, pattern)) return true;
    }
    return false;
  }
}

/**
 * Backup Result Class
 * 
 * NOTE: VSS (Volume Shadow Copy) is NOT implemented.
 * Locked files will be skipped with error code SKIPPED-LOCKED.
 * Full VSS support via vssadmin/PowerShell is a later phase.
 */
class BackupResult extends EventEmitter {
  constructor() {
    super();
    this.success = false;
    this.cancelled = false; // stopped by the user — not a failure
    this.files_backed_up = 0;
    this.files_skipped = 0;
    this.files_failed = 0;
    this.locked_files_skipped = 0;  // Files skipped due to being locked (EACCES)
    this.total_bytes = 0;
    this.duration_seconds = 0;
    this.backup_path = '';  // Path to the created ZIP file or plain-copy folder
    this.backup_format = 'zip'; // 'zip' or 'folder' (plain copy, same files)
    this.log_file = '';
    this.error_messages = [];
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Backup State Class
 */
class BackupState {
  constructor(stateFile) {
    this.stateFile = stateFile;
    this.state = this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.stateFile)) {
        const content = fs.readFileSync(this.stateFile, 'utf-8');
        return JSON.parse(content);
      }
    } catch (e) {
      console.error('Error loading backup state:', e.message);
    }
    return {};
  }

  save() {
    const dir = path.dirname(this.stateFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    // Atomic write: a torn .backup_state.json (crash / disk full
    // mid-write) used to load as {} and silently re-back up everything
    // — or worse, lose the record of what was backed up. Write to a
    // temp file in the same folder and rename over it.
    const tmp = this.stateFile + '.tmp-' + process.pid;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.state, null, 2));
      fs.renameSync(tmp, this.stateFile);
      return true;
    } catch (e) {
      try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch (e2) {}
      // The state is advisory (a stale state only costs a re-backup),
      // so a failed save must never fail the backup itself.
      console.error('Error saving backup state:', e.message);
      return false;
    }
  }

  get(filePath) {
    const relative = path.relative(this.getBaseDir(), filePath).replace(/\\/g, '/');
    return this.state[relative];
  }

  set(filePath, info) {
    const relative = path.relative(this.getBaseDir(), filePath).replace(/\\/g, '/');
    if (relative === '__meta__') return; // metadata key, never a file
    this.state[relative] = info;
  }

  getBaseDir() {
    // Metadata lives under __meta__ now: a real source file literally
    // named __base_dir__ used to collide with the old flat key and
    // turn getBaseDir() into a file-info object (TypeError on the next
    // run). Old state files still have the flat key — read it as a
    // fallback.
    const meta = this.state['__meta__'];
    if (meta && typeof meta === 'object' && typeof meta.baseDir === 'string') return meta.baseDir;
    if (typeof this.state['__base_dir__'] === 'string') return this.state['__base_dir__'];
    return process.cwd();
  }

  setBaseDir(dir) {
    this.state['__meta__'] = { baseDir: dir };
    // Remove the LEGACY flat metadata key — but only when it is a
    // string. A real source file literally named __base_dir__ stores
    // its file info under that key; deleting it unconditionally made
    // every incremental re-back that file up forever.
    if (typeof this.state['__base_dir__'] === 'string') delete this.state['__base_dir__'];
  }
}

/**
 * Thrown (internally) when the user stops a running backup. The run
 * methods catch it, delete the partial artifact and return a result
 * with cancelled:true — it never escapes to main.js as a throw.
 */
class BackupCancelled extends Error {
  constructor() {
    super('Backup stopped by user');
    this.code = 'BACKUP_CANCELLED';
  }
}

/**
 * Backup Engine Class
 */
class BackupEngine {
  constructor(jobConfig, logger = null) {
    // main.js passes the raw job object from the renderer, not a
    // JobConfig instance — normalize it here so shouldInclude /
    // shouldExclude and source.path / destination.path always exist.
    this.jobConfig = jobConfig instanceof JobConfig ? jobConfig : new JobConfig(jobConfig || {});
    this.logger = logger;
    // Stop support (one flag per engine — a fresh engine is created
    // for every run, so the flag starts false and is never reused):
    // requestCancel() sets it; the run loops and the finalize race
    // check it. _activeStreams is the stream of the file currently
    // being read (gate / plain copy), _activeArchive/_activeOutput
    // are the ZIP being written — requestCancel() tears all of them
    // down so a stop lands promptly, not just between files.
    this._cancelRequested = false;
    this._cancelWait = null;
    this._cancelResolve = null;
    this._activeStreams = null;
    this._activeArchive = null;
    this._activeOutput = null;
    const destPath = (this.jobConfig.destination && this.jobConfig.destination.path) || '';
    this.logsDir = destPath ? path.join(destPath, 'logs') : './logs';
    this.backupDir = destPath || './backup';
    // The backup folder is named after the job: sanitize it, because
    // a job literally named ".." used to make the backup folder the
    // PARENT of the destination (and "." the destination itself).
    this.backupName = String(this.jobConfig.name || 'job')
      .replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^\.+$/, '_') || 'job';
    this._collectErrors = [];

    // Setup must not throw out of the constructor: a destination that
    // is an existing file, read-only, or on a disconnected drive used
    // to crash the IPC handler with no history record. Record the
    // failure and let the run methods return it as a failed result.
    this._initError = null;
    if (!destPath) {
      // No destination at all: the run methods report "no destination"
      // — but the constructor used to mkdir ./backup (and ./logs) in
      // the working directory first, so a job with an empty destination
      // "succeeded" into <cwd>/backup with no warning. Create nothing.
      this._initError = new Error('No destination folder is set for this job.');
    } else {
      try {
        if (!fs.existsSync(this.logsDir)) {
          fs.mkdirSync(this.logsDir, { recursive: true });
        }
        if (!fs.existsSync(this.backupDir)) {
          fs.mkdirSync(this.backupDir, { recursive: true });
        }
      } catch (e) {
        this._initError = e;
      }
    }
  }

  /**
   * Stop this run. Synchronous and prompt: it only sets the flag and
   * tears down the live streams — the run's own awaits then unwind
   * through the cancel checks (per-file loop, finalize race) and the
   * outer catch deletes the partial artifact and returns
   * { cancelled: true }. Safe to call when no run is active (a fresh
   * engine just records the flag). Mid-file: destroying the active
   * read stream with a BackupCancelled error settles the gate /
   * plain-copy await at once; a stream already handed to archiver is
   * stopped by archive.abort() instead, and the finalize race (which
   * also listens on the cancel waiter) plus the post-race flag check
   * end the run even if the archive never reports the abort.
   */
  requestCancel() {
    this._cancelRequested = true;
    if (typeof this._cancelResolve === 'function') { try { this._cancelResolve(); } catch (e) {} }
    const streams = this._activeStreams;
    this._activeStreams = null;
    if (streams) {
      const err = new BackupCancelled();
      try { if (streams.rs) streams.rs.destroy(err); } catch (e) {}
      try { if (streams.tee) streams.tee.destroy(err); } catch (e) {}
      try { if (streams.ws) streams.ws.destroy(); } catch (e) {}
    }
    try { if (this._activeArchive && typeof this._activeArchive.abort === 'function') this._activeArchive.abort(); } catch (e) {}
    try { if (this._activeOutput) this._activeOutput.destroy(); } catch (e) {}
  }

  /**
   * Real progress reporting for the UI. main.js sets engine.onProgress
   * to forward these to the window; scheduled runs leave it unset
   * (no-op). Payload: { pct, phase, filesDone, filesTotal, bytesDone,
   * bytesTotal, currentFile }. Only emits when the rounded percent
   * moves, so the IPC channel is not flooded on many-small-file jobs.
   * Never goes backwards and never reaches 100 — the caller sets 100
   * when the IPC reply arrives.
   */
  _emitProgress(pct, phase, currentFile, filesDone, filesTotal, bytesDone, bytesTotal) {
    if (typeof this.onProgress !== 'function') return;
    const p = Math.max(0, Math.min(99, Math.round(pct * 10) / 10));
    if (p <= this._lastProgressPct) return;
    this._lastProgressPct = p;
    try {
      this.onProgress({ pct: p, phase, currentFile: currentFile || '', filesDone, filesTotal, bytesDone, bytesTotal });
    } catch (e) { /* progress is best-effort */ }
  }

  /**
   * Calculate SHA-256 hash of a file
   */
  calculateHash(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', data => hash.update(data));
      stream.on('end', () => {
        resolve(hash.digest('hex'));
      });
      stream.on('error', reject);
    });
  }

  /**
   * Get file info (size, mtime, hash)
   */
  async getFileInfo(filePath) {
    const stats = fs.statSync(filePath);
    const hash = await this.calculateHash(filePath);
    
    return {
      path: filePath,
      size: stats.size,
      mtime: stats.mtimeMs,
      hash: hash
    };
  }

  /**
   * Copy one file into a plain-copy backup folder, keeping the same
   * relative path it had in the source. Used when compression is 'none':
   * the user wants the backup to be the same files, not a ZIP.
   * Streamed (not copyFileSync) so a single huge file reports progress
   * per chunk through onProgress(chunkBytes) instead of jumping 0→100.
   * Resolves { dest, hash, size }: the SHA-256 is computed from the
   * very bytes that were written, so the state file and the integrity
   * manifest record what is actually in the backup — a file edited
   * mid-copy no longer leaves a stale pre-read hash behind.
   */
  _copyPlainFile(file, sourceDir, destRoot, onProgress) {
    const relativePath = path.relative(sourceDir, file).replace(/\\/g, '/');
    const dest = path.join(destRoot, relativePath);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    return new Promise((resolve, reject) => {
      const rs = fs.createReadStream(file);
      const ws = fs.createWriteStream(dest);
      // Stop support: requestCancel() destroys these, so a stop
      // mid-copy settles this promise at once (via fail, below)
      // instead of waiting for the whole file to copy.
      this._activeStreams = { rs: rs, ws: ws };
      const hash = crypto.createHash('sha256');
      let bytesCopied = 0;
      let failed = false;
      const fail = (err) => {
        if (failed) return;
        failed = true;
        if (this._activeStreams && this._activeStreams.rs === rs) this._activeStreams = null;
        try { rs.destroy(); } catch (e) {}
        try { ws.destroy(); } catch (e) {}
        // A failed copy must not leave a truncated file behind that
        // looks like a successful backup — remove the partial file.
        try { if (fs.existsSync(dest)) fs.unlinkSync(dest); } catch (e) {}
        reject(err);
      };
      rs.on('data', chunk => {
        hash.update(chunk);
        bytesCopied += chunk.length;
        if (typeof onProgress === 'function') { try { onProgress(chunk.length); } catch (e) {} }
      });
      rs.on('error', fail);
      ws.on('error', fail);
      ws.on('finish', () => { if (this._activeStreams && this._activeStreams.rs === rs) this._activeStreams = null; resolve({ dest: dest, hash: hash.digest('hex'), size: bytesCopied }); });
      rs.pipe(ws);
    });
  }

  /**
   * Run full backup
   */
  async run_full_backup() {
    const result = new BackupResult();
    const startTime = Date.now();
    const logFile = path.join(this.logsDir, `full_backup_${new Date().toISOString().replace(/[:.]/g, '-')}.log`);
    result.log_file = logFile;

    let sourceDir = this.jobConfig.source.path;
    const backupName = this.backupName;

    // Setup failed in the constructor (destination is a file, is
    // read-only, or sits on a disconnected drive): report it as a
    // failed run instead of throwing out of the IPC handler.
    if (this._initError) {
      result.success = false;
      result.error_messages.push(`Cannot use destination: ${this._initError.message}`);
      this.log('error', `Full backup failed: ${this._initError.message}`);
      this._writeLog(logFile, result);
      return result;
    }
    // An empty destination used to silently fall back to ./backup in
    // the process working directory — a backup the user never asked
    // for, in a place they never look.
    if (!this.jobConfig.destination || !this.jobConfig.destination.path) {
      result.success = false;
      result.error_messages.push('No destination folder is set for this job.');
      this.log('error', 'Full backup failed: no destination folder is set for this job.');
      this._writeLog(logFile, result);
      return result;
    }

    // Never record a 0-file backup as COMPLETED when the source is
    // missing — that was the old bug (source.path was undefined).
    if (!sourceDir || !fs.existsSync(sourceDir)) {
      result.success = false;
      result.error_messages.push(`Source folder does not exist: ${sourceDir || '(empty)'}`);
      this.log('error', `Full backup failed: source folder does not exist: ${sourceDir}`);
      this._writeLog(logFile, result);
      return result;
    }

    // A symlinked source folder is followed to its real path, so
    // relative entry names stay consistent (see _collectFiles).
    try { sourceDir = fs.realpathSync(sourceDir); } catch (e) {}

    // Single-file source: relative paths are computed from the file's
    // parent folder, so the backed-up file keeps its own name.
    let sourceBase;
    try {
      sourceBase = fs.statSync(sourceDir).isFile() ? path.dirname(sourceDir) : sourceDir;
    } catch (e) {
      result.success = false;
      result.error_messages.push(`Cannot read source: ${e.message}`);
      this.log('error', `Full backup failed: ${e.message}`);
      this._writeLog(logFile, result);
      return result;
    }

    // Create backup directory
    const backupSubDir = path.join(this.backupDir, backupName);
    if (!fs.existsSync(backupSubDir)) {
      fs.mkdirSync(backupSubDir, { recursive: true });
    }

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const zipPath = path.join(backupSubDir, `${backupName}_full_${stamp}.zip`);
    // No compression at all means: no ZIP. The backup is a plain folder
    // with the same files, same names, same folder structure — unless
    // encryption is on, which always needs a ZIP (stored + AES-256).
    const plainCopy = this.jobConfig.compression === 'none' && !this.jobConfig.encryptionEnabled;
    const copyDir = path.join(backupSubDir, `${backupName}_full_${stamp}`);
    if (plainCopy) fs.mkdirSync(copyDir, { recursive: true });
    // Never back the backup up into itself: when the destination
    // lives inside the source, the backup folder, the logs folder and
    // the state file are excluded from collection.
    const stateFile = path.join(backupSubDir, '.backup_state.json');
    const excludePaths = [path.resolve(backupSubDir), path.resolve(this.logsDir), path.resolve(stateFile)];

    this.log('info', `Starting FULL backup for job: ${this.jobConfig.name}`);
    this.log('info', `Source: ${sourceDir}`);
    this.log('info', `Destination: ${plainCopy ? copyDir + ' (plain files, no ZIP)' : zipPath + (this.jobConfig.encryptionEnabled ? ' (AES-256 encrypted)' : '')}`);

    try {
      // Stop support: a waiter the finalize race listens on, so a
      // stop during finalize ends the run at once. The flag itself
      // starts false in the constructor (one engine per run).
      this._cancelWait = new Promise((resolve) => { this._cancelResolve = resolve; });
      // Real progress: one metric — bytes actually read from the
      // source (plus bytes of skipped files) over total source bytes,
      // 0→99%. The old renderer-side fake bar raced to 92% and froze
      // there, and archiver's own 'progress' event fires only once per
      // file, so it cannot drive a smooth bar for one huge file
      // either. ZIP entries are therefore appended as counted read
      // streams (paused until archiver pipes them, so no chunk can
      // flow — and be lost — before archiver is listening).
      this._lastProgressPct = -1;
      let totalBytes = 0;
      let bytesDone = 0;
      let filesSeen = 0;
      let currentFileName = '';
      // Create ZIP archive (skipped for plain-copy backups)
      let archive = null;
      let outputClosed = null;
      let outputStream = null;
      // A failing source stream never surfaces as an archiver error
      // (verified against the installed archiver: the queue stalls
      // and finalize()/outputClosed never settle), so the stream's
      // own error handler rejects this promise and the finalize race
      // below fails the run cleanly instead of hanging forever.
      let streamError = null;
      let failArchive = null;
      const archiveFailed = new Promise((_, reject) => { failArchive = reject; });
      // These promises can reject while the file loop is still
      // running — before the race below attaches to them. Mark the
      // rejections handled at once; the race still reports them.
      archiveFailed.catch(() => {});
      const onStreamError = (err) => {
        if (!streamError) {
          streamError = err;
          if (failArchive) failArchive(err);
          // Release the output file handle so the partial ZIP can be
          // deleted by the failure path.
          try { if (outputStream) outputStream.destroy(); } catch (e) {}
        }
      };
      if (!plainCopy) {
        const output = fs.createWriteStream(zipPath);
        outputStream = output;
        archive = this.jobConfig.createArchive();
        // An archiver error must settle the run as a failure through
        // outputClosed's reject (below) — the old listener threw here,
        // which is an uncaught exception in an async event handler:
        // it skipped the reject listener, so the backup promise never
        // settled and the UI hung forever.
        archive.on('progress', prog => {
          this.log('debug', `Processed: ${prog.entries.processed}/${prog.entries.total}`);
        });
        // finalize() resolves when archiver finishes queueing, NOT when
        // the file is fully written — awaiting only it returned while
        // the ZIP was still truncated (no central directory). Wait for
        // the output stream to close before the backup is "done".
        outputClosed = new Promise((resolve, reject) => {
          output.on('close', resolve);
          output.on('error', reject);
          archive.on('error', reject);
        });
        // The archive can emit 'error' while the file loop is still
        // running, before the race below awaits this promise — mark
        // the rejection handled now; the race still reports it.
        outputClosed.catch(() => {});
        output.on('close', () => {
          this.log('info', `Archive created: ${archive.pointer()} bytes`);
        });
        archive.pipe(output);
        // Stop support: requestCancel() aborts this archive and
        // destroys this output stream.
        this._activeArchive = archive;
        this._activeOutput = outputStream;
      }

      // Collect all files
      const files = this._collectFiles(sourceDir, excludePaths);
      this.log('info', `Found ${files.length} files to backup`);
      // Unreadable subtrees found during collection are failures, not
      // silent omissions: report them instead of a clean COMPLETED.
      for (const ce of this._collectErrors) {
        result.files_failed++;
        result.error_messages.push(ce);
        this.log('error', ce);
      }
      this._collectErrors = [];
      // Stable denominator for real progress: total bytes of all files.
      for (const f of files) { try { totalBytes += fs.statSync(f).size; } catch (e) {} }
      const emitLive = (name) => {
        this._emitProgress(99 * bytesDone / (totalBytes || 1), plainCopy ? 'copying' : 'writing', name, filesSeen, files.length, bytesDone, totalBytes);
      };
      // Files that are never read (excluded, locked, failed, or not
      // included) still count, so the bar keeps moving past them.
      // `counted` is how many bytes of this file already flowed through
      // a data handler — a file that failed halfway must not be
      // counted twice (the old code added its full size on top).
      const markSkipped = (size, name, counted) => {
        bytesDone += Math.max(0, size - (counted || 0));
        filesSeen++;
        emitLive(name);
      };
      // Info (size/mtime/hash) of files actually backed up in this
      // run — the state file is built from this, and only this.
      const backedUpInfo = new Map();

      for (const file of files) {
        let stats = null;
        try { stats = fs.statSync(file); } catch (e) {}
        const fileSize = stats ? stats.size : 0;
        let fileCounted = 0;
        try {
          // Stop requested (between files): end the run now — the
          // outer catch deletes the partial artifact and records
          // the run as cancelled.
          if (this._cancelRequested) throw new BackupCancelled();
          const relativePath = path.relative(sourceBase, file).replace(/\\/g, '/');
          currentFileName = relativePath;

          if (this.jobConfig.shouldExclude(file)) {
            this.log('debug', `Excluded: ${relativePath}`);
            result.files_skipped++;
            markSkipped(fileSize, relativePath, 0);
            continue;
          }

          if (!this.jobConfig.shouldInclude(file)) {
            result.files_skipped++;
            markSkipped(fileSize, relativePath, 0);
            continue;
          }

          // Check if file is locked (VSS not implemented - skip locked files)
          try {
            // Try to access the file - will throw EACCES if locked
            fs.accessSync(file, fs.constants.R_OK);
          } catch (e) {
            if (e.code === 'EACCES' || e.code === 'EPERM') {
              // File is locked or permission denied - skip as SKIPPED-LOCKED
              result.locked_files_skipped++;
              result.files_skipped++;
              this.log('warn', `[SKIPPED-LOCKED] ${relativePath}: ${e.code} - VSS deferred, use vssadmin for locked files`);
              result.error_messages.push(`SKIPPED-LOCKED: ${relativePath}: ${e.code}`);
              markSkipped(fileSize, relativePath, 0);
              continue;
            }
          }

          // A file that vanished after collection must not fail the
          // whole run: archive.file() used to warn and skip it, so do
          // the same here instead of appending a broken stream.
          if (!stats) {
            result.files_failed++;
            result.error_messages.push(`Failed to backup ${file}: file disappeared before it could be read`);
            this.log('error', `Failed to backup ${file}: file disappeared before it could be read`);
            markSkipped(0, relativePath, 0);
            continue;
          }

          // The state must record the hash of the bytes that actually
          // went into the backup — not a separate pre-read. A file
          // edited mid-run used to get the pre-read hash in the state
          // while the archive held different bytes (and the next
          // incremental then trusted the wrong hash). So the hash is
          // computed from the same stream that feeds the archive /
          // the plain copy: for a plain copy it is final as soon as
          // the copy finishes; for a ZIP it resolves when the stream
          // has been fully consumed (after finalize, below).
          const fileInfo = { path: file, size: stats.size, mtime: stats.mtimeMs, hash: null };
          const hashState = { hash: null };

          // File is readable: copy it as-is, or add it to the ZIP
          if (plainCopy) {
            const copied = await this._copyPlainFile(file, sourceBase, copyDir, (n) => {
              bytesDone += n;
              fileCounted += n;
              emitLive(relativePath);
            });
            // The plain copy finished here: its hash IS the hash of
            // the backed-up bytes.
            fileInfo.hash = copied.hash;
            fileInfo.size = copied.size;
          } else {
            // Counted read stream: archiver reads the file through it
            // while compressing, so the bytes that flow ARE the real
            // work. The stream passes through a hashing Transform so
            // the hash is of the exact bytes archiver received
            // (pipe() applies backpressure, so a huge file cannot
            // grow the buffer unboundedly).
            const hash = crypto.createHash('sha256');
            const tee = new Transform({
              transform(chunk, encoding, callback) {
                hash.update(chunk);
                bytesDone += chunk.length;
                fileCounted += chunk.length;
                emitLive(relativePath);
                callback(null, chunk);
              },
              flush(callback) { hashState.hash = hash.digest('hex'); callback(); }
            });
            const rs = fs.createReadStream(file);
            // Stop support: requestCancel() destroys this stream, so
            // a stop while the gate waits settles it at once.
            this._activeStreams = { rs: rs, tee: null };
            // Gate: wait until the stream has its first chunk (or EOF)
            // BEFORE handing it to archiver. A file that fails to open
            // or read at all (deleted mid-run, transient error) is then
            // caught by the per-file catch below and counted as one
            // failed file — instead of stalling archiver's queue and
            // failing the whole run. The gate's error listener must
            // CAPTURE the error into gateError (not just reject the
            // gate promise): the stream fills its buffer synchronously
            // after the first chunk, so an error can fire before the
            // await continuation runs — a bare once('error', reject)
            // would swallow it and the run would hang in finalize on
            // the stalled stream.
            let gateError = null;
            const onGateError = (err) => { if (!gateError) gateError = err; };
            rs.on('error', onGateError);
            await new Promise((resolve) => {
              rs.once('readable', resolve);
              rs.once('error', resolve);
              rs.once('end', resolve);
            });
            rs.removeListener('error', onGateError);
            if (gateError) throw gateError;
            // A stream error needs its own listener (otherwise it is
            // an uncaught exception) and it must fail the run: see
            // onStreamError — archiver alone never reports it.
            rs.on('error', onStreamError);
            tee.on('error', onStreamError);
            rs.pipe(tee);
            this._activeStreams = { rs: rs, tee: tee };
            archive.append(tee, { name: relativePath, stats });
            // From here the stream belongs to archiver (a stop aborts
            // the archive instead of destroying the stream).
            this._activeStreams = null;
          }
          backedUpInfo.set(relativePath, { info: fileInfo, hashState: hashState });
          result.files_backed_up++;
          result.total_bytes += fileSize;
          this.log('info', `Backed up: ${relativePath}`);
          filesSeen++;
        } catch (err) {
          // A stop turns into a cancelled run, not a failed file:
          // rethrow so the outer catch handles the cleanup.
          if (this._cancelRequested || (err && err.code === 'BACKUP_CANCELLED')) throw new BackupCancelled();
          // A file that fails on the actual read (locked between the
          // probe and the read, deleted mid-run, I/O error) is a
          // locked skip when the OS says so, a failure otherwise —
          // never a silent success.
          if (err && (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EBUSY')) {
            result.locked_files_skipped++;
            result.files_skipped++;
            this.log('warn', `[SKIPPED-LOCKED] ${file}: ${err.code} - VSS deferred`);
            result.error_messages.push(`SKIPPED-LOCKED: ${file}: ${err.code}`);
          } else {
            result.files_failed++;
            result.error_messages.push(`Failed to backup ${file}: ${err.message}`);
            this.log('error', `Failed to backup ${file}: ${err.message}`);
          }
          markSkipped(fileSize, file, fileCounted);
        }
      }

      if (!plainCopy) {
        // Race the normal completion against a source-stream failure:
        // archiver never reports a failing stream, so without this
        // race the run would hang here forever. The loser's rejection
        // is swallowed — the race reports the outcome. The cancel
        // waiter joins the race so a stop during finalize ends the
        // run at once instead of waiting for the archive to finish.
        const normalPath = (async () => { await archive.finalize(); await outputClosed; })();
        normalPath.catch(() => {});
        await Promise.race([normalPath, archiveFailed, this._cancelWait]);
        // A stop during finalize ends the run here — the archive is
        // aborted by requestCancel and the partial ZIP is deleted by
        // the outer catch, like any other cancellation.
        if (this._cancelRequested) throw new BackupCancelled();
        if (streamError) throw streamError;
        this._activeArchive = null;
        this._activeOutput = null;
      }

      // Set the backup path on result
      result.backup_path = plainCopy ? copyDir : zipPath;
      result.backup_format = plainCopy ? 'folder' : (this.jobConfig.encryptionEnabled ? 'zip-encrypted' : 'zip');
      result.encrypted = this.jobConfig.encryptionEnabled;

      // Save state for incremental backups: a FRESH state built only
      // from the files this run actually backed up. The old code
      // re-hashed every included file after the run — so excluded
      // files, locked files and files that failed all got recorded as
      // backed up, and the next incremental silently skipped them
      // forever. Files deleted from the source drop out of the state
      // with the rebuild, instead of accumulating forever.
      const backupState = new BackupState(stateFile);
      backupState.state = {};
      backupState.setBaseDir(sourceBase);
      for (const [relativePath, entry] of backedUpInfo) {
        // A stop that lands while the state is being built still
        // cancels the run (the complete ZIP is removed by the catch
        // — a cancelled run leaves no artifact behind).
        if (this._cancelRequested) throw new BackupCancelled();
        // The ZIP-path hash resolves only once the stream was fully
        // consumed (after finalize, which already happened above);
        // the plain-copy hash was final at copy time. Either way the
        // state now records the hash of the bytes that actually went
        // into the backup. If a hash somehow never resolved (a stream
        // that never flushed), fall back to one fresh read rather
        // than recording a null hash the next incremental would
        // misread as "unchanged".
        if (entry.hashState.hash) entry.info.hash = entry.hashState.hash;
        else entry.info.hash = await this.calculateHash(entry.info.path);
        backupState.state[relativePath] = entry.info;
      }
      backupState.save();

      // A plain-folder backup gets a SHA-256 manifest of the bytes
      // that were actually written, so a restore can verify each
      // file instead of trusting the copy. Written after the copy
      // loop, so it describes the finished backup — never a
      // half-written one. (ZIP backups need none: every entry
      // already carries its own CRC32, checked at restore time.)
      if (plainCopy) {
        const manifest = { version: 1, files: {} };
        for (const [relativePath, entry] of backedUpInfo) {
          manifest.files[relativePath] = { sha256: entry.info.hash, size: entry.info.size };
        }
        fs.writeFileSync(path.join(copyDir, '.techvision-manifest.json'), JSON.stringify(manifest, null, 2));
      }

      // A full backup that archived 0 files (empty source, everything
      // excluded, or all files locked) must not be reported COMPLETED —
      // and neither must a run where any file failed OR any file was
      // skipped because it was locked: 99 of 100 files is a partial
      // backup, not a completed one.
      result.success = result.files_backed_up > 0 && result.files_failed === 0 && result.locked_files_skipped === 0;
      if (result.files_backed_up === 0) result.error_messages.push('No files were backed up (source empty, everything excluded, or all files locked).');
      if (result.files_failed > 0) result.error_messages.push(`${result.files_failed} file(s) failed to back up — see the log for details.`);
      if (result.locked_files_skipped > 0) result.error_messages.push(`${result.locked_files_skipped} file(s) skipped because they were locked — the backup is incomplete, see the log for details.`);
      const duration = (Date.now() - startTime) / 1000;
      result.duration_seconds = duration;
      const mbSize = (result.total_bytes / 1024 / 1024).toFixed(2);
      this.log('info', `Full backup completed: ${result.files_backed_up} files, ${mbSize} MB`);
      this.log('info', `Duration: ${duration.toFixed(2)}s`);

    } catch (err) {
      result.success = false;
      // A stop is a cancelled run, not a failure: one clean message,
      // no failure email (main.js keys off result.cancelled), and
      // the partial artifact is removed — a failed plain-copy folder
      // keeps the files that did copy, but a cancelled run leaves
      // nothing behind at all.
      if (this._cancelRequested || (err && err.code === 'BACKUP_CANCELLED')) {
        result.cancelled = true;
        result.error_messages = ['Backup stopped by user'];
        result.duration_seconds = (Date.now() - startTime) / 1000;
        this.log('info', 'Full backup stopped by user');
        if (plainCopy) {
          try { if (fs.existsSync(copyDir)) fs.rmSync(copyDir, { recursive: true, force: true }); } catch (e) {}
        } else {
          try { if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); } catch (e) {}
        }
      } else {
        result.error_messages.push(err.message);
        this.log('error', `Full backup failed: ${err.message}`);
        // A failed ZIP is truncated (no central directory) — delete it
        // so it can never be mistaken for a valid backup. A failed
        // plain-copy folder keeps the files that did copy (only the
        // failed file's partial is removed, in _copyPlainFile).
        if (!plainCopy) {
          try { if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); } catch (e) {}
        }
      }
    } finally {
      this._activeArchive = null;
      this._activeOutput = null;
      this._activeStreams = null;
    }

    this._writeLog(logFile, result);
    return result;
  }

  /**
   * Run incremental backup
   */
  async run_incremental_backup() {
    const result = new BackupResult();
    const startTime = Date.now();
    const logFile = path.join(this.logsDir, `incremental_backup_${new Date().toISOString().replace(/[:.]/g, '-')}.log`);
    result.log_file = logFile;

    let sourceDir = this.jobConfig.source.path;
    const backupName = this.backupName;

    if (this._initError) {
      result.success = false;
      result.error_messages.push(`Cannot use destination: ${this._initError.message}`);
      this.log('error', `Incremental backup failed: ${this._initError.message}`);
      this._writeLog(logFile, result);
      return result;
    }
    if (!this.jobConfig.destination || !this.jobConfig.destination.path) {
      result.success = false;
      result.error_messages.push('No destination folder is set for this job.');
      this.log('error', 'Incremental backup failed: no destination folder is set for this job.');
      this._writeLog(logFile, result);
      return result;
    }

    if (!sourceDir || !fs.existsSync(sourceDir)) {
      result.success = false;
      result.error_messages.push(`Source folder does not exist: ${sourceDir || '(empty)'}`);
      this.log('error', `Incremental backup failed: source folder does not exist: ${sourceDir}`);
      this._writeLog(logFile, result);
      return result;
    }

    try { sourceDir = fs.realpathSync(sourceDir); } catch (e) {}

    // Create backup directory
    const backupSubDir = path.join(this.backupDir, backupName);
    if (!fs.existsSync(backupSubDir)) {
      fs.mkdirSync(backupSubDir, { recursive: true });
    }

    // Initialize backup state
    const stateFile = path.join(backupSubDir, '.backup_state.json');
    const backupState = new BackupState(stateFile);
    let sourceBaseInc;
    try {
      sourceBaseInc = fs.statSync(sourceDir).isFile() ? path.dirname(sourceDir) : sourceDir;
    } catch (e) {
      result.success = false;
      result.error_messages.push(`Cannot read source: ${e.message}`);
      this.log('error', `Incremental backup failed: ${e.message}`);
      this._writeLog(logFile, result);
      return result;
    }
    backupState.setBaseDir(sourceBaseInc);

    const stampInc = new Date().toISOString().replace(/[:.]/g, '-');
    const zipPath = path.join(backupSubDir, `${backupName}_incremental_${stampInc}.zip`);
    const plainCopyInc = this.jobConfig.compression === 'none' && !this.jobConfig.encryptionEnabled;
    const copyDirInc = path.join(backupSubDir, `${backupName}_incremental_${stampInc}`);
    if (plainCopyInc) fs.mkdirSync(copyDirInc, { recursive: true });
    // Same exclusion as full backups: never back the backup up into
    // itself when the destination lives inside the source.
    const excludePathsInc = [path.resolve(backupSubDir), path.resolve(this.logsDir), path.resolve(stateFile)];

    this.log('info', `Starting INCREMENTAL backup for job: ${this.jobConfig.name}`);
    this.log('info', `Source: ${sourceDir}`);
    this.log('info', `Destination: ${plainCopyInc ? copyDirInc + ' (plain files, no ZIP)' : zipPath + (this.jobConfig.encryptionEnabled ? ' (AES-256 encrypted)' : '')}`);

    try {
      // Stop support: a waiter the finalize race listens on (see the
      // full backup — the flag itself starts false in the constructor).
      this._cancelWait = new Promise((resolve) => { this._cancelResolve = resolve; });
      // Get previous state
      const prevState = backupState.state;

      // Real progress — same scheme as full backups: bytes actually
      // read (plus bytes of skipped files) over total source bytes.
      this._lastProgressPct = -1;
      let totalBytes = 0;
      let bytesDone = 0;
      let filesSeen = 0;
      let currentFileName = '';

      // Create ZIP archive (skipped for plain-copy backups)
      let archive = null;
      let outputClosed = null;
      let outputStream = null;
      // See the full backup: a failing source stream never surfaces
      // as an archiver error, so the stream's own error handler
      // rejects this promise and the finalize race fails the run.
      let streamError = null;
      let failArchive = null;
      const archiveFailed = new Promise((_, reject) => { failArchive = reject; });
      archiveFailed.catch(() => {});
      const onStreamError = (err) => {
        if (!streamError) {
          streamError = err;
          if (failArchive) failArchive(err);
          try { if (outputStream) outputStream.destroy(); } catch (e) {}
        }
      };
      if (!plainCopyInc) {
        const output = fs.createWriteStream(zipPath);
        outputStream = output;
        archive = this.jobConfig.createArchive();
        // An archiver error must settle the run as a failure through
        // outputClosed's reject (below) — the old listener threw here,
        // which is an uncaught exception in an async event handler:
        // it skipped the reject listener, so the backup promise never
        // settled and the UI hung forever.
        archive.on('progress', prog => {
          this.log('debug', `Processed: ${prog.entries.processed}/${prog.entries.total}`);
        });
        // Same as full backups: finalize() alone does not mean the file
        // is fully written — wait for the output stream to close.
        outputClosed = new Promise((resolve, reject) => {
          output.on('close', resolve);
          output.on('error', reject);
          archive.on('error', reject);
        });
        outputClosed.catch(() => {}); // see the full backup
        output.on('close', () => {
          this.log('info', `Archive created: ${archive.pointer()} bytes`);
        });
        archive.pipe(output);
        // Stop support: requestCancel() aborts this archive and
        // destroys this output stream.
        this._activeArchive = archive;
        this._activeOutput = outputStream;
      }

      // Collect current files
      const currentFiles = this._collectFiles(sourceDir, excludePathsInc);
      let filesNeedingBackup = 0;
      // Files actually backed up in THIS run (relative path -> { info, hashState }):
      // the state and the integrity manifest are built from this after
      // finalize, once every stream hash has resolved.
      const incBackedUp = new Map();
      for (const f of currentFiles) { try { totalBytes += fs.statSync(f).size; } catch (e) {} }
      const emitLive = (name) => {
        this._emitProgress(99 * bytesDone / (totalBytes || 1), plainCopyInc ? 'copying' : 'writing', name, filesSeen, currentFiles.length, bytesDone, totalBytes);
      };
      const markSkipped = (size, name, counted) => {
        bytesDone += Math.max(0, size - (counted || 0));
        filesSeen++;
        emitLive(name);
      };

      for (const file of currentFiles) {
        let stats = null;
        try { stats = fs.statSync(file); } catch (e) {}
        const fileSize = stats ? stats.size : 0;
        let fileCounted = 0;
        try {
          // Stop requested (between files): end the run now — the
          // outer catch deletes the partial artifact and records
          // the run as cancelled.
          if (this._cancelRequested) throw new BackupCancelled();
          const relativePath = path.relative(sourceBaseInc, file).replace(/\\/g, '/');
          currentFileName = relativePath;

          if (this.jobConfig.shouldExclude(file)) {
            this.log('debug', `Excluded: ${relativePath}`);
            result.files_skipped++;
            markSkipped(fileSize, relativePath, 0);
            continue;
          }

          if (!this.jobConfig.shouldInclude(file)) {
            result.files_skipped++;
            markSkipped(fileSize, relativePath, 0);
            continue;
          }

          // Check if file is locked (VSS not implemented - skip locked files)
          try {
            fs.accessSync(file, fs.constants.R_OK);
          } catch (e) {
            if (e.code === 'EACCES' || e.code === 'EPERM') {
              result.locked_files_skipped++;
              result.files_skipped++;
              this.log('warn', `[SKIPPED-LOCKED] ${relativePath}: ${e.code} - VSS deferred`);
              result.error_messages.push(`SKIPPED-LOCKED: ${relativePath}: ${e.code}`);
              markSkipped(fileSize, relativePath, 0);
              continue;
            }
          }

          // Does this file need backing up? Size + mtime first (cheap):
          // only when they match do we hash to confirm it is really
          // unchanged. The old code hashed every file in full before
          // even looking at size/mtime, so a changed 10 GB file was
          // read twice for no reason.
          const prevInfo = prevState[relativePath];
          let currentInfo = null;
          let needsBackup;
          // mtime is stored as stats.mtimeMs (a number) by
          // getFileInfo — comparing it with stats.mtime (a Date)
          // is always false and would re-back up every file.
          if (prevInfo && stats && prevInfo.size === stats.size && prevInfo.mtime === stats.mtimeMs) {
            currentInfo = await this.getFileInfo(file);
            needsBackup = this._needsBackup(file, prevInfo, currentInfo);
          } else {
            needsBackup = true; // new file, or size/mtime changed
          }

          if (needsBackup) {
            // A file that vanished after collection must not fail the
            // whole run (same guard as full backups).
            if (!stats) {
              result.files_failed++;
              result.error_messages.push(`Failed to backup ${file}: file disappeared before it could be read`);
              this.log('error', `Failed to backup ${file}: file disappeared before it could be read`);
              markSkipped(0, relativePath, 0);
              // No state update: the next run retries it.
              continue;
            }
            // The state must record the hash of the bytes that
            // actually went into this backup (same rule as full
            // backups): the plain-copy hash is final when the copy
            // finishes; the ZIP hash resolves after finalize.
            const incHashState = { hash: null };
            if (plainCopyInc) {
              const copied = await this._copyPlainFile(file, sourceBaseInc, copyDirInc, (n) => {
                bytesDone += n;
                fileCounted += n;
                emitLive(relativePath);
              });
              currentInfo = { path: file, size: copied.size, mtime: stats.mtimeMs, hash: copied.hash };
              result.files_backed_up++;
              result.total_bytes += fileSize;
              filesNeedingBackup++;
              this.log('info', `Incremental update: ${relativePath}`);
              filesSeen++;
            } else {
              const hash = crypto.createHash('sha256');
              const tee = new Transform({
                transform(chunk, encoding, callback) {
                  hash.update(chunk);
                  bytesDone += chunk.length;
                  fileCounted += chunk.length;
                  emitLive(relativePath);
                  callback(null, chunk);
                },
                flush(callback) { incHashState.hash = hash.digest('hex'); callback(); }
              });
              const rs = fs.createReadStream(file);
              // Stop support: requestCancel() destroys this stream,
              // so a stop while the gate waits settles it at once.
              this._activeStreams = { rs: rs, tee: null };
              // Same gate as full backups: a file that fails to open
              // or read at all is one failed file, not a failed run
              // (the error is captured, never swallowed — see the
              // full-backup gate comment).
              let gateError = null;
              const onGateError = (err) => { if (!gateError) gateError = err; };
              rs.on('error', onGateError);
              await new Promise((resolve) => {
                rs.once('readable', resolve);
                rs.once('error', resolve);
                rs.once('end', resolve);
              });
              rs.removeListener('error', onGateError);
              if (gateError) throw gateError;
              // See the full-backup loop: the stream error must fail
              // the run through onStreamError, archiver never does.
              rs.on('error', onStreamError);
              tee.on('error', onStreamError);
              rs.pipe(tee);
              this._activeStreams = { rs: rs, tee: tee };
              archive.append(tee, { name: relativePath, stats });
              // From here the stream belongs to archiver (a stop aborts
              // the archive instead of destroying the stream).
              this._activeStreams = null;
              currentInfo = { path: file, size: stats.size, mtime: stats.mtimeMs, hash: null };
              result.files_backed_up++;
              result.total_bytes += fileSize;
              filesNeedingBackup++;
              this.log('info', `Incremental update: ${relativePath}`);
              filesSeen++;
            }
            if (currentInfo) {
              backupState.set(file, currentInfo);
              incBackedUp.set(relativePath, { info: currentInfo, hashState: incHashState });
            }
          } else {
            result.files_skipped++;
            this.log('debug', `Skipped (unchanged): ${relativePath}`);
            markSkipped(fileSize, relativePath, 0);
            // Unchanged: refresh the state entry with the (identical)
            // info so the state stays in sync.
            if (currentInfo) backupState.set(file, currentInfo);
          }
        } catch (err) {
          // A stop turns into a cancelled run, not a failed file:
          // rethrow so the outer catch handles the cleanup.
          if (this._cancelRequested || (err && err.code === 'BACKUP_CANCELLED')) throw new BackupCancelled();
          if (err && (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EBUSY')) {
            result.locked_files_skipped++;
            result.files_skipped++;
            this.log('warn', `[SKIPPED-LOCKED] ${file}: ${err.code} - VSS deferred`);
            result.error_messages.push(`SKIPPED-LOCKED: ${file}: ${err.code}`);
          } else {
            result.files_failed++;
            result.error_messages.push(`Failed to backup ${file}: ${err.message}`);
            this.log('error', `Failed to backup ${file}: ${err.message}`);
          }
          markSkipped(fileSize, file, fileCounted);
        }
      }

      if (!plainCopyInc) {
        const normalPath = (async () => { await archive.finalize(); await outputClosed; })();
        normalPath.catch(() => {});
        // The cancel waiter joins the race so a stop during finalize
        // ends the run at once (see the full backup).
        await Promise.race([normalPath, archiveFailed, this._cancelWait]);
        // A stop during finalize ends the run here — the archive is
        // aborted by requestCancel and the partial ZIP is deleted by
        // the outer catch, like any other cancellation.
        if (this._cancelRequested) throw new BackupCancelled();
        if (streamError) throw streamError;
        this._activeArchive = null;
        this._activeOutput = null;
      }

      // Set the backup path on result
      result.backup_path = plainCopyInc ? copyDirInc : zipPath;
      result.backup_format = plainCopyInc ? 'folder' : (this.jobConfig.encryptionEnabled ? 'zip-encrypted' : 'zip');
      result.encrypted = this.jobConfig.encryptionEnabled;

      // Resolve the streamed hashes now that every stream has been
      // fully consumed (after finalize). A hash that never resolved
      // falls back to one fresh read, never a null. The state entries
      // were stored by reference, so mutating the info objects here
      // updates what gets saved.
      for (const [relativePath, entry] of incBackedUp) {
        // A stop that lands while the hashes resolve still cancels
        // the run (the complete ZIP is removed by the catch — a
        // cancelled run leaves no artifact behind).
        if (this._cancelRequested) throw new BackupCancelled();
        if (entry.hashState.hash) entry.info.hash = entry.hashState.hash;
        else entry.info.hash = await this.calculateHash(entry.info.path);
      }
      // A plain-folder incremental gets the same SHA-256 manifest as
      // a full one, covering just this run's files.
      if (plainCopyInc) {
        const manifest = { version: 1, files: {} };
        for (const [relativePath, entry] of incBackedUp) {
          manifest.files[relativePath] = { sha256: entry.info.hash, size: entry.info.size };
        }
        fs.writeFileSync(path.join(copyDirInc, '.techvision-manifest.json'), JSON.stringify(manifest, null, 2));
      }
      // Prune the state: files deleted from the source drop out, so
      // the state file stops growing forever and cannot resurrect
      // deleted files into the next incremental's decisions.
      const liveKeys = new Set(currentFiles.map((f) => path.relative(sourceBaseInc, f).replace(/\\/g, '/')));
      for (const key of Object.keys(backupState.state)) {
        if (key !== '__meta__' && key !== '__base_dir__' && !liveKeys.has(key)) delete backupState.state[key];
      }
      // Save updated state
      backupState.save();

      // An incremental that failed on any file — or skipped any file
      // because it was locked — must not report success. Zero changed
      // files is still a success (nothing to do).
      result.success = result.files_failed === 0 && result.locked_files_skipped === 0;
      if (result.files_failed > 0) result.error_messages.push(`${result.files_failed} file(s) failed to back up — see the log for details.`);
      if (result.locked_files_skipped > 0) result.error_messages.push(`${result.locked_files_skipped} file(s) skipped because they were locked — the backup is incomplete, see the log for details.`);
      const duration = (Date.now() - startTime) / 1000;
      result.duration_seconds = duration;
      const mbSize = (result.total_bytes / 1024 / 1024).toFixed(2);
      this.log('info', `Incremental backup completed: ${result.files_backed_up} files, ${mbSize} MB`);
      this.log('info', `Files skipped: ${result.files_skipped}, Files updated: ${filesNeedingBackup}`);
      this.log('info', `Duration: ${duration.toFixed(2)}s`);

    } catch (err) {
      result.success = false;
      // A stop is a cancelled run, not a failure (see the full
      // backup): one clean message, no failure email, and the
      // partial artifact is removed — including the plain-copy
      // folder, which a failed run keeps.
      if (this._cancelRequested || (err && err.code === 'BACKUP_CANCELLED')) {
        result.cancelled = true;
        result.error_messages = ['Backup stopped by user'];
        result.duration_seconds = (Date.now() - startTime) / 1000;
        this.log('info', 'Incremental backup stopped by user');
        if (plainCopyInc) {
          try { if (fs.existsSync(copyDirInc)) fs.rmSync(copyDirInc, { recursive: true, force: true }); } catch (e) {}
        } else {
          try { if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); } catch (e) {}
        }
      } else {
        result.error_messages.push(err.message);
        this.log('error', `Incremental backup failed: ${err.message}`);
        if (!plainCopyInc) {
          try { if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); } catch (e) {}
        }
      }
    } finally {
      this._activeArchive = null;
      this._activeOutput = null;
      this._activeStreams = null;
    }

    this._writeLog(logFile, result);
    return result;
  }

  /**
   * Check if file needs backup
   */
  _needsBackup(filePath, prevInfo, currentInfo) {
    if (!prevInfo) {
      return true;
    }

    // Check size and mtime first (faster)
    if (prevInfo.size !== currentInfo.size || prevInfo.mtime !== currentInfo.mtime) {
      return true;
    }

    // Check hash
    if (prevInfo.hash !== currentInfo.hash) {
      return true;
    }

    return false;
  }

  /**
   * Collect all files from directory. Symlinked directories are
   * skipped (a symlink loop used to recurse until the stack overflowed
   * and the same file landed in the ZIP dozens of times); symlinked
   * files are backed up by content, as before. `excludePaths` are
   * absolute paths (the backup folder itself, the logs folder, the
   * state file) that must never be collected when the destination
   * lives inside the source.
   */
  _collectFiles(dir, excludePaths) {
    const files = [];

    if (!fs.existsSync(dir)) {
      return files;
    }
    // Single-file source: the backup is just that one file.
    // (A symlinked source folder itself is followed here — the loop
    // risk is only from links *inside* the tree, which are skipped
    // below — but the run methods resolve the source to its real path
    // first, so this stays consistent.)
    try {
      if (fs.statSync(dir).isFile()) return [dir];
    } catch (e) {
      return files;
    }

    const isExcluded = (p) => {
      if (!excludePaths || !excludePaths.length) return false;
      const abs = path.resolve(p);
      return excludePaths.some((x) => abs === x || abs.startsWith(x + path.sep));
    };
    if (isExcluded(dir)) return files;

    const items = fs.readdirSync(dir);

    for (const item of items) {
      const fullPath = path.join(dir, item);

      try {
        const lst = fs.lstatSync(fullPath);

        if (lst.isSymbolicLink()) {
          // Resolve the target to decide: directory link -> skip
          // (prevents loops and escaping the source tree); file link
          // -> back up the target's content under the link's name.
          let targetIsDir = false;
          try { targetIsDir = fs.statSync(fullPath).isDirectory(); } catch (e) { targetIsDir = false; }
          if (targetIsDir) {
            this.log('warn', `Skipped symlinked directory: ${fullPath}`);
            continue;
          }
          files.push(fullPath);
          continue;
        }

        if (lst.isDirectory()) {
          if (isExcluded(fullPath)) continue;
          const subFiles = this._collectFiles(fullPath, excludePaths);
          files.push(...subFiles);
        } else {
          files.push(fullPath);
        }
      } catch (e) {
        // An unreadable subfolder used to vanish silently: the run
        // reported success while a whole subtree was missing. Record
        // it so the run reports the failure.
        this._collectErrors.push(`Cannot access: ${fullPath}: ${e.message}`);
        this.log('warn', `Cannot access: ${fullPath}`);
      }
    }

    return files;
  }

  /**
   * Logging
   */
  log(level, message) {
    const timestamp = new Date().toISOString();
    // Strip newlines: a file or job name containing \n could forge
    // log lines (log injection) in the written log files.
    const clean = String(message).replace(/[\r\n]+/g, ' ');
    const logMessage = `[${timestamp}] ${level.toUpperCase()}: ${clean}`;

    if (this.logger) {
      console.log(logMessage);
    }
  }

  _writeLog(logFile, result) {
    // No destination means no log folder either: never create ./logs
    // in the working directory for a job that has nowhere to back up to.
    if (!this.jobConfig.destination || !this.jobConfig.destination.path) return;
    // Writing the log must never throw the backup result away: a full
    // disk after a good ZIP used to make the caller see a throw
    // instead of the successful result.
    try {
      const content = [
        `== TechVision Backup Log ==`,
        `Backup: ${this.jobConfig.name}`,
        `Timestamp: ${result.timestamp}`,
        ``,
        `Result:`,
        `  Success: ${result.success}`,
        `  Files backed up: ${result.files_backed_up}`,
        `  Files skipped: ${result.files_skipped}`,
        `  Locked files skipped: ${result.locked_files_skipped}`,
        `  Files failed: ${result.files_failed}`,
        `  Total bytes: ${result.total_bytes}`,
        `  Duration: ${result.duration_seconds}s`,
        `  Log file: ${result.log_file}`,
        ``,
        result.error_messages.length > 0 ? `Errors:` : `No errors`,
        ...result.error_messages
      ].join('\n');

      const dir = path.dirname(logFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(logFile, content);
    } catch (e) {
      console.error('Error writing backup log:', e.message);
    }
  }
}

module.exports = {
  JobConfig,
  BackupEngine,
  BackupResult,
  BackupState
};