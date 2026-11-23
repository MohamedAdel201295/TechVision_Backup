/**
 * TechVision.Core - Backup Engine for Node.js
 * Ported from Python implementation
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const archiver = require('archiver');
const { EventEmitter } = require('events');

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
   * Get include patterns (minimum 1 char)
   */
  getIncludePatterns() {
    const patterns = this.source && this.source.include;
    if (!Array.isArray(patterns) || patterns.length === 0) {
      return ['*.*'];
    }
    return patterns.filter((p) => typeof p === 'string' && p.length > 0);
  }

  /**
   * Get exclude patterns
   */
  getExcludePatterns() {
    if (!this.source.exclude) {
      return [];
    }
    return this.source.exclude;
  }

  /**
   * Check if path should be included
   */
  shouldInclude(filePath) {
    const fileName = path.basename(filePath);
    const patterns = this.getIncludePatterns();
    
    for (const pattern of patterns) {
      if (typeof pattern !== 'string') continue;
      // Handle *.txt, *.pdf patterns - and *.* for all files
      if (pattern === '*' || pattern === '*.*') {
        return true;
      }
      if (pattern.startsWith('*')) {
        const ext = pattern.substring(1); // Get .txt or .*
        if (fileName.endsWith(ext)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check if path should be excluded
   */
  shouldExclude(filePath) {
    const patterns = this.getExcludePatterns();
    const fileName = path.basename(filePath);
    
    for (const pattern of patterns) {
      if (pattern.startsWith('*')) {
        const ext = pattern.substring(1);
        if (fileName.endsWith(ext)) {
          return true;
        }
      }
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
    fs.writeFileSync(this.stateFile, JSON.stringify(this.state, null, 2));
  }

  get(filePath) {
    const relative = path.relative(this.getBaseDir(), filePath).replace(/\\/g, '/');
    return this.state[relative];
  }

  set(filePath, info) {
    const relative = path.relative(this.getBaseDir(), filePath).replace(/\\/g, '/');
    this.state[relative] = info;
  }

  getBaseDir() {
    return this.state['__base_dir__'] || process.cwd();
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
    const destPath = (this.jobConfig.destination && this.jobConfig.destination.path) || '';
    this.logsDir = destPath ? path.join(destPath, 'logs') : './logs';
    this.backupDir = destPath || './backup';
    
    // Ensure directories exist
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
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
   */
  _copyPlainFile(file, sourceDir, destRoot) {
    const relativePath = path.relative(sourceDir, file).replace(/\\/g, '/');
    const dest = path.join(destRoot, relativePath);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(file, dest);
    return dest;
  }

  /**
   * Run full backup
   */
  async run_full_backup() {
    const result = new BackupResult();
    const startTime = Date.now();
    const logFile = path.join(this.logsDir, `full_backup_${new Date().toISOString().replace(/[:.]/g, '-')}.log`);
    result.log_file = logFile;

    const sourceDir = this.jobConfig.source.path;
    const backupName = path.basename(this.jobConfig.name);

    // Never record a 0-file backup as COMPLETED when the source is
    // missing — that was the old bug (source.path was undefined).
    if (!sourceDir || !fs.existsSync(sourceDir)) {
      result.success = false;
      result.error_messages.push(`Source folder does not exist: ${sourceDir || '(empty)'}`);
      this.log('error', `Full backup failed: source folder does not exist: ${sourceDir}`);
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
    // with the same files, same names, same folder structure.
    const plainCopy = this.jobConfig.compression === 'none';
    const copyDir = path.join(backupSubDir, `${backupName}_full_${stamp}`);
    if (plainCopy) fs.mkdirSync(copyDir, { recursive: true });

    this.log('info', `Starting FULL backup for job: ${this.jobConfig.name}`);
    this.log('info', `Source: ${sourceDir}`);
    this.log('info', `Destination: ${plainCopy ? copyDir + ' (plain files, no ZIP)' : zipPath}`);

    try {
      // Create ZIP archive (skipped for plain-copy backups)
      let archive = null;
      if (!plainCopy) {
        const output = fs.createWriteStream(zipPath);
        archive = archiver('zip', this.jobConfig.getArchiveOptions());
        archive.on('error', err => { throw err; });
        archive.on('progress', prog => {
          this.log('debug', `Processed: ${prog.entries.processed}/${prog.entries.total}`);
        });
        output.on('close', () => {
          this.log('info', `Archive created: ${archive.pointer()} bytes`);
        });
        archive.pipe(output);
      }

      // Collect all files
      const files = this._collectFiles(sourceDir);
      this.log('info', `Found ${files.length} files to backup`);

      for (const file of files) {
        try {
          const relativePath = path.relative(sourceDir, file).replace(/\\/g, '/');
          
          if (this.jobConfig.shouldExclude(file)) {
            this.log('debug', `Excluded: ${relativePath}`);
            result.files_skipped++;
            continue;
          }

          if (this.jobConfig.shouldInclude(file)) {
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
                continue;
              }
            }
            
            // File is readable: copy it as-is, or add it to the ZIP
            if (plainCopy) {
              this._copyPlainFile(file, sourceDir, copyDir);
            } else {
              archive.file(file, { name: relativePath });
            }
            result.files_backed_up++;
            result.total_bytes += fs.statSync(file).size;
            this.log('info', `Backed up: ${relativePath}`);
          }
        } catch (err) {
          result.files_failed++;
          result.error_messages.push(`Failed to backup ${file}: ${err.message}`);
          this.log('error', `Failed to backup ${file}: ${err.message}`);
        }
      }

      if (!plainCopy) await archive.finalize();

      // Set the backup path on result
      result.backup_path = plainCopy ? copyDir : zipPath;
      result.backup_format = plainCopy ? 'folder' : 'zip';

      // Save state for incremental backups
      const stateFile = path.join(backupSubDir, '.backup_state.json');
      const backupState = new BackupState(stateFile);
      backupState.state['__base_dir__'] = sourceDir;
      
      // Save file states
      for (const file of files) {
        try {
          if (this.jobConfig.shouldInclude(file)) {
            const relativePath = path.relative(sourceDir, file).replace(/\\/g, '/');
            const fileInfo = await this.getFileInfo(file);
            backupState.set(file, fileInfo);
          }
        } catch (e) {
          // Skip files that can't be processed
        }
      }
      backupState.save();
      
      // A full backup that archived 0 files (empty source, everything
      // excluded, or all files locked) must not be reported COMPLETED.
      result.success = result.files_backed_up > 0;
      if (!result.success) result.error_messages.push('No files were backed up (source empty, everything excluded, or all files locked).');
      const duration = (Date.now() - startTime) / 1000;
      result.duration_seconds = duration;
      const mbSize = (result.total_bytes / 1024 / 1024).toFixed(2);
      this.log('info', `Full backup completed: ${result.files_backed_up} files, ${mbSize} MB`);
      this.log('info', `Duration: ${duration.toFixed(2)}s`);

    } catch (err) {
      result.success = false;
      result.error_messages.push(err.message);
      this.log('error', `Full backup failed: ${err.message}`);
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

    const sourceDir = this.jobConfig.source.path;
    const backupName = path.basename(this.jobConfig.name);

    if (!sourceDir || !fs.existsSync(sourceDir)) {
      result.success = false;
      result.error_messages.push(`Source folder does not exist: ${sourceDir || '(empty)'}`);
      this.log('error', `Incremental backup failed: source folder does not exist: ${sourceDir}`);
      this._writeLog(logFile, result);
      return result;
    }

    // Create backup directory
    const backupSubDir = path.join(this.backupDir, backupName);
    if (!fs.existsSync(backupSubDir)) {
      fs.mkdirSync(backupSubDir, { recursive: true });
    }

    // Initialize backup state
    const stateFile = path.join(backupSubDir, '.backup_state.json');
    const backupState = new BackupState(stateFile);
    backupState.state['__base_dir__'] = sourceDir;

    const stampInc = new Date().toISOString().replace(/[:.]/g, '-');
    const zipPath = path.join(backupSubDir, `${backupName}_incremental_${stampInc}.zip`);
    const plainCopyInc = this.jobConfig.compression === 'none';
    const copyDirInc = path.join(backupSubDir, `${backupName}_incremental_${stampInc}`);
    if (plainCopyInc) fs.mkdirSync(copyDirInc, { recursive: true });

    this.log('info', `Starting INCREMENTAL backup for job: ${this.jobConfig.name}`);
    this.log('info', `Source: ${sourceDir}`);
    this.log('info', `Destination: ${plainCopyInc ? copyDirInc + ' (plain files, no ZIP)' : zipPath}`);

    try {
      // Get previous state
      const prevState = backupState.state;

      // Create ZIP archive (skipped for plain-copy backups)
      let archive = null;
      if (!plainCopyInc) {
        const output = fs.createWriteStream(zipPath);
        archive = archiver('zip', this.jobConfig.getArchiveOptions());
        archive.on('error', err => { throw err; });
        archive.on('progress', prog => {
          this.log('debug', `Processed: ${prog.entries.processed}/${prog.entries.total}`);
        });
        output.on('close', () => {
          this.log('info', `Archive created: ${archive.pointer()} bytes`);
        });
        archive.pipe(output);
      }

      // Collect current files
      const currentFiles = this._collectFiles(sourceDir);
      let filesNeedingBackup = 0;

      for (const file of currentFiles) {
        try {
          const relativePath = path.relative(sourceDir, file).replace(/\\/g, '/');
          
          if (this.jobConfig.shouldExclude(file)) {
            this.log('debug', `Excluded: ${relativePath}`);
            result.files_skipped++;
            continue;
          }

          if (!this.jobConfig.shouldInclude(file)) {
            result.files_skipped++;
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
              continue;
            }
          }

          // Check if file needs backup
          const currentInfo = await this.getFileInfo(file);
          const prevInfo = prevState[relativePath];
          const needsBackup = this._needsBackup(file, prevInfo, currentInfo);

          if (needsBackup) {
            if (plainCopyInc) {
              this._copyPlainFile(file, sourceDir, copyDirInc);
            } else {
              archive.file(file, { name: relativePath });
            }
            result.files_backed_up++;
            result.total_bytes += currentInfo.size;
            filesNeedingBackup++;
            this.log('info', `Incremental update: ${relativePath}`);
          } else {
            result.files_skipped++;
            this.log('debug', `Skipped (unchanged): ${relativePath}`);
          }

          // Update state
          backupState.set(file, currentInfo);
        } catch (err) {
          result.files_failed++;
          result.error_messages.push(`Failed to backup ${file}: ${err.message}`);
          this.log('error', `Failed to backup ${file}: ${err.message}`);
        }
      }

      if (!plainCopyInc) await archive.finalize();

      // Set the backup path on result
      result.backup_path = plainCopyInc ? copyDirInc : zipPath;
      result.backup_format = plainCopyInc ? 'folder' : 'zip';

      // Save updated state
      backupState.save();
      
      result.success = true;
      const duration = (Date.now() - startTime) / 1000;
      result.duration_seconds = duration;
      const mbSize = (result.total_bytes / 1024 / 1024).toFixed(2);
      this.log('info', `Incremental backup completed: ${result.files_backed_up} files, ${mbSize} MB`);
      this.log('info', `Files skipped: ${result.files_skipped}, Files updated: ${filesNeedingBackup}`);
      this.log('info', `Duration: ${duration.toFixed(2)}s`);

    } catch (err) {
      result.success = false;
      result.error_messages.push(err.message);
      this.log('error', `Incremental backup failed: ${err.message}`);
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
   * Collect all files from directory
   */
  _collectFiles(dir) {
    const files = [];
    
    if (!fs.existsSync(dir)) {
      return files;
    }

    const items = fs.readdirSync(dir);
    
    for (const item of items) {
      const fullPath = path.join(dir, item);
      
      try {
        const stats = fs.statSync(fullPath);
        
        if (stats.isDirectory()) {
          const subFiles = this._collectFiles(fullPath);
          files.push(...subFiles);
        } else {
          files.push(fullPath);
        }
      } catch (e) {
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
    const logMessage = `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    
    if (this.logger) {
      console.log(logMessage);
    }
  }

  _writeLog(logFile, result) {
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
  }
}

module.exports = {
  JobConfig,
  BackupEngine,
  BackupResult,
  BackupState
};