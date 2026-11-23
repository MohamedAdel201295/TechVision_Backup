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
    try {
      if (zipPath && fs.existsSync(zipPath) && !fs.statSync(zipPath).isDirectory()) {
        const info = zipAes.inspectZip(zipPath);
        if (info.encrypted) {
          if (!password) throw new Error('This backup is encrypted — a password is required to restore it.');
          if (!fs.existsSync(restoreDir)) fs.mkdirSync(restoreDir, { recursive: true });
          const zipData = new Map();
          const extracted = zipAes.extractEncrypted(zipPath, restoreDir, password, function (name, size) {
            result.files_restored++;
            result.total_bytes += size;
            zipData.set(name, fs.readFileSync(path.join(restoreDir, name.split('/').join(path.sep))));
          });
          result.errors = extracted.errors;
          // Hash-verify each restored file against its decrypted content.
          for (const [name, content] of zipData) {
            const restoredPath = path.join(restoreDir, name.split('/').join(path.sep));
            try {
              if (this.calculateHash(fs.readFileSync(restoredPath)) === this.calculateHash(content)) result.files_verified++;
              else { result.files_mismatched++; result.errors.push('Hash mismatch: ' + name); }
            } catch (e) { result.errors.push('Verification error: ' + name + ': ' + e.message); }
          }
          result.success = result.files_mismatched === 0 && result.errors.length === 0 && result.files_restored > 0;
          result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
          return result;
        }
      }
    } catch (e) {
      result.success = false;
      result.errors.push(e.message);
      result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
      return result;
    }
    // Plain-copy backup: backup_path is a folder with the same files,
    // not a ZIP. Restore is a straight copy back, same structure.
    try {
      if (zipPath && fs.existsSync(zipPath) && fs.statSync(zipPath).isDirectory()) {
        if (!fs.existsSync(restoreDir)) fs.mkdirSync(restoreDir, { recursive: true });
        const walk = (dir) => {
          for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const src = path.join(dir, entry.name);
            const dest = path.join(restoreDir, path.relative(zipPath, src));
            if (entry.isDirectory()) { fs.mkdirSync(dest, { recursive: true }); walk(src); }
            else { fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.copyFileSync(src, dest); result.files_restored++; result.total_size += fs.statSync(src).size; }
          }
        };
        walk(zipPath);
        result.success = result.files_restored > 0;
        result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
        return result;
      }
    } catch (e) {
      result.success = false;
      result.errors.push(e.message);
      result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
      return result;
    }
    const zipFiles = [];
    const zipData = new Map();
    const restoredSizes = [];
    
    return new Promise((resolve, reject) => {
      let pendingEntries = 0;
      
      // Ensure restore directory exists
      if (!fs.existsSync(restoreDir)) {
        fs.mkdirSync(restoreDir, { recursive: true });
      }

      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          result.success = false;
          result.errors.push(err.message);
          result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
          return resolve(result);
        }

        zipfile.readEntry();

        zipfile.on('entry', (entry) => {
          zipfile.readEntry();
          
          if (entry.externalAttributes >> 16 === 0x10) { // Directory entry
            return;
          }
          
          // File entry
          const entryPath = path.join(restoreDir, entry.fileName.replace(/\//g, path.sep));
          const dirName = path.dirname(entryPath);
          const fileSize = entry.uncompressedSize;
          
          zipFiles.push({
            path: entryPath,
            name: entry.fileName,
            size: fileSize
          });
          
          pendingEntries++;
          
          // Create directories
          if (!fs.existsSync(dirName)) {
            fs.mkdirSync(dirName, { recursive: true });
          }
          
          // Read entry
          zipfile.openReadStream(entry, (err, ReadStream) => {
            if (err) {
              result.errors.push(`Failed to open ${entry.fileName}: ${err.message}`);
              pendingEntries--;
              if (pendingEntries === 0) finish();
              return;
            }
            
            const chunks = [];
            
            ReadStream.on('data', (chunk) => {
              chunks.push(chunk);
            });
            
            ReadStream.on('end', () => {
              const content = Buffer.concat(chunks);
              const size = content.length;
              restoredSizes.push(size);
              zipData.set(entry.fileName, content);
              
              try {
                fs.writeFileSync(entryPath, content);
                result.files_restored++;
              } catch (e) {
                result.errors.push(`Failed to write ${entry.fileName}: ${e.message}`);
              }
              
              pendingEntries--;
              if (pendingEntries === 0) finish();
            });
            
            ReadStream.on('error', (err) => {
              result.errors.push(`Read error for ${entry.fileName}: ${err.message}`);
              pendingEntries--;
              if (pendingEntries === 0) finish();
            });
          });
        });

        const finish = () => {
          result.errors = [...new Set(result.errors)];
          result.total_bytes = restoredSizes.reduce((a, b) => a + b, 0);
          result.duration_seconds = Math.floor((Date.now() - startTime) / 1000);
          console.log(`    Found ${zipFiles.length} files in ZIP`);
          
          // Verify hashes
          for (const file of zipFiles) {
            const restoredPath = file.path;
            const originalContent = zipData.get(file.name);
            
            if (fs.existsSync(restoredPath) && originalContent) {
              try {
                const restoredContent = fs.readFileSync(restoredPath);
                const restoredHash = this.calculateHash(restoredContent);
                const originalHash = this.calculateHash(originalContent);
                
                if (restoredHash === originalHash) {
                  result.files_verified++;
                } else {
                  result.files_mismatched++;
                  result.errors.push(`Hash mismatch: ${file.name}`);
                }
              } catch (e) {
                result.errors.push(`Verification error: ${file.name}: ${e.message}`);
              }
            }
          }

          result.success = result.files_mismatched === 0;
          resolve(result);
        };
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
          
          if (entry.externalAttributes >> 16 !== 0x10) { // Not a directory
            entries.push({
              path: entry.fileName.replace(/\//g, path.sep),
              size: entry.uncompressedSize,
              isDir: false,
              encrypted: false
            });
          }
        });
        
        zipfile.on('end', () => {
          resolve(entries);
        });
      });
    });
  }

  /**
   * Restore single file to specific location
   */
  async restoreFile(zipPath, entryName, destPath, password) {
    // Encrypted entry: decrypt it directly with the AES reader.
    // (If the inspector cannot read this ZIP at all — e.g. Zip64 — we
    // fall through to the yauzl path below instead of failing here.)
    try {
      if (zipPath && fs.existsSync(zipPath) && !fs.statSync(zipPath).isDirectory()) {
        const info = zipAes.inspectZip(zipPath);
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
      }
    } catch (e) {
      if (e.message && e.message.indexOf('Wrong password') === 0) throw e;
      if (e.message && e.message.indexOf('password is required') !== -1) throw e;
      // Inspector could not read the file: fall through to yauzl.
    }
    return new Promise((resolve, reject) => {
      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        
        zipfile.readEntry();
        
        zipfile.on('entry', (entry) => {
          zipfile.readEntry();
          
          if (entry.fileName === entryName.replace(/\\/g, '/')) {
            zipfile.openReadStream(entry, (err, ReadStream) => {
              if (err) return reject(err);
              
              const dir = path.dirname(destPath);
              if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
              }
              
              const file = fs.createWriteStream(destPath);
              ReadStream.pipe(file);
              
              file.on('finish', resolve);
              file.on('error', reject);
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
