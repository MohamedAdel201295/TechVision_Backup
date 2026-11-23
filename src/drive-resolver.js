/**
 * TechVision Backup — removable-drive resolver (main process).
 *
 * A backup source can live on an external disk that gets unplugged
 * and comes back on a DIFFERENT drive letter (G: today, H: tomorrow).
 * The job stores the volume label (e.g. "Nile view") when it is saved;
 * at run time we find whichever letter that volume is on now and use
 * that path. The literal saved path is always tried first.
 *
 * Drive listing uses PowerShell (Get-CimInstance Win32_LogicalDisk),
 * with WMIC as a fallback. Both are read-only queries. On non-Windows
 * or when both fail, the list is empty and only the literal path works.
 */
const fs = require('fs');
const { execFile } = require('child_process');

const CACHE_MS = 10000;
let cache = { at: 0, drives: [] };

function driveLetterOf(p) {
  if (typeof p !== 'string') return null;
  const m = /^([A-Za-z]):[\\/]/.exec(p.trim());
  return m ? m[1].toUpperCase() : null;
}

function parsePowerShellJson(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return [];
  const data = JSON.parse(trimmed);
  const rows = Array.isArray(data) ? data : [data];
  return rows
    .map(function (r) {
      const letter = String(r.DeviceID || r.DriveLetter || '').replace(':', '').toUpperCase();
      const label = String(r.VolumeName || r.FileSystemLabel || '').trim();
      return letter ? { letter: letter, label: label } : null;
    })
    .filter(Boolean);
}

function parseWmicCsv(text) {
  const drives = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const parts = line.split(',');
    if (parts.length < 3) continue;
    const letter = (parts[1] || '').replace(':', '').trim().toUpperCase();
    const label = (parts[2] || '').trim();
    if (/^[A-Z]$/.test(letter)) drives.push({ letter: letter, label: label });
  }
  return drives;
}

function execTimeout(file, args, ms) {
  return new Promise(function (resolve) {
    execFile(file, args, { timeout: ms, windowsHide: true }, function (err, stdout) {
      if (err) return resolve(null);
      resolve(stdout || '');
    });
  });
}

async function listDrives() {
  const now = Date.now();
  if (now - cache.at < CACHE_MS) return cache.drives;
  let drives = [];
  if (process.platform === 'win32') {
    const ps = await execTimeout('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName | ConvertTo-Json -Compress'], 10000);
    if (ps) {
      try { drives = parsePowerShellJson(ps); } catch (e) { drives = []; }
    }
    if (!drives.length) {
      const wmic = await execTimeout('wmic', ['logicaldisk', 'get', 'DeviceID,VolumeName', '/format:csv'], 10000);
      if (wmic) {
        try { drives = parseWmicCsv(wmic); } catch (e) { drives = []; }
      }
    }
  }
  cache = { at: now, drives: drives };
  return drives;
}

/**
 * Resolve a saved source/destination path.
 * @param {string} savedPath  the path stored on the job
 * @param {string|null} storedLabel  volume label captured when the job was saved
 * @param {Array<{letter,label}>} [drives]  optional drive list (for tests; otherwise pass null and use listDrives first)
 * @returns {{found:boolean, path:string, letter:string|null, label:string|null, remapped:boolean}}
 */
function resolvePath(savedPath, storedLabel, drives) {
  const letter = driveLetterOf(savedPath);
  if (savedPath && fs.existsSync(savedPath)) {
    return { found: true, path: savedPath, letter: letter, label: storedLabel || null, remapped: false };
  }
  if (storedLabel && Array.isArray(drives)) {
    const want = String(storedLabel).trim().toLowerCase();
    const hit = drives.find(function (d) { return d.label && d.label.toLowerCase() === want; });
    if (hit && letter) {
      const rebuilt = hit.letter + ':' + savedPath.slice(2);
      if (fs.existsSync(rebuilt)) {
        return { found: true, path: rebuilt, letter: hit.letter, label: hit.label, remapped: true };
      }
    }
  }
  return { found: false, path: savedPath, letter: letter, label: storedLabel || null, remapped: false };
}

async function resolvePathAsync(savedPath, storedLabel) {
  if (savedPath && fs.existsSync(savedPath)) {
    return { found: true, path: savedPath, letter: driveLetterOf(savedPath), label: storedLabel || null, remapped: false };
  }
  const drives = await listDrives();
  return resolvePath(savedPath, storedLabel, drives);
}

function labelForLetter(drives, letter) {
  if (!letter || !Array.isArray(drives)) return null;
  const hit = drives.find(function (d) { return d.letter === String(letter).toUpperCase(); });
  return hit ? (hit.label || null) : null;
}

module.exports = { driveLetterOf, listDrives, resolvePath, resolvePathAsync, labelForLetter, parsePowerShellJson, parseWmicCsv };
