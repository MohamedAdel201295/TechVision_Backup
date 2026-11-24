/**
 * TechVision Backup — removable-drive resolver (main process).
 *
 * A backup source/destination can live on an external disk that gets
 * unplugged and comes back on a DIFFERENT drive letter (G: today, H:
 * tomorrow). Each job stores HOW to find its drive again:
 *   { mode: 'label' | 'letter' | 'serial', label, serial, serialKind }
 * - 'label'  — match the volume label (e.g. "Nile view") on any letter.
 * - 'letter' — use the saved path literally, never remap.
 * - 'serial' — match the disk's serial number on any letter.
 * The serial is the hardware serial when the drive reports one, and
 * the volume serial (XXXX-XXXX) otherwise. It is read automatically
 * at save time — the user never types it, and never needs to see the
 * drive's name or letter for it to work. Serial mode NEVER falls
 * back to the label: two disks can share a label, and the fallback
 * is exactly what serial mode exists to prevent. A serial that
 * cannot be found is a failure, not a label match.
 * Old jobs that only have sourceVolumeLabel keep working as 'label'.
 *
 * Drive listing uses PowerShell (Get-CimInstance Win32_Volume, plus
 * Get-Partition / Get-Disk / Get-PhysicalDisk for the hardware
 * serial), with WMIC as a fallback (letter + label + volume serial
 * only). On non-Windows or when both fail, the list is empty and
 * only the literal path works.
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

// Win32 volume serials are UInt32; WMIC reports them as hex text.
// Normalize both to the familiar "XXXX-XXXX" uppercase form.
function formatVolumeSerial(v) {
  if (v === null || v === undefined || v === '') return null;
  let hex = null;
  if (typeof v === 'number' && isFinite(v)) {
    hex = (v >>> 0).toString(16).toUpperCase();
  } else {
    const s = String(v).trim().toUpperCase().replace(/[^0-9A-F]/g, '');
    if (!s) return null;
    hex = s;
  }
  hex = hex.padStart(8, '0').slice(-8);
  return hex.slice(0, 4) + '-' + hex.slice(4);
}

function normalizeSerial(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim().toUpperCase();
  return t ? t : null;
}

function parsePowerShellJson(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return [];
  const data = JSON.parse(trimmed);
  const rows = Array.isArray(data) ? data : [data];
  return rows
    .map(function (r) {
      // Win32_Volume: DeviceID is the volume GUID path
      // (\\?\Volume{...}\) — the letter lives in DriveLetter.
      // Win32_LogicalDisk (old shape): DeviceID IS the letter (G:).
      const devId = String(r.DeviceID || '');
      let letter = String(r.DriveLetter || r.Letter || '').replace(':', '').toUpperCase();
      if (!/^[A-Z]$/.test(letter)) {
        const m = /^([A-Za-z]):/.exec(devId);
        letter = m ? m[1].toUpperCase() : null;
      }
      if (!letter) return null;
      const label = String(r.Label || r.VolumeName || r.FileSystemLabel || '').trim();
      const guid = (typeof r.Guid === 'string' && r.Guid) ? r.Guid
        : (typeof r.DeviceID === 'string' && r.DeviceID.indexOf('Volume{') !== -1 ? r.DeviceID : null);
      const volumeSerial = formatVolumeSerial(r.VolumeSerial !== undefined ? r.VolumeSerial : r.SerialNumber);
      const hw = normalizeSerial(r.Serial);
      return {
        letter: letter,
        label: label,
        guid: guid,
        volumeSerial: volumeSerial,
        serial: hw || volumeSerial,
        // A drive that reports neither serial claims no serial at all:
        // the old code reported serialKind 'volume' with a null serial.
        serialKind: hw ? 'hardware' : (volumeSerial ? 'volume' : null)
      };
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
    if (!/^[A-Z]$/.test(letter)) continue;
    const volumeSerial = parts.length >= 4 ? formatVolumeSerial(parts[3]) : null;
    drives.push({
      letter: letter,
      label: label,
      guid: null,
      volumeSerial: volumeSerial,
      serial: volumeSerial,
      serialKind: 'volume'
    });
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

// One PowerShell pipeline: every lettered volume, with its label,
// volume GUID, volume serial, and (best effort, per drive) the
// hardware serial of the physical disk behind it. A drive whose
// hardware serial cannot be read still appears — with its volume
// serial standing in — so one odd USB enclosure never kills the list.
const PS_LIST_COMMAND = "Get-CimInstance Win32_Volume | Where-Object { $_.DriveLetter } | ForEach-Object { $v = $_; $hw = $null; try { $letter = $v.DriveLetter -replace ':', ''; $part = Get-Partition -DriveLetter $letter -ErrorAction Stop; $disk = $part | Get-Disk -ErrorAction Stop; $phys = $disk | Get-PhysicalDisk -ErrorAction Stop; $hw = @($phys.SerialNumber)[0] } catch { }; [PSCustomObject]@{ Letter = $v.DriveLetter; Label = $v.Label; Guid = $v.DeviceID; VolumeSerial = $v.SerialNumber; Serial = $hw } } | ConvertTo-Json -Compress";

async function listDrives() {
  const now = Date.now();
  if (now - cache.at < CACHE_MS) return cache.drives;
  let drives = [];
  if (process.platform === 'win32') {
    const ps = await execTimeout('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS_LIST_COMMAND], 15000);
    if (ps) {
      try { drives = parsePowerShellJson(ps); } catch (e) { drives = []; }
    }
    if (!drives.length) {
      const wmic = await execTimeout('wmic', ['logicaldisk', 'get', 'DeviceID,VolumeName,VolumeSerialNumber', '/format:csv'], 10000);
      if (wmic) {
        try { drives = parseWmicCsv(wmic); } catch (e) { drives = []; }
      }
    }
  }
  cache = { at: now, drives: drives };
  return drives;
}

// Normalize what a job stored about its drive into a match object.
// Accepts: null (literal path only), a plain string (an old job's
// volume label — treated as mode 'label'), or the match object the
// wizard saves. Anything unrecognised degrades to 'label'.
function normalizeStored(stored) {
  if (!stored) return null;
  if (typeof stored === 'string') {
    return stored.trim() ? { mode: 'label', label: stored.trim(), serial: null } : null;
  }
  if (typeof stored === 'object') {
    const mode = (stored.mode === 'letter' || stored.mode === 'serial' || stored.mode === 'label') ? stored.mode : 'label';
    return {
      mode: mode,
      label: (typeof stored.label === 'string' && stored.label.trim()) ? stored.label.trim() : null,
      serial: normalizeSerial(stored.serial),
      // serialKind tells callers which kind of serial the stored value
      // is; dropping it lost the distinction between a hardware serial
      // and a volume serial (XXXX-XXXX).
      serialKind: (stored.serialKind === 'hardware' || stored.serialKind === 'volume') ? stored.serialKind : null
    };
  }
  return null;
}

function rebuildWithLetter(savedPath, letter) {
  return letter + ':' + savedPath.slice(2);
}

// Verify the drive at the saved letter against the stored match.
// Returns 'ok' (matches, or nothing to check), 'mismatch' (the drive
// at that letter is provably NOT the job's drive), or 'unknown'
// (no drive list, or the letter is not in it — accept the literal
// path rather than break a job over a stale list).
function checkLiteralIdentity(savedPath, match, drives) {
  if (!match || match.mode === 'letter') return 'ok';
  const letter = driveLetterOf(savedPath);
  if (!letter || !Array.isArray(drives)) return 'unknown';
  const at = driveInfoForLetter(drives, letter);
  if (!at) return 'unknown';
  if (match.mode === 'serial' && match.serial) {
    const want = match.serial;
    if (normalizeSerial(at.serial) === want || normalizeSerial(at.volumeSerial) === want) return 'ok';
    return 'mismatch';
  }
  if (match.label) {
    if (at.label && at.label.trim().toLowerCase() === match.label.trim().toLowerCase()) return 'ok';
    return 'mismatch';
  }
  return 'ok';
}

/**
 * Resolve a saved source/destination path.
 * @param {string} savedPath  the path stored on the job
 * @param {string|object|null} stored  job's drive match (string = legacy
 *   volume label; object = { mode, label, serial }; null = literal only)
 * @param {Array} [drives]  optional drive list (for tests; otherwise
 *   pass null and use listDrives first)
 * @returns {{found:boolean, path:string, letter:string|null, label:string|null, remapped:boolean, identityMismatch?:boolean, serialNotFound?:boolean}}
 */
function resolvePath(savedPath, stored, drives) {
  const letter = driveLetterOf(savedPath);
  const match = normalizeStored(stored);
  // Is the saved DRIVE present, even if the exact folder is not?
  // A destination folder may legitimately not exist yet (the engine
  // creates it); only a missing drive should block or wait. null =
  // cannot tell (no letter, e.g. a Linux path, or no drive list).
  const letterPresent = () => {
    if (!letter || !Array.isArray(drives)) return null;
    return drives.some((d) => d.letter === letter);
  };
  let identityMismatch = false;
  if (savedPath && fs.existsSync(savedPath)) {
    // The literal path exists — but is it the job's drive? A different
    // disk can mount on the same letter with the same folder path, and
    // the old code returned immediately here without checking, which
    // defeated the whole drive-match feature in the most dangerous
    // case. On a mismatch, fall through and look for the real drive
    // on another letter instead of silently using the wrong disk.
    if (checkLiteralIdentity(savedPath, match, drives) === 'mismatch') {
      identityMismatch = true;
    } else {
      return { found: true, path: savedPath, letter: letter, label: (match && match.label) || null, remapped: false, drivePresent: true };
    }
  }
  // 'letter' mode (and no match info at all): the saved path is the
  // whole truth — never guess another drive.
  if (!match || match.mode === 'letter') {
    return { found: false, path: savedPath, letter: letter, label: (match && match.label) || null, remapped: false, identityMismatch: identityMismatch, drivePresent: letterPresent() };
  }
  if (!letter || !Array.isArray(drives)) {
    return { found: false, path: savedPath, letter: letter, label: (match && match.label) || null, remapped: false, identityMismatch: identityMismatch, drivePresent: null };
  }
  // 'serial' mode: find the disk by its serial number, on any letter.
  // Compare against both the hardware serial and the volume serial,
  // so a drive saved from the WMIC fallback still matches. If no
  // drive matches by serial, FAIL — never fall back to the label.
  if (match.mode === 'serial' && match.serial) {
    const want = match.serial;
    const hit = drives.find(function (d) {
      return normalizeSerial(d.serial) === want || normalizeSerial(d.volumeSerial) === want;
    });
    if (hit) {
      const rebuilt = rebuildWithLetter(savedPath, hit.letter);
      if (fs.existsSync(rebuilt)) {
        return { found: true, path: rebuilt, letter: hit.letter, label: hit.label || match.label, remapped: true, drivePresent: true };
      }
      // The right disk is here, the folder is not: the drive is
      // present (a destination can still be created on it). Return
      // the rebuilt path, not the stale saved letter, so the caller
      // creates/reports on the correct drive.
      return { found: false, path: rebuilt, letter: hit.letter, label: hit.label || match.label, remapped: true, identityMismatch: identityMismatch, drivePresent: true };
    }
    return { found: false, path: savedPath, letter: letter, label: match.label, remapped: false, identityMismatch: identityMismatch, serialNotFound: true, drivePresent: false };
  }
  // 'label' mode (and serial mode with no serial stored): match the
  // volume label. Try EVERY drive with that label, not just the first
  // — two disks can share a label, and the file may only be on the
  // second one.
  if (match.label) {
    const wantLabel = match.label.trim().toLowerCase();
    let labelDrivePresent = false;
    let firstCandidate = null;
    for (const d of drives) {
      if (!d.label || d.label.toLowerCase() !== wantLabel) continue;
      labelDrivePresent = true;
      const rebuilt = rebuildWithLetter(savedPath, d.letter);
      if (!firstCandidate) firstCandidate = { path: rebuilt, letter: d.letter, label: d.label };
      if (fs.existsSync(rebuilt)) {
        return { found: true, path: rebuilt, letter: d.letter, label: d.label, remapped: true, drivePresent: true };
      }
    }
    // A drive with the label exists but the folder does not: return
    // the path rebuilt on that drive (not the stale saved letter) so
    // a destination can be created there and errors name the right disk.
    if (firstCandidate) {
      return { found: false, path: firstCandidate.path, letter: firstCandidate.letter, label: firstCandidate.label, remapped: true, identityMismatch: identityMismatch, drivePresent: true };
    }
    return { found: false, path: savedPath, letter: letter, label: (match && match.label) || null, remapped: false, identityMismatch: identityMismatch, drivePresent: false };
  }
  return { found: false, path: savedPath, letter: letter, label: (match && match.label) || null, remapped: false, identityMismatch: identityMismatch, drivePresent: letterPresent() };
}

async function resolvePathAsync(savedPath, stored) {
  const match = normalizeStored(stored);
  if (savedPath && fs.existsSync(savedPath)) {
    if (!match || match.mode === 'letter') {
      return { found: true, path: savedPath, letter: driveLetterOf(savedPath), label: (match && match.label) || null, remapped: false, drivePresent: true };
    }
    // Verify the drive at this letter before trusting the literal
    // path; a wrong disk here must be caught, not accepted.
    const drives = await listDrives();
    if (checkLiteralIdentity(savedPath, match, drives) !== 'mismatch') {
      return { found: true, path: savedPath, letter: driveLetterOf(savedPath), label: match.label, remapped: false, drivePresent: true };
    }
    return resolvePath(savedPath, stored, drives);
  }
  const drives = await listDrives();
  return resolvePath(savedPath, stored, drives);
}

function driveInfoForLetter(drives, letter) {
  if (!letter || !Array.isArray(drives)) return null;
  const hit = drives.find(function (d) { return d.letter === String(letter).toUpperCase(); });
  return hit || null;
}

function labelForLetter(drives, letter) {
  const hit = driveInfoForLetter(drives, letter);
  return hit ? (hit.label || null) : null;
}

function serialForLetter(drives, letter) {
  const hit = driveInfoForLetter(drives, letter);
  return hit ? (hit.serial || null) : null;
}

module.exports = { driveLetterOf, formatVolumeSerial, normalizeSerial, listDrives, resolvePath, resolvePathAsync, driveInfoForLetter, labelForLetter, serialForLetter, parsePowerShellJson, parseWmicCsv, PS_LIST_COMMAND };
