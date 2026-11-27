'use strict';
/**
 * TechVision Cloud — Map network drive (client side, main process).
 *
 * Windows-only: trusts the picked server's pinned certificate once
 * (Local Machine Trusted Root store — the WebClient service runs as
 * SYSTEM and validates against the machine store, NOT the user
 * store), then maps https://<host>:<port>/dav as a drive letter with
 * `net use` in the user's own session (an elevated mapping is
 * invisible to Explorer, so the mapping itself is NEVER elevated).
 *
 * Every function returns { success, ... } / { success: false, error }
 * instead of throwing, and on non-Windows returns a clear error
 * instead of crashing. Passwords are passed as argv elements (never
 * through a shell) and never logged.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

function isWindows() {
  return process.platform === 'win32';
}

function winOnlyError() {
  return { success: false, error: 'Mapping a network drive is available on Windows only.' };
}

// Thumbprints of a PEM certificate (hex, lowercase, no separators):
// the machine Root store dump shows both, so checking either is
// enough to know the cert is already trusted.
function thumbprintsOfCertPem(certPem) {
  try {
    const b64 = String(certPem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = Buffer.from(b64, 'base64');
    return {
      sha1: crypto.createHash('sha1').update(der).digest('hex'),
      sha256: crypto.createHash('sha256').update(der).digest('hex'),
    };
  } catch (e) {
    return { sha1: '', sha256: '' };
  }
}

function runCmd(exe, args, timeoutMs) {
  return new Promise((resolve) => {
    if (!isWindows()) return resolve({ success: false, error: 'Windows only.' });
    execFile(exe, args, { windowsHide: true, timeout: timeoutMs || 30000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({
        success: !err,
        code: err ? err.code : 0,
        stdout: String(stdout || ''),
        stderr: String(stderr || ''),
        error: err ? (String(stderr || '').trim() || err.message) : '',
      });
    });
  });
}

/* One UAC prompt, then the command runs elevated and we wait for it
 * (same $p.WaitForExit() pattern as wireguard.js / nat-gateway.js —
 * Start-Process -Wait returns early with -Verb RunAs). The temp
 * launcher is deleted afterwards either way. */
function runElevatedCommand(exe, args) {
  return new Promise((resolve) => {
    if (!isWindows()) return resolve({ success: false, error: 'Windows only.' });
    const q = (s) => "'" + String(s).replace(/'/g, "''") + "'";
    const scriptText = [
      '$ErrorActionPreference = "Stop"',
      'try {',
      '  $p = Start-Process -FilePath ' + q(exe) + ' -ArgumentList ' + args.map(q).join(', ') + ' -Verb RunAs -PassThru',
      '  $p.WaitForExit()',
      '  exit $p.ExitCode',
      '} catch {',
      '  exit 2',
      '}',
    ].join('\r\n');
    const launcherPath = path.join(os.tmpdir(), 'techvision-mapdrive-launcher.ps1');
    try { fs.writeFileSync(launcherPath, scriptText, 'utf8'); } catch (e) { return resolve({ success: false, error: 'Could not write the elevation script.' }); }
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', launcherPath], { timeout: 120000, windowsHide: true }, (err) => {
      try { fs.unlinkSync(launcherPath); } catch (e) {}
      if (err) {
        if (err.code === 2) return resolve({ success: false, declined: true, error: 'Administrator permission was not granted.' });
        return resolve({ success: false, error: 'The elevated command failed (code ' + err.code + ').' });
      }
      resolve({ success: true });
    });
  });
}

// Is this exact certificate already in the Local Machine Trusted
// Root store? Checked first so a repeat mapping never asks for UAC
// again. certutil -store Root lists the store; the dump shows both
// the SHA-1 and the SHA-256 hash of every certificate.
async function isCertTrusted(certPem) {
  if (!isWindows()) return { success: false, error: 'Windows only.' };
  const tp = thumbprintsOfCertPem(certPem);
  if (!tp.sha256) return { success: false, error: 'The server certificate could not be read.' };
  const r = await runCmd('certutil.exe', ['-store', 'Root'], 60000);
  if (!r.success) return { success: false, error: 'Could not read the Windows certificate store: ' + (r.error || 'certutil failed.') };
  const flat = r.stdout.toLowerCase().replace(/[^0-9a-f]/g, '');
  return { success: true, trusted: flat.includes(tp.sha256) || flat.includes(tp.sha1) };
}

// Install the server's pinned certificate into the Local Machine
// Trusted Root store (admin once). ONLY the exact cert of the server
// the user picked — the caller matches its fingerprint against the
// saved record first. The temp PEM file is deleted afterwards.
async function installCert(certPem) {
  if (!isWindows()) return winOnlyError();
  const pemPath = path.join(os.tmpdir(), 'techvision-cloud-cert-' + crypto.randomBytes(6).toString('hex') + '.pem');
  try { fs.writeFileSync(pemPath, String(certPem || ''), 'utf8'); } catch (e) {
    return { success: false, error: 'Could not write the certificate file.' };
  }
  const r = await runElevatedCommand('certutil.exe', ['-addstore', 'Root', pemPath]);
  try { fs.unlinkSync(pemPath); } catch (e) {}
  if (!r.success) {
    return { success: false, declined: !!r.declined, error: r.declined ? 'Certificate install was cancelled (administrator permission was not granted).' : 'Could not install the server certificate. Install it manually into the Local Machine Trusted Root store, then try again.' };
  }
  return { success: true };
}

// The WebDAV redirector needs the WebClient service running.
async function ensureWebClient() {
  if (!isWindows()) return winOnlyError();
  const q = await runCmd('sc.exe', ['query', 'WebClient'], 15000);
  if (q.success && /RUNNING/.test(q.stdout)) return { success: true };
  const start = await runElevatedCommand('net.exe', ['start', 'WebClient']);
  if (!start.success) {
    return { success: false, declined: !!start.declined, error: start.declined ? 'The WebClient service could not be started (administrator permission was not granted).' : 'The WebClient service is not running and could not be started. Start it from services.msc, then try again.' };
  }
  return { success: true };
}

function davUrl(host, port) {
  return 'https://' + host + ':' + port + '/dav';
}

// Office documents open straight from a WebDAV URL with the Office
// URI scheme (ms-word:ofe|u|… = open for edit). No download; saves
// go back to the server through WebDAV. Returns null for anything
// that is not an Office document.
const OFFICE_SCHEMES = { doc: 'ms-word', docx: 'ms-word', xls: 'ms-excel', xlsx: 'ms-excel', ppt: 'ms-powerpoint', pptx: 'ms-powerpoint' };
function officeSchemeFor(name) {
  const i = String(name || '').lastIndexOf('.');
  if (i <= 0) return null;
  return OFFICE_SCHEMES[String(name).slice(i + 1).toLowerCase()] || null;
}
function officeUriFor(host, port, rel) {
  const scheme = officeSchemeFor(rel);
  if (!scheme || !host || !port) return null;
  const segs = String(rel || '').split('/').filter((s) => s !== '');
  if (!segs.length) return null;
  return scheme + ':ofe|u|' + davUrl(host, port) + '/' + segs.map((s) => encodeURIComponent(s)).join('/');
}

// Media (video/audio) opens straight from the WebDAV URL in the
// default player — the player pulls ranges over HTTPS, so a big video
// starts playing without downloading first. Returns null for anything
// that is not media.
const MEDIA_EXTS = ['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v', '3gp', 'mp3', 'wav', 'flac', 'ogg', 'm4a', 'aac', 'wma'];
function mediaUrlFor(host, port, rel) {
  const i = String(rel || '').lastIndexOf('.');
  if (i <= 0 || MEDIA_EXTS.indexOf(String(rel).slice(i + 1).toLowerCase()) < 0) return null;
  if (!host || !port) return null;
  const segs = String(rel || '').split('/').filter((s) => s !== '');
  if (!segs.length) return null;
  return davUrl(host, port) + '/' + segs.map((s) => encodeURIComponent(s)).join('/');
}

// The Credential Manager targets a Cloud login is seeded under.
// Round 2 #14: the old code only seeded DOMAIN credentials
// (`cmdkey /add:<host>` and `/add:<host:port>`) — those are what
// `net use`/SMB consults. Office opens the file over HTTPS through
// WinINET, which looks up GENERIC credentials keyed by the URL — a
// bare-host domain credential never matches, so Office kept
// prompting (and pre-filled the Windows logon user instead of the
// Cloud user). The documented fix (Office WebDAV + Credential
// Manager) is a generic credential whose address is the site URL, so
// seed both kinds, under every target form WinINET and the WebClient
// redirector may look up: the URL, the DAV root URL, and the bare
// host forms, as generic and as domain credentials.
function credentialTargetsFor(host, port) {
  const h = String(host);
  const p = String(port);
  const base = 'https://' + h + ':' + p;
  return [
    { kind: 'generic', name: base },
    { kind: 'generic', name: base + '/dav' },
    { kind: 'generic', name: h },
    { kind: 'generic', name: h + ':' + p },
    { kind: 'add', name: h },
    { kind: 'add', name: h + ':' + p },
  ];
}

// Seed the Cloud credentials into the Windows Credential Manager so
// Word/Excel (and media players) do not prompt for a login when they
// open the WebDAV URL. Best-effort per target (a failure on one must
// not block the rest); the caller logs the summary. Passwords are
// passed as argv elements (never through a shell) and never logged.
async function seedCredentials(host, port, user, password) {
  if (!isWindows()) return { success: false, error: 'Windows only.' };
  if (!host || !port || !user || !password) return { success: false, error: 'Missing credentials.' };
  const targets = credentialTargetsFor(host, port);
  const failed = [];
  let ok = 0;
  for (const t of targets) {
    const flag = t.kind === 'generic' ? '/generic:' : '/add:';
    const r = await runCmd('cmdkey.exe', [flag + t.name, '/user:' + String(user), '/pass:' + String(password)], 15000);
    if (r.success) ok++;
    else failed.push(t.kind + ':' + t.name + ' (' + (r.error || 'cmdkey failed') + ')');
  }
  if (!ok) return { success: false, error: 'Could not store the Cloud credentials in Windows Credential Manager: ' + failed.join('; ') };
  return { success: true, seeded: ok, failed: failed.length ? failed : undefined };
}

function mapErrorText(r) {
  const text = (r.stdout + ' ' + r.stderr).toLowerCase();
  if (/system error 86/.test(text)) return 'Wrong user name or password for this Cloud server.';
  if (/system error 1219/.test(text)) return 'Windows already has a connection to this server with different credentials — disconnect the other mapping first (or sign out and back in).';
  if (/system error 85/.test(text)) return 'That drive letter is already in use — pick a different letter.';
  if (/system error 67/.test(text)) return 'The server could not be reached at that address, or Windows does not trust its certificate yet.';
  if (/system error 53/.test(text)) return 'The network path was not found — check the server address and port.';
  if (/system error 1326/.test(text)) return 'Wrong user name or password for this Cloud server.';
  // 1244 = Windows refused to send the login at all: the TLS
  // handshake failed, so no credentials ever went over the wire.
  // That is a certificate problem (not trusted for this address, or
  // the certificate does not cover this address), not a wrong
  // password — saying so plainly instead of quoting the raw error.
  if (/system error 1244/.test(text)) return 'Windows refused to send your login (System error 1244): it does not trust the server certificate for this address. If the address was added after the server started, restart the Cloud server on the server machine so it issues a new certificate covering it, then connect again and map.';
  const raw = (r.stderr || r.stdout || '').trim().replace(/\s+/g, ' ');
  return raw ? 'Mapping failed: ' + raw.slice(0, 300) : 'Mapping failed (net use error ' + (r.code || '?') + ').';
}

// Map https://host:port/dav as a drive letter, in the user's own
// session (UN-elevated — an elevated mapping is invisible to
// Explorer). Assumes the certificate is already trusted; call
// isCertTrusted/installCert first.
async function mapDrive(opts) {
  if (!isWindows()) return winOnlyError();
  const letter = String((opts && opts.letter) || '').toUpperCase();
  const host = String((opts && opts.host) || '').trim();
  const port = parseInt((opts && opts.port) || '', 10);
  const user = String((opts && opts.user) || '').trim();
  const password = String((opts && opts.password) || '');
  if (!/^[A-Z]$/.test(letter)) return { success: false, error: 'Pick a drive letter (A–Z).' };
  if (!host || !port || port < 1 || port > 65535) return { success: false, error: 'Bad server address or port.' };
  if (!user || !password) return { success: false, error: 'password-needed' };
  const wc = await ensureWebClient();
  if (!wc.success) return wc;
  const url = davUrl(host, port);
  // A letter that is already mapped to THIS server is fine — reuse
  // it instead of failing with error 85.
  const cur = await getDriveStatus(letter);
  if (cur.success && cur.mapped && cur.remote === url) return { success: true, letter, alreadyMapped: true };
  const r = await runCmd('net.exe', ['use', letter + ':', url, '/user:' + user, password, '/persistent:no'], 60000);
  if (!r.success) return { success: false, error: mapErrorText(r) };
  return { success: true, letter };
}

async function unmapDrive(letter) {
  if (!isWindows()) return winOnlyError();
  const l = String(letter || '').toUpperCase();
  if (!/^[A-Z]$/.test(l)) return { success: false, error: 'Bad drive letter.' };
  const r = await runCmd('net.exe', ['use', l + ':', '/delete', '/y'], 30000);
  if (!r.success) {
    const text = (r.stdout + ' ' + r.stderr).toLowerCase();
    if (/no entries|not found|there are no/i.test(text)) return { success: true, letter: l, alreadyGone: true };
    return { success: false, error: 'Could not disconnect the drive: ' + ((r.stderr || r.stdout || '').trim().replace(/\s+/g, ' ').slice(0, 200) || ('net use error ' + (r.code || '?'))) };
  }
  return { success: true, letter: l };
}

// `net use X:` — the remote path must match our dav URL exactly, so
// a letter mapped to something else never counts as ours.
async function getDriveStatus(letter) {
  if (!isWindows()) return { success: false, error: 'Windows only.' };
  const l = String(letter || '').toUpperCase();
  if (!/^[A-Z]$/.test(l)) return { success: false, error: 'Bad drive letter.' };
  const r = await runCmd('net.exe', ['use', l + ':'], 15000);
  const text = r.stdout || '';
  if (!r.success || /there are no entries in the list/i.test(text)) return { success: true, mapped: false, letter: l };
  const m = /Remote name\s+(\S+)/i.exec(text);
  const remote = m ? m[1].trim() : '';
  let exists = false;
  try { exists = fs.existsSync(l + ':\\'); } catch (e) {}
  return { success: true, mapped: !!remote, letter: l, remote, reachable: exists };
}

// Letters Windows already uses (local drives + mapped drives), so
// the picker only offers free ones. Z first — the usual default.
async function listFreeLetters() {
  if (!isWindows()) return { success: false, error: 'Windows only.' };
  const used = new Set();
  for (let c = 65; c <= 90; c++) {
    const l = String.fromCharCode(c);
    try { if (fs.existsSync(l + ':\\')) used.add(l); } catch (e) {}
  }
  const r = await runCmd('net.exe', ['use'], 15000);
  if (r.success) {
    const re = /^([A-Z]):\s+/gm;
    let m;
    while ((m = re.exec(r.stdout || '')) !== null) used.add(m[1]);
  }
  const free = [];
  for (let c = 90; c >= 67; c--) {
    const l = String.fromCharCode(c);
    if (!used.has(l)) free.push(l);
  }
  return { success: true, letters: free };
}

async function openExplorer(letter) {
  if (!isWindows()) return winOnlyError();
  const l = String(letter || '').toUpperCase();
  if (!/^[A-Z]$/.test(l)) return { success: false, error: 'Bad drive letter.' };
  try {
    const { shell } = require('electron');
    const err = await shell.openPath(l + ':\\');
    return err ? { success: false, error: 'Windows could not open the drive: ' + err } : { success: true, letter: l };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
}

// Join a server-relative path (forward slashes, from a listing) onto
// a mapped letter and prove it stays under the letter root. The rel
// comes from the server, so it is validated anyway: no '..' escape.
function mappedPathFor(letter, rel) {
  const l = String(letter || '').toUpperCase();
  if (!/^[A-Z]$/.test(l)) return { success: false, error: 'Bad drive letter.' };
  const root = l + ':\\';
  const parts = String(rel || '').split('/').filter((p) => p && p !== '.');
  if (parts.some((p) => p === '..' || /[<>:"|?*]/.test(p))) return { success: false, error: 'Bad file path.' };
  // Backslash-joined by hand, not path.join: on a Windows machine
  // path.join would do the same, but this module must also stay
  // correct when loaded (not run) on other platforms.
  const joined = root + parts.join('\\');
  if (joined !== root && !joined.startsWith(root)) return { success: false, error: 'Bad file path.' };
  return { success: true, path: joined };
}

// --- state: mapdrive.json in .techvision ---
// { mappings: [{ serverId, letter, host, port, user, reconnect }] }
function loadState(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const s = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      if (s && Array.isArray(s.mappings)) return s;
    }
  } catch (e) {}
  return { mappings: [] };
}

function saveState(filePath, state) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
    fs.renameSync(tmp, filePath);
    return { success: true };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : String(e) };
  }
}

module.exports = {
  isWindows,
  thumbprintsOfCertPem,
  isCertTrusted,
  installCert,
  ensureWebClient,
  mapDrive,
  mapErrorText,
  unmapDrive,
  getDriveStatus,
  listFreeLetters,
  openExplorer,
  mappedPathFor,
  davUrl,
  officeSchemeFor,
  officeUriFor,
  mediaUrlFor,
  seedCredentials,
  credentialTargetsFor,
  loadState,
  saveState,
};
