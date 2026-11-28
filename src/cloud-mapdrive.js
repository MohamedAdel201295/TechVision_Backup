'use strict';
/**
 * TechVision Cloud — Map network drive (client side, main process).
 *
 * Windows-only: trusts the picked server's pinned certificate once
 * (Local Machine Trusted Root store — the WebClient service runs as
 * SYSTEM and validates against the machine store, NOT the user
 * store), then maps https://<host>:<port>/dav as a drive letter with
 * `net use` in the app's OWN session (2026-11-28 correction: the
 * mapping belongs to the session the app runs in — a normal-user run
 * maps in the user session, an elevated run maps in the admin
 * session — and is NEVER duplicated into the other session; an
 * elevated mapping is invisible to a normal Explorer, so the panel
 * says which session the drive belongs to).
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
const { execFile, spawn } = require('child_process');

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

// Is the app itself running elevated (as administrator)? `net
// session` succeeds only for an elevated process (error 5
// otherwise). The mapping lives in the session the app runs in —
// normal-user run: user session; elevated run: admin session —
// so the Map panel can say which one this drive belongs to.
async function isElevated() {
  if (!isWindows()) return { success: false, error: 'Windows only.' };
  const r = await runCmd('net.exe', ['session'], 15000);
  return { success: true, elevated: !!r.success };
}

// Windows reports a WebDAV mapping's remote as a UNC path
// (\\host@SSL@port\dav), not the https URL the app mapped —
// comparing the two strings can never match, so the app kept
// saying "Not mapped" about its own mapping and re-ran `net use`
// on every press. Accept every form Windows can report for the
// same DAV root: the UNC form (with or without @SSL@), the URL
// form, and the \DavWWWRoot form the redirector sometimes shows.
// Real Windows reports the remote with TWO segments —
// \\host@SSL@port\DavWWWRoot\dav — and that is the form the
// redirector actually uses on the device (2026-11-28, drive M:);
// a one-segment-only match rejected a drive that was really
// mapped and declared "verification failed".
function normalizeDavRemote(remote) {
  const s = String(remote || '').trim();
  let m = /^\\\\([^@\\]+)(?:@SSL@|@)(\d+)\\(?:DavWWWRoot(?:\\dav)?|dav)\\?$/i.exec(s);
  if (m) return { host: m[1].toLowerCase(), port: parseInt(m[2], 10), ssl: /@SSL@/i.test(s) };
  m = /^(https?):\/\/([^/:]+):(\d+)\/dav\/?$/i.exec(s);
  if (m) return { host: m[2].toLowerCase(), port: parseInt(m[3], 10), ssl: m[1].toLowerCase() === 'https' };
  m = /^\\\\DavWWWRoot\\(?:dav|DavWWWRoot)\\?$/i.exec(s);
  if (m) return { host: null, port: null, ssl: null, davWwwRoot: true };
  return null;
}

function remoteMatchesDav(remote, host, port) {
  const n = normalizeDavRemote(remote);
  if (!n) return false;
  // The host-less \DavWWWRoot form carries no address to compare:
  // it can only be a WebDAV mapping, and this app only ever maps
  // its own DAV root, so it counts as ours.
  if (n.davWwwRoot) return true;
  return n.host === String(host).toLowerCase() && n.port === parseInt(port, 10);
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

// Media (video/audio) URL for a file — used only to build the DAV
// address the app itself fetches from. The PLAYER never sees this
// URL any more: it gets a plain local proxy URL instead (see
// cloud-media-proxy.js), because a non-WinINET player cannot answer
// the DAV login and exits with an error. The proxy still streams
// ranges, so a big video starts playing without downloading first.
// Returns null for anything that is not media.
const MEDIA_EXTS = ['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v', '3gp', 'mp3', 'wav', 'flac', 'ogg', 'm4a', 'aac', 'wma'];
function mediaUrlFor(host, port, rel) {
  const i = String(rel || '').lastIndexOf('.');
  if (i <= 0 || MEDIA_EXTS.indexOf(String(rel).slice(i + 1).toLowerCase()) < 0) return null;
  if (!host || !port) return null;
  const segs = String(rel || '').split('/').filter((s) => s !== '');
  if (!segs.length) return null;
  return davUrl(host, port) + '/' + segs.map((s) => encodeURIComponent(s)).join('/');
}

// --- default media player (Part D) ---
// shell.openExternal('https://…') always opens the DEFAULT BROWSER
// for an https URL — that is why videos opened in Chrome instead of
// the media player. A player is found the way Windows finds one:
// the per-extension UserChoice ProgId, then that ProgId's
// shell\open\command. WinINET-based players also consult the
// Credential Manager generic credentials seeded at connect time,
// so the player does not prompt for the Cloud login.
function parseRegValue(output, name) {
  const lines = String(output || '').split(/\r?\n/);
  for (const line of lines) {
    const m = /^\s*(.*?)\s+REG_\w+\s+(.*)$/.exec(line);
    if (!m) continue;
    const n = m[1].trim();
    if (name === '(Default)' ? (n === '(Default)' || n === '') : n === name) return m[2].trim();
  }
  return null;
}

async function regQueryValue(key, valueName) {
  const args = ['query', key];
  if (valueName === '(Default)') args.push('/ve');
  else args.push('/v', valueName);
  const r = await runCmd('reg.exe', args, 15000);
  if (!r.success) return null;
  return parseRegValue(r.stdout, valueName);
}

async function resolvePlayerCommand(ext) {
  const e = String(ext || '').replace(/^\./, '').toLowerCase();
  if (!e) return null;
  const progId = await regQueryValue('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.' + e + '\\UserChoice', 'ProgId');
  if (!progId) return null;
  const keys = [
    'HKCU\\Software\\Classes\\' + progId + '\\shell\\open\\command',
    'HKCR\\' + progId + '\\shell\\open\\command',
  ];
  for (const k of keys) {
    const cmd = await regQueryValue(k, '(Default)');
    if (cmd) return { progId, command: cmd };
  }
  return null;
}

// Split a Windows command template ("C:\Program Files\...\player.exe"
// "%1" /play) into tokens the way the shell would: quoted parts stay
// whole, "" inside quotes is a literal quote. No shell is ever run
// on the result — the tokens go straight to spawn() as argv.
function splitCommandLine(s) {
  const out = [];
  let cur = '';
  let inQ = false;
  let has = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"') {
      if (inQ && s[i + 1] === '"') { cur += '"'; i++; }
      else inQ = !inQ;
      has = true;
    } else if (!inQ && (ch === ' ' || ch === '\t')) {
      if (has) { out.push(cur); cur = ''; has = false; }
    } else { cur += ch; has = true; }
  }
  if (has) out.push(cur);
  return out;
}

// Build the argv for a registered player open command. The %1 (or
// %L) placeholder is replaced with the media URL as ONE argument —
// never re-parsed, never expanded — so a percent-encoded URL keeps
// its %XX sequences intact (an Arabic filename becomes %D8%B3... and
// must reach the player exactly like that). Only the EXE path gets
// %VAR% expansion (Windows expands those in the template itself); a
// command with no placeholder gets the URL appended. Returns null
// when the template is empty.
function buildPlayerArgv(command, url) {
  const parts = splitCommandLine(String(command || ''));
  if (!parts.length) return null;
  // Windows expands %VAR% case-insensitively; match that so a
  // template using %systemroot% still resolves.
  const envLower = {};
  for (const k of Object.keys(process.env)) envLower[k.toLowerCase()] = process.env[k];
  const exe = parts[0].replace(/%([^%]+)%/g, (m, name) => (envLower[String(name).toLowerCase()] !== undefined ? envLower[String(name).toLowerCase()] : m));
  const args = [];
  let replaced = false;
  for (const p of parts.slice(1)) {
    if (/%1|%L/i.test(p)) { args.push(p.replace(/%1|%L/gi, url)); replaced = true; }
    else args.push(p);
  }
  if (!replaced) args.push(url);
  return { exe, args };
}

// Open a media URL in the registered media player for its
// extension. The URL is normally the local proxy URL minted by
// cloud-media-proxy.js — plain HTTP on 127.0.0.1, no login — so ANY
// player plays it. The player is launched DIRECTLY (spawn exe +
// argv) — never through cmd.exe, which expands %...% as environment
// variables and mangles a percent-encoded URL, so an Arabic filename
// never reached the player intact. Returns { success: false,
// playerFailed: true, error } when there is no association or the
// launch fails — the caller shows the error in the app instead of
// falling back to the browser.
async function openMediaInPlayer(url, ext) {
  if (!isWindows()) return { success: false, playerFailed: true, error: 'Windows only.' };
  const resolved = await resolvePlayerCommand(ext);
  if (!resolved || !resolved.command) return { success: false, playerFailed: true, error: 'No media player is registered for .' + String(ext || '').replace(/^\./, '') + ' files.' };
  const argv = buildPlayerArgv(resolved.command, url);
  if (!argv) return { success: false, playerFailed: true, error: 'The registered media player command could not be read.' };
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    let child;
    try {
      child = spawn(argv.exe, argv.args, { windowsHide: true, detached: true });
    } catch (e) {
      return finish({ success: false, playerFailed: true, error: 'Could not start the media player: ' + (e && e.message ? e.message : String(e)) });
    }
    child.on('error', (e) => finish({ success: false, playerFailed: true, error: 'Could not start the media player: ' + (e && e.message ? e.message : String(e)) }));
    // A player that exits at once with an error never took the URL;
    // one that stays up (or detaches) has it. 500 ms is enough to tell.
    const timer = setTimeout(() => { try { child.unref(); } catch (e) {} finish({ success: true, player: resolved.progId }); }, 500);
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) { clearTimeout(timer); finish({ success: false, playerFailed: true, error: 'The media player exited with an error (code ' + code + ').' }); }
    });
  });
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
  if (/system error 1219/.test(text)) return 'Windows already has a connection to this server with different credentials (System error 1219) — disconnect the other mapping to this server first, or map the second user under a different address for the same server (its LAN address or hostname).';
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

// --- Map attempt trace (2026-11-28 diagnostics round) ---
// A failed Map used to leave NO trace in the app log: `net use`
// exits 0 while the drive never sticks, and the failure path logged
// nothing at all — the Full log ended with old success lines. The
// trace records every step (timings, net use exit code + output,
// verification results) so a failed Map on the device explains
// itself. Passwords never enter the trace: outputs are scrubbed of
// the exact password string before they are recorded.
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// One line for the trace: single-line, whitespace collapsed, capped
// so a chatty command cannot flood the app log.
function traceText(s, maxLen) {
  return String(s || '').replace(/\s+/g, ' ').trim().slice(0, maxLen || 400);
}

// Map https://host:port/dav as a drive letter, in the app's OWN
// session (2026-11-28 correction: a normal-user run maps in the
// user session, an elevated run maps in the admin session — the
// mapping is NEVER duplicated into the other session). Assumes the
// certificate is already trusted; call isCertTrusted/installCert
// first. Verifies afterwards that the drive really exists in this
// session before reporting success: `net use` exiting 0 used to be
// reported as "Drive mapped" even when the drive never appeared.
// On Windows error 1219 (one credential set per server NAME per
// logon session) retries the same physical server under each
// alternate host in opts.altHosts (e.g. LAN address instead of the
// Tailscale IP), skipping any the certificate does not cover
// (opts.coversHost, may be async; false = skip, true/null = try).
// Returns { success, letter, host } — host is the address the
// mapping actually ended up under (viaAltHost: true when it took
// an alternate), or { success: false, error, code: '1219' }.
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
  const altHosts = Array.isArray(opts && opts.altHosts) ? opts.altHosts.map((h) => String(h || '').trim()).filter(Boolean) : [];
  const coversHost = opts && typeof opts.coversHost === 'function' ? opts.coversHost : null;
  // The attempt trace: every step of this mapping, with timings and
  // the raw output of the commands that ran. Returned on every
  // result so the caller can write it to the app log on failure.
  // The password is scrubbed out of any recorded output first.
  const trace = [];
  const scrub = (s) => {
    const t = String(s || '');
    return password ? t.split(password).join('[password]') : t;
  };
  const tWc0 = Date.now();
  const wc = await ensureWebClient();
  trace.push('webclient: ' + (wc.success ? 'running' : 'FAILED — ' + traceText(wc.error || '')) + ' in ' + (Date.now() - tWc0) + 'ms');
  if (!wc.success) return Object.assign({}, wc, { trace });
  // A letter that is already mapped to THIS server is fine — reuse
  // it instead of failing with error 85. The remote is compared
  // with remoteMatchesDav, not string equality: Windows reports the
  // remote as \\host@SSL@port\dav, never as the https URL.
  const tPre0 = Date.now();
  const cur = await getDriveStatus(letter);
  trace.push('precheck ' + letter + ': ' + (cur.success ? (cur.mapped ? 'mapped to "' + traceText(scrub(cur.remote || '')) + '"' : 'not mapped') : 'status error — ' + traceText(cur.error || '')) + ' in ' + (Date.now() - tPre0) + 'ms');
  if (cur.success && cur.mapped && remoteMatchesDav(cur.remote, host, port)) return { success: true, letter, host, alreadyMapped: true, trace };

  const attempt = async (h) => {
    const tNet0 = Date.now();
    const r = await runCmd('net.exe', ['use', letter + ':', davUrl(h, port), '/user:' + user, password, '/persistent:no'], 60000);
    trace.push('net use ' + letter + ': ' + davUrl(h, port) + ' /user:' + user + ': exit=' + (r.code === undefined || r.code === null ? '?' : r.code) + ' in ' + (Date.now() - tNet0) + 'ms; stdout: "' + traceText(scrub(r.stdout)) + '"; stderr: "' + traceText(scrub(r.stderr)) + '"');
    if (!r.success) {
      const is1219 = /system error 1219/.test((r.stdout + ' ' + r.stderr).toLowerCase());
      return { success: false, error: mapErrorText(r), code: is1219 ? '1219' : undefined, trace };
    }
    // Post-map verification, in THIS session, before any success is
    // reported: the status must show this server's mapping AND the
    // drive root must open. A `net use` that exits 0 while the
    // drive never sticks is a failure, not a mapped drive. The
    // redirector may need a moment to surface the drive, so
    // re-check a few times with a short delay before giving up.
    let sawStatus = false;
    for (let v = 1; v <= 3; v++) {
      const tV0 = Date.now();
      const st = await getDriveStatus(letter);
      let reachable = false;
      try { reachable = fs.existsSync(letter + ':\\'); } catch (e) {}
      const statusOk = !!(st.success && st.mapped && remoteMatchesDav(st.remote, h, port));
      if (statusOk) sawStatus = true;
      trace.push('verify attempt ' + v + '/3: mapped=' + (st.success && st.mapped ? 'yes' : 'no') + ' remote="' + traceText(scrub(st.remote || '')) + '" exists=' + reachable + ' in ' + (Date.now() - tV0) + 'ms; net use ' + letter + ': output: "' + traceText(scrub(st.raw || '')) + '"');
      if (statusOk && reachable) return { success: true, letter, host: h, trace };
      if (v < 3) await sleep(1000);
    }
    // A failed Map must leave nothing behind: `net use` exited 0
    // above, so this attempt may have created a mapping that never
    // verified — every failed Map on the device left one behind
    // (seven stale mappings to the same server, 2026-11-28).
    // Best-effort unmap of the letter this attempt just created.
    // The precheck already returned early for a letter mapped to
    // this server, and a failed `net use` never reaches here, so
    // this only ever removes what this attempt made. An unmap
    // failure must not change the reported error.
    let cleanup = '';
    try {
      const u = await unmapDrive(letter);
      cleanup = u.success ? 'removed' : 'FAILED — ' + traceText(u.error || '');
    } catch (e) { cleanup = 'FAILED — ' + traceText(e && e.message ? e.message : String(e)); }
    trace.push('cleanup ' + letter + ': ' + cleanup);
    if (!sawStatus) {
      return { success: false, error: 'Mapping reported success, but drive ' + letter + ': did not appear afterwards (verification failed) — the mapping did not stick. Try again, or disconnect any other mapping to this server first.', trace };
    }
    return { success: false, error: 'Mapping reported success, but drive ' + letter + ': cannot be opened afterwards (verification failed) — the mapping did not stick.', trace };
  };

  const first = await attempt(host);
  if (first.success) return first;
  if (first.code !== '1219' || !altHosts.length) return first;
  for (const alt of altHosts) {
    if (!alt || alt.toLowerCase() === host.toLowerCase()) continue;
    if (coversHost) {
      let ok = null;
      try { ok = await coversHost(alt); } catch (e) { ok = false; }
      if (ok === false) continue;
    }
    const r = await attempt(alt);
    if (r.success) { r.viaAltHost = true; return r; }
    if (r.code !== '1219') return r; // a different failure: report it, don't keep guessing
  }
  return { success: false, code: '1219', error: 'Windows already has a connection to this server with different credentials (System error 1219) — the other mapping to ' + host + ' must be disconnected first, or the second user must reach the server under a different address (its LAN address or hostname). The automatic retry under another address could not be used (no alternate address, or the server certificate does not cover it).', trace };
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

// `net use X:` — the remote is what Windows reports (usually the
// UNC form \\host@SSL@port\dav). Callers compare it with
// remoteMatchesDav, never with the https URL.
async function getDriveStatus(letter) {
  if (!isWindows()) return { success: false, error: 'Windows only.' };
  const l = String(letter || '').toUpperCase();
  if (!/^[A-Z]$/.test(l)) return { success: false, error: 'Bad drive letter.' };
  const r = await runCmd('net.exe', ['use', l + ':'], 15000);
  const text = r.stdout || '';
  // `raw` is the verbatim `net use X:` output, for the Map trace:
  // on a failed Map it shows exactly what Windows reported.
  if (!r.success || /there are no entries in the list/i.test(text)) return { success: true, mapped: false, letter: l, raw: text };
  const m = /Remote name\s+(\S+)/i.exec(text);
  const remote = m ? m[1].trim() : '';
  let exists = false;
  try { exists = fs.existsSync(l + ':\\'); } catch (e) {}
  return { success: true, mapped: !!remote, letter: l, remote, reachable: exists, raw: text };
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
  isElevated,
  thumbprintsOfCertPem,
  isCertTrusted,
  installCert,
  ensureWebClient,
  mapDrive,
  mapErrorText,
  remoteMatchesDav,
  normalizeDavRemote,
  unmapDrive,
  getDriveStatus,
  listFreeLetters,
  openExplorer,
  mappedPathFor,
  davUrl,
  officeSchemeFor,
  officeUriFor,
  mediaUrlFor,
  openMediaInPlayer,
  buildPlayerArgv,
  splitCommandLine,
  resolvePlayerCommand,
  seedCredentials,
  credentialTargetsFor,
  loadState,
  saveState,
};
