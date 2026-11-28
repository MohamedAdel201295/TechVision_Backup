/**
 * TechVision Cloud - Server
 * HTTPS file server that runs inside the main process (the app already
 * stays alive in the tray). TLS only, scrypt-hashed users, per-user
 * root folders, session tokens, login lockout, audit logging.
 *
 * Config lives in <userData>/.techvision/cloud.json (owned by main.js,
 * passed in here). The server never trusts a client-supplied path:
 * every path is jailed inside the caller's root, including symlinks.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const https = require('https');
const stream = require('stream');
// Lazy: the app must still open when this package is missing (e.g. a
// source checkout where `npm install` was not run yet). The server
// refuses to start with a clear message instead of crashing the app.
let selfsigned = null;
try { selfsigned = require('selfsigned'); } catch (e) { selfsigned = null; }

// Same scrypt parameters as the vault (vault.js).
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_LOGIN_FAILS = 5;
const LOCKOUT_MS = 10 * 60 * 1000;
// DAV auth cache: a correct Basic credential is re-verified with a
// full scrypt (~50 ms) on EVERY DAV request, and a player open/play
// is dozens of requests — so seconds accumulate. The cache remembers
// a verified credential for 5 minutes (sliding), so repeat requests
// skip scrypt. A wrong password never hits the cache (different key
// -> miss -> full scrypt -> 401 + lockout counting, exactly as
// before); a password change / user delete takes effect at once
// because every hit re-checks the live passHash, and
// _revokeSessionsFor purges the user's entries too. In-memory only:
// a server restart clears it. The key is a SHA-256 of the presented
// base64 token — the password itself is never stored or logged.
const DAV_AUTH_CACHE_TTL_MS = 5 * 60 * 1000;
const DAV_AUTH_CACHE_MAX = 128;
const MAX_JSON_BYTES = 1024 * 1024;
// Largest single upload the server accepts. A client streaming past
// this gets a 413 and the partial file is deleted.
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024;

function hashPassword(password, saltB64) {
  const salt = saltB64 ? Buffer.from(saltB64, 'base64') : crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, SCRYPT_OPTS);
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}

// Async on purpose: scrypt blocks the event loop for ~50-100 ms, and
// login is the one endpoint anyone on the network can hit repeatedly.
function verifyPassword(password, saltB64, hashB64) {
  return new Promise((resolve) => {
    let salt, expected;
    try {
      salt = Buffer.from(saltB64, 'base64');
      expected = Buffer.from(hashB64, 'base64');
    } catch (e) { return resolve(false); }
    crypto.scrypt(password, salt, 32, SCRYPT_OPTS, (err, actual) => {
      if (err) return resolve(false);
      resolve(actual.length === expected.length && crypto.timingSafeEqual(actual, expected));
    });
  });
}

// Fixed dummy credentials, computed once at load: a login for a user
// that does not exist still runs one scrypt, so the timing does not
// reveal whether the user name exists.
const DUMMY_CREDENTIALS = hashPassword('techvision-dummy-password-never-a-real-user');

function fingerprintOfCertPem(certPem) {
  const b64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return crypto.createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex');
}

function defaultServerConfig() {
  return { enabled: false, port: 8443, cert: null, users: [], accessMode: 'normal', ddnsHostname: '' };
}

function certSans(certPem) {
  try {
    const x = new crypto.X509Certificate(certPem);
    const san = x.subjectAltName || '';
    const dns = [], ips = [];
    for (const part of san.split(',')) {
      const p = part.trim();
      if (p.startsWith('DNS:')) dns.push(p.slice(4));
      else if (p.startsWith('IP Address:')) ips.push(p.slice(11));
    }
    return { dns, ips, hasSans: dns.length > 0 || ips.length > 0 };
  } catch (e) { return { dns: [], ips: [], hasSans: false }; }
}

// One-time migration (round 2 #12): a stored cert is regenerated
// when it has no usable SANs at all (every cert made before this fix
// — CN only, or the selfsigned default URI SAN that matches no host,
// which is exactly why `net use` failed with error 1244), or when
// the DDNS hostname was added/changed and is not in the cert yet, or
// when the DDNS hostname recorded on the cert at issuance no longer
// matches the configured one (changed or removed since).
// Nothing else regenerates it: LAN addresses come and go (a VPN
// going up/down adds/removes interfaces), and churning the
// fingerprint on every such change would force every client to
// re-trust for no reason.
function certNeedsRegen(cfg) {
  if (!cfg.cert || !cfg.cert.cert) return true;
  const sans = certSans(cfg.cert.cert);
  if (!sans.hasSans) return true;
  const ddns = String((cfg.ddnsHostname) || '').trim().toLowerCase();
  // The DDNS hostname recorded when the cert was issued: a mismatch
  // means the config changed (or the DDNS was removed) since, so the
  // cert no longer matches and must be regenerated once.
  if (typeof cfg.cert.ddnsHostname === 'string' && cfg.cert.ddnsHostname !== ddns) return true;
  if (ddns) {
    const dns = sans.dns.map(function (n) { return String(n).toLowerCase(); });
    if (dns.indexOf(ddns) < 0) return true;
  }
  return false;
}

// Does this certificate cover `host` for Windows hostname validation
// (`net use` / WebClient)? An IPv4 host needs an IP SAN, a hostname
// needs a DNS SAN. Returns true / false, or null when the host form
// cannot be judged here (IPv6) — the caller then proceeds as before
// instead of blocking a mapping it cannot evaluate.
// This is the 1244 hole (2026-11-27): the SANs are frozen at issuance
// — an address that appears later (Tailscale coming up after the
// server first started) is never in the cert, certNeedsRegen never
// fires for it, and `net use` fails with System error 1244 while the
// in-app Client still connects fine (fingerprint pinning does no
// hostname validation). The map flow must check coverage and fail
// with the actual cause instead of the cryptic 1244.
function certCoversHost(certPem, host) {
  const h = String(host || '').trim().toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (h.indexOf(':') >= 0) return null; // IPv6 (incl. bracketed): not judged here
  const sans = certSans(certPem);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return sans.ips.indexOf(h) >= 0;
  return sans.dns.map(function (n) { return String(n).toLowerCase(); }).indexOf(h) >= 0;
}

function certExtensions(cfg, publicIp) {
  const altNames = [];
  const seen = new Set();
  const addDns = (v) => { const k = 'd:' + v; if (v && !seen.has(k)) { seen.add(k); altNames.push({ type: 2, value: v }); } };
  const addIp = (v) => { const k = 'i:' + v; if (v && !seen.has(k)) { seen.add(k); altNames.push({ type: 7, ip: v }); } };
  addDns(os.hostname() || 'TechVision-Cloud');
  for (const ip of lanIPs()) addIp(ip);
  addDns(String((cfg && cfg.ddnsHostname) || '').trim());
  if (publicIp) addIp(publicIp);
  // Same basicConstraints/keyUsage as the old default extensions —
  // only the subjectAltName list is new, so pinning behaviour does
  // not change: the cert stays its own trust anchor.
  return [
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, nonRepudiation: true, keyEncipherment: true, dataEncipherment: true },
    { name: 'subjectAltName', altNames },
  ];
}

async function ensureCert(cfg) {
  if (cfg.cert && cfg.cert.cert && cfg.cert.key && cfg.cert.fingerprint && !certNeedsRegen(cfg)) return cfg.cert;
  if (!selfsigned) {
    throw new Error('The "selfsigned" package is not installed. Run "npm install" in the project folder, then start the server again.');
  }
  // Public IP only when it can be detected (best-effort, 5s): the
  // DDNS name already covers the public path, and a failed detect
  // just leaves the IP out.
  let publicIp = null;
  try { publicIp = await detectPublicIP(); } catch (e) { publicIp = null; }
  const attrs = [{ name: 'commonName', value: os.hostname() || 'TechVision-Cloud' }];
  const pems = selfsigned.generate(attrs, { days: 3650, keySize: 2048, algorithm: 'sha256', extensions: certExtensions(cfg, publicIp) });
  cfg.cert = {
    cert: pems.cert,
    key: pems.private,
    fingerprint: fingerprintOfCertPem(pems.cert),
    ddnsHostname: String(cfg.ddnsHostname || '').trim().toLowerCase(),
  };
  return cfg.cert;
}

// LAN IPv4 addresses (non-internal) for the Server card.
function lanIPs() {
  const out = [];
  try {
    const ifs = os.networkInterfaces();
    for (const name of Object.keys(ifs)) {
      for (const a of ifs[name] || []) {
        if (a.family === 'IPv4' && !a.internal) out.push(a.address);
      }
    }
  } catch (e) {}
  return out;
}

// Public IP, asked from an external service on demand (5s timeout).
// Returns null when it cannot be determined.
function detectPublicIP() {
  return new Promise((resolve) => {
    try {
      const req = https.get('https://api.ipify.org', { timeout: 5000 }, (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < 64) body += c; });
        res.on('end', () => {
          const ip = body.trim();
          resolve(res.statusCode === 200 && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? ip : null);
        });
      });
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.on('error', () => resolve(null));
    } catch (e) {
      resolve(null);
    }
  });
}

class CloudServer {
  // opts: { config, onConfigChange, log }
  //   config: the cloud.json object (server + clients); the server reads
  //   cfg.server at start and re-reads it on every request, so user
  //   edits apply without a restart (except port / cert changes).
  //   log(level, message): audit log, e.g. main.js appendAppLog.
  constructor(opts) {
    this.cfg = opts.config;
    this.onConfigChange = opts.onConfigChange || (() => {});
    this.log = opts.log || (() => {});
    this.httpsServer = null;
    this.port = 0;
    this.sessions = new Map(); // token -> { user, root, canWrite, expiresAt }
    this.loginFails = new Map(); // ip -> { fails, lockedUntil, lastFailAt }
    this._davAuthCache = new Map(); // SHA-256 of Basic token -> { name, passHash, expiresAt } (in-memory only)
    this._davLocks = new Map(); // absolute path -> { token, expiresAt, owner } (WebDAV LOCK, in-memory only)
    this._uploadsInFlight = new Set(); // dest paths with an upload running
    this.maxUploadBytes = (opts && opts.maxUploadBytes) || MAX_UPLOAD_BYTES;
  }

  isRunning() {
    return !!this.httpsServer;
  }

  status() {
    return {
      running: this.isRunning(),
      port: this.port,
      users: (this.cfg.server.users || []).length,
      fingerprint: this.cfg.server.cert ? this.cfg.server.cert.fingerprint : null,
      lanIPs: lanIPs(),
    };
  }

  _audit(ip, user, action, detail) {
    // Strip newlines: a user name or file name must never be able to
    // forge log lines.
    const safe = (v) => String(v == null ? '' : v).replace(/[\r\n]+/g, ' ');
    this.log('info', `[Cloud] ${safe(user) || '-'} @ ${safe(ip) || '-'}: ${safe(action)}${detail ? ' — ' + safe(detail) : ''}`);
  }

  _serverCfg() {
    return this.cfg.server || (this.cfg.server = defaultServerConfig());
  }

  // --- users (passwords are never stored or returned in the clear) ---
  // Multi-root users: a user has a LIST of roots (folders) instead
  // of one root. Old single-root users migrate on first read:
  // root -> [root]. The `root` field is kept as roots[0] so old
  // callers keep working. One read/write flag per user (not per
  // root) — per-folder permissions are still out of scope.
  _userRoots(u) {
    if (Array.isArray(u.roots) && u.roots.length) return u.roots.map((r) => path.normalize(String(r)));
    return u.root ? [path.normalize(String(u.root))] : [];
  }
  _migrateUsers() {
    const users = this._serverCfg().users || [];
    let changed = false;
    for (const u of users) {
      if (!Array.isArray(u.roots) || !u.roots.length) {
        if (u.root) { u.roots = [path.normalize(String(u.root))]; changed = true; }
      }
      if (u.roots && u.roots.length && u.root !== u.roots[0]) { u.root = u.roots[0]; changed = true; }
    }
    if (changed) this.onConfigChange();
  }
  // Display name of one root folder inside the user's virtual root:
  // the folder's own name (a drive root 'D:\' shows as 'D'). Two
  // roots with the same name get a number suffix so the virtual root
  // listing never has two identical folders.
  _rootDisplayName(root) {
    const base = String(root || '').replace(/[\\/]+$/, '');
    const m = /([^\\/]+)$/.exec(base);
    if (m) return m[1];
    const drive = /^([A-Za-z]):$/.exec(base);
    if (drive) return drive[1];
    return 'Cloud';
  }
  _rootDisplayNames(roots) {
    const names = [];
    for (const r of roots || []) {
      let name = this._rootDisplayName(r);
      if (names.indexOf(name) >= 0) {
        let n = 2;
        while (names.indexOf(name + ' (' + n + ')') >= 0) n++;
        name = name + ' (' + n + ')';
      }
      names.push(name);
    }
    return names;
  }
  // Resolve a client-relative path against a user's roots. With ONE
  // root the path resolves directly under it, exactly as before
  // (rel == '' is the root itself) — a single-root user sees no
  // extra folder level, in the browser, the DAV layer or the mapped
  // drive. With TWO OR MORE roots the first segment names the root
  // (its display name); the rest is jailed inside that root, and
  // rel == '' is the virtual root itself (no single target).
  // Returns { target, root, displayName, isVirtualRoot, isRoot } or
  // null when it escapes / names no root.
  _resolveUserPath(roots, rel) {
    const clean = String(rel || '').replace(/^[/\\]+/, '').split(/[\\/]+/).filter((p) => p && p !== '.');
    const names = this._rootDisplayNames(roots);
    if (roots.length === 1) {
      const root = roots[0];
      const target = this._jail(root, clean.join('/'));
      if (target === null) return null;
      const realRoot = this._realRoot(root);
      return { target, root, displayName: names[0], isVirtualRoot: false, isRoot: realRoot !== null && target === realRoot };
    }
    if (!clean.length) return { target: null, root: null, displayName: '', isVirtualRoot: true, isRoot: false };
    const idx = names.indexOf(clean[0]);
    if (idx < 0) return null;
    const root = roots[idx];
    const target = this._jail(root, clean.slice(1).join('/'));
    if (target === null) return null;
    const realRoot = this._realRoot(root);
    return { target, root, displayName: names[idx], isVirtualRoot: false, isRoot: realRoot !== null && target === realRoot };
  }
  listUsers() {
    this._migrateUsers();
    return (this._serverCfg().users || []).map((u) => {
      const roots = this._userRoots(u);
      return {
        name: u.name, root: roots[0] || u.root, roots, canWrite: !!u.canWrite,
      };
    });
  }

  addUser(name, password, root, canWrite) {
    const clean = String(name || '').trim();
    if (!clean) throw new Error('User name is required.');
    if (typeof password !== 'string' || password.length < 12) {
      throw new Error('Password must be at least 12 characters (this server is reachable from the internet).');
    }
    if (!root || !path.isAbsolute(root)) throw new Error('Root folder must be an absolute path.');
    let rootStat = null;
    try { rootStat = fs.statSync(root); } catch (e) { rootStat = null; }
    if (!rootStat || !rootStat.isDirectory()) throw new Error('Root folder does not exist or is not a folder.');
    const users = this._serverCfg().users || (this._serverCfg().users = []);
    if (users.some((u) => u.name === clean)) throw new Error('A user with this name already exists.');
    const { salt, hash } = hashPassword(password);
    const normRoot = path.normalize(root);
    users.push({ name: clean, passHash: hash, salt, root: normRoot, roots: [normRoot], canWrite: !!canWrite });
    this.onConfigChange();
    return { name: clean, root: normRoot, roots: [normRoot], canWrite: !!canWrite };
  }

  // Edit a user: rename, rotate the password, replace the roots
  // list, flip read/write — everything the Edit form changes.
  // password ''/missing = keep the old one; roots missing = keep
  // the old list. A rename updates the user in place; the caller
  // (main.js) updates saved client records that point at this
  // server. Any change drops the user's sessions at once: the
  // login-time snapshot (name, roots) must never outlive the edit.
  editUser(name, updates) {
    const users = this._serverCfg().users || [];
    const u = users.find((x) => x.name === name);
    if (!u) throw new Error('User not found.');
    const clean = (updates && updates.name !== undefined) ? String(updates.name || '').trim() : u.name;
    if (!clean) throw new Error('User name is required.');
    if (clean !== name && users.some((x) => x.name === clean)) throw new Error('A user with this name already exists.');
    let roots = this._userRoots(u);
    if (updates && updates.roots !== undefined) {
      if (!Array.isArray(updates.roots) || !updates.roots.length) throw new Error('At least one folder is required.');
      const seen = new Set();
      roots = updates.roots.map((r) => {
        if (!r || !path.isAbsolute(String(r))) throw new Error('Each folder must be an absolute path.');
        const norm = path.normalize(String(r));
        let st = null;
        try { st = fs.statSync(norm); } catch (e) { st = null; }
        if (!st || !st.isDirectory()) throw new Error('Folder does not exist or is not a folder: ' + norm);
        if (seen.has(norm.toLowerCase())) throw new Error('The same folder is listed twice: ' + norm);
        seen.add(norm.toLowerCase());
        return norm;
      });
    }
    let passwordChanged = false;
    if (updates && updates.password !== undefined && updates.password !== null && updates.password !== '') {
      if (typeof updates.password !== 'string' || updates.password.length < 12) throw new Error('Password must be at least 12 characters.');
      const { salt, hash } = hashPassword(updates.password);
      u.passHash = hash;
      u.salt = salt;
      passwordChanged = true;
    }
    const renamed = clean !== name;
    u.name = clean;
    u.roots = roots;
    u.root = roots[0];
    if (updates && updates.canWrite !== undefined) u.canWrite = !!updates.canWrite;
    this._revokeSessionsFor(name);
    if (renamed) this._revokeSessionsFor(clean);
    this.onConfigChange();
    return { name: clean, root: roots[0], roots: roots.slice(), canWrite: !!u.canWrite, renamed, passwordChanged };
  }

  removeUser(name) {
    const users = this._serverCfg().users || [];
    const i = users.findIndex((u) => u.name === name);
    if (i < 0) throw new Error('User not found.');
    users.splice(i, 1);
    this._revokeSessionsFor(name);
    this.onConfigChange();
  }

  setUserPassword(name, password) {
    if (typeof password !== 'string' || password.length < 12) {
      throw new Error('Password must be at least 12 characters.');
    }
    const u = (this._serverCfg().users || []).find((x) => x.name === name);
    if (!u) throw new Error('User not found.');
    const { salt, hash } = hashPassword(password);
    u.passHash = hash;
    u.salt = salt;
    this._revokeSessionsFor(name);
    this.onConfigChange();
  }

  // A removed user (or a rotated password) must lose access at once —
  // their token must not keep working for the rest of its 12 hours.
  _revokeSessionsFor(name) {
    for (const [t, s] of this.sessions) {
      if (s.user === name) this.sessions.delete(t);
    }
    // The DAV auth cache is keyed by credential, not by user — drop
    // this user's entries too, so a removed / re-passworded user loses
    // DAV access at once. (The passHash check on a cache hit already
    // makes stale entries unusable; this is belt-and-braces.)
    if (this._davAuthCache) {
      for (const [k, v] of this._davAuthCache) {
        if (v.name === name) this._davAuthCache.delete(k);
      }
    }
  }

  // --- lifecycle ---
  async start() {
    if (this.httpsServer) return this.status();
    const scfg = this._serverCfg();
    await ensureCert(scfg);
    this.onConfigChange();
    const port = scfg.port || 8443;
    const server = https.createServer({ key: scfg.cert.key, cert: scfg.cert.cert }, (req, res) => {
      this._handle(req, res).catch((e) => {
        try { this._sendJson(res, 500, { error: 'Server error.' }); } catch (_) {}
      });
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '0.0.0.0', () => { server.removeListener('error', reject); resolve(); });
    });
    this.httpsServer = server;
    this.port = port;
    this.log('info', `[Cloud] Server started on port ${port} (fingerprint ${scfg.cert.fingerprint.slice(0, 16)}…)`);
    return this.status();
  }

  async stop() {
    if (!this.httpsServer) return this.status();
    const s = this.httpsServer;
    this.httpsServer = null;
    this.port = 0;
    this.sessions.clear();
    this._davAuthCache.clear();
    this._davLocks.clear();
    // close() alone waits for open connections forever; destroy them
    // so Stop never hangs on a client holding a connection open.
    const closed = new Promise((resolve) => s.close(() => resolve()));
    try { s.closeAllConnections(); } catch (e) {}
    await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, 5000))]);
    this.log('info', '[Cloud] Server stopped.');
    return this.status();
  }

  // --- request handling ---
  _clientIP(req) {
    const fwd = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '';
    return String(fwd).replace(/^::ffff:/, '');
  }

  _sendJson(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  }

  _readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_JSON_BYTES) { req.destroy(); reject(new Error('Request body too large.')); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
        catch (e) { reject(new Error('Invalid JSON body.')); }
      });
      req.on('error', reject);
    });
  }

  _lockInfo(ip) {
    // Prune stale entries so the map does not grow forever: expired
    // locks and fail counts older than an hour.
    const now = Date.now();
    for (const [k, rec] of this.loginFails) {
      const locked = rec.lockedUntil && now < rec.lockedUntil;
      const recent = rec.lastFailAt && (now - rec.lastFailAt) <= 60 * 60 * 1000;
      if (!locked && !recent) this.loginFails.delete(k);
    }
    const rec = this.loginFails.get(ip);
    if (rec && rec.lockedUntil && Date.now() < rec.lockedUntil) return rec;
    return null;
  }

  _noteLoginFail(ip) {
    const rec = this.loginFails.get(ip) || { fails: 0, lockedUntil: 0, lastFailAt: 0 };
    rec.fails += 1;
    rec.lastFailAt = Date.now();
    if (rec.fails >= MAX_LOGIN_FAILS) {
      rec.lockedUntil = Date.now() + LOCKOUT_MS;
      rec.fails = 0;
      this._audit(ip, null, 'login locked out', `too many failed attempts (${MAX_LOGIN_FAILS})`);
    }
    this.loginFails.set(ip, rec);
  }

  _auth(req) {
    const h = req.headers.authorization || '';
    const m = /^Bearer\s+(\S+)$/.exec(h);
    if (!m) return null;
    const s = this.sessions.get(m[1]);
    if (!s) return null;
    if (Date.now() > s.expiresAt) { this.sessions.delete(m[1]); return null; }
    // Sliding expiry: an actively used session stays alive; only an
    // idle one dies after 12 hours.
    s.expiresAt = Date.now() + TOKEN_TTL_MS;
    return s;
  }

  _realRoot(root) {
    try { return fs.realpathSync(root); } catch (e) { return null; }
  }

  // Jail a client-relative path inside the user's root. Returns the
  // absolute path, or null when it escapes (including via symlinks).
  _jail(root, rel) {
    let realRoot;
    try { realRoot = fs.realpathSync(root); }
    catch (e) { return null; }
    // A filesystem root is "D:\" (or "/") — it already ends with the
    // separator, so blindly appending another one ("D:\\") would make
    // every child path fail the prefix check.
    const prefix = realRoot.endsWith(path.sep) ? realRoot : realRoot + path.sep;
    const clean = String(rel || '').replace(/^[/\\]+/, '').split(/[\\/]+/).filter((p) => p && p !== '.').join(path.sep);
    const target = path.join(realRoot, clean);
    if (target !== realRoot && !target.startsWith(prefix)) return null;
    // Symlink escape: resolve the nearest existing ancestor.
    let probe = target;
    while (!fs.existsSync(probe)) {
      const parent = path.dirname(probe);
      if (parent === probe) break;
      probe = parent;
    }
    let realProbe;
    try { realProbe = fs.realpathSync(probe); }
    catch (e) { return null; }
    if (realProbe !== realRoot && !realProbe.startsWith(prefix)) return null;
    return target;
  }

  async _handle(req, res) {
    const ip = this._clientIP(req);
    const u = new URL(req.url || '/', 'https://localhost');
    const pathname = u.pathname;
    if (req.method === 'POST' && pathname === '/api/login') {
      if (this._lockInfo(ip)) { this._sendJson(res, 429, { error: 'Too many failed logins. Try again later.' }); return; }
      let body;
      try { body = await this._readJsonBody(req); }
      catch (e) { this._sendJson(res, 400, { error: e.message }); return; }
      if (!body || typeof body !== 'object') { this._sendJson(res, 400, { error: 'Invalid request.' }); return; }
      const users = this._serverCfg().users || [];
      const user = users.find((x) => x.name === String(body.user || ''));
      let ok = false;
      if (user) {
        ok = await verifyPassword(String(body.password || ''), user.salt, user.passHash);
      } else {
        // Same scrypt cost as a real check, so the timing does not
        // reveal whether the user name exists.
        await verifyPassword(String(body.password || ''), DUMMY_CREDENTIALS.salt, DUMMY_CREDENTIALS.hash);
      }
      if (!ok) {
        this._noteLoginFail(ip);
        this._audit(ip, String(body.user || ''), 'login failed', '');
        this._sendJson(res, 401, { error: 'Wrong user name or password.' });
        return;
      }
      this.loginFails.delete(ip);
      const token = crypto.randomBytes(32).toString('hex');
      const roots = this._userRoots(user);
      this.sessions.set(token, { user: user.name, root: roots[0], roots, canWrite: !!user.canWrite, expiresAt: Date.now() + TOKEN_TTL_MS });
      this._audit(ip, user.name, 'login ok', '');
      this._sendJson(res, 200, { token });
      return;
    }

    // Logout: drop the session server-side (disconnecting the client
    // alone used to leave the token valid for up to 12 hours).
    if (req.method === 'POST' && pathname === '/api/logout') {
      const h = req.headers.authorization || '';
      const m = /^Bearer\s+(\S+)$/.exec(h);
      if (m) this.sessions.delete(m[1]);
      this._sendJson(res, 200, { ok: true });
      return;
    }

    // WebDAV (Map network drive): /dav/<path> = the authenticated
    // user's root folder. Basic auth, not Bearer — the Windows
    // redirector cannot send Bearer tokens. Handled before the
    // session check below.
    if (pathname === '/dav' || pathname.startsWith('/dav/')) {
      await this._handleDav(req, res, ip, pathname);
      return;
    }

    const session = this._auth(req);
    if (!session) { this._sendJson(res, 401, { error: 'Not signed in.' }); return; }

    if (req.method === 'GET' && pathname === '/api/info') {
      // addrs: the server's other addresses (LAN IPs + DDNS). A
      // client that maps the same server as a second user hits
      // Windows error 1219 on the first address; the Map tab retries
      // under one of these — same physical server, different name.
      const addrs = lanIPs();
      const ddns = this._serverCfg().ddnsHostname;
      if (ddns) addrs.push(ddns);
      this._sendJson(res, 200, { name: 'TechVision Cloud', version: 1, user: session.user, root: session.root, roots: session.roots || [session.root], canWrite: session.canWrite, addrs });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/list') {
      const rel = u.searchParams.get('path') || '';
      const resolved = this._resolveUserPath(session.roots || [session.root], rel);
      if (resolved === null) {
        this._sendJson(res, 404, { error: 'Folder not found.' });
        return;
      }
      // The virtual root: one folder per root the user has.
      if (resolved.isVirtualRoot) {
        const names = this._rootDisplayNames(session.roots || [session.root]);
        const entries = (session.roots || [session.root]).map((r, i) => {
          let mtime = 0;
          try { mtime = fs.statSync(r).mtimeMs; } catch (_) {}
          return { name: names[i], isDir: true, size: 0, mtime };
        });
        this._sendJson(res, 200, { path: rel, entries });
        return;
      }
      const target = resolved.target;
      if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
        this._sendJson(res, 404, { error: 'Folder not found.' });
        return;
      }
      let entries = [];
      try {
        entries = fs.readdirSync(target, { withFileTypes: true }).map((e) => {
          let size = 0, mtime = 0, isDir = e.isDirectory();
          try { const st = fs.statSync(path.join(target, e.name)); size = st.size; mtime = st.mtimeMs; isDir = st.isDirectory(); }
          catch (_) {}
          return { name: e.name, isDir, size, mtime };
        });
        entries.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : (a.isDir ? -1 : 1)));
      } catch (e) {
        this._sendJson(res, 500, { error: 'Could not read folder.' });
        return;
      }
      this._sendJson(res, 200, { path: u.searchParams.get('path') || '', entries });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/download') {
      const rel = u.searchParams.get('path') || '';
      const resolved = this._resolveUserPath(session.roots || [session.root], rel);
      const target = resolved && !resolved.isVirtualRoot ? resolved.target : null;
      if (target === null || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
        this._sendJson(res, 404, { error: 'File not found.' });
        return;
      }
      const size = fs.statSync(target).size;
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': size,
        'Content-Disposition': 'attachment; filename="' + path.basename(target).replace(/["\r\n]/g, '') + '"',
      });
      this._audit(ip, session.user, 'download', rel || path.basename(target));
      // A read stream with no error listener throws as an uncaught
      // exception if the file vanishes mid-download — and that kills
      // the whole app (scheduler, tray and server included).
      const rs = fs.createReadStream(target);
      rs.on('error', () => { try { if (!res.headersSent) res.writeHead(410, { 'Content-Type': 'application/json' }); res.end(); } catch (_) {} });
      rs.pipe(res);
      return;
    }

    if (req.method === 'POST' && pathname === '/api/upload') {
      if (!session.canWrite) { this._sendJson(res, 403, { error: 'This user is read-only.' }); return; }
      const rel = u.searchParams.get('path') || '';
      const resolved = this._resolveUserPath(session.roots || [session.root], rel);
      const dir = resolved && !resolved.isVirtualRoot ? resolved.target : null;
      const fileName = String(req.headers['x-filename'] || '').split(/[\\/]/).pop();
      if (dir === null || !fileName || !fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
        this._sendJson(res, 400, { error: 'Bad upload destination.' });
        return;
      }
      const declared = parseInt(req.headers['content-length'] || '', 10);
      if (declared > this.maxUploadBytes) { this._sendJson(res, 413, { error: 'File is too large.' }); return; }
      const dest = path.join(dir, fileName);
      if (this._uploadsInFlight.has(dest)) { this._sendJson(res, 409, { error: 'An upload to this file is already in progress.' }); return; }
      // Write to a temp file and rename into place only on success:
      // a failed or aborted upload must never leave a truncated file
      // that looks complete, and two uploads to the same name must
      // never interleave into one file.
      const tmp = dest + '.part-' + crypto.randomBytes(6).toString('hex');
      this._uploadsInFlight.add(dest);
      let received = 0;
      let tooBig = false;
      const self = this;
      const counter = new stream.Transform({
        transform(chunk, enc, cb) {
          received += chunk.length;
          if (received > self.maxUploadBytes) { tooBig = true; cb(new Error('File is too large.')); }
          else cb(null, chunk);
        },
      });
      try {
        await stream.promises.pipeline(req, counter, fs.createWriteStream(tmp));
      } catch (e) {
        this._uploadsInFlight.delete(dest);
        try { fs.unlinkSync(tmp); } catch (_) {}
        if (tooBig) { try { this._sendJson(res, 413, { error: 'File is too large.' }); } catch (_) {} }
        else if (!res.headersSent) { try { this._sendJson(res, 400, { error: 'Upload failed.' }); } catch (_) {} }
        return;
      }
      this._uploadsInFlight.delete(dest);
      try { fs.renameSync(tmp, dest); }
      catch (e) {
        try { fs.unlinkSync(tmp); } catch (_) {}
        this._sendJson(res, 500, { error: 'Could not save the uploaded file.' });
        return;
      }
      this._audit(ip, session.user, 'upload', (rel ? rel + '/' : '') + fileName);
      this._sendJson(res, 200, { ok: true, name: fileName });
      return;
    }

    if (req.method === 'POST' && (pathname === '/api/mkdir' || pathname === '/api/delete' || pathname === '/api/rename' || pathname === '/api/copy')) {
      if (!session.canWrite) { this._sendJson(res, 403, { error: 'This user is read-only.' }); return; }
      let body;
      try { body = await this._readJsonBody(req); }
      catch (e) { this._sendJson(res, 400, { error: e.message }); return; }
      if (!body || typeof body !== 'object') { this._sendJson(res, 400, { error: 'Invalid request.' }); return; }
      // Multi-root: every path resolves through the user's roots
      // (first segment = the root's display name). resolve() returns
      // null for the virtual root itself and for paths that escape.
      const roots = session.roots || [session.root];
      const resolve = (p) => {
        const r = this._resolveUserPath(roots, p || '');
        return r && !r.isVirtualRoot ? r : null;
      };
      try {
        if (pathname === '/api/mkdir') {
          const r = resolve(body.path || '');
          if (r === null) throw new Error('Bad path.');
          fs.mkdirSync(r.target, { recursive: true });
          this._audit(ip, session.user, 'mkdir', body.path || '');
          this._sendJson(res, 200, { ok: true });
          return;
        }
        // A shared folder itself can never be deleted, moved or
        // copied: deleting it would brick the user until an admin
        // fixes it. Each root guards itself (r.isRoot).
        // copy (duplicate): file or folder, to a path that must not
        // exist yet — the client picks a free "name - copy" name.
        // Never the shared folder itself, never a folder into itself.
        if (pathname === '/api/copy') {
          const from = resolve(body.from || '');
          if (!from || !fs.existsSync(from.target)) throw new Error('Bad path.');
          if (from.isRoot) throw new Error('Cannot copy the shared folder itself.');
          const to = resolve(body.to || '');
          if (!to) throw new Error('Bad path.');
          if (to.target === from.target || to.target.startsWith(from.target + path.sep)) throw new Error('Cannot copy a folder into itself.');
          if (fs.existsSync(to.target)) throw new Error('A file or folder with that name already exists.');
          fs.mkdirSync(path.dirname(to.target), { recursive: true });
          fs.cpSync(from.target, to.target, { recursive: true, force: false, errorOnExist: true });
          this._audit(ip, session.user, 'copy', (body.from || '') + ' -> ' + (body.to || ''));
          this._sendJson(res, 200, { ok: true });
          return;
        }
        // delete
        if (pathname === '/api/delete') {
          const r = resolve(body.path || '');
          if (r === null || !fs.existsSync(r.target)) throw new Error('Not found.');
          if (r.isRoot) throw new Error('Cannot delete the shared folder itself.');
          const st = fs.statSync(r.target);
          if (st.isDirectory()) fs.rmSync(r.target, { recursive: true, force: true });
          else fs.unlinkSync(r.target);
          this._audit(ip, session.user, 'delete', body.path || '');
          this._sendJson(res, 200, { ok: true });
          return;
        }
        // rename
        const from = resolve(body.from || '');
        if (!from || !fs.existsSync(from.target)) throw new Error('Bad path.');
        if (from.isRoot) throw new Error('Cannot move the shared folder itself.');
        const to = resolve(body.to || '');
        if (!to) throw new Error('Bad path.');
        fs.mkdirSync(path.dirname(to.target), { recursive: true });
        fs.renameSync(from.target, to.target);
        this._audit(ip, session.user, 'rename', (body.from || '') + ' -> ' + (body.to || ''));
        this._sendJson(res, 200, { ok: true });
        return;
      } catch (e) {
        this._sendJson(res, 400, { error: e.message || 'Operation failed.' });
        return;
      }
    }

    this._sendJson(res, 404, { error: 'Unknown endpoint.' });
  }

  // ---------- WebDAV (Map network drive, /dav) ----------
  // Same server, port, TLS cert, users and jail as /api/*. The
  // Windows WebClient (Map network drive) speaks WebDAV over HTTPS
  // with HTTP Basic auth — it cannot send our Bearer tokens, so DAV
  // authenticates per request against the same scrypt store, with
  // the same login lockout. No new dependencies, pure Node.
  _davXmlEscape(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  }

  _davMime(name) {
    const ext = String(name || '').split('.').pop().toLowerCase();
    const map = {
      txt: 'text/plain', html: 'text/html', htm: 'text/html', css: 'text/css',
      js: 'application/javascript', json: 'application/json', xml: 'application/xml',
      pdf: 'application/pdf', zip: 'application/zip',
      png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
      bmp: 'image/bmp', webp: 'image/webp', svg: 'image/svg+xml',
      mp3: 'audio/mpeg', wav: 'audio/wav', mp4: 'video/mp4', mkv: 'video/x-matroska',
      avi: 'video/x-msvideo', mov: 'video/quicktime',
      doc: 'application/msword',
      docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      xls: 'application/vnd.ms-excel',
      xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      ppt: 'application/vnd.ms-powerpoint',
      pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    };
    return map[ext] || 'application/octet-stream';
  }

  // href for a resource: /dav + URL-encoded segments. Collections
  // end with a slash (the redirector expects it).
  _davHref(rel, isDir) {
    const segs = String(rel || '').split('/').filter((s) => s !== '');
    const href = '/dav' + (segs.length ? '/' + segs.map((s) => encodeURIComponent(s)).join('/') : '/');
    return isDir && !href.endsWith('/') ? href + '/' : href;
  }

  _readTextBody(req, limit) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > (limit || 64 * 1024)) { req.destroy(); reject(new Error('Request body too large.')); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  // Basic auth for DAV. Returns { name, root, canWrite } or null
  // (the 401/429 response is already sent).
  async _davAuth(req, res, ip) {
    if (this._lockInfo(ip)) {
      this._sendJson(res, 429, { error: 'Too many failed logins. Try again later.' });
      return null;
    }
    const h = req.headers.authorization || '';
    const m = /^Basic\s+(\S+)$/.exec(h);
    let name = '', password = '';
    if (m) {
      try {
        const decoded = Buffer.from(m[1], 'base64').toString('utf8');
        const i = decoded.indexOf(':');
        if (i >= 0) { name = decoded.slice(0, i); password = decoded.slice(i + 1); }
      } catch (e) {}
    }
    const users = this._serverCfg().users || [];
    const user = users.find((x) => x.name === name);
    // Fast path: this exact credential verified recently, and the
    // user + password hash are unchanged since then — skip scrypt.
    // A wrong password can never hit here (different credential ->
    // different key -> miss -> full scrypt below), and a lockout
    // above already 429s before this point, exactly as before.
    if (m && user && name) {
      const key = crypto.createHash('sha256').update(m[1]).digest('hex');
      const hit = this._davAuthCache.get(key);
      if (hit && hit.name === name && hit.passHash === user.passHash && hit.expiresAt > Date.now()) {
        // Sliding expiry: active playback keeps the entry alive.
        hit.expiresAt = Date.now() + DAV_AUTH_CACHE_TTL_MS;
        this.loginFails.delete(ip);
        const roots = this._userRoots(user);
        return { name: user.name, root: roots[0], roots, canWrite: !!user.canWrite };
      }
      if (hit) this._davAuthCache.delete(key);
    }
    let ok = false;
    if (user && name) {
      ok = await verifyPassword(password, user.salt, user.passHash);
    } else {
      // Same scrypt cost as a real check, so the timing does not
      // reveal whether the user name exists.
      await verifyPassword(password, DUMMY_CREDENTIALS.salt, DUMMY_CREDENTIALS.hash);
    }
    if (!ok) {
      this._noteLoginFail(ip);
      this._audit(ip, name, 'dav login failed', '');
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="TechVision Cloud"', 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Wrong user name or password.' }));
      return null;
    }
    // Remember this verified credential so repeat requests skip
    // scrypt. The key is a hash of the presented token, never the
    // password; the live passHash is re-checked on every hit.
    if (m) {
      const key = crypto.createHash('sha256').update(m[1]).digest('hex');
      if (this._davAuthCache.size >= DAV_AUTH_CACHE_MAX) {
        let oldest = null; let oldestAt = Infinity;
        for (const [k, v] of this._davAuthCache) { if (v.expiresAt < oldestAt) { oldestAt = v.expiresAt; oldest = k; } }
        if (oldest) this._davAuthCache.delete(oldest);
      }
      this._davAuthCache.set(key, { name: user.name, passHash: user.passHash, expiresAt: Date.now() + DAV_AUTH_CACHE_TTL_MS });
    }
    this.loginFails.delete(ip);
    const roots = this._userRoots(user);
    return { name: user.name, root: roots[0], roots, canWrite: !!user.canWrite };
  }

  // Relative path inside the user's root for a /dav request.
  // Returns '' for /dav or /dav/, null on a malformed escape.
  _davRel(pathname) {
    let rest = pathname === '/dav' ? '' : pathname.slice(4);
    if (rest.startsWith('/')) rest = rest.slice(1);
    if (!rest) return '';
    try { return decodeURIComponent(rest); }
    catch (e) { return null; }
  }

  // Destination header of a MOVE/COPY: an absolute URI. Returns the
  // client-relative path, or null when it is not one of ours.
  _davDestRel(req) {
    const dest = req.headers.destination;
    if (!dest) return null;
    let p;
    try { p = new URL(String(dest)).pathname; }
    catch (e) { return null; }
    if (p !== '/dav' && !p.startsWith('/dav/')) return null;
    return this._davRel(p);
  }

  _davLockPrune() {
    const now = Date.now();
    for (const [k, l] of this._davLocks) {
      if (!l || l.expiresAt <= now) this._davLocks.delete(k);
    }
  }

  // Does the request carry the token that locks this path? A locked
  // resource refuses writes without it (423). Tokens arrive in the
  // If header (and, for UNLOCK, the Lock-Token header).
  _davLockCheck(target, req) {
    this._davLockPrune();
    const lock = this._davLocks.get(target);
    if (!lock) return true;
    const hay = (req.headers.if || '') + ' ' + (req.headers['lock-token'] || '');
    const tokens = hay.match(/opaquelocktoken:[^\s)>]+/g) || [];
    return tokens.indexOf(lock.token) >= 0;
  }

  _davLockXml(lock, href) {
    return '<?xml version="1.0" encoding="utf-8" ?>\n' +
      '<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>' +
      '<D:locktype><D:write/></D:locktype>' +
      '<D:lockscope><D:exclusive/></D:lockscope>' +
      '<D:depth>0</D:depth>' +
      '<D:owner>' + this._davXmlEscape(lock.owner || '') + '</D:owner>' +
      '<D:timeout>Second-3600</D:timeout>' +
      '<D:locktoken><D:href>' + this._davXmlEscape(lock.token) + '</D:href></D:locktoken>' +
      '<D:lockroot><D:href>' + this._davXmlEscape(href) + '</D:href></D:lockroot>' +
      '</D:activelock></D:lockdiscovery></D:prop>';
  }

  _davPropXml(target, rel, isDir) {
    let size = 0, mtime = 0;
    try { const st = fs.statSync(target); size = st.size; mtime = st.mtimeMs; } catch (_) {}
    const name = rel ? rel.split('/').pop() : (path.basename(path.normalize(this._realRoot(target) || target)) || 'Cloud');
    const lines = [];
    lines.push('<D:response>');
    lines.push('<D:href>' + this._davXmlEscape(this._davHref(rel, isDir)) + '</D:href>');
    lines.push('<D:propstat><D:prop>');
    lines.push('<D:displayname>' + this._davXmlEscape(name) + '</D:displayname>');
    if (isDir) lines.push('<D:resourcetype><D:collection/></D:resourcetype>');
    else {
      lines.push('<D:resourcetype/>');
      lines.push('<D:getcontentlength>' + size + '</D:getcontentlength>');
      lines.push('<D:getcontenttype>' + this._davMime(name) + '</D:getcontenttype>');
    }
    lines.push('<D:getlastmodified>' + new Date(mtime).toUTCString() + '</D:getlastmodified>');
    lines.push('</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>');
    lines.push('</D:response>');
    return lines.join('\n');
  }

  async _handleDav(req, res, ip, pathname) {
    // OPTIONS needs no auth: the redirector sends it first, without
    // credentials, to discover the server.
    if (req.method === 'OPTIONS') {
      res.writeHead(200, {
        DAV: '1, 2',
        Allow: 'OPTIONS, PROPFIND, GET, PUT, MKCOL, DELETE, MOVE, COPY, LOCK, UNLOCK',
        'MS-Author-Via': 'DAV',
        'Content-Length': '0',
      });
      res.end();
      return;
    }
    const user = await this._davAuth(req, res, ip);
    if (!user) return;
    const rel = this._davRel(pathname);
    if (rel === null) { this._sendJson(res, 400, { error: 'Bad path.' }); return; }
    // Multi-root: the first segment names the root; '' is the
    // virtual root (one folder per root). It has no single target —
    // PROPFIND lists it, anything else gets a 404.
    const resolved = this._resolveUserPath(user.roots, rel);
    if (resolved === null) { this._sendJson(res, 404, { error: 'Not found.' }); return; }
    const target = resolved.target;
    const isRoot = resolved.isRoot;
    const writeMethod = ['PUT', 'MKCOL', 'DELETE', 'MOVE', 'COPY', 'LOCK', 'UNLOCK'].indexOf(req.method) >= 0;
    if (writeMethod && !user.canWrite) { this._sendJson(res, 403, { error: 'This user is read-only.' }); return; }

    if (req.method === 'PROPFIND') {
      try { await this._readTextBody(req, 64 * 1024); } catch (e) { this._sendJson(res, 400, { error: e.message }); return; }
      if (resolved.isVirtualRoot) {
        const depth = String(req.headers.depth || '1').toLowerCase();
        const names = this._rootDisplayNames(user.roots);
        let xml = '<?xml version="1.0" encoding="utf-8" ?>\n<D:multistatus xmlns:D="DAV:">\n';
        xml += '<D:response><D:href>/dav/</D:href><D:propstat><D:prop><D:displayname>Cloud</D:displayname><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n';
        if (depth !== '0') {
          for (let i = 0; i < user.roots.length; i++) {
            xml += this._davPropXml(user.roots[i], names[i], true) + '\n';
          }
        }
        xml += '</D:multistatus>';
        const body = Buffer.from(xml, 'utf8');
        res.writeHead(207, { 'Content-Type': 'application/xml; charset="utf-8"', 'Content-Length': body.length });
        res.end(body);
        return;
      }
      if (!fs.existsSync(target)) { this._sendJson(res, 404, { error: 'Not found.' }); return; }
      const depth = String(req.headers.depth || '1').toLowerCase();
      const deep = depth !== '0';
      let st;
      try { st = fs.statSync(target); } catch (e) { this._sendJson(res, 404, { error: 'Not found.' }); return; }
      const isDir = st.isDirectory();
      let xml = '<?xml version="1.0" encoding="utf-8" ?>\n<D:multistatus xmlns:D="DAV:">\n';
      xml += this._davPropXml(target, rel, isDir) + '\n';
      if (deep && isDir) {
        let names = [];
        try { names = fs.readdirSync(target); } catch (e) { names = []; }
        for (const name of names) {
          const child = path.join(target, name);
          let cisDir = false;
          try { cisDir = fs.statSync(child).isDirectory(); } catch (e) {}
          xml += this._davPropXml(child, (rel ? rel + '/' : '') + name, cisDir) + '\n';
        }
      }
      xml += '</D:multistatus>';
      const body = Buffer.from(xml, 'utf8');
      res.writeHead(207, { 'Content-Type': 'application/xml; charset="utf-8"', 'Content-Length': body.length });
      res.end(body);
      return;
    }

    // The virtual root is a listing only: no file to GET, no folder
    // to create, delete or move.
    if (resolved.isVirtualRoot) { this._sendJson(res, 404, { error: 'Not found.' }); return; }

    if (req.method === 'GET') {
      if (!fs.existsSync(target) || !fs.statSync(target).isFile()) { this._sendJson(res, 404, { error: 'File not found.' }); return; }
      const stat = fs.statSync(target);
      const size = stat.size;
      const range = String(req.headers.range || '');
      const rm = /^bytes=(\d*)-(\d*)$/.exec(range);
      let start = 0, end = size - 1, partial = false;
      if (rm) {
        if (rm[1] === '' && rm[2] !== '') { start = Math.max(0, size - parseInt(rm[2], 10)); }
        else {
          start = parseInt(rm[1] || '0', 10);
          if (rm[2] !== '') end = Math.min(parseInt(rm[2], 10), size - 1);
        }
        if (isNaN(start) || isNaN(end) || start < 0 || end < start || start >= size) {
          res.writeHead(416, { 'Content-Range': 'bytes */' + size });
          res.end();
          return;
        }
        partial = true;
      }
      res.writeHead(partial ? 206 : 200, {
        'Content-Type': this._davMime(path.basename(target)),
        'Content-Length': end - start + 1,
        'Accept-Ranges': 'bytes',
        'Last-Modified': new Date(stat.mtimeMs).toUTCString(),
        ...(partial ? { 'Content-Range': 'bytes ' + start + '-' + end + '/' + size } : {}),
      });
      if (!size) { res.end(); return; }
      const rs = fs.createReadStream(target, { start, end });
      rs.on('error', () => { try { if (!res.headersSent) res.writeHead(410, { 'Content-Type': 'application/json' }); res.end(); } catch (_) {} });
      rs.pipe(res);
      return;
    }

    if (req.method === 'PUT') {
      if (!this._davLockCheck(target, req)) { this._sendJson(res, 423, { error: 'File is locked.' }); return; }
      if (fs.existsSync(target) && fs.statSync(target).isDirectory()) { this._sendJson(res, 405, { error: 'Target is a folder.' }); return; }
      const parent = path.dirname(target);
      if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) { this._sendJson(res, 409, { error: 'Parent folder does not exist.' }); return; }
      const declared = parseInt(req.headers['content-length'] || '', 10);
      if (!isNaN(declared) && declared > this.maxUploadBytes) { this._sendJson(res, 413, { error: 'File is too large.' }); return; }
      const existed = fs.existsSync(target);
      const tmp = target + '.part-' + crypto.randomBytes(6).toString('hex');
      let received = 0;
      let tooBig = false;
      const self = this;
      const counter = new stream.Transform({
        transform(chunk, enc, cb) {
          received += chunk.length;
          if (received > self.maxUploadBytes) { tooBig = true; cb(new Error('File is too large.')); }
          else cb(null, chunk);
        },
      });
      try {
        await stream.promises.pipeline(req, counter, fs.createWriteStream(tmp));
      } catch (e) {
        try { fs.unlinkSync(tmp); } catch (_) {}
        if (tooBig) { try { this._sendJson(res, 413, { error: 'File is too large.' }); } catch (_) {} }
        else if (!res.headersSent) { try { this._sendJson(res, 400, { error: 'Upload failed.' }); } catch (_) {} }
        return;
      }
      try { fs.renameSync(tmp, target); }
      catch (e) {
        try { fs.unlinkSync(tmp); } catch (_) {}
        this._sendJson(res, 500, { error: 'Could not save the file.' });
        return;
      }
      this._audit(ip, user.name, 'dav put', rel);
      if (existed) { res.writeHead(204); res.end(); return; }
      this._sendJson(res, 201, { ok: true });
      return;
    }

    if (req.method === 'MKCOL') {
      try { await this._readTextBody(req, 64 * 1024); } catch (e) {}
      if (fs.existsSync(target)) { this._sendJson(res, 405, { error: 'A file or folder with that name already exists.' }); return; }
      const parent = path.dirname(target);
      if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) { this._sendJson(res, 409, { error: 'Parent folder does not exist.' }); return; }
      try { fs.mkdirSync(target); } catch (e) { this._sendJson(res, 500, { error: 'Could not create the folder.' }); return; }
      this._audit(ip, user.name, 'dav mkdir', rel);
      this._sendJson(res, 201, { ok: true });
      return;
    }

    if (req.method === 'DELETE') {
      if (isRoot) { this._sendJson(res, 403, { error: 'Cannot delete the shared folder itself.' }); return; }
      if (!fs.existsSync(target)) { this._sendJson(res, 404, { error: 'Not found.' }); return; }
      if (!this._davLockCheck(target, req)) { this._sendJson(res, 423, { error: 'File is locked.' }); return; }
      try {
        const st = fs.statSync(target);
        if (st.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
        else fs.unlinkSync(target);
      } catch (e) { this._sendJson(res, 500, { error: 'Could not delete.' }); return; }
      this._audit(ip, user.name, 'dav delete', rel);
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'MOVE' || req.method === 'COPY') {
      const destRel = this._davDestRel(req);
      if (destRel === null) { this._sendJson(res, 400, { error: 'Destination header is missing or invalid.' }); return; }
      // The source root itself can never be moved: check it before
      // the destination (a new top-level name has no root to resolve
      // against, and must still get the shared-folder error).
      if (isRoot) { this._sendJson(res, 403, { error: 'Cannot move the shared folder itself.' }); return; }
      const destResolved = this._resolveUserPath(user.roots, destRel);
      if (destResolved === null || destResolved.isVirtualRoot) { this._sendJson(res, 404, { error: 'Destination not found.' }); return; }
      if (destResolved.isRoot) { this._sendJson(res, 403, { error: 'Cannot replace a shared folder.' }); return; }
      const dest = destResolved.target;
      if (!fs.existsSync(target)) { this._sendJson(res, 404, { error: 'Not found.' }); return; }
      if (req.method === 'MOVE' && !this._davLockCheck(target, req)) { this._sendJson(res, 423, { error: 'File is locked.' }); return; }
      if (dest === target) { this._sendJson(res, 403, { error: 'Source and destination are the same.' }); return; }
      if (dest.startsWith(target + path.sep)) { this._sendJson(res, 403, { error: 'Cannot move a folder into itself.' }); return; }
      const destExists = fs.existsSync(dest);
      const overwrite = String(req.headers.overwrite || 'T').toUpperCase() !== 'F';
      if (destExists && !overwrite) { this._sendJson(res, 412, { error: 'Destination already exists.' }); return; }
      const destParent = path.dirname(dest);
      if (!fs.existsSync(destParent) || !fs.statSync(destParent).isDirectory()) { this._sendJson(res, 409, { error: 'Destination folder does not exist.' }); return; }
      if (destExists) {
        const srcIsDir = fs.statSync(target).isDirectory();
        const dstIsDir = fs.statSync(dest).isDirectory();
        if (srcIsDir !== dstIsDir) { this._sendJson(res, 409, { error: 'Cannot replace a file with a folder (or the other way round).' }); return; }
      }
      try {
        if (destExists) {
          const dst = fs.statSync(dest);
          if (dst.isDirectory()) fs.rmSync(dest, { recursive: true, force: true });
          else fs.unlinkSync(dest);
        }
        if (req.method === 'MOVE') {
          try { fs.renameSync(target, dest); }
          catch (e) {
            if (e.code !== 'EXDEV') throw e;
            fs.cpSync(target, dest, { recursive: true, force: false, errorOnExist: true });
            const st = fs.statSync(target);
            if (st.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
            else fs.unlinkSync(target);
          }
        } else {
          fs.cpSync(target, dest, { recursive: true, force: false, errorOnExist: true });
        }
      } catch (e) {
        this._sendJson(res, 500, { error: 'Could not ' + (req.method === 'MOVE' ? 'move' : 'copy') + ' the file.' });
        return;
      }
      this._audit(ip, user.name, req.method === 'MOVE' ? 'dav move' : 'dav copy', rel + ' -> ' + destRel);
      if (destExists) { res.writeHead(204); res.end(); return; }
      this._sendJson(res, 201, { ok: true });
      return;
    }

    if (req.method === 'LOCK') {
      let body = '';
      try { body = await this._readTextBody(req, 64 * 1024); } catch (e) { this._sendJson(res, 400, { error: e.message }); return; }
      if (!fs.existsSync(target)) { this._sendJson(res, 404, { error: 'Not found.' }); return; }
      this._davLockPrune();
      const ifTokens = (req.headers.if || '').match(/opaquelocktoken:[^\s)>]+/g) || [];
      // Refresh: an empty body with the token in the If header just
      // extends the lock instead of creating a new one.
      if (!body.trim() && ifTokens.length) {
        const existing = this._davLocks.get(target);
        if (existing && existing.token === ifTokens[0]) {
          existing.expiresAt = Date.now() + 3600 * 1000;
          const xml = this._davLockXml(existing, this._davHref(rel, false));
          const b = Buffer.from(xml, 'utf8');
          res.writeHead(200, { 'Content-Type': 'application/xml; charset="utf-8"', 'Content-Length': b.length, 'Lock-Token': '<' + existing.token + '>' });
          res.end(b);
          return;
        }
        this._sendJson(res, 412, { error: 'Lock token does not match.' });
        return;
      }
      const existing = this._davLocks.get(target);
      if (existing) { this._sendJson(res, 423, { error: 'File is already locked.' }); return; }
      const lock = {
        token: 'opaquelocktoken:' + crypto.randomUUID(),
        expiresAt: Date.now() + 3600 * 1000,
        owner: user.name,
      };
      this._davLocks.set(target, lock);
      this._audit(ip, user.name, 'dav lock', rel);
      const xml = this._davLockXml(lock, this._davHref(rel, false));
      const b = Buffer.from(xml, 'utf8');
      res.writeHead(200, { 'Content-Type': 'application/xml; charset="utf-8"', 'Content-Length': b.length, 'Lock-Token': '<' + lock.token + '>' });
      res.end(b);
      return;
    }

    if (req.method === 'UNLOCK') {
      const m = /opaquelocktoken:[^\s)>]+/.exec(req.headers['lock-token'] || '');
      if (!m) { this._sendJson(res, 400, { error: 'Lock-Token header is missing.' }); return; }
      this._davLockPrune();
      for (const [k, l] of this._davLocks) {
        if (l.token === m[0]) { this._davLocks.delete(k); break; }
      }
      this._audit(ip, user.name, 'dav unlock', rel);
      res.writeHead(204);
      res.end();
      return;
    }

    this._sendJson(res, 405, { error: 'Method not supported for WebDAV.' });
  }
}

module.exports = { CloudServer, defaultServerConfig, ensureCert, certSans, certCoversHost, certNeedsRegen, fingerprintOfCertPem, hashPassword, verifyPassword, lanIPs, detectPublicIP, MAX_UPLOAD_BYTES };
