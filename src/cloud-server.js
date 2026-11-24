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
  return { enabled: false, port: 8443, cert: null, users: [], accessMode: 'normal' };
}

function ensureCert(cfg) {
  if (cfg.cert && cfg.cert.cert && cfg.cert.key && cfg.cert.fingerprint) return cfg.cert;
  if (!selfsigned) {
    throw new Error('The "selfsigned" package is not installed. Run "npm install" in the project folder, then start the server again.');
  }
  const attrs = [{ name: 'commonName', value: os.hostname() || 'TechVision-Cloud' }];
  const pems = selfsigned.generate(attrs, { days: 3650, keySize: 2048, algorithm: 'sha256' });
  cfg.cert = {
    cert: pems.cert,
    key: pems.private,
    fingerprint: fingerprintOfCertPem(pems.cert),
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
  listUsers() {
    return (this._serverCfg().users || []).map((u) => ({
      name: u.name, root: u.root, canWrite: !!u.canWrite,
    }));
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
    users.push({ name: clean, passHash: hash, salt, root: path.normalize(root), canWrite: !!canWrite });
    this.onConfigChange();
    return { name: clean, root: path.normalize(root), canWrite: !!canWrite };
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
  }

  // --- lifecycle ---
  async start() {
    if (this.httpsServer) return this.status();
    const scfg = this._serverCfg();
    ensureCert(scfg);
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
      this.sessions.set(token, { user: user.name, root: user.root, canWrite: !!user.canWrite, expiresAt: Date.now() + TOKEN_TTL_MS });
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

    const session = this._auth(req);
    if (!session) { this._sendJson(res, 401, { error: 'Not signed in.' }); return; }

    if (req.method === 'GET' && pathname === '/api/info') {
      this._sendJson(res, 200, { name: 'TechVision Cloud', version: 1, user: session.user, root: session.root, canWrite: session.canWrite });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/list') {
      const target = this._jail(session.root, u.searchParams.get('path') || '');
      if (target === null || !fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
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
      const target = this._jail(session.root, u.searchParams.get('path') || '');
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
      this._audit(ip, session.user, 'download', path.relative(session.root, target) || path.basename(target));
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
      const dir = this._jail(session.root, u.searchParams.get('path') || '');
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
      this._audit(ip, session.user, 'upload', path.relative(session.root, dest));
      this._sendJson(res, 200, { ok: true, name: fileName });
      return;
    }

    if (req.method === 'POST' && (pathname === '/api/mkdir' || pathname === '/api/delete' || pathname === '/api/rename')) {
      if (!session.canWrite) { this._sendJson(res, 403, { error: 'This user is read-only.' }); return; }
      let body;
      try { body = await this._readJsonBody(req); }
      catch (e) { this._sendJson(res, 400, { error: e.message }); return; }
      if (!body || typeof body !== 'object') { this._sendJson(res, 400, { error: 'Invalid request.' }); return; }
      try {
        if (pathname === '/api/mkdir') {
          const target = this._jail(session.root, body.path || '');
          if (target === null) throw new Error('Bad path.');
          fs.mkdirSync(target, { recursive: true });
          this._audit(ip, session.user, 'mkdir', body.path || '');
          this._sendJson(res, 200, { ok: true });
          return;
        }
        // The shared folder itself can never be deleted or moved:
        // deleting it would brick the user until an admin fixes it.
        const realRoot = this._realRoot(session.root);
        if (pathname === '/api/delete') {
          const target = this._jail(session.root, body.path || '');
          if (target === null || !fs.existsSync(target)) throw new Error('Not found.');
          if (realRoot !== null && target === realRoot) throw new Error('Cannot delete the shared folder itself.');
          const st = fs.statSync(target);
          if (st.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
          else fs.unlinkSync(target);
          this._audit(ip, session.user, 'delete', body.path || '');
          this._sendJson(res, 200, { ok: true });
          return;
        }
        // rename
        const from = this._jail(session.root, body.from || '');
        const to = this._jail(session.root, body.to || '');
        if (from === null || to === null || !fs.existsSync(from)) throw new Error('Bad path.');
        if (realRoot !== null && from === realRoot) throw new Error('Cannot move the shared folder itself.');
        fs.mkdirSync(path.dirname(to), { recursive: true });
        fs.renameSync(from, to);
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
}

module.exports = { CloudServer, defaultServerConfig, ensureCert, fingerprintOfCertPem, hashPassword, verifyPassword, lanIPs, detectPublicIP, MAX_UPLOAD_BYTES };
