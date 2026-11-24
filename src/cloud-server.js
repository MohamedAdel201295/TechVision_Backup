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

function hashPassword(password, saltB64) {
  const salt = saltB64 ? Buffer.from(saltB64, 'base64') : crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, SCRYPT_OPTS);
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}

function verifyPassword(password, saltB64, hashB64) {
  try {
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(password, salt, 32, SCRYPT_OPTS);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch (e) {
    return false;
  }
}

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
        res.on('data', (c) => { body += c; });
        res.on('end', () => {
          const ip = body.trim();
          resolve(/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? ip : null);
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
    this.loginFails = new Map(); // ip -> { fails, lockedUntil }
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
    this.log('info', `[Cloud] ${user || '-'} @ ${ip || '-'}: ${action}${detail ? ' — ' + detail : ''}`);
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
    this.onConfigChange();
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
    await new Promise((resolve) => s.close(() => resolve()));
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
    const rec = this.loginFails.get(ip);
    if (rec && rec.lockedUntil && Date.now() < rec.lockedUntil) return rec;
    return null;
  }

  _noteLoginFail(ip) {
    const rec = this.loginFails.get(ip) || { fails: 0, lockedUntil: 0 };
    rec.fails += 1;
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
    return s;
  }

  // Jail a client-relative path inside the user's root. Returns the
  // absolute path, or null when it escapes (including via symlinks).
  _jail(root, rel) {
    let realRoot;
    try { realRoot = fs.realpathSync(root); }
    catch (e) { return null; }
    const clean = String(rel || '').replace(/^[/\\]+/, '').split(/[\\/]+/).filter((p) => p && p !== '.').join(path.sep);
    const target = path.join(realRoot, clean);
    if (target !== realRoot && !target.startsWith(realRoot + path.sep)) return null;
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
    if (realProbe !== realRoot && !realProbe.startsWith(realRoot + path.sep)) return null;
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
      const users = this._serverCfg().users || [];
      const user = users.find((x) => x.name === String(body.user || ''));
      const ok = !!user && verifyPassword(String(body.password || ''), user.salt, user.passHash);
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
        'Content-Disposition': 'attachment; filename="' + path.basename(target).replace(/"/g, '') + '"',
      });
      this._audit(ip, session.user, 'download', path.relative(session.root, target) || path.basename(target));
      fs.createReadStream(target).pipe(res);
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
      const dest = path.join(dir, fileName);
      await new Promise((resolve, reject) => {
        const ws = fs.createWriteStream(dest);
        req.pipe(ws);
        ws.on('finish', resolve);
        ws.on('error', reject);
        req.on('error', reject);
      }).catch((e) => { throw e; });
      this._audit(ip, session.user, 'upload', path.relative(session.root, dest));
      this._sendJson(res, 200, { ok: true, name: fileName });
      return;
    }

    if (req.method === 'POST' && (pathname === '/api/mkdir' || pathname === '/api/delete' || pathname === '/api/rename')) {
      if (!session.canWrite) { this._sendJson(res, 403, { error: 'This user is read-only.' }); return; }
      let body;
      try { body = await this._readJsonBody(req); }
      catch (e) { this._sendJson(res, 400, { error: e.message }); return; }
      try {
        if (pathname === '/api/mkdir') {
          const target = this._jail(session.root, body.path || '');
          if (target === null) throw new Error('Bad path.');
          fs.mkdirSync(target, { recursive: true });
          this._audit(ip, session.user, 'mkdir', body.path || '');
          this._sendJson(res, 200, { ok: true });
          return;
        }
        if (pathname === '/api/delete') {
          const target = this._jail(session.root, body.path || '');
          if (target === null || !fs.existsSync(target)) throw new Error('Not found.');
          const st = fs.statSync(target);
          if (st.isDirectory()) fs.rmdirSync(target);
          else fs.unlinkSync(target);
          this._audit(ip, session.user, 'delete', body.path || '');
          this._sendJson(res, 200, { ok: true });
          return;
        }
        // rename
        const from = this._jail(session.root, body.from || '');
        const to = this._jail(session.root, body.to || '');
        if (from === null || to === null || !fs.existsSync(from)) throw new Error('Bad path.');
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

module.exports = { CloudServer, defaultServerConfig, ensureCert, fingerprintOfCertPem, hashPassword, verifyPassword, lanIPs, detectPublicIP };
