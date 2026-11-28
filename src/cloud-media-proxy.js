'use strict';
// Local loopback media proxy (2026-11-28).
//
// Why: a non-WinINET player (PotPlayer, VLC, ...) cannot use the
// Credential Manager login the app seeds, so the DAV server answers
// 401 and the player exits with an error (code 1) — nothing plays.
// Chrome used to hide that by prompting / using cached credentials;
// the Chrome fallback is gone by Mohamed's decision, so the failure
// became visible instead.
//
// How: the app serves the file to the player itself over plain HTTP
// on 127.0.0.1 with a one-time token URL — no auth, no credentials,
// no filename in the URL — and fetches upstream from DAV with the
// app's own credentials (HTTP Basic over pinned TLS, the same path
// the credential-verify probe uses). Range requests are forwarded
// so seeking/scrubbing works. The URL works for ANY registered
// player, because from the player's side it is a plain local HTTP
// stream with no login.
//
// Security:
// - Binds 127.0.0.1 ONLY (never 0.0.0.0); ephemeral port.
// - Tokens are random 192-bit base64url, bound to one server record
//   + one file; the file identity lives server-side, never in the
//   URL (the URL carries only the token + the file extension, so
//   players that sniff the extension still pick the right demuxer).
// - Tokens slide-expire 15 minutes after the last fetch (absolute
//   cap 4 hours) and are revoked on disconnect / Forget / record
//   remove / vault lock / vault reset. Wrong or expired token -> 404.
// - Upstream 401/429 never reaches the player (mapped to 502), so
//   no player can pop a login dialog for the Cloud server.
// - Nothing sensitive is ever logged: no token, no password, no DAV
//   URL, no filename — the module logs nothing at all.
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const DEFAULT_TOKEN_TTL_MS = 15 * 60 * 1000;
const TOKEN_MAX_AGE_MS = 4 * 60 * 60 * 1000;
const MAX_TOKENS = 64;
const UPSTREAM_TIMEOUT_MS = 30000;
const SWEEP_MS = 60 * 1000;

// Headers a player needs, copied from the upstream DAV response.
// Anything else (notably WWW-Authenticate / Set-Cookie / Server)
// is never forwarded.
const FORWARDED_HEADERS = ['content-type', 'content-length', 'content-range', 'accept-ranges', 'last-modified', 'etag'];

function davPathFor(relPath) {
  const segs = String(relPath || '').split('/').filter((s) => s !== '');
  return '/dav/' + segs.map((s) => encodeURIComponent(s)).join('/');
}

function extOf(relPath) {
  const base = String(relPath || '').split('/').pop() || '';
  const i = base.lastIndexOf('.');
  if (i <= 0) return '';
  return base.slice(i + 1).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8);
}

function createMediaProxy(resolveCredentials, opts) {
  opts = opts || {};
  const tokenTtlMs = opts.tokenTtlMs || DEFAULT_TOKEN_TTL_MS;
  const tokens = new Map(); // token -> { serverId, relPath, ext, createdAt, expiresAt }
  // One shared upstream agent: without it, every proxied player
  // request opens a fresh TLS connection to the DAV server (the
  // default https.request has keep-alive off) — a handshake per
  // chunk on top of the per-request scrypt the DAV cache now skips.
  // NOTE: checkServerIdentity MUST live on the agent, not on each
  // request — a fresh arrow function per request makes the agent
  // treat every request as a different pool (measured: 48 TLS
  // connections for 48 chunks) and reuse never happens. The check
  // itself is unchanged (hostname verification off; the pinned
  // cert in `ca` is the trust anchor, exactly as before) — only
  // where the option sits moved. `ca` stays per-request because it
  // varies per server record, and that does not break reuse.
  const upstreamAgent = new https.Agent({ keepAlive: true, maxSockets: 8, checkServerIdentity: () => undefined });
  let server = null;
  let address = null;
  let sweepTimer = null;

  function purgeExpired() {
    const now = Date.now();
    for (const [t, rec] of tokens) {
      if (rec.expiresAt <= now) tokens.delete(t);
    }
  }

  function startSweep() {
    if (sweepTimer) return;
    sweepTimer = setInterval(purgeExpired, SWEEP_MS);
    if (sweepTimer.unref) sweepTimer.unref();
  }

  function lookupToken(token) {
    const rec = tokens.get(token);
    if (!rec) return null;
    if (rec.expiresAt <= Date.now()) { tokens.delete(token); return null; }
    // Sliding expiry: the token stays alive while the player is
    // actively fetching (long playback + seeks), and dies 15 min
    // after the last fetch. Absolute cap: 4 hours from mint.
    rec.expiresAt = Math.min(Date.now() + tokenTtlMs, rec.createdAt + TOKEN_MAX_AGE_MS);
    return rec;
  }

  function send404(res) {
    try { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); } catch (e) {}
  }
  function send502(res) {
    try { if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('Bad gateway'); } catch (e) {}
  }

  function onRequest(req, res) {
    // Only media fetches: GET (play/seek) and HEAD (probe).
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      try { res.writeHead(405, { 'Content-Type': 'text/plain' }); res.end('Method not allowed'); } catch (e) {}
      return;
    }
    let pathname = '';
    try { pathname = decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname); } catch (e) { return send404(res); }
    const m = /^\/([A-Za-z0-9_-]{16,})(\.[A-Za-z0-9]{1,8})?$/.exec(pathname);
    if (!m) return send404(res);
    const rec = lookupToken(m[1]);
    if (!rec) return send404(res);

    let creds = null;
    try { creds = resolveCredentials(rec.serverId); } catch (e) { creds = null; }
    if (!creds || !creds.host || !creds.port || !creds.certPem || !creds.user || !creds.password) return send502(res);

    const headers = {
      Authorization: 'Basic ' + Buffer.from(String(creds.user) + ':' + String(creds.password)).toString('base64'),
    };
    if (req.headers.range) headers.Range = req.headers.range;
    // A HEAD is a probe: the player wants headers, not bytes. Ask
    // upstream for one byte only instead of opening a full stream
    // that gets destroyed — but only when the player did not ask for
    // a range itself (its range is forwarded as-is).
    const headProbe = req.method === 'HEAD' && !req.headers.range;
    if (headProbe) headers.Range = 'bytes=0-0';
    let upReq;
    // True once the upstream response has finished normally. The
    // player's close handler below must only destroy the upstream
    // request on a PREMATURE close — destroying it after a normal
    // finish would kill the keep-alive socket and lose reuse.
    let upFinished = false;
    try {
      upReq = https.request({
        host: String(creds.host), port: parseInt(creds.port, 10),
        path: davPathFor(rec.relPath), method: 'GET',
        ca: [creds.certPem],
        agent: upstreamAgent,
        headers,
      }, (upRes) => {
        // Never let an auth challenge reach the player: a 401 here
        // would pop a login dialog in some players.
        if (upRes.statusCode === 401 || upRes.statusCode === 429) {
          try { upRes.resume(); } catch (e) {}
          return send502(res);
        }
        // Pass through only the statuses a player understands;
        // anything else is an upstream failure, not a playable file.
        if (upRes.statusCode !== 200 && upRes.statusCode !== 206 && upRes.statusCode !== 404 && upRes.statusCode !== 416) {
          try { upRes.resume(); } catch (e) {}
          return send502(res);
        }
        const out = {};
        for (const h of FORWARDED_HEADERS) {
          if (upRes.headers[h] !== undefined) out[h] = upRes.headers[h];
        }
        if (req.method === 'HEAD') {
          // Headers only: the player is probing. Do not stream the
          // file — end the response. For a 1-byte probe, drain that
          // byte so the socket returns to the keep-alive pool; for
          // anything else (a full 200 stream) drop the socket
          // instead, so the file is not downloaded for a probe.
          let status = upRes.statusCode;
          if (headProbe) {
            // The probe fetched one byte upstream (Range: bytes=0-0),
            // so the answer must NOT look like a range answer: a 206
            // whose Content-Length is the whole file and whose
            // Content-Range covers one byte is self-contradictory,
            // and players (PotPlayer) reject it as "file not found"
            // without ever issuing a GET. Synthesize the 200 a plain
            // GET would have carried: full length, no Content-Range.
            // The 1-byte upstream fetch stays (the speed win stays).
            const cr = String(upRes.headers['content-range'] || '');
            if (upRes.statusCode === 206) {
              const cm = /^bytes \d+-\d+\/(\d+)$/.exec(cr);
              if (cm) { status = 200; out['content-length'] = cm[1]; delete out['content-range']; }
            } else if (upRes.statusCode === 416) {
              // Empty file: the 1-byte probe is out of range upstream
              // (Content-Range: bytes */N). Answer 200 with the
              // total length, as the old proxy did.
              const cm = /^bytes \*\/(\d+)$/.exec(cr);
              if (cm) { status = 200; out['content-length'] = cm[1]; delete out['content-range']; }
            }
            // 404 passes through untouched (file really missing /
            // wrong user); 200 passes through as today.
          }
          try { res.writeHead(status, out); res.end(); } catch (e) {}
          if (upRes.statusCode === 206) { upFinished = true; try { upRes.resume(); } catch (e) {} }
          else { try { upReq.destroy(); } catch (e) {} }
          return;
        }
        try { res.writeHead(upRes.statusCode, out); } catch (e) { try { upReq.destroy(); } catch (e2) {} return; }
        upRes.on('end', () => { upFinished = true; try { upReq.setTimeout(0); } catch (e) {} });
        upRes.on('error', () => { try { res.destroy(); } catch (e) {} });
        upRes.pipe(res);
      });
    } catch (e) { return send502(res); }
    upReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => { try { upReq.destroy(new Error('upstream timeout')); } catch (e) {} });
    upReq.on('timeout', () => { try { upReq.destroy(new Error('upstream timeout')); } catch (e) {} });
    upReq.on('error', () => send502(res));
    // The player gave up mid-stream: stop fetching upstream too.
    // (After a normal finish the socket belongs to the keep-alive
    // pool — destroying the request then would lose reuse.)
    res.on('close', () => { if (!upFinished) { try { upReq.destroy(); } catch (e) {} } });
    upReq.end();
  }

  function start() {
    if (server && address) return Promise.resolve(address);
    if (server) return new Promise((resolve, reject) => { server.once('listening', () => resolve(address)); server.once('error', reject); });
    return new Promise((resolve, reject) => {
      server = http.createServer(onRequest);
      server.on('error', (e) => { server = null; address = null; reject(e); });
      server.listen(0, '127.0.0.1', () => {
        address = server.address();
        startSweep();
        resolve(address);
      });
    });
  }

  function stop() {
    return new Promise((resolve) => {
      tokens.clear();
      try { upstreamAgent.destroy(); } catch (e) {}
      if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
      if (!server) { address = null; return resolve(); }
      const s = server; server = null; address = null;
      try { s.close(() => resolve()); } catch (e) { resolve(); }
      setTimeout(resolve, 1000);
    });
  }

  async function mint(serverId, relPath) {
    if (!serverId || !relPath) return null;
    let addr;
    try { addr = await start(); } catch (e) { return null; }
    if (!addr || !addr.port) return null;
    purgeExpired();
    // Bound the token table: drop the oldest token first.
    if (tokens.size >= MAX_TOKENS) {
      let oldest = null; let oldestAt = Infinity;
      for (const [t, r] of tokens) { if (r.createdAt < oldestAt) { oldestAt = r.createdAt; oldest = t; } }
      if (oldest) tokens.delete(oldest);
    }
    const token = crypto.randomBytes(24).toString('base64url');
    const ext = extOf(relPath);
    const now = Date.now();
    tokens.set(token, { serverId, relPath: String(relPath), ext, createdAt: now, expiresAt: now + tokenTtlMs });
    return 'http://127.0.0.1:' + addr.port + '/' + token + (ext ? '.' + ext : '');
  }

  function revokeServer(serverId) {
    for (const [t, r] of tokens) { if (r.serverId === serverId) tokens.delete(t); }
  }
  function revokeAll() { tokens.clear(); }

  return {
    start,
    stop,
    mint,
    revokeServer,
    revokeAll,
    address: () => (address ? { address: address.address, port: address.port } : null),
    tokenCount: () => tokens.size,
  };
}

module.exports = { createMediaProxy };
