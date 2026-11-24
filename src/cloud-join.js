'use strict';
/*
 * TechVision WireGuard VPN — Cloud join (Phase 2, part c).
 *
 * The third key-exchange option (spec: "Join via Cloud"): a client
 * sends a join request through the user's own Cloud connection — same
 * username/password, same TLS-pinned channel, no third party, no new
 * auth scheme — and the server operator presses Approve (an explicit
 * local action). The client then polls for the approval and gets the
 * server public key + endpoint + its allocated tunnel IP back over the
 * same channel, ready for wg-connect to install.
 *
 * What this file is — and is not:
 * - It does NOT edit the Cloud server or client: cloud-server.js has
 *   no route-registration hook, so attachJoinRoutes() wraps the
 *   CloudServer instance's _handle (the https callback dispatches
 *   through `this._handle`, so an instance override is picked up) and
 *   intercepts only /api/wg-join-* paths, delegating everything else
 *   to the original handler untouched. Auth, JSON-body limits and
 *   _sendJson are the server's own methods, reused, not re-implemented.
 *   If cloud-server.js ever gains a registerRoute hook, this wrapper
 *   is the one place to change.
 * - It does NOT add IPC: main.js (the coordinator) wires the IPC
 *   handlers and passes this module a store + the WireGuard deps.
 *   approveJoinRequest() takes those deps explicitly — getPeers(),
 *   addPeer() — because the peer list and its live `wg set` apply
 *   live in main.js (the wg-add-peer handler). The coordinator's
 *   addPeer MUST be the same code path wg-add-peer uses (validate
 *   key, allocate with nextTunnelIp, push to wireguard.json, save,
 *   live-apply with wireguard.setPeer when the server is running);
 *   this module only decides WHICH peer to add and refuses to add
 *   the same public key twice.
 * - cloud-client.js does NOT export its internal doJson helper, so
 *   the client side here has a small pinned-HTTPS JSON helper
 *   (requestJson) that follows doJson's exact pattern (ca: [certPem],
 *   hostname check skipped, Bearer token, 15 s timeout, same TLS
 *   error wording). If doJson is ever exported, requestJson can be
 *   deleted and the calls below pointed at it.
 *
 * Security, stated plainly:
 * - A join request carries ONLY the client's public key + device
 *   name. A private key or a password is never sent, never stored
 *   server-side, and never appears in the persisted pending list.
 *   submitJoinRequest() returns the fresh private key to its caller
 *   (main.js) to hold in memory until approval; this module never
 *   writes it anywhere.
 * - A pending request grants nothing. Only an explicit local
 *   approveJoinRequest() call adds the peer, and it is idempotent by
 *   public key: approving the same device twice (same request twice,
 *   or a second request with the same key) reuses the one tunnel IP.
 * - Request ids are 128-bit random; the status endpoint only answers
 *   the Cloud user who submitted the request (another user gets the
 *   same 404 as an unknown id, so existence does not leak).
 * - Pending requests expire after JOIN_REQUEST_TTL_MS (1 hour).
 *   Approved/rejected entries expire on the same clock, so a stale
 *   approval cannot be polled forever.
 * - 401 handling: CloudServer.stop() clears all sessions, so a
 *   server restart mid-join shows up as 401 on the next poll.
 *   pollJoinStatus() reports that as code 'server-restarted' with
 *   retryable:false and NEVER re-logs-in or retries by itself: an
 *   automatic re-login loop is what could trip the server's
 *   5-failed-logins lockout. The user re-sends the request by hand
 *   (a fresh keypair, a fresh request). Note a status poll itself
 *   can never trip the lockout — only /api/login failures count —
 *   but the client still stops polling on 401 instead of spinning.
 *
 * Persistence: the pending list lives in cloud.json, at
 * cfg.server.wgJoinRequests, through configBackedStore() — the same
 * file the Cloud server already persists through onConfigChange, so
 * a server restart does not lose pending requests. Entries are plain
 * JSON (public key + device name + status only).
 */
const crypto = require('crypto');
const https = require('https');
const wireguard = require('./wireguard.js');

const JOIN_REQUEST_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_DEVICE_NAME_LENGTH = 64;
const API_TIMEOUT_MS = 15000;
const REQUEST_ID_RE = /^[0-9a-f]{32}$/;
const ENDPOINT_RE = /^[A-Za-z0-9.-]+:\d{1,5}$/;
const TUNNEL_IP_RE = /^10\.0\.0\.(\d{1,3})$/;

/* ---------- validation ---------- */

function validateDeviceName(name) {
  if (typeof name !== 'string') return { ok: false, error: 'Give the device a name first.' };
  // Same treatment as main.js wg-add-peer: newlines become spaces.
  const clean = name.replace(/[\r\n]+/g, ' ').trim();
  if (!clean) return { ok: false, error: 'Give the device a name first.' };
  if (clean.length > MAX_DEVICE_NAME_LENGTH) return { ok: false, error: 'Device name must be ' + MAX_DEVICE_NAME_LENGTH + ' characters or fewer.' };
  if (/[\x00-\x1f\x7f]/.test(clean)) return { ok: false, error: 'Device name contains characters that are not allowed.' };
  return { ok: true, name: clean };
}

function validateJoinRequestBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, error: 'Invalid request.' };
  const v = validateDeviceName(body.deviceName);
  if (!v.ok) return v;
  if (!wireguard.isWgKey(body.publicKey)) return { ok: false, error: 'That is not a valid WireGuard public key (44 characters, ending in =).' };
  return { ok: true, deviceName: v.name, publicKey: body.publicKey };
}

function cleanExtraLines(v) {
  if (v == null) return [];
  if (!Array.isArray(v)) throw new Error('Extra config lines must be an array of "Key = value" strings.');
  for (const l of v) {
    if (typeof l !== 'string' || /[\r\n]/.test(l) || l.indexOf('=') < 1 || !l.trim()) throw new Error('Invalid extra config line: "' + String(l).slice(0, 60) + '"');
  }
  return v.map((l) => l.trim());
}

/* ---------- the pending-request store ---------- */

// An entry is plain JSON: { id, deviceName, publicKey, user, status,
// createdAt, expiresAt, approvedAt?, tunnelIp?, serverPublicKey?,
// endpoint?, allowedIPs?, extraInterfaceLines?, extraPeerLines? }.
// No private key, no password, ever.
function isValidEntry(e) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return false;
  if (typeof e.id !== 'string' || !REQUEST_ID_RE.test(e.id)) return false;
  if (typeof e.deviceName !== 'string' || !e.deviceName.trim()) return false;
  if (!wireguard.isWgKey(e.publicKey)) return false;
  if (typeof e.user !== 'string' || !e.user) return false;
  if (['pending', 'approved', 'rejected'].indexOf(e.status) < 0) return false;
  if (!Number.isFinite(e.createdAt) || !Number.isFinite(e.expiresAt)) return false;
  return true;
}

function copyEntry(e) {
  return JSON.parse(JSON.stringify(e));
}

// load(): () => entry array (the source of truth, re-read on every
// operation so a server restart / another process's write is seen).
// save(list): persist the whole list. Both are supplied by the
// coordinator; with no arguments the store is memory-only.
function createJoinStore(opts) {
  const o = opts || {};
  const ttlMs = (typeof o.ttlMs === 'number' && o.ttlMs > 0) ? o.ttlMs : JOIN_REQUEST_TTL_MS;
  const load = typeof o.load === 'function' ? o.load : () => [];
  const save = typeof o.save === 'function' ? o.save : () => {};
  let memory = [];

  // Re-read on every operation: the source of truth is load(), so a
  // server restart (or another writer) is always seen. With no load
  // supplied, the list lives in `memory` instead.
  const hasExternalLoad = typeof o.load === 'function';
  function read() {
    if (!hasExternalLoad) return memory.filter(isValidEntry).map(copyEntry);
    let list = [];
    try {
      const raw = load();
      list = Array.isArray(raw) ? raw.filter(isValidEntry).map(copyEntry) : [];
    } catch (e) { list = []; }
    return list;
  }
  function write(list) {
    const clean = list.filter(isValidEntry).map(copyEntry);
    if (!hasExternalLoad) memory = clean;
    try { save(clean); } catch (e) { /* persistence must not break the join */ }
    return clean;
  }

  // Drop expired entries; returns { list, removed }.
  function pruneList(list, now) {
    const kept = list.filter((e) => e.expiresAt > now);
    return { list: kept, removed: list.length - kept.length };
  }

  return {
    ttlMs,
    prune(now) {
      const p = pruneList(read(), now || Date.now());
      if (p.removed) write(p.list);
      return p.removed;
    },
    submit(req) {
      const v = validateJoinRequestBody(req);
      if (!v.ok) return { success: false, error: v.error };
      const user = String((req && req.user) || '').trim();
      if (!user) return { success: false, error: 'Join request has no Cloud user.' };
      const now = Date.now();
      const p = pruneList(read(), now);
      let list = p.list;
      // Idempotent re-submit: the same user + same public key while a
      // request is still pending returns the original id instead of
      // spamming the server's list with duplicates.
      const existing = list.find((e) => e.status === 'pending' && e.user === user && e.publicKey === v.publicKey);
      if (existing) { if (p.removed) write(list); return { success: true, alreadySubmitted: true, entry: copyEntry(existing) }; }
      const entry = {
        id: crypto.randomBytes(16).toString('hex'),
        deviceName: v.deviceName,
        publicKey: v.publicKey,
        user,
        status: 'pending',
        createdAt: now,
        expiresAt: now + ttlMs,
      };
      list.push(entry);
      write(list);
      return { success: true, entry: copyEntry(entry) };
    },
    get(id) {
      if (typeof id !== 'string' || !REQUEST_ID_RE.test(id)) return null;
      const p = pruneList(read(), Date.now());
      if (p.removed) write(p.list);
      const e = p.list.find((x) => x.id === id);
      return e ? copyEntry(e) : null;
    },
    list(status) {
      const p = pruneList(read(), Date.now());
      if (p.removed) write(p.list);
      const out = status ? p.list.filter((e) => e.status === status) : p.list;
      return out.map(copyEntry);
    },
    listPending() { return this.list('pending'); },
    markApproved(id, approval) {
      const now = Date.now();
      const p = pruneList(read(), now);
      const list = p.list;
      const e = list.find((x) => x.id === id);
      if (!e) return { success: false, error: 'Join request not found or expired.' };
      if (e.status !== 'pending') return { success: false, error: 'Join request is no longer pending (status: ' + e.status + ').' };
      e.status = 'approved';
      e.approvedAt = now;
      e.serverPublicKey = approval.serverPublicKey;
      e.endpoint = approval.endpoint;
      e.tunnelIp = approval.tunnelIp;
      e.allowedIPs = approval.allowedIPs;
      if (approval.extraInterfaceLines) e.extraInterfaceLines = approval.extraInterfaceLines;
      if (approval.extraPeerLines) e.extraPeerLines = approval.extraPeerLines;
      write(list);
      return { success: true, entry: copyEntry(e) };
    },
    markRejected(id) {
      const p = pruneList(read(), Date.now());
      const list = p.list;
      const e = list.find((x) => x.id === id);
      if (!e) return { success: false, error: 'Join request not found or expired.' };
      if (e.status !== 'pending') return { success: false, error: 'Join request is no longer pending (status: ' + e.status + ').' };
      e.status = 'rejected';
      write(list);
      return { success: true, entry: copyEntry(e) };
    },
    cancel(id, user) {
      if (typeof id !== 'string' || !REQUEST_ID_RE.test(id)) return { success: false, code: 'not-found', error: 'Join request not found or expired.' };
      const p = pruneList(read(), Date.now());
      const list = p.list;
      const i = list.findIndex((x) => x.id === id);
      if (i < 0 || list[i].user !== user) return { success: false, code: 'not-found', error: 'Join request not found or expired.' };
      if (list[i].status !== 'pending') return { success: false, code: 'not-pending', error: 'Only a pending request can be cancelled (status: ' + list[i].status + ').' };
      list.splice(i, 1);
      write(list);
      return { success: true };
    },
  };
}

// Store backed by the Cloud config object (cloud.json): the pending
// list lives at cfg.server.wgJoinRequests and is saved through the
// Cloud server's onConfigChange, so it survives a server restart.
// cloudConfig is the same object CloudServer holds, so writes land
// in the file the next time the config is saved.
function configBackedStore(cloudConfig, onConfigChange) {
  const cfg = (cloudConfig && typeof cloudConfig === 'object') ? cloudConfig : {};
  function load() {
    if (!cfg.server || typeof cfg.server !== 'object') cfg.server = {};
    const list = cfg.server.wgJoinRequests;
    return Array.isArray(list) ? list : [];
  }
  function save(list) {
    if (!cfg.server || typeof cfg.server !== 'object') cfg.server = {};
    cfg.server.wgJoinRequests = list;
    if (typeof onConfigChange === 'function') { try { onConfigChange(); } catch (e) {} }
  }
  return createJoinStore({ load, save });
}

/* ---------- server side: approve / reject / list / status ---------- */

function approvalOf(entry) {
  return {
    serverPublicKey: entry.serverPublicKey,
    endpoint: entry.endpoint,
    tunnelIp: entry.tunnelIp,
    allowedIPs: entry.allowedIPs,
    extraInterfaceLines: entry.extraInterfaceLines || [],
    extraPeerLines: entry.extraPeerLines || [],
  };
}

function listJoinRequests(store) {
  return store.listPending().map((e) => ({
    id: e.id, deviceName: e.deviceName, publicKey: e.publicKey,
    user: e.user, status: e.status, createdAt: e.createdAt, expiresAt: e.expiresAt,
  }));
}

// The explicit server-side approval. deps:
//   serverPublicKey (string, the WG server's public key)
//   endpoint (string, "host:port" the client must reach)
//   getPeers() -> [{ publicKey, tunnelIp }] (the live peer list)
//   addPeer(peer) -> Promise<{ success, error? }> — MUST be the same
//     code path wg-add-peer uses (validate, allocate, save, live
//     `wg set` when running). This module never writes wireguard.json.
//   extraInterfaceLines / extraPeerLines (optional, Phase 2
//     obfuscation fields, passed through into the approval).
// Returns { success, approval, peer, alreadyApproved?, alreadyPeer? }
// or { success:false, error }. A failed approval leaves the request
// pending, so the operator can retry after fixing the cause.
async function approveJoinRequest(store, id, deps) {
  if (!store || typeof store.get !== 'function') return { success: false, error: 'Join store is not wired up.' };
  const d = deps || {};
  if (typeof d.getPeers !== 'function' || typeof d.addPeer !== 'function') return { success: false, error: 'WireGuard peer handling is not wired up.' };
  const entry = store.get(id);
  if (!entry) return { success: false, error: 'Join request not found or expired.' };
  // Approving an already-approved request returns the stored
  // approval — never a second tunnel IP.
  if (entry.status === 'approved') return { success: true, alreadyApproved: true, approval: approvalOf(entry), peer: { name: entry.deviceName, publicKey: entry.publicKey, tunnelIp: entry.tunnelIp, allowedIPs: entry.allowedIPs } };
  if (entry.status !== 'pending') return { success: false, error: 'Join request is no longer pending (status: ' + entry.status + ').' };
  if (!wireguard.isWgKey(entry.publicKey)) return { success: false, error: 'Stored public key is not a valid WireGuard key.' };
  if (!wireguard.isWgKey(d.serverPublicKey)) return { success: false, error: 'The WireGuard server has no valid public key yet. Start the server first.' };
  const endpoint = String(d.endpoint || '').trim();
  if (!ENDPOINT_RE.test(endpoint)) return { success: false, error: 'No public address for this server yet. Set the endpoint (public IP or DDNS hostname) in the Server panel first.' };
  let extraInterfaceLines = [], extraPeerLines = [];
  try {
    extraInterfaceLines = cleanExtraLines(d.extraInterfaceLines);
    extraPeerLines = cleanExtraLines(d.extraPeerLines);
  } catch (e) { return { success: false, error: e.message }; }
  let peers = [];
  try { peers = d.getPeers() || []; } catch (e) { return { success: false, error: 'Could not read the peer list.' }; }
  // Idempotent by public key: a peer with this key already exists
  // (approved before, or added by hand / by QR invite) — reuse its
  // tunnel IP instead of allocating a second one.
  const existingPeer = peers.find((p) => p && p.publicKey === entry.publicKey);
  let tunnelIp = existingPeer ? wireguard.tunnelIpOf(existingPeer.tunnelIp || existingPeer.allowedIPs) : null;
  let alreadyPeer = !!tunnelIp;
  if (!tunnelIp) {
    tunnelIp = wireguard.nextTunnelIp(peers.map((p) => p.tunnelIp));
    if (!tunnelIp) return { success: false, error: 'No free tunnel address left (10.0.0.2 – 10.0.0.254 are all taken).' };
  }
  if (!alreadyPeer) {
    let r;
    try {
      r = await d.addPeer({ name: entry.deviceName, publicKey: entry.publicKey, tunnelIp, allowedIPs: tunnelIp + '/32', createdAt: new Date().toISOString() });
    } catch (e) { return { success: false, error: e && e.message ? e.message : 'Could not add the peer.' }; }
    if (!r || !r.success) return { success: false, error: (r && r.error) || 'Could not add the peer.' };
  }
  const approval = { serverPublicKey: d.serverPublicKey, endpoint, tunnelIp, allowedIPs: tunnelIp + '/32', extraInterfaceLines, extraPeerLines };
  const marked = store.markApproved(entry.id, approval);
  if (!marked.success) return { success: false, error: marked.error };
  return { success: true, approval, peer: { name: entry.deviceName, publicKey: entry.publicKey, tunnelIp, allowedIPs: tunnelIp + '/32' }, alreadyPeer };
}

function rejectJoinRequest(store, id) {
  if (!store || typeof store.markRejected !== 'function') return { success: false, error: 'Join store is not wired up.' };
  const r = store.markRejected(id);
  if (!r.success) return { success: false, error: r.error };
  return { success: true };
}

// What a polling client may see. `user` is the requesting Cloud user:
// a request belonging to someone else (or an unknown/expired id)
// answers exactly like "not found", so existence does not leak.
function getJoinStatus(store, id, user) {
  if (!store || typeof store.get !== 'function') return { success: false, code: 'not-found', error: 'Join request not found or expired.' };
  const entry = store.get(id);
  if (!entry || entry.user !== user) return { success: false, code: 'not-found', error: 'Join request not found or expired.' };
  if (entry.status === 'approved') return Object.assign({ success: true, status: 'approved' }, approvalOf(entry));
  return { success: true, status: entry.status };
}

/* ---------- HTTP routes on the Cloud server ---------- */

// Wraps a CloudServer instance so POST /api/wg-join-request,
// GET /api/wg-join-status and POST /api/wg-join-cancel are handled
// here (session auth via the server's own _auth, JSON body via its
// own _readJsonBody, 1 MB limit included). Every other path is
// delegated to the original _handle untouched. Idempotent: attaching
// twice is a no-op. Returns { success, store, alreadyAttached? }.
function attachJoinRoutes(cloudServer, opts) {
  if (!cloudServer || typeof cloudServer._handle !== 'function' || typeof cloudServer._auth !== 'function' || typeof cloudServer._sendJson !== 'function') {
    throw new Error('attachJoinRoutes needs a CloudServer instance.');
  }
  if (cloudServer.__wgJoinAttached) return { success: true, alreadyAttached: true, store: cloudServer.__wgJoinStore };
  const store = (opts && opts.store) || createJoinStore({});
  const origHandle = cloudServer._handle.bind(cloudServer);
  cloudServer.__wgJoinOriginalHandle = origHandle;
  cloudServer._handle = async function (req, res) {
    let pathname = '';
    let query = null;
    try {
      const u = new URL(req.url || '/', 'https://localhost');
      pathname = u.pathname;
      query = u.searchParams;
    } catch (e) { return origHandle(req, res); }
    const isJoin = (req.method === 'POST' && pathname === '/api/wg-join-request')
      || (req.method === 'GET' && pathname === '/api/wg-join-status')
      || (req.method === 'POST' && pathname === '/api/wg-join-cancel');
    if (!isJoin) return origHandle(req, res);
    const send = (code, obj) => { try { cloudServer._sendJson(res, code, obj); } catch (e) {} };
    try {
      const session = cloudServer._auth(req);
      if (!session) { send(401, { error: 'Not signed in.' }); return; }
      const ip = typeof cloudServer._clientIP === 'function' ? cloudServer._clientIP(req) : '';
      if (req.method === 'POST' && pathname === '/api/wg-join-request') {
        let body;
        try { body = await cloudServer._readJsonBody(req); }
        catch (e) { send(400, { error: e.message || 'Invalid request.' }); return; }
        const v = validateJoinRequestBody(body);
        if (!v.ok) { send(400, { error: v.error }); return; }
        const r = store.submit({ deviceName: v.deviceName, publicKey: v.publicKey, user: session.user });
        if (!r.success) { send(400, { error: r.error }); return; }
        try { cloudServer._audit(ip, session.user, 'wg-join-request', v.deviceName); } catch (e) {}
        send(200, { id: r.entry.id, status: 'pending', expiresAt: r.entry.expiresAt });
        return;
      }
      if (req.method === 'GET' && pathname === '/api/wg-join-status') {
        const st = getJoinStatus(store, query.get('id') || '', session.user);
        if (!st.success) { send(404, { error: 'Join request not found or expired.' }); return; }
        if (st.status === 'approved') {
          send(200, { status: 'approved', serverPublicKey: st.serverPublicKey, endpoint: st.endpoint, tunnelIp: st.tunnelIp, allowedIPs: st.allowedIPs, extraInterfaceLines: st.extraInterfaceLines || [], extraPeerLines: st.extraPeerLines || [] });
          return;
        }
        send(200, { status: st.status });
        return;
      }
      // POST /api/wg-join-cancel
      let body;
      try { body = await cloudServer._readJsonBody(req); }
      catch (e) { send(400, { error: e.message || 'Invalid request.' }); return; }
      const cid = body && typeof body.id === 'string' ? body.id : '';
      const r = store.cancel(cid, session.user);
      if (!r.success) { send(r.code === 'not-found' ? 404 : 400, { error: r.error }); return; }
      send(200, { ok: true });
    } catch (e) { send(500, { error: 'Server error.' }); }
  };
  cloudServer.__wgJoinAttached = true;
  cloudServer.__wgJoinStore = store;
  return { success: true, store };
}

function detachJoinRoutes(cloudServer) {
  if (!cloudServer || !cloudServer.__wgJoinAttached) return { success: false, error: 'Join routes are not attached.' };
  if (cloudServer.__wgJoinOriginalHandle) cloudServer._handle = cloudServer.__wgJoinOriginalHandle;
  delete cloudServer.__wgJoinAttached;
  delete cloudServer.__wgJoinOriginalHandle;
  delete cloudServer.__wgJoinStore;
  return { success: true };
}

/* ---------- client side: pinned JSON over the Cloud channel ---------- */

// Same shape as cloud-client.js doJson (which is not exported): the
// server's pinned cert is the only trusted CA, the hostname check is
// skipped (access is by IP), the session token rides as a Bearer
// header. Rejects with an Error carrying .status (HTTP code, 0 when
// there was no HTTP answer) and .code ('unauthorized' | 'unreachable'
// | 'timeout' | 'cert' | 'server').
function requestJson(conn, method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (conn.token) headers.Authorization = 'Bearer ' + conn.token;
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const fail = (e) => {
      if (e && typeof e.status === 'number') return reject(e);
      const err = new Error(e && e.message ? e.message : 'Connection failed.');
      err.status = 0;
      if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND' || e.code === 'ECONNRESET' || /socket hang up/i.test(err.message))) err.code = 'unreachable';
      else if (e && (e.code === 'CERT_HAS_EXPIRED' || e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || e.code === 'SELF_SIGNED_CERT_IN_CHAIN')) { err.code = 'cert'; err.message = 'The server certificate does not match the trusted one. If the server was reinstalled, remove it and add it again to trust the new certificate.'; }
      else if (e && /did not answer in time/i.test(err.message)) err.code = 'timeout';
      else err.code = 'server';
      reject(err);
    };
    let req;
    try {
      req = https.request({
        host: conn.host, port: conn.port, path: apiPath, method,
        ca: [conn.certPem], checkServerIdentity: () => undefined, headers,
      }, (res) => {
        const chunks = [];
        let size = 0;
        let tooBig = false;
        res.on('data', (c) => {
          size += c.length;
          if (size > 10 * 1024 * 1024) { tooBig = true; req.destroy(new Error('Server response is too large.')); return; }
          chunks.push(c);
        });
        res.on('end', () => {
          if (tooBig) return fail(new Error('Server response is too large.'));
          let obj = {};
          try { obj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) { /* keep {} */ }
          if (res.statusCode >= 400) {
            const err = new Error((obj && obj.error) || ('Server error ' + res.statusCode));
            err.status = res.statusCode;
            err.code = res.statusCode === 401 ? 'unauthorized' : (res.statusCode === 404 ? 'not-found' : 'server');
            return reject(err);
          }
          resolve(obj);
        });
      });
    } catch (e) { return fail(e); }
    req.setTimeout(API_TIMEOUT_MS, () => req.destroy(new Error('Server did not answer in time.')));
    req.on('error', fail);
    if (data) req.write(data);
    req.end();
  });
}

// Map a requestJson failure onto the join result shape. The 401 case
// is the important one: the Cloud session is gone (the server was
// restarted — stop() clears sessions — or the user was signed out).
// It is terminal and NOT retried: re-sending needs a fresh login and
// a fresh request, by user action.
function joinErrorResult(e) {
  if (e && e.code === 'unauthorized') {
    return { success: false, code: 'server-restarted', retryable: false, error: 'The Cloud session ended (the server was restarted, or you were signed out). Send the join request again.' };
  }
  if (e && e.code === 'not-found') {
    return { success: false, code: 'expired', retryable: false, error: 'Join request expired or not found. Send a new join request.' };
  }
  if (e && e.code === 'unreachable') return { success: false, code: 'unreachable', retryable: true, error: e.message || 'Cannot reach the server.' };
  if (e && e.code === 'timeout') return { success: false, code: 'timeout', retryable: true, error: 'Server did not answer in time.' };
  if (e && e.code === 'cert') return { success: false, code: 'cert', retryable: false, error: e.message };
  return { success: false, code: 'server-error', retryable: false, error: (e && e.message) || 'Server error.' };
}

function checkConn(conn) {
  if (!conn || typeof conn !== 'object' || !conn.host || !conn.port || !conn.certPem) {
    return { success: false, code: 'not-connected', retryable: false, error: 'Not connected to a Cloud server. Connect to the server first.' };
  }
  if (!conn.token) {
    return { success: false, code: 'not-connected', retryable: false, error: 'Cloud session ended. Sign in to the server again, then send the join request.' };
  }
  return null;
}

// Generate a fresh client keypair, send ONLY the public key + device
// name, keep the private key in the returned object (held in memory
// by the caller until approval — never sent, never stored here).
async function submitJoinRequest(conn, deviceName, opts) {
  const v = validateDeviceName(deviceName);
  if (!v.ok) return { success: false, code: 'invalid', retryable: false, error: v.error };
  const badConn = checkConn(conn);
  if (badConn) return badConn;
  const keygen = (opts && typeof opts.keygen === 'function') ? opts.keygen : wireguard.genkeypair;
  let kp;
  try { kp = await keygen(); } catch (e) { return { success: false, code: 'keygen', retryable: false, error: e && e.message ? e.message : 'Could not generate a WireGuard key.' }; }
  if (!kp || !kp.success) return { success: false, code: 'keygen', retryable: false, error: (kp && kp.error) || 'Could not generate a WireGuard key.' };
  let r;
  try { r = await requestJson(conn, 'POST', '/api/wg-join-request', { deviceName: v.name, publicKey: kp.publicKey }); }
  catch (e) { return joinErrorResult(e); }
  if (!r || typeof r.id !== 'string' || !REQUEST_ID_RE.test(r.id)) return { success: false, code: 'server-error', retryable: false, error: 'Server gave an unexpected answer to the join request.' };
  return { success: true, requestId: r.id, deviceName: v.name, publicKey: kp.publicKey, privateKey: kp.privateKey, status: 'pending', expiresAt: r.expiresAt || null };
}

// Poll the status endpoint once. The caller (main.js) decides when to
// poll again; this function never loops by itself. On approval with
// opts.privateKey supplied, the returned object also carries confText
// (built by buildClientConfigFromApproval) ready for wg-connect.
async function pollJoinStatus(conn, requestId, opts) {
  if (typeof requestId !== 'string' || !REQUEST_ID_RE.test(requestId)) return { success: false, code: 'invalid', retryable: false, error: 'Join request id is not valid.' };
  const badConn = checkConn(conn);
  if (badConn) return badConn;
  let r;
  try { r = await requestJson(conn, 'GET', '/api/wg-join-status?id=' + encodeURIComponent(requestId)); }
  catch (e) { return joinErrorResult(e); }
  if (!r || typeof r.status !== 'string') return { success: false, code: 'server-error', retryable: false, error: 'Server gave an unexpected answer to the status check.' };
  if (r.status === 'pending') return { success: true, status: 'pending' };
  if (r.status === 'rejected') return { success: true, status: 'rejected' };
  if (r.status !== 'approved') return { success: false, code: 'server-error', retryable: false, error: 'Server gave an unknown join status: ' + r.status };
  const approval = {
    serverPublicKey: r.serverPublicKey, endpoint: r.endpoint,
    tunnelIp: r.tunnelIp, allowedIPs: r.allowedIPs,
    extraInterfaceLines: r.extraInterfaceLines || [], extraPeerLines: r.extraPeerLines || [],
  };
  const out = Object.assign({ success: true, status: 'approved' }, approval);
  const privateKey = opts && opts.privateKey;
  if (privateKey) {
    const built = await buildClientConfigFromApproval(approval, privateKey);
    if (!built.success) return { success: false, code: 'server-error', retryable: false, error: 'Server approved the request, but the approval was incomplete: ' + built.error };
    out.confText = built.confText;
    out.client = built.meta;
  }
  return out;
}

async function cancelJoinRequest(conn, requestId) {
  if (typeof requestId !== 'string' || !REQUEST_ID_RE.test(requestId)) return { success: false, code: 'invalid', retryable: false, error: 'Join request id is not valid.' };
  const badConn = checkConn(conn);
  if (badConn) return badConn;
  try {
    await requestJson(conn, 'POST', '/api/wg-join-cancel', { id: requestId });
  } catch (e) { return joinErrorResult(e); }
  return { success: true };
}

// Turn an approval payload + the client's private key into a .conf
// text wg-connect can install (its confText path), plus the metadata
// wg-connect stores. Extra obfuscation lines ride through verbatim.
async function buildClientConfigFromApproval(approval, privateKey, opts) {
  if (!approval || typeof approval !== 'object') return { success: false, error: 'No approval to build a config from.' };
  if (!wireguard.isWgKey(privateKey)) return { success: false, error: 'Client private key is not a valid WireGuard key.' };
  if (!wireguard.isWgKey(approval.serverPublicKey)) return { success: false, error: 'Server public key in the approval is not a valid WireGuard key.' };
  if (!ENDPOINT_RE.test(String(approval.endpoint || '').trim())) return { success: false, error: 'Endpoint in the approval is not host:port.' };
  const tunnelIp = wireguard.tunnelIpOf(approval.tunnelIp || '');
  if (!tunnelIp || !TUNNEL_IP_RE.test(tunnelIp)) return { success: false, error: 'Tunnel address in the approval is not valid.' };
  let extraInterfaceLines = [], extraPeerLines = [];
  try {
    extraInterfaceLines = cleanExtraLines(approval.extraInterfaceLines);
    extraPeerLines = cleanExtraLines(approval.extraPeerLines);
  } catch (e) { return { success: false, error: e.message }; }
  const allowedIPs = (opts && opts.allowedIPs) || approval.allowedIPs || wireguard.TUNNEL_SUBNET;
  let confText;
  try {
    confText = wireguard.buildClientConf({
      privateKey, serverPublicKey: approval.serverPublicKey,
      endpoint: String(approval.endpoint).trim(), address: tunnelIp + '/32',
      allowedIPs, extraInterfaceLines, extraPeerLines,
    });
  } catch (e) { return { success: false, error: e.message }; }
  let publicKey = null;
  try {
    const p = await wireguard.pubkey(privateKey);
    if (p && p.success) publicKey = p.key;
  } catch (e) { /* the conf is still usable; wg-connect derives it again */ }
  return {
    success: true,
    confText,
    meta: { privateKey, publicKey, serverPublicKey: approval.serverPublicKey, endpoint: String(approval.endpoint).trim(), tunnelIp, allowedIPs },
  };
}

module.exports = {
  JOIN_REQUEST_TTL_MS, MAX_DEVICE_NAME_LENGTH,
  validateDeviceName, validateJoinRequestBody,
  createJoinStore, configBackedStore,
  listJoinRequests, approveJoinRequest, rejectJoinRequest, getJoinStatus,
  attachJoinRoutes, detachJoinRoutes,
  requestJson, submitJoinRequest, pollJoinStatus, cancelJoinRequest,
  buildClientConfigFromApproval,
};
