/**
 * TechVision Cloud - Client
 * Talks to a Cloud server over pinned TLS. The server uses a
 * self-signed certificate, so the client pins it: the first connect
 * (probe) reads the presented certificate and returns its SHA-256
 * fingerprint + PEM; the user trusts that fingerprint once, and every
 * later call verifies the server against that exact certificate
 * (ca: [certPem], hostname check skipped — access is by IP).
 * No request carrying a password or token is ever sent before the
 * certificate has been verified by the TLS layer.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const API_TIMEOUT_MS = 15000;
const TRANSFER_STALL_MS = 60000; // no data for this long = give up
const MAX_JSON_RESPONSE_BYTES = 10 * 1024 * 1024;

function fingerprintOfDer(derBuffer) {
  return crypto.createHash('sha256').update(derBuffer).digest('hex');
}

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
}

// TLS handshake only: read the certificate the server presents.
// Nothing sensitive is sent.
function probeServer(host, port) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host, port, path: '/api/info', method: 'GET',
      rejectUnauthorized: false, timeout: API_TIMEOUT_MS,
    }, (res) => {
      const cert = res.socket && res.socket.getPeerCertificate ? res.socket.getPeerCertificate(true) : null;
      res.resume();
      req.destroy();
      if (!cert || !cert.raw) return reject(new Error('Server did not present a certificate.'));
      resolve({ fingerprint: fingerprintOfDer(cert.raw), certPem: derToPem(cert.raw) });
    });
    req.on('timeout', () => { req.destroy(new Error('Server did not answer in time.')); });
    req.on('error', (e) => reject(new Error(e.code === 'ECONNREFUSED' ? 'Cannot reach the server (connection refused). Check the address, port and that the server is running.' : (e.message || String(e)))));
    req.end();
  });
}

function pinnedOptions(conn, method, apiPath, extraHeaders) {
  return {
    host: conn.host, port: conn.port, path: apiPath, method,
    ca: [conn.certPem],
    // Access is by IP while the cert is for a hostname: skip the
    // hostname check, keep the chain check (the pinned cert itself is
    // the only trusted CA, so no other certificate can pass).
    checkServerIdentity: () => undefined,
    headers: Object.assign({}, extraHeaders || {}),
  };
}

function doJson(conn, method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (conn.token) headers.Authorization = 'Bearer ' + conn.token;
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const req = https.request(pinnedOptions(conn, method, apiPath, headers), (res) => {
      const chunks = [];
      let size = 0;
      let tooBig = false;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_JSON_RESPONSE_BYTES) { tooBig = true; req.destroy(new Error('Server response is too large.')); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        if (tooBig) return reject(new Error('Server response is too large.'));
        let obj = {};
        try { obj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) { /* keep {} */ }
        if (res.statusCode >= 400) return reject(new Error((obj && obj.error) || ('Server error ' + res.statusCode)));
        resolve(obj);
      });
    });
    req.setTimeout(API_TIMEOUT_MS, () => req.destroy(new Error('Server did not answer in time.')));
    req.on('error', (e) => reject(new Error(mapTlsError(e))));
    if (data) req.write(data);
    req.end();
  });
}

function mapTlsError(e) {
  if (!e) return 'Connection failed.';
  if (e.code === 'ECONNREFUSED') return 'Cannot reach the server (connection refused).';
  if (e.code === 'CERT_HAS_EXPIRED') return 'The server certificate has expired.';
  if (e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || e.code === 'SELF_SIGNED_CERT_IN_CHAIN') {
    return 'The server certificate does not match the trusted one. If the server was reinstalled, remove it and add it again to trust the new certificate.';
  }
  return e.message || String(e);
}

async function logout(conn) {
  try { await doJson(conn, 'POST', '/api/logout'); } catch (e) { /* the token is dropped locally either way */ }
}

async function login(host, port, certPem, user, password) {
  const conn = { host, port, certPem, token: null };
  const r = await doJson(conn, 'POST', '/api/login', { user, password });
  if (!r || !r.token) throw new Error('Login failed.');
  conn.token = r.token;
  return conn;
}

async function info(conn) {
  return doJson(conn, 'GET', '/api/info');
}

async function list(conn, relPath) {
  return doJson(conn, 'GET', '/api/list?path=' + encodeURIComponent(relPath || ''));
}

async function mkdir(conn, relPath) {
  return doJson(conn, 'POST', '/api/mkdir', { path: relPath });
}

async function remove(conn, relPath) {
  return doJson(conn, 'POST', '/api/delete', { path: relPath });
}

async function rename(conn, from, to) {
  return doJson(conn, 'POST', '/api/rename', { from, to });
}

async function copy(conn, from, to) {
  return doJson(conn, 'POST', '/api/copy', { from, to });
}

function download(conn, relPath, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    let done = false;
    const fail = (e) => {
      if (done) return;
      done = true;
      try { req.destroy(); } catch (_) {}
      try { if (ws) ws.destroy(); } catch (_) {}
      // Never leave a truncated file that looks like a good download.
      try { fs.unlinkSync(destPath); } catch (_) {}
      reject(e);
    };
    let ws = null;
    let stallTimer = null;
    const armStall = () => {
      if (stallTimer) clearTimeout(stallTimer);
      stallTimer = setTimeout(() => fail(new Error('Download stalled — no data for a minute.')), TRANSFER_STALL_MS);
      if (stallTimer.unref) stallTimer.unref();
    };
    const headers = {};
    if (conn.token) headers.Authorization = 'Bearer ' + conn.token;
    const req = https.request(pinnedOptions(conn, 'GET', '/api/download?path=' + encodeURIComponent(relPath), headers), (res) => {
      if (res.statusCode >= 400) {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let msg = 'Download failed.';
          try { msg = JSON.parse(Buffer.concat(chunks).toString('utf8')).error || msg; } catch (e) {}
          fail(new Error(msg));
        });
        return;
      }
      const total = parseInt(res.headers['content-length'] || '0', 10) || 0;
      let received = 0;
      ws = fs.createWriteStream(destPath);
      armStall();
      res.on('data', (c) => {
        received += c.length;
        armStall();
        if (typeof onProgress === 'function') { try { onProgress(received, total); } catch (e) {} }
      });
      res.pipe(ws);
      ws.on('finish', () => {
        if (stallTimer) clearTimeout(stallTimer);
        if (done) return;
        // The server promised `total` bytes: a short file is a failed
        // download, not a successful one.
        if (total > 0 && received !== total) return fail(new Error('Download was cut short (' + received + ' of ' + total + ' bytes). Try again.'));
        done = true;
        resolve({ size: received });
      });
      ws.on('error', (e) => fail(e));
      res.on('error', (e) => fail(e));
    });
    req.on('error', (e) => fail(new Error(mapTlsError(e))));
    req.end();
  });
}

function upload(conn, localPath, remoteDir, onProgress) {
  return new Promise((resolve, reject) => {
    let total = 0;
    try { total = fs.statSync(localPath).size; } catch (e) { return reject(e); }
    let done = false;
    const fail = (e) => {
      if (done) return;
      done = true;
      try { rs.destroy(); } catch (_) {}
      try { req.destroy(); } catch (_) {}
      reject(e);
    };
    const headers = { 'X-Filename': path.basename(localPath) };
    if (conn.token) headers.Authorization = 'Bearer ' + conn.token;
    let stallTimer = null;
    const armStall = () => {
      if (stallTimer) clearTimeout(stallTimer);
      stallTimer = setTimeout(() => fail(new Error('Upload stalled — no data sent for a minute.')), TRANSFER_STALL_MS);
      if (stallTimer.unref) stallTimer.unref();
    };
    const req = https.request(pinnedOptions(conn, 'POST', '/api/upload?path=' + encodeURIComponent(remoteDir || ''), headers), (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (stallTimer) clearTimeout(stallTimer);
        // The server answered early (e.g. read-only or too large):
        // stop sending the rest of the file.
        try { rs.destroy(); } catch (_) {}
        let obj = {};
        try { obj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) {}
        if (done) return;
        if (res.statusCode >= 400) return fail(new Error((obj && obj.error) || ('Upload failed (' + res.statusCode + ')')));
        done = true;
        resolve(obj);
      });
    });
    req.on('error', (e) => fail(new Error(mapTlsError(e))));
    let sent = 0;
    const rs = fs.createReadStream(localPath);
    armStall();
    rs.on('data', (c) => {
      sent += c.length;
      armStall();
      if (typeof onProgress === 'function') { try { onProgress(sent, total); } catch (e) {} }
    });
    rs.on('error', (e) => fail(e));
    rs.pipe(req);
  });
}

function joinRemote(a, b) {
  if (!a) return b;
  if (!b) return a;
  return a.replace(/\/+$/, '') + '/' + b;
}

/* Upload a list of local paths (files and folders, e.g. copied in
   Windows Explorer) into a remote folder. Folders are walked
   recursively; each file keeps its relative path under the folder.
   Returns { uploaded, failed: [{ path, error }] } — one bad file never
   stops the rest. */
async function uploadPaths(conn, localPaths, remoteDir, onProgress) {
  const out = { uploaded: 0, failed: [] };
  // One listing per destination folder, so a file that already exists
  // on the server is skipped (never silently overwritten) instead of
  // replacing it.
  const dirListings = new Map();
  async function existingNames(destDir) {
    if (dirListings.has(destDir)) return dirListings.get(destDir);
    let names = new Set();
    try { const r = await list(conn, destDir); names = new Set((r.entries || []).map((e) => e.name)); }
    catch (e) { /* an unreadable folder is treated as empty */ }
    dirListings.set(destDir, names);
    return names;
  }
  const walk = async (localPath, destDir) => {
    let st;
    try { st = fs.statSync(localPath); } catch (e) { out.failed.push({ path: localPath, error: e.message }); return; }
    if (st.isFile()) {
      const names = await existingNames(destDir);
      const base = path.basename(localPath);
      if (names.has(base)) { out.failed.push({ path: localPath, error: 'already exists on the server — skipped' }); return; }
      try {
        await upload(conn, localPath, destDir, (sent, total) => { if (typeof onProgress === 'function') { try { onProgress(base, sent, total); } catch (e) {} } });
        out.uploaded++;
        names.add(base);
      } catch (e) { out.failed.push({ path: localPath, error: e.message }); }
      return;
    }
    if (st.isDirectory()) {
      // The upload endpoint refuses a destination folder that does not
      // exist yet, so create the remote folder first.
      const here = joinRemote(destDir, path.basename(localPath));
      try { await mkdir(conn, here); } catch (e) { out.failed.push({ path: localPath, error: e.message }); return; }
      let kids;
      try { kids = fs.readdirSync(localPath); } catch (e) { out.failed.push({ path: localPath, error: e.message }); return; }
      if (!kids.length) { out.uploaded++; return; } // an empty folder still counts as copied
      for (const kid of kids) await walk(path.join(localPath, kid), here);
      return;
    }
    out.failed.push({ path: localPath, error: 'Not a file or folder.' });
  };
  for (const p of localPaths || []) await walk(p, remoteDir || '');
  return out;
}

/* Parse the Windows clipboard file list ("FileNameW"): a sequence of
   UTF-16LE null-terminated paths, terminated by an extra null. Returns
   the local paths (drive-letter or UNC) the user copied in Explorer. */
function parseClipboardFiles(buf) {
  if (!buf || !buf.length) return [];
  const text = buf.toString('utf16le');
  return text.split('\0').map((s) => s.trim()).filter((s) => s && (/^[A-Za-z]:[\\/]/.test(s) || s.startsWith('\\\\')));
}

module.exports = { probeServer, login, logout, info, list, mkdir, remove, rename, copy, download, upload, uploadPaths, parseClipboardFiles, fingerprintOfDer, derToPem };
