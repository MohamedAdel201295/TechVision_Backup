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
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
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

function download(conn, relPath, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (conn.token) headers.Authorization = 'Bearer ' + conn.token;
    const req = https.request(pinnedOptions(conn, 'GET', '/api/download?path=' + encodeURIComponent(relPath), headers), (res) => {
      if (res.statusCode >= 400) {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let msg = 'Download failed.';
          try { msg = JSON.parse(Buffer.concat(chunks).toString('utf8')).error || msg; } catch (e) {}
          reject(new Error(msg));
        });
        return;
      }
      const total = parseInt(res.headers['content-length'] || '0', 10) || 0;
      let done = 0;
      const ws = fs.createWriteStream(destPath);
      res.on('data', (c) => {
        done += c.length;
        if (typeof onProgress === 'function') { try { onProgress(done, total); } catch (e) {} }
      });
      res.pipe(ws);
      ws.on('finish', () => resolve({ size: done }));
      ws.on('error', reject);
      res.on('error', reject);
    });
    req.on('error', (e) => reject(new Error(mapTlsError(e))));
    req.end();
  });
}

function upload(conn, localPath, remoteDir, onProgress) {
  return new Promise((resolve, reject) => {
    let total = 0;
    try { total = fs.statSync(localPath).size; } catch (e) { return reject(e); }
    const headers = { 'X-Filename': path.basename(localPath) };
    if (conn.token) headers.Authorization = 'Bearer ' + conn.token;
    const req = https.request(pinnedOptions(conn, 'POST', '/api/upload?path=' + encodeURIComponent(remoteDir || ''), headers), (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let obj = {};
        try { obj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) {}
        if (res.statusCode >= 400) return reject(new Error((obj && obj.error) || ('Upload failed (' + res.statusCode + ')')));
        resolve(obj);
      });
    });
    req.on('error', (e) => reject(new Error(mapTlsError(e))));
    let sent = 0;
    const rs = fs.createReadStream(localPath);
    rs.on('data', (c) => {
      sent += c.length;
      if (typeof onProgress === 'function') { try { onProgress(sent, total); } catch (e) {} }
    });
    rs.on('error', reject);
    rs.pipe(req);
  });
}

module.exports = { probeServer, login, info, list, mkdir, remove, rename, download, upload, fingerprintOfDer, derToPem };
