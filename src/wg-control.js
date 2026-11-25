'use strict';
/*
 * TechVision WireGuard VPN — control channel between the two gateways.
 *
 * The two gateways are WireGuard peers, so they can talk to each other
 * over the tunnel (10.0.0.x) with no LAN or router port at all. This
 * file is the tiny HTTP server + client for that channel. It carries
 * one command today: remote NAT start — when the user presses Start
 * NAT service on one gateway, the other gateway's NAT service starts
 * by itself, with zero configuration typed there (its config is
 * auto-detected + carried in the command; see nat-gateway.js
 * buildRemoteStartCommand / buildRemoteNatConfig).
 *
 * Authentication: the server binds to the local tunnel address ONLY,
 * so it is reachable through the tunnel and nowhere else, and it
 * accepts a command only from a tunnel-internal source address other
 * than its own (the tunnel is WireGuard-authenticated — only a peer
 * holding the tunnel keys can send a packet through it). When the
 * local machine is a server with known peers, the source must also
 * be one of the peer tunnel IPs (peerTunnelIps). No shared secret:
 * the tunnel keys ARE the credential.
 *
 * The listener starts when the tunnel comes up (server running or
 * client connected) and stops when the tunnel goes down — main.js
 * owns that lifecycle (refreshWgControl). A bind failure (e.g. the
 * tunnel address is not a local interface yet) is soft: the tunnel
 * still works, only the remote-start command cannot be received.
 *
 * The client (sendRemoteNatStart) has two timeouts: a short connect
 * timeout (the peer is unreachable — fail fast instead of hanging
 * on a dead tunnel) and a long total timeout (the remote start runs
 * an elevated setup on the remote machine, so the remote user gets
 * time to answer the UAC prompt).
 *
 * Dependency-free except Node builtins (http). The http module is
 * injectable so the harness can drive the round-trip on loopback.
 */
const http = require('http');

const WG_CONTROL_PORT = 51821;
const WG_CONTROL_PATH = '/nat-start';
const CONNECT_TIMEOUT_MS = 10000;
const TOTAL_TIMEOUT_MS = 150000;

function isTunnelSource(addr, tunnelIp, tunnelSubnet, peerTunnelIps) {
  if (!addr || typeof addr !== 'string') return false;
  if (addr === tunnelIp) return false;
  /* A mapped IPv6 loopback from a local test client is not a tunnel
     peer — only dotted IPv4 tunnel addresses count. */
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(addr)) return false;
  if (Array.isArray(peerTunnelIps) && peerTunnelIps.length > 0) {
    return peerTunnelIps.indexOf(addr) >= 0;
  }
  if (!tunnelSubnet) return false;
  const parts = tunnelSubnet.split('/');
  if (parts.length !== 2) return false;
  const prefix = parseInt(parts[1], 10);
  if (prefix !== 24) return false;
  return addr.split('.').slice(0, 3).join('.') === parts[0].split('.').slice(0, 3).join('.');
}

/* One control server. opts: { http (injectable), logger }.
 * start(cfg) takes { tunnelIp, tunnelSubnet, peerTunnelIps,
 * handleNatStart } — handleNatStart(command) returns the ack object.
 * Idempotent: starting on the same tunnel address is a no-op, a
 * changed address restarts the listener. */
function createControlServer(opts) {
  const mod = (opts && opts.http) || http;
  const log = (opts && opts.logger) || (() => {});
  let server = null;
  let bound = null; /* { tunnelIp, tunnelSubnet } */

  function status() {
    return { running: !!server, port: WG_CONTROL_PORT, tunnelIp: bound ? bound.tunnelIp : null };
  }

  function stop() {
    if (!server) return;
    const s = server;
    server = null;
    bound = null;
    try { s.close(); } catch (e) {}
  }

  async function start(cfg) {
    const tunnelIp = cfg && cfg.tunnelIp;
    if (!tunnelIp) { stop(); return { success: false, error: 'No tunnel address to listen on.' }; }
    if (server && bound && bound.tunnelIp === tunnelIp) return { success: true, alreadyRunning: true };
    stop();
    const tunnelSubnet = cfg.tunnelSubnet || null;
    const peerTunnelIps = cfg.peerTunnelIps || null;
    const handleNatStart = cfg.handleNatStart;
    const srv = mod.createServer((req, res) => {
      const send = (code, obj) => {
        try {
          res.writeHead(code, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(obj));
        } catch (e) {}
      };
      if (req.method !== 'POST' || req.url !== WG_CONTROL_PATH) { send(404, { ok: false, error: 'Unknown control path.' }); return; }
      const src = req.socket && req.socket.remoteAddress;
      if (!isTunnelSource(src, tunnelIp, tunnelSubnet, peerTunnelIps)) {
        send(403, { ok: false, error: 'Rejected: not a tunnel peer.' });
        return;
      }
      let body = '';
      req.on('data', (chunk) => { body += chunk.toString('utf8'); if (body.length > 65536) { try { req.destroy(); } catch (e) {} } });
      req.on('end', async () => {
        let command = null;
        try { command = JSON.parse(body); } catch (e) { send(400, { ok: false, error: 'Bad command (not JSON).' }); return; }
        try {
          const ack = await handleNatStart(command);
          send(200, ack && typeof ack === 'object' ? ack : { ok: false, error: 'Bad acknowledgement.' });
        } catch (e) {
          send(500, { ok: false, error: e && e.message ? e.message : 'Remote NAT start failed.' });
        }
      });
    });
    srv.on('error', (err) => { log('WireGuard control channel failed: ' + (err && err.message ? err.message : String(err))); });
    try {
      await new Promise((resolve, reject) => {
        srv.once('error', reject);
        srv.listen(WG_CONTROL_PORT, tunnelIp, () => { srv.removeListener('error', reject); resolve(); });
      });
    } catch (e) {
      try { srv.close(); } catch (e2) {}
      return { success: false, error: 'Could not listen on the tunnel address ' + tunnelIp + ':' + WG_CONTROL_PORT + ' (' + (e && e.message ? e.message : String(e)) + ').' };
    }
    server = srv;
    bound = { tunnelIp, tunnelSubnet };
    return { success: true };
  }

  return { start, stop, status };
}

/* POST a remote-start command to the peer gateway over the tunnel.
 * Returns the parsed ack ({ ok, ... }) or { ok: false, error }.
 * opts: { http (injectable), connectTimeoutMs, timeoutMs,
 * localAddress (tests only — forces the source address) }. */
async function sendRemoteNatStart(remoteTunnelIp, command, opts) {
  const o = opts || {};
  const mod = o.http || http;
  const connectTimeoutMs = o.connectTimeoutMs || CONNECT_TIMEOUT_MS;
  const totalTimeoutMs = o.timeoutMs || TOTAL_TIMEOUT_MS;
  return new Promise((resolve) => {
    let done = false;
    const finish = (obj) => { if (!done) { done = true; resolve(obj); } };
    let req;
    try {
      req = mod.request({
        host: remoteTunnelIp,
        port: WG_CONTROL_PORT,
        path: WG_CONTROL_PATH,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        localAddress: o.localAddress || undefined,
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk.toString('utf8'); });
        res.on('end', () => {
          try {
            const ack = JSON.parse(body);
            finish(ack && typeof ack === 'object' ? ack : { ok: false, error: 'Bad acknowledgement from the other gateway.' });
          } catch (e) {
            finish({ ok: false, error: 'Bad acknowledgement from the other gateway.' });
          }
        });
      });
    } catch (e) {
      finish({ ok: false, error: 'Could not reach the other gateway at ' + remoteTunnelIp + ' (' + (e && e.message ? e.message : String(e)) + ').' });
      return;
    }
    const connectTimer = setTimeout(() => {
      try { req.destroy(new Error('connect timeout')); } catch (e) {}
      finish({ ok: false, error: 'The other gateway at ' + remoteTunnelIp + ' did not answer — its tunnel may be down or the WireGuard control channel is not running there.' });
    }, connectTimeoutMs);
    const totalTimer = setTimeout(() => {
      try { req.destroy(new Error('total timeout')); } catch (e) {}
      finish({ ok: false, error: 'The other gateway at ' + remoteTunnelIp + ' did not finish starting its NAT service in time (its administrator prompt may still be waiting).' });
    }, totalTimeoutMs);
    req.on('socket', (socket) => {
      socket.on('connect', () => clearTimeout(connectTimer));
    });
    req.on('error', (err) => {
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      finish({ ok: false, error: 'Could not reach the other gateway at ' + remoteTunnelIp + ' (' + (err && err.message ? err.message : String(err)) + ').' });
    });
    req.on('response', () => { clearTimeout(connectTimer); });
    req.on('close', () => { clearTimeout(connectTimer); clearTimeout(totalTimer); });
    try {
      req.end(JSON.stringify(command || {}));
    } catch (e) {
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      finish({ ok: false, error: 'Could not reach the other gateway at ' + remoteTunnelIp + ' (' + (e && e.message ? e.message : String(e)) + ').' });
    }
  });
}

module.exports = {
  WG_CONTROL_PORT,
  WG_CONTROL_PATH,
  CONNECT_TIMEOUT_MS,
  TOTAL_TIMEOUT_MS,
  isTunnelSource,
  createControlServer,
  sendRemoteNatStart,
};
