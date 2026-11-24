'use strict';
/*
 * TechVision VPN — Tailscale client manager (main process).
 *
 * This module does NOT implement a VPN. It manages the Tailscale CLI
 * that is already installed on the machine: status, connect/disconnect,
 * peer list, and (optionally) advertising this machine's LAN subnet so
 * the tailnet can reach devices without Tailscale.
 *
 * Security: the wrapper only ever spawns `tailscale` with a fixed
 * argument list. The only variable input is the LAN subnet, which is
 * computed locally from os.networkInterfaces() and validated as a CIDR
 * — never free text from the renderer. Every call has a timeout.
 */
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const WIN_CLI = 'C:\\Program Files\\Tailscale\\tailscale.exe';

let cliPathCache = null; // null = not resolved yet

function resolveCli() {
  if (cliPathCache !== null) return cliPathCache;
  // PATH lookup: execFile('tailscale') resolves through PATH, so we only
  // need the well-known install path as a fallback (Windows installer
  // normally puts it on PATH, but not always for the current shell).
  if (process.platform === 'win32' && fs.existsSync(WIN_CLI)) {
    cliPathCache = WIN_CLI;
  } else {
    cliPathCache = 'tailscale';
  }
  return cliPathCache;
}

function runCli(args, timeoutMs) {
  return new Promise((resolve) => {
    const child = execFile(resolveCli(), args, { timeout: timeoutMs || 15000, windowsHide: true }, (err, stdout, stderr) => {
      if (err && err.code === 'ENOENT') return resolve({ code: -1, stdout: '', stderr: '', notFound: true });
      if (err && err.killed) return resolve({ code: -2, stdout: stdout || '', stderr: stderr || '', timedOut: true });
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

function isCidr(s) {
  if (typeof s !== 'string') return false;
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) { const n = parseInt(m[i], 10); if (n < 0 || n > 255) return false; }
  const p = parseInt(m[5], 10);
  return p >= 8 && p <= 30;
}

/* First non-internal IPv4 interface -> its network as CIDR, e.g. 192.168.1.0/24. */
function lanSubnet() {
  try {
    const ifs = os.networkInterfaces();
    for (const name of Object.keys(ifs)) {
      for (const a of ifs[name] || []) {
        if (a.family !== 'IPv4' || a.internal) continue;
        const ip = a.address.split('.').map(Number);
        const mask = a.netmask.split('.').map(Number);
        const net = ip.map((b, i) => b & mask[i]);
        const prefix = mask.reduce((n, b) => n + b.toString(2).split('1').length - 1, 0);
        const cidr = net.join('.') + '/' + prefix;
        if (isCidr(cidr)) return cidr;
      }
    }
  } catch (e) { /* fall through */ }
  return null;
}

function tailnetFromDns(dnsName) {
  if (!dnsName || typeof dnsName !== 'string') return null;
  const parts = dnsName.split('.');
  // "machine.tailnet.ts.net" -> "tailnet"; "machine.tailnet" -> "tailnet".
  if (parts.length >= 3 && parts[parts.length - 1] === 'net' && parts[parts.length - 2] === 'ts') return parts.slice(1, -2).join('.') || null;
  if (parts.length >= 2) return parts.slice(1).join('.') || null;
  return null;
}

async function getStatus() {
  const r = await runCli(['status', '--json'], 10000);
  if (r.notFound) return { installed: false, connected: false, error: 'Tailscale is not installed on this computer.' };
  if (r.timedOut) return { installed: true, connected: false, error: 'Tailscale did not answer in time. Is the Tailscale service running?' };
  let j = null;
  try { j = JSON.parse(r.stdout); } catch (e) { /* fall through */ }
  if (!j) return { installed: true, connected: false, error: 'Could not read Tailscale status.' };
  const backend = j.BackendState || '';
  const connected = backend === 'Running';
  const self = j.Self || {};
  const selfIp = (self.TailscaleIPs && self.TailscaleIPs[0]) || null;
  const peers = [];
  const peerMap = j.Peer || {};
  for (const id of Object.keys(peerMap)) {
    const p = peerMap[id] || {};
    peers.push({
      id,
      name: p.HostName || p.DNSName || id,
      ip: (p.TailscaleIPs && p.TailscaleIPs[0]) || null,
      os: p.OS || '',
      online: !!p.Online,
      lastSeen: p.LastSeen || null,
    });
  }
  peers.sort((a, b) => (a.online === b.online ? String(a.name).localeCompare(String(b.name)) : (a.online ? -1 : 1)));
  // AdvertiseRoutes, best effort (debug prefs may fail on some builds).
  let advertiseRoutes = [];
  try {
    const pr = await runCli(['debug', 'prefs'], 5000);
    const pj = JSON.parse(pr.stdout);
    if (Array.isArray(pj.AdvertiseRoutes)) advertiseRoutes = pj.AdvertiseRoutes;
  } catch (e) { /* unknown; leave empty */ }
  return {
    installed: true,
    connected,
    backendState: backend,
    needsLogin: backend === 'NeedsLogin',
    authUrl: j.AuthURL || null,
    selfName: self.HostName || null,
    selfIp,
    tailnet: tailnetFromDns(self.DNSName),
    peers,
    advertiseRoutes,
    lanSubnet: lanSubnet(),
  };
}

async function setConnected(on) {
  const args = on ? ['up'] : ['down'];
  const r = await runCli(args, 60000);
  if (r.notFound) return { success: false, error: 'Tailscale is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'Tailscale is taking a long time — if a browser sign-in window opened, complete it there, then press Refresh.' };
  const out = (r.stdout || '') + '\n' + (r.stderr || '');
  if (r.code !== 0) {
    const url = (out.match(/https:\/\/login\.tailscale\.com\/[A-Za-z0-9/?=&._-]+/) || [])[0] || null;
    return { success: false, needsLogin: !!url, authUrl: url, error: 'Tailscale could not ' + (on ? 'connect' : 'disconnect') + '.' };
  }
  const url = (out.match(/https:\/\/login\.tailscale\.com\/[A-Za-z0-9/?=&._-]+/) || [])[0] || null;
  return { success: true, needsLogin: !!url, authUrl: url };
}

async function setSubnetRouter(on) {
  const subnet = lanSubnet();
  if (on && !subnet) return { success: false, error: 'Could not find your home network address.' };
  if (on && !isCidr(subnet)) return { success: false, error: 'Invalid network address.' };
  const args = on ? ['up', '--advertise-routes=' + subnet] : ['up', '--advertise-routes='];
  const r = await runCli(args, 60000);
  if (r.notFound) return { success: false, error: 'Tailscale is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'Tailscale did not answer in time. Try again.' };
  if (r.code !== 0) return { success: false, error: 'Could not change the subnet router setting.' };
  return { success: true, subnet: on ? subnet : null };
}

module.exports = { getStatus, setConnected, setSubnetRouter, lanSubnet, isCidr };
