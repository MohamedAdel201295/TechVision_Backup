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
const https = require('https');
const http = require('http');

const WIN_CLI = 'C:\\Program Files\\Tailscale\\tailscale.exe';
const MSI_URL = 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi';
const MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;

function resolveCli() {
  // Re-checked on every call: the CLI may appear while the app is
  // running (e.g. right after the auto-install below finishes).
  if (process.platform === 'win32' && fs.existsSync(WIN_CLI)) return WIN_CLI;
  return 'tailscale';
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
const VIRTUAL_IFACE_RE = /docker|veth|vmware|virtual|vbox|tailscale|wintun|wsl|hyper-v|tap|tun|br-/i;
function isPrivateIpv4(ip) {
  const p = String(ip || '').split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  return false;
}
function cidrOf(a) {
  const ip = String(a.address || '').split('.').map(Number);
  const mask = String(a.netmask || '').split('.').map(Number);
  if (ip.length !== 4 || mask.length !== 4 || ip.some(Number.isNaN) || mask.some(Number.isNaN)) return null;
  const net = ip.map((b, i) => b & mask[i]);
  const prefix = mask.reduce((n, b) => n + b.toString(2).split('1').length - 1, 0);
  const cidr = net.join('.') + '/' + prefix;
  return isCidr(cidr) ? cidr : null;
}
// Pick the LAN subnet from an os.networkInterfaces() table. Pure, so
// it is unit-testable. Passes: (1) a real private LAN on a real
// adapter, (2) anything on a real adapter, (3) anything at all.
// Virtual adapters (Docker, VMware, WSL, Tailscale itself) and
// link-local addresses (169.254.x) never win while a real LAN exists —
// advertising a virtual subnet would send the tailnet nowhere.
function pickLanSubnet(ifs) {
  const passes = [
    (name, a) => !VIRTUAL_IFACE_RE.test(name) && isPrivateIpv4(a.address),
    (name, a) => !VIRTUAL_IFACE_RE.test(name),
    () => true,
  ];
  for (const ok of passes) {
    for (const name of Object.keys(ifs || {})) {
      for (const a of ifs[name] || []) {
        if (a.family !== 'IPv4' || a.internal) continue;
        if (String(a.address || '').startsWith('169.254.')) continue;
        if (!ok(name, a)) continue;
        const cidr = cidrOf(a);
        if (cidr) return cidr;
      }
    }
  }
  return null;
}
function lanSubnet() {
  try { return pickLanSubnet(os.networkInterfaces()); }
  catch (e) { return null; }
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

/* Disable key expiry for this device (`tailscale set --key-expiry=off`).
   Runs on the device itself — no API token needed. The device must
   already be connected. Tailscale normally makes the node key expire
   after 180 days and asks for another sign-in; with expiry off the
   device stays connected forever. Returns { success, error? }. */
async function disableKeyExpiry() {
  const st = await getStatus();
  if (!st.installed) return { success: false, error: 'Tailscale is not installed on this computer.' };
  if (!st.connected) return { success: false, error: 'Connect to Tailscale first.' };
  const r = await runCli(['set', '--key-expiry=off'], 30000);
  if (r.notFound) return { success: false, error: 'Tailscale is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'Tailscale did not answer in time. Try again.' };
  if (r.code !== 0) {
    const msg = (r.stderr || '').trim() || 'Could not disable key expiry.';
    return { success: false, error: msg };
  }
  return { success: true };
}

module.exports = {
  getStatus, setConnected, setSubnetRouter, lanSubnet, isCidr,
  installAndConnect, downloadFile, verifySignature, MSI_URL,
  disableKeyExpiry, pickLanSubnet, tailnetFromDns, buildInstallScript,
};

/* ---------- Auto-install (Windows only) ----------
   One click: download the official MSI from tailscale.com, verify its
   Authenticode signature (must be Valid, signed by Tailscale), install
   it silently with one UAC prompt, wait for the CLI, then connect.
   The download is HTTPS from Tailscale's own package host; nothing is
   run before the signature check passes. The installer file is deleted
   afterwards. On any other OS this returns an error telling the user
   to install Tailscale manually — there is no silent install there. */

/* Download a file, following up to 5 redirects. onProgress(done, total).
   An https download never downgrades to http mid-redirect. */
function downloadFile(url, dest, onProgress) {
  return new Promise((resolve, reject) => {
    const initialHttps = String(url).startsWith('https:');
    const get = (u, hops) => {
      if (hops > 5) return reject(new Error('Too many redirects while downloading.'));
      const lib = u.startsWith('https:') ? https : http;
      const req = lib.get(u, { headers: { 'User-Agent': 'TechVision-Backup/1.0' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const next = new URL(res.headers.location, u).toString();
          if (initialHttps && !next.startsWith('https:')) {
            res.resume();
            return reject(new Error('Download redirected to an insecure address.'));
          }
          res.resume();
          return get(next, hops + 1);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error('Download failed (HTTP ' + res.statusCode + ').'));
        }
        const total = parseInt(res.headers['content-length'], 10) || 0;
        let done = 0;
        const out = fs.createWriteStream(dest);
        res.on('data', (chunk) => {
          done += chunk.length;
          if (done > MAX_DOWNLOAD_BYTES) { req.destroy(); out.destroy(); return reject(new Error('Download is larger than expected.')); }
          if (onProgress) { try { onProgress(done, total); } catch (e) {} }
        });
        res.on('error', (e) => {
          out.destroy();
          // A connection that dies mid-download surfaces as a bare 'aborted'
          // / 'socket hang up' — say what actually happened while we know
          // how many bytes were expected.
          if (total > 0 && done < total) return reject(new Error('Download incomplete (' + done + ' of ' + total + ' bytes).'));
          reject(e);
        });
        out.on('error', reject);
        out.on('finish', () => {
          // A connection that ends early still fires 'finish' — a short file
          // would then fail the signature check with no explanation. Reject
          // it here, while we still know the expected size.
          if (total > 0 && done !== total) return reject(new Error('Download incomplete (' + done + ' of ' + total + ' bytes).'));
          resolve({ bytes: done, total });
        });
        res.pipe(out);
      });
      req.on('error', reject);
      req.setTimeout(120000, () => { req.destroy(new Error('Download timed out.')); });
    };
    get(url, 0);
  });
}

/* Verifies the installer's Authenticode signature. Resolves
   { ok, status, subject?, detail? } — the status is the reason the check
   failed (e.g. 'NotTrusted', 'UnknownError'), so the user sees more than
   a bare "could not be verified". Windows only; anywhere else, or on any
   check failure, ok is false. */
function verifySignature(file) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ ok: false, status: 'unsupported-platform' });
    const ps = "(Get-AuthenticodeSignature -FilePath '" + file.replace(/'/g, "''") + "' | Select-Object Status, @{N='Subject';E={$_.SignerCertificate.Subject}} | ConvertTo-Json -Compress)";
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { timeout: 30000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve({ ok: false, status: 'check-failed', detail: (err.message || 'PowerShell check failed').slice(0, 120) });
      try {
        const j = JSON.parse(stdout);
        const valid = j.Status === 'Valid' && typeof j.Subject === 'string' && /Tailscale/i.test(j.Subject);
        resolve({ ok: valid, status: j.Status || 'unknown', subject: j.Subject || null });
      } catch (e) { resolve({ ok: false, status: 'check-failed', detail: 'could not read the signature result' }); }
    });
  });
}

/* The PowerShell that runs the MSI install elevated. Extracted so it
   is testable: $p.WaitForExit() — not Start-Process -Wait, which is
   known to return early when combined with -Verb RunAs, leaving the
   installer still running while the app thinks it finished. */
function buildInstallScript(msiPath) {
  return [
    '$ErrorActionPreference = "Stop"',
    'try {',
    '  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList \'/i\', \'"' + msiPath + '"\', \'/qn\', \'/norestart\', \'TS_NOLAUNCH=true\' -Verb RunAs -PassThru',
    '  $p.WaitForExit()',
    '  exit $p.ExitCode',
    '} catch {',
    '  exit 2',
    '}',
  ].join('\r\n');
}

/* Silent per-machine MSI install, elevated once via UAC.
   TS_NOLAUNCH=true stops the Tailscale tray app from popping up —
   TechVision is the UI here. Returns { success, declined?, error? }. */
function installMsiElevated(msiPath) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ success: false, error: 'Automatic install is available on Windows only.' });
    const scriptPath = path.join(os.tmpdir(), 'techvision-install-tailscale.ps1');
    fs.writeFileSync(scriptPath, buildInstallScript(msiPath), 'utf8');
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath], { timeout: 600000, windowsHide: true }, (err) => {
      try { fs.unlinkSync(scriptPath); } catch (e) {}
      if (err) {
        if (err.code === 2) return resolve({ success: false, declined: true, error: 'Installation was cancelled (administrator permission was not granted).' });
        return resolve({ success: false, error: 'Tailscale installation failed (code ' + err.code + ').' });
      }
      resolve({ success: true });
    });
  });
}

async function waitForCli(timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 60000);
  while (Date.now() < deadline) {
    const r = await runCli(['version'], 5000);
    if (!r.notFound && r.code === 0) return true;
    await new Promise((res) => setTimeout(res, 2000));
  }
  return false;
}

/* Full one-click flow. progress({ phase, pct, text }) reports
   downloading / verifying / installing / waiting / connecting. */
async function installAndConnect(progress) {
  const emit = (phase, pct, text) => { if (progress) { try { progress({ phase, pct, text }); } catch (e) {} } };
  if (process.platform !== 'win32') {
    return { success: false, error: 'Automatic install is available on Windows only. Install Tailscale from tailscale.com/download, then press Connect.' };
  }
  const st0 = await getStatus();
  if (st0.installed) return setConnected(true);
  const dir = path.join(os.tmpdir(), 'TechVision');
  try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
  const msi = path.join(dir, 'tailscale-setup-latest-amd64.msi');
  emit('downloading', 0, 'Downloading Tailscale…');
  try {
    await downloadFile(MSI_URL, msi, (done, total) => {
      emit('downloading', total > 0 ? Math.round((done / total) * 100) : 0, 'Downloading Tailscale…');
    });
  } catch (e) {
    try { fs.unlinkSync(msi); } catch (_) {}
    return { success: false, error: 'Could not download Tailscale: ' + e.message };
  }
  emit('verifying', 0, 'Verifying the installer…');
  const v = await verifySignature(msi);
  if (!v.ok) {
    try { fs.unlinkSync(msi); } catch (e) {}
    const why = v.detail ? ' (' + v.detail + ')' : (v.status && v.status !== 'unsupported-platform' ? ' (signature status: ' + v.status + ')' : '');
    return { success: false, error: 'The downloaded installer could not be verified' + why + '. Install Tailscale manually from tailscale.com/download.' };
  }
  emit('installing', 0, 'Installing Tailscale — Windows will ask for administrator permission once.');
  const ins = await installMsiElevated(msi);
  try { fs.unlinkSync(msi); } catch (e) {}
  if (!ins.success) return { success: false, error: ins.error || 'Tailscale installation failed.' };
  emit('waiting', 0, 'Waiting for Tailscale…');
  const found = await waitForCli(60000);
  if (!found) return { success: false, error: 'Tailscale was installed but the command was not found. Restart the app and try again.' };
  emit('connecting', 0, 'Connecting…');
  return setConnected(true);
}
