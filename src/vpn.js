'use strict';
/*
 * TechVision Tailscale VPN — Tailscale client manager (main process).
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
const { execFile, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const http = require('http');

const WIN_CLI = 'C:\\Program Files\\Tailscale\\tailscale.exe';
const WIN_GUI = 'C:\\Program Files\\Tailscale\\tailscale-ipn.exe';
const MSI_URL = 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi';
const MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;

function resolveCli() {
  // Re-checked on every call: the CLI may appear while the app is
  // running (e.g. right after the auto-install below finishes).
  if (process.platform === 'win32' && fs.existsSync(WIN_CLI)) return WIN_CLI;
  return 'tailscale';
}

function runCli(args, timeoutMs, onData) {
  return new Promise((resolve) => {
    const child = execFile(resolveCli(), args, { timeout: timeoutMs || 15000, windowsHide: true }, (err, stdout, stderr) => {
      if (err && err.code === 'ENOENT') return resolve({ code: -1, stdout: '', stderr: '', notFound: true });
      if (err && err.killed) return resolve({ code: -2, stdout: stdout || '', stderr: stderr || '', timedOut: true });
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
    // Stream output as it arrives: `tailscale up` prints the sign-in URL
    // and then blocks for up to 60s waiting for the browser login. A
    // caller that needs the URL (to open the browser itself) must not
    // wait for the process to exit first — that was a 60-second delay
    // before the browser opened on a real device.
    if (onData) {
      const feed = (d) => { try { onData(String(d)); } catch (e) {} };
      if (child.stdout) child.stdout.on('data', feed);
      if (child.stderr) child.stderr.on('data', feed);
    }
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
const VIRTUAL_IFACE_RE = /docker|veth|vmware|virtual|vbox|tailscale|wintun|wsl|hyper-v|tap|tun|br-|wireguard|amnezia|awg/i;
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
function cidrContainsIp(cidr, ip) {
  const m = String(cidr || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  const p = String(ip || '').split('.').map(Number);
  if (!m || p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const prefix = parseInt(m[5], 10);
  if (prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const net = ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0;
  const addr = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  return (addr & mask) >>> 0 === (net & mask) >>> 0;
}
// Pick the LAN subnet from an os.networkInterfaces() table. Pure, so
// it is unit-testable. Passes: (1) a real private LAN on a real
// adapter, (2) anything on a real adapter, (3) anything at all.
// Virtual adapters (Docker, VMware, WSL, Tailscale itself, and the
// WireGuard/AmneziaWG tunnel) and link-local addresses (169.254.x)
// never win while a real LAN exists — advertising a virtual subnet
// would send the tailnet nowhere.
// excludeIps (optional): addresses whose subnet must never be picked
// — the WireGuard tunnel address: its /24 is a tunnel, not the home
// LAN, and advertising it would point the tailnet at the tunnel
// instead of at the printers and cameras (2026-11-27: the router
// advertised 10.0.0.0/24 for exactly this reason).
function pickLanSubnet(ifs, excludeIps) {
  const excluded = Array.isArray(excludeIps) ? excludeIps.filter(Boolean) : [];
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
        if (!cidr) continue;
        if (excluded.some((ip) => cidrContainsIp(cidr, ip))) continue;
        return cidr;
      }
    }
  }
  return null;
}
// The WireGuard/AmneziaWG tunnel address (default 10.0.0.1): its
// subnet is a tunnel, never the home LAN. main pushes the configured
// address in (getWgConfig().server.address) before every status read.
let tunnelAddress = '10.0.0.1';
function setTunnelAddress(ip) {
  if (typeof ip === 'string' && ip.trim()) tunnelAddress = ip.trim().split('/')[0];
}
function lanSubnet() {
  try { return pickLanSubnet(os.networkInterfaces(), tunnelAddress ? [tunnelAddress] : []); }
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
  if (r.timedOut) return { installed: true, connected: false, guiRunning: await guiRunning(), error: 'Tailscale did not answer in time. Is the Tailscale service running?' };
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
    guiRunning: await guiRunning(),
    needsLogin: backend === 'NeedsLogin',
    authUrl: j.AuthURL || null,
    selfName: self.HostName || null,
    selfIp,
    deviceId: self.ID || null, // the node ID the Tailscale API needs
    tailnet: tailnetFromDns(self.DNSName),
    peers,
    advertiseRoutes,
    lanSubnet: lanSubnet(),
  };
}

/* The Tailscale sign-in URL, from `tailscale up` output or a status
   report. Only login.tailscale.com counts — never open an arbitrary URL
   from CLI output in a browser. */
function extractLoginUrl(text) {
  const m = String(text || '').match(/https:\/\/login\.tailscale\.com\/[A-Za-z0-9/?=&._-]+/);
  return m ? m[0] : null;
}

/* The Tailscale tray app (tailscale-ipn.exe) is a separate per-user
   process from the Windows service, and the service alone is NOT
   enough: with no GUI process running, the backend sits in NoState
   and never connects — `tailscale up` can even report success while
   the view stays stuck on "Not connected", and the tray icon is
   nowhere to be seen. The installer runs with TS_NOLAUNCH=true, so
   after our one-click install the GUI never starts on its own.
   Relaunching the GUI needs no admin rights. */
function parseTasklistOutput(text) {
  return /(^|\r?\n)\s*tailscale-ipn\.exe\s/i.test(String(text || ''));
}

function guiRunning() {
  if (process.platform !== 'win32') return Promise.resolve(true);
  return new Promise((resolve) => {
    execFile('tasklist', ['/FI', 'IMAGENAME eq tailscale-ipn.exe', '/NH'], { timeout: 10000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve(false);
      resolve(parseTasklistOutput(stdout || ''));
    });
  });
}

function launchGui() {
  if (process.platform !== 'win32') return Promise.resolve(false);
  if (!fs.existsSync(WIN_GUI)) return Promise.resolve(false);
  return new Promise((resolve) => {
    try {
      const child = spawn(WIN_GUI, [], { detached: true, stdio: 'ignore', windowsHide: true });
      child.on('error', () => resolve(false));
      child.unref();
      resolve(true);
    } catch (e) { resolve(false); }
  });
}

// The backend state without the debug-prefs call: light enough to poll
// while waiting for the GUI to pull the backend out of NoState.
async function backendState() {
  const r = await runCli(['status', '--json'], 10000);
  if (r.notFound || r.timedOut) return null;
  try { const j = JSON.parse(r.stdout); return j.BackendState || null; }
  catch (e) { return null; }
}

async function ensureGuiRunning() {
  if (process.platform !== 'win32') return { running: true, launched: false };
  if (await guiRunning()) return { running: true, launched: false };
  const launched = await launchGui();
  if (!launched) return { running: false, launched: false };
  // The GUI takes a few seconds to pull the backend out of NoState.
  for (let i = 0; i < 10; i++) {
    const st = await backendState();
    if (st && st !== 'NoState' && st !== 'Starting') return { running: true, launched: true };
    await new Promise((res) => setTimeout(res, 2000));
  }
  return { running: true, launched: true, backendStillStarting: true };
}

async function setConnected(on, timeoutMs, onAuthUrl) {
  cachedDeviceId = null; // the identity may have changed; re-read it once on next use
  if (on) {
    // Open the Tailscale app first when it is not running — otherwise
    // the backend never leaves NoState and Connect looks dead.
    await ensureGuiRunning();
  }
  const args = on ? ['up'] : ['down'];
  // Fire onAuthUrl the moment the sign-in URL appears in the output —
  // `tailscale up` blocks for up to 60s waiting for the browser login,
  // so waiting for it to exit first delays the browser by a full minute.
  // The output is accumulated because a chunk may split the URL.
  let streamed = '', urlSeen = null;
  const r = await runCli(args, timeoutMs || 60000, (chunk) => {
    if (!on || !onAuthUrl || urlSeen) return;
    streamed += chunk;
    const url = extractLoginUrl(streamed);
    if (url) { urlSeen = url; onAuthUrl(url); }
  });
  if (r.notFound) return { success: false, error: 'Tailscale is not installed on this computer.' };
  if (r.timedOut) {
    // `tailscale up` blocks while it waits for the browser sign-in — and
    // on some machines it never opens the browser at all. The login URL
    // is in the output it already printed; hand it back instead of
    // dropping it, so the app can open it itself.
    const url = extractLoginUrl((r.stdout || '') + '\n' + (r.stderr || ''));
    return { success: false, needsLogin: !!url, authUrl: url, error: 'Tailscale is taking a long time — if a browser sign-in window opened, complete it there, then press Refresh.' };
  }
  const out = (r.stdout || '') + '\n' + (r.stderr || '');
  if (r.code !== 0) {
    const url = extractLoginUrl(out);
    return { success: false, needsLogin: !!url, authUrl: url, error: 'Tailscale could not ' + (on ? 'connect' : 'disconnect') + '.' };
  }
  const url = extractLoginUrl(out);
  return { success: true, needsLogin: !!url, authUrl: url };
}

async function setSubnetRouter(on, auth) {
  const subnet = lanSubnet();
  if (on && !subnet) return { success: false, error: 'Could not find your home network address.' };
  if (on && !isCidr(subnet)) return { success: false, error: 'Invalid network address.' };
  const args = on ? ['up', '--advertise-routes=' + subnet] : ['up', '--advertise-routes='];
  const r = await runCli(args, 60000);
  if (r.notFound) return { success: false, error: 'Tailscale is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'Tailscale did not answer in time. Try again.' };
  if (r.code !== 0) return { success: false, error: 'Could not change the subnet router setting.' };
  if (!on) return { success: true, subnet: null, approved: false };
  // Advertising alone does nothing — approve the routes through the API
  // when a credential is saved (OAuth client needs the devices:routes
  // scope; an API token inherits the user's access). Without one, the
  // caller falls back to the admin console button.
  const a = typeof auth === 'string' ? { apiToken: auth } : (auth || {});
  if ((a.clientId && a.clientSecret) || (a.apiToken && String(a.apiToken).trim())) {
    const ap = await approveRoutes(auth, [subnet]);
    if (ap.success) return { success: true, subnet, approved: true };
    return { success: true, subnet, approved: false, approveError: ap.error };
  }
  return { success: true, subnet, approved: false };
}

/* A stale advertisement, fixed on sight. pickLanSubnet used to return
   the WireGuard tunnel subnet (10.0.0.0/24) when the tunnel adapter
   was enumerated before the real LAN, so a machine could sit there
   advertising the tunnel instead of its home LAN. When the router is
   ON and the advertised set no longer matches the freshly detected
   LAN, re-advertise the right subnet (`tailscale up` sets the exact
   set, so the stale advertisement is replaced) and retry the API
   approval. Never runs while disconnected — `tailscale up` then
   would try to sign in. `status` is an already-fetched getStatus()
   result (the caller usually has one); without it, it reads its own.
   Returns { success, reconciled, subnet?, approved?, reason? }. */
async function reconcileSubnetRouter(auth, status) {
  let st = status || null;
  if (!st) {
    try { st = await getStatus(); }
    catch (e) { return { success: false, reconciled: false, error: 'Could not read Tailscale status.' }; }
  }
  if (!st || !st.installed) return { success: false, reconciled: false, error: 'Tailscale is not installed on this computer.' };
  if (!st.connected) return { success: true, reconciled: false, reason: 'not-connected' };
  const advertised = Array.isArray(st.advertiseRoutes) ? st.advertiseRoutes : [];
  if (!advertised.length) return { success: true, reconciled: false, reason: 'router-off' };
  const lan = st.lanSubnet || null;
  if (!lan) return { success: true, reconciled: false, reason: 'no-lan' };
  if (advertised.indexOf(lan) >= 0 && advertised.length === 1) return { success: true, reconciled: false, reason: 'already-correct' };
  const r = await setSubnetRouter(true, auth);
  if (!r || !r.success) return { success: false, reconciled: false, error: (r && r.error) || 'Could not re-advertise the home network.' };
  return { success: true, reconciled: true, subnet: r.subnet, approved: !!r.approved, previous: advertised };
}

/* ---------- Tailscale API: key expiry (the real integration) ----------
 * `tailscale set --key-expiry=off` is NOT a real CLI flag — the official
 * CLI has no way to turn off key expiry (the only nearby command is the
 * debug-only `tailscale debug set-expire`), so that call always failed
 * with "unknown flag" and the view hid the reason behind a generic
 * toast. The documented route is the Tailscale API:
 *   POST /api/v2/device/{deviceID}/key  {"keyExpiryDisabled": true}
 * with one of two credentials, both created once by the tailnet admin
 * in the console (the app cannot create them — only a signed-in admin
 * can, which is the whole point of the control-plane check):
 *   1. OAuth client (Settings -> Trust credentials -> OAuth clients,
 *      scope devices:core) — the secret never expires; the app
 *      exchanges it for a 1-hour access token and refreshes it itself,
 *      so after the one-time setup nothing is ever pasted again.
 *   2. API access token (Settings -> Keys, tskey-api-...) — simpler,
 *      but it expires within 90 days and must be regenerated.
 * GET /api/v2/device/{deviceID} returns the real keyExpiryDisabled
 * flag, so the view can show the truth instead of the preference.
 * Credentials are stored in the app settings (same as the SMTP
 * password) and can be revoked any time from the console. */
const TAILSCALE_API_BASE = 'https://api.tailscale.com/api/v2';

let oauthTokenCache = null; // { clientId, accessToken, expiresAt }

async function exchangeOAuthToken(clientId, clientSecret) {
  const now = Date.now();
  if (oauthTokenCache && oauthTokenCache.clientId === clientId && oauthTokenCache.expiresAt - 60000 > now) return { token: oauthTokenCache.accessToken };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret });
    const res = await fetch(TAILSCALE_API_BASE + '/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: ctrl.signal,
    });
    let j = null;
    try { j = await res.json(); } catch (e) { /* fall through */ }
    if (!res.ok || !j || !j.access_token) return { error: 'Tailscale refused the OAuth client (HTTP ' + res.status + '). Check the client ID and secret in the VPN settings.' };
    oauthTokenCache = { clientId, accessToken: j.access_token, expiresAt: now + ((j.expires_in || 3600) * 1000) };
    return { token: j.access_token };
  } catch (e) {
    return { error: e && e.name === 'AbortError' ? 'Tailscale API did not answer in time.' : (e && e.message && e.message !== 'fetch failed' ? e.message : 'Could not reach the Tailscale API.') };
  } finally { clearTimeout(timer); }
}

/* Resolve the API credential the app should use, in order:
   1. OAuth client (never expires, auto-refreshed) — { clientId, clientSecret }
   2. API access token (expires within 90 days) — { apiToken } or a bare string
   Returns { header, via } or { error, via }. */
async function resolveApiAuth(auth) {
  const a = typeof auth === 'string' ? { apiToken: auth } : (auth || {});
  if (a.clientId && a.clientSecret) {
    const ex = await exchangeOAuthToken(String(a.clientId).trim(), String(a.clientSecret).trim());
    if (ex.error) return { error: ex.error, via: 'oauth' };
    return { header: 'Bearer ' + ex.token, via: 'oauth' };
  }
  if (a.apiToken && String(a.apiToken).trim()) return { header: 'Basic ' + Buffer.from(String(a.apiToken).trim() + ':').toString('base64'), via: 'token' };
  return { error: 'No API credential saved.', via: null };
}

async function apiFetch(apiPath, authHeader, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(TAILSCALE_API_BASE + apiPath, {
      method: (opts && opts.method) || 'GET',
      headers: {
        Authorization: authHeader,
        'Content-Type': 'application/json',
      },
      body: opts && opts.body ? JSON.stringify(opts.body) : undefined,
      signal: ctrl.signal,
    });
    let body = null;
    try { body = await res.json(); } catch (e) { /* empty body on success */ }
    return { ok: res.ok, status: res.status, body };
  } catch (e) {
    // Node's fetch reports a refused/DNS failure as a bare "fetch
    // failed" — the credentials line must say what that means in
    // plain words instead of showing the engine jargon. Any other
    // specific message (e.g. a certificate problem) is kept as-is.
    return { ok: false, status: 0, body: null, error: e && e.name === 'AbortError' ? 'Tailscale API did not answer in time.' : (e && e.message && e.message !== 'fetch failed' ? e.message : 'Could not reach the Tailscale API.') };
  } finally { clearTimeout(timer); }
}

/* The device ID never changes for this device, but reading it costs a
   slow `tailscale status --json` call every time — and every API
   operation (key expiry, routes) used to pay that cost, which is why
   flipping the subnet toggle felt like it took forever. Read it once
   and keep it; a connect/disconnect clears it in case the identity
   changed. */
let cachedDeviceId = null;
let lastDeviceId = null; // kept even across disconnects: a stale id only
// risks a 404 on a verify call, and a 404 still proves the credential.
async function selfDeviceId() {
  if (cachedDeviceId) return { id: cachedDeviceId, error: null };
  const st = await getStatus();
  if (!st.installed) return { id: null, error: 'Tailscale is not installed on this computer.' };
  if (!st.connected) return { id: null, error: 'Connect to Tailscale first.' };
  if (!st.deviceId) return { id: null, error: 'Could not find this device in Tailscale status.' };
  cachedDeviceId = st.deviceId;
  lastDeviceId = st.deviceId;
  return { id: st.deviceId, error: null };
}

/* One API call with the resolved credential; on a 401 with OAuth the
   cached token is dropped and the call is retried once with a fresh one. */
async function apiCallWithAuth(apiPath, auth, opts) {
  const first = await resolveApiAuth(auth);
  if (first.error) return { ok: false, status: 0, body: null, error: first.error, via: first.via || null };
  const r = await apiFetch(apiPath, first.header, opts);
  if (r.status === 401 && first.via === 'oauth') {
    oauthTokenCache = null;
    const second = await resolveApiAuth(auth);
    if (second.error) return { ok: false, status: 0, body: null, error: second.error, via: 'oauth' };
    const r2 = await apiFetch(apiPath, second.header, opts);
    return { ok: r2.ok, status: r2.status, body: r2.body, error: r2.error, via: 'oauth' };
  }
  return { ok: r.ok, status: r.status, body: r.body, error: r.error, via: first.via };
}

function authRefusedError(via, status, scope) {
  const need = scope || 'devices:core';
  if (via === 'oauth') return 'Tailscale API refused the OAuth client (HTTP ' + status + '). Check the client ID and secret, and that the client has the ' + need + ' scope.';
  return 'Tailscale API refused the token (HTTP ' + status + '). Check the API access token in the VPN settings.';
}

/* Does the saved credential actually work? "Saved" says nothing about
   that, so the UI shows a word instead — Connected or Disconnected.
   Any non-401/403 answer proves the credential authenticates, so even
   a 404 (device id unknown — e.g. never connected on this machine)
   counts as valid; only a refused auth or a failed exchange means the
   credential itself is wrong. Returns { valid, via?, error? }. */
async function verifyApiAuth(auth) {
  const a = typeof auth === 'string' ? { apiToken: auth } : (auth || {});
  if (!a.clientId && !a.apiToken) return { valid: false, error: 'No API credentials saved.' };
  const idRes = await selfDeviceId().catch(() => ({ id: null }));
  const id = (idRes && idRes.id) || lastDeviceId || 'nUNKNOWN';
  const r = await apiCallWithAuth('/device/' + encodeURIComponent(id), auth, { method: 'GET' });
  if (r.ok) return { valid: true, via: r.via };
  if (r.status === 404) return { valid: true, via: r.via };
  if (r.status === 401 || r.status === 403) return { valid: false, via: r.via, error: authRefusedError(r.via, r.status) };
  return { valid: false, via: r.via || null, error: r.error || ('Tailscale API answered HTTP ' + (r.status || '?') + '.') };
}

async function disableKeyExpiryViaApi(auth) {
  return setKeyExpiryDisabled(auth, true);
}

/* Set the key-expiry flag either way: disabled=true turns expiry off
   (the toggle ON), disabled=false turns it back on (the toggle OFF).
   The toggle is a real switch, not a preference — flipping it calls
   this immediately and the state line shows what the API says. */
async function setKeyExpiryDisabled(auth, disabled) {
  const { id, error } = await selfDeviceId();
  if (!id) return { success: false, error };
  const r = await apiCallWithAuth('/device/' + encodeURIComponent(id) + '/key', auth, { method: 'POST', body: { keyExpiryDisabled: !!disabled } });
  if (r.ok) return { success: true, via: 'api' };
  if (r.status === 401 || r.status === 403) return { success: false, error: authRefusedError(r.via, r.status) };
  return { success: false, error: r.error || ('Tailscale API error (HTTP ' + (r.status || '?') + ').') };
}

async function enableKeyExpiry(auth) {
  return setKeyExpiryDisabled(auth, false);
}

/* ---------- Tailscale API: subnet route approval ----------
 * Advertising a route (tailscale up --advertise-routes) is only half
 * the job: the route does nothing until the tailnet admin approves it.
 * The admin console approval is the same API call the console itself
 * makes — POST /device/{deviceId}/routes {"routes": [...]} (scope
 * devices:routes) — so with an OAuth client or API token saved, the
 * app approves the route itself and the console button is not needed.
 * Without a credential the app can only advertise, and the user still
 * has to approve it in the console. GET /device/{deviceId}/routes
 * returns the real state ({routes: [{route, advertised, enabled}]}),
 * so the view can say whether the route is approved or still waiting. */
async function getDeviceRoutes(auth) {
  const { id, error } = await selfDeviceId();
  if (!id) return { success: false, error };
  const r = await apiCallWithAuth('/device/' + encodeURIComponent(id) + '/routes', auth, { method: 'GET' });
  if (!r.ok) {
    if (r.status === 401 || r.status === 403) return { success: false, error: authRefusedError(r.via, r.status, 'devices:routes') };
    return { success: false, error: r.error || ('Tailscale API error (HTTP ' + (r.status || '?') + ').') };
  }
  const routes = Array.isArray((r.body || {}).routes) ? r.body.routes : [];
  return { success: true, routes: routes.map((x) => ({ route: x.route, advertised: !!x.advertised, enabled: !!x.enabled })) };
}

async function approveRoutes(auth, routes) {
  const { id, error } = await selfDeviceId();
  if (!id) return { success: false, error };
  const r = await apiCallWithAuth('/device/' + encodeURIComponent(id) + '/routes', auth, { method: 'POST', body: { routes: routes || [] } });
  if (r.ok) return { success: true, via: 'api' };
  if (r.status === 401 || r.status === 403) return { success: false, error: authRefusedError(r.via, r.status, 'devices:routes') };
  return { success: false, error: r.error || ('Tailscale API error (HTTP ' + (r.status || '?') + ').') };
}

/* The real key-expiry state of this device, from the API. Returns
   { success, disabled, expires } — disabled is the flag itself, so it
   stays true even though the `expires` timestamp goes stale after the
   flag is set (Tailscale keeps the original expiry time). */
async function getKeyExpiryState(auth) {
  const a = typeof auth === 'string' ? { apiToken: auth } : (auth || {});
  if (!a.clientId && !a.apiToken) return { success: false, error: 'No API credential saved.' };
  const { id, error } = await selfDeviceId();
  if (!id) return { success: false, error };
  const r = await apiCallWithAuth('/device/' + encodeURIComponent(id), auth, { method: 'GET' });
  if (!r.ok) {
    if (r.status === 401 || r.status === 403) return { success: false, error: authRefusedError(r.via, r.status) };
    return { success: false, error: r.error || ('Tailscale API error (HTTP ' + (r.status || '?') + ').') };
  }
  const b = r.body || {};
  return { success: true, disabled: b.keyExpiryDisabled === true, expires: b.expires || null };
}

/* Disable key expiry for this device. With a saved credential the
   documented API route is used (OAuth first, then API token); without
   one the old CLI call is kept as a fallback (it fails on current
   Tailscale builds — there is no --key-expiry flag — but the real
   error is now returned instead of being swallowed). Tailscale
   normally makes the node key expire after 180 days and asks for
   another sign-in; with expiry off the device stays connected
   forever. Returns { success, error?, via? }. */
async function disableKeyExpiry(auth) {
  const a = typeof auth === 'string' ? { apiToken: auth } : (auth || {});
  if ((a.clientId && a.clientSecret) || (a.apiToken && String(a.apiToken).trim())) return disableKeyExpiryViaApi(auth);
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
  return { success: true, via: 'cli' };
}

module.exports = {
  getStatus, setConnected, setSubnetRouter, reconcileSubnetRouter, setTunnelAddress, lanSubnet, isCidr, cidrContainsIp,
  installAndConnect, downloadFile, verifySignature, parseSignatureResult, extractLoginUrl, MSI_URL,
  disableKeyExpiry, enableKeyExpiry, getKeyExpiryState, verifyApiAuth, disableKeyExpiryViaApi, exchangeOAuthToken, getDeviceRoutes, approveRoutes, pickLanSubnet, tailnetFromDns, buildInstallScript,
  parseTasklistOutput, guiRunning, ensureGuiRunning, backendState,
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

/* Parses the JSON from Get-AuthenticodeSignature. Windows PowerShell 5.1's
   ConvertTo-Json renders enums as NUMBERS (Valid = 0), while PowerShell 7
   renders them as names — accept both, or a valid Tailscale signature is
   misread as "unknown" (seen on a real device: the toast said
   "signature status: unknown" for a properly signed installer). */
function parseSignatureResult(stdout) {
  try {
    const j = JSON.parse(stdout);
    const o = (j && typeof j === 'object' && !Array.isArray(j)) ? j : {};
    const st = o.Status;
    const statusName = typeof st === 'number' ? (st === 0 ? 'Valid' : 'Status(' + st + ')') : (st || 'unknown');
    const subject = typeof o.Subject === 'string' ? o.Subject : null;
    const valid = (st === 'Valid' || st === 0) && !!subject && /Tailscale/i.test(subject);
    return { ok: valid, status: statusName, subject };
  } catch (e) {
    return { ok: false, status: 'check-failed', detail: 'could not read the signature result' };
  }
}

/* Verifies the installer's Authenticode signature. Resolves
   { ok, status, subject?, detail? } — the status is the reason the check
   failed (e.g. 'NotTrusted', 'UnknownError'), so the user sees more than
   a bare "could not be verified". Windows only; anywhere else, or on any
   check failure, ok is false. */
function verifySignature(file) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ ok: false, status: 'unsupported-platform' });
    const ps = "(Get-AuthenticodeSignature -FilePath '" + file.replace(/'/g, "''") + "' | Select-Object @{N='Status';E={$_.Status.ToString()}}, @{N='Subject';E={$_.SignerCertificate.Subject}} | ConvertTo-Json -Compress)";
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { timeout: 30000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve({ ok: false, status: 'check-failed', detail: (err.message || 'PowerShell check failed').slice(0, 120) });
      resolve(parseSignatureResult(stdout));
    });
  });
}

/* The PowerShell that runs the MSI install elevated. Extracted so it
   is testable: $p.WaitForExit() — not Start-Process -Wait, which is
   known to return early when combined with -Verb RunAs, leaving the
   installer still running while the app thinks it finished.
   Two ways to get administrator rights:
   - no adminUser: -Verb RunAs, the Windows UAC prompt asks an
     administrator to approve (the normal case).
   - adminUser: the MSI runs as the administrator account the user
     typed (a domain PC where the user is not an admin). The password
     is NEVER in this script — it is fed on the install process's
     stdin and read here into a SecureString, so it appears in no
     file, no command line and no log. */
function buildInstallScript(msiPath, adminUser) {
  if (adminUser) {
    return [
      '$ErrorActionPreference = "Stop"',
      'try {',
      '  $pass = [Console]::In.ReadToEnd() -replace \'\\r?\\n$\', \'\'',
      '  $sec = ConvertTo-SecureString $pass -AsPlainText -Force',
      '  $cred = New-Object System.Management.Automation.PSCredential(\'' + String(adminUser).replace(/'/g, "''") + '\', $sec)',
      '  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList \'/i\', \'"' + msiPath + '"\', \'/qn\', \'/norestart\', \'TS_NOLAUNCH=true\' -Credential $cred -PassThru',
      '  $p.WaitForExit()',
      '  exit $p.ExitCode',
      '} catch {',
      '  exit 2',
      '}',
    ].join('\r\n');
  }
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

/* Silent per-machine MSI install, elevated once via UAC — or, when
   adminCreds { user, password } is given (a domain PC), run as that
   administrator account instead of the UAC prompt. The password is
   used once, in memory only: it travels on the install process's
   stdin, is never written to a file or a log, and is never stored.
   TS_NOLAUNCH=true stops the Tailscale tray app from popping up —
   TechVision is the UI here. Returns { success, declined?, error? }. */
function installMsiElevated(msiPath, adminCreds) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ success: false, error: 'Automatic install is available on Windows only.' });
    const scriptPath = path.join(os.tmpdir(), 'techvision-install-tailscale.ps1');
    const hasCreds = !!(adminCreds && adminCreds.user && adminCreds.password);
    fs.writeFileSync(scriptPath, buildInstallScript(msiPath, hasCreds ? adminCreds.user : null), 'utf8');
    const child = execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath], { timeout: 600000, windowsHide: true }, (err) => {
      try { fs.unlinkSync(scriptPath); } catch (e) {}
      if (err) {
        if (err.code === 2) return resolve({ success: false, declined: true, error: 'Installation was cancelled (administrator permission was not granted).' });
        return resolve({ success: false, error: 'Tailscale installation failed (code ' + err.code + ').' });
      }
      resolve({ success: true });
    });
    // Feed the administrator password on stdin only when the
    // credential path is used; close stdin either way so the script
    // never blocks waiting for input it will not read.
    if (child.stdin) {
      try { if (hasCreds) child.stdin.write(String(adminCreds.password) + '\n'); } catch (e) {}
      try { child.stdin.end(); } catch (e) {}
    }
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
   downloading / verifying / installing / waiting / connecting.
   onAuthUrl(url) fires the moment the sign-in URL appears, so the
   browser opens without waiting for `tailscale up` to finish. */
async function installAndConnect(progress, onAuthUrl, adminCreds) {
  const emit = (phase, pct, text) => { if (progress) { try { progress({ phase, pct, text }); } catch (e) {} } };
  if (process.platform !== 'win32') {
    return { success: false, error: 'Automatic install is available on Windows only. Install Tailscale from tailscale.com/download, then press Connect.' };
  }
  const hasCreds = !!(adminCreds && adminCreds.user && adminCreds.password);
  const st0 = await getStatus();
  if (st0.installed) return setConnected(true, undefined, onAuthUrl);
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
  emit('installing', 0, hasCreds ? ('Installing Tailscale as ' + adminCreds.user + '…') : 'Installing Tailscale — Windows will ask for administrator permission once.');
  const ins = await installMsiElevated(msi, hasCreds ? adminCreds : null);
  try { fs.unlinkSync(msi); } catch (e) {}
  if (!ins.success) return { success: false, error: ins.error || 'Tailscale installation failed.' };
  emit('waiting', 0, 'Waiting for Tailscale…');
  const found = await waitForCli(60000);
  if (!found) return { success: false, error: 'Tailscale was installed but the command was not found. Restart the app and try again.' };
  emit('connecting', 0, 'Connecting…');
  return setConnected(true, undefined, onAuthUrl);
}
