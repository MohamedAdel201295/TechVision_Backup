'use strict';
/*
 * TechVision WireGuard VPN — self-hosted WireGuard manager (main process).
 *
 * This module does NOT implement a VPN protocol. It manages the official
 * WireGuard Windows app (`wireguard.exe` / `wg.exe`) that is already
 * installed on the machine: key generation, config building, tunnel
 * services, status, and peer list. There is no coordination server, no
 * account, and no third party in the loop — the server IS this machine.
 *
 * Verified against the official docs (wireguard-windows enterprise
 * docs, 2026-11-24):
 *   wireguard /installtunnelservice C:\path\to\wg0.conf
 *     — imports the .conf (plaintext is destroyed on import; the
 *       service keeps a DPAPI-encrypted copy) and creates the service
 *       WireGuardTunnel$wg0, which starts at boot with no login.
 *   wireguard /uninstalltunnelservice wg0
 *     — removes the service again. Keys and peer list stay in
 *       wireguard.json, so starting again is one click.
 *   wg show interfaces / wg show <iface> dump
 *     — the dump is tab-separated and machine-readable.
 *
 * Security: the wrapper only ever spawns `wg` / `wireguard` with a
 * fixed argument list. The only variable inputs are key material and
 * IPs the app itself generated, or a public key the user pasted into
 * the Add-peer box (validated as a 44-char base64 key before use).
 * Every call has a timeout. Private keys are stored PLAINTEXT in
 * wireguard.json — the same deliberate precedent as the Cloud server
 * TLS key in cloud.json: the tunnel service must be able to start at
 * boot with nobody logged in and no vault unlocked, and a
 * vault-stored key would block exactly that.
 *
 * Honest limits (only provable on real Windows):
 * - Installing a tunnel service needs admin: on Windows the install /
 *   uninstall runs elevated through a PowerShell Start-Process -Verb
 *   RunAs helper (one UAC prompt), the same pattern as the Tailscale
 *   MSI install. The elevated path itself cannot be tested in this
 *   Linux sandbox.
 * - `wg show` / `wg set` against a service-installed (.conf.dpapi)
 *   tunnel need Local System or Administrator rights per the official
 *   docs. If a non-elevated app gets access denied there, getStatus
 *   returns the real error instead of a made-up state — a proper
 *   elevated helper for status polling is future work, not silent
 *   guessing.
 */
const { execFile, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const WIN_WG = 'C:\\Windows\\System32\\wg.exe';
const WIN_WIREGUARD = 'C:\\Program Files\\WireGuard\\wireguard.exe';
const WG_DOWNLOAD_URL = 'https://www.wireguard.com/install/';
const SERVER_TUNNEL = 'wg0';
const CLIENT_TUNNEL = 'wg1';
const SERVER_ADDRESS = '10.0.0.1/24';
const TUNNEL_SUBNET = '10.0.0.0/24';
const LISTEN_PORT = 51820;
const DEFAULT_KEEPALIVE = 25;

/* Swappable transport (Phase 2 prep, core requirement 2026-11-24):
   the stealth/obfuscation method is still under verification
   (AmneziaWG vs WireGuard-over-TLS/WebSocket vs udp2raw), so the
   transport binary must NOT be hardcoded to stock wireguard.exe.
   setTransportBinaries() lets the app point this wrapper at a
   different wg / wireguard binary; main.js applies the saved
   `transport` block from wireguard.json at startup. With no override
   set, behavior is exactly Phase 1: the stock well-known Windows
   paths, then PATH. */
let transportOverride = { wg: null, wireguard: null };
function setTransportBinaries(o) {
  const v = (o && typeof o === 'object') ? o : {};
  const clean = (x) => (typeof x === 'string' && x.trim() ? x.trim() : null);
  transportOverride = { wg: clean(v.wg), wireguard: clean(v.wireguard) };
  return { wg: transportOverride.wg, wireguard: transportOverride.wireguard };
}
function getTransportBinaries() {
  return { wg: transportOverride.wg, wireguard: transportOverride.wireguard };
}

function resolveWg() {
  if (transportOverride.wg) return transportOverride.wg;
  if (process.platform === 'win32' && fs.existsSync(WIN_WG)) return WIN_WG;
  return 'wg';
}

function resolveWireguard() {
  if (transportOverride.wireguard) return transportOverride.wireguard;
  if (process.platform === 'win32' && fs.existsSync(WIN_WIREGUARD)) return WIN_WIREGUARD;
  return 'wireguard';
}

/* One WireGuard key: 32 bytes as base64 — 44 chars ending in '='. */
function isWgKey(s) {
  return typeof s === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(s);
}

function runCli(bin, args, timeoutMs, input) {
  return new Promise((resolve) => {
    /* NOTE: do NOT use execFile's `input` option here. On Node 24 it
       silently never delivers stdin to the child (verified 2026-11-24:
       `wg pubkey` with `input:` hung until the 10 s timeout with empty
       output, while writing to child.stdin by hand answered in ~0.2 s).
       The same hang would break keypair generation on real Windows,
       where `wg pubkey` reads the private key from stdin. */
    const child = execFile(bin, args, { timeout: timeoutMs || 15000, windowsHide: true }, (err, stdout, stderr) => {
      if (err && err.code === 'ENOENT') return resolve({ code: -1, stdout: '', stderr: '', notFound: true });
      if (err && err.killed) return resolve({ code: -2, stdout: stdout || '', stderr: stderr || '', timedOut: true });
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
    if (typeof input === 'string' && child.stdin) {
      try { child.stdin.write(input); } catch (e) {}
      try { child.stdin.end(); } catch (e) {}
    }
  });
}

function runWg(args, timeoutMs, input) {
  return runCli(resolveWg(), args, timeoutMs, input);
}

function runWireguard(args, timeoutMs) {
  return runCli(resolveWireguard(), args, timeoutMs);
}

/* ---------- keys ---------- */
async function genkey() {
  const r = await runWg(['genkey'], 10000);
  if (r.notFound) return { success: false, error: 'WireGuard is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  const key = (r.stdout || '').trim();
  if (r.code !== 0 || !isWgKey(key)) return { success: false, error: 'Could not generate a WireGuard key.' };
  return { success: true, key };
}

async function pubkey(privateKey) {
  if (!isWgKey(privateKey)) return { success: false, error: 'Not a valid WireGuard private key.' };
  const r = await runWg(['pubkey'], 10000, privateKey + '\n');
  if (r.notFound) return { success: false, error: 'WireGuard is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  const key = (r.stdout || '').trim();
  if (r.code !== 0 || !isWgKey(key)) return { success: false, error: 'Could not derive the public key.' };
  return { success: true, key };
}

async function genkeypair() {
  const g = await genkey();
  if (!g.success) return g;
  const p = await pubkey(g.key);
  if (!p.success) return p;
  return { success: true, privateKey: g.key, publicKey: p.key };
}

/* ---------- config building / parsing ---------- */
/* Server config: [Interface] + one [Peer] per client, each allowed its
   own /32 tunnel address. Peer names ride as `# name` comments — the
   config format has no name field of its own. */
/* A WireGuard Address needs CIDR (10.0.0.2/32) — a bare IP is invalid
   in a real .conf. Call sites pass bare tunnel IPs, so normalize here. */
function withCidr(addr, fallbackPrefix) {
  const a = String(addr || '').trim();
  if (!a) return null;
  return a.indexOf('/') >= 0 ? a : a + fallbackPrefix;
}

/* Extra config lines (Phase 2 prep): the config builders accept
   verbatim "Key = value" lines for the [Interface] / [Peer] sections
   (e.g. AmneziaWG's Jc/Jmin/Jmax/S1/S2 fields, once the obfuscation
   method is chosen). One line per string, no CR/LF, must contain '=' —
   anything else throws instead of writing a broken .conf. */
function extraLines(v) {
  if (v == null) return [];
  if (!Array.isArray(v)) throw new Error('Extra config lines must be an array of "Key = value" strings.');
  for (const l of v) {
    if (typeof l !== 'string' || /[\r\n]/.test(l) || l.indexOf('=') < 1 || !l.trim()) throw new Error('Invalid extra config line: "' + String(l).slice(0, 60) + '"');
  }
  return v.map((l) => l.trim());
}

function buildServerConf(opts) {
  const o = opts || {};
  if (!isWgKey(o.privateKey)) throw new Error('Server private key is not a valid WireGuard key.');
  const extraIface = extraLines(o.extraInterfaceLines);
  const extraPeer = extraLines(o.extraPeerLines);
  const lines = ['[Interface]', 'PrivateKey = ' + o.privateKey, 'Address = ' + (withCidr(o.address || SERVER_ADDRESS, '/24')), 'ListenPort = ' + (o.listenPort || LISTEN_PORT)];
  lines.push.apply(lines, extraIface);
  lines.push('');
  for (const p of o.peers || []) {
    if (!isWgKey(p.publicKey)) throw new Error('Peer public key is not a valid WireGuard key.');
    const ips = p.allowedIPs || (p.tunnelIp ? tunnelIpOf(p.tunnelIp) + '/32' : null);
    if (!ips) throw new Error('Peer "' + (p.name || p.publicKey.slice(0, 8)) + '" has no tunnel address.');
    if (p.name) lines.push('# ' + String(p.name).replace(/[\r\n]/g, ' '));
    lines.push('[Peer]', 'PublicKey = ' + p.publicKey, 'AllowedIPs = ' + ips);
    lines.push.apply(lines, extraPeer);
    lines.push('');
  }
  return lines.join('\n');
}

/* Client config: split tunnel by default — only the tunnel subnet
   (10.0.0.0/24) goes through the VPN, normal internet is untouched.
   AllowedIPs = 0.0.0.0/0 (full tunnel) is possible but the UI warns
   before allowing it, because then the server going down takes the
   machine's internet with it. */
function buildClientConf(opts) {
  const o = opts || {};
  if (!isWgKey(o.privateKey)) throw new Error('Client private key is not a valid WireGuard key.');
  if (!isWgKey(o.serverPublicKey)) throw new Error('Server public key is not a valid WireGuard key.');
  if (!o.endpoint || typeof o.endpoint !== 'string' || !/^[A-Za-z0-9.-]+:\d{1,5}$/.test(o.endpoint.trim())) throw new Error('Endpoint must be host:port, e.g. 203.0.113.10:51820.');
  const extraIface = extraLines(o.extraInterfaceLines);
  const extraPeer = extraLines(o.extraPeerLines);
  const lines = [
    '[Interface]',
    'PrivateKey = ' + o.privateKey,
    'Address = ' + (withCidr(o.address || o.tunnelIp || '10.0.0.2/32', '/32')),
  ];
  lines.push.apply(lines, extraIface);
  lines.push(
    '',
    '[Peer]',
    'PublicKey = ' + o.serverPublicKey,
    'Endpoint = ' + o.endpoint.trim(),
    'AllowedIPs = ' + (o.allowedIPs || TUNNEL_SUBNET),
    'PersistentKeepalive = ' + (o.persistentKeepalive || DEFAULT_KEEPALIVE),
  );
  lines.push.apply(lines, extraPeer);
  lines.push('');
  return lines.join('\n');
}

/* The /32 address a peer may claim, from its tunnel IP. Accepts
   '10.0.0.2' or '10.0.0.2/32' or an AllowedIPs list ('10.0.0.2/32'). */
function tunnelIpOf(s) {
  const m = String(s || '').match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return m ? m[1] : null;
}

/* Parse a standard .conf file (the official WireGuard format — the
   same file the official app and the phone apps read and write).
   Unknown keys are KEPT in `extra` (lowercased key -> raw value) so an
   import round-trip does not silently drop fields a different
   transport needs (e.g. AmneziaWG's Jc/Jmin/Jmax/S1/S2); section keys
   match case-insensitively. Throws an Error with a plain message on
   malformed input. */
function parseConf(text) {
  const out = { interface: {}, peers: [] };
  let section = null;
  let peer = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const sec = line.match(/^\[(Interface|Peer)\]$/i);
    if (sec) {
      section = sec[1].toLowerCase();
      if (section === 'peer') { peer = {}; out.peers.push(peer); }
      continue;
    }
    const kv = line.match(/^([^=]+)=(.*)$/);
    if (!kv || !section) throw new Error('Invalid line in config file: "' + line.slice(0, 60) + '"');
    const key = kv[1].trim().toLowerCase();
    const value = kv[2].trim();
    const target = section === 'interface' ? out.interface : peer;
    if (key === 'privatekey') target.privateKey = value;
    else if (key === 'publickey') target.publicKey = value;
    else if (key === 'address') target.address = value;
    else if (key === 'listenport') target.listenPort = parseInt(value, 10);
    else if (key === 'dns') target.dns = value;
    else if (key === 'allowedips') target.allowedIPs = value;
    else if (key === 'endpoint') target.endpoint = value;
    else if (key === 'persistentkeepalive') target.persistentKeepalive = parseInt(value, 10);
    else if (key === 'presharedkey') target.presharedKey = value;
    else if (key === 'mtu') target.mtu = parseInt(value, 10);
    else { if (!target.extra) target.extra = {}; target.extra[key] = value; }
  }
  if (!out.interface.privateKey && out.peers.length === 0) throw new Error('Config file has no [Interface] and no [Peer].');
  if (out.interface.privateKey && !isWgKey(out.interface.privateKey)) throw new Error('PrivateKey in the config file is not a valid WireGuard key.');
  for (const p of out.peers) {
    if (p.publicKey && !isWgKey(p.publicKey)) throw new Error('A peer PublicKey in the config file is not a valid WireGuard key.');
  }
  return out;
}

/* ---------- wg show parsing ---------- */
/* `wg show <iface> dump` — tab-separated, one interface line then one
   line per peer:
     iface  private-key  public-key  listen-port  fwmark
     iface  peer-pubkey  preshared-key  endpoint  allowed-ips
            latest-handshake  transfer-rx  transfer-tx  persistent-keepalive
   '(none)' means absent; latest-handshake is unix epoch seconds
   (0 = never). This is the machine-readable format — never parse the
   human `wg show` output for state. */
function parseWgShowDump(text) {
  const out = { interface: null, peers: [] };
  for (const raw of String(text || '').split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const f = raw.split('\t');
    if (f.length < 5) continue;
    if (f.length === 5) {
      out.interface = {
        name: f[0],
        publicKey: f[2] === '(none)' ? null : f[2],
        listenPort: f[3] === '(none)' ? null : parseInt(f[3], 10),
        fwmark: f[4] === '(none)' ? null : f[4],
      };
    } else if (f.length >= 9) {
      const hs = parseInt(f[5], 10);
      out.peers.push({
        publicKey: f[1],
        presharedKey: f[2] === '(none)' ? null : f[2],
        endpoint: f[3] === '(none)' ? null : f[3],
        allowedIPs: f[4] === '(none)' ? null : f[4],
        latestHandshake: Number.isNaN(hs) || hs <= 0 ? null : new Date(hs * 1000),
        transferRx: parseInt(f[6], 10) || 0,
        transferTx: parseInt(f[7], 10) || 0,
        persistentKeepalive: f[8] === '(none)' ? null : (f[8] === 'off' ? 0 : parseInt(f[8], 10)),
      });
    }
  }
  return out;
}

function parseWgShowInterfaces(text) {
  return String(text || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

async function dumpInterface(iface) {
  const r = await runWg(['show', iface, 'dump'], 10000);
  if (r.notFound) return { error: 'WireGuard is not installed on this computer.' };
  if (r.code !== 0) return { error: (r.stderr || '').trim() || 'Could not read WireGuard status.' };
  return parseWgShowDump(r.stdout);
}

async function getStatus() {
  const r = await runWg(['show', 'interfaces'], 10000);
  if (r.notFound) return { installed: false, serverRunning: false, clientRunning: false, server: null, client: null, error: 'WireGuard is not installed on this computer.' };
  if (r.timedOut) return { installed: true, serverRunning: false, clientRunning: false, server: null, client: null, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { installed: true, serverRunning: false, clientRunning: false, server: null, client: null, error: (r.stderr || '').trim() || 'Could not read WireGuard status.' };
  const ifaces = parseWgShowInterfaces(r.stdout);
  const out = { installed: true, serverRunning: false, clientRunning: false, server: null, client: null, error: null };
  if (ifaces.indexOf(SERVER_TUNNEL) >= 0) {
    out.serverRunning = true;
    const d = await dumpInterface(SERVER_TUNNEL);
    if (!d.error) out.server = { publicKey: d.interface ? d.interface.publicKey : null, listenPort: d.interface ? d.interface.listenPort : null, peers: d.peers };
    else out.error = d.error;
  }
  if (ifaces.indexOf(CLIENT_TUNNEL) >= 0) {
    out.clientRunning = true;
    const d = await dumpInterface(CLIENT_TUNNEL);
    if (!d.error) out.client = { publicKey: d.interface ? d.interface.publicKey : null, listenPort: d.interface ? d.interface.listenPort : null, peers: d.peers };
    else if (!out.error) out.error = d.error;
  }
  return out;
}

/* ---------- tunnel service ---------- */
/* The elevated PowerShell that installs/uninstalls a tunnel service.
   Extracted so it is testable: $p.WaitForExit() — not Start-Process
   -Wait, which is known to return early when combined with
   -Verb RunAs. A tunnel service needs admin (the service runs as
   Local System); the UAC prompt appears once per install. */
function buildElevatedScript(exePath, args) {
  const q = (s) => "'" + String(s).replace(/'/g, "''") + "'";
  return [
    '$ErrorActionPreference = "Stop"',
    'try {',
    '  $p = Start-Process -FilePath ' + q(exePath) + ' -ArgumentList ' + args.map(q).join(', ') + ' -Verb RunAs -PassThru',
    '  $p.WaitForExit()',
    '  exit $p.ExitCode',
    '} catch {',
    '  exit 2',
    '}',
  ].join('\r\n');
}

function runElevated(exePath, args) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ success: false, error: 'Elevated install is available on Windows only.' });
    const scriptPath = path.join(os.tmpdir(), 'techvision-wireguard-elevated.ps1');
    try { fs.writeFileSync(scriptPath, buildElevatedScript(exePath, args), 'utf8'); } catch (e) { return resolve({ success: false, error: 'Could not write the install script.' }); }
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath], { timeout: 120000, windowsHide: true }, (err) => {
      try { fs.unlinkSync(scriptPath); } catch (e) {}
      if (err) {
        if (err.code === 2) return resolve({ success: false, declined: true, error: 'Installation was cancelled (administrator permission was not granted).' });
        return resolve({ success: false, error: 'Could not install the tunnel service (code ' + err.code + ').' });
      }
      resolve({ success: true });
    });
  });
}

/* Write a temp .conf, install it as a tunnel service, and remove the
   plaintext again: the tool itself imports it as a DPAPI-encrypted
   copy and destroys the plaintext on success, but the delete here
   covers the failure path too — a private key must never linger in
   the temp folder. On Windows the install runs elevated (one UAC
   prompt); anywhere else the binary is run directly — which is how
   the test stub exercises this path, and how a missing binary
   reports a clean "not installed" instead of a crash. */
async function installTunnelService(name, confText) {
  if (!name || !/^[A-Za-z0-9_-]+$/.test(name)) return { success: false, error: 'Invalid tunnel name.' };
  if (!confText || typeof confText !== 'string') return { success: false, error: 'No config to install.' };
  const dir = path.join(os.tmpdir(), 'TechVision');
  try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
  // The file name IS the tunnel name: /installtunnelservice
  // C:\...\wg0.conf creates the service WireGuardTunnel$wg0, so the
  // temp file must be named exactly <name>.conf, nothing else.
  const confPath = path.join(dir, name + '.conf');
  try { fs.writeFileSync(confPath, confText, 'utf8'); } catch (e) { return { success: false, error: 'Could not write the tunnel config.' }; }
  try {
    let r;
    if (process.platform === 'win32') {
      r = await runElevated(resolveWireguard(), ['/installtunnelservice', confPath]);
      return r;
    }
    r = await runWireguard(['/installtunnelservice', confPath], 60000);
    if (r.notFound) return { success: false, error: 'WireGuard is not installed on this computer.' };
    if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
    if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not install the tunnel service.' };
    return { success: true };
  } finally {
    try { fs.unlinkSync(confPath); } catch (e) {}
  }
}

async function uninstallTunnelService(name) {
  if (!name || !/^[A-Za-z0-9_-]+$/.test(name)) return { success: false, error: 'Invalid tunnel name.' };
  if (process.platform === 'win32') return runElevated(resolveWireguard(), ['/uninstalltunnelservice', name]);
  const r = await runWireguard(['/uninstalltunnelservice', name], 30000);
  if (r.notFound) return { success: false, error: 'WireGuard is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not remove the tunnel service.' };
  return { success: true };
}

/* ---------- live peer changes ---------- */
/* Add or update one peer on a running tunnel without restarting it.
   `wg set` returns nothing on success. */
async function setPeer(iface, publicKey, allowedIPs) {
  if (!isWgKey(publicKey)) return { success: false, error: 'Not a valid WireGuard public key.' };
  if (!allowedIPs || typeof allowedIPs !== 'string') return { success: false, error: 'No address for this peer.' };
  const r = await runWg(['set', iface, 'peer', publicKey, 'allowed-ips', allowedIPs], 15000);
  if (r.notFound) return { success: false, error: 'WireGuard is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not update the peer.' };
  return { success: true };
}

async function removePeer(iface, publicKey) {
  if (!isWgKey(publicKey)) return { success: false, error: 'Not a valid WireGuard public key.' };
  const r = await runWg(['set', iface, 'peer', publicKey, 'remove'], 15000);
  if (r.notFound) return { success: false, error: 'WireGuard is not installed on this computer.' };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not remove the peer.' };
  return { success: true };
}

/* ---------- address allocation ---------- */
/* Next free 10.0.0.x for a new peer, starting at .2 (.1 is the
   server). Returns null when the /24 is full — 253 peers is the
   practical cap of one server tunnel. */
function nextTunnelIp(usedIps) {
  const used = new Set();
  for (const ip of usedIps || []) {
    const m = String(ip || '').match(/^10\.0\.0\.(\d{1,3})$/);
    if (m) used.add(parseInt(m[1], 10));
  }
  for (let n = 2; n <= 254; n++) {
    if (!used.has(n)) return '10.0.0.' + n;
  }
  return null;
}

module.exports = {
  getStatus, genkey, pubkey, genkeypair, isWgKey,
  buildServerConf, buildClientConf, parseConf,
  parseWgShowDump, parseWgShowInterfaces,
  installTunnelService, uninstallTunnelService,
  setPeer, removePeer, nextTunnelIp, tunnelIpOf,
  buildElevatedScript, resolveWg, resolveWireguard,
  setTransportBinaries, getTransportBinaries,
  WG_DOWNLOAD_URL, SERVER_TUNNEL, CLIENT_TUNNEL,
  SERVER_ADDRESS, TUNNEL_SUBNET, LISTEN_PORT, DEFAULT_KEEPALIVE,
};
