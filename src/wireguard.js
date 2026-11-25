'use strict';
/*
 * TechVision WireGuard VPN — self-hosted WireGuard manager (main process).
 *
 * This module does NOT implement a VPN protocol. It manages the
 * AmneziaWG Windows app (`amneziawg.exe` / `awg.exe`) that is already
 * installed on the machine: key generation, config building, tunnel
 * services, status, and peer list. AmneziaWG is a WireGuard fork with
 * traffic obfuscation (junk packets Jc/Jmin/Jmax, header mangling
 * S1–S4/H1–H4) — the transport since Phase 2, because stock WireGuard
 * does not understand the obfuscation fields and both ends must run
 * AmneziaWG. Stock WireGuard (`wireguard.exe` / `wg.exe`) is still
 * supported as a fallback transport via setTransport('wireguard'):
 * the same wrapper, the same .conf format, minus the obfuscation
 * fields. The wrapper itself defaults to stock (Phase 1 behavior);
 * the app selects AmneziaWG at startup in main.js (getWgConfig),
 * which is the default the user chose — the transport name lives
 * in wireguard.json. There is no coordination server, no account,
 * and no third party in the loop — the server IS this machine.
 *
 * Verified against the official docs (amneziawg-windows-client
 * enterprise docs + the 3.1.0 MSI itself, 2026-11-24):
 *   amneziawg /installtunnelservice C:\path\to\wg0.conf
 *     — imports the .conf (plaintext is destroyed on import; the
 *       service keeps a DPAPI-encrypted copy) and creates the service
 *       AmneziaWGTunnel$wg0, which starts at boot with no login.
 *       (Same CLI surface as stock wireguard.exe.)
 *   amneziawg /uninstalltunnelservice wg0
 *     — removes the service again. Keys and peer list stay in
 *       wireguard.json, so starting again is one click.
 *   awg show interfaces / awg show <iface> dump
 *     — `awg` is the AmneziaWG equivalent of `wg` (same subcommands:
 *       genkey, pubkey, show, set). The MSI installs it at
 *       C:\Program Files\AmneziaWG\awg.exe and adds that folder to
 *       PATH; amneziawg.exe lives in the same folder.
 *   The 3.1.0 MSI (amneziawg-amd64-3.1.0.msi, 3,641,344 bytes,
 *   downloaded 2026-11-24) carries a \x05DigitalSignature stream, i.e.
 *   it IS Authenticode-signed — but the signer identity could not be
 *   checked in this Linux sandbox; verifyInstallerSignature() checks
 *   it on Windows and requires the subject to name Amnezia.
 *   The MSI also supports the DO_NOT_LAUNCH=1 property for a silent
 *   install that does not open the UI afterwards.
 *
 * Obfuscation parameters (generated ONCE by generateObfuscationParams
 * and stored in wireguard.json under `obfuscation` — never regenerated
 * silently, or every existing peer breaks):
 *   Jc/Jmin/Jmax — junk packets before each handshake (Jc count,
 *     each Jmin..Jmax bytes; Jmax must stay below the MTU).
 *   S1–S4 — random prefix (padding) sizes for the init / response /
 *     cookie / data messages; S1+56 must not equal S2.
 *   H1–H4 — replacement header values (ranges "lo-hi") for the four
 *     WireGuard message types 1–4; the four ranges must not overlap
 *     and must not contain 1–4. S1–S4 and H1–H4 MUST match on server
 *     and client, or the tunnel comes up but no traffic passes.
 *   Jc/Jmin/Jmax are sender-only and need not match. This module
 *   writes the same full set on both ends anyway, so a client config
 *   built here always matches its server.
 *   Ranges follow the AmneziaWG docs (GL.iNet obfuscation reference
 *   + amneziawg-tools): Jc 1–128, 0 <= Jmin < Jmax < 1280,
 *   S1 0–1132, S2 0–1188, S3 0–1216, S4 0–32, H 5–2147483647.
 *   AmneziaWG 3.x adds further fields (I1–I5, HeaderProtectionKey,
 *   ContentPaddingAddition, …) — NOT generated here; the 2.0 set
 *   above is what this phase uses.
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
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');

const WIN_WG = 'C:\\Windows\\System32\\wg.exe';
const WIN_WIREGUARD = 'C:\\Program Files\\WireGuard\\wireguard.exe';
/* AmneziaWG well-known paths — verified against the 3.1.0 MSI
   (2026-11-24): the MSI installs amneziawg.exe + awg.exe + wintun.dll
   under ProgramFiles64Folder\AmneziaWG, i.e. C:\Program Files\AmneziaWG\,
   and appends that folder to PATH. (The amneziawg-windows library
   repo mentions %ProgramFiles%\Amnezia\AmneziaWG\Configurations as the
   tunnel-config search path for the tunnel.dll service build — that
   is the library layout, NOT the client MSI layout; the MSI is what
   this app installs, so its paths win here.) */
const WIN_AMNEZIAWG = 'C:\\Program Files\\AmneziaWG\\amneziawg.exe';
const WIN_AWG = 'C:\\Program Files\\AmneziaWG\\awg.exe';
/* Official AmneziaWG Windows client, latest release 3.1.0
   (21 Aug 2026). Asset name verified live 2026-11-24: a HEAD request
   for this exact URL returns 302 to the release asset
   (amneziawg-amd64-3.1.0.msi); sibling guesses (x64, no-version)
   return 404. Do NOT change the version without re-verifying the
   asset name on the releases page — the file name carries the
   version, and a wrong name is a silent 404 at download time. */
const AMNEZIAWG_VERSION = '3.1.0';
const AMNEZIAWG_MSI_NAME = 'amneziawg-amd64-' + AMNEZIAWG_VERSION + '.msi';
const AMNEZIAWG_DOWNLOAD_URL = 'https://github.com/amnezia-vpn/amneziawg-windows-client/releases/download/' + AMNEZIAWG_VERSION + '/' + AMNEZIAWG_MSI_NAME;
/* Manual-download fallback (the releases page, not a direct file):
   shown when the one-click install fails, so the user can still
   fetch the same official MSI by hand. */
const AMNEZIAWG_RELEASES_URL = 'https://github.com/amnezia-vpn/amneziawg-windows-client/releases';
const AMNEZIAWG_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;
const WG_DOWNLOAD_URL = 'https://www.wireguard.com/install/';
const SERVER_TUNNEL = 'wg0';
const CLIENT_TUNNEL = 'wg1';
const SERVER_ADDRESS = '10.0.0.1/24';
const TUNNEL_SUBNET = '10.0.0.0/24';
const LISTEN_PORT = 51820;
const DEFAULT_KEEPALIVE = 25;

/* Swappable transport (Phase 2, core requirement 2026-11-24):
   AmneziaWG is the transport the app selects (main.js calls
   setTransport('amneziawg') at startup unless wireguard.json says
   otherwise); stock WireGuard is the fallback. setTransport(...)
   switches the binaries resolveWg()/resolveWireguard() point at.
   setTransportBinaries() still allows an explicit per-binary
   override (used by tests and by a custom install path); an
   explicit override wins over the transport name.
   With no transport set, behavior is exactly Phase 1: the stock
   well-known Windows paths, then PATH. */
let currentTransport = 'wireguard';
let transportOverride = { wg: null, wireguard: null };
function setTransport(name) {
  const n = (name === 'amneziawg') ? 'amneziawg' : 'wireguard';
  currentTransport = n;
  return n;
}
function getTransport() { return currentTransport; }
function setTransportBinaries(o) {
  const v = (o && typeof o === 'object') ? o : {};
  const clean = (x) => (typeof x === 'string' && x.trim() ? x.trim() : null);
  transportOverride = { wg: clean(v.wg), wireguard: clean(v.wireguard) };
  return { wg: transportOverride.wg, wireguard: transportOverride.wireguard };
}
function getTransportBinaries() {
  return { wg: transportOverride.wg, wireguard: transportOverride.wireguard };
}

/* AmneziaWG binary resolution: the MSI's well-known install folder
   first, then PATH (the installer adds the folder to PATH, and `awg`
   is the wg-equivalent CLI — same genkey/pubkey/show/set
   subcommands). On non-Windows these return the bare binary names so
   the sandbox stub (named `amneziawg` / `awg`) can stand in. */
function resolveAmneziaWg() {
  if (process.platform === 'win32' && fs.existsSync(WIN_AWG)) return WIN_AWG;
  return 'awg';
}
function resolveAmneziaWireguard() {
  if (process.platform === 'win32' && fs.existsSync(WIN_AMNEZIAWG)) return WIN_AMNEZIAWG;
  return 'amneziawg';
}

function transportName() { return currentTransport === 'amneziawg' ? 'AmneziaWG' : 'WireGuard'; }
function notInstalledMsg() { return transportName() + ' is not installed on this computer.'; }

function resolveWg() {
  if (transportOverride.wg) return transportOverride.wg;
  if (currentTransport === 'amneziawg') return resolveAmneziaWg();
  if (process.platform === 'win32' && fs.existsSync(WIN_WG)) return WIN_WG;
  return 'wg';
}

function resolveWireguard() {
  if (transportOverride.wireguard) return transportOverride.wireguard;
  if (currentTransport === 'amneziawg') return resolveAmneziaWireguard();
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
  if (r.notFound) return { success: false, error: notInstalledMsg() };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  const key = (r.stdout || '').trim();
  if (r.code !== 0 || !isWgKey(key)) return { success: false, error: 'Could not generate a WireGuard key.' };
  return { success: true, key };
}

async function pubkey(privateKey) {
  if (!isWgKey(privateKey)) return { success: false, error: 'Not a valid WireGuard private key.' };
  const r = await runWg(['pubkey'], 10000, privateKey + '\n');
  if (r.notFound) return { success: false, error: notInstalledMsg() };
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
    lines.push('[Peer]', 'PublicKey = ' + p.publicKey);
    // The peer's reachable address, when the operator typed one
    // (the manual add-peer form always sets it; Cloud-join peers
    // have none — the client initiates, so the server needs no
    // endpoint for them). The server dials this address, so a peer
    // without it can only ever be reached when IT connects first.
    if (p.endpoint) {
      const ep = String(p.endpoint).trim();
      if (!isValidEndpoint(ep)) throw new Error('Peer "' + (p.name || p.publicKey.slice(0, 8)) + '" has an invalid endpoint (host:port).');
      lines.push('Endpoint = ' + ep);
    }
    lines.push('AllowedIPs = ' + ips);
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
  if (r.notFound) return { error: notInstalledMsg() };
  if (r.code !== 0) return { error: (r.stderr || '').trim() || 'Could not read WireGuard status.' };
  return parseWgShowDump(r.stdout);
}

async function getStatus() {
  const r = await runWg(['show', 'interfaces'], 10000);
  if (r.notFound) return { installed: false, serverRunning: false, clientRunning: false, server: null, client: null, error: notInstalledMsg() };
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
    if (r.notFound) return { success: false, error: notInstalledMsg() };
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
  if (r.notFound) return { success: false, error: notInstalledMsg() };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not remove the tunnel service.' };
  return { success: true };
}

/* ---------- live peer changes ---------- */
/* Add or update one peer on a running tunnel without restarting it.
   `wg set` returns nothing on success. */
async function setPeer(iface, publicKey, allowedIPs, endpoint) {
  if (!isWgKey(publicKey)) return { success: false, error: 'Not a valid WireGuard public key.' };
  if (!allowedIPs || typeof allowedIPs !== 'string') return { success: false, error: 'No address for this peer.' };
  const args = ['set', iface, 'peer', publicKey];
  if (endpoint) {
    if (!isValidEndpoint(endpoint)) return { success: false, error: 'Not a valid endpoint (host:port).' };
    args.push('endpoint', String(endpoint).trim());
  }
  args.push('allowed-ips', allowedIPs);
  const r = await runWg(args, 15000);
  if (r.notFound) return { success: false, error: notInstalledMsg() };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not update the peer.' };
  return { success: true };
}

async function removePeer(iface, publicKey) {
  if (!isWgKey(publicKey)) return { success: false, error: 'Not a valid WireGuard public key.' };
  const r = await runWg(['set', iface, 'peer', publicKey, 'remove'], 15000);
  if (r.notFound) return { success: false, error: notInstalledMsg() };
  if (r.timedOut) return { success: false, error: 'WireGuard did not answer in time.' };
  if (r.code !== 0) return { success: false, error: (r.stderr || '').trim() || 'Could not remove the peer.' };
  return { success: true };
}

/* ---------- address allocation ---------- */
/* The /24 tunnel subnet for a server address: '10.8.0.1' (or
   '10.8.0.1/24') -> '10.8.0.0/24'. The tunnel is always a /24 and
   the server holds one address in it. Garbage falls back to the
   default TUNNEL_SUBNET. */
function tunnelSubnetFor(address) {
  const ip = tunnelIpOf(address);
  if (!ip || !isValidIpv4(ip)) return TUNNEL_SUBNET;
  return ip.split('.').slice(0, 3).join('.') + '.0/24';
}

/* The tunnel address the server holds in a /24 tunnel subnet:
   '10.0.0.0/24' -> '10.0.0.1'. The app's convention (see
   nextTunnelIp: peers start at .2 because .1 is the server). A
   client gateway uses this to find its server's tunnel address. */
function serverTunnelIpFor(subnet) {
  const m = String(subnet || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/);
  return m ? m[1] + '.' + m[2] + '.' + m[3] + '.1' : null;
}

/* Strict IPv4: four decimal octets, no leading zeros (octal
   ambiguity), each 0-255 — and not the all-zeros or all-ones
   address, neither of which can be a tunnel address. */
function isValidIpv4(s) {
  const m = String(s || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    if (m[i].length > 1 && m[i][0] === '0') return false;
    const n = parseInt(m[i], 10);
    if (n < 0 || n > 255) return false;
  }
  if (m[1] === '0' && m[2] === '0' && m[3] === '0' && m[4] === '0') return false;
  if (m[1] === '255' && m[2] === '255' && m[3] === '255' && m[4] === '255') return false;
  return true;
}

/* The endpoint clients connect to: host + ':' + port, or '' when no
   host is saved yet. One place so a listen-port change flows to
   every consumer (manual add, Cloud-join approval) the same way. */
function serverEndpoint(host, listenPort) {
  const h = String(host || '').trim();
  if (!h) return '';
  return h + ':' + listenPort;
}

/* A hostname or IPv4 address for the endpoint / server export:
   letters, digits, dots and dashes only, at most 253 chars. */
function isValidEndpointHost(host) {
  const h = String(host || '').trim();
  return h.length > 0 && h.length <= 253 && /^[A-Za-z0-9.-]+$/.test(h);
}

/* A full peer endpoint, host:port — the host is a real IP or DDNS
   hostname (same rule as isValidEndpointHost) and the port is
   1–65535. One validator for the manual add-peer form, the live
   `wg set` call and the server config writer. */
function isValidEndpoint(endpoint) {
  const e = String(endpoint || '').trim();
  const m = e.match(/^([A-Za-z0-9.-]+):(\d{1,5})$/);
  if (!m) return false;
  const port = Number(m[2]);
  return isValidEndpointHost(m[1]) && Number.isInteger(port) && port >= 1 && port <= 65535;
}

/* Server export (the server card's Export button): the whole server
   identity a fresh install needs, and nothing it must not carry.
   { endpoint (public IP or DNS), port, tunnelAddress } — the server
   PUBLIC KEY is deliberately NOT exported: it is regenerated when
   the program is reinstalled, so an exported key would be stale
   and misleading. The private key is never exported either. */
function buildServerExport(server) {
  const s = server || {};
  return {
    version: 1,
    kind: 'techvision-server',
    endpoint: String(s.endpoint || '').trim(),
    port: Number.isInteger(s.listenPort) ? s.listenPort : parseInt(s.listenPort, 10) || 51820,
    tunnelAddress: String(s.address || '').trim(),
  };
}

/* Validate an imported server file. Returns { ok, endpoint, port,
   tunnelAddress } or { ok: false, error }. The tunnel address and
   port still go through validateServerSettings (so a move to
   another /24 while peers exist is refused, exactly as in the UI);
   the endpoint host is checked with isValidEndpointHost. A missing
   `kind` is accepted (an old hand-written file); a wrong kind is
   refused. */
function validateServerImport(data, current) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { ok: false, error: 'That file is not a TechVision server export.' };
  }
  if (data.kind !== undefined && data.kind !== 'techvision-server') {
    return { ok: false, error: 'That file is not a TechVision server export (kind: ' + String(data.kind) + ').' };
  }
  const endpoint = String(data.endpoint == null ? '' : data.endpoint).trim();
  if (endpoint && !isValidEndpointHost(endpoint)) {
    return { ok: false, error: 'Endpoint "' + endpoint + '" is not a valid hostname or IP address.' };
  }
  const v = validateServerSettings(current || {}, { address: data.tunnelAddress, listenPort: data.port });
  if (!v.ok) return { ok: false, error: v.error };
  return { ok: true, endpoint, port: v.listenPort, tunnelAddress: v.address };
}

/* Validates a server-settings change (the UI's editable tunnel
   address + listen port). current: {address, listenPort, peerCount};
   input: {address, listenPort} (strings or numbers). Returns
   {ok:true, address, listenPort} with the address bare (no /24)
   and the port a number, or {ok:false, error}. A move to a
   different /24 while peers exist is refused — the peers hold
   tunnel addresses in the old subnet and their configs would
   break; remove them first, or stay in the current subnet. */
function validateServerSettings(current, input) {
  const cur = current || {};
  const inp = input || {};
  const rawAddress = String(inp.address == null ? '' : inp.address).trim();
  if (!isValidIpv4(rawAddress)) return { ok: false, error: 'Tunnel address must be a valid IPv4 address, e.g. 10.0.0.1.' };
  const rawPort = inp.listenPort;
  let portNum;
  if (typeof rawPort === 'number') portNum = rawPort;
  else if (typeof rawPort === 'string' && /^\d+$/.test(rawPort.trim())) portNum = parseInt(rawPort.trim(), 10);
  else return { ok: false, error: 'Port must be a whole number between 1 and 65535.' };
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return { ok: false, error: 'Port must be a whole number between 1 and 65535.' };
  const curSubnet = tunnelSubnetFor(cur.address);
  const newSubnet = tunnelSubnetFor(rawAddress);
  const peerCount = cur.peerCount || 0;
  if (peerCount > 0 && curSubnet !== newSubnet) {
    return { ok: false, error: 'That address is in a different subnet (' + newSubnet + ') than the current one (' + curSubnet + '). The ' + peerCount + ' device(s) already added hold tunnel addresses in ' + curSubnet + ' — remove them first, or pick an address in ' + curSubnet + '.' };
  }
  return { ok: true, address: rawAddress, listenPort: portNum };
}

/* Next free x.x.x.x for a new peer, starting at .2 (.1 is the
   server). Returns null when the /24 is full — 253 peers is the
   practical cap of one server tunnel. The subnet defaults to
   TUNNEL_SUBNET; callers with a moved server address pass the
   effective subnet from tunnelSubnetFor(). */
function nextTunnelIp(usedIps, subnet) {
  const m = String(subnet || TUNNEL_SUBNET).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/);
  const prefix = m ? m[1] + '.' + m[2] + '.' + m[3] + '.' : '10.0.0.';
  const used = new Set();
  for (const ip of usedIps || []) {
    const s = String(ip || '');
    if (s.indexOf(prefix) === 0) {
      const rest = s.slice(prefix.length);
      if (/^\d{1,3}$/.test(rest)) used.add(parseInt(rest, 10));
    }
  }
  for (let n = 2; n <= 254; n++) {
    if (!used.has(n)) return prefix + n;
  }
  return null;
}

/* ---------- obfuscation parameters (AmneziaWG) ---------- */
/* Ranges from the AmneziaWG docs (GL.iNet obfuscation reference +
   amneziawg-tools): Jc 1–128; 0 <= Jmin < Jmax < 1280 (Jmax must stay
   below the MTU — 1420 here — so the <1280 cap already satisfies it);
   S1 0–1132, S2 0–1188 with S1+56 != S2, S3 0–1216, S4 0–32;
   H1–H4 are ranges of u32 values 5–2147483647, pairwise disjoint,
   never containing 1–4 (WireGuard's fixed message types).
   Generation uses narrower, typical values (installer-doc ranges:
   Jc 4–12, Jmin 40–89, Jmax Jmin+50..Jmin+250, S1/S2 15–150,
   S3 8–55, S4 4–27); validation accepts the full documented range.
   H ranges are generated in four disjoint bands (1M, 2M, 3M, 4M)
   so they can never overlap however the random draw lands. */
const OBF_RANGES = {
  jc: { min: 1, max: 128 },
  jmin: { min: 0, max: 1279 },
  jmax: { min: 1, max: 1279 },
  s1: { min: 0, max: 1132 },
  s2: { min: 0, max: 1188 },
  s3: { min: 0, max: 1216 },
  s4: { min: 0, max: 32 },
  h: { min: 5, max: 2147483647 },
};
const OBF_KEYS = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4'];

function randInt(lo, hi) { return crypto.randomInt(lo, hi + 1); }

/* Generate the obfuscation set ONCE. The caller stores the result in
   wireguard.json under `obfuscation` and reuses it on every later
   start — regenerating silently would break every existing peer,
   because S1–S4/H1–H4 must match on both ends. H values are "lo-hi"
   range strings, as AmneziaWG 2.0+ accepts. */
function generateObfuscationParams() {
  const jc = randInt(4, 12);
  const jmin = randInt(40, 89);
  const jmax = jmin + randInt(50, 250);
  const s1 = randInt(15, 150);
  let s2 = randInt(15, 150);
  while (s2 === s1 + 56) s2 = randInt(15, 150);
  const s3 = randInt(8, 55);
  const s4 = randInt(4, 27);
  const h = {};
  for (let i = 0; i < 4; i++) {
    const base = (i + 1) * 1000000;
    const lo = base + randInt(0, 900000);
    const hi = lo + randInt(50, 999);
    h['h' + (i + 1)] = lo + '-' + hi;
  }
  return { Jc: jc, Jmin: jmin, Jmax: jmax, S1: s1, S2: s2, S3: s3, S4: s4, H1: h.h1, H2: h.h2, H3: h.h3, H4: h.h4 };
}

/* Parse one H value: a single integer, or a "lo-hi" range string.
   Returns { lo, hi } or null when malformed. */
function parseHRange(v) {
  if (typeof v === 'number' && Number.isInteger(v)) return { lo: v, hi: v };
  if (typeof v === 'string') {
    const m = v.trim().match(/^(\d+)\s*-\s*(\d+)$/);
    if (m) return { lo: parseInt(m[1], 10), hi: parseInt(m[2], 10) };
    if (/^\d+$/.test(v.trim())) { const n = parseInt(v.trim(), 10); return { lo: n, hi: n }; }
  }
  return null;
}

function isIntIn(v, lo, hi) { return Number.isInteger(v) && v >= lo && v <= hi; }

/* Validate a stored or pasted obfuscation set. Accepts the
   capitalised keys this module writes (Jc/Jmin/…) and the lowercased
   keys parseConf keeps in `extra`. Returns { ok, errors } — never
   throws, so a bad stored block can be reported instead of crashing
   the server start. */
function validateObfuscationParams(p) {
  const errors = [];
  if (!p || typeof p !== 'object') return { ok: false, errors: ['No obfuscation parameters.'] };
  const get = (k) => (p[k] !== undefined ? p[k] : p[k.toLowerCase()]);
  const jc = get('Jc');
  if (!isIntIn(jc, OBF_RANGES.jc.min, OBF_RANGES.jc.max)) errors.push('Jc must be an integer ' + OBF_RANGES.jc.min + '–' + OBF_RANGES.jc.max + '.');
  const jmin = get('Jmin');
  if (!isIntIn(jmin, OBF_RANGES.jmin.min, OBF_RANGES.jmin.max)) errors.push('Jmin must be an integer ' + OBF_RANGES.jmin.min + '–' + OBF_RANGES.jmin.max + '.');
  const jmax = get('Jmax');
  if (!isIntIn(jmax, OBF_RANGES.jmax.min, OBF_RANGES.jmax.max)) errors.push('Jmax must be an integer ' + OBF_RANGES.jmax.min + '–' + OBF_RANGES.jmax.max + '.');
  if (isIntIn(jmin, 0, 1e9) && isIntIn(jmax, 0, 1e9) && jmin >= jmax) errors.push('Jmin must be smaller than Jmax.');
  if (isIntIn(jmax, 0, 1e9) && jmax >= 1280) errors.push('Jmax must stay below 1280 (and below the MTU).');
  const s1 = get('S1');
  if (!isIntIn(s1, OBF_RANGES.s1.min, OBF_RANGES.s1.max)) errors.push('S1 must be an integer ' + OBF_RANGES.s1.min + '–' + OBF_RANGES.s1.max + '.');
  const s2 = get('S2');
  if (!isIntIn(s2, OBF_RANGES.s2.min, OBF_RANGES.s2.max)) errors.push('S2 must be an integer ' + OBF_RANGES.s2.min + '–' + OBF_RANGES.s2.max + '.');
  if (isIntIn(s1, 0, 1e9) && isIntIn(s2, 0, 1e9) && s2 === s1 + 56) errors.push('S2 must not equal S1 + 56.');
  const s3 = get('S3');
  if (!isIntIn(s3, OBF_RANGES.s3.min, OBF_RANGES.s3.max)) errors.push('S3 must be an integer ' + OBF_RANGES.s3.min + '–' + OBF_RANGES.s3.max + '.');
  const s4 = get('S4');
  if (!isIntIn(s4, OBF_RANGES.s4.min, OBF_RANGES.s4.max)) errors.push('S4 must be an integer ' + OBF_RANGES.s4.min + '–' + OBF_RANGES.s4.max + '.');
  const hs = [];
  for (let i = 1; i <= 4; i++) {
    const raw = get('H' + i);
    const r = parseHRange(raw);
    if (!r) { errors.push('H' + i + ' must be an integer or a "lo-hi" range.'); continue; }
    if (r.lo < OBF_RANGES.h.min || r.hi > OBF_RANGES.h.max || r.lo > r.hi) errors.push('H' + i + ' must lie inside ' + OBF_RANGES.h.min + '–' + OBF_RANGES.h.max + ' with lo <= hi.');
    hs.push({ i, lo: r.lo, hi: r.hi });
  }
  for (let a = 0; a < hs.length; a++) {
    for (let b = a + 1; b < hs.length; b++) {
      if (hs[a].lo <= hs[b].hi && hs[b].lo <= hs[a].hi) errors.push('H' + hs[a].i + ' and H' + hs[b].i + ' overlap — the four header ranges must be disjoint.');
    }
  }
  return { ok: errors.length === 0, errors };
}

/* A validated set as the [Interface] lines buildServerConf /
   buildClientConf take as extraInterfaceLines — the same lines on
   server and client, so both ends always agree. Throws on an invalid
   set instead of writing a .conf that silently fails to connect. */
function obfuscationParamsToLines(p) {
  const v = validateObfuscationParams(p);
  if (!v.ok) throw new Error('Invalid obfuscation parameters: ' + v.errors.join(' '));
  const get = (k) => (p[k] !== undefined ? p[k] : p[k.toLowerCase()]);
  const lines = [];
  for (const k of ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4']) lines.push(k + ' = ' + String(get(k)).trim());
  return lines;
}

/* Read the obfuscation set back out of a parsed .conf's `extra`
   (lowercased keys, as parseConf keeps them). Returns the set with
   capitalised keys, or null when the config carries no obfuscation
   fields at all (a stock WireGuard config). A partial set is
   returned as-is — validateObfuscationParams() is the judge of it. */
function obfuscationParamsFromExtra(extra) {
  if (!extra || typeof extra !== 'object') return null;
  const found = {};
  let any = false;
  for (const k of OBF_KEYS) {
    if (extra[k] !== undefined) {
      any = true;
      const cap = k === 'jc' ? 'Jc' : k === 'jmin' ? 'Jmin' : k === 'jmax' ? 'Jmax' : k.toUpperCase();
      const raw = String(extra[k]).trim();
      found[cap] = (k === 'h1' || k === 'h2' || k === 'h3' || k === 'h4' || !/^-?\d+$/.test(raw)) ? raw : parseInt(raw, 10);
    }
  }
  return any ? found : null;
}

/* ---------- AmneziaWG install (Windows only, one click) ---------- */
/* The download URL must be exactly the official GitHub release asset:
   https://github.com/amnezia-vpn/amneziawg-windows-client/releases/
   download/<version>/amneziawg-amd64-<version>.msi — nothing else is
   ever fetched, so a tampered or mistyped URL cannot redirect the
   install at an attacker's file. */
function validateAmneziaInstallerUrl(url) {
  if (typeof url !== 'string') return { ok: false, error: 'Download URL must be a string.' };
  let u;
  try { u = new URL(url); } catch (e) { return { ok: false, error: 'Download URL is not a valid URL.' }; }
  if (u.protocol !== 'https:') return { ok: false, error: 'Download URL must use HTTPS.' };
  if (u.hostname !== 'github.com') return { ok: false, error: 'Download URL must come from github.com.' };
  const m = u.pathname.match(/^\/amnezia-vpn\/amneziawg-windows-client\/releases\/download\/([0-9]+\.[0-9]+\.[0-9]+)\/(amneziawg-amd64-[0-9]+\.[0-9]+\.[0-9]+\.msi)$/);
  if (!m) return { ok: false, error: 'Download URL is not an official AmneziaWG Windows client release asset.' };
  if (m[1] !== m[2].replace(/^amneziawg-amd64-/, '').replace(/\.msi$/, '')) return { ok: false, error: 'Download URL version and file name do not match.' };
  return { ok: true, version: m[1], fileName: m[2] };
}

/* Download the official MSI with progress, mirroring the Tailscale
   download in vpn.js: up to 5 redirects, never downgrading HTTPS to
   HTTP, a 100 MB cap, and an explicit error when the connection ends
   short — a truncated MSI would otherwise fail the signature check
   with no explanation. Returns { bytes, total, path }. */
function downloadAmneziaInstaller(destDir, onProgress) {
  return new Promise((resolve, reject) => {
    const v = validateAmneziaInstallerUrl(AMNEZIAWG_DOWNLOAD_URL);
    if (!v.ok) return reject(new Error(v.error));
    if (!destDir || typeof destDir !== 'string') return reject(new Error('No destination folder for the installer.'));
    try { fs.mkdirSync(destDir, { recursive: true }); } catch (e) { return reject(new Error('Could not create the installer folder.')); }
    const dest = path.join(destDir, v.fileName);
    const get = (u, hops) => {
      if (hops > 5) return reject(new Error('Too many redirects while downloading AmneziaWG.'));
      const lib = u.startsWith('https:') ? https : http;
      const req = lib.get(u, { headers: { 'User-Agent': 'TechVision-Backup/1.0' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const next = new URL(res.headers.location, u).toString();
          if (!next.startsWith('https:')) { res.resume(); return reject(new Error('Download redirected to an insecure address.')); }
          res.resume();
          return get(next, hops + 1);
        }
        if (res.statusCode !== 200) { res.resume(); return reject(new Error('Download failed (HTTP ' + res.statusCode + ').')); }
        const total = parseInt(res.headers['content-length'], 10) || 0;
        let done = 0;
        const out = fs.createWriteStream(dest);
        res.on('data', (chunk) => {
          done += chunk.length;
          if (done > AMNEZIAWG_MAX_DOWNLOAD_BYTES) { req.destroy(); out.destroy(); return reject(new Error('Download is larger than expected.')); }
          if (onProgress) { try { onProgress(done, total); } catch (e) {} }
        });
        res.on('error', (e) => {
          out.destroy();
          if (total > 0 && done < total) return reject(new Error('Download incomplete (' + done + ' of ' + total + ' bytes).'));
          reject(e);
        });
        out.on('error', reject);
        out.on('finish', () => {
          if (total > 0 && done !== total) return reject(new Error('Download incomplete (' + done + ' of ' + total + ' bytes).'));
          resolve({ bytes: done, total, path: dest });
        });
        res.pipe(out);
      });
      req.on('error', reject);
      req.setTimeout(120000, () => { req.destroy(new Error('Download timed out.')); });
    };
    get(AMNEZIAWG_DOWNLOAD_URL, 0);
  });
}

/* Parses the JSON from Get-AuthenticodeSignature. Windows PowerShell
   5.1 renders enums as NUMBERS (Valid = 0), PowerShell 7 as names —
   accept both (same lesson as vpn.js parseSignatureResult). Valid
   only when the status is Valid AND the signer is the Amnezia
   project's publisher. VERIFIED 2026-11-24 against the real 3.1.0
   MSI (amneziawg-amd64-3.1.0.msi, 3,641,344 bytes): the signer is
   NOT "Amnezia" — it is "Privacy Technologies OU" (CN=Privacy
   Technologies OU, O=Privacy Technologies OU, S=Harjumaa, C=EE,
   issued by Sectigo Public Code Signing CA R36, cert valid
   2023-08-31 → 2026-08-30, timestamped so Windows still reports
   Valid). The earlier /Amnezia/i-only check rejected this real
   installer with "(signature status: Valid)" — a valid signature
   from the real publisher. Accept both names; when the status is
   Valid but the signer matches neither, the detail names the
   signer so the failure is diagnosable from the toast alone. */
function parseAmneziaSignatureResult(stdout) {
  try {
    const j = JSON.parse(stdout);
    const o = (j && typeof j === 'object' && !Array.isArray(j)) ? j : {};
    const st = o.Status;
    const statusName = typeof st === 'number' ? (st === 0 ? 'Valid' : 'Status(' + st + ')') : (st || 'unknown');
    const subject = typeof o.Subject === 'string' ? o.Subject : null;
    const valid = (st === 'Valid' || st === 0) && !!subject && (/Amnezia/i.test(subject) || /Privacy Technologies/i.test(subject));
    const detail = (!valid && (st === 'Valid' || st === 0) && subject) ? ('signer is not Amnezia: ' + subject) : undefined;
    return { ok: valid, status: statusName, subject, detail };
  } catch (e) {
    return { ok: false, status: 'check-failed', detail: 'could not read the signature result' };
  }
}

/* Verifies the installer's Authenticode signature. Resolves
   { ok, status, subject?, detail? }. Windows only; anywhere else, or
   on any check failure, ok is false. Nothing is run before this
   passes — the caller deletes the file on failure. */
function verifyInstallerSignature(file) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ ok: false, status: 'unsupported-platform' });
    if (!file || typeof file !== 'string' || !fs.existsSync(file)) return resolve({ ok: false, status: 'not-found', detail: 'installer file not found' });
    const ps = "(Get-AuthenticodeSignature -FilePath '" + file.replace(/'/g, "''") + "' | Select-Object @{N='Status';E={$_.Status.ToString()}}, @{N='Subject';E={$_.SignerCertificate.Subject}} | ConvertTo-Json -Compress)";
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { timeout: 30000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve({ ok: false, status: 'check-failed', detail: (err.message || 'PowerShell check failed').slice(0, 120) });
      resolve(parseAmneziaSignatureResult(stdout));
    });
  });
}

/* The PowerShell that runs the MSI install elevated — extracted so it
   is testable, mirroring vpn.js buildInstallScript: $p.WaitForExit(),
   not Start-Process -Wait (which returns early with -Verb RunAs).
   DO_NOT_LAUNCH=1 is the AmneziaWG MSI property that suppresses
   launching the UI after install (the Tailscale equivalent is
   TS_NOLAUNCH=true); TechVision is the UI here. One UAC prompt. */
function buildAmneziaInstallScript(msiPath) {
  if (!msiPath || typeof msiPath !== 'string') throw new Error('No installer path.');
  return [
    '$ErrorActionPreference = "Stop"',
    'try {',
    '  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList \'/i\', \'' + msiPath.replace(/'/g, "''") + '\', \'/qn\', \'/norestart\', \'DO_NOT_LAUNCH=1\' -Verb RunAs -PassThru',
    '  $p.WaitForExit()',
    '  exit $p.ExitCode',
    '} catch {',
    '  exit 2',
    '}',
  ].join('\r\n');
}

/* Silent per-machine MSI install, elevated once via UAC. Returns
   { success, declined?, error? }. Windows only. */
function installAmnezia(msiPath) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ success: false, error: 'Automatic install is available on Windows only.' });
    if (!msiPath || typeof msiPath !== 'string' || !fs.existsSync(msiPath)) return resolve({ success: false, error: 'Installer file not found.' });
    const scriptPath = path.join(os.tmpdir(), 'techvision-install-amneziawg.ps1');
    try { fs.writeFileSync(scriptPath, buildAmneziaInstallScript(msiPath), 'utf8'); } catch (e) { return resolve({ success: false, error: 'Could not write the install script.' }); }
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath], { timeout: 600000, windowsHide: true }, (err) => {
      try { fs.unlinkSync(scriptPath); } catch (e) {}
      if (err) {
        if (err.code === 2) return resolve({ success: false, declined: true, error: 'Installation was cancelled (administrator permission was not granted).' });
        return resolve({ success: false, error: 'AmneziaWG installation failed (code ' + err.code + ').' });
      }
      resolve({ success: true });
    });
  });
}

/* Full one-click flow: download -> verify signature -> install.
   progress({ phase, pct, text }) reports downloading / verifying /
   installing. On signature failure the downloaded file is DELETED
   and a clear error is returned — nothing unverified is ever run or
   left on disk. The MSI is deleted after a successful install too.
   Returns { success, error?, declined? }. */
async function downloadAndInstallAmnezia(progress) {
  const emit = (phase, pct, text) => { if (progress) { try { progress({ phase, pct, text }); } catch (e) {} } };
  if (process.platform !== 'win32') {
    return { success: false, error: 'Automatic install is available on Windows only. Install AmneziaWG from github.com/amnezia-vpn/amneziawg-windows-client/releases, then try again.' };
  }
  const dir = path.join(os.tmpdir(), 'TechVision');
  let dl;
  emit('downloading', 0, 'Downloading AmneziaWG…');
  try {
    dl = await downloadAmneziaInstaller(dir, (done, total) => {
      emit('downloading', total > 0 ? Math.round((done / total) * 100) : 0, 'Downloading AmneziaWG…');
    });
  } catch (e) {
    return { success: false, error: 'Could not download AmneziaWG: ' + e.message };
  }
  emit('verifying', 0, 'Verifying the installer…');
  const v = await verifyInstallerSignature(dl.path);
  if (!v.ok) {
    try { fs.unlinkSync(dl.path); } catch (e) {}
    const why = v.detail ? ' (' + v.detail + ')' : (v.status && v.status !== 'unsupported-platform' ? ' (signature status: ' + v.status + ')' : '');
    return { success: false, error: 'The downloaded installer could not be verified' + why + '. Install AmneziaWG manually from github.com/amnezia-vpn/amneziawg-windows-client/releases.' };
  }
  emit('installing', 0, 'Installing AmneziaWG — Windows will ask for administrator permission once.');
  const ins = await installAmnezia(dl.path);
  try { fs.unlinkSync(dl.path); } catch (e) {}
  if (!ins.success) return { success: false, error: ins.error || 'AmneziaWG installation failed.', declined: !!ins.declined };
  return { success: true };
}

module.exports = {
  getStatus, genkey, pubkey, genkeypair, isWgKey,
  buildServerConf, buildClientConf, parseConf,
  parseWgShowDump, parseWgShowInterfaces,
  installTunnelService, uninstallTunnelService,
  setPeer, removePeer, nextTunnelIp, tunnelIpOf,
  isValidIpv4, tunnelSubnetFor, serverTunnelIpFor, validateServerSettings, serverEndpoint,
  isValidEndpointHost, isValidEndpoint, buildServerExport, validateServerImport,
  buildElevatedScript, resolveWg, resolveWireguard,
  resolveAmneziaWg, resolveAmneziaWireguard,
  setTransport, getTransport, setTransportBinaries, getTransportBinaries,
  generateObfuscationParams, validateObfuscationParams,
  obfuscationParamsToLines, obfuscationParamsFromExtra, parseHRange,
  validateAmneziaInstallerUrl, downloadAmneziaInstaller,
  parseAmneziaSignatureResult, verifyInstallerSignature,
  buildAmneziaInstallScript, installAmnezia, downloadAndInstallAmnezia,
  AMNEZIAWG_VERSION, AMNEZIAWG_MSI_NAME, AMNEZIAWG_DOWNLOAD_URL,
  AMNEZIAWG_RELEASES_URL,
  WIN_AMNEZIAWG, WIN_AWG,
  WG_DOWNLOAD_URL, SERVER_TUNNEL, CLIENT_TUNNEL,
  SERVER_ADDRESS, TUNNEL_SUBNET, LISTEN_PORT, DEFAULT_KEEPALIVE,
};
