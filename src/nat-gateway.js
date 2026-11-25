'use strict';
/*
 * TechVision WireGuard VPN — gateway NAT service (main process).
 *
 * One TechVision PC per site is the GATEWAY: it sees its whole LAN,
 * the two gateways are linked by the (AmneziaWG) tunnel, and ANY
 * device on either LAN reaches ANY device on the other LAN through
 * its own gateway — no TechVision install on printers, cameras or
 * other PCs. This file is the Node side of that service; the packet
 * work itself lives in the small native helper src/nat/tvnat.exe
 * (WinDivert 2.2.2, official signed binaries bundled unmodified in
 * src/nat/vendor/), which this file spawns and supervises.
 *
 * Two site pairs, two very different jobs:
 *   - DIFFERENT subnets (e.g. 192.168.16.0/24 <-> 192.168.1.0/24):
 *     no address translation is needed — the remote subnet is real
 *     and routable. The service only enables IP forwarding on the
 *     gateway (and the UI tells the user the one static-route line
 *     per router: remote subnet via this gateway PC). NO helper
 *     process runs in this mode: plain forwarding through the
 *     tunnel is done by Windows + WireGuard's AllowedIPs.
 *   - SAME subnet (both LANs 192.168.1.0/24, colliding .3/.4/.5):
 *     the remote devices are addressed by VIRTUAL addresses in a
 *     SEPARATE virtual subnet (e.g. remote 192.168.1.49 appears as
 *     192.168.2.3 — the user picks the alias freely). The app adds
 *     a persistent Windows route for the virtual subnet
 *     (route add -p 192.168.2.0/24 via this gateway PC) when the
 *     service starts and removes it on stop, so local PCs send
 *     virtual-subnet traffic to the gateway instead of the router;
 *     the gateway never answers ARP for a virtual address (a PC
 *     never ARPs for an address outside its own subnet). The
 *     service (a) enables IP forwarding, and (b) runs tvnat.exe,
 *     which diverts only the virtual-subnet traffic with WinDivert
 *     and rewrites it per the mapping table (see tvnat_core.h for
 *     the packet model: LAN origSrc -> virtDst becomes tunnel
 *     gwTunnel -> realDst, and replies come back the same way).
 *     farVirtIp is the one address that still lives on the LAN:
 *     the address the REMOTE gateway is known by on this LAN
 *     (remote devices reply to it), added as a secondary IP so
 *     this gateway answers ARP for it.
 *     (Earlier design: virtual addresses inside the LAN subnet,
 *     e.g. .203/.204/.205 with proxy ARP. Superseded 2026-11-24
 *     by the user's separate-virtual-subnet model + auto-route.)
 *
 * Helper protocol (stdin/stdout, one JSON object per line):
 *   Node -> helper:  {"type":"config", ...}   (exactly one line,
 *     written right after spawn; see buildHelperConfig())
 *   helper -> Node:  {"type":"ready", "filter":"...", "mappings":N}
 *   helper -> Node:  {"type":"log", "level":"info"|"error", "msg":"..."}
 *   helper -> Node:  {"type":"stats", "packets":N, "translated":N,
 *                      "passed":N, "dropped":N}   (every ~5 s)
 *   helper -> Node:  {"type":"error", "msg":"..."} (fatal, exits)
 *   Node -> helper:  {"type":"stop"}  — or close stdin (EOF); the
 *     helper then closes its WinDivert handle and exits 0.
 * The helper never runs on Linux: start() on a non-Windows platform
 * validates the config and then fails cleanly with "Windows only"
 * instead of pretending. Everything driver- or network-related is
 * Windows-only; everything in this file that CAN be tested without
 * Windows (mapping table, validation, filter/config building, the
 * protocol framing, start/stop orchestration with injected deps)
 * is covered by src/nat/test/test-nat.js.
 *
 * Elevation: adding a secondary IP and enabling forwarding need
 * admin. They run through the same elevated-PowerShell pattern as
 * wireguard.js (Start-Process -Verb RunAs, one UAC prompt, the
 * script waits for exit). The WinDivert driver itself installs
 * silently on demand the first time tvnat.exe opens its handle
 * (official signed WinDivert64.sys, admin once); this file invents
 * no driver-install flow of its own.
 *
 * Storage: the config lives in wireguard.json under `nat`
 * (main.js), alongside the keys — it holds IPs and names only, no
 * secrets. Private keys are NOT involved here.
 *
 * Dependency-free: Node builtins only, so no new npm package.
 */
const { spawn, execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_MAPPINGS = 256; /* must match TVNAT_MAX_MAPPINGS in tvnat_core.h */
const HELPER_TIMEOUT_MS = 15000;
const STOP_TIMEOUT_MS = 5000;

/* ------------------------------------------------------------------ */
/* IP helpers (dotted-quad strings; no dependency on tvnat_core)      */
/* ------------------------------------------------------------------ */

/* Strict IPv4: four decimal octets, no leading zeros (except "0"
 * itself — "01" would be octal in some parsers), no trailing junk,
 * no 0.0.0.0, no 255.255.255.255. Returns the dotted string or null. */
function isValidIp(s) {
  if (typeof s !== 'string') return false;
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const part = m[i];
    if (part.length > 1 && part[0] === '0') return false;
    const n = parseInt(part, 10);
    if (n > 255) return false;
  }
  if (s === '0.0.0.0' || s === '255.255.255.255') return false;
  return true;
}

function ipToInt(s) {
  const p = String(s).split('.').map((x) => parseInt(x, 10));
  return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}

function intToIp(n) {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

function subnetMask(prefix) {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xffffffff;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

/* "192.168.1.0/24" -> { network: "192.168.1.0", prefix: 24 } or null.
 * The network part need not be the masked address — it is masked
 * here, so "192.168.1.5/24" parses to network 192.168.1.0. */
function parseCidr(s) {
  if (typeof s !== 'string') return null;
  const m = s.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (!m) return null;
  if (!isValidIp(m[1]) && m[1] !== '0.0.0.0') return null;
  const prefix = parseInt(m[2], 10);
  if (prefix < 0 || prefix > 32) return null;
  const network = intToIp(ipToInt(m[1]) & subnetMask(prefix));
  return { network, prefix };
}

function inSubnet(ip, cidr) {
  if (!isValidIp(ip) || !cidr) return false;
  const mask = subnetMask(cidr.prefix);
  return (ipToInt(ip) & mask) === (ipToInt(cidr.network) & mask);
}

function isNetworkOrBroadcast(ip, cidr) {
  if (!isValidIp(ip) || !cidr) return false;
  const mask = subnetMask(cidr.prefix);
  /* NOTE: JS bitwise ops return SIGNED int32, while ipToInt returns
   * unsigned — compare unsigned to unsigned (>>> 0), or the network
   * address itself (e.g. 192.168.1.0) never matches. */
  const net = (ipToInt(cidr.network) & mask) >>> 0;
  const bcast = (net | (~mask >>> 0)) >>> 0;
  const v = ipToInt(ip);
  return v === net || v === bcast;
}

function sameSubnet(a, b) {
  if (!a || !b) return false;
  return a.network === b.network && a.prefix === b.prefix;
}

/* Do two CIDRs overlap at all (one contains the other's network)? */
function cidrsOverlap(a, b) {
  if (!a || !b) return false;
  return inSubnet(a.network, b) || inSubnet(b.network, a);
}

/* The /24 a dotted IP sits in: '192.168.2.3' -> '192.168.2.0/24'. */
function cidr24Of(ip) {
  if (!isValidIp(ip)) return null;
  const p = String(ip).split('.');
  return p[0] + '.' + p[1] + '.' + p[2] + '.0/24';
}

/* The virtual subnet for a mapping table (same-subnet mode): the
 * /24 every virtual address shares, e.g. '192.168.2.0/24' for
 * aliases 192.168.2.3/192.168.2.4. Returns null when there are no
 * mappings or no valid virtual address to derive it from. */
function virtualSubnetFromMappings(mappings) {
  if (!Array.isArray(mappings) || mappings.length === 0) return null;
  let subnet = null;
  for (const m of mappings) {
    if (!m || !isValidIp(m.virt)) continue;
    const s = cidr24Of(m.virt);
    if (subnet === null) subnet = s;
    /* The aliases must all share one /24 — a mixed table has no
       single virtual subnet, so there is nothing to derive. */
    else if (s !== subnet) return null;
  }
  return subnet;
}

/* Count the 1 bits in a dotted netmask: '255.255.255.0' -> 24.
   A non-contiguous mask (e.g. 255.0.255.0) is not a mask at all. */
function netmaskToPrefix(mask) {
  if (!isValidIp(mask) && mask !== '0.0.0.0') return null;
  const n = ipToInt(mask) >>> 0;
  /* Contiguous: the host bits are a run of 0s at the bottom, so
     inverting gives a run of 1s — and (x & (x + 1)) is 0 only for
     a run of 1s. */
  const inv = (~n) >>> 0;
  if ((inv & (inv + 1)) !== 0) return null;
  let bits = 0, x = n;
  while (x) { bits += x & 1; x >>>= 1; }
  return bits;
}

/* This gateway PC's LAN address, auto-detected from its interfaces:
 * the first non-internal IPv4 address that is not in one of the
 * excluded CIDRs (the tunnel subnet — the AmneziaWG adapter is an
 * interface too, and it is not a LAN address). Returns
 * { address, subnet, interfaceName } or null. `interfaces` is
 * os.networkInterfaces() (injectable for tests); a missing netmask
 * is treated as /24. */
function detectLanAddress(interfaces, excludeCidrs) {
  const ifs = interfaces || os.networkInterfaces();
  const exclude = (excludeCidrs || []).map(parseCidr).filter(Boolean);
  for (const name of Object.keys(ifs)) {
    for (const addr of ifs[name] || []) {
      if (!addr || addr.family !== 'IPv4' || addr.internal) continue;
      if (!isValidIp(addr.address)) continue;
      if (exclude.some((c) => inSubnet(addr.address, c))) continue;
      const prefix = netmaskToPrefix(addr.netmask) ?? 24;
      const network = intToIp(ipToInt(addr.address) & subnetMask(prefix));
      return { address: addr.address, subnet: network + '/' + prefix, interfaceName: name };
    }
  }
  return null;
}

/* Is this IP assigned to one of this machine's own interfaces?
 * The cheap, synchronous half of "is this address free on the
 * LAN" — the full check (ARP table + ping) is isIpFreeOnLan. */
function isAddressInUseLocally(ip, interfaces) {
  if (!isValidIp(ip)) return true;
  const ifs = interfaces || os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const addr of ifs[name] || []) {
      if (addr && addr.family === 'IPv4' && addr.address === ip) return true;
    }
  }
  return false;
}

/* First free host address in a subnet, preferring .200–.254 on a
 * /24 (far from the DHCP pool and the colliding .3/.4/.5), then
 * .2–.199. On any other prefix the usable hosts from the top down.
 * Skips addresses in `used`, addresses assigned to this machine,
 * and — when an async isFree predicate is given — anything it
 * reports as taken on the LAN. Returns null when the subnet is
 * full (a /30 with two hosts has no spare address at all). At most
 * 512 probes: a probe is a ping on Windows, so an unbounded scan
 * of a big subnet would hang the start. */
async function pickFreeAddress(cidr, used, interfaces, isFree) {
  const c = parseCidr(cidr);
  if (!c) return null;
  const usedSet = new Set(used || []);
  const base = ipToInt(c.network);
  const total = Math.pow(2, 32 - c.prefix);
  const free = typeof isFree === 'function' ? isFree : async () => true;
  const candidates = [];
  if (c.prefix === 24) {
    for (let n = 254; n >= 200; n--) candidates.push(n);
    for (let n = 199; n >= 2; n--) candidates.push(n);
  } else {
    /* Usable hosts are network+1 .. broadcast-1, scanned from the
       top down (offset total-2 .. 1). */
    for (let n = total - 2; n >= 1 && candidates.length < 512; n--) candidates.push(n);
  }
  for (const n of candidates) {
    const ip = intToIp(base + n);
    if (usedSet.has(ip)) continue;
    if (isAddressInUseLocally(ip, interfaces)) continue;
    if (!(await free(ip))) continue;
    return ip;
  }
  return null;
}

/* Is this IP free on this machine's LAN? The synchronous interface
 * check first, then — on Windows only — the ARP table (an entry
 * with a MAC means a device holds it) and one ping (a reply means
 * a device holds it). On other platforms the interface check is
 * the whole verdict (the full probe is Windows-only). `deps` is
 * injectable for tests: { execFile, networkInterfaces, platform }. */
async function isIpFreeOnLan(ip, deps) {
  if (!isValidIp(ip)) return false;
  const d = deps || {};
  const ifs = d.networkInterfaces ? d.networkInterfaces() : os.networkInterfaces();
  if (isAddressInUseLocally(ip, ifs)) return false;
  if ((d.platform || process.platform) !== 'win32') return true;
  const exec = d.execFile || execFile;
  const run = (args) => new Promise((resolve) => {
    try {
      exec('cmd.exe', args, { timeout: 8000, windowsHide: true }, (err, stdout) => resolve({ err, stdout: String(stdout || '') }));
    } catch (e) { resolve({ err: e, stdout: '' }); }
  });
  const arp = await run(['/c', 'arp -a']);
  /* An ARP line for the IP with a real MAC (not "incomplete" and
     not the broadcast ff-ff-ff-ff-ff-ff) means a device holds it. */
  const arpHit = arp.stdout.split(/\r?\n/).some((line) => {
    const m = line.match(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s/);
    return m && m[1] === ip && m[2].toLowerCase() !== 'ff-ff-ff-ff-ff-ff';
  });
  if (arpHit) return false;
  const ping = await run(['/c', 'ping -n 1 -w 400 ' + ip]);
  if (/Reply from/i.test(ping.stdout)) return false;
  return true;
}

/* The persistent Windows route for the virtual subnet (same-subnet
 * mode only): local PCs send virtual-subnet traffic to this gateway
 * instead of the router. Added by the setup script when the NAT
 * service starts, removed by the teardown script when it stops.
 * Returns the full command string, or null when there is no
 * virtual subnet to route (different-subnet mode, or no mappings). */
function buildRouteAddCommand(config) {
  if (!config || config.mode !== 'same-subnet') return null;
  const vs = config.virtualSubnet || virtualSubnetFromMappings(config.mappings);
  const v = parseCidr(vs);
  if (!v || v.prefix !== 24 || !isValidIp(config.gatewayLanIp)) return null;
  return 'route add -p ' + v.network + ' mask ' + intToIp(subnetMask(v.prefix)) + ' ' + config.gatewayLanIp;
}
function buildRouteDeleteCommand(config) {
  if (!config || config.mode !== 'same-subnet') return null;
  const vs = config.virtualSubnet || virtualSubnetFromMappings(config.mappings);
  const v = parseCidr(vs);
  if (!v) return null;
  return 'route delete ' + v.network;
}

/* ------------------------------------------------------------------ */
/* Mapping table                                                      */
/* ------------------------------------------------------------------ */

/* One mapping: a remote device's REAL address and the VIRTUAL
 * address it is known by on this LAN. `name` is display-only. */
function validateMapping(m, i) {
  const at = 'Mapping ' + (i + 1);
  if (!m || typeof m !== 'object') return at + ': not an object.';
  if (!isValidIp(m.real)) return at + ': real address "' + String(m.real) + '" is not a valid IPv4 address.';
  if (!isValidIp(m.virt)) return at + ': virtual address "' + String(m.virt) + '" is not a valid IPv4 address.';
  if (m.real === m.virt) return at + ': real and virtual addresses are the same (' + m.real + ').';
  if (m.name !== undefined && typeof m.name !== 'string') return at + ': name must be text.';
  if (typeof m.name === 'string' && /[\r\n]/.test(m.name)) return at + ': name must not contain line breaks.';
  return null;
}

function createMappingTable() {
  return [];
}

/* Add a mapping. Returns { ok: true } or { ok: false, error }.
 * Rejects duplicates by real OR by virtual address — a virtual
 * address may only ever stand for one real device. */
function addMapping(table, real, virt, name) {
  if (!Array.isArray(table)) return { ok: false, error: 'No mapping table.' };
  const err = validateMapping({ real, virt, name }, table.length);
  if (err) return { ok: false, error: err };
  if (table.length >= MAX_MAPPINGS) return { ok: false, error: 'Mapping table is full (' + MAX_MAPPINGS + ' mappings).' };
  if (table.some((m) => m.real === real)) return { ok: false, error: 'Real address ' + real + ' is already mapped.' };
  if (table.some((m) => m.virt === virt)) return { ok: false, error: 'Virtual address ' + virt + ' is already used.' };
  table.push({ real, virt, name: typeof name === 'string' ? name : '' });
  return { ok: true };
}

function removeMapping(table, virt) {
  if (!Array.isArray(table)) return { ok: false, error: 'No mapping table.' };
  const before = table.length;
  for (let i = table.length - 1; i >= 0; i--) {
    if (table[i].virt === virt || table[i].real === virt) table.splice(i, 1);
  }
  if (table.length === before) return { ok: false, error: 'No mapping for ' + virt + '.' };
  return { ok: true };
}

function findByReal(table, real) {
  if (!Array.isArray(table)) return null;
  return table.find((m) => m.real === real) || null;
}

function findByVirt(table, virt) {
  if (!Array.isArray(table)) return null;
  return table.find((m) => m.virt === virt) || null;
}

/* Translate one address through the table: LAN side -> tunnel side
 * (virtual to real) or the reverse. Returns the translated address,
 * or null when the address is not a mapped one. */
function translateAddress(table, ip, direction) {
  if (!isValidIp(ip)) return null;
  const m = direction === 'virt-to-real' ? findByVirt(table, ip)
    : direction === 'real-to-virt' ? findByReal(table, ip) : null;
  if (!m) return null;
  return direction === 'virt-to-real' ? m.real : m.virt;
}

/* ------------------------------------------------------------------ */
/* Config validation                                                  */
/* ------------------------------------------------------------------ */

/*
 * NAT config shape (stored in wireguard.json under `nat`):
 * {
 *   mode: 'same-subnet' | 'different-subnet',
 *   localSubnet:  '192.168.1.0/24',   // this site's LAN
 *   remoteSubnet: '192.168.1.0/24',   // the other site's LAN
 *   gatewayLanIp: '192.168.1.10',     // this gateway PC's LAN address
 *   gatewayTunnelIp: '10.0.0.1',      // this gateway's tunnel address
 *   remoteTunnelIp:  '10.0.0.2',      // the other gateway's tunnel address
 *   farVirtIp: '192.168.1.201',       // same-subnet only: the virtual
 *                                     // address the REMOTE gateway is
 *                                     // known by on THIS lan — i.e.
 *                                     // the address remote devices
 *                                     // reply to (see tvnat_core.h)
 *   interfaceName: 'Ethernet',        // optional; auto-detected when
 *                                     // omitted (the adapter whose
 *                                     // address is in localSubnet)
 *   mappings: [ { real, virt, name } ] // same-subnet only, >= 1;
 *                                     // virt lives in the VIRTUAL
 *                                     // subnet (e.g. 192.168.2.x),
 *                                     // a separate /24 outside both
 *                                     // LANs — see virtualSubnet
 *   virtualSubnet: '192.168.2.0/24', // same-subnet only, derived
 *                                     // from the mappings (the /24
 *                                     // every alias shares); the app
 *                                     // adds a persistent route for
 *                                     // it when the service starts.
 * }
 * validateNatConfig returns { ok, errors, config } — `config` is the
 * normalised copy (trimmed strings, mappings copied), or null.
 * It never throws, so a bad stored block can be reported instead of
 * crashing the start.
 */
/* Virtual addresses that fall inside the tunnel subnet (same-subnet
   mode only): a virtual address must be on the LAN, never inside
   the tunnel. The subnet is passed in — it is the EFFECTIVE tunnel
   subnet, derived from the saved server address, not the hardcoded
   default: a server moved to 10.8.0.1 clashes on 10.8.0.x, not on
   10.0.0.x. Returns the list of clash messages (empty = no clash). */
function tunnelSubnetClashes(cfg, tunnelSubnet) {
  const out = [];
  const tunnelCidr = parseCidr(tunnelSubnet);
  if (!cfg || cfg.mode !== 'same-subnet' || !tunnelCidr) return out;
  if (inSubnet(cfg.farVirtIp, tunnelCidr)) out.push('farVirtIp ' + cfg.farVirtIp + ' is inside the tunnel subnet ' + tunnelSubnet + ' — a virtual address must be on the LAN.');
  (cfg.mappings || []).forEach((m, i) => {
    if (inSubnet(m.virt, tunnelCidr)) out.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' is inside the tunnel subnet ' + tunnelSubnet + ' — a virtual address must be on the LAN.');
  });
  return out;
}

function validateNatConfig(input) {
  const errors = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, errors: ['No NAT configuration.'], config: null };
  }
  const mode = String(input.mode || '').trim();
  if (mode !== 'same-subnet' && mode !== 'different-subnet') {
    errors.push('Mode must be "same-subnet" or "different-subnet".');
  }
  const local = parseCidr(input.localSubnet);
  if (!local) errors.push('Local subnet "' + String(input.localSubnet) + '" is not a valid CIDR (e.g. 192.168.1.0/24).');
  const remote = parseCidr(input.remoteSubnet);
  if (!remote) errors.push('Remote subnet "' + String(input.remoteSubnet) + '" is not a valid CIDR (e.g. 192.168.16.0/24).');
  if (local && remote) {
    if (mode === 'same-subnet' && !sameSubnet(local, remote)) {
      errors.push('Same-subnet mode needs both sites on the same subnet — local ' + input.localSubnet + ' and remote ' + input.remoteSubnet + ' differ.');
    }
    if (mode === 'different-subnet' && sameSubnet(local, remote)) {
      errors.push('Different-subnet mode needs two different subnets — both are ' + input.localSubnet + '. Use same-subnet mode for that pair.');
    }
    if (mode === 'different-subnet' && cidrsOverlap(local, remote)) {
      errors.push('The two subnets overlap (' + input.localSubnet + ' vs ' + input.remoteSubnet + ') — they must be disjoint for the different-subnet mode.');
    }
  }
  if (!isValidIp(input.gatewayLanIp)) errors.push('Gateway LAN address "' + String(input.gatewayLanIp) + '" is not a valid IPv4 address.');
  else if (local && !inSubnet(input.gatewayLanIp, local)) errors.push('Gateway LAN address ' + input.gatewayLanIp + ' is not in the local subnet ' + input.localSubnet + '.');
  if (!isValidIp(input.gatewayTunnelIp)) errors.push('Gateway tunnel address "' + String(input.gatewayTunnelIp) + '" is not a valid IPv4 address.');
  if (!isValidIp(input.remoteTunnelIp)) errors.push('Remote gateway tunnel address "' + String(input.remoteTunnelIp) + '" is not a valid IPv4 address.');
  if (isValidIp(input.gatewayTunnelIp) && isValidIp(input.remoteTunnelIp) && input.gatewayTunnelIp === input.remoteTunnelIp) {
    errors.push('The two gateways cannot share one tunnel address (' + input.gatewayTunnelIp + ').');
  }
  if (input.interfaceName !== undefined && input.interfaceName !== null && typeof input.interfaceName !== 'string') {
    errors.push('Interface name must be text.');
  }
  if (typeof input.interfaceName === 'string' && input.interfaceName.length > 0 && !input.interfaceName.trim()) {
    errors.push('Interface name must not be empty.');
  }

  const mappings = Array.isArray(input.mappings) ? input.mappings : [];
  if (mode === 'different-subnet' && mappings.length > 0) {
    errors.push('Different-subnet mode needs no mappings — the remote addresses are real and routable, so a mapping table would never be used.');
  }
  /* The remote side of a same-subnet pair (remote: true) carries
     no rows — the rows live on the initiating gateway only, and
     this side's helper only needs farVirtIp + the tunnel IPs for
     the return path (the inbound flow rewrites the source to
     farVirtIp; it never consults the mapping table). Without the
     flag, an empty table is a user error: same-subnet mode needs
     at least one device row to translate. */
  const isRemote = input.remote === true;
  if (mode === 'same-subnet') {
    if (mappings.length === 0 && !isRemote) errors.push('Same-subnet mode needs at least one mapping (a remote device and the virtual address it appears as).');
    if (mappings.length > MAX_MAPPINGS) errors.push('Too many mappings (' + mappings.length + ' — the limit is ' + MAX_MAPPINGS + ').');
    if (!isValidIp(input.farVirtIp)) errors.push('farVirtIp "' + String(input.farVirtIp) + '" is not a valid IPv4 address — same-subnet mode needs the virtual address this gateway is known by on the remote LAN.');
    else if (local && !inSubnet(input.farVirtIp, local)) errors.push('farVirtIp ' + input.farVirtIp + ' is not in the local subnet ' + input.localSubnet + ' — it must be an address on this LAN.');
    else if (local && isNetworkOrBroadcast(input.farVirtIp, local)) errors.push('farVirtIp ' + input.farVirtIp + ' is the network or broadcast address of ' + input.localSubnet + '.');
    else if (isValidIp(input.gatewayLanIp) && input.farVirtIp === input.gatewayLanIp) errors.push('farVirtIp ' + input.farVirtIp + ' is this gateway PC\'s own LAN address.');
    const seenReal = new Set(), seenVirt = new Set();
    /* The virtual subnet is the /24 the first alias sits in — every
       alias must share it, and it must be a separate subnet outside
       this LAN (a PC only routes to the gateway for an address
       outside its own subnet; an alias inside the LAN would be
       ARPed for directly and never reach the gateway). */
    const virtSubnet = virtualSubnetFromMappings(mappings);
    const virtCidr = virtSubnet ? parseCidr(virtSubnet) : null;
    /* A mixed table has no single virtual subnet (the helper above
       returns null for it), so the per-mapping check below cannot
       see the mismatch — call it out directly. */
    const virt24s = new Set();
    mappings.forEach((m) => { if (m && isValidIp(m.virt)) virt24s.add(cidr24Of(m.virt)); });
    if (virt24s.size > 1) errors.push('All virtual addresses must share one virtual subnet — the mappings use ' + Array.from(virt24s).join(', ') + '.');
    mappings.forEach((m, i) => {
      const err = validateMapping(m, i);
      if (err) { errors.push(err); return; }
      if (seenReal.has(m.real)) errors.push('Mapping ' + (i + 1) + ': real address ' + m.real + ' appears twice.');
      if (seenVirt.has(m.virt)) errors.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' appears twice.');
      seenReal.add(m.real); seenVirt.add(m.virt);
      if (remote && !inSubnet(m.real, remote)) errors.push('Mapping ' + (i + 1) + ': real address ' + m.real + ' is not in the remote subnet ' + input.remoteSubnet + '.');
      if (local && inSubnet(m.virt, local)) errors.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' is inside your own network ' + input.localSubnet + ' — virtual addresses live in a separate subnet, e.g. 192.168.2.x, so your PCs route them to the gateway.');
      if (virtCidr && !inSubnet(m.virt, virtCidr)) errors.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' is in ' + cidr24Of(m.virt) + ' but the other mappings use ' + virtSubnet + ' — all virtual addresses must share one subnet.');
      if (virtCidr && isNetworkOrBroadcast(m.virt, virtCidr)) errors.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' is the network or broadcast address of ' + virtSubnet + '.');
      if (isValidIp(input.gatewayLanIp) && m.virt === input.gatewayLanIp) errors.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' is this gateway PC\'s own LAN address — it would steal the gateway\'s own traffic.');
      if (isValidIp(input.farVirtIp) && m.virt === input.farVirtIp) errors.push('Mapping ' + (i + 1) + ': virtual address ' + m.virt + ' collides with farVirtIp — the gateway\'s own virtual address cannot also be a device.');
      if (isValidIp(input.farVirtIp) && m.real === input.farVirtIp) errors.push('Mapping ' + (i + 1) + ': real address ' + m.real + ' is the gateway\'s virtual address (farVirtIp) — a remote device cannot sit at the address the gateway itself answers for.');
      if (isValidIp(input.gatewayTunnelIp) && (m.real === input.gatewayTunnelIp || m.virt === input.gatewayTunnelIp)) errors.push('Mapping ' + (i + 1) + ': address ' + m.real + '/' + m.virt + ' collides with the tunnel address.');
      if (isValidIp(input.remoteTunnelIp) && (m.real === input.remoteTunnelIp || m.virt === input.remoteTunnelIp)) errors.push('Mapping ' + (i + 1) + ': address ' + m.real + '/' + m.virt + ' collides with the remote tunnel address.');
    });
  }
  if (errors.length > 0) return { ok: false, errors, config: null };
  const config = {
    mode,
    localSubnet: local.network + '/' + local.prefix,
    remoteSubnet: remote.network + '/' + remote.prefix,
    gatewayLanIp: String(input.gatewayLanIp),
    gatewayTunnelIp: String(input.gatewayTunnelIp),
    remoteTunnelIp: String(input.remoteTunnelIp),
    farVirtIp: mode === 'same-subnet' ? String(input.farVirtIp) : '',
    interfaceName: typeof input.interfaceName === 'string' && input.interfaceName.trim() ? input.interfaceName.trim() : '',
    mappings: mappings.map((m) => ({ real: m.real, virt: m.virt, name: typeof m.name === 'string' ? m.name : '' })),
    virtualSubnet: mode === 'same-subnet' ? (virtualSubnetFromMappings(mappings) || '') : '',
    remote: isRemote,
  };
  return { ok: true, errors: [], config };
}

/* ------------------------------------------------------------------ */
/* Remote NAT auto-start — the start command over the tunnel          */
/* ------------------------------------------------------------------ */

/* The remote-start command: what the initiating gateway sends to
 * the other gateway over the WireGuard tunnel (see src/wg-control.js
 * for the transport). It carries only what the remote side cannot
 * know by itself: the mode, this gateway's LAN subnet (the remote
 * side's remoteSubnet), and the farVirtIp this gateway proposes as
 * its source identity on the remote LAN. Everything else (the
 * remote side's own LAN IP and subnet, its tunnel IP, its
 * mappings) is auto-detected or empty there — the remote side
 * needs no configuration typed by anyone. */
function buildRemoteStartCommand(local) {
  if (!local || typeof local !== 'object') return null;
  return {
    type: 'nat-start',
    mode: local.mode,
    farVirtIp: local.mode === 'same-subnet' ? String(local.farVirtIpProposal || '') : '',
    localSubnet: String(local.localSubnet || ''),
    initiatorTunnelIp: String(local.gatewayTunnelIp || ''),
    initiatorLanIp: String(local.gatewayLanIp || ''),
  };
}

/* The remote side's NAT config, built from the command plus its own
 * auto-detected values (own: { address, subnet, tunnelIp }). The
 * farVirtIp here is the verified one from the command — the address
 * the initiating gateway is known by on THIS lan, which this
 * gateway answers ARP for and its helper uses as the source
 * identity for replies. Mappings stay empty: the remote side needs
 * no rows for the return path. */
function buildRemoteNatConfig(command, own, farVirtIp) {
  if (!command || typeof command !== 'object' || !own || typeof own !== 'object') return null;
  return {
    mode: command.mode,
    localSubnet: String(own.subnet || ''),
    remoteSubnet: String(command.localSubnet || ''),
    gatewayLanIp: String(own.address || ''),
    gatewayTunnelIp: String(own.tunnelIp || ''),
    remoteTunnelIp: String(command.initiatorTunnelIp || ''),
    farVirtIp: command.mode === 'same-subnet' ? String(farVirtIp || '') : '',
    interfaceName: '',
    mappings: [],
    remote: true,
  };
}

/* Verify the initiator's proposed farVirtIp on the remote LAN: keep
 * it when it is free there (isFree returns true), else pick the
 * first free address in the same subnet and report that the
 * proposal was adjusted. Returns { farVirtIp, adjusted } or null
 * when nothing is free. isFree is an async predicate (ARP table +
 * ping on Windows, a stub in tests). */
async function adjustFarVirtIp(proposed, subnet, isFree) {
  const c = parseCidr(subnet);
  if (!c) return null;
  const free = typeof isFree === 'function' ? isFree : async () => true;
  if (isValidIp(proposed) && inSubnet(proposed, c) && !isNetworkOrBroadcast(proposed, c) && (await free(proposed))) {
    return { farVirtIp: proposed, adjusted: false };
  }
  const picked = await pickFreeAddress(subnet, proposed ? [proposed] : [], undefined, free);
  if (!picked) return null;
  return { farVirtIp: picked, adjusted: true };
}

/* The tunnel peer's AllowedIPs while the NAT service runs. The tunnel
 * service only encrypts packets for addresses in the remote gateway
 * peer's AllowedIPs — without this, a packet the helper translated
 * to a remote real address dies inside the tunnel service, because
 * the peer only has its tunnel /32. Same-subnet: the peer's tunnel
 * /32 plus every mapped real /32. Different-subnet: the peer's tunnel
 * /32 plus the whole remote subnet CIDR (the remote addresses are
 * real and routable there). Returns null for an unusable config. */
function allowedIPsForPeer(config) {
  if (!config || !isValidIp(config.remoteTunnelIp)) return null;
  const out = [config.remoteTunnelIp + '/32'];
  if (config.mode === 'same-subnet') {
    if (!Array.isArray(config.mappings)) return null;
    for (const m of config.mappings) {
      if (!m || !isValidIp(m.real)) return null;
      const ip = m.real + '/32';
      if (out.indexOf(ip) < 0) out.push(ip);
    }
  } else if (config.mode === 'different-subnet') {
    if (!parseCidr(config.remoteSubnet)) return null;
    out.push(config.remoteSubnet);
  } else {
    return null;
  }
  return out.join(', ');
}

/* ------------------------------------------------------------------ */
/* WinDivert filter + helper config                                   */
/* ------------------------------------------------------------------ */

/* The narrow WinDivert filter for the helper: only IPv4 packets that
 * are part of the NAT scheme — addressed TO a virtual address (LAN
 * side, including the far gateway's virtual address), TO this
 * gateway's tunnel address, or FROM the remote gateway's tunnel
 * address (tunnel side). Everything else never reaches the helper
 * at all. The helper's core still decides per packet (translate /
 * pass / drop), so the filter may be a superset — but it must never
 * be wider than the scheme's own addresses. Different-subnet mode
 * has no helper, so its filter is null. */
function buildFilter(config) {
  if (!config || config.mode !== 'same-subnet') return null;
  const dsts = config.mappings.map((m) => m.virt);
  if (config.farVirtIp) dsts.push(config.farVirtIp);
  if (config.gatewayTunnelIp) dsts.push(config.gatewayTunnelIp);
  const parts = dsts.map((ip) => 'ip.DstAddr == ' + ip);
  parts.push('ip.SrcAddr == ' + config.remoteTunnelIp);
  return '(' + parts.join(' or ') + ') and ip';
}

/* The one JSON line written to the helper's stdin. The helper reads
 * exactly this shape (see tvnat.c); keep the two in sync. */
function buildHelperConfig(config) {
  return {
    type: 'config',
    gwTunnelIp: config.gatewayTunnelIp,
    remoteTunnelIp: config.remoteTunnelIp,
    farVirtIp: config.farVirtIp || '',
    filter: buildFilter(config),
    mappings: config.mappings.map((m) => ({ real: m.real, virt: m.virt, name: m.name || '' })),
  };
}

function helperConfigLine(config) {
  return JSON.stringify(buildHelperConfig(config));
}

/* ------------------------------------------------------------------ */
/* Windows setup: secondary IPs + IP forwarding (elevated)            */
/* ------------------------------------------------------------------ */

function helperPath() {
  return path.join(__dirname, 'nat', 'tvnat.exe');
}

function vendorDir() {
  return path.join(__dirname, 'nat', 'vendor', 'WinDivert-2.2.2-A', 'x64');
}

/* The LAN interface for the NAT: the named one when configured, else
 * the adapter whose IPv4 address sits in the local subnet. Returns
 * the adapter name, or null when none can be found. `interfaces` is
 * os.networkInterfaces() (injectable for tests). */
function detectLanInterface(config, interfaces) {
  if (config.interfaceName) return config.interfaceName;
  const ifs = interfaces || os.networkInterfaces();
  const local = parseCidr(config.localSubnet);
  if (!local) return null;
  for (const name of Object.keys(ifs)) {
    for (const addr of ifs[name] || []) {
      if (addr.family === 'IPv4' && !addr.internal && inSubnet(addr.address, local)) return name;
    }
  }
  return null;
}

/* PowerShell (run elevated, -Verb RunAs) that sets the gateway up:
 * add farVirtIp as a secondary IP on the LAN interface (so the
 * gateway answers ARP for it — remote devices reply to it, and the
 * helper translates the replies back through the tunnel), add the
 * persistent route for the virtual subnet (same-subnet mode only),
 * then enable IP forwarding on that interface. The mapping virtuals
 * are NOT secondary IPs: they live in a separate virtual subnet
 * (e.g. 192.168.2.x) that PCs reach through the route — a PC never
 * ARPs for an address outside its own subnet, so answering ARP for
 * them would do nothing. `netsh interface ipv4 add address` with
 * skipassource keeps Windows from ever SOURCE-addressing traffic
 * from the virtual address — the gateway only ever answers for it.
 * Extracted so it is testable without admin rights. */
function buildSetupScript(config, interfaceName) {
  if (!interfaceName || typeof interfaceName !== 'string') throw new Error('No LAN interface for the NAT setup.');
  const q = (s) => '"' + String(s).replace(/"/g, '') + '"';
  const lines = [
    '$ErrorActionPreference = "Stop"',
    '$iface = ' + q(interfaceName),
  ];
  if (config.farVirtIp) {
    const mask = intToIp(subnetMask(parseCidr(config.localSubnet).prefix));
    lines.push('netsh interface ipv4 add address name=$iface ' + config.farVirtIp + ' ' + mask + ' skipassource=true');
  }
  const routeAdd = buildRouteAddCommand(config);
  if (routeAdd) lines.push(routeAdd);
  lines.push('netsh interface ipv4 set interface name=$iface forwarding=enabled');
  lines.push('exit 0');
  return lines.join('\r\n');
}

/* The matching teardown: remove the secondary IP and the persistent
 * route again and turn forwarding back off. A delete of an address
 * or route that is already gone fails — hence the try/catch per
 * line (a half-torn-down gateway must not abort the rest of the
 * teardown). */
function buildTeardownScript(config, interfaceName) {
  if (!interfaceName || typeof interfaceName !== 'string') throw new Error('No LAN interface for the NAT teardown.');
  const q = (s) => '"' + String(s).replace(/"/g, '') + '"';
  const lines = [
    '$ErrorActionPreference = "Continue"',
    '$iface = ' + q(interfaceName),
  ];
  if (config.farVirtIp) {
    lines.push('try { netsh interface ipv4 delete address name=$iface ' + config.farVirtIp + ' } catch {}');
  }
  const routeDel = buildRouteDeleteCommand(config);
  if (routeDel) lines.push('try { ' + routeDel + ' } catch {}');
  lines.push('try { netsh interface ipv4 set interface name=$iface forwarding=disabled } catch {}');
  lines.push('exit 0');
  return lines.join('\r\n');
}

/* One UAC prompt, then the script runs elevated and we wait for it
 * (same $p.WaitForExit() pattern as wireguard.js — Start-Process
 * -Wait returns early with -Verb RunAs). The temp script is deleted
 * afterwards either way. */
function runElevatedScript(scriptText, timeoutMs) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ success: false, error: 'The NAT setup needs Windows (administrator permission once).' });
    const scriptPath = path.join(os.tmpdir(), 'techvision-nat-setup.ps1');
    try { fs.writeFileSync(scriptPath, scriptText, 'utf8'); } catch (e) { return resolve({ success: false, error: 'Could not write the NAT setup script.' }); }
    const ps = [
      '$ErrorActionPreference = "Stop"',
      'try {',
      '  $p = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ' + "'" + scriptPath.replace(/'/g, "''") + "'" + ' -Verb RunAs -PassThru',
      '  $p.WaitForExit()',
      '  exit $p.ExitCode',
      '} catch {',
      '  exit 2',
      '}',
    ].join('\r\n');
    const launcherPath = path.join(os.tmpdir(), 'techvision-nat-launcher.ps1');
    try { fs.writeFileSync(launcherPath, ps, 'utf8'); } catch (e) { return resolve({ success: false, error: 'Could not write the NAT setup script.' }); }
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', launcherPath], { timeout: timeoutMs || 120000, windowsHide: true }, (err) => {
      try { fs.unlinkSync(scriptPath); } catch (e) {}
      try { fs.unlinkSync(launcherPath); } catch (e) {}
      if (err) {
        if (err.code === 2) return resolve({ success: false, declined: true, error: 'NAT setup was cancelled (administrator permission was not granted).' });
        return resolve({ success: false, error: 'NAT setup failed (code ' + err.code + ').' });
      }
      resolve({ success: true });
    });
  });
}

/* ------------------------------------------------------------------ */
/* Service                                                             */
/* ------------------------------------------------------------------ */

/* The static-route guidance for the different-subnet pair: the one
 * line per router. This is data, not a side effect — the renderer
 * shows it, the user types it into the router once. `via` is the
 * gateway PC's LAN address on that site (filled in by the caller:
 * this site's gatewayLanIp for the local router, the remote
 * gateway's LAN address for the remote router). */
function staticRouteLines(config) {
  if (!config) return [];
  if (config.mode === 'same-subnet') return [];
  return [
    { router: 'local', route: 'On this site\'s router: route ' + config.remoteSubnet + ' via ' + config.gatewayLanIp + ' (this gateway PC).' },
    { router: 'remote', route: 'On the other site\'s router: route ' + config.localSubnet + ' via the other gateway PC\'s LAN address.' },
  ];
}

/* Default dependencies — injectable so the harness can drive the
 * orchestration without Windows, a driver, or admin rights. */
function defaultDeps() {
  return {
    platform: process.platform,
    spawn,
    execFile,
    existsSync: fs.existsSync,
    networkInterfaces: () => os.networkInterfaces(),
    runElevatedScript,
  };
}

/* One service instance. main.js holds the singleton (natService);
 * tests build their own with stub deps via createNatService(). */
function createNatService(deps) {
  const d = deps || defaultDeps();
  let state = {
    running: false,
    mode: null,
    config: null,
    interfaceName: null,
    helperPid: null,
    startedAt: null,
    stats: { packets: 0, translated: 0, passed: 0, dropped: 0 },
    lastError: null,
    /* The peer whose AllowedIPs the service extended, and what they
       were before — set at start, cleared by the restore. */
    appliedPeer: null,
  };
  let child = null;
  let stopTimer = null;

  /* Put the remote gateway peer's AllowedIPs back to what they were
     before start() extended them. Best-effort: a failed restore is
     recorded, never thrown — the service must still stop. */
  async function restoreAppliedPeer() {
    const ap = state.appliedPeer;
    state.appliedPeer = null;
    if (!ap || !ap.hooks || typeof ap.hooks.restorePeerAllowedIPs !== 'function') return;
    try {
      const r = await ap.hooks.restorePeerAllowedIPs(ap.remoteTunnelIp, ap.previousAllowedIPs);
      if (r && r.success === false) state.lastError = r.error || 'Could not restore the peer routes (AllowedIPs).';
    } catch (e) {
      state.lastError = 'Could not restore the peer routes (AllowedIPs).';
    }
  }

  function status() {
    return {
      running: state.running,
      mode: state.mode,
      mappings: state.config ? state.config.mappings.length : 0,
      interfaceName: state.interfaceName,
      helperPid: state.helperPid,
      startedAt: state.startedAt,
      stats: Object.assign({}, state.stats),
      lastError: state.lastError,
      helperAvailable: d.existsSync(helperPath()),
    };
  }

  function handleHelperLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch (e) { return; }
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'stats' && msg) {
      state.stats = {
        packets: msg.packets | 0,
        translated: msg.translated | 0,
        passed: msg.passed | 0,
        dropped: msg.dropped | 0,
      };
    } else if (msg.type === 'log' && msg.msg) {
      /* Helper logs are diagnostics, not user errors — keep the
         last error line only. */
      if (msg.level === 'error') state.lastError = String(msg.msg);
    } else if (msg.type === 'error' && msg.msg) {
      state.lastError = String(msg.msg);
    }
  }

  /* hooks (optional second arg) is the peer-route wiring from
     main.js: { applyPeerAllowedIPs(remoteTunnelIp, allowedIPs),
     restorePeerAllowedIPs(remoteTunnelIp, previousAllowedIPs) }.
     The service cannot translate without it — a packet the helper
     rewrites to a remote real address only enters the tunnel when
     that address is in the remote gateway peer's AllowedIPs — so a
     start with no hooks is refused rather than silently broken. */
  async function start(input, hooks) {
    if (state.running) return { success: false, error: 'The NAT service is already running.' };
    const v = validateNatConfig(input);
    if (!v.ok) return { success: false, error: v.errors[0], errors: v.errors };
    const config = v.config;
    if (d.platform !== 'win32') {
      return { success: false, error: 'The gateway NAT service runs on Windows only (it needs WinDivert and administrator permission once). The configuration itself is valid.' };
    }
    const iface = detectLanInterface(config, d.networkInterfaces());
    if (!iface) return { success: false, error: 'Could not find the LAN interface for ' + config.localSubnet + ' — check the gateway PC is on that network, or set the interface name in the NAT config.' };
    if (!hooks || typeof hooks.applyPeerAllowedIPs !== 'function' || typeof hooks.restorePeerAllowedIPs !== 'function') {
      return { success: false, error: 'The NAT service needs the peer-route wiring (AllowedIPs) — the remote gateway peer cannot be found or updated.' };
    }
    const allowed = allowedIPsForPeer(config);
    if (!allowed) return { success: false, error: 'Could not work out the remote gateway peer\'s routes (AllowedIPs) from the NAT configuration.' };
    /* Secondary IPs + forwarding first: if the user declines the
       UAC prompt, nothing else has started yet. */
    const setup = await d.runElevatedScript(buildSetupScript(config, iface), 120000);
    if (!setup.success) return { success: false, error: setup.error || 'NAT setup failed.', declined: !!setup.declined };
    /* Extend the remote gateway peer's AllowedIPs BEFORE anything
       can send translated packets: if this fails, roll the network
       setup back — a half-started gateway is worse than none. */
    const applied = await hooks.applyPeerAllowedIPs(config.remoteTunnelIp, allowed);
    if (!applied || !applied.success) {
      try { await d.runElevatedScript(buildTeardownScript(config, iface), 120000); } catch (e) {}
      return { success: false, error: applied && applied.error ? applied.error : 'Could not extend the remote gateway peer\'s routes (AllowedIPs). The network setup was rolled back.' };
    }
    state = Object.assign({}, state, {
      running: true, mode: config.mode, config, interfaceName: iface,
      startedAt: new Date().toISOString(), lastError: null,
      stats: { packets: 0, translated: 0, passed: 0, dropped: 0 },
      appliedPeer: { remoteTunnelIp: config.remoteTunnelIp, previousAllowedIPs: applied.previousAllowedIPs, hooks },
    });
    if (config.mode === 'different-subnet') {
      /* No helper in this mode — forwarding alone does the job. */
      return { success: true, mode: config.mode, helperPid: null, routes: staticRouteLines(config) };
    }
    /* Same-subnet mode: the helper does the translating. */
    if (!d.existsSync(helperPath())) {
      state.running = false;
      await restoreAppliedPeer();
      try { await d.runElevatedScript(buildTeardownScript(config, iface), 120000); } catch (e) {}
      return { success: false, error: 'The NAT helper (tvnat.exe) is not built yet — run make in src/nat to build it from source, then start the service again. The network setup was rolled back.' };
    }
    const env = Object.assign({}, process.env, {
      PATH: vendorDir() + path.delimiter + (process.env.PATH || ''),
    });
    let helper;
    try {
      helper = d.spawn(helperPath(), [], {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
        env,
      });
    } catch (e) {
      state.running = false;
      await restoreAppliedPeer();
      try { await d.runElevatedScript(buildTeardownScript(config, iface), 120000); } catch (e2) {}
      return { success: false, error: 'Could not start the NAT helper: ' + (e && e.message ? e.message : String(e)) };
    }
    child = helper;
    state.helperPid = helper.pid || null;
    let buffer = '';
    let ready = false;
    const readyPromise = new Promise((resolveReady) => {
      const timer = setTimeout(() => { if (!ready) resolveReady({ ok: false, error: 'The NAT helper did not answer in time.' }); }, HELPER_TIMEOUT_MS);
      const onData = (chunk) => {
        buffer += chunk.toString('utf8');
        let idx;
        while ((idx = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, idx).trim();
          buffer = buffer.slice(idx + 1);
          if (!line) continue;
          handleHelperLine(line);
          let msg = null;
          try { msg = JSON.parse(line); } catch (e) {}
          if (msg && msg.type === 'ready' && !ready) {
            ready = true;
            clearTimeout(timer);
            resolveReady({ ok: true });
          } else if (msg && msg.type === 'error' && !ready) {
            ready = true;
            clearTimeout(timer);
            resolveReady({ ok: false, error: msg.msg || 'The NAT helper failed to start.' });
          }
        }
      };
      helper.stdout.on('data', onData);
      helper.stderr.on('data', (chunk) => { state.lastError = chunk.toString('utf8').slice(0, 200); });
      helper.on('error', (err) => {
        if (!ready) {
          ready = true;
          clearTimeout(timer);
          resolveReady({ ok: false, error: 'Could not start the NAT helper: ' + (err && err.message ? err.message : String(err)) });
        } else {
          state.lastError = err && err.message ? err.message : String(err);
        }
      });
      helper.on('exit', (code) => {
        if (child === helper) {
          /* The helper died under us: the service is no longer
             translating, so report it as stopped rather than
             leaving a "running" service with no helper — and put
             the peer's routes back, so no translated packet can
             enter the tunnel with nothing to translate it back. */
          const wasRunning = state.running;
          state.running = false;
          state.helperPid = null;
          child = null;
          if (wasRunning) restoreAppliedPeer();
          if (wasRunning && !state.lastError) state.lastError = 'The NAT helper exited (code ' + code + ').';
          if (!ready) {
            ready = true;
            clearTimeout(timer);
            resolveReady({ ok: false, error: state.lastError || 'The NAT helper exited during startup.' });
          }
        }
      });
    });
    try { helper.stdin.write(helperConfigLine(config) + '\n'); } catch (e) {
      try { helper.kill(); } catch (e2) {}
      state.running = false;
      child = null;
      await restoreAppliedPeer();
      try { await d.runElevatedScript(buildTeardownScript(config, iface), 120000); } catch (e3) {}
      return { success: false, error: 'Could not send the configuration to the NAT helper. The network setup was rolled back.' };
    }
    const r = await readyPromise;
    if (!r.ok) {
      try { helper.kill(); } catch (e) {}
      child = null;
      state.running = false;
      state.helperPid = null;
      await restoreAppliedPeer();
      try { await d.runElevatedScript(buildTeardownScript(config, iface), 120000); } catch (e) {}
      return { success: false, error: r.error || 'The NAT helper failed to start. The network setup was rolled back.' };
    }
    return { success: true, mode: config.mode, helperPid: state.helperPid };
  }

  async function stop() {
    if (!state.running && !child) return { success: true, alreadyStopped: true };
    const config = state.config;
    const iface = state.interfaceName;
    const helper = child;
    child = null;
    state.running = false;
    state.helperPid = null;
    if (helper) {
      try { helper.stdin.write(JSON.stringify({ type: 'stop' }) + '\n'); } catch (e) {}
      try { helper.stdin.end(); } catch (e) {}
      await new Promise((resolve) => {
        let done = false;
        const finish = () => { if (!done) { done = true; resolve(); } };
        helper.on('exit', finish);
        stopTimer = setTimeout(() => { try { helper.kill(); } catch (e) {} finish(); }, STOP_TIMEOUT_MS);
      });
      if (stopTimer) { clearTimeout(stopTimer); stopTimer = null; }
    }
    /* Roll the peer's routes back first, then the network setup:
       remove the secondary IPs and turn forwarding off again.
       Best-effort on non-Windows (nothing was set up there) — but
       stop() on a running service only ever happens after a Windows
       start, so this normally runs. */
    await restoreAppliedPeer();
    if (config && iface && d.platform === 'win32') {
      try { await d.runElevatedScript(buildTeardownScript(config, iface), 120000); } catch (e) {}
    }
    state.config = null;
    state.mode = null;
    state.interfaceName = null;
    state.startedAt = null;
    return { success: true };
  }

  return { start, stop, status, _handleHelperLine: handleHelperLine };
}

const natService = createNatService();

module.exports = {
  isValidIp, ipToInt, intToIp, parseCidr, inSubnet, isNetworkOrBroadcast,
  sameSubnet, cidrsOverlap, cidr24Of, virtualSubnetFromMappings,
  netmaskToPrefix, detectLanAddress, isAddressInUseLocally,
  pickFreeAddress, isIpFreeOnLan,
  buildRouteAddCommand, buildRouteDeleteCommand,
  buildRemoteStartCommand, buildRemoteNatConfig, adjustFarVirtIp,
  createMappingTable, addMapping, removeMapping, findByReal, findByVirt,
  translateAddress, validateMapping, validateNatConfig, tunnelSubnetClashes, allowedIPsForPeer,
  buildFilter, buildHelperConfig, helperConfigLine,
  helperPath, vendorDir, detectLanInterface,
  buildSetupScript, buildTeardownScript, runElevatedScript,
  staticRouteLines, createNatService, natService,
  MAX_MAPPINGS, HELPER_TIMEOUT_MS,
};
