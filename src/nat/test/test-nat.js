'use strict';
/*
 * test-nat.js — harness for the gateway NAT service (src/nat-gateway.js).
 *
 * Run:  NODE_PATH=~/workspace/.tvprotect/app2/node_modules node test-nat.js
 * (from this directory; the module needs no npm package, so the
 * NODE_PATH is only there to match the other harnesses' invocation.)
 *
 * Pure-Node only: mapping-table logic, config validation, WinDivert
 * filter / helper-config building, setup-script building, and the
 * start/stop orchestration with injected stub deps (fake spawn,
 * fake elevated script, fake interface list). No live driver, no
 * admin rights, no Windows — the driver load, real packet
 * translation, throughput and proxy ARP are Windows-only and can
 * only be proven on the user's machine.
 *
 * Exit code 0 when every check passes, 1 otherwise.
 */
const { EventEmitter } = require('events');
const path = require('path');
const nat = require(path.join(__dirname, '..', '..', 'nat-gateway.js'));

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name); console.log('FAIL ' + name + (extra !== undefined ? '  -- ' + extra : '')); }
}
function eq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

/* ------------------------------------------------------------------ */
/* IP helpers                                                          */
/* ------------------------------------------------------------------ */
check('isValidIp accepts a normal address', nat.isValidIp('192.168.1.203') === true);
check('isValidIp accepts 10.0.0.1', nat.isValidIp('10.0.0.1') === true);
check('isValidIp rejects 256', nat.isValidIp('192.168.1.256') === false);
check('isValidIp rejects 3 octets', nat.isValidIp('192.168.1') === false);
check('isValidIp rejects 5 octets', nat.isValidIp('1.2.3.4.5') === false);
check('isValidIp rejects trailing junk', nat.isValidIp('192.168.1.3x') === false);
check('isValidIp rejects leading zeros (octal ambiguity)', nat.isValidIp('192.168.01.3') === false);
check('isValidIp rejects empty', nat.isValidIp('') === false);
check('isValidIp rejects non-string', nat.isValidIp(1234) === false);
check('isValidIp rejects 0.0.0.0', nat.isValidIp('0.0.0.0') === false);
check('isValidIp rejects 255.255.255.255', nat.isValidIp('255.255.255.255') === false);
check('ipToInt/intToIp round-trip', nat.intToIp(nat.ipToInt('192.168.16.200')) === '192.168.16.200');
check('ipToInt 192.168.1.3 is 0xC0A80103', nat.ipToInt('192.168.1.3') === 0xC0A80103);
check('parseCidr masks the network', eq(nat.parseCidr('192.168.1.5/24'), { network: '192.168.1.0', prefix: 24 }));
check('parseCidr /32', eq(nat.parseCidr('10.0.0.1/32'), { network: '10.0.0.1', prefix: 32 }));
check('parseCidr rejects no prefix', nat.parseCidr('192.168.1.0') === null);
check('parseCidr rejects /33', nat.parseCidr('192.168.1.0/33') === null);
check('parseCidr rejects bad address', nat.parseCidr('999.1.1.0/24') === null);
check('inSubnet true inside', nat.inSubnet('192.168.1.203', nat.parseCidr('192.168.1.0/24')) === true);
check('inSubnet false outside', nat.inSubnet('192.168.2.3', nat.parseCidr('192.168.1.0/24')) === false);
check('inSubnet false across 16 vs 1', nat.inSubnet('192.168.1.3', nat.parseCidr('192.168.16.0/24')) === false);
check('isNetworkOrBroadcast network address', nat.isNetworkOrBroadcast('192.168.1.0', nat.parseCidr('192.168.1.0/24')) === true);
check('isNetworkOrBroadcast broadcast address', nat.isNetworkOrBroadcast('192.168.1.255', nat.parseCidr('192.168.1.0/24')) === true);
check('isNetworkOrBroadcast normal host is neither', nat.isNetworkOrBroadcast('192.168.1.203', nat.parseCidr('192.168.1.0/24')) === false);
check('sameSubnet equal CIDRs', nat.sameSubnet(nat.parseCidr('192.168.1.0/24'), nat.parseCidr('192.168.1.99/24')) === true);
check('sameSubnet different subnets', nat.sameSubnet(nat.parseCidr('192.168.1.0/24'), nat.parseCidr('192.168.16.0/24')) === false);
check('sameSubnet different prefix', nat.sameSubnet(nat.parseCidr('192.168.1.0/24'), nat.parseCidr('192.168.1.0/25')) === false);
check('cidrsOverlap nested CIDRs', nat.cidrsOverlap(nat.parseCidr('192.168.1.0/24'), nat.parseCidr('192.168.1.128/25')) === true);
check('cidrsOverlap disjoint CIDRs', nat.cidrsOverlap(nat.parseCidr('192.168.1.0/24'), nat.parseCidr('192.168.16.0/24')) === false);

/* ------------------------------------------------------------------ */
/* Mapping table                                                       */
/* ------------------------------------------------------------------ */
const table = nat.createMappingTable();
check('addMapping accepts .3 -> .203', nat.addMapping(table, '192.168.1.3', '192.168.1.203', 'printer').ok === true);
check('addMapping accepts .4 -> .204', nat.addMapping(table, '192.168.1.4', '192.168.1.204', 'camera').ok === true);
check('addMapping rejects duplicate real', nat.addMapping(table, '192.168.1.3', '192.168.1.205', 'other').ok === false);
check('addMapping rejects duplicate virtual', nat.addMapping(table, '192.168.1.5', '192.168.1.203', 'other').ok === false);
check('addMapping rejects real == virt', nat.addMapping(table, '192.168.1.9', '192.168.1.9').ok === false);
check('addMapping rejects bad real', nat.addMapping(table, '999.1.1.1', '192.168.1.206').ok === false);
check('addMapping rejects bad virt', nat.addMapping(table, '192.168.1.6', 'not-an-ip').ok === false);
check('table holds exactly the 2 accepted mappings', table.length === 2);
check('findByReal finds .3', nat.findByReal(table, '192.168.1.3') && nat.findByReal(table, '192.168.1.3').virt === '192.168.1.203');
check('findByVirt finds .204', nat.findByVirt(table, '192.168.1.204') && nat.findByVirt(table, '192.168.1.204').real === '192.168.1.4');
check('findByReal misses unknown', nat.findByReal(table, '192.168.1.99') === null);
check('translateAddress virt-to-real', nat.translateAddress(table, '192.168.1.203', 'virt-to-real') === '192.168.1.3');
check('translateAddress real-to-virt', nat.translateAddress(table, '192.168.1.4', 'real-to-virt') === '192.168.1.204');
check('translateAddress unknown returns null', nat.translateAddress(table, '192.168.1.99', 'virt-to-real') === null);
check('translateAddress bad direction returns null', nat.translateAddress(table, '192.168.1.203', 'sideways') === null);
check('removeMapping by virt works', nat.removeMapping(table, '192.168.1.204').ok === true && table.length === 1);
check('removeMapping unknown fails', nat.removeMapping(table, '192.168.1.204').ok === false);
check('removeMapping by real works too', nat.removeMapping(table, '192.168.1.3').ok === true && table.length === 0);
/* Table cap: 256 mappings max, matching TVNAT_MAX_MAPPINGS. */
const big = nat.createMappingTable();
let capOk = true;
for (let i = 0; i < 256; i++) {
  const r = nat.addMapping(big, '10.1.' + Math.floor(i / 254) + '.' + (i % 254 + 1), '10.2.' + Math.floor(i / 254) + '.' + (i % 254 + 1), '');
  if (!r.ok) { capOk = false; break; }
}
check('table accepts exactly 256 mappings', capOk === true && big.length === 256);
check('table rejects the 257th mapping', nat.addMapping(big, '10.1.9.9', '10.2.9.9').ok === false);

/* ------------------------------------------------------------------ */
/* Config validation — the user's real same-subnet case                */
/* ------------------------------------------------------------------ */
const sameSubnetCfg = {
  mode: 'same-subnet',
  localSubnet: '192.168.1.0/24',
  remoteSubnet: '192.168.1.0/24',
  gatewayLanIp: '192.168.1.10',
  gatewayTunnelIp: '10.0.0.1',
  remoteTunnelIp: '10.0.0.2',
  farVirtIp: '192.168.1.201',
  mappings: [
    { real: '192.168.1.3', virt: '192.168.1.203', name: 'printer' },
    { real: '192.168.1.4', virt: '192.168.1.204', name: 'camera' },
    { real: '192.168.1.5', virt: '192.168.1.205', name: 'pc' },
  ],
};
const diffSubnetCfg = {
  mode: 'different-subnet',
  localSubnet: '192.168.16.0/24',
  remoteSubnet: '192.168.1.0/24',
  gatewayLanIp: '192.168.16.10',
  gatewayTunnelIp: '10.0.0.1',
  remoteTunnelIp: '10.0.0.2',
  mappings: [],
};
const vSame = nat.validateNatConfig(sameSubnetCfg);
check('valid same-subnet config passes', vSame.ok === true, JSON.stringify(vSame.errors));
check('same-subnet config normalises CIDRs', vSame.config && vSame.config.localSubnet === '192.168.1.0/24' && vSame.config.remoteSubnet === '192.168.1.0/24');
check('same-subnet config keeps 3 mappings', vSame.config && vSame.config.mappings.length === 3);
const vDiff = nat.validateNatConfig(diffSubnetCfg);
check('valid different-subnet config passes', vDiff.ok === true, JSON.stringify(vDiff.errors));
check('different-subnet config drops farVirtIp', vDiff.config && vDiff.config.farVirtIp === '');
/* The editor form sends interfaceName: '' when the field is left
   blank — an empty string means "auto-detect", same as omitting
   the key (the normaliser already maps '' to ''). Only a
   whitespace-only non-empty string is an error. */
check('empty interfaceName means auto-detect (passes)', nat.validateNatConfig(Object.assign({}, sameSubnetCfg, { interfaceName: '' })).ok === true);
check('empty interfaceName normalises to empty', nat.validateNatConfig(Object.assign({}, sameSubnetCfg, { interfaceName: '' })).config.interfaceName === '');
check('explicit interfaceName passes and is kept', nat.validateNatConfig(Object.assign({}, sameSubnetCfg, { interfaceName: 'Wi-Fi' })).config.interfaceName === 'Wi-Fi');

function expectInvalid(name, mutate, needle) {
  const cfg = JSON.parse(JSON.stringify(sameSubnetCfg));
  mutate(cfg);
  const v = nat.validateNatConfig(cfg);
  check(name, v.ok === false && v.errors.some((e) => e.indexOf(needle) >= 0),
    'ok=' + v.ok + ' errors=' + JSON.stringify(v.errors));
}
expectInvalid('rejects bad mode', (c) => { c.mode = 'mesh'; }, 'Mode must be');
expectInvalid('rejects whitespace-only interfaceName', (c) => { c.interfaceName = '   '; }, 'Interface name');
expectInvalid('rejects local subnet without CIDR', (c) => { c.localSubnet = '192.168.1.0'; }, 'Local subnet');
expectInvalid('rejects same-subnet mode with different subnets', (c) => { c.remoteSubnet = '192.168.16.0/24'; }, 'same subnet');
expectInvalid('rejects gateway LAN IP outside local subnet', (c) => { c.gatewayLanIp = '192.168.16.10'; }, 'not in the local subnet');
expectInvalid('rejects identical tunnel IPs', (c) => { c.remoteTunnelIp = '10.0.0.1'; }, 'share one tunnel address');
expectInvalid('rejects virtual outside local subnet', (c) => { c.mappings[0].virt = '192.168.16.203'; }, 'not in the local subnet');
expectInvalid('rejects real outside remote subnet', (c) => { c.mappings[0].real = '192.168.16.3'; }, 'not in the remote subnet');
expectInvalid('rejects virtual == gateway LAN IP', (c) => { c.mappings[0].virt = '192.168.1.10'; }, 'own LAN address');
expectInvalid('rejects virtual == network address', (c) => { c.mappings[0].virt = '192.168.1.0'; }, 'network or broadcast');
expectInvalid('rejects virtual == broadcast address', (c) => { c.mappings[0].virt = '192.168.1.255'; }, 'network or broadcast');
expectInvalid('rejects virtual == farVirtIp', (c) => { c.mappings[0].virt = '192.168.1.201'; }, 'collides with farVirtIp');
expectInvalid('rejects duplicate virtual', (c) => { c.mappings[1].virt = '192.168.1.203'; }, 'appears twice');
expectInvalid('rejects duplicate real', (c) => { c.mappings[1].real = '192.168.1.3'; }, 'appears twice');
expectInvalid('rejects real == virt in a mapping', (c) => { c.mappings[0].virt = '192.168.1.3'; }, 'are the same');
expectInvalid('rejects empty mapping list in same-subnet', (c) => { c.mappings = []; }, 'at least one mapping');
expectInvalid('rejects missing farVirtIp in same-subnet', (c) => { delete c.farVirtIp; }, 'farVirtIp');
expectInvalid('rejects farVirtIp outside local subnet', (c) => { c.farVirtIp = '192.168.16.201'; }, 'farVirtIp');
expectInvalid('rejects farVirtIp == gateway LAN IP', (c) => { c.farVirtIp = '192.168.1.10'; }, 'own LAN address');
expectInvalid('rejects mappings in different-subnet mode', (c) => {
  c.mode = 'different-subnet'; c.localSubnet = '192.168.16.0/24';
  c.gatewayLanIp = '192.168.16.10'; c.remoteSubnet = '192.168.1.0/24';
}, 'needs no mappings');
expectInvalid('rejects different-subnet mode with identical subnets', (c) => {
  c.mode = 'different-subnet'; c.mappings = [];
}, 'two different subnets');
expectInvalid('rejects overlapping different-subnet pair', (c) => {
  c.mode = 'different-subnet'; c.mappings = []; delete c.farVirtIp;
  c.localSubnet = '192.168.1.0/24'; c.remoteSubnet = '192.168.1.128/25';
  c.gatewayLanIp = '192.168.1.10';
}, 'overlap');
check('validateNatConfig(null) fails cleanly, never throws', nat.validateNatConfig(null).ok === false);
check('validateNatConfig("x") fails cleanly', nat.validateNatConfig('x').ok === false);
check('validateNatConfig([]) fails cleanly', nat.validateNatConfig([]).ok === false);
const vNorm = nat.validateNatConfig(Object.assign({}, sameSubnetCfg, { localSubnet: '192.168.1.9/24', remoteSubnet: '192.168.1.9/24' }));
check('host bits in the CIDR are masked on normalise', vNorm.ok === true && vNorm.config.localSubnet === '192.168.1.0/24', JSON.stringify(vNorm.errors));

/* ------------------------------------------------------------------ */
/* Filter + helper config (what tvnat.c reads on stdin)                */
/* ------------------------------------------------------------------ */
const filter = nat.buildFilter(vSame.config);
check('filter mentions every virtual address',
  ['192.168.1.203', '192.168.1.204', '192.168.1.205'].every((ip) => filter.indexOf(ip) >= 0), filter);
check('filter mentions farVirtIp + gateway tunnel IP', filter.indexOf('192.168.1.201') >= 0 && filter.indexOf('10.0.0.1') >= 0);
check('filter mentions remote tunnel IP as source', filter.indexOf('ip.SrcAddr == 10.0.0.2') >= 0);
check('filter is IPv4-only', filter.indexOf(' and ip') >= 0);
check('filter for different-subnet mode is null (no helper)', nat.buildFilter(vDiff.config) === null);
const hc = nat.buildHelperConfig(vSame.config);
check('helper config type is config', hc.type === 'config');
check('helper config carries both tunnel IPs', hc.gwTunnelIp === '10.0.0.1' && hc.remoteTunnelIp === '10.0.0.2');
check('helper config carries farVirtIp', hc.farVirtIp === '192.168.1.201');
check('helper config carries the filter', hc.filter === filter);
check('helper config carries 3 mappings', hc.mappings.length === 3 && hc.mappings[0].real === '192.168.1.3' && hc.mappings[0].virt === '192.168.1.203');
const line = nat.helperConfigLine(vSame.config);
let lineBack = null;
try { lineBack = JSON.parse(line); } catch (e) {}
check('helper config line is one JSON line that round-trips', lineBack && lineBack.type === 'config' && lineBack.mappings.length === 3 && line.indexOf('\n') < 0);
check('helper path ends in nat/tvnat.exe', nat.helperPath().endsWith(path.join('nat', 'tvnat.exe')));
check('vendor dir ends in WinDivert x64 folder', nat.vendorDir().endsWith(path.join('WinDivert-2.2.2-A', 'x64')));

/* ------------------------------------------------------------------ */
/* Static-route guidance                                               */
/* ------------------------------------------------------------------ */
const routes = nat.staticRouteLines(vDiff.config);
check('different-subnet mode yields 2 route lines', routes.length === 2);
check('local route line names the remote subnet via this gateway',
  routes[0].route.indexOf('192.168.1.0/24') >= 0 && routes[0].route.indexOf('192.168.16.10') >= 0, routes[0] && routes[0].route);
check('remote route line names the local subnet',
  routes[1].route.indexOf('192.168.16.0/24') >= 0, routes[1] && routes[1].route);
check('same-subnet mode yields no route lines (no router change)', nat.staticRouteLines(vSame.config).length === 0);
check('staticRouteLines(null) is empty', nat.staticRouteLines(null).length === 0);

/* ------------------------------------------------------------------ */
/* AllowedIPs for the remote gateway peer while NAT runs               */
/* ------------------------------------------------------------------ */
check('allowedIPsForPeer same-subnet: tunnel /32 plus every mapped real /32',
  nat.allowedIPsForPeer(vSame.config) === '10.0.0.2/32, 192.168.1.3/32, 192.168.1.4/32, 192.168.1.5/32', nat.allowedIPsForPeer(vSame.config));
check('allowedIPsForPeer different-subnet: tunnel /32 plus the remote subnet CIDR',
  nat.allowedIPsForPeer(vDiff.config) === '10.0.0.2/32, 192.168.1.0/24', nat.allowedIPsForPeer(vDiff.config));
check('allowedIPsForPeer dedupes a real address equal to the tunnel /32',
  nat.allowedIPsForPeer(Object.assign({}, vSame.config, { mappings: [{ real: '10.0.0.2', virt: '192.168.1.203', name: '' }] })) === '10.0.0.2/32');
check('allowedIPsForPeer null on a bad remote tunnel IP', nat.allowedIPsForPeer(Object.assign({}, vSame.config, { remoteTunnelIp: 'nope' })) === null);
check('allowedIPsForPeer null on an unknown mode', nat.allowedIPsForPeer(Object.assign({}, vSame.config, { mode: 'nope' })) === null);
check('allowedIPsForPeer null on a bad mapping', nat.allowedIPsForPeer(Object.assign({}, vSame.config, { mappings: [{ real: '999.1.1.1', virt: '192.168.1.203', name: '' }] })) === null);
check('allowedIPsForPeer null on a bad remote subnet (different-subnet)', nat.allowedIPsForPeer(Object.assign({}, vDiff.config, { remoteSubnet: 'junk' })) === null);

/* ------------------------------------------------------------------ */
/* LAN interface detection + setup/teardown scripts                    */
/* ------------------------------------------------------------------ */
const fakeIfs = {
  Ethernet: [{ address: '192.168.1.10', family: 'IPv4', internal: false }],
  'Wi-Fi': [{ address: '192.168.16.10', family: 'IPv4', internal: false }],
  Loopback: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
};
check('detectLanInterface finds the adapter in the local subnet',
  nat.detectLanInterface(vSame.config, fakeIfs) === 'Ethernet');
check('detectLanInterface honours an explicit interfaceName',
  nat.detectLanInterface(Object.assign({}, vSame.config, { interfaceName: 'Wi-Fi' }), fakeIfs) === 'Wi-Fi');
check('detectLanInterface returns null when no adapter matches',
  nat.detectLanInterface(vSame.config, { 'Wi-Fi': [{ address: '10.9.9.9', family: 'IPv4', internal: false }] }) === null);
const setup = nat.buildSetupScript(vSame.config, 'Ethernet');
check('setup script adds each virtual as a secondary IP',
  ['192.168.1.203', '192.168.1.204', '192.168.1.205'].every((ip) => setup.indexOf('add address name=$iface ' + ip) >= 0), setup);
check('setup script adds farVirtIp too', setup.indexOf('add address name=$iface 192.168.1.201') >= 0);
check('setup script uses skipassource (never source from a virtual)', setup.indexOf('skipassource=true') >= 0);
check('setup script uses the /24 mask', setup.indexOf('255.255.255.0') >= 0);
check('setup script enables forwarding', setup.indexOf('forwarding=enabled') >= 0);
check('setup script targets the named interface', setup.indexOf('$iface = "Ethernet"') >= 0);
const teardown = nat.buildTeardownScript(vSame.config, 'Ethernet');
check('teardown removes each virtual address',
  ['192.168.1.203', '192.168.1.204', '192.168.1.205'].every((ip) => teardown.indexOf('delete address name=$iface ' + ip) >= 0));
check('teardown removes farVirtIp', teardown.indexOf('delete address name=$iface 192.168.1.201') >= 0);
check('teardown disables forwarding again', teardown.indexOf('forwarding=disabled') >= 0);
check('teardown tolerates already-gone addresses (try/catch)', teardown.indexOf('try { netsh') >= 0);
let threw = false;
try { nat.buildSetupScript(vSame.config, ''); } catch (e) { threw = true; }
check('buildSetupScript throws without an interface', threw === true);
threw = false;
try { nat.buildTeardownScript(vSame.config, null); } catch (e) { threw = true; }
check('buildTeardownScript throws without an interface', threw === true);

/* ------------------------------------------------------------------ */
/* Service orchestration with stub deps                                */
/* ------------------------------------------------------------------ */
function makeStubs() {
  const calls = { spawn: [], elevated: [], order: [] };
  let child = null;
  const stubs = {
    platform: 'win32',
    existsSync: () => true,
    networkInterfaces: () => fakeIfs,
    runElevatedScript: async (script) => {
      calls.order.push(script.indexOf('forwarding=enabled') >= 0 ? 'setup' : 'teardown');
      calls.elevated.push(script);
      return { success: true };
    },
    spawn: (exe, args, opts) => {
      calls.order.push('spawn');
      calls.spawn.push({ exe, args, opts });
      child = new EventEmitter();
      child.pid = 1234;
      child.stdin = { written: '', write(d) { this.written += d; return true; }, end() {} };
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.kill = () => { child.emit('exit', 0); };
      stubs.child = child;
      return child;
    },
    calls,
  };
  return stubs;
}

/* Stub peer-route hooks (what main.js wires in at wg-nat-start):
 * apply records the call and reports the previous AllowedIPs;
 * restore records it. Both can be made to fail via opts. */
function makeHooks(stubs, opts) {
  const o = opts || {};
  const calls = { apply: [], restore: [] };
  const hooks = {
    applyPeerAllowedIPs: async (remoteTunnelIp, allowedIPs) => {
      stubs.calls.order.push('apply');
      calls.apply.push({ remoteTunnelIp, allowedIPs });
      if (o.applyFails) return { success: false, error: 'stub apply failed' };
      return { success: true, previousAllowedIPs: o.previousAllowedIPs || '10.0.0.2/32' };
    },
    restorePeerAllowedIPs: async (remoteTunnelIp, previousAllowedIPs) => {
      stubs.calls.order.push('restore');
      calls.restore.push({ remoteTunnelIp, previousAllowedIPs });
      if (o.restoreFails) return { success: false, error: 'stub restore failed' };
      return { success: true };
    },
    calls,
  };
  return hooks;
}

async function serviceTests() {
  /* Happy path, same-subnet: setup -> spawn -> ready -> stats -> stop. */
  const stubs = makeStubs();
  const hooks = makeHooks(stubs);
  const svc = nat.createNatService(stubs);
  check('status before start: not running, helper missing flag is honest',
    svc.status().running === false && svc.status().helperPid === null);
  const p = svc.start(sameSubnetCfg, hooks);
  /* The service writes the config line to the helper's stdin before
   * the ready line can arrive — assert on it while start() waits. */
  await new Promise((r) => setImmediate(r));
  const written = stubs.child ? stubs.child.stdin.written : '';
  let cfgLine = null;
  try { cfgLine = JSON.parse(written.trim()); } catch (e) {}
  check('helper receives exactly one JSON config line on stdin',
    cfgLine && cfgLine.type === 'config' && cfgLine.mappings.length === 3, written.slice(0, 120));
  check('helper config line carries the WinDivert filter',
    cfgLine && typeof cfgLine.filter === 'string' && cfgLine.filter.indexOf('192.168.1.203') >= 0);
  check('helper is spawned with the vendor dir on PATH (WinDivert.dll resolves)',
    stubs.calls.spawn.length === 1 && String(stubs.calls.spawn[0].opts.env.PATH).indexOf('WinDivert-2.2.2-A') >= 0);
  check('elevated setup ran before the helper started', stubs.calls.elevated.length === 1 && stubs.calls.elevated[0].indexOf('forwarding=enabled') >= 0);
  stubs.child.stdout.emit('data', '{"type":"ready","filter":"x","mappings":3}\n');
  const started = await p;
  check('start succeeds once the helper says ready', started.success === true && started.mode === 'same-subnet' && started.helperPid === 1234, JSON.stringify(started));
  check('AllowedIPs applied for the remote gateway peer (tunnel /32 + mapped reals)',
    hooks.calls.apply.length === 1 && hooks.calls.apply[0].remoteTunnelIp === '10.0.0.2' &&
    hooks.calls.apply[0].allowedIPs === '10.0.0.2/32, 192.168.1.3/32, 192.168.1.4/32, 192.168.1.5/32', JSON.stringify(hooks.calls.apply));
  check('AllowedIPs applied after the network setup and before the helper spawn',
    JSON.stringify(stubs.calls.order.slice(0, 3)) === JSON.stringify(['setup', 'apply', 'spawn']), JSON.stringify(stubs.calls.order));
  check('status after start: running, 3 mappings, helper pid',
    svc.status().running === true && svc.status().mappings === 3 && svc.status().helperPid === 1234);
  stubs.child.stdout.emit('data', '{"type":"stats","packets":10,"translated":7,"passed":3,"dropped":0}\n');
  check('stats lines from the helper update status()',
    svc.status().stats.packets === 10 && svc.status().stats.translated === 7 && svc.status().stats.passed === 3);
  const again = await svc.start(sameSubnetCfg);
  check('second start while running is refused', again.success === false && /already running/.test(again.error || ''));
  const stopP = svc.stop();
  check('stop writes {"type":"stop"} to the helper stdin',
    stubs.child.stdin.written.indexOf('"type":"stop"') >= 0);
  stubs.child.emit('exit', 0);
  const stopped = await stopP;
  check('stop succeeds', stopped.success === true);
  check('stop restores the peer routes to what they were before start',
    hooks.calls.restore.length === 1 && hooks.calls.restore[0].remoteTunnelIp === '10.0.0.2' &&
    hooks.calls.restore[0].previousAllowedIPs === '10.0.0.2/32', JSON.stringify(hooks.calls.restore));
  check('status after stop: not running, no helper',
    svc.status().running === false && svc.status().helperPid === null);
  check('teardown ran on stop (secondary IPs removed)', stubs.calls.elevated.length === 2 && stubs.calls.elevated[1].indexOf('forwarding=disabled') >= 0);
  const stopAgain = await svc.stop();
  check('stop when already stopped succeeds quietly', stopAgain.success === true && stopAgain.alreadyStopped === true);

  /* Different-subnet: forwarding only, NO helper process. */
  const stubs2 = makeStubs();
  const hooks2 = makeHooks(stubs2);
  const svc2 = nat.createNatService(stubs2);
  const d = await svc2.start(diffSubnetCfg, hooks2);
  check('different-subnet start succeeds without a helper',
    d.success === true && d.mode === 'different-subnet' && d.helperPid === null, JSON.stringify(d));
  check('different-subnet start spawns nothing', stubs2.calls.spawn.length === 0);
  check('different-subnet AllowedIPs: tunnel /32 plus the whole remote subnet',
    hooks2.calls.apply.length === 1 && hooks2.calls.apply[0].allowedIPs === '10.0.0.2/32, 192.168.1.0/24', JSON.stringify(hooks2.calls.apply));
  check('different-subnet start returns the static-route lines',
    Array.isArray(d.routes) && d.routes.length === 2);
  check('different-subnet status: running, 0 mappings',
    svc2.status().running === true && svc2.status().mappings === 0);
  await svc2.stop();
  check('different-subnet stop leaves it stopped', svc2.status().running === false);
  check('different-subnet stop restores the peer routes',
    hooks2.calls.restore.length === 1 && hooks2.calls.restore[0].previousAllowedIPs === '10.0.0.2/32');

  /* No peer-route hooks: start is refused before any side effect —
     a gateway that cannot extend the peer's AllowedIPs would
     translate packets into a tunnel that drops them. */
  const stubsH = makeStubs();
  const svcH = nat.createNatService(stubsH);
  const noHooks = await svcH.start(sameSubnetCfg);
  check('start without peer-route hooks fails before any side effect',
    noHooks.success === false && /AllowedIPs/.test(noHooks.error || '') &&
    stubsH.calls.spawn.length === 0 && stubsH.calls.elevated.length === 0, JSON.stringify(noHooks));

  /* Apply failure: start fails, setup rolled back, nothing spawns. */
  const stubsA = makeStubs();
  const hooksA = makeHooks(stubsA, { applyFails: true });
  const svcA = nat.createNatService(stubsA);
  const applyFail = await svcA.start(sameSubnetCfg, hooksA);
  check('AllowedIPs apply failure fails start() with the apply error',
    applyFail.success === false && /stub apply failed/.test(applyFail.error || ''), JSON.stringify(applyFail));
  check('apply failure spawns nothing and rolls the setup back',
    stubsA.calls.spawn.length === 0 && stubsA.calls.elevated.length === 2);
  check('service is not left running after apply failure', svcA.status().running === false);

  /* Invalid config: nothing is spawned, nothing is set up. */
  const stubs3 = makeStubs();
  const svc3 = nat.createNatService(stubs3);
  const bad = await svc3.start(Object.assign({}, sameSubnetCfg, { mode: 'nope' }));
  check('invalid config fails before any side effect',
    bad.success === false && stubs3.calls.spawn.length === 0 && stubs3.calls.elevated.length === 0, JSON.stringify(bad));

  /* Non-Windows: config validates, then a clean Windows-only error. */
  const stubs4 = makeStubs();
  stubs4.platform = 'linux';
  const svc4 = nat.createNatService(stubs4);
  const lin = await svc4.start(sameSubnetCfg);
  check('start on Linux fails cleanly with a Windows-only error',
    lin.success === false && /Windows only/.test(lin.error || '') && stubs4.calls.spawn.length === 0, JSON.stringify(lin));

  /* No LAN interface for the subnet: clean error, no spawn. */
  const stubs5 = makeStubs();
  stubs5.networkInterfaces = () => ({ 'Wi-Fi': [{ address: '10.9.9.9', family: 'IPv4', internal: false }] });
  const svc5 = nat.createNatService(stubs5);
  const noIf = await svc5.start(sameSubnetCfg);
  check('no matching LAN interface fails cleanly',
    noIf.success === false && /LAN interface/.test(noIf.error || ''), JSON.stringify(noIf));

  /* Helper missing (not built yet): setup is rolled back. */
  const stubs6 = makeStubs();
  stubs6.existsSync = () => false;
  const hooks6 = makeHooks(stubs6);
  const svc6 = nat.createNatService(stubs6);
  const noHelper = await svc6.start(sameSubnetCfg, hooks6);
  check('missing tvnat.exe fails with a build hint',
    noHelper.success === false && /not built/.test(noHelper.error || ''), JSON.stringify(noHelper));
  check('missing tvnat.exe rolls the setup back', stubs6.calls.elevated.length === 2);
  check('missing tvnat.exe restores the peer routes', hooks6.calls.restore.length === 1);
  check('service is not left running after the rollback', svc6.status().running === false);

  /* Helper dies during startup: start fails, setup rolled back. */
  const stubs7 = makeStubs();
  const hooks7 = makeHooks(stubs7);
  const svc7 = nat.createNatService(stubs7);
  const p7 = svc7.start(sameSubnetCfg, hooks7);
  await new Promise((r) => setImmediate(r));
  stubs7.child.emit('exit', 1);
  const died = await p7;
  check('helper exiting during startup fails start()',
    died.success === false, JSON.stringify(died));
  check('helper death rolls the setup back', stubs7.calls.elevated.length === 2);
  check('helper death restores the peer routes', hooks7.calls.restore.length === 1);
  check('service is not left running after helper death', svc7.status().running === false);

  /* Helper error line before ready: start fails with its message. */
  const stubs8 = makeStubs();
  const hooks8 = makeHooks(stubs8);
  const svc8 = nat.createNatService(stubs8);
  const p8 = svc8.start(sameSubnetCfg, hooks8);
  await new Promise((r) => setImmediate(r));
  stubs8.child.stdout.emit('data', '{"type":"error","msg":"WinDivert needs administrator permission"}\n');
  const herr = await p8;
  check('helper error line fails start() with the helper message',
    herr.success === false && /administrator permission/.test(herr.error || ''), JSON.stringify(herr));
  check('helper error line restores the peer routes', hooks8.calls.restore.length === 1);

  /* UAC declined: the elevated setup error surfaces, nothing spawns. */
  const stubs9 = makeStubs();
  stubs9.runElevatedScript = async () => ({ success: false, declined: true, error: 'NAT setup was cancelled (administrator permission was not granted).' });
  const hooks9 = makeHooks(stubs9);
  const svc9 = nat.createNatService(stubs9);
  const declined = await svc9.start(sameSubnetCfg, hooks9);
  check('declined UAC fails start() with declined=true',
    declined.success === false && declined.declined === true && stubs9.calls.spawn.length === 0, JSON.stringify(declined));

  /* Direct line handling: log/error lines update lastError. */
  const svc10 = nat.createNatService(makeStubs());
  svc10._handleHelperLine('{"type":"log","level":"error","msg":"recv failed"}');
  check('helper error log line is kept as lastError', svc10.status().lastError === 'recv failed');
  svc10._handleHelperLine('not json at all');
  check('a non-JSON helper line is ignored, not a crash', svc10.status().lastError === 'recv failed');
  svc10._handleHelperLine('{"type":"stats","packets":5,"translated":5,"passed":0,"dropped":0}');
  check('stats line via _handleHelperLine updates counters', svc10.status().stats.packets === 5);
}

serviceTests().then(() => {
  console.log('---');
  console.log('test-nat: ' + pass + ' passed, ' + fail + ' failed');
  if (fail > 0) { console.log('failures: ' + failures.join(' | ')); process.exit(1); }
}).catch((e) => {
  console.error('HARNESS ERROR', e);
  process.exit(2);
});
