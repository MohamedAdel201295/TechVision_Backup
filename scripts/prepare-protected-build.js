/**
 * TechVision Backup — protected build preparation (runs as `prebuild`).
 *
 * What it does, and what it does NOT do:
 * - It never touches the real source in src/. Everything it produces
 *   goes into build-protected/ (gitignored), and electron-builder
 *   packages that staging copy instead of src/ (see package.json
 *   build.files). `npm start` / `electron .` never run this script,
 *   so day-to-day development is unchanged.
 * - Main-process files (main.js, engine, vault, mailer, restore,
 *   zip-aes, drive-resolver, cloud-server, cloud-client) are compiled to V8 bytecode (.jsc) with
 *   bytenode, so the shipped app contains no readable JavaScript for
 *   the engine. main.js becomes a tiny loader that requires('bytenode')
 *   and loads main.jsc.
 * - preload.js stays PLAIN JavaScript, deliberately: a preload runs in
 *   Electron's sandboxed renderer context, whose require() cannot load
 *   bare node_modules packages (verified: require('bytenode') fails
 *   there with "module not found"). The preload is only a thin IPC
 *   bridge — it exposes method names the renderer already calls, and
 *   holds no secrets — so leaving it readable costs nothing.
 * - Renderer files (renderer.js, job-wizard.js, restore-wizard.js,
 *   log-viewer.js) cannot be bytecode (they run in the browser
 *   context), so they are obfuscated with javascript-obfuscator.
 * - Main-process files are obfuscated FIRST (strings + control flow),
 *   with every exported name reserved, so cross-file requires keep
 *   working: `module.exports = { BackupEngine }` in one file and
 *   `const { BackupEngine } = require(...)` in another must agree.
 *
 * Bytecode is tied to the exact Electron version (V8). This script
 * compiles with the Electron binary from node_modules, so the .jsc
 * always matches the Electron version being packaged. If Electron is
 * upgraded past v41, bytenode needs compileElectronMainCode /
 * compileElectronRendererCode instead of compileElectronCode — the
 * version check below switches automatically.
 *
 * Any failure here aborts the build (exit 1): a broken protected
 * build must never ship a Release.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const srcDir = path.join(root, 'src');
const stagingDir = path.join(root, 'build-protected');
const stagingSrc = path.join(stagingDir, 'src');

const MAIN_FILES = [
  'main.js', 'techvision-core.js', 'restore.js', 'zip-aes.js',
  'mailer.js', 'vault.js', 'drive-resolver.js',
  'cloud-server.js', 'cloud-client.js', 'vpn.js',
];
// preload.js is deliberately NOT compiled (see the header comment).
const RENDERER_FILES = [
  'renderer.js', 'job-wizard.js', 'restore-wizard.js', 'log-viewer.js',
];
const COMPILED = new Set(MAIN_FILES);

function fail(message) {
  console.error('[Protected build] FAILED: ' + message);
  process.exit(1);
}

function copyDirRecursive(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const s = path.join(from, entry.name);
    const d = path.join(to, entry.name);
    if (entry.isDirectory()) copyDirRecursive(s, d);
    else fs.copyFileSync(s, d);
  }
}

// Exported names of a file: anything another file can require from it.
// Those identifiers must NOT be renamed by the obfuscator, or the
// cross-file contract breaks (e.g. { BackupEngine } exported here and
// destructured there).
function exportedNames(code) {
  const names = new Set();
  const brace = code.match(/module\.exports\s*=\s*\{([\s\S]*?)\}/);
  if (brace) {
    for (const part of brace[1].split(',')) {
      const token = part.trim().split(':')[0].trim();
      if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(token)) names.add(token);
    }
  }
  for (const m of code.matchAll(/(?:module\.exports|exports)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=/g)) {
    names.add(m[1]);
  }
  return [...names];
}

function obfuscate(code, reserved) {
  const JavaScriptObfuscator = require('javascript-obfuscator');
  const result = JavaScriptObfuscator.obfuscate(code, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.5,
    deadCodeInjection: false,
    debugProtection: false,
    disableConsoleOutput: false,
    identifierNamesGenerator: 'hexadecimal',
    renameGlobals: false,
    reservedNames: reserved.map(function (n) { return '^' + n + '$'; }),
    selfDefending: false,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 0.75,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    sourceMap: false,
  });
  return result.getObfuscatedCode();
}

async function main() {
  console.log('[Protected build] Preparing protected staging copy in build-protected/ ...');
  let bytenode;
  try { bytenode = require('bytenode'); } catch (e) { fail('bytenode is not installed (npm ci). ' + e.message); }
  let electronPath;
  try { electronPath = require('electron'); } catch (e) { fail('electron is not installed (npm ci). ' + e.message); }
  let electronVersion = '0';
  try { electronVersion = require(path.join(root, 'node_modules', 'electron', 'package.json')).version; } catch (e) {}
  const major = parseInt(String(electronVersion).split('.')[0], 10) || 0;
  // Electron <= 41: bytenode.compileFile({ electron: true }) compiles
  // via ELECTRON_RUN_AS_NODE, whose bytecode the main process accepts.
  // Electron >= 42: bytecode must be compiled in the process type
  // that will load it — electronMain for main-process files,
  // electronRenderer for the preload.
  console.log(`[Protected build] Electron ${electronVersion} — using ${major >= 42 ? 'process-specific' : 'compileElectronCode'} compilation.`);

  fs.rmSync(stagingDir, { recursive: true, force: true });
  copyDirRecursive(srcDir, stagingSrc);

  // Main-process files: rewrite relative requires to .jsc, obfuscate,
  // compile to bytecode. main.js keeps a tiny .js loader.
  for (const file of MAIN_FILES) {
    const staged = path.join(stagingSrc, file);
    if (!fs.existsSync(staged)) fail('missing source file: src/' + file);
    let code = fs.readFileSync(staged, 'utf-8');
    const reserved = exportedNames(code);
    code = code.replace(/require\(\s*(['"])(\.\/[^'"]+)\.js\1\s*\)/g, function (m, q, base) {
      const target = path.basename(base) + '.js';
      if (!COMPILED.has(target)) return m;
      return 'require(' + q + base + '.jsc' + q + ')';
    });
    const obfuscated = obfuscate(code, reserved);
    const tmpJs = staged + '.obf.js';
    fs.writeFileSync(tmpJs, obfuscated);
    const outJsc = staged.replace(/\.js$/, '.jsc');
    try {
      await bytenode.compileFile({
        filename: tmpJs,
        output: outJsc,
        electron: true,
        electronMain: major >= 42,
        electronPath: electronPath,
      });
    } catch (e) {
      fail('bytenode failed for ' + file + ': ' + (e && e.message ? e.message : e));
    }
    fs.unlinkSync(tmpJs);
    if (file === 'main.js') {
      fs.writeFileSync(staged,
        '// Protected build loader — the real code is main.jsc (V8 bytecode).\n' +
        "require('bytenode');\n" +
        "require('./main.jsc');\n");
    } else {
      fs.unlinkSync(staged);
    }
    console.log(`[Protected build] ${file} -> ${path.basename(outJsc)} (obfuscated + bytecode)`);
  }

  // Renderer files: obfuscate only, same filename.
  for (const file of RENDERER_FILES) {
    const staged = path.join(stagingSrc, file);
    if (!fs.existsSync(staged)) { console.log('[Protected build] skip missing renderer file: ' + file); continue; }
    const code = fs.readFileSync(staged, 'utf-8');
    fs.writeFileSync(staged, obfuscate(code, []));
    console.log(`[Protected build] ${file} obfuscated`);
  }

  console.log('[Protected build] Staging ready: build-protected/src/');
}

main().catch(function (e) { fail(e && e.stack ? e.stack : String(e)); });
