/**
 * Simple Phase 1 Test Runner
 */
const fs = require('fs');
const path = require('path');
const { BackupEngine, JobConfig, BackupResult } = require('./src/techvision-core.js');
const { RestoreEngine } = require('./src/restore.js');

const BASE = __dirname;
const TEST_DIR = path.join(BASE, 'test-output');
const SOURCE_DIR = path.join(BASE, 'test-data');

// Ensure test directory exists
if (!fs.existsSync(TEST_DIR)) {
  fs.mkdirSync(TEST_DIR, { recursive: true });
}

console.log('=== Phase 1 Verification Test ===\n');

async function run() {
  // Verify test file exists
  const testFile = path.join(SOURCE_DIR, 'large_random_50mb.bin');
  const size = fs.statSync(testFile).size;
  console.log('Test file exists:', testFile);
  console.log('Test file size:', (size/1024/1024).toFixed(2), 'MB');
  
  // Clean output directory
  if (fs.existsSync(TEST_DIR)) {
    const items = fs.readdirSync(TEST_DIR);
    for (const item of items) {
      fs.rmSync(path.join(TEST_DIR, item), { recursive: true, force: true });
    }
  }
  
  // Run backup
  console.log('\nRunning full backup...');
  const job = new JobConfig({
    name: 'test-job',
    source: { path: SOURCE_DIR, include: ['*.*'] },
    destination: { path: TEST_DIR }
  });
  
  const engine = new BackupEngine(job);
  const start = Date.now();
  const result = await engine.run_full_backup();
  const duration = (Date.now() - start) / 1000;
  
  console.log('\nBackup Result:');
  console.log('  Success:', result.success);
  console.log('  Files backed up:', result.files_backed_up);
  console.log('  Files skipped:', result.files_skipped);
  console.log('  Locked files skipped:', result.locked_files_skipped);
  console.log('  Total bytes:', result.total_bytes);
  console.log('  Duration:', duration.toFixed(2), 's');
  
  if (result.error_messages.length > 0) {
    console.log('  Errors:', result.error_messages);
  }
  
  // Find ZIP
  const backupDir = path.join(TEST_DIR, 'test-job');
  if (fs.existsSync(backupDir)) {
    const zips = fs.readdirSync(backupDir).filter(f => f.endsWith('.zip'));
    
    if (zips.length > 0) {
      const zipPath = path.join(backupDir, zips[0]);
      const zipSize = fs.statSync(zipPath).size;
      console.log('\nZIP file:', zips[0]);
      console.log('ZIP size:', (zipSize/1024).toFixed(2), 'KB');
      console.log('Compression ratio:', (result.total_bytes/zipSize).toFixed(2), 'x');
      
      // Test restore
      console.log('\nTesting restore with yauzl streaming...');
      const restoreDir = path.join(TEST_DIR, 'restored');
      const restoreEngine = new RestoreEngine();
      
      const restoreStart = Date.now();
      const restoreResult = await restoreEngine.restore_all(zipPath, restoreDir);
      const restoreDuration = (Date.now() - restoreStart) / 1000;
      
      console.log('Restore Result:');
      console.log('  Success:', restoreResult.success);
      console.log('  Files restored:', restoreResult.files_restored);
      console.log('  Files verified:', restoreResult.files_verified);
      console.log('  Files mismatched:', restoreResult.files_mismatched);
      console.log('  Duration:', restoreDuration.toFixed(2), 's');
      
      if (restoreResult.errors.length > 0) {
        console.log('  Errors:', restoreResult.errors);
      }
    } else {
      console.log('No ZIP files found');
    }
  } else {
    console.log('Backup directory not created');
  }
  
  console.log('\n=== Test Complete ===');
}

run().catch(e => { console.error('Error:', e); process.exit(1); });