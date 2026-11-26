/* Restore wizard — plain JavaScript, Electron renderer only.
   No require(). All native calls go through window.electronAPI.
   Browse buttons stay in this window. Start Restore calls
   restoreAll and ALWAYS shows a success or an error — the main
   process handler must always return a reply (see main.js.patch.md). */
(function () {
  'use strict';
  var api = window.electronAPI || null;
  var timer = null;
  function $(id) { return document.getElementById(id); }
  function toast(title, message, kind) {
    var box = $('toasts'); if (!box) return;
    var el = document.createElement('div');
    el.className = 'toast ' + (kind || '');
    el.innerHTML = '<div><b></b><span></span></div>';
    el.querySelector('b').textContent = title;
    el.querySelector('span').textContent = message || '';
    box.appendChild(el);
    setTimeout(function () { el.classList.add('leaving'); setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 260); }, 4200);
  }
  function applyTheme(theme) { document.body.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark'); }
  function formatBytes(n) {
    n = Number(n) || 0;
    if (n <= 0) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    if (i === 0) return n + ' B';
    var v = n / Math.pow(1024, i);
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
  }
  function formatDate(v) {
    if (!v) return '—';
    var d = v instanceof Date ? v : new Date(v);
    if (isNaN(d.getTime())) return String(v);
    var p = function (x) { return String(x).padStart(2, '0'); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  /* The job this restore was opened from (Restore... on a job), if any:
     its source is the "Original Location", its type/compression fill
     the Backup Information card. Standalone opens have none of it. */
  var jobInfo = null;
  function fillRestoreInfo(zipPath, info) {
    var empty = $('restoreInfoEmpty'), list = $('restoreInfoList');
    if (!empty || !list) return;
    if (!info || !info.success || !Array.isArray(info.entries)) { empty.style.display = ''; list.style.display = 'none'; list.innerHTML = ''; return; }
    var rows = [];
    if (jobInfo && jobInfo.type) rows.push(['Type', jobInfo.type === 'incremental' ? 'Incremental' : 'Full']);
    if (jobInfo && jobInfo.timestamp) rows.push(['Created', formatDate(jobInfo.timestamp)]);
    var total = 0, encrypted = false;
    info.entries.forEach(function (e) { total += Number(e.size) || 0; if (e.encrypted) encrypted = true; });
    rows.push(['Size', formatBytes(total)]);
    rows.push(['Files', String(info.entries.length)]);
    if (jobInfo && jobInfo.compression) {
      var c = String(jobInfo.compression).toLowerCase();
      rows.push(['Compression', c === 'none' ? 'No compression — plain files' : c === 'advanced' ? 'Advanced — Deflate level 9' : 'Standard — Deflate level 6']);
    }
    rows.push(['Encryption', encrypted ? 'AES-256' : 'Off']);
    list.innerHTML = '';
    rows.forEach(function (r) {
      var div = document.createElement('div');
      var dt = document.createElement('dt'); dt.textContent = r[0];
      var dd = document.createElement('dd'); dd.textContent = r[1];
      div.appendChild(dt); div.appendChild(dd); list.appendChild(div);
    });
    empty.style.display = 'none'; list.style.display = '';
  }
  function showValid(zipPath, ok) {
    var el = $('restoreValid'); if (!el) return;
    if (ok === true) {
      el.style.display = '';
      el.classList.remove('bad');
      el.textContent = zipPath && zipPath.toLowerCase().endsWith('.zip') ? '✓ Valid backup file (.zip)' : '✓ Valid backup folder';
    } else if (ok === false) {
      el.style.display = '';
      el.classList.add('bad');
      el.textContent = 'Could not read this backup file — is it a .zip backup?';
    } else {
      el.style.display = 'none';
    }
  }
  function setProgress(pct, files, fileName) {
    var p = Math.max(0, Math.min(100, Number(pct) || 0));
    $('progressPct').textContent = Math.round(p) + '%';
    $('progressFill').style.width = p + '%';
    if (files !== undefined) $('progressCount').textContent = files + ' files';
    if (fileName !== undefined) $('progressFile').textContent = fileName;
  }
  function showResult(ok, title, message) {
    var box = $('resultBox');
    box.style.display = 'block';
    var le = $('restoreLogEmpty'); if (le) le.style.display = 'none';
    box.className = 'note ' + (ok ? 'info' : '');
    if (!ok) box.style.borderColor = 'rgba(239,68,68,.45)';
    box.innerHTML = '';
    var b = document.createElement('strong'); b.textContent = title;
    var p = document.createElement('div'); p.textContent = message || '';
    box.appendChild(b); box.appendChild(p);
  }
  async function pickFile() {
    if (!api || typeof api.showOpenDialog !== 'function') { toast('Browse unavailable', 'File picker API is not available.', 'error'); return; }
    try {
      var result = await api.showOpenDialog({ properties: ['openFile'], filters: [{ name: 'Backup files', extensions: ['zip'] }] });
      var path = null;
      if (typeof result === 'string') path = result;
      else if (result && Array.isArray(result.filePaths) && result.filePaths.length) path = result.filePaths[0];
      else if (result && result.filePath) path = result.filePath;
      else if (Array.isArray(result) && result.length) path = result[0];
      if (path) { $('backupFile').value = path; $('fileError').classList.remove('show'); checkEncrypted(path); }
    } catch (e) { toast('Browse failed', e && e.message ? e.message : 'Could not open the file picker.', 'error'); }
  }
  // Encrypted backup? Ask for its password before restoring.
  var isEncryptedBackup = false;
  async function checkEncrypted(zipPath) {
    isEncryptedBackup = false;
    $('restorePasswordField').style.display = 'none';
    if (!api || typeof api.getZipInfo !== 'function') { showValid(zipPath, null); return; }
    try {
      var info = await api.getZipInfo(zipPath);
      if (info && info.success && Array.isArray(info.entries)) {
        showValid(zipPath, true);
        fillRestoreInfo(zipPath, info);
        if (info.entries.some(function (e) { return e.encrypted; })) {
          isEncryptedBackup = true;
          $('restorePasswordField').style.display = 'block';
        }
      } else {
        showValid(zipPath, false);
        fillRestoreInfo(zipPath, null);
      }
    } catch (e) { showValid(zipPath, false); fillRestoreInfo(zipPath, null); /* unknown: restore will report the real error */ }
  }
  /* Restore To: Original Location restores into the job's source
     folder (only when opened from a job); Custom Location uses the
     Browse field. The field stays disabled while Original is picked. */
  function setupRestoreDest() {
    var orig = $('restoreDestOriginal'), cust = $('restoreDestCustom'), hint = $('restoreOriginalHint');
    if (!orig || !cust) return;
    var hasSource = !!(jobInfo && jobInfo.source);
    orig.disabled = !hasSource;
    if (hint) hint.style.display = hasSource ? 'none' : '';
    var apply = function () {
      var useOrig = orig.checked && hasSource;
      $('restoreTo').disabled = useOrig;
      $('browseDest').disabled = useOrig;
      if (useOrig) { $('restoreTo').value = jobInfo.source; $('destError').classList.remove('show'); }
    };
    orig.addEventListener('change', apply);
    cust.addEventListener('change', apply);
    apply();
  }
  async function pickFolder() {
    if (!api || typeof api.showOpenDialog !== 'function') { toast('Browse unavailable', 'Folder picker API is not available.', 'error'); return; }
    try {
      var result = await api.showOpenDialog({ properties: ['openDirectory'] });
      var path = null;
      if (typeof result === 'string') path = result;
      else if (result && Array.isArray(result.filePaths) && result.filePaths.length) path = result.filePaths[0];
      else if (result && result.filePath) path = result.filePath;
      else if (Array.isArray(result) && result.length) path = result[0];
      if (path) { $('restoreTo').value = path; $('destError').classList.remove('show'); }
    } catch (e) { toast('Browse failed', e && e.message ? e.message : 'Could not open the folder picker.', 'error'); }
  }
  async function startRestore() {
    var zipPath = $('backupFile').value.trim();
    var dest = $('restoreTo').value.trim();
    var ok = true;
    if (!zipPath) { $('fileError').classList.add('show'); ok = false; }
    else $('fileError').classList.remove('show');
    if (!dest) { $('destError').classList.add('show'); ok = false; }
    else $('destError').classList.remove('show');
    var pw = $('restorePassword').value;
    if (isEncryptedBackup && !pw) { $('restorePasswordError').classList.add('show'); ok = false; }
    else $('restorePasswordError').classList.remove('show');
    if (!ok) { toast('Missing information', 'Please choose a backup file and a destination folder.', 'warning'); return; }
    if (!api || typeof api.restoreAll !== 'function') { toast('Restore unavailable', 'Restore API is not available.', 'error'); return; }
    $('startBtn').disabled = true;
    $('startBtn').textContent = 'Restoring…';
    $('cancelBtn').disabled = true;
    $('resultBox').style.display = 'none';
    var le0 = $('restoreLogEmpty'); if (le0) le0.style.display = '';
    $('progressCard').classList.add('show');
    var pe = $('restoreProgressEmpty'); if (pe) pe.style.display = 'none';
    setProgress(0, 0, '');
    var pct = 0;
    timer = setInterval(function () { pct = Math.min(92, pct + Math.random() * 9 + 3); setProgress(pct); }, 350);
    try {
      var result = await api.restoreAll(zipPath, dest, isEncryptedBackup ? $('restorePassword').value : null);
      clearInterval(timer);
      var files = result ? Number(result.files ?? result.restoredFiles ?? result.fileCount ?? 0) : 0;
      setProgress(100, files, '');
      if (result && result.success === false) {
        showResult(false, 'Restore failed', result.error || result.message || 'The restore did not complete.');
        toast('Restore failed', result.error || result.message || 'The restore did not complete.', 'error');
      } else {
        showResult(true, 'Restore completed', files + ' file' + (files === 1 ? '' : 's') + ' restored to ' + dest + '.');
        toast('Restore completed', files + ' file' + (files === 1 ? '' : 's') + ' restored.', 'success');
      }
      if (typeof api.refreshJobs === 'function') { try { await api.refreshJobs(); } catch (e) {} }
    } catch (e) {
      clearInterval(timer);
      var msg = e && e.message ? e.message : 'The restore did not complete.';
      showResult(false, 'Restore failed', msg);
      toast('Restore failed', msg, 'error');
    } finally {
      $('startBtn').disabled = false;
      $('startBtn').textContent = 'Start Restore';
      $('cancelBtn').disabled = false;
      setTimeout(function () {
        $('progressCard').classList.remove('show');
        var pe2 = $('restoreProgressEmpty'); if (pe2) pe2.style.display = '';
      }, 1200);
    }
  }
  function closeWizard() {
    if (api && typeof api.closeRestoreWizard === 'function') { api.closeRestoreWizard(); }
  }
  // Wire immediately like the job wizard: this script sits at the end of
  // <body>, so the buttons already exist. DOMContentLoaded-only wiring was
  // the pattern that left wizard buttons dead.
  function wireRestore() {
    if (wireRestore.done) return; wireRestore.done = true;
    function on(id, ev, fn) { var el = $(id); if (el) el.addEventListener(ev, fn); }
    on('browseFile', 'click', pickFile);
    on('browseDest', 'click', pickFolder);
    on('startBtn', 'click', startRestore);
    on('cancelBtn', 'click', closeWizard);
    on('restoreAdvancedBtn', 'click', function () {
      var adv = $('restoreAdvanced'), btn = $('restoreAdvancedBtn');
      if (!adv || !btn) return;
      var open = adv.style.display === 'none';
      adv.style.display = open ? '' : 'none';
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.textContent = open ? 'Advanced Options ▾' : 'Advanced Options ▸';
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') closeWizard(); });
    if (api && typeof api.getSettings === 'function') {
      api.getSettings().then(function (s) { if (s && s.theme) applyTheme(s.theme); }).catch(function () {});
    }
    // Edit/restore from History: pre-fill the backup file from the job
    // passed to the wizard (its result.backup_path).
    if (api && typeof api.getJobConfig === 'function') {
      api.getJobConfig(null).then(function (cfg) {
        if (cfg) {
          jobInfo = {
            source: cfg.source || (cfg.job && cfg.job.source) || null,
            type: cfg.type || (cfg.job && cfg.job.type) || null,
            compression: cfg.compression || (cfg.job && cfg.job.compression) || null,
            timestamp: cfg.timestamp || (cfg.job && cfg.job.timestamp) || null
          };
          setupRestoreDest();
        }
        if (cfg && cfg.result && cfg.result.backup_path) { $('backupFile').value = cfg.result.backup_path; checkEncrypted(cfg.result.backup_path); }
      }).catch(function () {});
    } else setupRestoreDest();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireRestore);
  else wireRestore();
})();
