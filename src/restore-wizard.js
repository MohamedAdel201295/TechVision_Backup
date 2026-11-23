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
      if (path) { $('backupFile').value = path; $('fileError').classList.remove('show'); }
    } catch (e) { toast('Browse failed', e && e.message ? e.message : 'Could not open the file picker.', 'error'); }
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
    if (!dest) { $('destError').classList.add('show'); ok = false; }
    if (!ok) { toast('Missing information', 'Please choose a backup file and a destination folder.', 'warning'); return; }
    if (!api || typeof api.restoreAll !== 'function') { toast('Restore unavailable', 'Restore API is not available.', 'error'); return; }
    $('startBtn').disabled = true;
    $('startBtn').textContent = 'Restoring…';
    $('cancelBtn').disabled = true;
    $('resultBox').style.display = 'none';
    $('progressCard').classList.add('show');
    setProgress(0, 0, '');
    var pct = 0;
    timer = setInterval(function () { pct = Math.min(92, pct + Math.random() * 9 + 3); setProgress(pct); }, 350);
    try {
      var result = await api.restoreAll(zipPath, dest);
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
      setTimeout(function () { $('progressCard').classList.remove('show'); }, 1200);
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
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') closeWizard(); });
    if (api && typeof api.getSettings === 'function') {
      api.getSettings().then(function (s) { if (s && s.theme) applyTheme(s.theme); }).catch(function () {});
    }
    // Edit/restore from History: pre-fill the backup file from the job
    // passed to the wizard (its result.backup_path).
    if (api && typeof api.getJobConfig === 'function') {
      api.getJobConfig(null).then(function (cfg) {
        if (cfg && cfg.result && cfg.result.backup_path) $('backupFile').value = cfg.result.backup_path;
      }).catch(function () {});
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireRestore);
  else wireRestore();
})();
