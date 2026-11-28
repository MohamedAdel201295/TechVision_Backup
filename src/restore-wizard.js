/* Restore wizard — plain JavaScript, Electron renderer only.
   No require(). All native calls go through window.electronAPI.
   Browse buttons stay in this window. Start Restore calls
   restoreAll and ALWAYS shows a success or an error — the main
   process handler must always return a reply (see main.js.patch.md). */
(function () {
  'use strict';
  var api = window.electronAPI || null;
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
     its type/compression/timestamp fill the Backup Information card.
     Standalone opens have none of it. The destination is always
     picked by hand — there is no "Original Location" any more. */
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
    // A layered .tvb's single entry is a whole ZIP, not a file —
    // report that instead of a misleading "1 file" + the ZIP's size.
    var isLayered = !!(info && info.layered);
    rows.push(['Size', isLayered ? 'Inside the encrypted archive' : formatBytes(total)]);
    rows.push(['Files', isLayered ? 'Inside the encrypted archive' : String(info.entries.length)]);
    if (jobInfo && jobInfo.compression) {
      var c = String(jobInfo.compression).toLowerCase();
      rows.push(['Compression', c === 'none' ? 'No compression — plain files' : c === 'advanced' ? 'Advanced — Deflate level 9' : 'Standard — Deflate level 6']);
    }
    // The encryption text must say WHICH password: a .zip's is a
    // WinZip AES password (7-Zip can open it), a .tvb's is the
    // program-only backup password.
    var isZip = (zipPath || '').toLowerCase().endsWith('.zip');
    rows.push(['Encryption', encrypted ? (isZip ? 'ZIP password (WinZip AES-256 — 7-Zip can open it)' : 'TechVision-only AES-256-GCM') : 'Off']);
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
      var lower = (zipPath || '').toLowerCase();
      el.textContent = lower.endsWith('.tvb') ? '✓ Valid backup file (.tvb — TechVision encrypted)'
        : lower.endsWith('.zip') ? '✓ Valid backup file (.zip)' : '✓ Valid backup folder';
    } else if (ok === false) {
      el.style.display = '';
      el.classList.add('bad');
      el.textContent = 'Could not read this backup file — is it a .zip or .tvb backup?';
    } else {
      el.style.display = 'none';
    }
  }
  function setProgress(pct, files, fileName) {
    var p = Math.max(0, Math.min(100, Number(pct) || 0));
    $('restoreProgressPct').textContent = Math.round(p) + '%';
    $('restoreProgressFill').style.width = p + '%';
    if (files !== undefined) $('restoreProgressCount').textContent = files + ' files';
    if (fileName !== undefined) $('restoreProgressFile').textContent = fileName;
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
      var result = await api.showOpenDialog({ properties: ['openFile'], filters: [{ name: 'Backup files', extensions: ['zip', 'tvb'] }] });
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
    var zf0 = $('restoreZipPasswordField'); if (zf0) zf0.style.display = 'none';
    var zp0 = $('restoreZipPassword'); if (zp0) zp0.value = '';
    if (!api || typeof api.getZipInfo !== 'function') { showValid(zipPath, null); return; }
    try {
      var info = await api.getZipInfo(zipPath);
      if (info && info.success && Array.isArray(info.entries)) {
        showValid(zipPath, true);
        fillRestoreInfo(zipPath, info);
        if (info.entries.some(function (e) { return e.encrypted; })) {
          isEncryptedBackup = true;
          // The first password field is the ZIP password for a .zip
          // and the backup (encryption) password for a .tvb — label
          // it so the two can never be confused.
          var isZip = (zipPath || '').toLowerCase().endsWith('.zip');
          var pwLabel = $('restorePasswordLabel'), pwHint = $('restorePasswordHint');
          if (isZip) {
            if (pwLabel) pwLabel.textContent = 'ZIP password';
            if (pwHint) pwHint.textContent = 'This ZIP is password-protected (WinZip AES-256). Enter its ZIP password — 7-Zip can open it with this password.';
          } else {
            if (pwLabel) pwLabel.textContent = 'Backup password';
            if (pwHint) pwHint.textContent = 'This backup is encrypted (TechVision-only). Enter its backup password to restore it.';
          }
          $('restorePasswordField').style.display = 'block';
          // Layered backup (encryption password AND ZIP password):
          // show BOTH fields up front, so one Start Restore submit
          // restores it. The ZIP field used to appear only after a
          // failed first attempt (ZIP_PASSWORD_REQUIRED) — that path
          // stays as a safety net for a layered file whose flag
          // could not be read here.
          if (info.layered) {
            var zf = $('restoreZipPasswordField');
            if (zf) zf.style.display = 'block';
          }
        }
      } else {
        showValid(zipPath, false);
        fillRestoreInfo(zipPath, null);
      }
    } catch (e) { showValid(zipPath, false); fillRestoreInfo(zipPath, null); /* unknown: restore will report the real error */ }
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
      if (path) { $('restoreTo').value = path; $('restoreDestError').classList.remove('show'); }
    } catch (e) { toast('Browse failed', e && e.message ? e.message : 'Could not open the folder picker.', 'error'); }
  }
  async function startRestore() {
    var zipPath = $('backupFile').value.trim();
    var dest = $('restoreTo').value.trim();
    var ok = true;
    if (!zipPath) { $('fileError').classList.add('show'); ok = false; }
    else $('fileError').classList.remove('show');
    if (!dest) { $('restoreDestError').classList.add('show'); ok = false; }
    else $('restoreDestError').classList.remove('show');
    var pw = $('restorePassword').value;
    if (isEncryptedBackup && !pw) { $('restorePasswordError').classList.add('show'); ok = false; }
    else $('restorePasswordError').classList.remove('show');
    // A layered backup's second password: the field is shown up
    // front for a layered backup (and after a ZIP_PASSWORD_REQUIRED
    // result as a safety net), and is then required.
    var zipField = $('restoreZipPasswordField');
    var zipFieldVisible = !!(zipField && zipField.style.display !== 'none');
    var zipPw = $('restoreZipPassword') ? $('restoreZipPassword').value : '';
    if (zipFieldVisible && !zipPw) { $('restoreZipPasswordError').classList.add('show'); ok = false; }
    else $('restoreZipPasswordError').classList.remove('show');
    if (!ok) { toast('Missing information', 'Please choose a backup file and a destination folder.', 'warning'); return; }
    if (!api || typeof api.restoreAll !== 'function') { toast('Restore unavailable', 'Restore API is not available.', 'error'); return; }
    $('startBtn').disabled = true;
    $('startBtn').textContent = 'Restoring…';
    $('restoreCancelBtn').disabled = true;
    $('resultBox').style.display = 'none';
    var le0 = $('restoreLogEmpty'); if (le0) le0.style.display = '';
    $('restoreProgressCard').classList.add('show');
    var pe = $('restoreProgressEmpty'); if (pe) pe.style.display = 'none';
    // Real progress only: until the first progress event arrives the
    // bar shows "Running…" with no percentage — never a random
    // number (the old timer added Math.random()*9+3 every 350 ms).
    // Each event is a file the engine really wrote (or skipped):
    // pct = files done / files total, capped at 99% until the run
    // itself reports completion, and never decreasing (a chain
    // restore learns a new artifact's total only when it starts it).
    var pctEl = $('restoreProgressPct'); if (pctEl) pctEl.textContent = 'Running…';
    $('restoreProgressFill').style.width = '0%';
    $('restoreProgressCount').textContent = '0 files';
    $('restoreProgressFile').textContent = '';
    var maxPct = 0;
    var unsubProgress = null;
    if (api && typeof api.onRestoreProgress === 'function') {
      unsubProgress = api.onRestoreProgress(function (p) {
        if (!p) return;
        var done = Number(p.filesDone) || 0;
        var total = Number(p.filesTotal) || 0;
        if (total > 0) {
          var pct = Math.min(99, Math.floor(100 * done / total));
          if (pct > maxPct) maxPct = pct;
          setProgress(maxPct, done, p.currentFile || '');
        } else {
          // Total unknown (a layered archive's inner file count is
          // only known once it is opened): count files, no fake %.
          $('restoreProgressCount').textContent = done + ' files';
          if (p.currentFile) $('restoreProgressFile').textContent = p.currentFile;
        }
      });
    }
    try {
      // Overwrite is OFF unless the checkbox is ticked: existing
      // files are then skipped, never replaced. Verification always
      // runs (manifest/CRC) — there is no toggle for it any more.
      var ow = $('optOverwrite');
      // The first password opens the .tvb (or a plain encrypted
      // ZIP); the second opens the ZIP inside a layered .tvb.
      var result = await api.restoreAll(zipPath, dest, isEncryptedBackup ? $('restorePassword').value : null, { overwrite: !!(ow && ow.checked), zipPassword: zipPw || null });
      var files = result ? Number(result.files ?? result.restoredFiles ?? result.fileCount ?? 0) : 0;
      var skipped = result ? Number(result.files_skipped ?? result.filesSkipped ?? result.skipped ?? 0) : 0;
      setProgress(100, files, '');
      if (result && result.success === false) {
        var errMsg = result.error || result.message || 'The restore did not complete.';
        if (errMsg.indexOf('ZIP_PASSWORD_REQUIRED') === 0) {
          // Layered backup: the .tvb opened with the backup
          // password, but the ZIP inside is also password-protected.
          // Show the second (ZIP) password field — the backup
          // password stays as typed — and ask for the ZIP one.
          // The field's error line stays hidden until the user
          // actually submits without a password (the validation
          // below shows it then); showing it here as well would
          // push the page past the no-scroll limit.
          var zf = $('restoreZipPasswordField');
          if (zf) zf.style.display = 'block';
          showResult(false, 'ZIP password needed', 'Enter the ZIP password for the backup inside, then press Start Restore again.');
          toast('ZIP password needed', 'Enter the ZIP password and press Start Restore again.', 'warning');
        } else {
          showResult(false, 'Restore failed', errMsg);
          toast('Restore failed', errMsg, 'error');
        }
      } else {
        showResult(true, 'Restore completed', files + ' file' + (files === 1 ? '' : 's') + ' restored to ' + dest + '.');
        if (skipped > 0) {
          // Clear skipped line in the result box: these files were
          // left alone because they already exist (overwrite OFF).
          var line = document.createElement('div');
          line.textContent = skipped + ' file' + (skipped === 1 ? '' : 's') + ' skipped — already exist.';
          $('resultBox').appendChild(line);
        }
        toast('Restore completed', files + ' file' + (files === 1 ? '' : 's') + ' restored.' + (skipped > 0 ? ' ' + skipped + ' skipped — already exist.' : ''), 'success');
      }
      if (typeof api.refreshJobs === 'function') { try { await api.refreshJobs(); } catch (e) {} }
    } catch (e) {
      var msg = e && e.message ? e.message : 'The restore did not complete.';
      showResult(false, 'Restore failed', msg);
      toast('Restore failed', msg, 'error');
    } finally {
      if (unsubProgress) { try { unsubProgress(); } catch (e) {} unsubProgress = null; }
      $('startBtn').disabled = false;
      $('startBtn').textContent = 'Start Restore';
      $('restoreCancelBtn').disabled = false;
      setTimeout(function () {
        $('restoreProgressCard').classList.remove('show');
        var pe2 = $('restoreProgressEmpty'); if (pe2) pe2.style.display = '';
      }, 1200);
    }
  }
  function closeWizard() {
    /* In-place wizard: closing means going back to the view it was
       opened from (Dashboard or Jobs) — there is no separate window
       any more. The old closeRestoreWizard IPC is kept as a fallback. */
    if (typeof window.__closeWizardView === 'function') { window.__closeWizardView(); return; }
    if (api && typeof api.closeRestoreWizard === 'function') { api.closeRestoreWizard(); }
  }
  /* Pre-fill from the job this restore was opened from (its
     result.backup_path), if any. Runs on first wire-up and on every
     reset, so opening Restore twice does not keep stale state. */
  function loadPendingRestore() {
    if (api && typeof api.getJobConfig === 'function') {
      api.getJobConfig(null).then(function (cfg) {
        if (cfg) {
          jobInfo = {
            type: cfg.type || (cfg.job && cfg.job.type) || null,
            compression: cfg.compression || (cfg.job && cfg.job.compression) || null,
            timestamp: cfg.timestamp || (cfg.job && cfg.job.timestamp) || null
          };
        }
        if (cfg && cfg.result && cfg.result.backup_path) { $('backupFile').value = cfg.result.backup_path; checkEncrypted(cfg.result.backup_path); }
      }).catch(function () {});
    }
  }
  /* Reset the restore view to a blank state. Called every time the
     restore view opens — the old separate window reloaded its page on
     every open, so this is the in-place equivalent of that fresh
     start. Exposed for renderer.js. */
  function resetRestore() {
    jobInfo = null; isEncryptedBackup = false;
    $('backupFile').value = '';
    $('restoreTo').value = '';
    $('restorePassword').value = '';
    $('restorePasswordField').style.display = 'none';
    var zp = $('restoreZipPassword'); if (zp) zp.value = '';
    var zf = $('restoreZipPasswordField'); if (zf) zf.style.display = 'none';
    showValid(null, null);
    var ei = $('restoreInfoEmpty'); if (ei) ei.style.display = '';
    var il = $('restoreInfoList'); if (il) { il.style.display = 'none'; il.innerHTML = ''; }
    var pc = $('restoreProgressCard'); if (pc) pc.classList.remove('show');
    var pe = $('restoreProgressEmpty'); if (pe) pe.style.display = '';
    var rb = $('resultBox'); if (rb) { rb.style.display = 'none'; rb.innerHTML = ''; }
    var le = $('restoreLogEmpty'); if (le) le.style.display = '';
    var ow = $('optOverwrite'); if (ow) ow.checked = false;
    var adv = $('restoreAdvanced'); if (adv) adv.style.display = 'none';
    var abtn = $('restoreAdvancedBtn');
    if (abtn) { abtn.setAttribute('aria-expanded', 'false'); abtn.textContent = 'Advanced Options ▸'; }
    var sb = $('startBtn'); if (sb) { sb.disabled = false; sb.textContent = 'Start Restore'; }
    var cb = $('restoreCancelBtn'); if (cb) cb.disabled = false;
    setProgress(0, 0, '');
    loadPendingRestore();
  }
  // Wire immediately like the job wizard: this script sits at the end of
  // <body>, so the buttons already exist. DOMContentLoaded-only wiring was
  // the pattern that left wizard buttons dead.
  function wireRestore() {
    if (wireRestore.done) return; wireRestore.done = true;
    function on(id, ev, fn) { var el = $(id); if (el) el.addEventListener(ev, fn); }
    on('browseFile', 'click', pickFile);
    on('restoreBrowseDest', 'click', pickFolder);
    on('startBtn', 'click', startRestore);
    on('restoreCancelBtn', 'click', closeWizard);
    on('restoreAdvancedBtn', 'click', function () {
      var adv = $('restoreAdvanced'), btn = $('restoreAdvancedBtn');
      if (!adv || !btn) return;
      var open = adv.style.display === 'none';
      adv.style.display = open ? '' : 'none';
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.textContent = open ? 'Advanced Options ▾' : 'Advanced Options ▸';
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { var v = $('view-restore'); if (v && v.style.display !== 'none') closeWizard(); } });
    if (api && typeof api.getSettings === 'function') {
      api.getSettings().then(function (s) { if (s && s.theme) applyTheme(s.theme); }).catch(function () {});
    }
    // Edit/restore from History: pre-fill the backup file from the job
    // passed to the wizard (its result.backup_path).
    loadPendingRestore();
  }
  /* In-place wizard: renderer.js opens this view and calls reset(). */
  window.__restoreWizard = { reset: resetRestore };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireRestore);
  else wireRestore();
})();
