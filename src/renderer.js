/* ==========================================================================
   TechVision Backup — dashboard renderer (index.html)
   Stack: Electron + Node.js + plain JavaScript ONLY. No Java, no Python,
   no C# / .NET / WPF. No require() here — all native calls go through
   window.electronAPI, exposed by preload.js via contextBridge.
   Every field access is guarded: a malformed job entry can never crash
   the history list. Missing values render as "—", never as undefined.
   ========================================================================== */
(function () {
  'use strict';

  var api = (typeof window !== 'undefined' && window.electronAPI) ? window.electronAPI : null;

  /* ---------- small helpers ---------- */
  function $(id) { return document.getElementById(id); }
  function safeStr(v, fallback) { return (v === null || v === undefined || v === '') ? (fallback || '—') : String(v); }
  function safeNum(v, fallback) { var n = Number(v); return Number.isFinite(n) ? n : (fallback || 0); }
  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function formatBytes(bytes) {
    var n = safeNum(bytes, 0);
    if (n <= 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    var v = n / Math.pow(1024, i);
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  function formatDuration(sec) {
    var n = safeNum(sec, 0);
    if (!n) return '0.0s';
    if (n < 60) return n.toFixed(1) + 's';
    var m = Math.floor(n / 60);
    return m + 'm ' + Math.round(n % 60) + 's';
  }
  function formatDate(v) {
    if (!v) return '—';
    var d = v instanceof Date ? v : new Date(v);
    if (isNaN(d.getTime())) return safeStr(v);
    var p = function (x) { return String(x).padStart(2, '0'); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function normJob(raw) {
    raw = (raw && typeof raw === 'object') ? raw : {};
    var name = safeStr(raw.name || raw.jobName || raw.id, 'Unnamed job');
    var type = safeStr(raw.type, 'FULL').toUpperCase();
    if (type !== 'FULL' && type !== 'INCREMENTAL' && type !== 'TEMPLATE') type = 'FULL';
    var status = safeStr(raw.status, 'PENDING').toUpperCase();
    if (['COMPLETED', 'RUNNING', 'PENDING', 'FAILED', 'TEMPLATE'].indexOf(status) === -1) status = 'PENDING';
    return {
      name: name,
      type: type,
      status: status,
      source: raw.source || raw.sourceDirectory || raw.sourceDir || '',
      destination: raw.destination || raw.destinationDirectory || raw.dest || raw.output || '',
      files: safeNum(raw.files ?? raw.fileCount ?? raw.totalFiles, 0),
      size: safeNum(raw.size ?? raw.totalSize ?? raw.sizeBytes, 0),
      duration: safeNum(raw.duration ?? raw.durationSeconds ?? raw.elapsed, 0),
      timestamp: raw.timestamp || raw.lastRun || raw.date || raw.createdAt || '',
      schedule: raw.schedule || null,
      raw: raw
    };
  }

  /* ---------- state ---------- */
  var jobs = [];
  var currentJob = null;
  var settings = {};
  var progressTimer = null;

  /* ---------- toasts (never alert()) ---------- */
  function toast(title, message, kind) {
    var box = $('toasts');
    if (!box) return;
    var el = document.createElement('div');
    el.className = 'toast ' + (kind || '');
    el.innerHTML = '<div><b></b><span></span></div>';
    el.querySelector('b').textContent = title;
    el.querySelector('span').textContent = message || '';
    box.appendChild(el);
    setTimeout(function () {
      el.classList.add('leaving');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 260);
    }, 4200);
  }

  /* ---------- theme: real CSS variables, persisted ---------- */
  function applyTheme(theme) {
    var t = theme === 'light' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', t);
    var toggle = $('themeToggle');
    if (toggle) toggle.textContent = t === 'light' ? '☀️' : '🌙';
    var lightBox = $('settingLightTheme');
    if (lightBox) lightBox.checked = (t === 'light');
  }
  async function loadSettings() {
    if (!api || typeof api.getSettings !== 'function') return;
    try {
      var s = await api.getSettings();
      settings = (s && typeof s === 'object') ? s : {};
      applyTheme(settings.theme || settings.appearance || 'dark');
      if ($('settingCompress')) $('settingCompress').checked = settings.compress !== false;
      if ($('settingVerify')) $('settingVerify').checked = settings.verify !== false;
      if ($('settingIncremental')) $('settingIncremental').checked = settings.allowIncremental !== false;
    } catch (e) { /* settings are optional; keep defaults */ }
  }
  async function saveSettings() {
    if (!api || typeof api.saveSettings !== 'function') { toast('Settings', 'Settings API is not available.', 'error'); return; }
    var next = Object.assign({}, settings, {
      theme: document.body.getAttribute('data-theme') || 'dark',
      compress: $('settingCompress') ? $('settingCompress').checked : true,
      verify: $('settingVerify') ? $('settingVerify').checked : true,
      allowIncremental: $('settingIncremental') ? $('settingIncremental').checked : true
    });
    try {
      await api.saveSettings(next);
      settings = next;
      toast('Settings saved', 'Your preferences have been saved.', 'success');
    } catch (e) {
      toast('Settings failed', e && e.message ? e.message : 'Could not save settings.', 'error');
    }
  }

  /* ---------- stats from REAL history ---------- */
  function renderStats() {
    var runs = jobs.filter(function (j) { return j.type !== 'TEMPLATE'; });
    var completed = runs.filter(function (j) { return j.status === 'COMPLETED'; });
    var totalBytes = completed.reduce(function (sum, j) { return sum + j.size; }, 0);
    var last = null;
    completed.forEach(function (j) {
      var d = j.timestamp ? new Date(j.timestamp) : null;
      if (d && !isNaN(d.getTime()) && (!last || d > last)) last = d;
    });
    $('statTotal').textContent = String(completed.length);
    $('statTotalSub').textContent = completed.length ? completed.length + ' completed backup' + (completed.length === 1 ? '' : 's') : 'No backups yet';
    var mb = totalBytes / (1024 * 1024);
    $('statData').innerHTML = escapeHtml(mb >= 100 ? String(Math.round(mb)) : mb.toFixed(1)) + ' <small>MB</small>';
    $('statDataSub').textContent = formatBytes(totalBytes) + ' across all backups';
    $('statLast').textContent = last ? formatDate(last) : '—';
    $('statLastSub').textContent = last ? 'Most recent completed backup' : 'Never';
    var rate = runs.length ? Math.round((completed.length / runs.length) * 100) : null;
    $('statSuccess').textContent = rate === null ? '—' : rate + '%';
    $('statSuccessSub').textContent = rate === null ? 'No runs yet' : completed.length + ' of ' + runs.length + ' runs completed';
  }

  /* ---------- history list ---------- */
  function pillClass(status, type) {
    if (status === 'COMPLETED') return 'pill-completed';
    if (status === 'RUNNING') return 'pill-running';
    if (status === 'FAILED') return 'pill-failed';
    if (status === 'TEMPLATE' || type === 'TEMPLATE') return 'pill-template';
    return 'pill-pending';
  }
  function renderJobs() {
    var list = $('jobList');
    if (!list) return;
    var q = ($('searchInput') ? $('searchInput').value : '').trim().toLowerCase();
    var sf = $('statusFilter') ? $('statusFilter').value : 'all';
    var tf = $('typeFilter') ? $('typeFilter').value : 'all';
    var visible = jobs.filter(function (j) {
      if (q && j.name.toLowerCase().indexOf(q) === -1 && (j.source || '').toLowerCase().indexOf(q) === -1) return false;
      if (sf !== 'all' && j.status !== sf) return false;
      if (tf !== 'all' && j.type !== tf) return false;
      return true;
    });
    list.innerHTML = '';
    $('emptyState').style.display = jobs.length === 0 ? 'block' : 'none';
    if (jobs.length && visible.length === 0) {
      list.innerHTML = '<div class="empty-state"><h3>No matching backups</h3><p>Try a different search or filter.</p></div>';
      return;
    }
    visible.forEach(function (job, idx) {
      var card = document.createElement('article');
      card.className = 'job-card';
      card.style.animationDelay = Math.min(idx * 0.05, 0.3) + 's';
      var initial = escapeHtml((job.name || 'T').charAt(0).toUpperCase());
      card.innerHTML =
        '<div class="job-icon">' + initial + '</div>' +
        '<div class="job-body">' +
          '<h3 class="job-name"></h3>' +
          '<div class="job-meta"><span>Type: <b></b></span><span>Files: <b></b></span><span>Size: <b></b></span><span>Duration: <b></b></span><span class="date"></span></div>' +
          '<div class="job-path"></div>' +
        '</div>' +
        '<div class="job-actions"><span class="pill"></span><div class="job-actions-row">' +
          '<button class="btn btn-sm" type="button" data-act="details">Details</button>' +
          '<button class="btn btn-sm" type="button" data-act="run">▶ Run</button>' +
          '<button class="btn btn-sm" type="button" data-act="restore">↺ Restore</button>' +
        '</div></div>';
      card.querySelector('.job-name').textContent = job.name;
      var meta = card.querySelectorAll('.job-meta b');
      meta[0].textContent = job.type;
      meta[1].textContent = String(job.files);
      meta[2].textContent = formatBytes(job.size);
      meta[3].textContent = formatDuration(job.duration);
      card.querySelector('.job-meta .date').textContent = formatDate(job.timestamp);
      card.querySelector('.job-path').textContent = job.source ? job.source + '  →  ' + (job.destination || '—') : (job.destination || '');
      var pill = card.querySelector('.pill');
      pill.className = 'pill ' + pillClass(job.status, job.type);
      pill.textContent = job.status;
      card.querySelector('.job-body').addEventListener('click', function () { openDrawer(job); });
      card.querySelectorAll('[data-act]').forEach(function (btn) {
        btn.addEventListener('click', function (ev) {
          ev.stopPropagation();
          var act = btn.getAttribute('data-act');
          if (act === 'details') openDrawer(job);
          if (act === 'run') runBackup(job, false);
          if (act === 'restore') openRestore(job);
        });
      });
      list.appendChild(card);
    });
  }

  /* ---------- job details drawer ---------- */
  function openDrawer(job) {
    currentJob = job;
    $('drawerName').textContent = job.name;
    $('drawerPills').innerHTML = '';
    var p1 = document.createElement('span');
    p1.className = 'pill ' + pillClass(job.status, job.type);
    p1.textContent = job.status;
    var p2 = document.createElement('span');
    p2.className = 'pill ' + (job.type === 'INCREMENTAL' ? 'pill-incremental' : 'pill-full');
    p2.textContent = job.type;
    $('drawerPills').appendChild(p1);
    $('drawerPills').appendChild(p2);
    $('drawerSource').textContent = job.source || '—';
    $('drawerDest').textContent = job.destination || '—';
    $('drawerType').textContent = job.type;
    $('drawerStatus').textContent = job.status;
    $('drawerFiles').textContent = String(job.files);
    $('drawerSize').textContent = formatBytes(job.size);
    $('drawerDuration').textContent = formatDuration(job.duration);
    $('drawerLastRun').textContent = formatDate(job.timestamp);
    $('jobDrawer').classList.add('show');
    $('drawerBackdrop').classList.add('show');
  }
  function closeDrawer() {
    $('jobDrawer').classList.remove('show');
    $('drawerBackdrop').classList.remove('show');
    currentJob = null;
  }
  function openSettings() {
    $('settingsDrawer').classList.add('show');
    $('settingsBackdrop').classList.add('show');
  }
  function closeSettings() {
    $('settingsDrawer').classList.remove('show');
    $('settingsBackdrop').classList.remove('show');
  }

  /* ---------- progress card ---------- */
  function showProgress(title) {
    $('progressTitle').textContent = title;
    $('progressPct').textContent = '0%';
    $('progressFill').style.width = '0%';
    $('progressCount').textContent = 'Starting…';
    $('progressSize').textContent = '';
    $('progressFile').textContent = '';
    $('progressCard').classList.add('show');
    setProgressButtons(true);
  }
  function setProgress(pct, files, size, fileName) {
    var p = Math.max(0, Math.min(100, safeNum(pct, 0)));
    $('progressPct').textContent = Math.round(p) + '%';
    $('progressFill').style.width = p + '%';
    if (files !== undefined) $('progressCount').textContent = files + ' files';
    if (size !== undefined) $('progressSize').textContent = formatBytes(size);
    if (fileName !== undefined) $('progressFile').textContent = fileName;
  }
  function hideProgress() {
    $('progressCard').classList.remove('show');
    setProgressButtons(false);
  }
  function setProgressButtons(disabled) {
    ['newJobBtn', 'restoreBtn', 'refreshBtn'].forEach(function (id) {
      var b = $(id);
      if (b) b.disabled = disabled;
    });
    var dr = $('drawerRun');
    if (dr) dr.disabled = disabled;
  }
  /* Simulated in-page progress while the main process works.
     The real result still comes from the IPC reply; this only keeps
     the user informed that the operation is running. */
  function simulateProgress(label, done) {
    var pct = 0;
    clearInterval(progressTimer);
    progressTimer = setInterval(function () {
      pct = Math.min(92, pct + Math.random() * 9 + 3);
      setProgress(pct);
    }, 350);
    return function stop() { clearInterval(progressTimer); };
  }

  /* ---------- backup / restore actions ---------- */
  async function runBackup(job, incremental) {
    if (!job) return;
    if (!api || typeof api.runFullBackup !== 'function') { toast('Backup unavailable', 'Backup API is not available.', 'error'); return; }
    closeDrawer();
    showProgress(incremental ? 'Running incremental backup…' : 'Running full backup…');
    var stop = simulateProgress();
    try {
      var result = incremental && typeof api.runIncrementalBackup === 'function'
        ? await api.runIncrementalBackup(job.raw || job)
        : await api.runFullBackup(job.raw || job);
      stop();
      setProgress(100, result && result.files, result && result.size);
      var files = result ? safeNum(result.files ?? result.fileCount, 0) : 0;
      setTimeout(function () { hideProgress(); }, 900);
      if (result && result.success === false) {
        toast('Backup failed', result.error || result.message || 'The backup did not complete.', 'error');
      } else {
        toast('Backup completed', job.name + ' — ' + files + ' file' + (files === 1 ? '' : 's') + ' backed up.', 'success');
      }
      await loadJobs();
    } catch (e) {
      stop();
      hideProgress();
      toast('Backup failed', e && e.message ? e.message : 'The backup did not complete.', 'error');
    }
  }
  async function openRestore(job) {
    if (!api || typeof api.showRestoreWizard !== 'function') { toast('Restore unavailable', 'Restore API is not available.', 'error'); return; }
    try { await api.showRestoreWizard(job ? (job.raw || job) : null); }
    catch (e) { toast('Restore failed', e && e.message ? e.message : 'Could not open Restore.', 'error'); }
  }
  async function openJobWizard(job) {
    if (!api || typeof api.showJobWizard !== 'function') { toast('New Job unavailable', 'Job wizard API is not available.', 'error'); return; }
    try { await api.showJobWizard(job ? (job.raw || job) : null); }
    catch (e) { toast('New Job failed', e && e.message ? e.message : 'Could not open the job wizard.', 'error'); }
  }

  /* ---------- load jobs ---------- */
  async function loadJobs() {
    if (!api || typeof api.getJobHistory !== 'function') {
      jobs = [];
      renderStats();
      renderJobs();
      return;
    }
    try {
      var data = await api.getJobHistory();
      var arr = Array.isArray(data) ? data : (data && Array.isArray(data.jobs) ? data.jobs : (data && Array.isArray(data.history) ? data.history : []));
      jobs = arr.map(normJob);
    } catch (e) {
      toast('Could not load history', e && e.message ? e.message : 'History could not be loaded.', 'error');
      jobs = [];
    }
    renderStats();
    renderJobs();
  }
  async function refreshJobs() {
    if (api && typeof api.refreshJobs === 'function') {
      try { await api.refreshJobs(); } catch (e) { /* fall through to reload */ }
    }
    await loadJobs();
  }

  /* ---------- wiring ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    $('newJobBtn').addEventListener('click', function () { openJobWizard(null); });
    $('emptyNewJobBtn').addEventListener('click', function () { openJobWizard(null); });
    $('restoreBtn').addEventListener('click', function () { openRestore(null); });
    $('navRestore').addEventListener('click', function () { openRestore(null); });
    $('refreshBtn').addEventListener('click', refreshJobs);
    $('searchInput').addEventListener('input', renderJobs);
    $('statusFilter').addEventListener('change', renderJobs);
    $('typeFilter').addEventListener('change', renderJobs);
    $('themeToggle').addEventListener('click', async function () {
      var next = document.body.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      applyTheme(next);
      if (api && typeof api.saveSettings === 'function') {
        try { await api.saveSettings(Object.assign({}, settings, { theme: next })); settings.theme = next; } catch (e) { /* theme already applied visually */ }
      }
    });
    $('settingsBtn').addEventListener('click', openSettings);
    $('settingsClose').addEventListener('click', closeSettings);
    $('settingsBackdrop').addEventListener('click', closeSettings);
    $('settingsSave').addEventListener('click', async function () { await saveSettings(); closeSettings(); });
    $('settingLightTheme').addEventListener('change', function (ev) { applyTheme(ev.target.checked ? 'light' : 'dark'); });
    $('clearHistoryBtn').addEventListener('click', async function () {
      if (!api || typeof api.clearJobHistory !== 'function') return;
      try { await api.clearJobHistory(); await loadJobs(); toast('History cleared', 'Backup history has been cleared.', 'success'); }
      catch (e) { toast('Clear failed', e && e.message ? e.message : 'History could not be cleared.', 'error'); }
    });
    document.querySelectorAll('[data-nav]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var nav = btn.getAttribute('data-nav');
        document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
        btn.classList.add('active');
        if (nav === 'settings') openSettings();
        if (nav === 'logs') toast('Logs', 'Open the Log Viewer from the Logs window.', '');
        if (nav === 'jobs') { var el = $('jobList'); if (el) el.scrollIntoView({ behavior: 'smooth' }); }
        if (nav === 'dashboard') { var m = document.querySelector('.main'); if (m) m.scrollIntoView({ behavior: 'smooth' }); }
      });
    });
    $('drawerClose').addEventListener('click', closeDrawer);
    $('drawerBackdrop').addEventListener('click', closeDrawer);
    $('drawerRun').addEventListener('click', function () { if (currentJob) runBackup(currentJob, false); });
    $('drawerRestore').addEventListener('click', function () { if (currentJob) openRestore(currentJob); });
    $('drawerEdit').addEventListener('click', function () { if (currentJob) { closeDrawer(); openJobWizard(currentJob); } });
    $('drawerDelete').addEventListener('click', async function () {
      if (!currentJob) return;
      toast('Delete', 'Delete is handled by the main process job store. Use Edit to change a job, or Clear History in Settings.', 'warning');
      closeDrawer();
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeDrawer(); closeSettings(); } });

    loadSettings().then(loadJobs);
  });
})();
