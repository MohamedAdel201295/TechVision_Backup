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
    var job = {
      id: raw.id || raw.jobId || '',
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
      compression: raw.compression || (raw.compress === false ? 'none' : 'standard'),
      runs: Array.isArray(raw.runs) ? raw.runs : [],
      runCount: raw.runCount ?? (Array.isArray(raw.runs) ? raw.runs.length : 0),
      raw: raw
    };
    if (job.runs && job.runs.length) {
      var last = job.runs[job.runs.length - 1];
      job.status = (last.status || job.status || 'PENDING').toUpperCase();
      job.files = safeNum(last.files, job.files);
      job.size = safeNum(last.size, job.size);
      job.duration = safeNum(last.duration, job.duration);
      job.timestamp = last.timestamp || job.timestamp;
    }
    return job;
  }

  /* ---------- state ---------- */
  var jobs = [];
  var currentJob = null;
  var settings = {};
  var currentLogTab = 'today';
  var logsTimer = null;
  var fullLogLines = [];

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
      if ($('settingAutoStart')) $('settingAutoStart').checked = settings.autoStart !== false;
      var em = (settings.email && typeof settings.email === 'object') ? settings.email : {};
      if ($('settingEmailEnabled')) $('settingEmailEnabled').checked = em.enabled === true;
      if ($('settingEmailStart')) $('settingEmailStart').checked = em.notifyOnStart !== false;
      if ($('settingEmailFinish')) $('settingEmailFinish').checked = em.notifyOnFinish !== false;
      if ($('settingEmailMissed')) $('settingEmailMissed').checked = em.notifyOnMissed !== false;
      if ($('settingEmailTo')) $('settingEmailTo').value = em.to || '';
      if ($('settingEmailUser')) $('settingEmailUser').value = em.smtpUser || '';
      if ($('settingEmailPass')) $('settingEmailPass').value = em.smtpPass || '';
      if ($('settingEmailHost')) $('settingEmailHost').value = em.smtpHost || 'smtp.gmail.com';
      if ($('settingEmailPort')) $('settingEmailPort').value = String(em.smtpPort || 465);
      if ($('settingVerify')) $('settingVerify').checked = settings.verify !== false;
      if ($('settingIncremental')) $('settingIncremental').checked = settings.allowIncremental !== false;
      refreshEmailMenuStatus();
    } catch (e) { /* settings are optional; keep defaults */ }
  }
  async function saveSettings() {
    if (!api || typeof api.saveSettings !== 'function') { toast('Settings', 'Settings API is not available.', 'error'); return; }
    var next = Object.assign({}, settings, {
      theme: document.body.getAttribute('data-theme') || 'dark',
      compress: $('settingCompress') ? $('settingCompress').checked : true,
      verify: $('settingVerify') ? $('settingVerify').checked : true,
      allowIncremental: $('settingIncremental') ? $('settingIncremental').checked : true,
      autoStart: $('settingAutoStart') ? $('settingAutoStart').checked : true,
      email: {
        enabled: $('settingEmailEnabled') ? $('settingEmailEnabled').checked : false,
        notifyOnStart: $('settingEmailStart') ? $('settingEmailStart').checked : true,
        notifyOnFinish: $('settingEmailFinish') ? $('settingEmailFinish').checked : true,
        notifyOnMissed: $('settingEmailMissed') ? $('settingEmailMissed').checked : true,
        to: $('settingEmailTo') ? $('settingEmailTo').value.trim() : '',
        smtpUser: $('settingEmailUser') ? $('settingEmailUser').value.trim() : '',
        smtpPass: $('settingEmailPass') ? $('settingEmailPass').value : '',
        smtpHost: $('settingEmailHost') ? $('settingEmailHost').value.trim() || 'smtp.gmail.com' : 'smtp.gmail.com',
        smtpPort: $('settingEmailPort') ? parseInt($('settingEmailPort').value, 10) || 465 : 465
      }
    });
    try {
      await api.saveSettings(next);
      settings = next;
      refreshEmailMenuStatus();
      toast('Settings saved', 'Your preferences have been saved.', 'success');
    } catch (e) {
      toast('Settings failed', e && e.message ? e.message : 'Could not save settings.', 'error');
    }
  }

  /* ---------- Yes/No confirm dialog ---------- */
  var confirmCallback = null;
  function askConfirm(message, onYes) {
    var modal = $('confirmModal'); var back = $('confirmBackdrop');
    if (!modal) { if (window.confirm(message)) onYes(); return; }
    $('confirmText').textContent = message;
    confirmCallback = onYes;
    modal.style.display = 'block';
    if (back) back.classList.add('show');
  }
  function closeConfirm() {
    var modal = $('confirmModal'); var back = $('confirmBackdrop');
    if (modal) modal.style.display = 'none';
    if (back) back.classList.remove('show');
    confirmCallback = null;
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

  /* ---------- views: Dashboard / Jobs ---------- */
  /* ---------- modules: Backup / Cloud / VPN ----------
     The sidebar has three top-level modules. Backup owns Dashboard, Jobs,
     Logs, New Job and Restore; Cloud owns Server and Client; VPN is a
     single Tailscale view. Switching modules swaps the visible nav
     group; going back to Backup returns to the last backup view instead
     of always resetting to Dashboard. */
  var currentModule = 'backup';
  var lastBackupView = 'dashboard';

  function applyModuleUI(mod) {
    currentModule = mod;
    var gb = $('navGroupBackup'); if (gb) gb.style.display = mod === 'backup' ? '' : 'none';
    var gc = $('navGroupCloud'); if (gc) gc.style.display = mod === 'cloud' ? '' : 'none';
    var gv = $('navGroupVpn'); if (gv) gv.style.display = mod === 'vpn' ? '' : 'none';
    document.querySelectorAll('.module-item').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-module') === mod); });
  }

  function setModule(mod) {
    applyModuleUI(mod);
    if (mod === 'backup') showView(lastBackupView || 'dashboard');
    else if (mod === 'cloud') showView('cloud');
    else if (mod === 'vpn') showView('vpn');
  }

  function syncCloudNav() {
    document.querySelectorAll('[data-nav="cloud-server"], [data-nav="cloud-client"]').forEach(function (b) { b.classList.remove('active'); });
    if (cloudPanel === 'server' || cloudPanel === 'client') {
      var btn = document.querySelector('[data-nav="cloud-' + cloudPanel + '"]');
      if (btn) btn.classList.add('active');
    }
  }

  function setBackTitle(t) { var b = $('backBarTitle'); if (b) b.textContent = t; }
  function setAppTitle(t, s) { var h = $('appTitle'); if (h) h.textContent = t; var p = $('appSubtitle'); if (p) p.textContent = s; }

  /* Back from the very top: from a Server/Client panel back to the
     Cloud home, from anywhere else back to the module chooser. */
  function goBack() {
    var cloudView = $('view-cloud');
    if (cloudView && cloudView.style.display !== 'none' && (cloudPanel === 'server' || cloudPanel === 'client')) { showCloudPanel('home'); return; }
    showView('modules');
  }

  function showView(name) {
    var dash = $('view-dashboard'); var jobsView = $('view-jobs'); var logsView = $('view-logs'); var cloudView = $('view-cloud');
    var vpnView = $('view-vpn');
    var modulesView = $('view-modules');
    if (dash) dash.style.display = name === 'dashboard' ? '' : 'none';
    if (jobsView) jobsView.style.display = name === 'jobs' ? '' : 'none';
    if (logsView) logsView.style.display = name === 'logs' ? '' : 'none';
    if (cloudView) cloudView.style.display = name === 'cloud' ? '' : 'none';
    if (vpnView) vpnView.style.display = name === 'vpn' ? '' : 'none';
    if (modulesView) modulesView.style.display = name === 'modules' ? '' : 'none';
    document.body.classList.toggle('modules-mode', name === 'modules');
    var bb = $('backBar'); if (bb) bb.style.display = name === 'modules' ? 'none' : '';
    var hdr = $('appHeader'); if (hdr) hdr.style.display = name === 'modules' ? 'none' : '';
    /* Inside a module only that module's things show: the module
       switcher (Backup / Cloud buttons) is hidden, the way back out
       is the top Back button. */
    var ms = $('moduleSwitcher'); if (ms) ms.style.display = name === 'modules' ? '' : 'none';
    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
    var btn = document.querySelector('[data-nav="' + name + '"]');
    if (btn) btn.classList.add('active');
    if (name === 'jobs') renderJobsView();
    if (name === 'logs') { renderLogs(currentLogTab); startLogsAutoRefresh(); }
    else stopLogsAutoRefresh();
    if (name === 'dashboard' || name === 'jobs' || name === 'logs') {
      lastBackupView = name; applyModuleUI('backup');
      setBackTitle('Backup');
      setAppTitle('TechVision Backup', 'Your data, protected — full and incremental backups, fast streaming restore.');
    }
    if (name === 'cloud') {
      applyModuleUI('cloud'); syncCloudNav();
      setBackTitle(cloudPanel === 'server' ? 'Cloud — Server' : cloudPanel === 'client' ? 'Cloud — Client' : 'Cloud');
      setAppTitle('TechVision Cloud', 'Your own remote drive — share a folder or open one, encrypted.');
      loadCloud();
    }
    if (name === 'vpn') {
      applyModuleUI('vpn');
      setBackTitle('VPN');
      setAppTitle('TechVision VPN', 'Your private network — every device, anywhere, as if it were home.');
      loadVpn();
    }
  }
  function startLogsAutoRefresh() {
    stopLogsAutoRefresh();
    logsTimer = setInterval(function () { renderLogs(currentLogTab); }, 10000);
  }
  function stopLogsAutoRefresh() {
    if (logsTimer) { clearInterval(logsTimer); logsTimer = null; }
  }

  /* ---------- Logs view: Today / Completed / Failed / Full log ---------- */
  function collectRuns() {
    var out = [];
    jobs.forEach(function (job) {
      (job.runs || []).forEach(function (run) {
        out.push({ job: job, run: run });
      });
    });
    out.sort(function (a, b) {
      return new Date(b.run.timestamp || 0) - new Date(a.run.timestamp || 0);
    });
    return out;
  }
  function isToday(ts) {
    var d = new Date(ts); if (isNaN(d.getTime())) return false;
    var n = new Date();
    return d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth() && d.getDate() === n.getDate();
  }
  function waitingOf(job) { return job.waitingForDrive || (job.raw && job.raw.waitingForDrive) || null; }
  function logLevelOf(text) {
    var s = String(text || '').toUpperCase();
    if (s.indexOf('ERROR') !== -1 || s.indexOf('FAIL') !== -1) return 'ERROR';
    if (s.indexOf('WARN') !== -1 || s.indexOf('SKIPPED') !== -1) return 'WARN';
    if (s.indexOf('SUCCESS') !== -1 || s.indexOf('COMPLETED') !== -1) return 'SUCCESS';
    return 'INFO';
  }
  function runRow(item, extraStatus) {
    var job = item.job, run = item.run;
    var div = document.createElement('article');
    div.className = 'job-card';
    var status = extraStatus || String((run.status || (run.success ? 'COMPLETED' : 'FAILED'))).toUpperCase();
    var body = document.createElement('div'); body.className = 'job-body';
    var h = document.createElement('h3'); h.className = 'job-name'; h.textContent = job.name;
    var meta = document.createElement('div'); meta.className = 'job-meta';
    var pill = document.createElement('span'); pill.className = 'pill ' + pillClass(status, run.type || 'full'); pill.textContent = status;
    var when = document.createElement('span'); when.textContent = ' ' + formatDate(run.timestamp);
    var files = document.createElement('span'); files.textContent = ' ' + safeNum(run.files, 0) + ' files · ' + formatBytes(run.size);
    meta.appendChild(pill); meta.appendChild(when); meta.appendChild(files);
    body.appendChild(h); body.appendChild(meta);
    var pathLine = document.createElement('div'); pathLine.className = 'job-path';
    pathLine.textContent = (job.source || '—') + '  →  ' + (job.destination || '—');
    body.appendChild(pathLine);
    if (run.error) {
      var err = document.createElement('div'); err.className = 'log-run-error'; err.textContent = run.error;
      body.appendChild(err);
    }
    if (extraStatus === 'WAITING' && item.waiting) {
      var w = item.waiting;
      var wdiv = document.createElement('div'); wdiv.className = 'job-waiting';
      wdiv.textContent = '⏳ Waiting for the ' + (w.which || 'source') + ' drive since ' + formatDate(w.since) + ' — ' + (w.path || '') + (w.label ? ' (volume "' + w.label + '")' : '') + '. The job runs as soon as the disk is back.';
      body.appendChild(wdiv);
    }
    div.appendChild(body);
    return div;
  }
  function renderLogs(tab) {
    currentLogTab = tab || currentLogTab;
    var list = $('logsList'); var fullBox = $('logsFullBox'); var toolbar = $('logsToolbar');
    var empty = $('logsEmptyState'); var emptyText = $('logsEmptyText');
    if (!list) return;
    document.querySelectorAll('#logsTabs .log-tab').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-logtab') === currentLogTab);
    });
    var isFull = currentLogTab === 'full';
    if (toolbar) toolbar.style.display = isFull ? '' : 'none';
    if (fullBox) fullBox.style.display = isFull ? '' : 'none';
    list.style.display = isFull ? 'none' : '';
    if (isFull) { loadFullLog(); if (empty) empty.style.display = 'none'; return; }
    var runs = collectRuns();
    var items = [];
    if (currentLogTab === 'today') {
      items = runs.filter(function (it) { return isToday(it.run.timestamp); });
      if (emptyText) emptyText.textContent = 'No tasks ran today yet.';
    } else if (currentLogTab === 'completed') {
      items = runs.filter(function (it) { return it.run.success === true || String(it.run.status || '').toUpperCase() === 'COMPLETED'; });
      if (emptyText) emptyText.textContent = 'No completed backups yet.';
    } else if (currentLogTab === 'failed') {
      items = runs.filter(function (it) { return it.run.success === false || String(it.run.status || '').toUpperCase() === 'FAILED'; });
      // Jobs still waiting for their drive belong here too — they have
      // not run, and the user asked to see what did not happen.
      jobs.forEach(function (job) {
        var w = waitingOf(job);
        if (w) items.push({ job: job, run: { status: 'WAITING', timestamp: w.since, files: 0, size: 0 }, waiting: w });
      });
      items.sort(function (a, b) { return new Date(b.run.timestamp || 0) - new Date(a.run.timestamp || 0); });
      if (emptyText) emptyText.textContent = 'No failed or waiting tasks. Everything ran fine.';
    }
    list.innerHTML = '';
    if (!items.length) { if (empty) empty.style.display = 'block'; return; }
    if (empty) empty.style.display = 'none';
    items.forEach(function (it) {
      var status = it.waiting ? 'WAITING' : null;
      list.appendChild(runRow(it, status));
    });
  }
  async function loadFullLog() {
    var box = $('logsFullBox'); if (!box) return;
    if (!api || typeof api.getAppLog !== 'function') {
      box.textContent = 'Log API is not available.';
      return;
    }
    try {
      var res = await api.getAppLog();
      fullLogLines = (res && Array.isArray(res.lines)) ? res.lines : [];
    } catch (e) { fullLogLines = ['[ERROR] Could not load the log: ' + (e && e.message ? e.message : 'unknown error')]; }
    renderFullLog();
  }
  function renderFullLog() {
    var box = $('logsFullBox'); if (!box) return;
    var level = $('logsLevelFilter') ? $('logsLevelFilter').value : 'all';
    var q = $('logsSearch') ? $('logsSearch').value.trim().toLowerCase() : '';
    var visible = fullLogLines.filter(function (l) {
      if (level !== 'all' && logLevelOf(l) !== level) return false;
      if (q && String(l).toLowerCase().indexOf(q) === -1) return false;
      return true;
    });
    box.innerHTML = '';
    if (!visible.length) {
      box.textContent = fullLogLines.length ? 'No log lines match this filter.' : 'No log lines yet. Run a backup or wait for a scheduled one to see activity here.';
      return;
    }
    visible.forEach(function (l) {
      var div = document.createElement('div');
      div.className = 'log-line log-' + logLevelOf(l).toLowerCase();
      div.textContent = String(l);
      box.appendChild(div);
    });
    box.scrollTop = box.scrollHeight;
  }
  function compressionLabel(job) {
    var c = (job.compression || (job.raw && job.raw.compression) || 'standard').toLowerCase();
    if (c === 'none') return 'No compression — plain files';
    if (c === 'advanced') return 'Advanced (max compression)';
    return 'Standard compression';
  }
  function renderJobsView() {
    var list = $('jobsList');
    if (!list) return;
    // Jobs page = the jobs whose turn it is to run: never run yet, or
    // scheduled for a next run. A job that already ran and has no
    // schedule is done — it stays in the Dashboard history only.
    var upcoming = jobs.filter(function (j) {
      var neverRun = !j.runs || j.runs.length === 0;
      var sched = j.schedule && j.schedule.enabled;
      return neverRun || sched;
    });
    list.innerHTML = '';
    var empty = $('jobsEmptyState');
    if (empty) empty.style.display = upcoming.length === 0 ? 'block' : 'none';
    upcoming.forEach(function (job, idx) {
      var card = document.createElement('article');
      card.className = 'job-card';
      card.style.animationDelay = Math.min(idx * 0.05, 0.3) + 's';
      var initial = escapeHtml((job.name || 'T').charAt(0).toUpperCase());
      card.innerHTML =
        '<div class="job-icon">' + initial + '</div>' +
        '<div class="job-body">' +
          '<h3 class="job-name"></h3>' +
          '<div class="job-meta"><span class="pill"></span><span>Last run: <b class="last-run"></b></span><span>Runs: <b class="run-count"></b></span></div>' +
          '<div class="job-path"></div>' +
          '<dl class="job-detail">' +
            '<div><dt>Schedule</dt><dd class="d-schedule"></dd></div>' +
            '<div><dt>Next run</dt><dd class="d-next"></dd></div>' +
            '<div><dt>Compression</dt><dd class="d-compress"></dd></div>' +
            '<div><dt>Last run files</dt><dd class="d-files"></dd></div>' +
          '</dl>' +
        '</div>' +
        '<div class="job-actions"><div class="job-actions-row">' +
          '<button class="btn btn-primary btn-sm" type="button" data-act="run">▶ Run now</button>' +
          '<button class="btn btn-sm" type="button" data-act="details">Details</button>' +
          '<button class="btn btn-sm" type="button" data-act="edit">✎ Edit</button>' +
          '<button class="btn btn-sm" type="button" data-act="restore">↺ Restore</button>' +
          '<button class="btn btn-danger btn-sm" type="button" data-act="delete">🗑 Delete</button>' +
        '</div></div>';
      card.querySelector('.job-name').textContent = job.name;
      var pill = card.querySelector('.pill');
      pill.className = 'pill ' + pillClass(job.status, job.type);
      pill.textContent = job.status;
      card.querySelector('.last-run').textContent = job.runs && job.runs.length ? formatDate(job.timestamp) : 'Never run';
      card.querySelector('.run-count').textContent = String(job.runCount || 0);
      card.querySelector('.job-path').textContent = job.source ? job.source + '  →  ' + (job.destination || '—') : (job.destination || '—');
      var w = waitingOf(job);
      if (w) {
        var wdiv = document.createElement('div');
        wdiv.className = 'job-waiting';
        wdiv.textContent = '⏳ Waiting for the ' + (w.which || 'source') + ' drive since ' + formatDate(w.since) + ' — ' + (w.path || '') + (w.label ? ' (volume "' + w.label + '")' : '');
        card.querySelector('.job-body').appendChild(wdiv);
      }
      var sched = job.schedule || (job.raw && job.raw.schedule) || null;
      card.querySelector('.d-schedule').textContent = sched && sched.enabled ? (sched.frequency || 'Daily') + ' at ' + (sched.time || '02:00') : 'Manual only';
      card.querySelector('.d-next').textContent = nextRunText(job);
      card.querySelector('.d-compress').textContent = compressionLabel(job);
      card.querySelector('.d-files').textContent = job.runs && job.runs.length ? job.files + ' files · ' + formatBytes(job.size) : '—';
      card.querySelectorAll('[data-act]').forEach(function (btn) {
        btn.addEventListener('click', async function (ev) {
          ev.stopPropagation();
          var act = btn.getAttribute('data-act');
          if (act === 'details') openDrawer(job);
          if (act === 'run') runBackup(job, false);
          if (act === 'edit') openJobWizard(job);
          if (act === 'restore') openRestore(job);
          if (act === 'delete') {
            if (!api || typeof api.deleteJob !== 'function') return;
            try {
              var res = await api.deleteJob(job.id);
              if (res && res.success) { toast('Job deleted', job.name + ' has been deleted.', 'success'); await refreshJobs(); }
              else toast('Delete failed', (res && res.error) || 'Could not delete job.', 'error');
            } catch (e) { toast('Delete error', e && e.message ? e.message : 'Could not delete job.', 'error'); }
          }
        });
      });
      list.appendChild(card);
    });
  }

  /* ---------- TechVision Cloud ---------- */
  var cloudCfg = null;           // last cloud-get-config result
  var cloudPanel = 'home';       // 'home' | 'server' | 'client'
  var cloudSelected = null;      // saved server record being connected to
  var cloudPendingProbe = null;  // { fingerprint, certPem } awaiting trust
  var cloudConn = null;          // { serverId, info } while connected
  var cloudPath = '';            // current remote path, '' = root, '/' separators
  var cloudTransferTimer = null;

  function cloudMissing() {
    toast('Cloud unavailable', 'Cloud API is not available in this build.', 'error');
    return true;
  }

  async function loadCloud() {
    if (!api || typeof api.cloudGetConfig !== 'function') return;
    try {
      cloudCfg = await api.cloudGetConfig();
      renderCloudHome();
      if (cloudPanel === 'server') renderCloudServer();
      if (cloudPanel === 'client') renderCloudClientList();
    } catch (e) {
      toast('Cloud', e && e.message ? e.message : 'Could not load Cloud settings.', 'error');
    }
  }

  function showCloudPanel(panel) {
    cloudPanel = panel;
    var modes = $('cloudModes'); if (modes) modes.style.display = panel === 'home' ? '' : 'none';
    var sp = $('cloudServerPanel'); if (sp) sp.style.display = panel === 'server' ? '' : 'none';
    var cp = $('cloudClientPanel'); if (cp) cp.style.display = panel === 'client' ? '' : 'none';
    if (panel === 'server') renderCloudServer();
    if (panel === 'client') { renderCloudClientList(); if (cloudClientAccess === 'tailscale') populateCloudPeers(); }
    syncCloudNav();
    setBackTitle(panel === 'server' ? 'Cloud — Server' : panel === 'client' ? 'Cloud — Client' : 'Cloud');
  }

  function renderCloudHome() {
    if (!cloudCfg) return;
    var s = cloudCfg.server || {};
    var ss = $('cloudServerModeStatus');
    if (ss) ss.textContent = s.running ? ('Running — port ' + (s.port || 8443)) : 'Stopped';
    var cs = $('cloudClientModeStatus');
    if (cs) cs.textContent = cloudConn ? ('Connected as ' + (cloudConn.info.user || '') + ' @ ' + (cloudConn.name || '')) : 'Not connected';
  }

  /* ---------- Cloud access: Normal vs Tailscale VPN ----------
     The server and the client each have two ways to reach each other.
     Normal = public IP / DDNS + port forwarding. Tailscale = the
     server's 100.x address on the private Tailscale network, no port
     forwarding. The server itself listens on all interfaces either way;
     the mode only changes what the UI shows and what gets saved. */
  var cloudServerAccess = 'normal';
  var cloudClientAccess = 'normal';

  function setServerAccess(mode) {
    cloudServerAccess = mode === 'tailscale' ? 'tailscale' : 'normal';
    document.querySelectorAll('#cloudServerAccessSeg .seg-btn').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-access') === cloudServerAccess); });
    var hint = $('cloudServerAccessHint');
    if (hint) hint.textContent = cloudServerAccess === 'tailscale'
      ? 'Clients on the same Tailscale network use the Tailscale address below + this port. No port forwarding needed.'
      : 'Clients use your public static IP or DDNS + this port (forward the port in your router).';
    var ti = $('cloudTailscaleInfo'); if (ti) ti.style.display = cloudServerAccess === 'tailscale' ? '' : 'none';
    var fg = $('cloudForwardGuide'); if (fg) fg.style.display = cloudServerAccess === 'tailscale' ? 'none' : '';
    if (cloudServerAccess === 'tailscale') refreshCloudTailscaleIp();
  }

  async function refreshCloudTailscaleIp() {
    var el = $('cloudTailscaleIp'); if (!el) return;
    if (!api || typeof api.vpnGetStatus !== 'function') { el.textContent = 'VPN module is not available.'; return; }
    el.textContent = 'Checking Tailscale…';
    try {
      var st = await api.vpnGetStatus();
      if (!st || !st.installed) el.textContent = 'Tailscale is not installed — install it from the VPN module.';
      else if (!st.connected) el.textContent = 'Tailscale is not connected on this computer — connect it from the VPN module.';
      else el.textContent = (st.selfIp || '—') + (st.tailnet ? '  (' + st.tailnet + ')' : '') + ' — give clients this address + port ' + String((cloudCfg && cloudCfg.server && cloudCfg.server.port) || 8443) + '.';
    } catch (e) { el.textContent = 'Could not read Tailscale status.'; }
  }

  function setClientAccess(mode) {
    cloudClientAccess = mode === 'tailscale' ? 'tailscale' : 'normal';
    document.querySelectorAll('#cloudClientAccessSeg .seg-btn').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-access') === cloudClientAccess); });
    var hint = $('cloudClientAccessHint');
    if (hint) hint.textContent = cloudClientAccess === 'tailscale'
      ? 'Tailscale IP (100.x.x.x) of the server — pick a device below or type it.'
      : 'Public IP, DDNS hostname or LAN IP of the server.';
    var host = $('cloudClientHost');
    if (host) host.placeholder = cloudClientAccess === 'tailscale' ? '100.64.0.1' : '203.0.113.10';
    var pf = $('cloudClientPeerField'); if (pf) pf.style.display = cloudClientAccess === 'tailscale' ? '' : 'none';
    if (cloudClientAccess === 'tailscale') populateCloudPeers();
  }

  async function populateCloudPeers() {
    var sel = $('cloudClientPeer'); if (!sel) return;
    sel.innerHTML = '';
    var opt0 = document.createElement('option'); opt0.value = ''; opt0.textContent = 'Checking Tailscale…';
    sel.appendChild(opt0);
    if (!api || typeof api.vpnGetStatus !== 'function') { opt0.textContent = 'VPN module is not available.'; return; }
    try {
      var st = await api.vpnGetStatus();
      sel.innerHTML = '';
      if (!st || !st.installed) { var o1 = document.createElement('option'); o1.value = ''; o1.textContent = 'Tailscale is not installed — see the VPN module.'; sel.appendChild(o1); return; }
      if (!st.connected) { var o2 = document.createElement('option'); o2.value = ''; o2.textContent = 'Tailscale is not connected — connect it from the VPN module.'; sel.appendChild(o2); return; }
      var peers = st.peers || [];
      if (!peers.length) { var o3 = document.createElement('option'); o3.value = ''; o3.textContent = 'No other devices on your Tailscale network yet.'; sel.appendChild(o3); return; }
      var blank = document.createElement('option'); blank.value = ''; blank.textContent = 'Choose a device…'; sel.appendChild(blank);
      peers.forEach(function (p) {
        if (!p.ip) return;
        var o = document.createElement('option'); o.value = p.ip; o.textContent = p.name + ' — ' + p.ip + (p.online ? '' : ' (offline)');
        o.setAttribute('data-peer-name', p.name);
        sel.appendChild(o);
      });
    } catch (e) { sel.innerHTML = ''; var oe = document.createElement('option'); oe.value = ''; oe.textContent = 'Could not read Tailscale status.'; sel.appendChild(oe); }
  }

  function renderCloudServer() {
    if (!cloudCfg) return;
    var s = cloudCfg.server || {};
    var pill = $('cloudServerPill');
    if (pill) {
      pill.textContent = s.running ? 'Running' : 'Stopped';
      pill.className = 'pill ' + (s.running ? 'pill-completed' : 'pill-pending');
    }
    var info = $('cloudServerInfo');
    if (info) {
      info.textContent = s.running
        ? ('Listening on port ' + (s.port || 8443) + ' — ' + (s.users || []).length + ' user(s)' + (s.fingerprint ? ' — fingerprint ' + s.fingerprint.slice(0, 16) + '…' : ''))
        : 'Not running';
    }
    var en = $('cloudServerEnabled'); if (en) en.checked = !!s.enabled;
    var port = $('cloudServerPort'); if (port) port.value = String(s.port || 8443);
    var gp = $('cloudGuidePort'); if (gp) gp.textContent = String(s.port || 8443);
    setServerAccess(s.accessMode || 'normal');
    var startBtn = $('cloudServerStartBtn');
    if (startBtn) startBtn.textContent = s.running ? '■ Stop server' : '▶ Start server';
    var list = $('cloudUsersList');
    if (list) {
      list.innerHTML = '';
      var users = s.users || [];
      if (!users.length) {
        var empty = document.createElement('div');
        empty.className = 'empty-state'; empty.style.display = '';
        empty.innerHTML = '<div class="big">👤</div><h3>No users yet</h3><p>Add at least one user before anyone can connect.</p>';
        list.appendChild(empty);
      }
      users.forEach(function (u) {
        var card = document.createElement('div');
        card.className = 'job-card';
        var body = document.createElement('div'); body.className = 'job-body';
        var h = document.createElement('h3'); h.className = 'job-name'; h.textContent = u.name;
        var meta = document.createElement('div'); meta.className = 'job-meta';
        meta.textContent = (u.canWrite ? 'Read + write' : 'Read-only') + ' — ' + u.root;
        var acts = document.createElement('div'); acts.className = 'drawer-actions';
        var del = document.createElement('button'); del.className = 'btn btn-danger btn-sm'; del.type = 'button'; del.textContent = '🗑 Delete user';
        del.addEventListener('click', function () {
          askConfirm('Delete user "' + u.name + '"? They will no longer be able to connect.', async function () {
            if (!api || typeof api.cloudUserRemove !== 'function') return cloudMissing();
            try {
              var r = await api.cloudUserRemove(u.name);
              if (r && r.success) { toast('User deleted', u.name + ' was removed.', 'success'); await loadCloud(); }
              else toast('Delete failed', (r && r.error) || 'Could not delete user.', 'error');
            } catch (e) { toast('Delete error', e && e.message ? e.message : 'Could not delete user.', 'error'); }
          });
        });
        acts.appendChild(del);
        body.appendChild(h); body.appendChild(meta); body.appendChild(acts);
        card.appendChild(body);
        list.appendChild(card);
      });
    }
  }

  function renderCloudClientList() {
    if (!cloudCfg) return;
    var list = $('cloudServersList');
    if (!list) return;
    list.innerHTML = '';
    var servers = cloudCfg.clients || [];
    if (!servers.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state'; empty.style.display = '';
      empty.innerHTML = '<div class="big">☁️</div><h3>No servers yet</h3><p>Add the server you want to open below.</p>';
      list.appendChild(empty);
    }
    servers.forEach(function (srv) {
      var card = document.createElement('div');
      card.className = 'job-card';
      var body = document.createElement('div'); body.className = 'job-body';
      var h = document.createElement('h3'); h.className = 'job-name'; h.textContent = srv.name;
      var meta = document.createElement('div'); meta.className = 'job-meta';
      meta.textContent = (srv.accessMode === 'tailscale' ? '🛡️ Tailscale' : '🌐 Normal') + ' — ' + srv.host + ':' + srv.port + ' — user ' + (srv.user || '—') + (srv.fingerprint ? ' — certificate trusted' : ' — not trusted yet');
      var acts = document.createElement('div'); acts.className = 'drawer-actions';
      var open = document.createElement('button'); open.className = 'btn btn-primary btn-sm'; open.type = 'button'; open.textContent = 'Open';
      open.addEventListener('click', function () { openCloudConnect(srv); });
      var del = document.createElement('button'); del.className = 'btn btn-danger btn-sm'; del.type = 'button'; del.textContent = '🗑 Remove';
      del.addEventListener('click', function () {
        askConfirm('Remove server "' + srv.name + '" from the list?', async function () {
          if (!api || typeof api.cloudClientRemove !== 'function') return cloudMissing();
          try { await api.cloudClientRemove(srv.id); await loadCloud(); }
          catch (e) { toast('Remove error', e && e.message ? e.message : 'Could not remove server.', 'error'); }
        });
      });
      acts.appendChild(open); acts.appendChild(del);
      body.appendChild(h); body.appendChild(meta); body.appendChild(acts);
      card.appendChild(body);
      list.appendChild(card);
    });
  }

  function openCloudConnect(srv, presetPassword) {
    cloudSelected = srv;
    cloudPendingProbe = null;
    var box = $('cloudConnectBox'); if (box) box.style.display = '';
    var title = $('cloudConnectTitle'); if (title) title.textContent = 'Connect to ' + srv.name;
    var fp = $('cloudFingerprintBox'); if (fp) fp.style.display = 'none';
    var pass = $('cloudConnectPass'); if (pass) pass.value = presetPassword || '';
    var btn = $('cloudConnectBtn'); if (btn) btn.textContent = 'Connect';
    if (box) box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function closeCloudConnect() {
    var box = $('cloudConnectBox'); if (box) box.style.display = 'none';
    cloudSelected = null;
    cloudPendingProbe = null;
  }

  async function cloudConnectFlow() {
    if (!cloudSelected) return;
    if (!api || typeof api.cloudClientProbe !== 'function' || typeof api.cloudClientConnect !== 'function') return cloudMissing();
    var btn = $('cloudConnectBtn');
    var pass = $('cloudConnectPass');
    var password = pass ? pass.value : '';
    // No trusted certificate yet: probe the server and ask the user to
    // trust its fingerprint first (nothing sensitive is sent to probe).
    if (!cloudSelected.fingerprint) {
      if (cloudPendingProbe) {
        // User already saw the fingerprint and pressed Trust & connect.
        try {
          if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
          var saved = await api.cloudClientSave({
            id: cloudSelected.id, name: cloudSelected.name, host: cloudSelected.host,
            port: cloudSelected.port, user: cloudSelected.user,
            fingerprint: cloudPendingProbe.fingerprint, certPem: cloudPendingProbe.certPem,
            accessMode: cloudClientAccess,
          });
          if (!saved || !saved.success) { toast('Save failed', (saved && saved.error) || 'Could not save server.', 'error'); return; }
          cloudSelected.fingerprint = cloudPendingProbe.fingerprint;
          cloudSelected.certPem = cloudPendingProbe.certPem;
          var fp = $('cloudFingerprintBox'); if (fp) fp.style.display = 'none';
          await loadCloud();
        } catch (e) {
          toast('Save error', e && e.message ? e.message : 'Could not save server.', 'error');
          return;
        } finally {
          if (btn) { btn.disabled = false; btn.textContent = 'Connect'; }
        }
      } else {
        try {
          if (btn) { btn.disabled = true; btn.textContent = 'Checking server…'; }
          var probe = await api.cloudClientProbe(cloudSelected.host, cloudSelected.port);
          if (!probe || !probe.success) { toast('Cannot reach server', (probe && probe.error) || 'Check the address and port.', 'error'); return; }
          cloudPendingProbe = { fingerprint: probe.fingerprint, certPem: probe.certPem };
          var ft = $('cloudFingerprintText'); if (ft) ft.textContent = probe.fingerprint;
          var fbox = $('cloudFingerprintBox'); if (fbox) fbox.style.display = '';
          if (btn) btn.textContent = 'Trust & connect';
          toast('Check the fingerprint', 'Compare it with the fingerprint shown on the server, then press Trust & connect.', '');
        } catch (e) {
          toast('Cannot reach server', e && e.message ? e.message : 'Check the address and port.', 'error');
        } finally {
          // A failed probe must leave the button usable again, with its
          // normal label — otherwise it stays stuck on "Checking server…".
          if (btn) { btn.disabled = false; if (btn.textContent === 'Checking server…') btn.textContent = 'Connect'; }
        }
        return;
      }
    }
    // Trusted certificate: connect with the password.
    if (!password) { toast('Password needed', 'Enter the password for user ' + (cloudSelected.user || '') + '.', 'error'); return; }
    try {
      if (btn) { btn.disabled = true; btn.textContent = 'Connecting…'; }
      var certPem = cloudSelected.certPem;
      if (!certPem) {
        // Fingerprint known but the PEM was saved before this build:
        // re-probe once to get it (the fingerprint must match).
        var p2 = await api.cloudClientProbe(cloudSelected.host, cloudSelected.port);
        if (!p2 || !p2.success || p2.fingerprint !== cloudSelected.fingerprint) {
          toast('Certificate changed', 'The server certificate does not match the trusted fingerprint. Remove the server and add it again.', 'error');
          return;
        }
        certPem = p2.certPem;
      }
      var r = await api.cloudClientConnect({
        serverId: cloudSelected.id, host: cloudSelected.host, port: cloudSelected.port,
        certPem: certPem, user: cloudSelected.user, password: password,
      });
      if (!r || !r.success) { toast('Connection failed', (r && r.error) || 'Wrong user name or password.', 'error'); return; }
      // Keep the server name: closeCloudConnect() clears cloudSelected.
      cloudConn = { serverId: cloudSelected.id, info: r.info, name: cloudSelected.name };
      if (pass) pass.value = '';
      closeCloudConnect();
      cloudPath = '';
      var browser = $('cloudBrowser'); if (browser) browser.style.display = '';
      toast('Connected', 'Signed in as ' + (r.info.user || cloudSelected.user) + (r.info.canWrite ? ' (read + write).' : ' (read-only).'), 'success');
      renderCloudHome();
      await cloudBrowse('');
    } catch (e) {
      toast('Connection failed', e && e.message ? e.message : 'Could not connect.', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Connect'; }
    }
  }

  async function cloudDisconnect() {
    if (cloudConn && api && typeof api.cloudClientDisconnect === 'function') {
      try { await api.cloudClientDisconnect(cloudConn.serverId); } catch (e) {}
    }
    cloudConn = null;
    cloudPath = '';
    var browser = $('cloudBrowser'); if (browser) browser.style.display = 'none';
    renderCloudHome();
  }

  function cloudJoin(base, name) { return base ? base + '/' + name : name; }
  // A rename / new-folder name is one segment, not a path: no slashes,
  // no "..", none of the characters Windows forbids in a file name.
  function isSingleCloudName(val) {
    if (typeof val !== 'string') return false;
    var v = val.trim();
    if (!v || v === '.' || v === '..') return false;
    if (/[/\\]/.test(v)) return false;
    if (/[<>:"|?*\u0000-\u001f]/.test(v)) return false;
    return true;
  }
  var cloudTransferBusy = false; // one transfer at a time (no double-clicks)
  function cloudParent(p) {
    var i = p.lastIndexOf('/');
    return i < 0 ? '' : p.slice(0, i);
  }

  async function cloudBrowse(relPath) {
    if (!cloudConn) return;
    if (!api || typeof api.cloudClientList !== 'function') return cloudMissing();
    try {
      var r = await api.cloudClientList(cloudConn.serverId, relPath || '');
      if (!r || !r.success) { toast('Cannot list folder', (r && r.error) || 'The server refused the request.', 'error'); return; }
      cloudPath = r.path || '';
      renderCloudBrowser(r.entries || []);
    } catch (e) {
      toast('Cannot list folder', e && e.message ? e.message : 'The server refused the request.', 'error');
    }
  }

  function renderCloudBrowser(entries) {
    var crumbs = $('cloudCrumbs');
    if (crumbs) {
      crumbs.innerHTML = '';
      var rootBtn = document.createElement('button');
      rootBtn.className = 'cloud-crumb'; rootBtn.type = 'button'; rootBtn.textContent = (cloudConn && cloudConn.name ? cloudConn.name : 'Server') + ' /';
      rootBtn.addEventListener('click', function () { cloudBrowse(''); });
      crumbs.appendChild(rootBtn);
      var parts = cloudPath ? cloudPath.split('/') : [];
      var acc = '';
      parts.forEach(function (part, i) {
        var sep = document.createElement('span'); sep.className = 'cloud-crumb-sep'; sep.textContent = ' › ';
        crumbs.appendChild(sep);
        acc = cloudJoin(acc, part);
        var b = document.createElement('button');
        b.className = 'cloud-crumb'; b.type = 'button'; b.textContent = part;
        (function (target) { b.addEventListener('click', function () { cloudBrowse(target); }); })(acc);
        crumbs.appendChild(b);
      });
    }
    var info = $('cloudBrowserInfo');
    if (info) info.textContent = (cloudConn && cloudConn.info ? 'Signed in as ' + cloudConn.info.user + (cloudConn.info.canWrite ? ' (read + write)' : ' (read-only)') : '');
    var list = $('cloudFileList');
    var empty = $('cloudEmptyState');
    if (!list) return;
    list.innerHTML = '';
    if (!entries.length) { if (empty) empty.style.display = ''; return; }
    if (empty) empty.style.display = 'none';
    entries.forEach(function (e) {
      var card = document.createElement('div');
      card.className = 'job-card';
      var body = document.createElement('div'); body.className = 'job-body';
      var h = document.createElement('h3'); h.className = 'job-name';
      h.textContent = (e.isDir ? '📁 ' : '📄 ') + e.name;
      var meta = document.createElement('div'); meta.className = 'job-meta';
      meta.textContent = e.isDir ? 'Folder' : (formatBytes(e.size) + (e.mtime ? ' — ' + formatDate(e.mtime) : ''));
      var acts = document.createElement('div'); acts.className = 'drawer-actions';
      var rel = cloudJoin(cloudPath, e.name);
      if (e.isDir) {
        var open = document.createElement('button'); open.className = 'btn btn-primary btn-sm'; open.type = 'button'; open.textContent = 'Open';
        open.addEventListener('click', function () { cloudBrowse(rel); });
        acts.appendChild(open);
        h.style.cursor = 'pointer';
        h.addEventListener('click', function () { cloudBrowse(rel); });
      } else {
        var dl = document.createElement('button'); dl.className = 'btn btn-sm'; dl.type = 'button'; dl.textContent = '⬇ Download';
        dl.addEventListener('click', function () { cloudDownload(rel); });
        acts.appendChild(dl);
      }
      if (cloudConn && cloudConn.info && cloudConn.info.canWrite) {
        var ren = document.createElement('button'); ren.className = 'btn btn-sm'; ren.type = 'button'; ren.textContent = '✎ Rename';
        ren.addEventListener('click', function () {
          askCloudInput('Rename', 'New name', e.name, async function (val) {
            if (!val || val === e.name) return;
            if (!isSingleCloudName(val)) { toast('Invalid name', 'Use a plain name without / \\ or special characters.', 'error'); return; }
            if (!api || typeof api.cloudClientRename !== 'function') return cloudMissing();
            try {
              var r = await api.cloudClientRename(cloudConn.serverId, rel, cloudJoin(cloudPath, val));
              if (r && r.success) { toast('Renamed', e.name + ' → ' + val, 'success'); await cloudBrowse(cloudPath); }
              else toast('Rename failed', (r && r.error) || 'Could not rename.', 'error');
            } catch (err) { toast('Rename error', err && err.message ? err.message : 'Could not rename.', 'error'); }
          });
        });
        acts.appendChild(ren);
        var del = document.createElement('button'); del.className = 'btn btn-danger btn-sm'; del.type = 'button'; del.textContent = '🗑 Delete';
        del.addEventListener('click', function () {
          askConfirm('Delete "' + e.name + '" from the server? This cannot be undone.', async function () {
            if (!api || typeof api.cloudClientDelete !== 'function') return cloudMissing();
            try {
              var r = await api.cloudClientDelete(cloudConn.serverId, rel);
              if (r && r.success) { toast('Deleted', e.name + ' was deleted.', 'success'); await cloudBrowse(cloudPath); }
              else toast('Delete failed', (r && r.error) || 'Could not delete.', 'error');
            } catch (err) { toast('Delete error', err && err.message ? err.message : 'Could not delete.', 'error'); }
          });
        });
        acts.appendChild(del);
      }
      body.appendChild(h); body.appendChild(meta); body.appendChild(acts);
      card.appendChild(body);
      list.appendChild(card);
    });
  }

  async function cloudDownload(relPath) {
    if (!cloudConn || cloudTransferBusy) return;
    if (!api || typeof api.showOpenDialog !== 'function' || typeof api.cloudClientDownload !== 'function') return cloudMissing();
    try {
      var pick = await api.showOpenDialog({ properties: ['openDirectory', 'createDirectory'] });
      if (!pick || pick.canceled || !pick.filePaths || !pick.filePaths.length) return;
      cloudTransferBusy = true;
      showCloudTransfer('Downloading…', 0);
      var r = await api.cloudClientDownload(cloudConn.serverId, relPath, pick.filePaths[0]);
      hideCloudTransfer();
      if (r && r.success) toast('Downloaded', relPath.split('/').pop() + ' saved.', 'success');
      else toast('Download failed', (r && r.error) || 'Could not download.', 'error');
    } catch (e) {
      hideCloudTransfer();
      toast('Download error', e && e.message ? e.message : 'Could not download.', 'error');
    } finally {
      cloudTransferBusy = false;
    }
  }

  async function cloudUpload() {
    if (!cloudConn || cloudTransferBusy) return;
    if (!api || typeof api.showOpenDialog !== 'function' || typeof api.cloudClientUpload !== 'function') return cloudMissing();
    try {
      var pick = await api.showOpenDialog({ properties: ['openFile'] });
      if (!pick || pick.canceled || !pick.filePaths || !pick.filePaths.length) return;
      cloudTransferBusy = true;
      showCloudTransfer('Uploading…', 0);
      var r = await api.cloudClientUpload(cloudConn.serverId, pick.filePaths[0], cloudPath);
      hideCloudTransfer();
      if (r && r.success) { toast('Uploaded', (r.name || 'File') + ' uploaded.', 'success'); await cloudBrowse(cloudPath); }
      else toast('Upload failed', (r && r.error) || 'Could not upload.', 'error');
    } catch (e) {
      hideCloudTransfer();
      toast('Upload error', e && e.message ? e.message : 'Could not upload.', 'error');
    } finally {
      cloudTransferBusy = false;
    }
  }

  function showCloudTransfer(text, pct) {
    var box = $('cloudTransfer'); if (box) box.style.display = '';
    var fill = $('cloudTransferFill'); if (fill) fill.style.width = Math.round(pct || 0) + '%';
    var t = $('cloudTransferText'); if (t) t.textContent = text;
    if (cloudTransferTimer) { clearTimeout(cloudTransferTimer); cloudTransferTimer = null; }
  }

  function hideCloudTransfer() {
    var box = $('cloudTransfer'); if (box) box.style.display = 'none';
    var fill = $('cloudTransferFill'); if (fill) fill.style.width = '0%';
  }

  /* ---------- small input dialog (same pattern as askConfirm) ---------- */
  var cloudPromptCallback = null;
  function askCloudInput(title, label, defaultValue, onOk) {
    var modal = $('cloudPromptModal'); var back = $('cloudPromptBackdrop');
    if (!modal) { var v = window.prompt(label, defaultValue); if (v !== null) onOk(v); return; }
    $('cloudPromptTitle').textContent = title;
    $('cloudPromptText').textContent = '';
    $('cloudPromptLabel').textContent = label;
    var input = $('cloudPromptInput'); input.value = defaultValue || '';
    cloudPromptCallback = onOk;
    modal.style.display = 'block';
    if (back) back.classList.add('show');
    setTimeout(function () { input.focus(); input.select(); }, 30);
  }
  function closeCloudPrompt() {
    var modal = $('cloudPromptModal'); var back = $('cloudPromptBackdrop');
    if (modal) modal.style.display = 'none';
    if (back) back.classList.remove('show');
    cloudPromptCallback = null;
  }

  /* ---------- schedule display ---------- */
  function nextRunText(job) {
    var s = job.schedule || (job.raw && job.raw.schedule) || null;
    if (!s || !s.enabled) return 'No schedule — manual only';
    var freq = s.frequency || 'Daily';
    var time = s.time || '02:00';
    var m = /^(\d{1,2}):(\d{2})$/.exec(time);
    if (!m) return freq + ' at ' + time;
    var next = new Date();
    next.setHours(parseInt(m[1], 10), parseInt(m[2], 10), 0, 0);
    if (freq.toLowerCase() === 'weekly') {
      if (next <= new Date()) next.setDate(next.getDate() + 7);
    } else if (freq.toLowerCase() === 'monthly') {
      if (next <= new Date()) next.setMonth(next.getMonth() + 1);
    } else if (next <= new Date()) {
      next.setDate(next.getDate() + 1);
    }
    return freq + ' at ' + time + ' — next: ' + formatDate(next.toISOString());
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
    var enc = job.encryptionEnabled === true || (job.raw && job.raw.encryptionEnabled === true);
    if ($('drawerEncryption')) $('drawerEncryption').textContent = enc ? 'AES-256 🔒' : 'Off';
    $('drawerStatus').textContent = job.status;
    $('drawerFiles').textContent = String(job.files);
    $('drawerSize').textContent = formatBytes(job.size);
    $('drawerDuration').textContent = formatDuration(job.duration);
    $('drawerLastRun').textContent = formatDate(job.timestamp);
    var sched = job.schedule || (job.raw && job.raw.schedule) || null;
    $('drawerSchedule').textContent = sched && sched.enabled
      ? (sched.frequency || 'Daily') + ' at ' + (sched.time || '02:00')
      : 'Manual only — no schedule set';
    $('drawerNextRun').textContent = nextRunText(job);
    var runsBox = $('drawerRuns');
    if (runsBox) {
      if (job.runs && job.runs.length) {
        var html = '<h3 style="margin:14px 0 6px;font-size:13px;">Run history (' + job.runs.length + ')</h3>';
        job.runs.slice().reverse().forEach(function (r) {
          html += '<div class="run-row" style="display:flex;gap:8px;justify-content:space-between;padding:6px 0;border-top:1px solid var(--hatch-widget-border, #ddd);font-size:12px;">' +
            '<span>' + escapeHtml(formatDate(r.timestamp)) + '</span>' +
            '<span>' + escapeHtml((r.type || '').toUpperCase()) + '</span>' +
            '<span>' + escapeHtml((r.status || '').toUpperCase()) + '</span>' +
            '<span>' + r.files + ' files · ' + escapeHtml(formatBytes(r.size)) + '</span></div>';
        });
        runsBox.innerHTML = html;
      } else {
        runsBox.innerHTML = '<p style="margin:12px 0 0;font-size:12px;opacity:.7;">No runs yet — this job has never run.</p>';
      }
    }
    $('jobDrawer').classList.add('show');
    $('drawerBackdrop').classList.add('show');
  }
  function closeDrawer() {
    $('jobDrawer').classList.remove('show');
    $('drawerBackdrop').classList.remove('show');
    currentJob = null;
  }
  function showSettingsView(view) {
    var home = $('settingsHomeView'), email = $('settingsEmailView');
    if (!home || !email) return;
    home.style.display = view === 'email' ? 'none' : '';
    email.style.display = view === 'email' ? '' : 'none';
  }
  function refreshEmailMenuStatus() {
    var el = $('emailMenuStatus'); if (!el) return;
    var enabled = $('settingEmailEnabled') ? $('settingEmailEnabled').checked : false;
    var to = $('settingEmailTo') ? $('settingEmailTo').value.trim() : '';
    el.textContent = enabled ? ('On' + (to ? ' — ' + to : '')) : 'Off — tap to set up';
  }
  function openSettings() {
    showSettingsView('home');
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
    ['refreshBtn'].forEach(function (id) {
      var b = $(id);
      if (b) b.disabled = disabled;
    });
    var dr = $('drawerRun');
    if (dr) dr.disabled = disabled;
  }
  /* ---------- backup / restore actions ---------- */
  // Ask for a job password in a modal. Resolves to the password, or
  // null when the user cancels.
  function askJobPassword(jobName) {
    return new Promise(function (resolve) {
      var modal = $('jobPwModal'); var back = $('jobPwBackdrop');
      var input = $('jobPwInput');
      $('jobPwText').textContent = 'Job "' + jobName + '" is encrypted and its password is not saved in the vault. Enter the backup password to run it.';
      input.value = '';
      modal.style.display = 'block'; back.classList.add('show');
      setTimeout(function () { input.focus(); }, 50);
      function done(value) {
        modal.style.display = 'none'; back.classList.remove('show');
        $('jobPwRun').onclick = null; $('jobPwCancel').onclick = null; input.onkeydown = null;
        resolve(value);
      }
      $('jobPwRun').onclick = function () { done(input.value || null); };
      $('jobPwCancel').onclick = function () { done(null); };
      input.onkeydown = function (ev) { if (ev.key === 'Enter') done(input.value || null); };
    });
  }
  async function runBackup(job, incremental) {
    if (!job) return;
    if (!api || typeof api.runFullBackup !== 'function') { toast('Backup unavailable', 'Backup API is not available.', 'error'); return; }
    var cfg = job.raw || job;
    // Encrypted job whose password is not in the vault: ask now, and
    // pass it for this run only (main.js stores it if the vault is open).
    if (cfg.encryptionEnabled === true) {
      var hasPw = false;
      if (api && typeof api.vaultHasJobPassword === 'function') {
        try { var hr = await api.vaultHasJobPassword(cfg.id); hasPw = !!(hr && hr.has); } catch (e) {}
      }
      if (!hasPw) {
        var pw = await askJobPassword(job.name || cfg.name || 'backup job');
        if (!pw) return; // cancelled
        cfg = Object.assign({}, cfg, { encryptionPassword: pw });
      }
    }
    closeDrawer();
    showProgress(incremental ? 'Running incremental backup…' : 'Running full backup…');
    // Real progress from the engine: main forwards 'backup-progress'
    // events as bytes are actually processed. This replaces the old
    // simulated bar that raced to 92% and froze there.
    var stopProgress = null;
    if (api && typeof api.onBackupProgress === 'function') {
      stopProgress = api.onBackupProgress(function (p) {
        setProgress(p.pct, p.filesDone, p.bytesDone, p.currentFile);
        var t = $('progressTitle');
        if (t) t.textContent = p.phase === 'writing' ? 'Writing archive…' : (p.phase === 'copying' ? 'Copying files…' : (incremental ? 'Running incremental backup…' : 'Running full backup…'));
      });
    }
    try {
      var result = incremental && typeof api.runIncrementalBackup === 'function'
        ? await api.runIncrementalBackup(cfg)
        : await api.runFullBackup(cfg);
      if (stopProgress) stopProgress();
      setProgress(100, result && result.files, result && result.size);
      var files = result ? safeNum(result.files ?? result.fileCount, 0) : 0;
      setTimeout(function () { hideProgress(); }, 900);
      if (result && (result.success === false || result.status === 'failed')) {
        if (result.error === 'ENCRYPTION_PASSWORD_REQUIRED') {
          toast('Password required', 'This job is encrypted and no password is saved. Unlock the vault in Settings, or run it and enter the password when asked.', 'error');
        } else {
          toast('Backup failed', result.error || result.message || 'The backup did not complete.', 'error');
        }
      } else {
        toast('Backup completed', job.name + ' — ' + files + ' file' + (files === 1 ? '' : 's') + ' backed up.', 'success');
      }
      await loadJobs();
    } catch (e) {
      if (stopProgress) stopProgress();
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
    renderJobsView();
  }
  if (api && typeof api.onJobsUpdated === 'function') {
    api.onJobsUpdated(function () { loadJobs(); });
  }
  async function refreshJobs() {
    if (api && typeof api.refreshJobs === 'function') {
      try { await api.refreshJobs(); } catch (e) { /* fall through to reload */ }
    }
    await loadJobs();
  }

  /* ---------- master-password vault ---------- */
  async function refreshVaultStatus() {
    var txt = $('vaultStatusText'); if (!txt) return;
    if (!api || typeof api.vaultStatus !== 'function') { txt.textContent = 'Vault API is not available.'; return; }
    try {
      var st = await api.vaultStatus();
      txt.textContent = !st.exists
        ? 'No master password set up yet.'
        : (st.locked ? 'Vault is set up and locked.' : 'Vault is unlocked for this session.');
      if ($('vaultSetupBox')) $('vaultSetupBox').style.display = st.exists ? 'none' : 'block';
      if ($('vaultChangeBox')) $('vaultChangeBox').style.display = st.exists ? 'block' : 'none';
    } catch (e) { txt.textContent = 'Could not read the vault status.'; }
  }
  async function checkVaultOnStartup() {
    if (!api || typeof api.vaultStatus !== 'function') return;
    try {
      var st = await api.vaultStatus();
      if (st.exists && st.locked) {
        $('vaultModal').style.display = 'block';
        $('vaultBackdrop').classList.add('show');
        setTimeout(function () { var i = $('vaultUnlockPass'); if (i) i.focus(); }, 50);
      }
    } catch (e) { /* vault stays locked; encrypted runs will ask instead */ }
  }
  function hideVaultModal() {
    $('vaultModal').style.display = 'none';
    $('vaultBackdrop').classList.remove('show');
    var e = $('vaultUnlockError'); if (e) e.classList.remove('show');
  }

  /* ---------- TechVision VPN (Tailscale client manager) ----------
     One panel per machine: status, connect/disconnect, peers, subnet
     router. There is no VPN server to build — Tailscale is a mesh and
     its coordination server is Tailscale's own. The Cloud module plugs
     in here: "Open in Cloud" jumps to the Cloud client with a peer's
     Tailscale IP prefilled (and the connection mode set to Tailscale). */
  var vpnStatusCache = null;
  var vpnBusy = false;

  function vpnMissing() { toast('VPN', 'The VPN bridge is not available in this build.', 'error'); }

  async function loadVpn() {
    if (!api || typeof api.vpnGetStatus !== 'function') return vpnMissing();
    var st;
    try { st = await api.vpnGetStatus(); } catch (e) { st = { installed: true, connected: false, error: e && e.message ? e.message : 'Could not read Tailscale status.' }; }
    vpnStatusCache = st || {};
    var txt = $('vpnStatusText'), sub = $('vpnStatusSub'), btn = $('vpnConnectBtn');
    var ni = $('vpnNotInstalled'), lb = $('vpnLoginBox'), dc = $('vpnDetailsCard');
    if (!st || !st.installed) {
      if (txt) txt.textContent = 'Not installed';
      if (sub) sub.textContent = 'Tailscale is not installed on this computer.';
      if (btn) { btn.textContent = 'Install & connect'; btn.disabled = false; }
      if (ni) ni.style.display = '';
      if (lb) lb.style.display = 'none';
      if (dc) dc.style.display = 'none';
      renderVpnPeers([]);
      return;
    }
    if (btn) btn.disabled = false;
    if (ni) ni.style.display = 'none';
    if (st.error && !st.connected && !st.needsLogin) {
      if (txt) txt.textContent = 'Error';
      if (sub) sub.textContent = st.error;
      if (btn) btn.textContent = 'Connect';
      if (lb) lb.style.display = 'none';
      if (dc) dc.style.display = 'none';
      renderVpnPeers([]);
      return;
    }
    if (st.needsLogin) {
      if (txt) txt.textContent = 'Not signed in';
      if (sub) sub.textContent = 'Sign in to Tailscale to join your private network.';
      if (btn) btn.textContent = 'Sign in';
      if (lb) {
        lb.style.display = '';
        var au = $('vpnAuthUrl');
        if (au) au.textContent = st.authUrl ? ('Sign-in link: ' + st.authUrl) : '';
      }
      if (dc) dc.style.display = 'none';
      renderVpnPeers([]);
      return;
    }
    if (!st.connected) {
      if (txt) txt.textContent = st.backendState === 'Stopped' ? 'Disconnected' : 'Not connected';
      if (sub) sub.textContent = st.backendState === 'Stopped' ? 'You are signed in, but the VPN is off.' : 'Tailscale is not connected.';
      if (btn) btn.textContent = 'Connect';
      if (lb) lb.style.display = 'none';
      if (dc) dc.style.display = 'none';
      renderVpnPeers([]);
      return;
    }
    if (txt) txt.textContent = 'Connected';
    if (sub) sub.textContent = 'You are on your private network' + (st.tailnet ? (' — ' + st.tailnet) : '') + '.';
    if (btn) btn.textContent = 'Disconnect';
    if (lb) lb.style.display = 'none';
    if (dc) dc.style.display = '';
    var si = $('vpnSelfIp'); if (si) si.textContent = st.selfIp || '—';
    var tn = $('vpnTailnet'); if (tn) tn.textContent = st.tailnet || '—';
    var sn = $('vpnSelfName'); if (sn) sn.textContent = st.selfName || '—';
    var tg = $('vpnSubnetToggle');
    var advertising = (st.advertiseRoutes || []).indexOf(st.lanSubnet) >= 0;
    if (tg) tg.checked = !!advertising;
    var rn = $('vpnRoutesNote');
    if (rn) {
      if (advertising) { rn.style.display = ''; rn.textContent = 'Advertising ' + st.lanSubnet + ' — approve this route once in the Tailscale admin console.'; }
      else rn.style.display = 'none';
    }
    var ss = $('vpnSubnetSub');
    if (ss) ss.textContent = st.lanSubnet
      ? ('Let devices on Tailscale reach your whole home network (' + st.lanSubnet + ' — printer, camera, router).')
      : 'Let devices on Tailscale reach your whole home network (printer, camera, router).';
    var ket = $('vpnKeyExpiryToggle'); if (ket) ket.checked = vpnKeyExpiryWanted();
    renderVpnPeers(st.peers || []);
    // First sign-in (or first view while connected): turn off the 180-day
    // key expiry automatically, so the device never asks to sign in again.
    maybeDisableVpnKeyExpiry();
  }

  /* ---------- VPN key expiry (stay connected forever) ---------- */
  var vpnKeyExpiryAttempted = false; // one auto attempt per app session
  function vpnKeyExpiryWanted() {
    return !(settings.vpn && settings.vpn.autoDisableKeyExpiry === false);
  }
  async function saveVpnSettings(patch) {
    var v = Object.assign({}, (settings.vpn && typeof settings.vpn === 'object') ? settings.vpn : {}, patch);
    try {
      var next = Object.assign({}, settings, { vpn: v });
      await api.saveSettings(next);
      settings = next;
    } catch (e) { /* keep the in-memory value; the toggle still works this session */ }
  }
  async function disableVpnKeyExpiry(quiet) {
    if (!api || typeof api.vpnDisableKeyExpiry !== 'function') return false;
    try {
      var r = await api.vpnDisableKeyExpiry();
      if (r && r.success) {
        await saveVpnSettings({ keyExpiryDisabled: true });
        if (!quiet) toast('VPN', 'Key expiry is off — this device will stay connected, no more sign-ins.', 'success');
        return true;
      }
      if (!quiet) toast('VPN', 'Could not turn off key expiry automatically. You can turn it off in the Tailscale admin console (Machines → this device → Disable key expiry).', 'error');
      return false;
    } catch (e) {
      if (!quiet) toast('VPN error', e && e.message ? e.message : 'Could not turn off key expiry.', 'error');
      return false;
    }
  }
  async function maybeDisableVpnKeyExpiry() {
    if (vpnKeyExpiryAttempted) return;
    if (!vpnKeyExpiryWanted()) return;
    if (settings.vpn && settings.vpn.keyExpiryDisabled === true) return;
    vpnKeyExpiryAttempted = true;
    await disableVpnKeyExpiry(false);
  }

  function renderVpnPeers(peers) {
    var list = $('vpnPeersList'); if (!list) return;
    list.innerHTML = '';
    if (!peers.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = '<div class="big">🛡️</div><h3>No devices yet</h3><p>Sign in to Tailscale and your devices will show up here.</p>';
      list.appendChild(empty);
      return;
    }
    peers.forEach(function (p) {
      var card = document.createElement('div');
      card.className = 'job-card';
      var body = document.createElement('div'); body.className = 'job-body';
      var h = document.createElement('h3'); h.className = 'job-name'; h.textContent = p.name;
      var meta = document.createElement('div'); meta.className = 'job-meta';
      meta.textContent = (p.ip || '—') + (p.os ? ' — ' + p.os : '') + ' — ' + (p.online ? 'online' : 'offline');
      var acts = document.createElement('div'); acts.className = 'drawer-actions';
      if (p.ip) {
        var open = document.createElement('button'); open.className = 'btn btn-primary btn-sm'; open.type = 'button'; open.textContent = 'Open in Cloud';
        open.addEventListener('click', function () { openCloudWithPeer(p); });
        acts.appendChild(open);
      }
      body.appendChild(h); body.appendChild(meta); body.appendChild(acts);
      card.appendChild(body);
      list.appendChild(card);
    });
  }

  function openCloudWithPeer(peer) {
    setModule('cloud');
    showCloudPanel('client');
    setClientAccess('tailscale');
    var host = $('cloudClientHost'); if (host) host.value = peer.ip || '';
    var name = $('cloudClientName'); if (name && !name.value) name.value = peer.name || '';
    toast('Cloud client', 'Server address set to ' + (peer.name || peer.ip) + ' over Tailscale. Add your user and password, then Save & connect.', 'success');
  }

  /* ---------- wiring ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    var nnj = $('navNewJob'); if (nnj) nnj.addEventListener('click', function () { openJobWizard(null); });
    var jnb = $('jobsNewJobBtn'); if (jnb) jnb.addEventListener('click', function () { openJobWizard(null); });
    var jenb = $('jobsEmptyNewJobBtn'); if (jenb) jenb.addEventListener('click', function () { openJobWizard(null); });
    $('emptyNewJobBtn').addEventListener('click', function () { openJobWizard(null); });

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
    $('settingsBtn').addEventListener('click', function () { openSettings(); refreshVaultStatus(); });
    var vsb = $('vaultSetupBtn');
    if (vsb) vsb.addEventListener('click', async function () {
      var p1 = $('vaultNewPass').value, p2 = $('vaultNewPassConfirm').value;
      if (p1.length < 8) { toast('Password too short', 'The master password must be at least 8 characters.', 'warning'); return; }
      if (p1 !== p2) { toast('Passwords do not match', 'Please repeat the same master password.', 'warning'); return; }
      try {
        var r = await api.vaultSetup(p1);
        if (r && r.success) { $('vaultNewPass').value = ''; $('vaultNewPassConfirm').value = ''; toast('Vault set up', 'Master password saved. The vault is unlocked for this session.', 'success'); }
        else toast('Setup failed', (r && r.error) || 'Could not set up the vault.', 'error');
      } catch (e) { toast('Setup failed', e && e.message ? e.message : 'Could not set up the vault.', 'error'); }
      refreshVaultStatus();
    });
    var vcb = $('vaultChangeBtn');
    if (vcb) vcb.addEventListener('click', async function () {
      var oldP = $('vaultOldPass').value, p1 = $('vaultChangeNew').value, p2 = $('vaultChangeConfirm').value;
      if (p1.length < 8) { toast('Password too short', 'The new master password must be at least 8 characters.', 'warning'); return; }
      if (p1 !== p2) { toast('Passwords do not match', 'Please repeat the same new master password.', 'warning'); return; }
      try {
        var r = await api.vaultChangePassword(oldP, p1);
        if (r && r.success) { $('vaultOldPass').value = ''; $('vaultChangeNew').value = ''; $('vaultChangeConfirm').value = ''; toast('Master password changed', 'The vault was re-encrypted with the new master password.', 'success'); }
        else toast('Change failed', (r && r.error) || 'Could not change the master password.', 'error');
      } catch (e) { toast('Change failed', e && e.message ? e.message : 'Could not change the master password.', 'error'); }
      refreshVaultStatus();
    });
    var vlb = $('vaultLockBtn');
    if (vlb) vlb.addEventListener('click', async function () {
      try { await api.vaultLock(); toast('Vault locked', 'Job passwords are locked until you unlock the vault again.', ''); } catch (e) {}
      refreshVaultStatus();
    });
    var vub = $('vaultUnlockBtn');
    if (vub) vub.addEventListener('click', async function () {
      var pw = $('vaultUnlockPass').value;
      try {
        var r = await api.vaultUnlock(pw);
        if (r && r.success) { $('vaultUnlockPass').value = ''; hideVaultModal(); toast('Vault unlocked', 'Scheduled encrypted backups can run again.', 'success'); }
        else { $('vaultUnlockError').classList.add('show'); }
      } catch (e) { $('vaultUnlockError').classList.add('show'); }
    });
    var vus = $('vaultUnlockSkip');
    if (vus) vus.addEventListener('click', hideVaultModal);
    var vup = $('vaultUnlockPass');
    if (vup) vup.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); $('vaultUnlockBtn').click(); } });
    $('settingsClose').addEventListener('click', closeSettings);
    $('settingsBackdrop').addEventListener('click', closeSettings);
    var emr = $('emailMenuRow');
    if (emr) emr.addEventListener('click', function () { showSettingsView('email'); });
    var ebb = $('emailBackBtn');
    if (ebb) ebb.addEventListener('click', function () { showSettingsView('home'); });
    $('settingsSave').addEventListener('click', async function () { await saveSettings(); closeSettings(); });
    var etb = $('emailTestBtn');
    if (etb) etb.addEventListener('click', async function () {
      await saveSettings();
      if (!api || typeof api.sendTestEmail !== 'function') { toast('Test unavailable', 'Test email API is not available.', 'error'); return; }
      try {
        var res = await api.sendTestEmail();
        if (res && res.success) toast('Test email sent', 'Check your inbox for the TechVision test email.', 'success');
        else toast('Test email failed', (res && res.error) || 'Could not send the test email.', 'error');
      } catch (e) { toast('Test email failed', e && e.message ? e.message : 'Could not send the test email.', 'error'); }
    });
    $('settingLightTheme').addEventListener('change', async function (ev) {
      var next = ev.target.checked ? 'light' : 'dark';
      applyTheme(next);
      /* Persist on change: before this, toggling Light only changed the
         main window visually, settings.json still said dark, and the next
         New Job wizard opened black. Save immediately, like themeToggle. */
      if (api && typeof api.saveSettings === 'function') {
        try { await api.saveSettings(Object.assign({}, settings, { theme: next })); settings.theme = next; } catch (e) { /* theme already applied visually */ }
      }
    });
    $('clearHistoryBtn').addEventListener('click', function () {
      if (!api || typeof api.clearJobHistory !== 'function') return;
      askConfirm('Do you want to delete ALL backup history? This cannot be undone.', async function () {
        try { await api.clearJobHistory(); await loadJobs(); toast('History cleared', 'Backup history has been cleared.', 'success'); }
        catch (e) { toast('Clear failed', e && e.message ? e.message : 'History could not be cleared.', 'error'); }
      });
    });
    var cy = $('confirmYes'); if (cy) cy.addEventListener('click', function () { var cb = confirmCallback; closeConfirm(); if (cb) cb(); });
    var cn = $('confirmNo'); if (cn) cn.addEventListener('click', closeConfirm);
    var cb2 = $('confirmBackdrop'); if (cb2) cb2.addEventListener('click', closeConfirm);
    document.querySelectorAll('[data-nav]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var nav = btn.getAttribute('data-nav');
        document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
        btn.classList.add('active');
        if (nav === 'settings') openSettings();
        if (nav === 'logs') toast('Logs', 'Open the Log Viewer from the Logs window.', '');
        if (nav === 'jobs') showView('jobs');
        if (nav === 'dashboard') showView('dashboard');
        if (nav === 'logs') showView('logs');
        if (nav === 'cloud') showView('cloud');
        if (nav === 'vpn') showView('vpn');
        if (nav === 'cloud-server') { setModule('cloud'); showCloudPanel('server'); }
        if (nav === 'cloud-client') { setModule('cloud'); showCloudPanel('client'); }
      });
    });
    document.querySelectorAll('[data-module]').forEach(function (btn) {
      btn.addEventListener('click', function () { setModule(btn.getAttribute('data-module')); });
    });
    document.querySelectorAll('#cloudServerAccessSeg .seg-btn').forEach(function (b) {
      b.addEventListener('click', function () { setServerAccess(b.getAttribute('data-access')); });
    });
    document.querySelectorAll('#cloudClientAccessSeg .seg-btn').forEach(function (b) {
      b.addEventListener('click', function () { setClientAccess(b.getAttribute('data-access')); });
    });
    var cps = $('cloudClientPeer');
    if (cps) cps.addEventListener('change', function () {
      var host = $('cloudClientHost'); if (host && cps.value) host.value = cps.value;
      var name = $('cloudClientName');
      if (name && !name.value && cps.selectedOptions && cps.selectedOptions[0]) name.value = cps.selectedOptions[0].getAttribute('data-peer-name') || '';
    });
    var vcb = $('vpnConnectBtn');
    if (vcb) vcb.addEventListener('click', async function () {
      if (!api || typeof api.vpnSetConnected !== 'function') return vpnMissing();
      if (vpnBusy) return;
      // Not installed yet → one click installs Tailscale, then connects.
      if (vpnStatusCache && !vpnStatusCache.installed) {
        if (typeof api.vpnInstallConnect !== 'function' || typeof api.onVpnInstallProgress !== 'function') return vpnMissing();
        vpnBusy = true; vcb.disabled = true; vcb.textContent = 'Installing…';
        var ib = $('vpnInstallBox'); if (ib) ib.style.display = '';
        var stopListen = api.onVpnInstallProgress(function (p) {
          var f = $('vpnInstallFill'); if (f) f.style.width = Math.max(0, Math.min(100, p.pct || 0)) + '%';
          var t = $('vpnInstallText'); if (t) t.textContent = p.text || '';
        });
        try {
          var r = await api.vpnInstallConnect();
          if (r && r.success) {
            if (r.needsLogin) toast('VPN', 'Tailscale is installed. Sign in to Tailscale in the browser window, then press Refresh.', '');
            else toast('VPN', 'Tailscale installed and connected.', 'success');
          } else toast('VPN error', (r && r.error) || 'Could not install Tailscale.', 'error');
        } catch (e) { toast('VPN error', e && e.message ? e.message : 'Could not install Tailscale.', 'error'); }
        finally { if (stopListen) stopListen(); vpnBusy = false; var ib2 = $('vpnInstallBox'); if (ib2) ib2.style.display = 'none'; await loadVpn(); }
        return;
      }
      vpnBusy = true; vcb.disabled = true; vcb.textContent = 'Working…';
      try {
        var wantOn = !(vpnStatusCache && vpnStatusCache.connected);
        var r = await api.vpnSetConnected(wantOn);
        if (r && r.success) {
          if (r.needsLogin) toast('VPN', 'Sign in to Tailscale in the browser window, then press Refresh.', '');
          else toast('VPN', wantOn ? 'VPN connected.' : 'VPN disconnected.', 'success');
        } else toast('VPN error', (r && r.error) || 'Could not change the VPN connection.', 'error');
        await loadVpn();
      } catch (e) { toast('VPN error', e && e.message ? e.message : 'Could not change the VPN connection.', 'error'); }
      finally { vpnBusy = false; }
    });
    var vrb = $('vpnRefreshBtn');
    if (vrb) vrb.addEventListener('click', function () { loadVpn(); });
    var vdb = $('vpnDownloadBtn');
    if (vdb) vdb.addEventListener('click', async function () {
      if (!api || typeof api.vpnOpenDownload !== 'function') return vpnMissing();
      await api.vpnOpenDownload();
    });
    var vrc = $('vpnRecheckBtn');
    if (vrc) vrc.addEventListener('click', function () { loadVpn(); });
    var vke = $('vpnKeyExpiryToggle');
    if (vke) vke.addEventListener('change', async function () {
      await saveVpnSettings({ autoDisableKeyExpiry: vke.checked });
      if (vke.checked) { vpnKeyExpiryAttempted = false; maybeDisableVpnKeyExpiry(); }
    });
    var vkb = $('vpnKeyExpiryBtn');
    if (vkb) vkb.addEventListener('click', async function () {
      if (vpnBusy) return;
      vpnBusy = true; vkb.disabled = true;
      try { await disableVpnKeyExpiry(false); }
      finally { vpnBusy = false; vkb.disabled = false; }
    });
    var vst = $('vpnSubnetToggle');
    if (vst) vst.addEventListener('change', async function () {
      if (!api || typeof api.vpnSetRoutes !== 'function') return vpnMissing();
      var on = vst.checked;
      try {
        var r = await api.vpnSetRoutes(on);
        if (r && r.success) {
          toast('VPN', on ? 'Sharing your home network — approve the route once in the Tailscale admin console.' : 'No longer sharing your home network.', 'success');
        } else { toast('VPN error', (r && r.error) || 'Could not change the subnet router setting.', 'error'); vst.checked = !on; }
        await loadVpn();
      } catch (e) { toast('VPN error', e && e.message ? e.message : 'Could not change the subnet router setting.', 'error'); vst.checked = !on; }
    });
    $('drawerClose').addEventListener('click', closeDrawer);
    $('drawerBackdrop').addEventListener('click', closeDrawer);
    $('drawerRun').addEventListener('click', function () { if (currentJob) runBackup(currentJob, false); });
    $('drawerRestore').addEventListener('click', function () { if (currentJob) openRestore(currentJob); });
    $('drawerEdit').addEventListener('click', function () { if (currentJob) { closeDrawer(); openJobWizard(currentJob); } });
    $('drawerDelete').addEventListener('click', async function () {
      if (!currentJob) return;
      try {
        const result = await api.deleteJob(currentJob.id);
        if (result.success) {
          toast('Job deleted', currentJob.name + ' has been deleted.', 'success');
          closeDrawer();
          await refreshJobs();
        } else {
          toast('Delete failed', result.error || 'Could not delete job.', 'error');
        }
      } catch (e) {
        toast('Delete error', e && e.message ? e.message : 'Could not delete job.', 'error');
      }
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeDrawer(); closeSettings(); } });

    document.querySelectorAll('#logsTabs .log-tab').forEach(function (btn) {
      btn.addEventListener('click', function () { renderLogs(btn.getAttribute('data-logtab')); });
    });
    var lrb = $('logsRefreshBtn');
    if (lrb) lrb.addEventListener('click', function () { loadJobs().then(function () { renderLogs(currentLogTab); }); });
    var llf = $('logsLevelFilter');
    if (llf) llf.addEventListener('change', renderFullLog);
    var ls = $('logsSearch');
    if (ls) ls.addEventListener('input', renderFullLog);

    /* ---------- TechVision Cloud wiring ---------- */
    var crb = $('cloudRefreshBtn');
    if (crb) crb.addEventListener('click', function () { loadCloud(); });
    var cms = $('cloudModeServer');
    if (cms) cms.addEventListener('click', function () { showCloudPanel('server'); });
    var cmc = $('cloudModeClient');
    if (cmc) cmc.addEventListener('click', function () { showCloudPanel('client'); });
    var css = $('cloudServerStartBtn');
    if (css) css.addEventListener('click', async function () {
      if (!api || typeof api.cloudServerStart !== 'function' || typeof api.cloudServerStop !== 'function') return cloudMissing();
      try {
        var running = cloudCfg && cloudCfg.server && cloudCfg.server.running;
        if (running) {
          var rs = await api.cloudServerStop();
          if (rs && rs.success) { toast('Server stopped', 'The Cloud server is stopped.', 'success'); await loadCloud(); }
          else toast('Server error', (rs && rs.error) || 'Could not stop the server.', 'error');
          return;
        }
        // Starting applies the port shown in the field first — changing
        // the port and pressing Start must not silently start the old one.
        var port = parseInt(($('cloudServerPort') || {}).value, 10);
        var saved = await api.cloudServerSave({ enabled: $('cloudServerEnabled') ? $('cloudServerEnabled').checked : true, port: port, accessMode: cloudServerAccess });
        if (!saved || !saved.success) { toast('Save failed', (saved && saved.error) || 'Could not save Cloud settings.', 'error'); return; }
        var r = await api.cloudServerStart();
        if (r && r.success) { toast('Server started', 'The Cloud server is running.', 'success'); await loadCloud(); }
        else toast('Server error', (r && r.error) || 'Could not start the server.', 'error');
      } catch (e) { toast('Server error', e && e.message ? e.message : 'Could not change the server state.', 'error'); }
    });
    var csv = $('cloudServerSaveBtn');
    if (csv) csv.addEventListener('click', async function () {
      if (!api || typeof api.cloudServerSave !== 'function') return cloudMissing();
      try {
        var port = parseInt(($('cloudServerPort') || {}).value, 10);
        var r = await api.cloudServerSave({ enabled: $('cloudServerEnabled') ? $('cloudServerEnabled').checked : false, port: port, accessMode: cloudServerAccess });
        if (r && r.success) { toast('Cloud settings saved', 'Server settings saved.', 'success'); await loadCloud(); }
        else toast('Save failed', (r && r.error) || 'Could not save Cloud settings.', 'error');
      } catch (e) { toast('Save error', e && e.message ? e.message : 'Could not save Cloud settings.', 'error'); }
    });
    var cdi = $('cloudDetectIpBtn');
    if (cdi) cdi.addEventListener('click', async function () {
      if (!api || typeof api.cloudDetectIP !== 'function') return cloudMissing();
      try {
        cdi.disabled = true; cdi.textContent = 'Detecting…';
        var r = await api.cloudDetectIP();
        var addrs = $('cloudServerAddrs');
        if (addrs) {
          var lines = [];
          if (r.publicIP) lines.push('Public (from outside): ' + r.publicIP);
          else lines.push('Public: unknown (no internet or detection failed)');
          if (r.lanIPs && r.lanIPs.length) lines.push('LAN (same network): ' + r.lanIPs.join(', '));
          addrs.textContent = lines.join(' — ');
        }
      } catch (e) { toast('Detect error', e && e.message ? e.message : 'Could not detect addresses.', 'error'); }
      finally { cdi.disabled = false; cdi.textContent = 'Detect my addresses'; }
    });
    var cub = $('cloudUserBrowseBtn');
    if (cub) cub.addEventListener('click', async function () {
      if (!api || typeof api.showOpenDialog !== 'function') return cloudMissing();
      try {
        var pick = await api.showOpenDialog({ properties: ['openDirectory'] });
        if (pick && !pick.canceled && pick.filePaths && pick.filePaths.length) {
          var f = $('cloudUserRoot'); if (f) f.value = pick.filePaths[0];
        }
      } catch (e) { toast('Browse error', e && e.message ? e.message : 'Could not open the folder picker.', 'error'); }
    });
    var cua = $('cloudUserAddBtn');
    if (cua) cua.addEventListener('click', async function () {
      if (!api || typeof api.cloudUserAdd !== 'function') return cloudMissing();
      try {
        var r = await api.cloudUserAdd({
          name: ($('cloudUserName') || {}).value || '',
          password: ($('cloudUserPass') || {}).value || '',
          root: ($('cloudUserRoot') || {}).value || '',
          canWrite: $('cloudUserCanWrite') ? $('cloudUserCanWrite').checked : false,
        });
        if (r && r.success) {
          toast('User added', r.user.name + ' can now connect.', 'success');
          var n = $('cloudUserName'); if (n) n.value = '';
          var p = $('cloudUserPass'); if (p) p.value = '';
          var rt = $('cloudUserRoot'); if (rt) rt.value = '';
          await loadCloud();
        } else toast('Add user failed', (r && r.error) || 'Could not add user.', 'error');
      } catch (e) { toast('Add user error', e && e.message ? e.message : 'Could not add user.', 'error'); }
    });
    var cca = $('cloudClientAddBtn');
    if (cca) cca.addEventListener('click', async function () {
      if (!api || typeof api.cloudClientSave !== 'function') return cloudMissing();
      try {
        var password = ($('cloudClientPass') || {}).value || '';
        var r = await api.cloudClientSave({
          name: ($('cloudClientName') || {}).value || '',
          host: ($('cloudClientHost') || {}).value || '',
          port: parseInt(($('cloudClientPort') || {}).value, 10),
          user: ($('cloudClientUser') || {}).value || '',
          accessMode: cloudClientAccess,
        });
        if (r && r.success) {
          toast('Server saved', 'Server added to the list.', 'success');
          var n2 = $('cloudClientName'); if (n2) n2.value = '';
          var h2 = $('cloudClientHost'); if (h2) h2.value = '';
          var u2 = $('cloudClientUser'); if (u2) u2.value = '';
          var p2 = $('cloudClientPass'); if (p2) p2.value = '';
          await loadCloud();
          // Save & connect: open the connect box with the password the
          // user just typed (it is never stored), and connect at once
          // when this server is already trusted.
          var rec = (cloudCfg && cloudCfg.clients || []).find(function (c) { return c.id === r.id; });
          if (rec) {
            openCloudConnect(rec, password);
            if (rec.fingerprint && password) cloudConnectFlow();
          }
        } else toast('Save failed', (r && r.error) || 'Could not save server.', 'error');
      } catch (e) { toast('Save error', e && e.message ? e.message : 'Could not save server.', 'error'); }
    });
    var ccb2 = $('cloudConnectBtn');
    if (ccb2) ccb2.addEventListener('click', function () { cloudConnectFlow(); });
    var ccc = $('cloudConnectCancelBtn');
    if (ccc) ccc.addEventListener('click', function () { closeCloudConnect(); });
    var ccp = $('cloudConnectPass');
    if (ccp) ccp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') cloudConnectFlow(); });
    var cdb = $('cloudDisconnectBtn');
    if (cdb) cdb.addEventListener('click', function () { cloudDisconnect(); });
    var cub2 = $('cloudUploadBtn');
    if (cub2) cub2.addEventListener('click', function () { cloudUpload(); });
    var cmb = $('cloudMkdirBtn');
    if (cmb) cmb.addEventListener('click', function () {
      askCloudInput('New folder', 'Folder name', '', async function (val) {
        if (!val) return;
        if (!isSingleCloudName(val)) { toast('Invalid name', 'Use a plain name without / \\ or special characters.', 'error'); return; }
        if (!api || typeof api.cloudClientMkdir !== 'function') return cloudMissing();
        try {
          var r = await api.cloudClientMkdir(cloudConn.serverId, cloudJoin(cloudPath, val));
          if (r && r.success) { toast('Folder created', val, 'success'); await cloudBrowse(cloudPath); }
          else toast('Create failed', (r && r.error) || 'Could not create folder.', 'error');
        } catch (e) { toast('Create error', e && e.message ? e.message : 'Could not create folder.', 'error'); }
      });
    });
    var cbr = $('cloudBrowserRefreshBtn');
    if (cbr) cbr.addEventListener('click', function () { cloudBrowse(cloudPath); });
    var cpo = $('cloudPromptOk');
    if (cpo) cpo.addEventListener('click', function () {
      var cb = cloudPromptCallback;
      var v = ($('cloudPromptInput') || {}).value || '';
      closeCloudPrompt();
      if (cb) cb(v);
    });
    var cpc = $('cloudPromptCancel');
    if (cpc) cpc.addEventListener('click', function () { closeCloudPrompt(); });
    var cpb = $('cloudPromptBackdrop');
    if (cpb) cpb.addEventListener('click', function () { closeCloudPrompt(); });
    var cpi = $('cloudPromptInput');
    if (cpi) cpi.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') { var cb = cloudPromptCallback; var v = cpi.value || ''; closeCloudPrompt(); if (cb) cb(v); }
      if (ev.key === 'Escape') closeCloudPrompt();
    });
    if (api && typeof api.onCloudProgress === 'function') {
      api.onCloudProgress(function (p) {
        if (!p) return;
        var kind = p.kind === 'upload' ? 'Uploading' : 'Downloading';
        showCloudTransfer(kind + ' ' + (p.name || '') + ' — ' + Math.round(p.pct || 0) + '%', p.pct || 0);
      });
    }

    document.querySelectorAll('[data-module-enter]').forEach(function (card) {
      card.addEventListener('click', function () { setModule(card.getAttribute('data-module-enter')); });
    });
    var tbb = $('topBackBtn');
    if (tbb) tbb.addEventListener('click', goBack);

    loadSettings().then(function () { loadJobs(); checkVaultOnStartup(); refreshVaultStatus(); });
    showView('modules');
  });
})();
