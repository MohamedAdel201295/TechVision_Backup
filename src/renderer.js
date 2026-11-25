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
  /* ---------- modules: Backup / Cloud / VPN / WireGuard ----------
     The sidebar has four top-level modules. Backup owns Dashboard, Jobs,
     Logs, New Job and Restore; Cloud owns Server and Client; VPN is a
     single Tailscale view; WireGuard VPN is a single self-hosted
     WireGuard view (server + client). Switching modules swaps the
     visible nav group; going back to Backup returns to the last backup
     view instead of always resetting to Dashboard. */
  var currentModule = 'backup';
  var lastBackupView = 'dashboard';

  function applyModuleUI(mod) {
    currentModule = mod;
    var gb = $('navGroupBackup'); if (gb) gb.style.display = mod === 'backup' ? '' : 'none';
    var gc = $('navGroupCloud'); if (gc) gc.style.display = mod === 'cloud' ? '' : 'none';
    var gv = $('navGroupVpn'); if (gv) gv.style.display = mod === 'vpn' ? '' : 'none';
    var gw = $('navGroupWireguard'); if (gw) gw.style.display = mod === 'wireguard' ? '' : 'none';
    document.querySelectorAll('.module-item').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-module') === mod); });
  }

  function setModule(mod) {
    applyModuleUI(mod);
    if (mod === 'backup') showView(lastBackupView || 'dashboard');
    else if (mod === 'cloud') showView('cloud');
    else if (mod === 'vpn') showView('vpn');
    else if (mod === 'wireguard') showView('wireguard');
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
    var wgView = $('view-wireguard');
    var modulesView = $('view-modules');
    if (dash) dash.style.display = name === 'dashboard' ? '' : 'none';
    if (jobsView) jobsView.style.display = name === 'jobs' ? '' : 'none';
    if (logsView) logsView.style.display = name === 'logs' ? '' : 'none';
    if (cloudView) cloudView.style.display = name === 'cloud' ? '' : 'none';
    if (vpnView) vpnView.style.display = name === 'vpn' ? '' : 'none';
    if (wgView) wgView.style.display = name === 'wireguard' ? '' : 'none';
    if (modulesView) modulesView.style.display = name === 'modules' ? '' : 'none';
    /* One refresh per module, at the top — the same ⟳ icon-button
       pattern as the Tailscale one, shown only while its module is
       active. The settings gear lives in the Backup module only:
       it is hidden in Cloud, Tailscale VPN and WireGuard, and on
       the module chooser (the drawer itself is unchanged — basic
       Backup settings only). */
    var isBackup = name === 'dashboard' || name === 'jobs' || name === 'logs';
    var gb2 = $('settingsBtn'); if (gb2) gb2.style.display = isBackup ? '' : 'none';
    var brb = $('backupTopRefreshBtn'); if (brb) brb.style.display = isBackup ? '' : 'none';
    var crb2 = $('cloudTopRefreshBtn'); if (crb2) crb2.style.display = name === 'cloud' ? '' : 'none';
    var tr = $('vpnTopRefreshBtn'); if (tr) tr.style.display = name === 'vpn' ? '' : 'none';
    var wrb = $('wgTopRefreshBtn'); if (wrb) wrb.style.display = name === 'wireguard' ? '' : 'none';
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
      setAppTitle('TechVision Tailscale VPN', 'Your private network — every device, anywhere, as if it were home.');
      loadVpn();
    }
    if (name === 'wireguard') {
      applyModuleUI('wireguard');
      setBackTitle('WireGuard VPN');
      setAppTitle('TechVision WireGuard VPN', 'Your own VPN server — no accounts, no middleman, one port on the router.');
      loadWireGuard();
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
    if (c === 'advanced') return 'Advanced — Deflate level 9';
    return 'Standard — Deflate level 6';
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
      card.querySelector('.d-schedule').textContent = scheduleLabel(sched) || 'Manual only';
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
    // The "your own remote drive" intro belongs to the Cloud home only —
    // inside Server/Client it is just a repeated sentence above the panel.
    var ht = $('cloudViewHeadText'); if (ht) ht.style.display = panel === 'home' ? '' : 'none';
    var sp = $('cloudServerPanel'); if (sp) sp.style.display = panel === 'server' ? '' : 'none';
    var cp = $('cloudClientPanel'); if (cp) cp.style.display = panel === 'client' ? '' : 'none';
    if (panel === 'server') renderCloudServer();
    if (panel === 'client') { renderCloudClientList(); if (cloudClientAccess === 'tailscale') populateCloudPeers(); if (cloudClientAccess === 'wireguard') populateCloudWgPeers(); }
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
  // Serializes Cloud server saves: an auto-save triggered by a blur can
  // otherwise race Start's own save, and two concurrent saves could both
  // try to start the server (main's save handler applies the config —
  // starting/stopping the server to match `enabled`).
  var cloudServerSaveQueue = Promise.resolve();

  // Server settings save themselves the moment anything changes — the
  // old "Save settings" button was the only thing standing between a
  // change and the config file, so it is gone. Silent on success (the
  // status pill / Tailscale line already show the result); a toast only
  // when the save fails. Note main's save handler also APPLIES the
  // config: flipping "Server enabled" on starts the server, off stops it.
  function saveCloudServerSettings() {
    cloudServerSaveQueue = cloudServerSaveQueue.then(async function () {
      if (!api || typeof api.cloudServerSave !== 'function') { cloudMissing(); return; }
      try {
        var port = parseInt(($('cloudServerPort') || {}).value, 10);
        var r = await api.cloudServerSave({ enabled: $('cloudServerEnabled') ? $('cloudServerEnabled').checked : false, port: port, accessMode: cloudServerAccess });
        if (r && r.success) { await loadCloud(); }
        else toast('Save failed', (r && r.error) || 'Could not save Cloud settings.', 'error');
      } catch (e) { toast('Save error', e && e.message ? e.message : 'Could not save Cloud settings.', 'error'); }
    });
    return cloudServerSaveQueue;
  }

  function setServerAccess(mode) {
    cloudServerAccess = mode === 'tailscale' ? 'tailscale' : mode === 'wireguard' ? 'wireguard' : 'normal';
    document.querySelectorAll('#cloudServerAccessSeg .seg-btn').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-access') === cloudServerAccess); });
    var hint = $('cloudServerAccessHint');
    if (hint) hint.textContent = cloudServerAccess === 'tailscale'
      ? 'Clients on the same Tailscale network use the Tailscale address below + this port. No port forwarding needed.'
      : cloudServerAccess === 'wireguard'
        ? 'Clients on the same WireGuard tunnel use the tunnel address below + this port. No port forwarding needed.'
        : 'Clients use your public static IP or DDNS + this port (forward the port in your router).';
    var ti = $('cloudTailscaleInfo'); if (ti) ti.style.display = cloudServerAccess === 'tailscale' ? '' : 'none';
    var wi = $('cloudWireguardInfo'); if (wi) wi.style.display = cloudServerAccess === 'wireguard' ? '' : 'none';
    var fg = $('cloudForwardGuide'); if (fg) fg.style.display = cloudServerAccess === 'normal' ? '' : 'none';
    // The port is the port the server listens on in every mode — but
    // the "forward it in your router" note only applies to Normal
    // mode. In either VPN mode it was telling the user to forward a
    // port that needs no forwarding. Same for the Addresses block:
    // in VPN modes the public and LAN addresses are useless here
    // (the tunnel address above is the only one clients need), so
    // hide the whole block.
    var ph = $('cloudServerPortHint');
    if (ph) ph.textContent = cloudServerAccess === 'tailscale'
      ? 'The port this server listens on. Clients connect to the Tailscale address above + this port — no port forwarding needed.'
      : cloudServerAccess === 'wireguard'
        ? 'The port this server listens on. Clients connect to the WireGuard tunnel address above + this port — no port forwarding needed.'
        : 'Forward this TCP port in your router to this computer. Do not open DMZ — forward this one port only.';
    var af = $('cloudServerAddrsField'); if (af) af.style.display = cloudServerAccess === 'normal' ? '' : 'none';
    if (cloudServerAccess === 'tailscale') refreshCloudTailscaleIp();
    if (cloudServerAccess === 'wireguard') refreshCloudWireguardIp();
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

  /* Same idea as refreshCloudTailscaleIp, for the WireGuard tunnel:
     the address clients need is this computer's tunnel address —
     the server address when this machine is the hub, or the client
     tunnel address when it joined as a client (the Cloud server
     listens on all interfaces, so it is reachable on the tunnel
     interface either way). */
  async function refreshCloudWireguardIp() {
    var el = $('cloudWireguardIp'); if (!el) return;
    if (!api || typeof api.wgGetStatus !== 'function') { el.textContent = 'WireGuard module is not available.'; return; }
    el.textContent = 'Checking WireGuard…';
    try {
      var st = await api.wgGetStatus();
      var addr = null;
      if (st && st.serverRunning && st.server && st.server.address) addr = String(st.server.address).split('/')[0];
      else if (st && st.clientRunning && st.client && st.client.tunnelIp) addr = st.client.tunnelIp;
      if (!st || !st.installed) el.textContent = 'AmneziaWG is not installed — install it from the WireGuard module.';
      else if (!addr) el.textContent = 'WireGuard is not connected on this computer — start the server or connect the client from the WireGuard module.';
      else el.textContent = addr + ' — give clients this address + port ' + String((cloudCfg && cloudCfg.server && cloudCfg.server.port) || 8443) + '.';
    } catch (e) { el.textContent = 'Could not read WireGuard status.'; }
  }

  function setClientAccess(mode) {
    cloudClientAccess = mode === 'tailscale' ? 'tailscale' : mode === 'wireguard' ? 'wireguard' : 'normal';
    document.querySelectorAll('#cloudClientAccessSeg .seg-btn').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-access') === cloudClientAccess); });
    var hint = $('cloudClientAccessHint');
    if (hint) hint.textContent = cloudClientAccess === 'tailscale'
      ? 'Tailscale IP (100.x.x.x) of the server — pick a device below or type it.'
      : cloudClientAccess === 'wireguard'
        ? 'WireGuard tunnel address (10.0.0.x) of the server — pick a device below or type it.'
        : 'Public IP, DDNS hostname or LAN IP of the server.';
    var host = $('cloudClientHost');
    if (host) host.placeholder = cloudClientAccess === 'tailscale' ? '100.64.0.1' : cloudClientAccess === 'wireguard' ? '10.0.0.1' : '203.0.113.10';
    var pf = $('cloudClientPeerField'); if (pf) pf.style.display = cloudClientAccess === 'normal' ? 'none' : '';
    var pl = $('cloudClientPeerLabel');
    if (pl) pl.textContent = cloudClientAccess === 'wireguard' ? 'Pick a device from your WireGuard tunnel' : 'Pick a device from your Tailscale network';
    var ph2 = $('cloudClientPeerHint');
    if (ph2) ph2.textContent = cloudClientAccess === 'wireguard'
      ? 'Both devices must be on the same WireGuard tunnel — see the WireGuard module.'
      : 'Both devices must be on the same Tailscale network — see the VPN module.';
    if (cloudClientAccess === 'tailscale') populateCloudPeers();
    if (cloudClientAccess === 'wireguard') populateCloudWgPeers();
  }

  // Signature of the last peer list the picker was built from. The list
  // is re-read on a timer while the client panel is open (see the
  // poller in the wiring), so a device that joins later appears on its
  // own — but rebuilding the <select> on every tick would close an open
  // dropdown and drop the selection, so an unchanged list is left alone.
  var lastCloudPeerSig = null;
  async function populateCloudPeers() {
    var sel = $('cloudClientPeer'); if (!sel) return;
    if (!sel.options.length) { var chk = document.createElement('option'); chk.value = ''; chk.textContent = 'Checking Tailscale…'; sel.appendChild(chk); }
    if (!api || typeof api.vpnGetStatus !== 'function') { sel.innerHTML = ''; var na = document.createElement('option'); na.value = ''; na.textContent = 'VPN module is not available.'; sel.appendChild(na); return; }
    var st;
    try { st = await api.vpnGetStatus(); }
    catch (e) { sel.innerHTML = ''; var oe = document.createElement('option'); oe.value = ''; oe.textContent = 'Could not read Tailscale status.'; sel.appendChild(oe); return; }
    var sig = JSON.stringify({ installed: !!st.installed, connected: !!st.connected, peers: (st.peers || []).map(function (p) { return [p.ip, p.name, p.online]; }) });
    if (sig === lastCloudPeerSig) return;
    lastCloudPeerSig = sig;
    var prevValue = sel.value;
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
    // A rebuild must not drop the device the user already picked.
    if (prevValue) { for (var i = 0; i < sel.options.length; i++) if (sel.options[i].value === prevValue) { sel.value = prevValue; break; } }
  }

  /* Same idea as populateCloudPeers, for the WireGuard tunnel: the
     picker lists the WireGuard peers (name + tunnel IP) and — when
     this machine is a client — the server it connects to
     (tunnelServer). Same signature guard so an open dropdown is
     never disturbed. */
  var lastCloudWgPeerSig = null;
  async function populateCloudWgPeers() {
    var sel = $('cloudClientPeer'); if (!sel) return;
    if (!sel.options.length) { var chk = document.createElement('option'); chk.value = ''; chk.textContent = 'Checking WireGuard…'; sel.appendChild(chk); }
    if (!api || typeof api.wgGetStatus !== 'function') { sel.innerHTML = ''; var na = document.createElement('option'); na.value = ''; na.textContent = 'WireGuard module is not available.'; sel.appendChild(na); return; }
    var st;
    try { st = await api.wgGetStatus(); }
    catch (e) { sel.innerHTML = ''; var oe = document.createElement('option'); oe.value = ''; oe.textContent = 'Could not read WireGuard status.'; sel.appendChild(oe); return; }
    var cands = (st.peers || []).map(function (p) { return [p.tunnelIp, p.name, p.online]; });
    if (st.tunnelServer && st.tunnelServer.tunnelIp) cands.push([st.tunnelServer.tunnelIp, 'Server', st.tunnelServer.online]);
    var sig = JSON.stringify({ installed: !!st.installed, serverRunning: !!st.serverRunning, clientRunning: !!st.clientRunning, peers: cands });
    if (sig === lastCloudWgPeerSig) return;
    lastCloudWgPeerSig = sig;
    var prevValue = sel.value;
    sel.innerHTML = '';
    if (!st || !st.installed) { var o1 = document.createElement('option'); o1.value = ''; o1.textContent = 'AmneziaWG is not installed — see the WireGuard module.'; sel.appendChild(o1); return; }
    if (!st.serverRunning && !st.clientRunning) { var o2 = document.createElement('option'); o2.value = ''; o2.textContent = 'WireGuard is not connected — start the server or connect the client from the WireGuard module.'; sel.appendChild(o2); return; }
    if (!cands.length) { var o3 = document.createElement('option'); o3.value = ''; o3.textContent = 'No other devices on your WireGuard tunnel yet.'; sel.appendChild(o3); return; }
    var blank = document.createElement('option'); blank.value = ''; blank.textContent = 'Choose a device…'; sel.appendChild(blank);
    cands.forEach(function (c) {
      if (!c[0]) return;
      var o = document.createElement('option'); o.value = c[0]; o.textContent = c[1] + ' — ' + c[0] + (c[2] ? '' : ' (offline)');
      o.setAttribute('data-peer-name', c[1]);
      sel.appendChild(o);
    });
    if (prevValue) { for (var i = 0; i < sel.options.length; i++) if (sel.options[i].value === prevValue) { sel.value = prevValue; break; } }
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
      meta.textContent = (srv.accessMode === 'tailscale' ? '🛡️ Tailscale' : srv.accessMode === 'wireguard' ? '🔐 WireGuard' : '🌐 Normal') + ' — ' + srv.host + ':' + srv.port + ' — user ' + (srv.user || '—') + (srv.fingerprint ? ' — certificate trusted' : ' — not trusted yet') + (srv.hasPassword ? ' — password saved on this device' : '');
      var acts = document.createElement('div'); acts.className = 'drawer-actions';
      // Already connected to this server: say so instead of offering
      // Connect again — Disconnect lives in the browser toolbar below.
      if (cloudConn && cloudConn.serverId === srv.id) {
        var badge = document.createElement('span'); badge.className = 'cloud-connected-badge'; badge.textContent = '● Connected';
        acts.appendChild(badge);
      } else {
        // One click when the password is saved on this device: connect
        // straight in (the main process uses the stored password). Without
        // one, the connect box opens and asks for it.
        var open = document.createElement('button'); open.className = 'btn btn-primary btn-sm'; open.type = 'button'; open.textContent = (srv.hasPassword && srv.fingerprint) ? 'Connect' : 'Open';
        open.addEventListener('click', function () {
          if (srv.hasPassword && srv.fingerprint) cloudConnectSaved(srv);
          else openCloudConnect(srv);
        });
        acts.appendChild(open);
      }
      var forget = null;
      if (srv.hasPassword) {
        forget = document.createElement('button'); forget.className = 'btn btn-ghost btn-sm'; forget.type = 'button'; forget.textContent = '🔑 Forget password';
        forget.addEventListener('click', async function () {
          if (!api || typeof api.cloudClientForgetPassword !== 'function') return cloudMissing();
          try { var r = await api.cloudClientForgetPassword(srv.id); if (r && r.success) { toast('Cloud', 'Saved password forgotten — you will type it next time.', 'success'); await loadCloud(); } else toast('Forget failed', (r && r.error) || 'Could not forget the password.', 'error'); }
          catch (e) { toast('Forget error', e && e.message ? e.message : 'Could not forget the password.', 'error'); }
        });
      }
      var del = document.createElement('button'); del.className = 'btn btn-danger btn-sm'; del.type = 'button'; del.textContent = '🗑 Remove';
      del.addEventListener('click', function () {
        askConfirm('Remove server "' + srv.name + '" from the list?', async function () {
          if (!api || typeof api.cloudClientRemove !== 'function') return cloudMissing();
          try {
            if (cloudConn && cloudConn.serverId === srv.id) await cloudDisconnect();
            await api.cloudClientRemove(srv.id); await loadCloud();
          }
          catch (e) { toast('Remove error', e && e.message ? e.message : 'Could not remove server.', 'error'); }
        });
      });
      if (forget) acts.appendChild(forget); acts.appendChild(del);
      body.appendChild(h); body.appendChild(meta); body.appendChild(acts);
      card.appendChild(body);
      list.appendChild(card);
    });
  }

  function openCloudConnect(srv, presetPassword) {
    cloudSelected = srv;
    cloudPendingProbe = null;
    var box = $('cloudConnectBox'); if (box) box.style.display = '';
    var title = $('cloudConnectTitle'); if (title) title.textContent = 'Connect to ' + srv.name + (srv.user ? ' as ' + srv.user : '');
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

  // One click on a saved server: the password is already on this device
  // (the main process uses the stored one), so go straight in — no box.
  async function cloudConnectSaved(srv) {
    cloudSelected = srv;
    cloudPendingProbe = null;
    await cloudConnectFlow(true, null);
  }

  // passwordOverride: undefined = read the connect box (the usual path);
  // null = use the password saved on this device (one-click reconnect).
  /* WireGuard tunnel pre-check for a Cloud server in 'wireguard'
     mode — mirrors main's wgTunnelToPeerCheck: the tunnel has to be
     up before any probe/connect, or the login would wait out the
     15s probe timeout and fail with a network error. Server role:
     the host must be a live peer (a recent handshake); client
     role: the client must be online and the host must be the
     server's tunnel address (.1 of the tunnel subnet). */
  async function wgTunnelUpFor(host) {
    if (!api || typeof api.wgGetStatus !== 'function') return { ok: false, error: 'WireGuard module is not available.' };
    try {
      var st = await api.wgGetStatus();
      var h = String(host || '').trim();
      var peer = (st.peers || []).find(function (p) { return p.tunnelIp === h; });
      if (peer) {
        if (peer.online) return { ok: true };
        return { ok: false, error: 'The WireGuard tunnel to ' + h + ' is not up — the peer is known but has not handshaken yet. Start the server on the other machine and check it connects.' };
      }
      if (st.client && st.client.tunnelIp && st.client.online) {
        var parts = String(st.client.tunnelIp).split('.');
        var serverIp = parts.length === 4 ? (parts[0] + '.' + parts[1] + '.' + parts[2] + '.1') : '';
        if (h === serverIp) return { ok: true };
        return { ok: false, error: 'The WireGuard tunnel is up, but the server address ' + h + ' is not the tunnel server (' + serverIp + '). Pick the server from the WireGuard peer list.' };
      }
      return { ok: false, error: 'The WireGuard tunnel is not up — connect the WireGuard client (or start the server) first, then connect to the Cloud server.' };
    } catch (e) { return { ok: false, error: 'Could not check the WireGuard tunnel: ' + (e && e.message ? e.message : String(e)) }; }
  }

  async function cloudConnectFlow(autoTrust, passwordOverride) {
    if (!cloudSelected) return;
    if (!api || typeof api.cloudClientProbe !== 'function' || typeof api.cloudClientConnect !== 'function') return cloudMissing();
    /* WireGuard mode: the tunnel has to be up before probing — a
       down tunnel fails fast here with a clear message instead of
       waiting out the 15s probe timeout. Main re-checks the same
       way in cloud-client-connect for the trusted path. */
    var wgMode = (cloudSelected.accessMode || cloudClientAccess) === 'wireguard';
    if (wgMode) {
      var wgCheck = await wgTunnelUpFor(cloudSelected.host);
      if (!wgCheck.ok) { toast('WireGuard tunnel is down', wgCheck.error, 'error'); return; }
    }
    var btn = $('cloudConnectBtn');
    var pass = $('cloudConnectPass');
    var password = passwordOverride !== undefined ? (passwordOverride || '') : (pass ? pass.value : '');
    var justTrusted = null; // fingerprint trusted in this very click
    // No trusted certificate yet: probe the server first (nothing
    // sensitive is sent to probe), then trust its fingerprint.
    if (!cloudSelected.fingerprint) {
      if (!cloudPendingProbe) {
        try {
          if (btn) { btn.disabled = true; btn.textContent = 'Checking server…'; }
          var probe = await api.cloudClientProbe(cloudSelected.host, cloudSelected.port);
          if (!probe || !probe.success) { toast('Cannot reach server', (probe && probe.error) || 'Check the address and port.', 'error'); return; }
          cloudPendingProbe = { fingerprint: probe.fingerprint, certPem: probe.certPem };
        } catch (e) {
          toast('Cannot reach server', e && e.message ? e.message : 'Check the address and port.', 'error');
          return;
        } finally {
          // A failed probe must leave the button usable again, with its
          // normal label — otherwise it stays stuck on "Checking server…".
          if (btn) { btn.disabled = false; if (btn.textContent === 'Checking server…') btn.textContent = 'Connect'; }
        }
        if (!autoTrust) {
          // Manual path: show the fingerprint and wait for the user to
          // compare it with the server screen and press Trust & connect.
          var ft = $('cloudFingerprintText'); if (ft) ft.textContent = cloudPendingProbe.fingerprint;
          var fbox = $('cloudFingerprintBox'); if (fbox) fbox.style.display = '';
          if (btn) btn.textContent = 'Trust & connect';
          toast('Check the fingerprint', 'Compare it with the fingerprint shown on the server, then press Trust & connect.', '');
          return;
        }
        // Save & connect asked for one click: trust this fingerprint
        // now and keep going to connect below. It is shown in the
        // Connected toast and stays pinned afterwards; a changed
        // certificate is still refused on the next connect.
      }
      // Trust the probed fingerprint (user pressed Trust & connect, or
      // Save & connect is doing the whole thing in one click).
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
        justTrusted = cloudPendingProbe.fingerprint;
        var fp = $('cloudFingerprintBox'); if (fp) fp.style.display = 'none';
        await loadCloud();
      } catch (e) {
        toast('Save error', e && e.message ? e.message : 'Could not save server.', 'error');
        return;
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Connect'; }
      }
    }
    // Trusted certificate: connect with the password — typed in the box,
    // or the one saved on this device when this is a one-click reconnect.
    if (!password && !cloudSelected.hasPassword) { toast('Password needed', 'Enter the password for user ' + (cloudSelected.user || '') + '.', 'error'); return; }
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
        certPem: certPem, user: cloudSelected.user, password: password || null,
      });
      if (!r || !r.success) { toast('Connection failed', (r && r.error) || 'Wrong user name or password.', 'error'); return; }
      // Keep the server name: closeCloudConnect() clears cloudSelected.
      cloudConn = { serverId: cloudSelected.id, info: r.info, name: cloudSelected.name };
      if (pass) pass.value = '';
      closeCloudConnect();
      cloudPath = '';
      var browser = $('cloudBrowser'); if (browser) browser.style.display = '';
      toast('Connected', 'Signed in as ' + (r.info.user || cloudSelected.user) + (r.info.canWrite ? ' (read + write).' : ' (read-only).') + (justTrusted ? ' Server fingerprint ' + justTrusted.slice(0, 16) + '… trusted.' : ''));
      renderCloudHome();
      // Re-read the config: a typed password was just saved on this
      // device, so the server card must now show Connect + Forget
      // without waiting for the user to navigate away and back.
      await loadCloud();
      await cloudBrowse('');
      cloudStartPoller();
    } catch (e) {
      toast('Connection failed', e && e.message ? e.message : 'Could not connect.', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Connect'; }
    }
  }

  async function cloudDisconnect() {
    cloudHideContextMenu();
    if (cloudConn && api && typeof api.cloudClientDisconnect === 'function') {
      try { await api.cloudClientDisconnect(cloudConn.serverId); } catch (e) {}
    }
    cloudStopPoller();
    cloudLinkDown = false;
    cloudReloginTried = false;
    cloudSetConnBanner(false);
    cloudConn = null;
    cloudPath = '';
    cloudSelectedEntry = null;
    cloudClipboard = null;
    var browser = $('cloudBrowser'); if (browser) browser.style.display = 'none';
    renderCloudHome();
    // The server card must go back to Connect/Open instead of keeping
    // its "Connected" badge.
    renderCloudClientList();
  }

  /* ---------- Cloud client auto-refresh ----------
     While connected, the file list is re-read every 10 seconds, so a
     file added on the server (or a server that goes down) shows up on
     its own — no manual Refresh, no disconnect + Save & connect.
     - List succeeds and the folder changed: re-render (the selection
       is kept by name, like a manual refresh).
     - Server unreachable: the browser shows "Disconnected — retrying"
       and the poller keeps trying; the moment the server answers, the
       list comes back on its own.
     - Session dead (the server was stopped — stopping clears sessions):
       sign in again automatically with the password saved on this
       device. Exactly one attempt per incident: a wrong saved password
       must not hammer the server into its login lockout. Without a
       saved password the client disconnects and says so. */
  var cloudPollTimer = null;
  var cloudPollBusy = false;
  var cloudLinkDown = false;
  var cloudReloginTried = false;
  var cloudLastSig = '';
  function cloudStartPoller() {
    cloudStopPoller();
    cloudPollTimer = setInterval(cloudPollTick, 10000);
  }
  function cloudStopPoller() {
    if (cloudPollTimer) { clearInterval(cloudPollTimer); cloudPollTimer = null; }
  }
  function cloudEntriesSig(entries) {
    return (entries || []).map(function (e) { return e.name + '|' + (e.isDir ? 'd' : 'f') + '|' + (e.size || 0) + '|' + (e.mtime || ''); }).join('\n');
  }
  function cloudSetConnBanner(show, text) {
    var b = $('cloudConnBanner');
    if (!b) return;
    if (show) { b.style.display = ''; b.textContent = text || ''; }
    else b.style.display = 'none';
  }
  async function cloudPollTick() {
    if (!cloudConn || cloudPollBusy || cloudTransferBusy) return;
    if (cloudPanel !== 'client') return; // only while the client panel is open
    if (!api || typeof api.cloudClientList !== 'function') return;
    cloudPollBusy = true;
    try {
      var r = await api.cloudClientList(cloudConn.serverId, cloudPath);
      if (r && r.success) {
        if (cloudLinkDown) { cloudLinkDown = false; cloudSetConnBanner(false); cloudReloginTried = false; toast('Reconnected', 'The server is reachable again.', 'success'); renderCloudHome(); }
        if ((r.path || '') === cloudPath && cloudEntriesSig(r.entries || []) !== cloudLastSig) renderCloudBrowser(r.entries || []);
        return;
      }
      if (r && r.code === 'auth') { await cloudPollRelogin(); return; }
      if (r && r.code === 'unreachable') {
        if (!cloudLinkDown) { cloudLinkDown = true; cloudSetConnBanner(true, 'Disconnected — the server is not reachable. Retrying automatically…'); cloudUpdateToolbar(); }
        return;
      }
      // Any other error (e.g. the folder was deleted on the server):
      // leave the view alone — a manual browse will surface it.
    } catch (e) {
      if (!cloudLinkDown) { cloudLinkDown = true; cloudSetConnBanner(true, 'Disconnected — the server is not reachable. Retrying automatically…'); cloudUpdateToolbar(); }
    } finally { cloudPollBusy = false; }
  }
  async function cloudPollRelogin() {
    if (cloudReloginTried) return;
    cloudReloginTried = true;
    var srv = (cloudCfg && cloudCfg.clients || []).find(function (c) { return c.id === cloudConn.serverId; });
    if (!srv || !srv.hasPassword) {
      // No saved password: nothing automatic to do — disconnect and
      // say so instead of looping on a dead session.
      toast('Session expired', 'The server was restarted or the session ended. Press Connect on the server to sign in again.', 'error');
      await cloudDisconnect();
      return;
    }
    try {
      // The renderer never holds the certificate itself — re-probe for
      // it (the fingerprint must still match the trusted one).
      var certPem = srv.certPem || null;
      if (!certPem) {
        var p = await api.cloudClientProbe(srv.host, srv.port);
        if (!p || !p.success) {
          cloudReloginTried = false;
          if (!cloudLinkDown) { cloudLinkDown = true; cloudSetConnBanner(true, 'Disconnected — the server is not reachable. Retrying automatically…'); cloudUpdateToolbar(); }
          return;
        }
        if (p.fingerprint !== srv.fingerprint) {
          toast('Certificate changed', 'The server certificate does not match the trusted fingerprint. Remove the server and add it again.', 'error');
          await cloudDisconnect();
          return;
        }
        certPem = p.certPem;
      }
      var r = await api.cloudClientConnect({
        serverId: srv.id, host: srv.host, port: srv.port,
        certPem: certPem, user: srv.user, password: null,
      });
      if (r && r.success) {
        cloudConn = { serverId: srv.id, info: r.info, name: srv.name };
        cloudLinkDown = false;
        cloudSetConnBanner(false);
        cloudReloginTried = false;
        toast('Reconnected', 'Signed in again automatically.', 'success');
        renderCloudHome();
        await cloudBrowse(cloudPath);
        return;
      }
      if (r && /Cannot reach the server|did not answer in time/i.test(r.error || '')) {
        // The server is down, not the password: keep retrying the list,
        // and allow one fresh login attempt once it answers again.
        cloudReloginTried = false;
        if (!cloudLinkDown) { cloudLinkDown = true; cloudSetConnBanner(true, 'Disconnected — the server is not reachable. Retrying automatically…'); cloudUpdateToolbar(); }
        return;
      }
      toast('Session expired', 'Could not sign in again automatically: ' + ((r && r.error) || 'unknown error') + ' — press Connect on the server to sign in again.', 'error');
      await cloudDisconnect();
    } catch (e) {
      if (!cloudLinkDown) { cloudLinkDown = true; cloudSetConnBanner(true, 'Disconnected — the server is not reachable. Retrying automatically…'); cloudUpdateToolbar(); }
    }
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
    if (cloudLinkDown) return; // the banner already says why; the poller clears this
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

  var cloudSelectedEntry = null; // { name, isDir, rel } — the one selected row
  var cloudClipboard = null;     // { rel, name, isDir } copied on the server
  var cloudLastEntries = [];     // entries of the folder now shown

  function cloudCanWrite() { return !!(cloudConn && cloudConn.info && cloudConn.info.canWrite); }

  // Explorer-style free name for a server-side copy: pasting into another
  // folder keeps the name when it is free, pasting next to the original
  // becomes "report - copy.pdf", then "report - copy (2).pdf".
  function cloudCopyName(name, isDir, existing) {
    if (existing.indexOf(name) < 0) return name;
    var base = name, ext = '';
    if (!isDir) { var i = name.lastIndexOf('.'); if (i > 0) { base = name.slice(0, i); ext = name.slice(i); } }
    var cand = base + ' - copy' + ext;
    if (existing.indexOf(cand) < 0) return cand;
    var n = 2;
    while (existing.indexOf(base + ' - copy (' + n + ')' + ext) >= 0) n++;
    return base + ' - copy (' + n + ')' + ext;
  }

  function cloudFileType(name) {
    var i = String(name || '').lastIndexOf('.');
    if (i <= 0) return 'File';
    var ext = name.slice(i + 1).toUpperCase();
    return ext ? ext + ' file' : 'File';
  }

  // Files copied in Windows Explorer also count for Paste: the check is
  // cheap (one local clipboard read) and cached for 2 seconds, so the
  // toolbar does not hammer it on every render.
  var cloudSysClipCache = { at: 0, has: false, count: 0 };
  async function cloudRefreshSysClip() {
    if (Date.now() - cloudSysClipCache.at < 2000) return cloudSysClipCache.has;
    cloudSysClipCache.at = Date.now();
    try {
      var f = (api && typeof api.cloudClipboardFiles === 'function') ? await api.cloudClipboardFiles() : [];
      cloudSysClipCache.has = Array.isArray(f) && f.length > 0;
      cloudSysClipCache.count = Array.isArray(f) ? f.length : 0;
    } catch (e) { cloudSysClipCache.has = false; cloudSysClipCache.count = 0; }
    return cloudSysClipCache.has;
  }

  function cloudUpdateToolbar() {
    var sel = cloudSelectedEntry, canWrite = cloudCanWrite() && !cloudLinkDown;
    var dl = $('cloudDownloadBtn'); if (dl) dl.disabled = !sel || sel.isDir || cloudLinkDown;
    var cp = $('cloudCopyBtn'); if (cp) cp.disabled = !sel || !canWrite;
    var ps = $('cloudPasteBtn'); if (ps) ps.disabled = (!cloudClipboard && !cloudSysClipCache.has) || !canWrite;
    var rn = $('cloudRenameBtn'); if (rn) rn.disabled = !sel || !canWrite;
    var del = $('cloudDeleteBtn'); if (del) del.disabled = !sel || !canWrite;
    var up = $('cloudUpBtn'); if (up) up.disabled = !cloudPath || cloudLinkDown;
    var ub = $('cloudUploadBtn'); if (ub) ub.disabled = !canWrite;
    var mb = $('cloudMkdirBtn'); if (mb) mb.disabled = !canWrite;
    var ci = $('cloudClipboardInfo');
    if (ci) {
      if (cloudClipboard) { ci.style.display = ''; ci.textContent = 'Copied: ' + cloudClipboard.name + ' — open a folder and press Paste.'; }
      else if (cloudSysClipCache.has) { ci.style.display = ''; ci.textContent = 'Windows clipboard: ' + cloudSysClipCache.count + ' item(s) copied — press Paste to upload here.'; }
      else ci.style.display = 'none';
    }
    // Re-check the Windows clipboard in the background: Paste lights up
    // on its own when the user copies a file in Explorer.
    if (canWrite && !cloudClipboard) {
      cloudRefreshSysClip().then(function (has) {
        if (!has || cloudClipboard) return;
        var ps2 = $('cloudPasteBtn'); if (ps2) ps2.disabled = false;
        var ci2 = $('cloudClipboardInfo');
        if (ci2) { ci2.style.display = ''; ci2.textContent = 'Windows clipboard: ' + cloudSysClipCache.count + ' item(s) copied — press Paste to upload here.'; }
      });
    }
  }

  function cloudSelectEntry(entry, rowEl) {
    cloudSelectedEntry = entry;
    var rows = document.querySelectorAll('#cloudFileList .cloud-row');
    rows.forEach(function (r) { r.classList.toggle('selected', r === rowEl); });
    cloudUpdateToolbar();
  }

  function cloudOpenEntry(entry) {
    if (!entry) return;
    if (entry.isDir) cloudBrowse(entry.rel);
    else cloudOpenFile(entry);
  }

  function cloudRenameSelected() {
    var entry = cloudSelectedEntry;
    if (!entry || !cloudCanWrite()) return;
    askCloudInput('Rename', 'New name', entry.name, async function (val) {
      if (!val || val === entry.name) return;
      if (!isSingleCloudName(val)) { toast('Invalid name', 'Use a plain name without / \\ or special characters.', 'error'); return; }
      if (!api || typeof api.cloudClientRename !== 'function') return cloudMissing();
      try {
        var r = await api.cloudClientRename(cloudConn.serverId, entry.rel, cloudJoin(cloudPath, val));
        if (r && r.success) { toast('Renamed', entry.name + ' → ' + val, 'success'); await cloudBrowse(cloudPath); }
        else toast('Rename failed', (r && r.error) || 'Could not rename.', 'error');
      } catch (err) { toast('Rename error', err && err.message ? err.message : 'Could not rename.', 'error'); }
    });
  }

  // New folder in a folder: the current one, or the folder the user
  // right-clicked.
  function cloudNewFolder(targetRel) {
    var target = (typeof targetRel === 'string') ? targetRel : cloudPath;
    if (!cloudConn || !cloudCanWrite()) return;
    askCloudInput('New folder', 'Folder name', '', async function (val) {
      if (!val) return;
      if (!isSingleCloudName(val)) { toast('Invalid name', 'Use a plain name without / \\ or special characters.', 'error'); return; }
      if (!api || typeof api.cloudClientMkdir !== 'function') return cloudMissing();
      try {
        var r = await api.cloudClientMkdir(cloudConn.serverId, cloudJoin(target, val));
        if (r && r.success) { toast('Folder created', val, 'success'); await cloudBrowse(target); }
        else toast('Create failed', (r && r.error) || 'Could not create folder.', 'error');
      } catch (e) { toast('Create error', e && e.message ? e.message : 'Could not create folder.', 'error'); }
    });
  }

  function cloudDeleteSelected() {
    var entry = cloudSelectedEntry;
    if (!entry || !cloudCanWrite()) return;
    askConfirm('Delete "' + entry.name + '" from the server? This cannot be undone.', async function () {
      if (!api || typeof api.cloudClientDelete !== 'function') return cloudMissing();
      try {
        var r = await api.cloudClientDelete(cloudConn.serverId, entry.rel);
        if (r && r.success) { cloudSelectedEntry = null; toast('Deleted', entry.name + ' was deleted.', 'success'); await cloudBrowse(cloudPath); }
        else toast('Delete failed', (r && r.error) || 'Could not delete.', 'error');
      } catch (err) { toast('Delete error', err && err.message ? err.message : 'Could not delete.', 'error'); }
    });
  }

  function cloudCopySelected() {
    var entry = cloudSelectedEntry;
    if (!entry || !cloudCanWrite()) return;
    cloudClipboard = { rel: entry.rel, name: entry.name, isDir: entry.isDir };
    toast('Copied', entry.name + ' copied — open a folder and press Paste.', 'success');
    cloudUpdateToolbar();
  }

  // Paste into a folder: the current one, or the folder the user
  // right-clicked. First the copy made inside this browser (server-side
  // /api/copy), then files copied in Windows Explorer (uploaded here).
  async function cloudPasteClipboard(targetRel) {
    var target = (typeof targetRel === 'string') ? targetRel : cloudPath;
    if (!cloudConn || !cloudCanWrite()) return;
    if (cloudClipboard) {
      if (!api || typeof api.cloudClientCopy !== 'function') return cloudMissing();
      var existing = (cloudLastEntries || []).map(function (e) { return e.name; });
      if (target !== cloudPath) {
        try {
          var lr = await api.cloudClientList(cloudConn.serverId, target);
          if (lr && lr.success) existing = (lr.entries || []).map(function (e) { return e.name; });
        } catch (e) {}
      }
      var destName = cloudCopyName(cloudClipboard.name, cloudClipboard.isDir, existing);
      try {
        var r = await api.cloudClientCopy(cloudConn.serverId, cloudClipboard.rel, cloudJoin(target, destName));
        if (r && r.success) { toast('Pasted', cloudClipboard.name + ' → ' + destName, 'success'); await cloudBrowse(target); }
        else toast('Paste failed', (r && r.error) || 'Could not copy.', 'error');
      } catch (err) { toast('Paste error', err && err.message ? err.message : 'Could not copy.', 'error'); }
      return;
    }
    var files = [];
    try { if (api && typeof api.cloudClipboardFiles === 'function') files = await api.cloudClipboardFiles() || []; } catch (e) {}
    if (files.length) { await cloudUploadClipboardFiles(files, target); return; }
    toast('Nothing to paste', 'Copy a file first — from this folder, or from Windows Explorer.', '');
  }

  async function cloudUploadClipboardFiles(files, target) {
    if (!cloudConn || cloudTransferBusy) return;
    if (!api || typeof api.cloudClientUploadFiles !== 'function') return cloudMissing();
    try {
      cloudTransferBusy = true;
      showCloudTransfer('Uploading ' + files.length + ' item(s)…', 0);
      var r = await api.cloudClientUploadFiles(cloudConn.serverId, files, target || '');
      hideCloudTransfer();
      if (r && r.success) {
        var failed = (r.failed || []).length;
        toast(failed ? 'Uploaded with errors' : 'Uploaded', (r.uploaded || 0) + ' item(s) uploaded' + (failed ? ' — ' + failed + ' failed: ' + (r.failed || []).slice(0, 3).map(function (f) { return f.path; }).join(', ') : '') + '.', failed ? 'error' : 'success');
        await cloudBrowse(target || '');
      } else toast('Upload failed', (r && r.error) || 'Could not upload.', 'error');
    } catch (e) {
      hideCloudTransfer();
      toast('Upload error', e && e.message ? e.message : 'Could not upload.', 'error');
    } finally {
      cloudTransferBusy = false;
    }
  }

  // Open a file the way Windows would: music plays, pictures open, a
  // game runs — the app downloads a copy to the temp folder and hands
  // it to the OS. Folders are entered, as before.
  async function cloudOpenFile(entry) {
    if (!entry) return;
    if (entry.isDir) { cloudBrowse(entry.rel); return; }
    if (!cloudConn || cloudTransferBusy) return;
    if (!api || typeof api.cloudClientOpen !== 'function') return cloudMissing();
    try {
      cloudTransferBusy = true;
      showCloudTransfer('Opening ' + entry.name + '…', 0);
      var r = await api.cloudClientOpen(cloudConn.serverId, entry.rel);
      hideCloudTransfer();
      if (!r || !r.success) toast('Could not open', (r && r.error) || 'The file could not be opened.', 'error');
    } catch (e) {
      hideCloudTransfer();
      toast('Open error', e && e.message ? e.message : 'Could not open the file.', 'error');
    } finally {
      cloudTransferBusy = false;
    }
  }

  /* ---------- Right-click menu (Windows Explorer style) ---------- */
  function cloudHideContextMenu() {
    var m = $('cloudContextMenu'); if (m) { m.style.display = 'none'; m.innerHTML = ''; }
  }
  function cloudContextItem(menu, label, disabled, onClick) {
    var b = document.createElement('button');
    b.className = 'cloud-context-item'; b.type = 'button'; b.textContent = label;
    b.disabled = !!disabled;
    b.addEventListener('click', function () { cloudHideContextMenu(); if (onClick) onClick(); });
    menu.appendChild(b);
    return b;
  }
  function cloudContextSep(menu) {
    var s = document.createElement('div'); s.className = 'cloud-context-sep'; menu.appendChild(s);
  }
  async function cloudShowContextMenu(x, y, entry) {
    var menu = $('cloudContextMenu');
    if (!menu || !cloudConn) return;
    var canWrite = cloudCanWrite() && !cloudLinkDown;
    var hasInternal = !!cloudClipboard;
    var hasSys = false;
    if (canWrite && !hasInternal) hasSys = await cloudRefreshSysClip();
    menu.innerHTML = '';
    var targetDir = entry && entry.isDir ? entry.rel : cloudPath;
    if (entry) {
      cloudContextItem(menu, 'Open', false, function () { cloudOpenEntry(entry); });
      if (!entry.isDir) cloudContextItem(menu, 'Download', cloudLinkDown, function () { cloudDownload(entry.rel); });
      cloudContextSep(menu);
      cloudContextItem(menu, 'Copy', !canWrite, function () { cloudCopySelected(); });
      cloudContextItem(menu, entry.isDir ? 'Paste into "' + entry.name + '"' : 'Paste here', !canWrite || (!hasInternal && !hasSys), function () { cloudPasteClipboard(targetDir); });
      cloudContextSep(menu);
      cloudContextItem(menu, 'Rename', !canWrite, function () { cloudRenameSelected(); });
      cloudContextItem(menu, 'Delete', !canWrite, function () { cloudDeleteSelected(); });
      cloudContextSep(menu);
    } else {
      cloudContextItem(menu, 'Paste here', !canWrite || (!hasInternal && !hasSys), function () { cloudPasteClipboard(targetDir); });
      cloudContextSep(menu);
    }
    cloudContextItem(menu, entry && entry.isDir ? 'New folder in "' + entry.name + '"' : 'New folder', !canWrite, function () { cloudNewFolder(targetDir); });
    cloudContextItem(menu, 'Refresh', cloudLinkDown, function () { cloudBrowse(cloudPath); });
    menu.style.display = '';
    menu.style.left = '0px'; menu.style.top = '0px';
    var w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = Math.max(4, Math.min(x, window.innerWidth - w - 4)) + 'px';
    menu.style.top = Math.max(4, Math.min(y, window.innerHeight - h - 4)) + 'px';
  }

  function renderCloudBrowser(entries) {
    cloudHideContextMenu();
    cloudLastEntries = entries || [];
    cloudLastSig = cloudEntriesSig(entries || []);
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
    if (!entries.length) { if (empty) empty.style.display = ''; }
    else if (empty) empty.style.display = 'none';
    // Keep the selection when the entry is still here (e.g. after a
    // refresh or a paste that did not touch it).
    var prevSel = cloudSelectedEntry ? cloudSelectedEntry.name : null;
    cloudSelectedEntry = null;
    entries.forEach(function (e) {
      var row = document.createElement('div');
      row.className = 'cloud-row';
      row.setAttribute('tabindex', '0');
      var rel = cloudJoin(cloudPath, e.name);
      var entry = { name: e.name, isDir: !!e.isDir, rel: rel };
      row.cloudEntry = entry;
      var nameEl = document.createElement('span'); nameEl.className = 'cx-name';
      nameEl.textContent = (e.isDir ? '📁 ' : '📄 ') + e.name;
      var sizeEl = document.createElement('span'); sizeEl.className = 'cx-size';
      sizeEl.textContent = e.isDir ? '—' : formatBytes(e.size);
      var mtimeEl = document.createElement('span'); mtimeEl.className = 'cx-mtime';
      mtimeEl.textContent = e.mtime ? formatDate(e.mtime) : '—';
      var typeEl = document.createElement('span'); typeEl.className = 'cx-type';
      typeEl.textContent = e.isDir ? 'Folder' : cloudFileType(e.name);
      row.appendChild(nameEl); row.appendChild(sizeEl); row.appendChild(mtimeEl); row.appendChild(typeEl);
      row.addEventListener('click', function () { cloudSelectEntry(entry, row); });
      row.addEventListener('dblclick', function () { cloudSelectEntry(entry, row); cloudOpenEntry(entry); });
      row.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') { cloudOpenEntry(entry); }
        else if (ev.key === 'Delete') { cloudSelectEntry(entry, row); cloudDeleteSelected(); }
      });
      list.appendChild(row);
      if (prevSel && e.name === prevSel) { cloudSelectedEntry = entry; row.classList.add('selected'); }
    });
    cloudUpdateToolbar();
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
  var DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  function scheduleLabel(s) {
    if (!s || !s.enabled) return null;
    var time = s.time || '02:00';
    if ((s.frequency || '').toLowerCase() === 'custom') {
      var names = (Array.isArray(s.days) ? s.days : []).map(function (d) { return DAY_NAMES[d] || ''; }).filter(Boolean);
      return 'Custom (' + (names.join(', ') || 'no days') + ') at ' + time;
    }
    return (s.frequency || 'Daily') + ' at ' + time;
  }
  function nextRunText(job) {
    var s = job.schedule || (job.raw && job.raw.schedule) || null;
    if (!s || !s.enabled) return 'No schedule — manual only';
    var freq = s.frequency || 'Daily';
    var time = s.time || '02:00';
    var m = /^(\d{1,2}):(\d{2})$/.exec(time);
    if (!m) return scheduleLabel(s);
    var next = new Date();
    next.setHours(parseInt(m[1], 10), parseInt(m[2], 10), 0, 0);
    if (freq.toLowerCase() === 'custom') {
      var days = Array.isArray(s.days) ? s.days : [];
      var found = null;
      for (var i = 0; i < 8; i++) {
        var c = new Date(); c.setDate(c.getDate() + i);
        if (days.indexOf(c.getDay()) < 0) continue;
        c.setHours(parseInt(m[1], 10), parseInt(m[2], 10), 0, 0);
        if (c > new Date()) { found = c; break; }
        if (i === 0) { found = c; break; } // due today
      }
      if (found) next = found;
      return scheduleLabel(s) + ' — next: ' + formatDate(next.toISOString());
    }
    if (freq.toLowerCase() === 'weekly') {
      if (next <= new Date()) next.setDate(next.getDate() + 7);
    } else if (freq.toLowerCase() === 'monthly') {
      if (next <= new Date()) next.setMonth(next.getMonth() + 1);
    } else if (next <= new Date()) {
      next.setDate(next.getDate() + 1);
    }
    return scheduleLabel(s) + ' — next: ' + formatDate(next.toISOString());
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
    $('drawerSchedule').textContent = scheduleLabel(sched) || 'Manual only — no schedule set';
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
    ['backupTopRefreshBtn'].forEach(function (id) {
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

  /* ---------- TechVision Tailscale VPN (Tailscale client manager) ----------
     One panel per machine: status, connect/disconnect, peers, subnet
     router. There is no VPN server to build — Tailscale is a mesh and
     its coordination server is Tailscale's own. The Cloud module plugs
     in here: "Open in Cloud" jumps to the Cloud client with a peer's
     Tailscale IP prefilled (and the connection mode set to Tailscale). */
  var vpnStatusCache = null;
  var vpnAuthUrlCache = null;
  var vpnBusy = false;

  function vpnMissing() { toast('VPN', 'The VPN bridge is not available in this build.', 'error'); }

  async function loadVpn() {
    if (!api || typeof api.vpnGetStatus !== 'function') return vpnMissing();
    var st;
    try { st = await api.vpnGetStatus(); } catch (e) { st = { installed: true, connected: false, error: e && e.message ? e.message : 'Could not read Tailscale status.' }; }
    vpnStatusCache = st || {};
    // Status dot + Connect button styling live here, in one place:
    // green pulsing dot while connected, grey otherwise; the button is
    // the primary (gradient) action whenever there is something to do
    // (connect / sign in / install) and plain for Disconnect.
    var dot = $('vpnStatusDot'); if (dot) dot.className = 'vpn-dot' + ((st && st.connected) ? ' on' : '');
    var cbtn = $('vpnConnectBtn'); if (cbtn) cbtn.classList.toggle('btn-primary', !(st && st.connected));
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
        vpnAuthUrlCache = st.authUrl || null;
        var au = $('vpnAuthUrl');
        if (au) au.textContent = st.authUrl ? ('Sign-in link: ' + st.authUrl) : '';
        var ob = $('vpnOpenAuthBtn');
        if (ob) ob.style.display = st.authUrl ? '' : 'none';
        // The hint must match what is actually on screen: when the
        // daemon has not handed us a login link yet there is no button
        // below to point at — Sign in is the way to open the page.
        var lh = $('vpnLoginHint');
        if (lh) lh.textContent = st.authUrl
          ? 'Complete the sign-in in your browser, then press Refresh. If no browser window opened, use the button below.'
          : 'Press Sign in — the sign-in page will open in your browser. Complete it there, then press Refresh.';
      }
      if (dc) dc.style.display = 'none';
      renderVpnPeers([]);
      return;
    }
    if (!st.connected) {
      if (txt) txt.textContent = st.backendState === 'Stopped' ? 'Disconnected' : 'Not connected';
      // The tray app is not running: the backend sits in NoState and
      // Connect looks dead until the app is opened. Connect opens it.
      if (sub) sub.textContent = st.guiRunning === false
        ? 'The Tailscale app is not running — press Connect and the app will open it for you.'
        : (st.backendState === 'Stopped' ? 'You are signed in, but the VPN is off.' : 'Tailscale is not connected.');
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
    refreshVpnRoutesState();
    var ss = $('vpnSubnetSub');
    if (ss) ss.textContent = st.lanSubnet
      ? ('Let devices on Tailscale reach your whole home network (' + st.lanSubnet + ' — printer, camera, router).')
      : 'Let devices on Tailscale reach your whole home network (printer, camera, router).';
    var ket = $('vpnKeyExpiryToggle'); if (ket) ket.checked = vpnKeyExpiryWanted();
    var tok = $('vpnApiToken'); if (tok) tok.value = (settings.vpn && settings.vpn.apiToken) || '';
    var ocid = $('vpnOauthClientId'); if (ocid) ocid.value = (settings.vpn && settings.vpn.oauthClientId) || '';
    var osec = $('vpnOauthClientSecret'); if (osec) osec.value = (settings.vpn && settings.vpn.oauthClientSecret) || '';
    renderVpnPeers(st.peers || []);
    // First sign-in (or first view while connected): turn off the 180-day
    // key expiry automatically, so the device never asks to sign in again.
    maybeDisableVpnKeyExpiry();
    refreshVpnKeyExpiryState();
    refreshVpnApiCredsStatus(false);
  }

  // `tailscale up` can return before the daemon reports itself Running, so
  // a single status read right after connect can catch it mid-startup and
  // freeze the view on "Not connected" after a "VPN connected." toast.
  // Re-check a few times until the view agrees with the result.
  async function pollVpnUntilConnected() {
    for (var i = 0; i < 4; i++) {
      if (vpnStatusCache && vpnStatusCache.connected) return;
      await new Promise(function (res) { setTimeout(res, 2000); });
      await loadVpn();
    }
  }

  /* ---------- VPN key expiry (stay connected forever) ---------- */
  var vpnKeyExpiryAttempted = false; // one auto attempt per app session
  function vpnKeyExpiryWanted() {
    return !(settings.vpn && settings.vpn.autoDisableKeyExpiry === false);
  }
  // The API credential for key expiry: OAuth client first (never
  // expires), API token second. null = nothing saved yet.
  function vpnAuth() {
    var v = (settings.vpn && typeof settings.vpn === 'object') ? settings.vpn : {};
    if (v.oauthClientId && v.oauthClientSecret) return { clientId: v.oauthClientId, clientSecret: v.oauthClientSecret };
    if (v.apiToken && String(v.apiToken).trim()) return { apiToken: v.apiToken };
    return null;
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
      var r = await api.vpnDisableKeyExpiry(vpnAuth());
      if (r && r.success) {
        await saveVpnSettings({ keyExpiryDisabled: true });
        if (!quiet) toast('VPN', 'Key expiry is off — this device will stay connected, no more sign-ins.', 'success');
        refreshVpnKeyExpiryState();
        return true;
      }
      // Show the real reason, not the old generic sentence: the failure
      // used to be invisible (the CLI flag does not exist), which is
      // exactly why the toggle looked on while nothing had happened.
      if (!quiet) toast('VPN', 'Could not turn off key expiry automatically: ' + ((r && r.error) || 'unknown error') + ' — you can also turn it off in the Tailscale admin console (Machines → this device → Disable key expiry).', 'error');
      return false;
    } catch (e) {
      if (!quiet) toast('VPN error', e && e.message ? e.message : 'Could not turn off key expiry.', 'error');
      return false;
    }
  }
  // The real key-expiry state from the Tailscale API — the toggle is a
  // real switch, and this line is its confirmation: it shows what the
  // API says, and the toggle is set to match it.
  async function refreshVpnKeyExpiryState() {
    var el = $('vpnKeyExpiryState');
    if (!el) return;
    var auth = vpnAuth();
    if (!auth) { el.textContent = 'Key expiry state: unknown — open “API credentials” above and save an OAuth client or a token.'; return; }
    if (!api || typeof api.vpnKeyExpiryState !== 'function') return;
    // Never flash "checking…" over a state that is already shown: the
    // view re-reads every 15 seconds, and the line used to blink to
    // "checking…" and back on every poll. Only show it on first load.
    if (!el.textContent) el.textContent = 'Key expiry state: checking…';
    try {
      var r = await api.vpnKeyExpiryState(auth);
      if (r && r.success) {
        var ket = $('vpnKeyExpiryToggle');
        if (ket) ket.checked = !!r.disabled;
        el.textContent = r.disabled
          ? 'Key expiry: OFF — this device stays connected, no more sign-ins.'
          : 'Key expiry: ON — the device will ask to sign in again when the key expires' + (r.expires ? ' (' + r.expires + ')' : '') + '.';
        if (r.disabled) await saveVpnSettings({ keyExpiryDisabled: true, autoDisableKeyExpiry: true });
        else await saveVpnSettings({ keyExpiryDisabled: false });
      } else {
        el.textContent = 'Key expiry state: unknown — ' + ((r && r.error) || 'could not read it.');
      }
    } catch (e) { el.textContent = 'Key expiry state: unknown — ' + (e && e.message ? e.message : 'could not read it.'); }
  }
  // "Saved" says nothing about whether the credential actually works,
  // so the credentials box carries a word of its own — Connected or
  // Disconnected — visible in the summary even while the box is
  // collapsed, with the full reason inside. Verified on load (at most
  // once a minute) and right after every save.
  var vpnApiCredsLastVerify = 0;
  var vpnApiCredsVerifying = false;
  async function refreshVpnApiCredsStatus(force) {
    var word = $('vpnApiCredsStatusWord');
    var line = $('vpnApiCredsStatus');
    if (!word && !line) return;
    var setWord = function (text, cls) { if (word) { word.textContent = text; word.className = 't-sub ' + (cls || ''); } };
    var setLine = function (text, cls) { if (line) { line.textContent = text; line.className = 't-sub ' + (cls || ''); } };
    var auth = vpnAuth();
    if (!auth) { setWord('· Not saved', ''); setLine('No credentials saved yet — save an OAuth client or a token below, and this line will say whether it works.'); return; }
    if (!force && Date.now() - vpnApiCredsLastVerify < 60000) return;
    if (vpnApiCredsVerifying) return;
    if (!api || typeof api.vpnVerifyApi !== 'function') return;
    vpnApiCredsVerifying = true;
    setWord('· Verifying…', '');
    setLine('Verifying the credentials with the Tailscale API…');
    try {
      var r = await api.vpnVerifyApi(auth);
      vpnApiCredsLastVerify = Date.now();
      if (r && r.valid) {
        var via = r.via === 'oauth' ? 'OAuth client' : (r.via === 'token' ? 'API token' : 'credentials');
        setWord('· Connected', 'vpn-creds-ok');
        setLine('Connected — the ' + via + ' works with the Tailscale API.');
      } else {
        setWord('· Disconnected', 'vpn-creds-bad');
        setLine('Disconnected — ' + ((r && r.error) || 'the credentials did not work.'));
      }
    } catch (e) {
      setWord('· Disconnected', 'vpn-creds-bad');
      setLine('Disconnected — ' + (e && e.message ? e.message : 'could not check the credentials.'));
    } finally { vpnApiCredsVerifying = false; }
  }
  // Turn key expiry back ON through the API (the toggle flipped off).
  async function enableVpnKeyExpiry() {
    if (!api || typeof api.vpnEnableKeyExpiry !== 'function') return false;
    try {
      var r = await api.vpnEnableKeyExpiry(vpnAuth());
      if (r && r.success) {
        await saveVpnSettings({ keyExpiryDisabled: false });
        toast('VPN', 'Key expiry is on again — the device will ask to sign in again when the key expires.', 'success');
        refreshVpnKeyExpiryState();
        return true;
      }
      toast('VPN', 'Could not turn key expiry back on: ' + ((r && r.error) || 'unknown error'), 'error');
      return false;
    } catch (e) {
      toast('VPN error', e && e.message ? e.message : 'Could not turn key expiry back on.', 'error');
      return false;
    }
  }
  // The real route state from the API: advertising + approved, or
  // advertising and still waiting. The toggle is a real switch like
  // the key-expiry one: when the route is advertising but not
  // approved yet and a credential is saved, the app approves it
  // itself — so a toggle that was turned on before the credential
  // existed still ends up approved without touching the console.
  // At most one approval attempt a minute, so a refused API (e.g. a
  // missing scope) does not hammer the API on every 15-second poll.
  // The console button only shows when the approval is missing and
  // the API cannot do it, and the note then carries the real reason.
  var vpnRoutesLastApproveTry = 0;
  var vpnRoutesApprovedHint = null; // {subnet, at} — a successful approve
  // call is trusted for a minute, so the note says "approved" at once
  // instead of waiting for the control plane to show it on a re-read.
  async function refreshVpnRoutesState() {
    var rn = $('vpnRoutesNote');
    var ab = $('vpnApproveBtn');
    if (!rn && !ab) return;
    var st = vpnStatusCache || {};
    var advertising = (st.advertiseRoutes || []).indexOf(st.lanSubnet) >= 0;
    if (!advertising || !st.connected) { if (rn) rn.style.display = 'none'; if (ab) ab.style.display = 'none'; return; }
    var waiting = 'Advertising ' + st.lanSubnet + ' — approve this route once in the Tailscale admin console.';
    var approvedNote = 'Advertising ' + st.lanSubnet + ' — approved.';
    var showWaiting = function (text) {
      if (rn) { rn.style.display = ''; rn.textContent = text || waiting; }
      if (ab) ab.style.display = '';
    };
    var showApproved = function () {
      if (rn) { rn.style.display = ''; rn.textContent = approvedNote; }
      if (ab) ab.style.display = 'none';
    };
    if (vpnRoutesApprovedHint && vpnRoutesApprovedHint.subnet === st.lanSubnet && Date.now() - vpnRoutesApprovedHint.at < 60000) { showApproved(); return; }
    var auth = vpnAuth();
    if (!auth || !api || typeof api.vpnGetRoutes !== 'function') { showWaiting(); return; }
    try {
      var r = await api.vpnGetRoutes(auth);
      if (!r || !r.success) { showWaiting('Advertising ' + st.lanSubnet + ' — could not read the route state: ' + ((r && r.error) || 'unknown error') + ' — approve it in the Tailscale admin console.'); return; }
      var approved = (r.routes || []).some(function (x) { return x.route === st.lanSubnet && x.enabled; });
      if (approved) { showApproved(); return; }
      if (typeof api.vpnApproveRoutes === 'function' && Date.now() - vpnRoutesLastApproveTry > 60000) {
        vpnRoutesLastApproveTry = Date.now();
        var ap = await api.vpnApproveRoutes(auth, [st.lanSubnet]);
        if (ap && ap.success) { vpnRoutesApprovedHint = { subnet: st.lanSubnet, at: Date.now() }; showApproved(); return; }
        showWaiting('Advertising ' + st.lanSubnet + ' — automatic approval failed: ' + ((ap && ap.error) || 'unknown error') + ' — approve it in the Tailscale admin console.');
        return;
      }
      showWaiting('Advertising ' + st.lanSubnet + ' — waiting for approval…');
    } catch (e) {
      showWaiting('Advertising ' + st.lanSubnet + ' — could not reach the Tailscale API: ' + (e && e.message ? e.message : 'unknown error') + ' — approve it in the Tailscale admin console.');
    }
  }
  async function maybeDisableVpnKeyExpiry() {
    if (vpnKeyExpiryAttempted) return;
    if (!vpnKeyExpiryWanted()) return;
    if (settings.vpn && settings.vpn.keyExpiryDisabled === true) return;
    vpnKeyExpiryAttempted = true;
    await disableVpnKeyExpiry(false);
  }

  // Same idea as populateCloudPeers: the VPN view is re-read on a timer
  // while it is open, so only rebuild the list when something actually
  // changed (a device joining/leaving, or a state change).
  var lastVpnPeersSig = null;
  function renderVpnPeers(peers) {
    var list = $('vpnPeersList'); if (!list) return;
    var cnt = $('vpnPeersCount');
    if (cnt) {
      if ((peers || []).length) { cnt.style.display = ''; cnt.textContent = peers.length + (peers.length === 1 ? ' device' : ' devices'); }
      else { cnt.style.display = 'none'; cnt.textContent = ''; }
    }
    var sig = JSON.stringify({ peers: (peers || []).map(function (p) { return [p.ip, p.name, p.online, p.os]; }), connected: !!(vpnStatusCache && vpnStatusCache.connected), installed: !!(vpnStatusCache && vpnStatusCache.installed), needsLogin: !!(vpnStatusCache && vpnStatusCache.needsLogin) });
    if (sig === lastVpnPeersSig) return;
    lastVpnPeersSig = sig;
    list.innerHTML = '';
    if (!peers.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      // "Sign in..." is wrong once he is signed in — with no other
      // devices on the tailnet he is simply the only one there.
      var msg = 'Sign in to Tailscale and your devices will show up here.';
      if (vpnStatusCache && vpnStatusCache.connected) msg = 'No other devices on your network yet — install Tailscale on another device and it will show up here.';
      else if (vpnStatusCache && vpnStatusCache.installed && !vpnStatusCache.needsLogin) msg = 'Connect the VPN and your devices will show up here.';
      empty.innerHTML = '<div class="big">🛡️</div><h3>No devices yet</h3><p>' + msg + '</p>';
      list.appendChild(empty);
      return;
    }
    peers.forEach(function (p) {
      var row = document.createElement('div');
      row.className = 'vpn-peer';
      var d = document.createElement('span'); d.className = 'vpn-peer-dot' + (p.online ? ' on' : '');
      var body = document.createElement('div'); body.className = 'vpn-peer-body';
      var h = document.createElement('h3'); h.className = 'vpn-peer-name'; h.textContent = p.name;
      var meta = document.createElement('div'); meta.className = 'vpn-peer-meta';
      meta.textContent = (p.ip || '—') + (p.os ? ' — ' + p.os : '') + ' — ' + (p.online ? 'online' : 'offline');
      body.appendChild(h); body.appendChild(meta);
      row.appendChild(d); row.appendChild(body);
      if (p.ip) {
        var open = document.createElement('button'); open.className = 'btn btn-primary btn-sm'; open.type = 'button'; open.textContent = 'Open in Cloud';
        open.addEventListener('click', function () { openCloudWithPeer(p); });
        row.appendChild(open);
      }
      list.appendChild(row);
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

  /* ---------- TechVision WireGuard VPN (self-hosted WireGuard) ----------
     A fourth module: this machine as a WireGuard server (hub) and as a
     client. No coordination server, no account — the server IS this
     machine, and the only router step is one UDP 51820 forward. The
     UI mirrors the VPN view (status hero, facts tiles, peer rows). */
  var wgStatusCache = null;
  var wgBusy = false;
  var lastWgPeersSig = null;
  // Cloud join (third key-exchange option): a request this machine
  // sent is { requestId, serverId, deviceName } — the private key
  // stays in main, so a restart loses the pending request and the
  // user simply sends a fresh one. The poll timer runs every 5s
  // while a request is outstanding and stops on any terminal state.
  var wgJoinPending = null;
  var wgJoinPollTimer = null;
  var lastWgJoinReqSig = null;
  var lastWgJoinServersSig = null;

  function wgMissing() { toast('WireGuard', 'The WireGuard bridge is not available in this build.', 'error'); }

  function wgHandshakeText(ms) {
    if (!ms) return 'never connected';
    var s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 60) return s + 's ago';
    var m = Math.round(s / 60);
    if (m < 60) return m + ' min ago';
    var h = Math.round(m / 60);
    if (h < 24) return h + 'h ago';
    return Math.round(h / 24) + 'd ago';
  }

  async function loadWireGuard() {
    if (!api || typeof api.wgGetStatus !== 'function') return wgMissing();
    var st;
    try { st = await api.wgGetStatus(); } catch (e) { st = { installed: false, serverRunning: false, clientRunning: false, error: e && e.message ? e.message : 'Could not read WireGuard status.' }; }
    wgStatusCache = st || {};
    renderWgNat(st || {});
    var dot = $('wgStatusDot'); if (dot) dot.className = 'vpn-dot' + ((st.serverRunning || st.clientRunning) ? ' on' : '');
    var txt = $('wgStatusText'), sub = $('wgStatusSub');
    var ni = $('wgNotInstalled');
    var sc = $('wgServerCard'), cc = $('wgClientCard');
    var tl = $('wgTransportLine');
    if (!st.installed) {
      if (txt) txt.textContent = 'Not installed';
      if (sub) sub.textContent = 'AmneziaWG is not installed on this computer.';
      if (tl) tl.style.display = 'none';
      if (ni) ni.style.display = '';
      if (sc) sc.style.display = 'none';
      if (cc) cc.style.display = 'none';
      // The early return below used to skip the button reset, so a
      // failed Start left the button stuck on "Working…" — reset
      // both buttons here too.
      var sb0 = $('wgServerBtn'); if (sb0) { sb0.textContent = 'Start server'; sb0.classList.add('btn-primary'); }
      var cb0 = $('wgClientBtn'); if (cb0) { cb0.textContent = 'Connect'; cb0.classList.add('btn-primary'); }
      renderWgPeers([]);
      return;
    }
    if (ni) ni.style.display = 'none';
    if (sc) sc.style.display = '';
    if (cc) cc.style.display = '';
    if (tl) {
      if (st.transport === 'amneziawg') { tl.style.display = ''; tl.textContent = st.obfuscated ? 'Transport: AmneziaWG — traffic is obfuscated, so it doesn\u2019t look like WireGuard on the network.' : 'Transport: AmneziaWG.'; }
      else { tl.style.display = ''; tl.textContent = 'Transport: stock WireGuard (no obfuscation).'; }
    }
    if (st.serverRunning && st.clientRunning) {
      if (txt) txt.textContent = 'Server running · Client connected';
      if (sub) sub.textContent = 'This machine is a hub and a client at the same time.';
    } else if (st.serverRunning) {
      if (txt) txt.textContent = 'Server running';
      if (sub) sub.textContent = 'This machine is the AmneziaWG hub — devices connect to it.';
    } else if (st.clientRunning) {
      if (txt) txt.textContent = 'Connected';
      if (sub) sub.textContent = 'This machine is connected to an AmneziaWG server.';
    } else if (st.error) {
      if (txt) txt.textContent = 'Error';
      if (sub) sub.textContent = st.error;
    } else {
      if (txt) txt.textContent = 'Off';
      if (sub) sub.textContent = 'The server is stopped and the client is disconnected.';
    }
    var sb = $('wgServerBtn');
    if (sb) { sb.textContent = st.serverRunning ? 'Stop server' : 'Start server'; sb.classList.toggle('btn-primary', !st.serverRunning); }
    var sk = $('wgServerKey'); if (sk) sk.textContent = (st.server && st.server.publicKey) || '—';
    // Editable server settings: prefill from status, never clobber
    // typing (same guard as the endpoint input).
    var si = $('wgServerIp');
    if (si && document.activeElement !== si) si.value = (st.server && st.server.address) || '10.0.0.1';
    var sp = $('wgServerPort');
    if (sp && document.activeElement !== sp) sp.value = String((st.server && st.server.listenPort) || 51820);
    var ph = $('wgPortHint');
    if (ph) ph.textContent = 'On your router, forward UDP ' + ((st.server && st.server.listenPort) || 51820) + ' to this machine — that is the only router step. Without it, nobody outside your home network can reach this server.';
    var ep = $('wgEndpoint');
    if (ep && document.activeElement !== ep) ep.value = (st.server && st.server.endpoint) || '';
    var cs = $('wgClientStatus');
    if (cs) {
      if (st.clientRunning) {
        var c = st.client || {};
        cs.textContent = 'Connected to ' + (c.endpoint || 'the server') + (c.tunnelIp ? (' as ' + c.tunnelIp) : '') + ' — last handshake ' + wgHandshakeText(c.latestHandshake) + ', ' + formatBytes(c.transferRx || 0) + ' down / ' + formatBytes(c.transferTx || 0) + ' up.';
      } else if (st.client && st.client.serverPublicKey) cs.textContent = 'Not connected. A client config is saved — press Connect to use it again.';
      else cs.textContent = 'Not connected.';
    }
    // This machine's own public key — the server operator pastes it
    // into the add-peer form. It lives in the saved client config,
    // so it shows even while disconnected.
    var ck = $('wgClientKey');
    if (ck) ck.textContent = (st.client && st.client.publicKey) || '—';
    var ckh = $('wgClientKeyHint');
    if (ckh) ckh.textContent = (st.client && st.client.publicKey) ? 'This key is this device\u2019s identity — the server operator pastes it into the add-peer form, with this machine\u2019s real IP or DDNS and port.' : (st.installed ? 'Your public key will show here.' : 'Install AmneziaWG and your public key will show here.');
    var cb = $('wgClientBtn');
    if (cb) { cb.textContent = st.clientRunning ? 'Disconnect' : 'Connect'; cb.classList.toggle('btn-primary', !st.clientRunning); }
    // Prefill the manual client fields from the saved client config —
    // only into empty fields, so typing is never clobbered.
    if (st.client) {
      var ck = $('wgClientServerKey'); if (ck && !ck.value && st.client.serverPublicKey) ck.value = st.client.serverPublicKey;
      var ce = $('wgClientEndpoint'); if (ce && !ce.value && st.client.endpoint) ce.value = st.client.endpoint;
      var ci = $('wgClientTunnelIp'); if (ci && !ci.value && st.client.tunnelIp) ci.value = st.client.tunnelIp;
    }
    renderWgPeers(st.peers || []);
    loadWgJoinRequests();
    try {
      var ccfg = await api.cloudGetConfig();
      renderWgJoinServers((ccfg && ccfg.clients) || []);
    } catch (e) { /* the join server list stays as it is */ }
  }

  /* Gateway NAT service status (site-to-site): the card lives in
     the WireGuard view next to the static-route guidance. The
     service itself is Windows-only — on Linux the status simply
     says stopped, and Start reports the real reason. The status
     line also carries the saved configuration summary, and Start
     stays disabled until a configuration has been saved. */
  function renderWgNat(st) {
    var ns = $('wgNatStatus'); if (!ns) return;
    var n = (st && st.nat) || {};
    var saved = (st && st.natConfig) || null;
    var summary = '';
    if (saved) {
      summary = ' Saved: ' + (saved.mode === 'same-subnet' ? 'same-subnet' : 'different-subnet') + ', ' +
        (saved.localSubnet || '') + ' ↔ ' + (saved.remoteSubnet || '') +
        (saved.mode === 'same-subnet' ? (', ' + (saved.mappings ? saved.mappings.length : 0) + ' mapped device' + ((saved.mappings || []).length === 1 ? '' : 's')) : ', no mappings') + '.';
    } else {
      summary = ' No site-to-site configuration saved yet — add devices below and press Save.';
    }
    if (n.running) {
      var s = n.stats || {};
      ns.textContent = 'NAT service: running — ' + (n.mode || '') + ' mode' +
        (n.mappings ? (', ' + n.mappings + ' mapped device' + (n.mappings === 1 ? '' : 's')) : '') +
        (s.translated ? (', ' + s.translated + ' packet' + (s.translated === 1 ? '' : 's') + ' translated') : '') + '.' + summary;
    } else {
      ns.textContent = 'NAT service: stopped.' + (n.lastError ? (' ' + n.lastError) : '') + summary;
    }
    /* Start is available when the service is not running and the
       mode has what it needs: different-subnet needs only a peer
       picked (there is no configuration to save there); same-subnet
       needs a saved config OR a peer — with no rows of its own this
       gateway starts as the remote side and the other gateway runs
       the rows. */
    var modeNow = currentWgNatMode();
    var peersNow = (st && st.peers) || [];
    var hasPeer = peersNow.length > 0 || !!(st && st.tunnelServer);
    var canStart = modeNow === 'different-subnet' ? hasPeer : (!!saved || hasPeer);
    var startBtn = $('wgNatStartBtn'); if (startBtn) startBtn.disabled = !!n.running || !canStart;
    var stopBtn = $('wgNatStopBtn'); if (stopBtn) stopBtn.disabled = !n.running;
    renderWgNatForm(st);
  }

  /* The NAT mapping editor: prefill from the saved config, show or
     hide the same-subnet blocks by mode, and never clobber the
     user's edits — the 15s poller calls loadWireGuard, so once the
     form is dirty it is left alone, and the mappings rows rebuild
     only when the saved config actually changes. */
  var wgNatFormDirty = false;
  var lastWgNatSavedSig = null;
  var lastWgNatMappingsSig = null;
  var lastWgNatPeersSig = null;
  function currentWgNatMode() {
    var diff = $('wgNatModeDiff');
    return (diff && diff.checked) ? 'different-subnet' : 'same-subnet';
  }
  function setWgNatMode(m) {
    var same = $('wgNatModeSame'), diff = $('wgNatModeDiff');
    if (same) same.checked = m !== 'different-subnet';
    if (diff) diff.checked = m === 'different-subnet';
    /* Same subnet: the mapping rows show. Different subnets: the
       whole configuration form hides — only the mode radios, the
       peer picker and Start/Stop remain — and the router note
       shows instead. */
    var fb = $('wgNatFormBody'); if (fb) fb.style.display = m === 'different-subnet' ? 'none' : '';
    var rn = $('wgNatRouterNote'); if (rn) rn.style.display = m === 'different-subnet' ? '' : 'none';
  }
  function wgNatAddMappingRow(m) {
    var box = $('wgNatMappingsRows'); if (!box) return;
    var row = document.createElement('div');
    row.className = 'wg-nat-map-row';
    row.style.cssText = 'display:flex; gap:8px; flex-wrap:wrap; margin-top:6px; align-items:center;';
    var mk = function (cls, ph) {
      var el = document.createElement('input');
      el.type = 'text'; el.className = cls; el.placeholder = ph; el.autocomplete = 'off';
      el.style.cssText = 'flex:1; min-width:130px;';
      el.addEventListener('input', function () { wgNatFormDirty = true; });
      return el;
    };
    var name = mk('wg-nat-map-name', 'Name, e.g. file server'); name.value = (m && m.name) || '';
    var real = mk('wg-nat-map-real', 'Real IP, e.g. 192.168.1.49'); real.value = (m && m.real) || '';
    var virt = mk('wg-nat-map-virt', 'Alias IP, e.g. 192.168.2.3'); virt.value = (m && m.virt) || '';
    var rm = document.createElement('button');
    rm.className = 'btn btn-ghost btn-sm'; rm.type = 'button'; rm.textContent = 'Remove';
    rm.addEventListener('click', function () {
      var rows = box.querySelectorAll('.wg-nat-map-row');
      if (rows.length <= 1) { real.value = ''; virt.value = ''; name.value = ''; wgNatFormDirty = true; return; }
      row.remove(); wgNatFormDirty = true;
    });
    row.appendChild(name); row.appendChild(real); row.appendChild(virt); row.appendChild(rm);
    box.appendChild(row);
  }
  function wgNatRebuildMappings(list) {
    var box = $('wgNatMappingsRows'); if (!box) return;
    box.innerHTML = '';
    var rows = (list && list.length) ? list : [null];
    rows.forEach(function (m) { wgNatAddMappingRow(m); });
  }
  function wgNatReadMappings() {
    var out = [];
    document.querySelectorAll('#wgNatMappingsRows .wg-nat-map-row').forEach(function (row) {
      var real = (row.querySelector('.wg-nat-map-real') || {}).value || '';
      var virt = (row.querySelector('.wg-nat-map-virt') || {}).value || '';
      var name = (row.querySelector('.wg-nat-map-name') || {}).value || '';
      if (String(real).trim() === '' && String(virt).trim() === '' && String(name).trim() === '') return;
      out.push({ real: String(real).trim(), virt: String(virt).trim(), name: String(name).trim() });
    });
    return out;
  }
  function renderWgNatPeerPick(peers, tunnelServer) {
    var sel = $('wgNatRemotePeerPick'); if (!sel) return;
    /* Candidates: the server's peers, plus the server this machine
       connects to as a client (tunnelServer) — a gateway can be a
       client, and its remote gateway is that server. */
    var cands = (peers || []).map(function (p) { return { name: p.name || 'peer', tunnelIp: p.tunnelIp }; });
    if (tunnelServer && tunnelServer.tunnelIp && !cands.some(function (c) { return c.tunnelIp === tunnelServer.tunnelIp; })) {
      cands.push({ name: 'Server', tunnelIp: tunnelServer.tunnelIp });
    }
    var sig = JSON.stringify(cands.map(function (p) { return [p.name, p.tunnelIp]; }));
    if (sig === lastWgNatPeersSig) return;
    lastWgNatPeersSig = sig;
    var prev = sel.value;
    sel.innerHTML = '';
    var o0 = document.createElement('option'); o0.value = '';
    o0.textContent = cands.length ? 'Pick the other gateway…' : 'No peers yet — add one above first';
    sel.appendChild(o0);
    cands.forEach(function (p) {
      var opt = document.createElement('option'); opt.value = p.tunnelIp;
      opt.textContent = (p.name || 'peer') + ' — ' + p.tunnelIp;
      sel.appendChild(opt);
    });
    if (prev) sel.value = prev;
    /* Exactly one gateway to pick from: select it — the user only
       has one other gateway, so there is nothing to choose. */
    else if (cands.length === 1) sel.value = cands[0].tunnelIp;
  }
  function renderWgNatForm(st) {
    var fs = $('wgNatFieldset'); if (!fs) return;
    var n = (st && st.nat) || {};
    var saved = (st && st.natConfig) || null;
    fs.disabled = !!n.running;
    var savedSig = JSON.stringify(saved || null);
    if (!wgNatFormDirty && savedSig !== lastWgNatSavedSig) {
      lastWgNatSavedSig = savedSig;
      /* The form holds only the mode and the mapping rows now —
         the subnets, the gateway LAN address and the far virtual
         address are auto-detected / auto-picked in main. */
      if (saved) {
        setWgNatMode(saved.mode === 'different-subnet' ? 'different-subnet' : 'same-subnet');
      } else {
        setWgNatMode('same-subnet');
      }
    }
    setWgNatMode(currentWgNatMode());
    var mapSig = JSON.stringify((saved && saved.mode === 'same-subnet') ? (saved.mappings || []) : []);
    if (!wgNatFormDirty && mapSig !== lastWgNatMappingsSig) {
      lastWgNatMappingsSig = mapSig;
      wgNatRebuildMappings(saved && saved.mappings ? saved.mappings : [null]);
    }
    renderWgNatPeerPick(st.peers || [], st.tunnelServer || null);
    /* Restore the saved remote gateway into the picker (unless the
       user changed it — the dirty flag guards that). */
    if (!wgNatFormDirty && saved && saved.remoteTunnelIp) {
      var sel = $('wgNatRemotePeerPick');
      if (sel && sel.querySelector('option[value="' + saved.remoteTunnelIp + '"]')) sel.value = saved.remoteTunnelIp;
    }
  }
  async function wgNatSaveForm() {
    var errEl = $('wgNatFormError');
    var fail = function (msg) {
      if (errEl) errEl.textContent = msg;
      toast('NAT configuration', msg, 'error');
      return false;
    };
    if (errEl) errEl.textContent = '';
    if (!api || typeof api.wgNatSave !== 'function') return wgMissing();
    var mode = currentWgNatMode();
    if (mode === 'different-subnet') return fail('Different-subnet mode needs no configuration — just pick the other gateway and press Start NAT service.');
    /* The other gateway comes from the peer picker (auto-selected
       when there is exactly one peer). */
    var pick = $('wgNatRemotePeerPick');
    var peerTunnelIp = pick ? String(pick.value || '').trim() : '';
    if (!peerTunnelIp) return fail('Pick the other gateway first — the remote gateway peer has to be set up before the NAT service can start.');
    /* The remote gateway must be a peer — checked here for instant
       feedback, and again in main (the authoritative check, before
       anything is saved). Either role counts: a server peer, or
       the server this client connects to. */
    var peers = (wgStatusCache && wgStatusCache.peers) || [];
    var ts = wgStatusCache && wgStatusCache.tunnelServer;
    var known = peers.some(function (p) { return p.tunnelIp === peerTunnelIp; }) || (ts && ts.tunnelIp === peerTunnelIp);
    if (!known) return fail('The remote gateway (' + peerTunnelIp + ') is not a WireGuard peer yet — add it first (with the add-peer form, or over Cloud join), then save.');
    /* The form sends just the mode, the mapping rows and the
       picked peer: the subnets, the gateway LAN address and the
       far virtual address are auto-detected / auto-picked in main,
       which validates everything with the real CIDR math. */
    var config = { mode: mode, mappings: wgNatReadMappings(), peerTunnelIp: peerTunnelIp };
    var saveBtn = $('wgNatSaveBtn'); if (saveBtn) saveBtn.disabled = true;
    try {
      var r = await api.wgNatSave(config);
      if (r && r.success) {
        wgNatFormDirty = false;
        toast('NAT configuration', 'Site-to-site configuration saved — press Start NAT service when ready.', 'success');
        await loadWireGuard();
      } else {
        var msg = (r && r.errors && r.errors.length > 1) ? r.errors.join(' ') : ((r && r.error) || 'Could not save the NAT configuration.');
        fail(msg);
      }
    } catch (e) { fail(e && e.message ? e.message : 'Could not save the NAT configuration.'); }
    finally { if (saveBtn) saveBtn.disabled = false; }
  }

  function renderWgPeers(peers) {
    var list = $('wgPeerList'); if (!list) return;
    var sig = JSON.stringify((peers || []).map(function (p) { return [p.name, p.tunnelIp, p.publicKey, p.endpoint, p.online, p.latestHandshake, p.transferRx, p.transferTx]; }));
    if (sig === lastWgPeersSig) return;
    lastWgPeersSig = sig;
    list.innerHTML = '';
    if (!peers.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = '<div class="big">🔐</div><h3>No devices yet</h3><p>Add a device below and it will show up here.</p>';
      list.appendChild(empty);
      return;
    }
    peers.forEach(function (p) {
      var row = document.createElement('div');
      row.className = 'vpn-peer';
      var d = document.createElement('span'); d.className = 'vpn-peer-dot' + (p.online ? ' on' : '');
      var body = document.createElement('div'); body.className = 'vpn-peer-body';
      var h = document.createElement('h3'); h.className = 'vpn-peer-name'; h.textContent = p.name + ' — ' + p.tunnelIp;
      var meta = document.createElement('div'); meta.className = 'vpn-peer-meta';
      meta.textContent = (p.online ? ('online — last handshake ' + wgHandshakeText(p.latestHandshake)) : 'never connected') + ' · ' + formatBytes(p.transferRx || 0) + ' down / ' + formatBytes(p.transferTx || 0) + ' up · ' + String(p.publicKey || '').slice(0, 12) + '…' + (p.endpoint ? (' · endpoint ' + p.endpoint) : '');
      body.appendChild(h); body.appendChild(meta);
      row.appendChild(d); row.appendChild(body);
      var rm = document.createElement('button'); rm.className = 'btn btn-ghost btn-sm'; rm.type = 'button'; rm.textContent = 'Remove';
      rm.addEventListener('click', async function () {
        if (!api || typeof api.wgRemovePeer !== 'function') return wgMissing();
        rm.disabled = true;
        try {
          var r = await api.wgRemovePeer({ publicKey: p.publicKey });
          if (r && r.success) toast('Peer removed', p.name + ' can no longer connect.', 'success');
          else toast('Remove failed', (r && r.error) || 'Could not remove the peer.', 'error');
        } catch (e) { toast('Remove failed', e && e.message ? e.message : 'Could not remove the peer.', 'error'); }
        await loadWireGuard();
      });
      row.appendChild(rm);
      list.appendChild(row);
    });
  }

  /* Cloud join — server side: pending requests with Approve /
     Reject. The list rebuilds only when it changes (sig guard), so
     a button never disappears under the mouse on the 15s refresh. */
  async function loadWgJoinRequests() {
    var list = $('wgJoinList'); if (!list) return;
    if (!api || typeof api.wgCloudJoinList !== 'function') { list.innerHTML = ''; return; }
    var reqs = [];
    try {
      var r = await api.wgCloudJoinList();
      if (r && r.success) reqs = r.requests || [];
    } catch (e) { /* keep the previous list */ return; }
    var sig = JSON.stringify(reqs.map(function (q) { return [q.id, q.deviceName, q.user, q.publicKey]; }));
    if (sig === lastWgJoinReqSig) return;
    lastWgJoinReqSig = sig;
    list.innerHTML = '';
    if (!reqs.length) {
      var none = document.createElement('div');
      none.className = 't-sub';
      none.textContent = 'No join requests.';
      list.appendChild(none);
      return;
    }
    reqs.forEach(function (q) {
      var row = document.createElement('div');
      row.className = 'vpn-peer';
      var d = document.createElement('span'); d.className = 'vpn-peer-dot';
      var body = document.createElement('div'); body.className = 'vpn-peer-body';
      var h = document.createElement('h3'); h.className = 'vpn-peer-name'; h.textContent = q.deviceName + ' — from ' + q.user;
      var meta = document.createElement('div'); meta.className = 'vpn-peer-meta';
      meta.textContent = 'public key ' + String(q.publicKey || '').slice(0, 12) + '… · waiting for approval';
      body.appendChild(h); body.appendChild(meta);
      row.appendChild(d); row.appendChild(body);
      var ok = document.createElement('button'); ok.className = 'btn btn-primary btn-sm'; ok.type = 'button'; ok.textContent = 'Approve';
      ok.addEventListener('click', async function () {
        if (!api || typeof api.wgCloudJoinApprove !== 'function') return wgMissing();
        ok.disabled = true;
        try {
          var ar = await api.wgCloudJoinApprove({ id: q.id });
          if (ar && ar.success) toast('Join approved', q.deviceName + ' got tunnel address ' + (ar.approval && ar.approval.tunnelIp ? ar.approval.tunnelIp : '') + '.', 'success');
          else toast('Approve failed', (ar && ar.error) || 'Could not approve the join request.', 'error');
        } catch (e) { toast('Approve failed', e && e.message ? e.message : 'Could not approve the join request.', 'error'); }
        lastWgJoinReqSig = null;
        await loadWireGuard();
      });
      row.appendChild(ok);
      var no = document.createElement('button'); no.className = 'btn btn-ghost btn-sm'; no.type = 'button'; no.textContent = 'Reject';
      no.addEventListener('click', async function () {
        if (!api || typeof api.wgCloudJoinReject !== 'function') return wgMissing();
        no.disabled = true;
        try {
          var rr = await api.wgCloudJoinReject({ id: q.id });
          if (rr && rr.success) toast('Join rejected', q.deviceName + ' was turned down.', 'success');
          else toast('Reject failed', (rr && rr.error) || 'Could not reject the join request.', 'error');
        } catch (e) { toast('Reject failed', e && e.message ? e.message : 'Could not reject the join request.', 'error'); }
        lastWgJoinReqSig = null;
        await loadWireGuard();
      });
      row.appendChild(no);
      list.appendChild(row);
    });
  }

  /* Cloud join — client side: the saved Cloud servers this machine
     can send a join request through. Options rebuild only when the
     saved list changes, so the user's pick is never clobbered. */
  function renderWgJoinServers(clients) {
    var sel = $('wgJoinServer'); if (!sel) return;
    var sig = JSON.stringify((clients || []).map(function (c) { return [c.id, c.name, c.host, c.port, c.user]; }));
    if (sig === lastWgJoinServersSig) return;
    lastWgJoinServersSig = sig;
    var prev = sel.value;
    sel.innerHTML = '';
    if (!clients || !clients.length) {
      var o = document.createElement('option'); o.value = ''; o.textContent = 'No saved Cloud server — add one in the Cloud module first';
      sel.appendChild(o);
      return;
    }
    clients.forEach(function (c) {
      var opt = document.createElement('option');
      opt.value = c.id;
      opt.textContent = (c.name || c.host) + ' — ' + (c.user || '') + ' @ ' + c.host + ':' + c.port;
      sel.appendChild(opt);
    });
    if (prev) sel.value = prev;
  }

  function wgJoinSetStatus(text) {
    var s = $('wgJoinStatus'); if (s) s.textContent = text || '';
    var cancel = $('wgJoinCancelBtn'); if (cancel) cancel.style.display = wgJoinPending ? '' : 'none';
    var send = $('wgJoinSendBtn'); if (send) send.disabled = !!wgJoinPending;
  }

  function wgJoinStopPolling() {
    if (wgJoinPollTimer) { clearInterval(wgJoinPollTimer); wgJoinPollTimer = null; }
  }

  function wgJoinClearPending() {
    wgJoinStopPolling();
    wgJoinPending = null;
    wgJoinSetStatus('');
  }

  // One poll of the outstanding join request. Approved hands the
  // config straight to wg-connect (the same path as a pasted config);
  // rejected / expired / server-restarted are terminal — the timer
  // stops and the user sends a fresh request.
  async function wgJoinPollOnce() {
    if (!wgJoinPending || !api || typeof api.wgCloudJoinPoll !== 'function') return;
    var r;
    try { r = await api.wgCloudJoinPoll({ requestId: wgJoinPending.requestId }); }
    catch (e) { r = { success: false, error: e && e.message ? e.message : 'Could not check the join request.' }; }
    if (!wgJoinPending) return;
    if (r && r.success && r.status === 'approved') {
      wgJoinClearPending();
      try {
        var c = await api.wgConnect({ confText: r.confText });
        if (c && c.success) toast('WireGuard', 'Join approved — connected as ' + (c.tunnelIp || r.tunnelIp || 'a client') + '.', 'success');
        else toast('Connect failed', (c && c.error) || 'The join was approved, but connecting failed.', 'error');
      } catch (e) { toast('Connect failed', e && e.message ? e.message : 'The join was approved, but connecting failed.', 'error'); }
      await loadWireGuard();
      return;
    }
    if (r && r.success && r.status === 'pending') {
      wgJoinSetStatus('Waiting for approval on the server — ' + wgJoinPending.deviceName + '…');
      return;
    }
    if (r && r.success && r.status === 'rejected') {
      wgJoinClearPending();
      toast('Join rejected', 'The server turned down the join request.', 'error');
      await loadWireGuard();
      return;
    }
    wgJoinClearPending();
    toast('Join request ended', (r && r.error) || 'The join request is no longer waiting.', 'error');
    await loadWireGuard();
  }

  function wgJoinStartPolling() {
    wgJoinStopPolling();
    wgJoinPollTimer = setInterval(wgJoinPollOnce, 5000);
  }

  /* ---------- wiring ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    var nnj = $('navNewJob'); if (nnj) nnj.addEventListener('click', function () { openJobWizard(null); });
    var jnb = $('jobsNewJobBtn'); if (jnb) jnb.addEventListener('click', function () { openJobWizard(null); });
    var jenb = $('jobsEmptyNewJobBtn'); if (jenb) jenb.addEventListener('click', function () { openJobWizard(null); });
    $('emptyNewJobBtn').addEventListener('click', function () { openJobWizard(null); });

    $('navRestore').addEventListener('click', function () { openRestore(null); });
    var brb = $('backupTopRefreshBtn');
    if (brb) brb.addEventListener('click', refreshJobs);
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
        if (nav === 'wireguard') showView('wireguard');
        if (nav === 'cloud-server') { setModule('cloud'); showCloudPanel('server'); }
        if (nav === 'cloud-client') { setModule('cloud'); showCloudPanel('client'); }
      });
    });
    document.querySelectorAll('[data-module]').forEach(function (btn) {
      btn.addEventListener('click', function () { setModule(btn.getAttribute('data-module')); });
    });
    document.querySelectorAll('#cloudServerAccessSeg .seg-btn').forEach(function (b) {
      b.addEventListener('click', function () { setServerAccess(b.getAttribute('data-access')); saveCloudServerSettings(); });
    });
    document.querySelectorAll('#cloudClientAccessSeg .seg-btn').forEach(function (b) {
      b.addEventListener('click', function () { setClientAccess(b.getAttribute('data-access')); });
    });
    var cps = $('cloudClientPeer');
    if (cps) cps.addEventListener('change', function () {
      var host = $('cloudClientHost'); if (host && cps.value) host.value = cps.value;
      var port = $('cloudClientPort'); if (port && cps.value && !port.value) port.value = '8443';
      var name = $('cloudClientName');
      if (name && !name.value && cps.selectedOptions && cps.selectedOptions[0]) name.value = cps.selectedOptions[0].getAttribute('data-peer-name') || '';
    });
    var vcb = $('vpnConnectBtn');
    if (vcb) vcb.addEventListener('click', async function () {
      if (!api || typeof api.vpnSetConnected !== 'function') return vpnMissing();
      if (vpnBusy) return;
      // The first status read may still be in flight when the view
      // opens — read it once before deciding between Install and
      // Connect, or a fast click takes the wrong branch.
      if (!vpnStatusCache) await loadVpn();
      // Not installed yet → show the administrator step first. The user
      // picks the Windows UAC prompt (empty fields) or types an
      // administrator account (domain PC); the install itself starts
      // on Install in the box below.
      if (vpnStatusCache && !vpnStatusCache.installed) {
        if (typeof api.vpnInstallConnect !== 'function' || typeof api.onVpnInstallProgress !== 'function') return vpnMissing();
        var ib = $('vpnInstallBox'); if (ib) ib.style.display = '';
        var af = $('vpnAdminForm'); if (af) af.style.display = '';
        var ip = $('vpnInstallProgress'); if (ip) ip.style.display = 'none';
        var au = $('vpnAdminUser'); if (au) au.value = '';
        var ap = $('vpnAdminPass'); if (ap) ap.value = '';
        vcb.disabled = true;
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
        if (r && r.success && wantOn && !r.needsLogin) await pollVpnUntilConnected();
      } catch (e) { toast('VPN error', e && e.message ? e.message : 'Could not change the VPN connection.', 'error'); }
      finally { vpnBusy = false; }
    });
    var vaib = $('vpnAdminInstallBtn');
    if (vaib) vaib.addEventListener('click', async function () {
      if (vpnBusy) return;
      if (typeof api.vpnInstallConnect !== 'function' || typeof api.onVpnInstallProgress !== 'function') return vpnMissing();
      var au = $('vpnAdminUser'); var ap = $('vpnAdminPass');
      var adminUser = au ? au.value.trim() : '';
      var adminPass = ap ? ap.value : '';
      // The password is used once for this install and never stored —
      // clear the field the moment it is read.
      if (ap) ap.value = '';
      if ((adminUser && !adminPass) || (!adminUser && adminPass)) { toast('Administrator account', 'Type both the administrator user name and password, or leave both empty for the Windows prompt.', 'error'); return; }
      var creds = (adminUser && adminPass) ? { user: adminUser, password: adminPass } : null;
      vpnBusy = true;
      var vcb2 = $('vpnConnectBtn'); if (vcb2) { vcb2.disabled = true; vcb2.textContent = 'Installing…'; }
      var af = $('vpnAdminForm'); if (af) af.style.display = 'none';
      var ip = $('vpnInstallProgress'); if (ip) ip.style.display = '';
      var stopListen = api.onVpnInstallProgress(function (p) {
        var f = $('vpnInstallFill'); if (f) f.style.width = Math.max(0, Math.min(100, p.pct || 0)) + '%';
        var t = $('vpnInstallText'); if (t) t.textContent = p.text || '';
      });
      try {
        var r = await api.vpnInstallConnect(creds);
        if (r && r.success) {
          if (r.needsLogin) toast('VPN', 'Tailscale is installed. Sign in to Tailscale in the browser window, then press Refresh.', '');
          else toast('VPN', 'Tailscale installed and connected.', 'success');
        } else toast('VPN error', (r && r.error) || 'Could not install Tailscale.', 'error');
      } catch (e) { toast('VPN error', e && e.message ? e.message : 'Could not install Tailscale.', 'error'); }
      finally { if (stopListen) stopListen(); vpnBusy = false; var ib2 = $('vpnInstallBox'); if (ib2) ib2.style.display = 'none'; await loadVpn(); if (r && r.success && !r.needsLogin) await pollVpnUntilConnected(); }
    });
    var vacb = $('vpnAdminCancelBtn');
    if (vacb) vacb.addEventListener('click', function () {
      var ib = $('vpnInstallBox'); if (ib) ib.style.display = 'none';
      var ap = $('vpnAdminPass'); if (ap) ap.value = '';
      var vcb3 = $('vpnConnectBtn'); if (vcb3) { vcb3.disabled = false; vcb3.textContent = 'Install & connect'; }
    });
    var vrb = $('vpnTopRefreshBtn');
    if (vrb) vrb.addEventListener('click', function () { loadVpn(); });
    // Peers appear on their own: while the VPN view is open, or the Cloud
    // client panel is open in Tailscale mode, re-read Tailscale status
    // every 15s so a device that joins shows up without re-opening the
    // view or re-picking anything. Both renderers skip rebuilding when
    // nothing changed, so an open dropdown or a selection is never
    // disturbed; skipped while an install/connect is in progress.
    setInterval(function () {
      if (vpnBusy) return;
      var vpnView = $('view-vpn');
      if (vpnView && vpnView.style.display !== 'none') loadVpn();
      var wgView = $('view-wireguard');
      if (wgView && wgView.style.display !== 'none' && !wgBusy) loadWireGuard();
      var cloudView = $('view-cloud');
      if (cloudView && cloudView.style.display !== 'none' && cloudPanel === 'client' && cloudClientAccess === 'tailscale') populateCloudPeers();
      if (cloudView && cloudView.style.display !== 'none' && cloudPanel === 'client' && cloudClientAccess === 'wireguard') populateCloudWgPeers();
    }, 15000);
    var vab = $('vpnOpenAuthBtn');
    if (vab) vab.addEventListener('click', async function () {
      if (!vpnAuthUrlCache) return;
      if (!api || typeof api.vpnOpenAuthUrl !== 'function') return vpnMissing();
      await api.vpnOpenAuthUrl(vpnAuthUrlCache);
    });
    var vdb = $('vpnDownloadBtn');
    if (vdb) vdb.addEventListener('click', async function () {
      if (!api || typeof api.vpnOpenDownload !== 'function') return vpnMissing();
      await api.vpnOpenDownload();
    });
    var vrc = $('vpnRecheckBtn');
    if (vrc) vrc.addEventListener('click', function () { loadVpn(); });
    var vke = $('vpnKeyExpiryToggle');
    if (vke) vke.addEventListener('change', async function () {
      var wantOff = vke.checked; // ON = key expiry OFF (stay connected forever)
      await saveVpnSettings({ autoDisableKeyExpiry: wantOff });
      var ok = wantOff ? await disableVpnKeyExpiry(false) : await enableVpnKeyExpiry();
      if (!ok) {
        // The switch must never lie: if the API said no, snap it back
        // to where it was, and open the credentials so the user can see
        // what is missing.
        vke.checked = !wantOff;
        await saveVpnSettings({ autoDisableKeyExpiry: !wantOff });
        if (!vpnAuth()) { var d = $('vpnApiCreds'); if (d) d.open = true; }
      }
      refreshVpnKeyExpiryState();
    });
    var vts = $('vpnApiTokenSaveBtn');
    if (vts) vts.addEventListener('click', async function () {
      var inp = $('vpnApiToken');
      var token = inp ? inp.value.trim() : '';
      await saveVpnSettings({ apiToken: token });
      toast('VPN', token ? 'API token saved.' : 'API token removed.', 'success');
      var d0 = $('vpnApiCreds'); if (d0) d0.open = true;
      refreshVpnApiCredsStatus(true);
      refreshVpnKeyExpiryState();
      refreshVpnRoutesState();
    });
    var vos = $('vpnOauthSaveBtn');
    if (vos) vos.addEventListener('click', async function () {
      var idInp = $('vpnOauthClientId');
      var secInp = $('vpnOauthClientSecret');
      var id = idInp ? idInp.value.trim() : '';
      var sec = secInp ? secInp.value.trim() : '';
      await saveVpnSettings({ oauthClientId: id, oauthClientSecret: sec });
      toast('VPN', (id && sec) ? 'OAuth client saved.' : 'OAuth client removed.', 'success');
      var d1 = $('vpnApiCreds'); if (d1) d1.open = true;
      refreshVpnApiCredsStatus(true);
      refreshVpnKeyExpiryState();
      refreshVpnRoutesState();
    });
    var voo = $('vpnOauthOpenBtn');
    if (voo) voo.addEventListener('click', async function () {
      if (!api || typeof api.vpnOpenOauthPage !== 'function') return vpnMissing();
      await api.vpnOpenOauthPage();
    });
    var vto = $('vpnApiTokenOpenBtn');
    if (vto) vto.addEventListener('click', async function () {
      if (!api || typeof api.vpnOpenKeysPage !== 'function') return vpnMissing();
      await api.vpnOpenKeysPage();
    });
    var vst = $('vpnSubnetToggle');
    if (vst) vst.addEventListener('change', async function () {
      if (!api || typeof api.vpnSetRoutes !== 'function') return vpnMissing();
      var on = vst.checked;
      try {
        var r = await api.vpnSetRoutes(on, vpnAuth());
        if (r && r.success) {
          // Update the cached status right away, so the view agrees
          // with the toggle without waiting for a slow `tailscale
          // status` re-read — and trust the approve call itself: the
          // note must say "approved" now, not after the next 15-second
          // poll (the control plane can take a few seconds to show it
          // on a re-read, which is exactly the long "waiting…" the
          // user saw).
          if (vpnStatusCache) {
            var adv = vpnStatusCache.advertiseRoutes || [];
            if (on && r.subnet && adv.indexOf(r.subnet) < 0) adv = adv.concat([r.subnet]);
            if (!on) adv = [];
            vpnStatusCache.advertiseRoutes = adv;
            if (r.subnet) vpnStatusCache.lanSubnet = r.subnet;
          }
          if (on) {
            if (r.approved) {
              vpnRoutesApprovedHint = { subnet: r.subnet, at: Date.now() };
              toast('VPN', 'Sharing your home network — the route was approved automatically.', 'success');
            } else {
              vpnRoutesApprovedHint = null;
              if (typeof api.vpnOpenAdmin === 'function') await api.vpnOpenAdmin();
              toast('VPN', 'Sharing your home network — approve the route in the Tailscale admin console (it just opened in your browser).' + (r.approveError ? ' The automatic approval failed: ' + r.approveError : ''), 'success');
            }
          } else {
            vpnRoutesApprovedHint = null;
            toast('VPN', 'No longer sharing your home network.', 'success');
          }
          refreshVpnRoutesState();
        } else { toast('VPN error', (r && r.error) || 'Could not change the subnet router setting.', 'error'); vst.checked = !on; await loadVpn(); }
      } catch (e) { toast('VPN error', e && e.message ? e.message : 'Could not change the subnet router setting.', 'error'); vst.checked = !on; await loadVpn(); }
    });
    var vab2 = $('vpnApproveBtn');
    if (vab2) vab2.addEventListener('click', async function () {
      if (!api || typeof api.vpnOpenAdmin !== 'function') return vpnMissing();
      await api.vpnOpenAdmin();
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
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeDrawer(); closeSettings(); cloudHideContextMenu(); } });

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
    var crb = $('cloudTopRefreshBtn');
    if (crb) crb.addEventListener('click', function () { loadCloud(); });
    var cms = $('cloudModeServer');
    if (cms) cms.addEventListener('click', function () { showCloudPanel('server'); });
    var cmc = $('cloudModeClient');
    if (cmc) cmc.addEventListener('click', function () { showCloudPanel('client'); });
    var css = $('cloudServerStartBtn');
    if (css) css.addEventListener('click', async function () {
      if (!api || typeof api.cloudServerStart !== 'function' || typeof api.cloudServerStop !== 'function') return cloudMissing();
      try {
        // Let any auto-save triggered by a blur finish first, so its
        // server start/stop cannot race the one below.
        await cloudServerSaveQueue;
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
    // Server settings auto-save: the enabled toggle, the port field
    // (on change = when the user leaves the field) and the access-mode
    // buttons all save immediately — there is no Save button anymore.
    var cse = $('cloudServerEnabled');
    if (cse) cse.addEventListener('change', function () { saveCloudServerSettings(); });
    var csp = $('cloudServerPort');
    if (csp) csp.addEventListener('change', function () { saveCloudServerSettings(); });
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
          // Save & connect, one click: open the connect box with the
          // password the user just typed (it is never stored), and do
          // the whole thing at once — probe, trust the fingerprint,
          // connect. Without a password the box stays open so the user
          // can type it and press Connect there.
          var rec = (cloudCfg && cloudCfg.clients || []).find(function (c) { return c.id === r.id; });
          if (rec) {
            openCloudConnect(rec, password);
            if (password) cloudConnectFlow(true);
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
    if (cmb) cmb.addEventListener('click', function () { cloudNewFolder(cloudPath); });
    var cbr = $('cloudBrowserRefreshBtn');
    if (cbr) cbr.addEventListener('click', function () { cloudBrowse(cloudPath); });
    // Explorer toolbar: the actions apply to the selected row.
    var cub3 = $('cloudUpBtn');
    if (cub3) cub3.addEventListener('click', function () { if (cloudPath) cloudBrowse(cloudParent(cloudPath)); });
    var cbd2 = $('cloudDownloadBtn');
    if (cbd2) cbd2.addEventListener('click', function () { if (cloudSelectedEntry && !cloudSelectedEntry.isDir) cloudDownload(cloudSelectedEntry.rel); });
    var cbc2 = $('cloudCopyBtn');
    if (cbc2) cbc2.addEventListener('click', function () { cloudCopySelected(); });
    var cbp2 = $('cloudPasteBtn');
    if (cbp2) cbp2.addEventListener('click', function () { cloudPasteClipboard(); });
    var cbr2 = $('cloudRenameBtn');
    if (cbr2) cbr2.addEventListener('click', function () { cloudRenameSelected(); });
    var cbdel = $('cloudDeleteBtn');
    if (cbdel) cbdel.addEventListener('click', function () { cloudDeleteSelected(); });
    var cfl = $('cloudFileList');
    if (cfl) cfl.addEventListener('keydown', function (ev) {
      if (ev.ctrlKey && (ev.key === 'c' || ev.key === 'C')) { cloudCopySelected(); ev.preventDefault(); }
      else if (ev.ctrlKey && (ev.key === 'v' || ev.key === 'V')) { cloudPasteClipboard(); ev.preventDefault(); }
    });
    // Right-click in the file list: the Windows menu (Open, Copy, Paste,
    // Rename, Delete, New folder). A right-click selects the row first.
    if (cfl) cfl.addEventListener('contextmenu', function (ev) {
      ev.preventDefault();
      var row = ev.target && ev.target.closest ? ev.target.closest('.cloud-row') : null;
      var entry = row && row.cloudEntry ? row.cloudEntry : null;
      if (entry) cloudSelectEntry(entry, row);
      cloudShowContextMenu(ev.clientX, ev.clientY, entry);
    });
    document.addEventListener('click', function (ev) {
      var m = $('cloudContextMenu');
      if (m && m.style.display !== 'none' && !m.contains(ev.target)) cloudHideContextMenu();
    }, true);
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


  // WireGuard view wiring — all buttons of #view-wireguard.
  var wgRb = $('wgTopRefreshBtn');
  if (wgRb) wgRb.addEventListener('click', function () { loadWireGuard(); });
  var wgDb = $('wgDownloadBtn');
  if (wgDb) wgDb.addEventListener('click', async function () {
    if (!api || typeof api.wgOpenDownload !== 'function') return wgMissing();
    await api.wgOpenDownload();
  });
  // One-click AmneziaWG install (the transport since Phase 2): the
  // button shows the download/verify/install phases live, mirroring
  // the Tailscale install button. On Linux this refuses in main
  // before fetching anything; on Windows it is one UAC prompt.
  var wgIb = $('wgInstallBtn');
  if (wgIb) wgIb.addEventListener('click', async function () {
    if (!api || typeof api.wgInstallAmneziawg !== 'function' || typeof api.onWgInstallProgress !== 'function') return wgMissing();
    if (wgBusy) return;
    wgBusy = true; wgIb.disabled = true; wgIb.textContent = 'Installing…';
    var stopListen = api.onWgInstallProgress(function (p) {
      if (!p) return;
      if (p.phase === 'downloading' && typeof p.pct === 'number') wgIb.textContent = 'Downloading… ' + p.pct + '%';
      else if (p.phase === 'verifying') wgIb.textContent = 'Verifying…';
      else if (p.phase === 'installing') wgIb.textContent = 'Installing…';
    });
    try {
      var r = await api.wgInstallAmneziawg();
      if (r && r.success) toast('AmneziaWG installed', 'AmneziaWG is ready — the server and client are now available.', 'success');
      else toast('Install failed', (r && r.error) || 'Could not install AmneziaWG.', 'error');
    } catch (e) { toast('Install failed', e && e.message ? e.message : 'Could not install AmneziaWG.', 'error'); }
    finally { if (stopListen) stopListen(); wgBusy = false; wgIb.disabled = false; wgIb.textContent = 'Install AmneziaWG'; await loadWireGuard(); }
  });
  var wgRc = $('wgRecheckBtn');
  if (wgRc) wgRc.addEventListener('click', function () { loadWireGuard(); });
  /* NAT mapping editor wiring: any edit marks the form dirty so the
     poller never overwrites it; mode radios toggle the same-subnet
     form; the peer picker marks the form dirty (the Start button
     reads the picked peer, the Save reads it too). */
  var wgNatFs = $('wgNatFieldset');
  if (wgNatFs) {
    wgNatFs.addEventListener('input', function () { wgNatFormDirty = true; });
    wgNatFs.addEventListener('change', function () { wgNatFormDirty = true; setWgNatMode(currentWgNatMode()); });
  }
  var wgNatPick = $('wgNatRemotePeerPick');
  if (wgNatPick) wgNatPick.addEventListener('change', function () { wgNatFormDirty = true; });
  var wgNatAddMap = $('wgNatAddMappingBtn');
  if (wgNatAddMap) wgNatAddMap.addEventListener('click', function () { wgNatAddMappingRow(null); wgNatFormDirty = true; });
  var wgNatSave = $('wgNatSaveBtn');
  if (wgNatSave) wgNatSave.addEventListener('click', function () { wgNatSaveForm(); });
  var wgNatExp = $('wgNatExportBtn');
  if (wgNatExp) wgNatExp.addEventListener('click', async function () {
    if (!api || typeof api.wgNatExport !== 'function') return wgMissing();
    try {
      var r = await api.wgNatExport();
      if (r && r.success) toast('Site-to-site', 'Configuration exported to ' + r.filePath + '.', 'success');
      else if (r && !r.canceled) toast('Export', (r && r.error) || 'Could not export the configuration.', 'error');
    } catch (e) { toast('Export', e && e.message ? e.message : 'Could not export the configuration.', 'error'); }
  });
  var wgNatImp = $('wgNatImportBtn');
  if (wgNatImp) wgNatImp.addEventListener('click', async function () {
    if (!api || typeof api.wgNatImport !== 'function') return wgMissing();
    try {
      var r2 = await api.wgNatImport();
      if (r2 && r2.success) { wgNatFormDirty = false; toast('Site-to-site', 'Configuration imported — press Start NAT service when ready.', 'success'); await loadWireGuard(); }
      else if (r2 && !r2.canceled) toast('Import', (r2 && r2.error) || 'Could not import the configuration.', 'error');
    } catch (e) { toast('Import', e && e.message ? e.message : 'Could not import the configuration.', 'error'); }
  });
  var wgNatStart = $('wgNatStartBtn');
  if (wgNatStart) wgNatStart.addEventListener('click', async function () {
    if (!api || typeof api.wgNatStart !== 'function') return wgMissing();
    if (wgBusy) return;
    wgBusy = true; wgNatStart.disabled = true; wgNatStart.textContent = 'Starting…';
    try {
      /* The mode and the picked remote gateway go with the start:
         in different-subnet mode there is no saved config at all,
         so the picker is the only place the peer comes from. */
      var pick2 = $('wgNatRemotePeerPick');
      var r = await api.wgNatStart({ mode: currentWgNatMode(), peerTunnelIp: pick2 ? String(pick2.value || '').trim() : '' });
      if (r && r.success) toast('NAT service', 'The gateway NAT service is running.' + ((r && r.remoteNote) ? ' ' + r.remoteNote : ''), 'success');
      else toast('NAT service', (r && r.error) || 'Could not start the NAT service.', 'error');
    } catch (e) { toast('NAT service', e && e.message ? e.message : 'Could not start the NAT service.', 'error'); }
    finally { wgBusy = false; wgNatStart.disabled = false; wgNatStart.textContent = 'Start NAT service'; await loadWireGuard(); }
  });
  var wgNatStop = $('wgNatStopBtn');
  if (wgNatStop) wgNatStop.addEventListener('click', async function () {
    if (!api || typeof api.wgNatStop !== 'function') return wgMissing();
    if (wgBusy) return;
    wgBusy = true; wgNatStop.disabled = true;
    try {
      var r = await api.wgNatStop();
      if (r && r.success) toast('NAT service', 'The gateway NAT service is stopped.', 'success');
      else toast('NAT service', (r && r.error) || 'Could not stop the NAT service.', 'error');
    } catch (e) { toast('NAT service', e && e.message ? e.message : 'Could not stop the NAT service.', 'error'); }
    finally { wgBusy = false; wgNatStop.disabled = false; await loadWireGuard(); }
  });
  var wgSb = $('wgServerBtn');
  if (wgSb) wgSb.addEventListener('click', async function () {
    if (!api || typeof api.wgStartServer !== 'function' || typeof api.wgStopServer !== 'function') return wgMissing();
    if (wgBusy) return;
    wgBusy = true; wgSb.disabled = true; wgSb.textContent = 'Working…';
    try {
      var running = !!(wgStatusCache && wgStatusCache.serverRunning);
      var r = running ? await api.wgStopServer() : await api.wgStartServer();
      if (r && r.success) toast('WireGuard', running ? 'Server stopped.' : 'Server is running.', 'success');
      else toast('WireGuard error', (r && r.error) || 'Could not change the server state.', 'error');
    } catch (e) { toast('WireGuard error', e && e.message ? e.message : 'Could not change the server state.', 'error'); }
    finally { wgBusy = false; wgSb.disabled = false; await loadWireGuard(); }
  });
  var wgEs = $('wgEndpointSaveBtn');
  if (wgEs) wgEs.addEventListener('click', async function () {
    if (!api || typeof api.wgSetEndpoint !== 'function') return wgMissing();
    var v = ($('wgEndpoint') || {}).value || '';
    try {
      var r = await api.wgSetEndpoint(v);
      if (r && r.success) toast('Endpoint saved', v.trim() ? ('Clients will connect to ' + r.endpoint + '.') : 'Endpoint cleared — the public IP will be read automatically.', 'success');
      else toast('Save failed', (r && r.error) || 'Could not save the endpoint.', 'error');
    } catch (e) { toast('Save failed', e && e.message ? e.message : 'Could not save the endpoint.', 'error'); }
    await loadWireGuard();
  });
  var wgSs = $('wgServerSettingsSaveBtn');
  if (wgSs) wgSs.addEventListener('click', async function () {
    if (!api || typeof api.wgSetServerSettings !== 'function') return wgMissing();
    var addr = ($('wgServerIp') || {}).value || '';
    var port = ($('wgServerPort') || {}).value || '';
    try {
      var r = await api.wgSetServerSettings({ address: addr, listenPort: port });
      if (r && r.success) toast('Server settings saved', 'Tunnel address ' + r.address + ', UDP port ' + r.listenPort + (r.restarted ? ' — the running server was rebuilt with them.' : ' — they apply the next time the server starts.'), 'success');
      else toast('Save failed', (r && r.error) || 'Could not save the server settings.', 'error');
    } catch (e) { toast('Save failed', e && e.message ? e.message : 'Could not save the server settings.', 'error'); }
    await loadWireGuard();
  });
  /* Server export/import (JSON): the export is the connection
     detail only — endpoint host, port, tunnel address — never the
     public key (it is regenerated when the program is
     reinstalled). Import validates with validateServerSettings,
     including the cross-subnet-change-with-peers refusal. */
  var wgSe = $('wgServerExportBtn');
  if (wgSe) wgSe.addEventListener('click', async function () {
    if (!api || typeof api.wgServerExport !== 'function') return wgMissing();
    try {
      var r2 = await api.wgServerExport();
      if (r2 && r2.success) toast('Server exported', 'Server saved to ' + r2.filePath + ' (endpoint, port and tunnel address — no keys).', 'success');
      else if (r2 && !r2.canceled) toast('Export', (r2 && r2.error) || 'Could not export the server.', 'error');
    } catch (e) { toast('Export', e && e.message ? e.message : 'Could not export the server.', 'error'); }
  });
  var wgSi = $('wgServerImportBtn');
  if (wgSi) wgSi.addEventListener('click', async function () {
    if (!api || typeof api.wgServerImport !== 'function') return wgMissing();
    try {
      var r3 = await api.wgServerImport();
      if (r3 && r3.success) toast('Server imported', 'Endpoint ' + r3.endpoint + ', tunnel address ' + r3.address + ', UDP port ' + r3.listenPort + (r3.restarted ? ' — the running server was rebuilt with them.' : ' — they apply the next time the server starts.'), 'success');
      else if (r3 && !r3.canceled) toast('Import', (r3 && r3.error) || 'Could not import the server.', 'error');
    } catch (e) { toast('Import', e && e.message ? e.message : 'Could not import the server.', 'error'); }
    await loadWireGuard();
  });
  var wgPa = $('wgPeerAddBtn');
  if (wgPa) wgPa.addEventListener('click', async function () {
    if (!api || typeof api.wgAddPeer !== 'function') return wgMissing();
    var key = ($('wgPeerKey') || {}).value || '';
    var host = ($('wgPeerHost') || {}).value || '';
    var port = ($('wgPeerPort') || {}).value || '';
    try {
      var r = await api.wgAddPeer({ publicKey: key, endpointHost: host, endpointPort: port });
      if (r && r.success) {
        toast('Peer added', r.peer.name + ' got tunnel address ' + r.peer.tunnelIp + (r.liveApplied === false && r.liveError ? ' (saved, but the running tunnel did not pick it up: ' + r.liveError + ')' : '') + '.', 'success');
        var k = $('wgPeerKey'); if (k) k.value = '';
        var h = $('wgPeerHost'); if (h) h.value = '';
        var pt = $('wgPeerPort'); if (pt) pt.value = '51820';
      } else toast('Add failed', (r && r.error) || 'Could not add the peer.', 'error');
    } catch (e) { toast('Add failed', e && e.message ? e.message : 'Could not add the peer.', 'error'); }
    await loadWireGuard();
  });
  var wgCk = $('wgClientKeyCopyBtn');
  if (wgCk) wgCk.addEventListener('click', async function () {
    var ck = $('wgClientKey');
    if (!ck || !ck.textContent || ck.textContent === '—') { toast('Nothing to copy', 'Your public key will show here once AmneziaWG is installed.', 'error'); return; }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(ck.textContent);
      else { var ta = document.createElement('textarea'); ta.value = ck.textContent; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }
      toast('Copied', 'Your public key is on the clipboard.', 'success');
    } catch (e) { toast('Copy failed', 'Select the key and copy it by hand.', 'error'); }
  });
  var wgCb = $('wgClientBtn');
  if (wgCb) wgCb.addEventListener('click', async function () {
    if (!api || typeof api.wgConnect !== 'function' || typeof api.wgDisconnect !== 'function') return wgMissing();
    if (wgBusy) return;
    wgBusy = true; wgCb.disabled = true; wgCb.textContent = 'Working…';
    try {
      if (wgStatusCache && wgStatusCache.clientRunning) {
        var d = await api.wgDisconnect();
        if (d && d.success) toast('WireGuard', 'Disconnected.', 'success');
        else toast('WireGuard error', (d && d.error) || 'Could not disconnect.', 'error');
      } else {
        var pasted = (($('wgImportText') || {}).value || '').trim();
        var r;
        if (pasted) {
          r = await api.wgConnect({ confText: pasted });
          if (r && r.success) { var it = $('wgImportText'); if (it) it.value = ''; }
        } else if ((($('wgClientServerKey') || {}).value || '').trim() && (($('wgClientEndpoint') || {}).value || '').trim()) {
          r = await api.wgConnect({
            serverPublicKey: $('wgClientServerKey').value,
            endpoint: $('wgClientEndpoint').value,
            tunnelIp: $('wgClientTunnelIp').value,
            fullTunnel: $('wgFullTunnel') ? $('wgFullTunnel').checked : false,
          });
        } else if (wgStatusCache && wgStatusCache.client) {
          r = await api.wgConnect({ reconnect: true });
        } else {
          toast('Nothing to connect with', 'Paste a config, or type the server details first.', 'error');
          wgBusy = false; wgCb.disabled = false; await loadWireGuard();
          return;
        }
        if (r && r.success) toast('WireGuard', 'Connected as ' + (r.tunnelIp || 'a client') + '.', 'success');
        else toast('WireGuard error', (r && r.error) || 'Could not connect.', 'error');
      }
    } catch (e) { toast('WireGuard error', e && e.message ? e.message : 'Could not change the connection.', 'error'); }
    finally { wgBusy = false; wgCb.disabled = false; await loadWireGuard(); }
  });
  var wgIm = $('wgImportBtn');
  if (wgIm) wgIm.addEventListener('click', async function () {
    if (!api || typeof api.showOpenDialog !== 'function' || typeof api.readFile !== 'function' || typeof api.wgImportConf !== 'function') return wgMissing();
    try {
      var pick = await api.showOpenDialog({ properties: ['openFile'], filters: [{ name: 'WireGuard config', extensions: ['conf'] }] });
      if (!pick || pick.canceled || !pick.filePaths || !pick.filePaths.length) return;
      var text = await api.readFile(pick.filePaths[0]);
      var r = await api.wgImportConf({ confText: text });
      if (r && r.success) {
        var it = $('wgImportText'); if (it) it.value = text;
        var s = r.summary || {};
        toast('Config imported', 'Server ' + (s.endpoint || 'unknown') + ', tunnel address ' + (s.address || 'unknown') + ' — press Connect.', 'success');
      } else toast('Import failed', (r && r.error) || 'Could not read that config file.', 'error');
    } catch (e) { toast('Import failed', e && e.message ? e.message : 'Could not read that config file.', 'error'); }
  });
  var wgIt = $('wgImportTextBtn');
  if (wgIt) wgIt.addEventListener('click', async function () {
    if (!api || typeof api.wgImportConf !== 'function') return wgMissing();
    var text = (($('wgImportText') || {}).value || '').trim();
    if (!text) { toast('Nothing to import', 'Paste a config first.', 'error'); return; }
    try {
      var r = await api.wgImportConf({ confText: text });
      if (r && r.success) {
        var s = r.summary || {};
        toast('Config imported', 'Server ' + (s.endpoint || 'unknown') + ', tunnel address ' + (s.address || 'unknown') + ' — press Connect.', 'success');
      } else toast('Import failed', (r && r.error) || 'Could not read that config file.', 'error');
    } catch (e) { toast('Import failed', e && e.message ? e.message : 'Could not read that config file.', 'error'); }
  });
  // Cloud join — client side: send a join request through a saved
  // Cloud server, then poll every 5s until the server approves (the
  // client connects by itself) or the request ends. One outstanding
  // request at a time; the Send button is disabled while waiting.
  var wgJs = $('wgJoinSendBtn');
  if (wgJs) wgJs.addEventListener('click', async function () {
    if (!api || typeof api.wgCloudJoinRequest !== 'function') return wgMissing();
    if (wgJoinPending) return;
    var serverId = ($('wgJoinServer') || {}).value || '';
    var deviceName = (($('wgJoinDeviceName') || {}).value || '').trim();
    if (!serverId) { toast('No Cloud server', 'Add a Cloud server in the Cloud module first.', 'error'); return; }
    if (!deviceName) { toast('Device name needed', 'Give this device a name first.', 'error'); return; }
    wgJs.disabled = true;
    try {
      var r = await api.wgCloudJoinRequest({ serverId: serverId, deviceName: deviceName });
      if (r && r.success) {
        wgJoinPending = { requestId: r.requestId, serverId: serverId, deviceName: r.deviceName };
        wgJoinSetStatus('Waiting for approval on the server — ' + r.deviceName + '…');
        wgJoinStartPolling();
        toast('Join request sent', 'Waiting for approval on the server.', 'success');
      } else toast('Join request failed', (r && r.error) || 'Could not send the join request.', 'error');
    } catch (e) { toast('Join request failed', e && e.message ? e.message : 'Could not send the join request.', 'error'); }
    finally { wgJs.disabled = !!wgJoinPending; }
  });
  var wgJc = $('wgJoinCancelBtn');
  if (wgJc) wgJc.addEventListener('click', async function () {
    if (!wgJoinPending) return;
    var reqId = wgJoinPending.requestId;
    wgJoinClearPending();
    try {
      if (api && typeof api.wgCloudJoinCancel === 'function') await api.wgCloudJoinCancel({ requestId: reqId });
    } catch (e) { /* the local request is already dropped */ }
    toast('Join request cancelled', 'No request is waiting any more.', 'success');
  });

    document.querySelectorAll('[data-module-enter]').forEach(function (card) {
      card.addEventListener('click', function () { setModule(card.getAttribute('data-module-enter')); });
    });
    var tbb = $('topBackBtn');
    if (tbb) tbb.addEventListener('click', goBack);

    loadSettings().then(function () { loadJobs(); checkVaultOnStartup(); refreshVaultStatus(); });
    showView('modules');
  });
})();
