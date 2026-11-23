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
  function showView(name) {
    var dash = $('view-dashboard'); var jobsView = $('view-jobs');
    if (dash) dash.style.display = name === 'jobs' ? 'none' : '';
    if (jobsView) jobsView.style.display = name === 'jobs' ? '' : 'none';
    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
    var btn = document.querySelector('[data-nav="' + name + '"]');
    if (btn) btn.classList.add('active');
    if (name === 'jobs') renderJobsView();
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
    ['refreshBtn'].forEach(function (id) {
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
    var stop = simulateProgress();
    try {
      var result = incremental && typeof api.runIncrementalBackup === 'function'
        ? await api.runIncrementalBackup(cfg)
        : await api.runFullBackup(cfg);
      stop();
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
      });
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

    loadSettings().then(function () { loadJobs(); checkVaultOnStartup(); refreshVaultStatus(); });
  });
})();
