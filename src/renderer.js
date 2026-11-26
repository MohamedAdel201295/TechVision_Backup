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
  // Signatures of what the Logs view currently shows. The 10s
  // auto-refresh re-renders the same data most of the time — when the
  // signature matches, the DOM is left completely alone so the view
  // never flashes. (Same pattern as the Cloud file-list poller.)
  var lastLogsSig = '';
  var lastFullLogSig = '';

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
  // opts: { title, yesLabel, noLabel } — the labels are restored to
  // the delete-all defaults when the dialog closes, so callers that
  // do not pass opts are unaffected.
  function askConfirm(message, onYes, opts) {
    var modal = $('confirmModal'); var back = $('confirmBackdrop');
    if (!modal) { if (window.confirm(message)) onYes(); return; }
    $('confirmText').textContent = message;
    if (opts && opts.title) $('confirmTitle').textContent = opts.title;
    if (opts && opts.yesLabel) $('confirmYes').textContent = opts.yesLabel;
    if (opts && opts.noLabel) $('confirmNo').textContent = opts.noLabel;
    confirmCallback = onYes;
    modal.style.display = 'block';
    if (back) back.classList.add('show');
  }
  function closeConfirm() {
    var modal = $('confirmModal'); var back = $('confirmBackdrop');
    if (modal) modal.style.display = 'none';
    if (back) back.classList.remove('show');
    $('confirmTitle').textContent = 'Are you sure?';
    $('confirmYes').textContent = 'Yes, delete all';
    $('confirmNo').textContent = 'No, keep it';
    confirmCallback = null;
  }

  /* ---------- dashboard 01: stats, status, recent, storage ---------- */
  /* Time + day split out of formatDashboardTime: the LAST BACKUP stat
     card is narrow, and "Today, 10:44 AM" clipped even at 17px. The
     card shows just the time, and the day + type move to the sub
     line — short, always fully visible. */
  function formatTimeOnly(v) {
    if (!v) return '—';
    var d = v instanceof Date ? v : new Date(v);
    if (isNaN(d.getTime())) return safeStr(v);
    var h = d.getHours(); var ampm = h >= 12 ? 'PM' : 'AM'; var h12 = h % 12; if (h12 === 0) h12 = 12;
    return h12 + ':' + String(d.getMinutes()).padStart(2, '0') + ' ' + ampm;
  }
  function formatDayWord(v) {
    if (!v) return '';
    var d = v instanceof Date ? v : new Date(v);
    if (isNaN(d.getTime())) return '';
    var now = new Date();
    var sameDay = function (a, b) { return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate(); };
    var y = new Date(now); y.setDate(y.getDate() - 1);
    if (sameDay(d, now)) return 'Today';
    if (sameDay(d, y)) return 'Yesterday';
    var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
  }
  function formatDashboardTime(v) {
    if (!v) return '—';
    var d = v instanceof Date ? v : new Date(v);
    if (isNaN(d.getTime())) return safeStr(v);
    return formatDayWord(v) + ', ' + formatTimeOnly(v);
  }
  function formatHMS(sec) {
    var n = Math.max(0, Math.round(safeNum(sec, 0)));
    var h = Math.floor(n / 3600), m = Math.floor((n % 3600) / 60), s = n % 60;
    var p = function (x) { return String(x).padStart(2, '0'); };
    return p(h) + ':' + p(m) + ':' + p(s);
  }
  function lastCompletedRun(list) {
    var last = null;
    list.forEach(function (j) {
      if (j.status !== 'COMPLETED') return;
      var d = j.timestamp ? new Date(j.timestamp) : null;
      if (d && !isNaN(d.getTime()) && (!last || d > new Date(last.timestamp))) last = j;
    });
    return last;
  }
  function renderStats() {
    var list = jobs.filter(function (j) { return j.type !== 'TEMPLATE'; });
    var seven = new Date(); seven.setDate(seven.getDate() - 7);
    var recent = list.filter(function (j) { var d = j.timestamp ? new Date(j.timestamp) : null; return d && !isNaN(d.getTime()) && d >= seven; });
    var ok = recent.filter(function (j) { return j.status === 'COMPLETED'; });
    var bad = recent.filter(function (j) { return j.status === 'FAILED'; });
    var active = list.filter(function (j) { var s = j.schedule || (j.raw && j.raw.schedule); return s && s.enabled; }).length;
    var set = function (id, v) { var el = $(id); if (el) el.textContent = v; };
    set('dashTotalJobs', String(list.length));
    set('dashTotalJobsSub', active ? active + ' Active' : (list.length ? 'No schedules' : 'No jobs yet'));
    set('dashSuccessJobs', String(ok.length));
    set('dashFailedJobs', String(bad.length));
    var last = lastCompletedRun(list);
    set('dashLastBackup', last ? formatTimeOnly(last.timestamp) : '—');
    set('dashLastBackupSub', last ? formatDayWord(last.timestamp) + ' · ' + (last.type === 'INCREMENTAL' ? 'Incremental' : 'Full') : 'No backups yet');
    renderDashboardStatus(list, bad, last);
    renderDashboardRecent(list);
  }
  function renderDashboardStatus(list, bad, last) {
    var banner = $('dashBanner'); if (!banner) return;
    var title = $('dashBannerTitle'), sub = $('dashBannerSub'), ico = $('dashBannerIco');
    banner.classList.remove('warn', 'idle');
    if (!list.length) {
      banner.classList.add('idle');
      if (ico) ico.textContent = 'ⓘ';
      if (title) title.textContent = 'No backups yet';
      if (sub) sub.textContent = 'Create your first backup job to protect your files.';
    } else if (bad.length) {
      banner.classList.add('warn');
      if (ico) ico.textContent = '!';
      if (title) title.textContent = 'Attention needed';
      if (sub) sub.textContent = bad.length + (bad.length === 1 ? ' job failed' : ' jobs failed') + ' in the last 7 days — check the Jobs page.';
    } else {
      if (ico) ico.textContent = '✓';
      if (title) title.textContent = 'System Protected';
      if (sub) sub.textContent = 'All scheduled backups are running normally.';
    }
    var best = null, bestDate = null;
    list.forEach(function (j) {
      var d = nextRunDate(j);
      if (d && (!bestDate || d < bestDate)) { bestDate = d; best = j; }
    });
    var set = function (id, v) { var el = $(id); if (el) el.textContent = v; };
    set('dashNextRun', bestDate ? formatDashboardTime(bestDate) : '—');
    set('dashNextRunSub', best ? best.name + ' – ' + (best.type === 'INCREMENTAL' ? 'Incremental' : 'Full') : 'No scheduled jobs');
    set('dashLastSize', last ? formatBytes(last.size) : '—');
    set('dashLastDuration', last ? formatHMS(last.duration) : '—');
  }
  function renderDashboardRecent(list) {
    var body = $('dashRecentBody'); if (!body) return;
    var sorted = list.slice().sort(function (a, b) { return new Date(b.timestamp || 0) - new Date(a.timestamp || 0); }).slice(0, 5);
    var empty = $('dashRecentEmpty');
    if (empty) empty.style.display = sorted.length ? 'none' : 'block';
    body.innerHTML = '';
    sorted.forEach(function (job) {
      var tr = document.createElement('tr');
      var typePill = '<span class="pill ' + (job.type === 'INCREMENTAL' ? 'pill-incremental' : 'pill-full') + '">' + (job.type === 'INCREMENTAL' ? 'Incremental' : 'Full') + '</span>';
      var statusPill = '<span class="pill ' + pillClass(job.status, job.type) + '">' + escapeHtml(job.status) + '</span>';
      tr.innerHTML = '<td class="job-name-cell"></td><td>' + typePill + '</td><td>' + statusPill + '</td><td></td><td></td><td></td>';
      tr.querySelector('.job-name-cell').textContent = job.name;
      var tds = tr.querySelectorAll('td');
      tds[3].textContent = formatBytes(job.size);
      tds[4].textContent = formatHMS(job.duration);
      tds[5].textContent = formatDashboardTime(job.timestamp);
      tr.addEventListener('click', function () { openDrawer(job); });
      body.appendChild(tr);
    });
  }
  /* Storage donut: usage of the drive holding the latest backup's
     destination. Re-reads only when the destination changes, or when
     Check Storage is pressed (force). A failed read shows "—", never
     a fake number. */
  var storageDest = '';
  async function refreshStorageCard(force) {
    var pctEl = $('dashStoragePct'); if (!pctEl) return;
    var last = lastCompletedRun(jobs.filter(function (j) { return j.type !== 'TEMPLATE'; }));
    var dest = last ? (last.destination || '') : '';
    var arc = $('dashDonutArc');
    var set = function (id, v) { var el = $(id); if (el) el.textContent = v; };
    if (!dest) {
      set('dashStoragePct', '—');
      set('dashUsed', '—'); set('dashFree', '—'); set('dashTotal', '—');
      set('dashStorageDrive', 'No backups yet — run a job to see storage.');
      if (arc) arc.setAttribute('stroke-dasharray', '0 339.292');
      storageDest = '';
      return;
    }
    if (!force && dest === storageDest) return;
    storageDest = dest;
    set('dashStorageDrive', dest);
    if (!api || typeof api.getDriveUsage !== 'function') return;
    try {
      var r = await api.getDriveUsage(dest);
      if (!r || !r.success) {
        set('dashStoragePct', '—');
        set('dashUsed', '—'); set('dashFree', '—'); set('dashTotal', '—');
        set('dashStorageDrive', dest + ' — could not read drive usage.');
        if (arc) arc.setAttribute('stroke-dasharray', '0 339.292');
        return;
      }
      var total = r.total, free = r.free, used = Math.max(0, total - free);
      var pct = total > 0 ? Math.round((used / total) * 100) : 0;
      var C = 339.292;
      if (arc) arc.setAttribute('stroke-dasharray', (pct / 100 * C).toFixed(1) + ' ' + C);
      set('dashStoragePct', pct + '%');
      set('dashUsed', formatBytes(used));
      set('dashFree', formatBytes(free));
      set('dashTotal', formatBytes(total));
    } catch (e) {
      set('dashStoragePct', '—');
    }
  }

  /* ---------- history list ---------- */
  function pillClass(status, type) {
    if (status === 'COMPLETED') return 'pill-completed';
    if (status === 'RUNNING') return 'pill-running';
    if (status === 'FAILED') return 'pill-failed';
    if (status === 'TEMPLATE' || type === 'TEMPLATE') return 'pill-template';
    return 'pill-pending';
  }
  /* ---------- history list (Jobs page, step 4) ---------- */

  /* ---------- views: Dashboard / Jobs ---------- */
  /* ---------- modules: Backup / Cloud / VPN / WireGuard ----------
     The sidebar shows every module at once, grouped with section
     labels (Dashboard / Backup / Cloud / VPN / WireGuard / System).
     There is no module chooser screen: the app opens on the Dashboard
     and the sidebar is the only navigation. Switching views only swaps
     the visible view; going back to Backup returns to the last backup
     view instead of always resetting to Dashboard. */
  var currentModule = 'backup';
  var lastBackupView = 'dashboard'; // the view Back / closing Settings returns to (any module)
  var currentView = 'dashboard'; // the view currently shown in the main area
  var wizardReturnView = 'dashboard'; // the view the wizard / restore returns to on Back or Cancel

  function applyModuleUI(mod) {
    currentModule = mod;
    /* All nav groups stay visible: the sidebar lists every module. */
    ['navGroupBackup', 'navGroupCloud', 'navGroupVpn', 'navGroupWireguard'].forEach(function (id) { var g = $(id); if (g) g.style.display = ''; });
  }

  function setModule(mod) {
    applyModuleUI(mod);
    if (mod === 'backup') showView(lastBackupView || 'dashboard');
    else if (mod === 'cloud') showView('cloud');
    else if (mod === 'vpn') showView('vpn');
    else if (mod === 'wireguard') showView('wireguard');
  }

  function syncCloudNav() {
    document.querySelectorAll('[data-nav="cloud-server"], [data-nav="cloud-client"], [data-nav="cloud-mapdrive"]').forEach(function (b) { b.classList.remove('active'); });
    if (cloudPanel === 'server' || cloudPanel === 'client' || cloudPanel === 'mapdrive') {
      var btn = document.querySelector('[data-nav="cloud-' + cloudPanel + '"]');
      if (btn) btn.classList.add('active');
    }
    /* The in-view tab bar mirrors the same panel. */
    document.querySelectorAll('[data-cloud-tab]').forEach(function (t) { t.classList.toggle('active', t.getAttribute('data-cloud-tab') === cloudPanel); });
  }

  function setBackTitle(t) { var b = $('backBarTitle'); if (b) b.textContent = t; }
  function setAppTitle(t, s) { var h = $('appTitle'); if (h) h.textContent = t; var p = $('appSubtitle'); if (p) p.textContent = s; }

  /* Back from the very top: from a Server/Client/Map panel back to the
     Cloud home, from anywhere else back to the Dashboard. */
  function goBack() {
    var settingsView = $('view-settings');
    if (settingsView && settingsView.style.display !== 'none') { showView(lastBackupView || 'dashboard'); return; }
    var wizView = $('view-wizard');
    if (wizView && wizView.style.display !== 'none') { showView(wizardReturnView || 'dashboard'); return; }
    var resView = $('view-restore');
    if (resView && resView.style.display !== 'none') { showView(wizardReturnView || 'dashboard'); return; }
    var cloudView = $('view-cloud');
    if (cloudView && cloudView.style.display !== 'none' && (cloudPanel === 'server' || cloudPanel === 'client' || cloudPanel === 'mapdrive')) { showCloudPanel('home'); return; }
    showView('dashboard');
  }

  /* The in-place wizard / restore close by going back — there is no
     separate window any more, so the wizard scripts call this. */
  window.__closeWizardView = function () { showView(wizardReturnView || 'dashboard'); };

  function showView(name) {
    currentView = name;
    var dash = $('view-dashboard'); var jobsView = $('view-jobs'); var logsView = $('view-logs'); var cloudView = $('view-cloud');
    var vpnView = $('view-vpn');
    var wgView = $('view-wireguard');
    var settingsView = $('view-settings');
    var wizView = $('view-wizard');
    var resView = $('view-restore');
    if (dash) dash.style.display = name === 'dashboard' ? '' : 'none';
    if (jobsView) jobsView.style.display = name === 'jobs' ? '' : 'none';
    if (logsView) logsView.style.display = name === 'logs' ? '' : 'none';
    if (cloudView) cloudView.style.display = name === 'cloud' ? '' : 'none';
    if (vpnView) vpnView.style.display = name === 'vpn' ? '' : 'none';
    if (wgView) wgView.style.display = name === 'wireguard' ? '' : 'none';
    if (settingsView) settingsView.style.display = name === 'settings' ? '' : 'none';
    if (wizView) wizView.style.display = name === 'wizard' ? '' : 'none';
    if (resView) resView.style.display = name === 'restore' ? '' : 'none';
    /* One refresh per module, at the top — the same ⟳ icon-button
       pattern as the Tailscale one, shown only while its module is
       active. The settings gear is always visible (the sidebar has
       no Settings item — the gear at the top right is the only way
       in, from any module). */
    var isBackup = name === 'dashboard' || name === 'jobs' || name === 'logs' || name === 'wizard' || name === 'restore';
    var gb2 = $('settingsBtn'); if (gb2) gb2.style.display = '';
    var brb = $('backupTopRefreshBtn'); if (brb) brb.style.display = isBackup ? '' : 'none';
    var crb2 = $('cloudTopRefreshBtn'); if (crb2) crb2.style.display = name === 'cloud' ? '' : 'none';
    var tr = $('vpnTopRefreshBtn'); if (tr) tr.style.display = name === 'vpn' ? '' : 'none';
    var wrb = $('wgTopRefreshBtn'); if (wrb) wrb.style.display = name === 'wireguard' ? '' : 'none';
    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
    var btn = document.querySelector('[data-nav="' + name + '"]');
    /* Inside Cloud the active item is the open panel, not Overview:
       syncCloudNav() marks it (called by showView('cloud') below and
       by showCloudPanel). Only mark Overview when the home panel is open. */
    if (btn && !(name === 'cloud' && (cloudPanel === 'server' || cloudPanel === 'client' || cloudPanel === 'mapdrive'))) btn.classList.add('active');
    /* The wizard / restore have no data-nav item — their sidebar
       buttons are #navNewJob / #navRestore, marked active here. */
    if (name === 'wizard') { var nw = $('navNewJob'); if (nw) nw.classList.add('active'); }
    if (name === 'restore') { var nr = $('navRestore'); if (nr) nr.classList.add('active'); }
    /* Groups open ONLY when the user clicks the group header — never
       on navigation. A view reached from elsewhere (Back button, jump
       button, Quick Action) shows in the main area on the right while
       the sidebar stays exactly as the user left it. */
    if (name === 'jobs') renderJobsView();
    if (name === 'logs') { renderLogs(currentLogTab); startLogsAutoRefresh(); }
    else stopLogsAutoRefresh();
    /* The dashboard has nowhere to go back to — hiding its back bar
       buys the tallest page ~48px so the whole page fits. The wizard
       and restore have their own Cancel button that returns to the
       origin view (the same destination as Back), so their back bar
       is redundant too — hiding it buys the wizard card the same
       ~30px, which is what finally lets the tallest steps fit with
       no scroll at all (round 2 #5). */
    var bb = $('backBar'); if (bb) bb.style.display = (name === 'dashboard' || name === 'wizard' || name === 'restore') ? 'none' : '';
    /* The top-bar subtitle is redundant — every view carries its own
       heading and description in the page — so it stays hidden and
       every page gains ~15px of room. */
    var asub = $('appSubtitle'); if (asub) asub.style.display = 'none';
    if (name === 'dashboard' || name === 'jobs' || name === 'logs') {
      lastBackupView = name; applyModuleUI('backup');
      setBackTitle('Backup');
      setAppTitle('Backup Dashboard', 'Manage backups, monitor jobs, and protect your data.');
    }
    if (name === 'settings') {
      /* A full page, not a drawer: it belongs to the Backup module
         but is NOT a lastBackupView — Back returns to the view it was
         opened from, and no sidebar item is ever active here. */
      applyModuleUI('backup');
      setBackTitle('Settings');
      setAppTitle('Settings', 'Your preferences for TechVision Backup.');
    }
    if (name === 'wizard') {
      /* In-place wizard: it belongs to the Backup module but is NOT
         a lastBackupView — Back / Cancel returns to the view it was
         opened from (wizardReturnView). */
      applyModuleUI('backup');
      setBackTitle('New Backup Job');
      setAppTitle('New Backup Job', 'Five quick steps — pick folders, options and encryption.');
    }
    if (name === 'restore') {
      /* Same rule as the wizard: Back / Cancel returns to
         wizardReturnView, never to the dashboard unconditionally. */
      applyModuleUI('backup');
      setBackTitle('Restore');
      setAppTitle('Restore Backup', 'Pick a .zip backup file and a folder to restore it into.');
    }
    if (name === 'cloud') {
      lastBackupView = name;
      applyModuleUI('cloud'); syncCloudNav();
      setBackTitle(cloudPanel === 'server' ? 'Cloud — Server' : cloudPanel === 'client' ? 'Cloud — Client' : cloudPanel === 'mapdrive' ? 'Cloud — Map network' : 'Cloud');
      setAppTitle('TechVision Cloud', 'Your own remote drive — share a folder or open one, encrypted.');
      loadCloud();
    }
    if (name === 'vpn') {
      lastBackupView = name;
      applyModuleUI('vpn');
      setBackTitle('VPN');
      setAppTitle('TechVision Tailscale VPN', 'Your private network — every device, anywhere, as if it were home.');
      loadVpn();
    }
    if (name === 'wireguard') {
      lastBackupView = name;
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
    // Silent background refresh: if the list would look exactly the
    // same, do not touch the DOM at all — no flash, no scroll jump.
    // A tab switch or a new/changed run changes the signature, so
    // those still rebuild.
    var sig = currentLogTab + '|' + items.map(function (it) {
      var r = it.run;
      return (it.job.id || it.job.name) + '|' + (r.timestamp || '') + '|' +
        String(r.status || (r.success ? 'COMPLETED' : 'FAILED')).toUpperCase() + '|' +
        safeNum(r.files, 0) + '|' + (r.size || 0) + '|' + (r.error || '') + '|' + (it.waiting ? 'W' : '');
    }).join('\n');
    if (sig === lastLogsSig) return;
    lastLogsSig = sig;
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
    // Silent background refresh: same filter + same lines means the
    // box already shows exactly this — leave the DOM alone.
    var sig = level + '|' + q + '|' + visible.join('\n');
    if (sig === lastFullLogSig) return;
    lastFullLogSig = sig;
    // Keep the reader's place: only follow the tail when he was
    // already at the bottom; otherwise restore his scroll position
    // instead of yanking him to the end every 10 seconds.
    var atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 4;
    var prevTop = box.scrollTop;
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
    box.scrollTop = atBottom ? box.scrollHeight : prevTop;
  }
  function compressionLabel(job) {
    var c = (job.compression || (job.raw && job.raw.compression) || 'standard').toLowerCase();
    if (c === 'none') return 'No compression — plain files';
    if (c === 'advanced') return 'Advanced — Deflate level 9';
    return 'Standard — Deflate level 6';
  }
  /* ---------- Jobs page 02: table + details panel ---------- */
  var jobsSelectedId = null; // id of the job shown in the details panel
  function selectedJob() {
    if (!jobsSelectedId) return null;
    var found = jobs.filter(function (j) { return j.id === jobsSelectedId; });
    return found.length ? found[0] : null;
  }
  function renderJobsView() {
    var body = $('jobsTableBody');
    if (!body) return;
    /* Every job, including never-run templates: a template is a real
       job with no runs yet, not a history entry to hide. */
    var list = jobs.slice();
    var set = function (id, v) { var el = $(id); if (el) el.textContent = v; };
    set('jobsChipTotal', String(list.length));
    set('jobsChipCompleted', String(list.filter(function (j) { return j.status === 'COMPLETED'; }).length));
    set('jobsChipRunning', String(list.filter(function (j) { return j.status === 'RUNNING'; }).length));
    set('jobsChipFailed', String(list.filter(function (j) { return j.status === 'FAILED'; }).length));
    var q = ($('jobsSearchInput') ? $('jobsSearchInput').value : '').trim().toLowerCase();
    var sf = $('jobsStatusFilter') ? $('jobsStatusFilter').value : 'all';
    var sort = $('jobsSortSelect') ? $('jobsSortSelect').value : 'newest';
    var visible = list.filter(function (j) {
      if (q && j.name.toLowerCase().indexOf(q) === -1 && (j.source || '').toLowerCase().indexOf(q) === -1) return false;
      if (sf !== 'all' && j.status !== sf) return false;
      return true;
    });
    visible.sort(function (a, b) {
      if (sort === 'name') return a.name.localeCompare(b.name);
      /* Never-run jobs have no last run: they sort last in "newest". */
      var ts = function (j) { return j.runs && j.runs.length ? new Date(j.timestamp || 0).getTime() : 0; };
      return sort === 'oldest' ? ts(a) - ts(b) : ts(b) - ts(a);
    });
    var sel = selectedJob();
    if (sel && visible.indexOf(sel) === -1) sel = null;
    if (!sel && visible.length) sel = visible[0];
    jobsSelectedId = sel ? sel.id : null;
    body.innerHTML = '';
    var empty = $('jobsEmptyState');
    if (empty) empty.style.display = list.length === 0 ? 'block' : 'none';
    if (list.length && visible.length === 0) {
      body.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:18px;">No matching jobs — try a different search or filter.</td></tr>';
    }
    visible.forEach(function (job) {
      var tr = document.createElement('tr');
      if (sel && job.id === sel.id) tr.classList.add('selected');
      var sched = job.schedule || (job.raw && job.raw.schedule) || null;
      tr.innerHTML = '<td class="job-name-cell"></td><td></td><td class="jobs-src-cell"></td><td></td><td></td><td></td>';
      tr.querySelector('.job-name-cell').textContent = job.name;
      var tds = tr.querySelectorAll('td');
      tds[1].innerHTML = '<span class="pill ' + (job.type === 'TEMPLATE' ? 'pill-template' : job.type === 'INCREMENTAL' ? 'pill-incremental' : 'pill-full') + '">' + (job.type === 'TEMPLATE' ? 'Template' : job.type === 'INCREMENTAL' ? 'Incremental' : 'Full') + '</span>';
      /* Sources shows just the folder name (full path on hover): the
         full path is in the details panel and would push the Status
         column off-screen. */
      var srcName = job.source ? job.source.replace(/[/\\]+$/, '').split(/[/\\]/).pop() : '—';
      tds[2].textContent = srcName;
      if (job.source) tds[2].title = job.source;
      tds[3].textContent = scheduleLabel(sched) || 'Manual only';
      tds[4].textContent = job.runs && job.runs.length ? formatDate(job.timestamp) : 'Never run';
      tds[5].innerHTML = '<span class="pill ' + pillClass(job.status, job.type) + '">' + escapeHtml(job.status) + '</span>';
      tr.addEventListener('click', function () { jobsSelectedId = job.id; renderJobsView(); });
      body.appendChild(tr);
    });
    renderJobsDetails(sel);
    var dis = !sel;
    ['jobsRunBtn', 'jobsEditBtn', 'jobsDeleteBtn', 'jobsDetailsRun', 'jobsDetailsRestore', 'jobsDetailsEdit'].forEach(function (id) { var b = $(id); if (b) b.disabled = dis; });
  }
  function renderJobsDetails(job) {
    var panel = $('jobsDetails'); if (!panel) return;
    var name = $('jobsDetailsName'), pill = $('jobsDetailsPill');
    var banner = $('jobsDetailsBanner'), bIco = $('jobsDetailsBannerIco'), bTitle = $('jobsDetailsBannerTitle'), bSub = $('jobsDetailsBannerSub');
    var listEl = $('jobsDetailsList'), waitEl = $('jobsDetailsWaiting');
    if (!job) {
      if (name) name.textContent = 'No job selected';
      if (pill) { pill.className = 'pill'; pill.textContent = '—'; }
      if (banner) { banner.classList.remove('warn', 'bad'); banner.classList.add('idle'); }
      if (bIco) bIco.textContent = 'ⓘ';
      if (bTitle) bTitle.textContent = 'No jobs yet';
      if (bSub) bSub.textContent = 'Create your first backup job to protect your files.';
      if (listEl) listEl.innerHTML = '';
      if (waitEl) waitEl.innerHTML = '';
      return;
    }
    if (name) name.textContent = job.name;
    if (pill) { pill.className = 'pill ' + pillClass(job.status, job.type); pill.textContent = job.status; }
    if (banner) {
      banner.classList.remove('warn', 'bad', 'idle');
      if (job.status === 'COMPLETED') {
        if (bIco) bIco.textContent = '✓';
        if (bTitle) bTitle.textContent = 'Last Backup: Completed';
        if (bSub) bSub.textContent = formatDashboardTime(job.timestamp);
      } else if (job.status === 'FAILED') {
        banner.classList.add('bad');
        if (bIco) bIco.textContent = '!';
        if (bTitle) bTitle.textContent = 'Last Backup: Failed';
        if (bSub) bSub.textContent = 'Failed at ' + formatDashboardTime(job.timestamp);
      } else if (job.status === 'RUNNING') {
        banner.classList.add('idle');
        if (bIco) bIco.textContent = '◷';
        if (bTitle) bTitle.textContent = 'Backup running';
        if (bSub) bSub.textContent = 'Started ' + formatDashboardTime(job.timestamp);
      } else {
        banner.classList.add('idle');
        if (bIco) bIco.textContent = 'ⓘ';
        if (bTitle) bTitle.textContent = job.runs && job.runs.length ? 'Last Backup: ' + job.status : 'Never run yet';
        if (bSub) bSub.textContent = job.runs && job.runs.length ? formatDashboardTime(job.timestamp) : 'Run this job to create its first backup.';
      }
    }
    if (listEl) {
      listEl.innerHTML = '';
      var sched = job.schedule || (job.raw && job.raw.schedule) || null;
      var enc = job.encryptionEnabled === true || (job.raw && job.raw.encryptionEnabled === true);
      var rows = [
        ['Backup Type', job.type === 'TEMPLATE' ? '—' : job.type === 'INCREMENTAL' ? 'Incremental' : 'Full'],
        ['Sources', job.source || '—'],
        ['Destination', job.destination || '—'],
        ['Schedule', scheduleLabel(sched) || 'Manual only'],
        ['Next run', nextRunText(job)],
        ['Compression', compressionLabel(job)],
        ['Encryption', enc ? 'Enabled (AES-256)' : 'Off'],
        ['Last Run Result', job.runs && job.runs.length ? job.status + ' — ' + formatDate(job.timestamp) : 'Never run'],
        ['Files Backed Up', job.runs && job.runs.length ? String(job.files) : '—'],
        ['Total Size', job.runs && job.runs.length ? formatBytes(job.size) : '—']
      ];
      rows.forEach(function (r) {
        var div = document.createElement('div');
        var dt = document.createElement('dt'); dt.textContent = r[0];
        var dd = document.createElement('dd'); dd.textContent = r[1]; dd.title = r[1];
        div.appendChild(dt); div.appendChild(dd); listEl.appendChild(div);
      });
    }
    if (waitEl) {
      waitEl.innerHTML = '';
      var w = waitingOf(job);
      if (w) {
        var wdiv = document.createElement('div');
        wdiv.className = 'job-waiting';
        wdiv.textContent = '⏳ Waiting for the ' + (w.which || 'source') + ' drive since ' + formatDate(w.since) + ' — ' + (w.path || '') + (w.label ? ' (volume "' + w.label + '")' : '');
        waitEl.appendChild(wdiv);
      }
    }
  }
  async function deleteSelectedJob() {
    var j = selectedJob();
    if (!j || !api || typeof api.deleteJob !== 'function') return;
    try {
      var res = await api.deleteJob(j.id);
      if (res && res.success) { toast('Job deleted', j.name + ' has been deleted.', 'success'); await refreshJobs(); }
      else toast('Delete failed', (res && res.error) || 'Could not delete job.', 'error');
    } catch (e) { toast('Delete error', e && e.message ? e.message : 'Could not delete job.', 'error'); }
  }

  /* ---------- TechVision Cloud ---------- */
  var cloudCfg = null;           // last cloud-get-config result
  var cloudPanel = 'home';       // 'home' | 'server' | 'client' | 'mapdrive'
  var wgPanel = 'server';        // 'server' | 'nat' — WireGuard tabs
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
      renderCloudOpenMode();
      renderCloudHome();
      if (cloudPanel === 'server') renderCloudServer();
      if (cloudPanel === 'client') renderCloudClientList();
      if (cloudPanel === 'mapdrive') renderMapdrivePanel();
    } catch (e) {
      toast('Cloud', e && e.message ? e.message : 'Could not load Cloud settings.', 'error');
    }
  }

  /* WireGuard tabs (Server / Site-to-Site): one card visible at a
     time, like the Cloud tabs, so each tab fits the window height. */
  function showWgPanel(panel) {
    wgPanel = panel;
    var server = $('wgServerCard'); if (server) server.style.display = panel === 'server' ? '' : 'none';
    var nat = $('wgNatCard'); if (nat) nat.style.display = panel === 'nat' ? '' : 'none';
    document.querySelectorAll('[data-wg-tab]').forEach(function (t) { t.classList.toggle('active', t.getAttribute('data-wg-tab') === panel); });
  }

  function showCloudPanel(panel) {
    cloudPanel = panel;
    var modes = $('cloudModes'); if (modes) modes.style.display = panel === 'home' ? '' : 'none';
    // The "your own remote drive" intro belongs to the Cloud home only —
    // inside Server/Client it is just a repeated sentence above the panel.
    var ht = $('cloudViewHeadText'); if (ht) ht.style.display = panel === 'home' ? '' : 'none';
    var sp = $('cloudServerPanel'); if (sp) sp.style.display = panel === 'server' ? '' : 'none';
    var cp = $('cloudClientPanel'); if (cp) cp.style.display = panel === 'client' ? '' : 'none';
    var mp = $('cloudMapPanel'); if (mp) mp.style.display = panel === 'mapdrive' ? '' : 'none';
    if (panel === 'server') renderCloudServer();
    if (panel === 'mapdrive') renderMapdrivePanel();
    if (panel === 'client') {
      // Open on the kind of server the user actually has: if the
      // current picker mode matches none of the saved servers, switch
      // it to the first server's mode so the list is never empty
      // while servers exist. An explicit picker click still filters
      // strictly to the picked kind.
      var saved = (cloudCfg && cloudCfg.clients) || [];
      if (saved.length) {
        var hasCurrent = saved.some(function (s) { return (s.accessMode || 'normal') === cloudClientAccess; });
        if (!hasCurrent) setClientAccess(saved[0].accessMode || 'normal');
      }
      renderCloudClientList(); if (cloudClientAccess === 'tailscale') populateCloudPeers(); if (cloudClientAccess === 'wireguard') populateCloudWgPeers();
    }
    syncCloudNav();
    if (panel === 'home') {
      var ov = document.querySelector('[data-nav="cloud"]');
      if (ov) ov.classList.add('active');
    }
    setBackTitle(panel === 'server' ? 'Cloud — Server' : panel === 'client' ? 'Cloud — Client' : panel === 'mapdrive' ? 'Cloud — Map network' : 'Cloud');
  }

  function renderCloudHome() {
    if (!cloudCfg) return;
    var s = cloudCfg.server || {};
    var badge = $('cloudServerModeBadge');
    if (badge) {
      badge.textContent = s.running ? 'Running' : 'Stopped';
      badge.className = 'pill ' + (s.running ? 'pill-completed' : 'pill-pending');
    }
    var sp = $('cloudServerModePort'); if (sp) sp.textContent = String(s.port || 8443);
    var su = $('cloudServerModeUsers'); if (su) su.textContent = String((s.users || []).length);
    var cb = $('cloudClientModeBadge');
    if (cb) {
      cb.textContent = cloudConn ? 'Connected' : 'Not connected';
      cb.className = 'pill ' + (cloudConn ? 'pill-completed' : 'pill-pending');
    }
    var ca = $('cloudClientModeAddr'); if (ca) ca.textContent = cloudConn ? (cloudConn.name || '—') : '—';
    var cc = $('cloudClientModeCount'); if (cc) cc.textContent = String(((cloudCfg.clients) || []).length);
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
    var apb = $('cloudClientWgAddPeerBtn'); if (apb) apb.style.display = cloudClientAccess === 'wireguard' ? '' : 'none';
    var pl = $('cloudClientPeerLabel');
    if (pl) pl.textContent = cloudClientAccess === 'wireguard' ? 'Pick a device from your WireGuard tunnel' : 'Pick a device from your Tailscale network';
    var ph2 = $('cloudClientPeerHint');
    if (ph2) ph2.textContent = cloudClientAccess === 'wireguard'
      ? 'Both devices must be on the same WireGuard tunnel — see the WireGuard module.'
      : 'Both devices must be on the same Tailscale network — see the VPN module.';
    if (cloudClientAccess === 'tailscale') populateCloudPeers();
    if (cloudClientAccess === 'wireguard') populateCloudWgPeers();
    renderCloudClientList();
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
    var fp = $('cloudServerFactPort'); if (fp) fp.textContent = String(s.port || 8443);
    var fu = $('cloudServerFactUsers'); if (fu) fu.textContent = String((s.users || []).length);
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
        meta.title = u.root;
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
        body.appendChild(h); body.appendChild(meta);
        card.appendChild(body); card.appendChild(acts);
        list.appendChild(card);
      });
    }
  }

  function renderCloudClientList() {
    if (!cloudCfg) return;
    var list = $('cloudServersList');
    if (!list) return;
    list.innerHTML = '';
    // The list follows the Connection picker above it: pick WireGuard
    // and the Tailscale servers hide (and vice versa) — the picker
    // chooses which kind of server this panel is about, so a server
    // of another kind must not sit above the form for this kind.
    var mode = cloudClientAccess || 'normal';
    var servers = (cloudCfg.clients || []).filter(function (srv) {
      return (srv.accessMode || 'normal') === mode;
    });
    if (!servers.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state'; empty.style.display = '';
      var label = mode === 'wireguard' ? 'No WireGuard servers yet' : mode === 'tailscale' ? 'No Tailscale servers yet' : 'No servers yet';
      empty.innerHTML = '<div class="big">☁️</div><h3>' + label + '</h3><p>Add the server you want to open below.</p>';
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

  /* ---------- Map network drive ---------- */
  // The letter the connected server is mapped to, if any — cached
  // per connection so a double-click does not run `net use` every
  // time. Invalidated on Map/Disconnect and when the connection
  // changes. A stale cache only ever falls back to the temp open.
  var cloudMapLetterCache = { serverId: null, letter: null, at: 0 };
  var cloudMapCurrentLetter = null; // letter of the mapping shown in the panel, if any
  function cloudMapInvalidateCache() { cloudMapLetterCache = { serverId: null, letter: null, at: 0 }; }

  async function cloudMapLetterFor(serverId) {
    if (!serverId || !api || typeof api.cloudMapdriveStatus !== 'function') return null;
    if (cloudMapLetterCache.serverId === serverId && Date.now() - cloudMapLetterCache.at < 30000) return cloudMapLetterCache.letter;
    var letter = null;
    try {
      var r = await api.cloudMapdriveStatus();
      if (r && r.success) {
        var m = (r.mappings || []).find(function (x) { return x.serverId === serverId && x.status === 'mapped'; });
        if (m) letter = m.letter;
      }
    } catch (e) {}
    cloudMapLetterCache = { serverId: serverId, letter: letter, at: Date.now() };
    return letter;
  }

  // The Map network panel: server picker (saved servers), letter
  // picker (free letters, Z first), Map / Disconnect / Open in
  // Explorer, status line, reconnect checkbox. Refreshes every time
  // the panel opens and after every Map/Disconnect.
  async function renderMapdrivePanel() {
    var sel = $('cloudMapServer');
    var letterSel = $('cloudMapLetter');
    var statusEl = $('cloudMapStatus');
    var mapBtn = $('cloudMapBtn');
    var disBtn = $('cloudMapDisconnectBtn');
    var expBtn = $('cloudMapExplorerBtn');
    var recBox = $('cloudMapReconnect');
    var recHint = $('cloudMapReconnectHint');
    var srvHint = $('cloudMapServerHint');
    if (!sel || !letterSel || !statusEl) return;
    var servers = (cloudCfg && cloudCfg.clients) || [];
    var prevServer = sel.value;
    sel.innerHTML = '';
    if (!servers.length) {
      var o0 = document.createElement('option'); o0.value = ''; o0.textContent = 'No servers yet — add one in the Client tab first.';
      sel.appendChild(o0);
    }
    servers.forEach(function (srv) {
      var o = document.createElement('option');
      o.value = srv.id;
      o.textContent = srv.name + ' — ' + srv.host + ':' + srv.port + ' (' + (srv.accessMode === 'tailscale' ? 'Tailscale' : srv.accessMode === 'wireguard' ? 'WireGuard' : 'Normal') + ')';
      sel.appendChild(o);
    });
    if (prevServer) { for (var i = 0; i < sel.options.length; i++) if (sel.options[i].value === prevServer) { sel.value = prevServer; break; } }
    var serverId = sel.value || (servers[0] && servers[0].id) || '';
    if (!servers.length) {
      cloudMapCurrentLetter = null;
      if (mapBtn) mapBtn.disabled = true;
      if (disBtn) disBtn.style.display = 'none';
      if (expBtn) expBtn.style.display = 'none';
      statusEl.textContent = 'No servers yet — add one in the Client tab first.';
      return;
    }
    if (mapBtn) mapBtn.disabled = false;
    var status = null;
    try {
      if (api && typeof api.cloudMapdriveStatus === 'function') status = await api.cloudMapdriveStatus();
    } catch (e) { status = null; }
    if (!status || !status.success) {
      cloudMapCurrentLetter = null;
      statusEl.textContent = (status && status.error) || 'Mapping a network drive is available on Windows only.';
      if (disBtn) disBtn.style.display = 'none';
      if (expBtn) expBtn.style.display = 'none';
      return;
    }
    var letters = (status.freeLetters && status.freeLetters.length) ? status.freeLetters : ['Z'];
    var prevLetter = letterSel.value;
    letterSel.innerHTML = '';
    letters.forEach(function (l) {
      var o = document.createElement('option'); o.value = l; o.textContent = l + ':';
      letterSel.appendChild(o);
    });
    var mapping = (status.mappings || []).find(function (x) { return x.serverId === serverId; });
    if (mapping && mapping.status === 'mapped') {
      // The mapped letter is in use, so it is not among the free
      // letters — show it selected at the top so the picker and the
      // Explorer button agree on which drive this is.
      var mo = document.createElement('option'); mo.value = mapping.letter; mo.textContent = mapping.letter + ': — mapped';
      letterSel.insertBefore(mo, letterSel.firstChild);
      letterSel.value = mapping.letter;
      cloudMapCurrentLetter = mapping.letter;
      if (disBtn) disBtn.style.display = '';
      if (expBtn) expBtn.style.display = '';
      statusEl.textContent = 'Mapped: ' + mapping.letter + ': → ' + (mapping.name || mapping.host) + ' (' + mapping.host + ':' + mapping.port + ')';
    } else if (mapping && mapping.status === 'password-needed') {
      cloudMapCurrentLetter = null;
      if (disBtn) disBtn.style.display = 'none';
      if (expBtn) expBtn.style.display = 'none';
      statusEl.textContent = 'Not mapped — save the server password in the Client tab first (connect once with the password, and it is saved on this device).';
    } else if (mapping && mapping.status === 'error') {
      cloudMapCurrentLetter = null;
      if (disBtn) disBtn.style.display = 'none';
      if (expBtn) expBtn.style.display = 'none';
      statusEl.textContent = 'Not mapped — ' + (mapping.error || 'could not check the drive.');
    } else {
      cloudMapCurrentLetter = null;
      if (disBtn) disBtn.style.display = 'none';
      if (expBtn) expBtn.style.display = 'none';
      statusEl.textContent = 'Not mapped';
    }
    if (prevLetter && !mapping) { for (var j = 0; j < letterSel.options.length; j++) if (letterSel.options[j].value === prevLetter) { letterSel.value = prevLetter; break; } }
    var chosen = servers.find(function (s) { return s.id === serverId; });
    var hasPassword = !!(chosen && chosen.hasPassword);
    if (recBox) recBox.disabled = !hasPassword;
    if (recHint) recHint.textContent = hasPassword
      ? 'Maps this drive again every time the app opens.'
      : 'Save the server password in the Client tab to reconnect automatically.';
    if (srvHint) srvHint.textContent = hasPassword ? 'Pick a saved server from the Client tab.' : 'This server has no saved password — connect once in the Client tab first.';
  }

  async function cloudMapDriveAction() {
    var sel = $('cloudMapServer');
    var letterSel = $('cloudMapLetter');
    var recBox = $('cloudMapReconnect');
    var serverId = sel ? sel.value : '';
    if (!serverId) { toast('No server', 'Add a server in the Client tab first.', 'error'); return; }
    if (!api || typeof api.cloudMapdriveMap !== 'function') return cloudMissing();
    var statusEl = $('cloudMapStatus');
    if (statusEl) statusEl.textContent = 'Mapping… (Windows may ask for administrator permission once, to trust the server certificate.)';
    try {
      var r = await api.cloudMapdriveMap(serverId, letterSel ? letterSel.value : 'Z', !!(recBox && recBox.checked));
      if (r && r.success) {
        toast('Drive mapped', 'The server is now drive ' + r.letter + ': — open files straight from it.', 'success');
        cloudMapInvalidateCache();
      } else if (r && r.error === 'password-needed') {
        toast('Password needed', 'Save the server password in the Client tab first — connect once with the password, and it is saved on this device.', 'error');
      } else {
        toast('Mapping failed', (r && r.error) || 'Could not map the drive.', 'error');
      }
    } catch (e) {
      toast('Mapping error', e && e.message ? e.message : 'Could not map the drive.', 'error');
    }
    await renderMapdrivePanel();
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
      cloudMapInvalidateCache();
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
    cloudMapInvalidateCache();
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
        cloudMapInvalidateCache();
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

  /* ---------- Open mode (spec v2) ---------- */
  // How a double-click opens a file: 'direct' (mapped drive, then
  // Office direct, then temp + save-back) or 'temp' (always temp +
  // save-back). Stored in cloud.json; default direct. No mode ever
  // creates a drive letter — a visible drive appears only via the
  // Map button in the Map network tab.
  function cloudOpenMode() { return (cloudCfg && cloudCfg.openMode === 'temp') ? 'temp' : 'direct'; }
  var CLOUD_PROGRAM_EXTS = ['exe', 'msi', 'bat', 'cmd', 'com', 'scr'];
  var CLOUD_OFFICE_EXTS = ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];
  function cloudFileExt(name) {
    var i = String(name || '').lastIndexOf('.');
    return i <= 0 ? '' : String(name).slice(i + 1).toLowerCase();
  }
  // Programs / games NEVER go through temp, in either mode: a game is
  // a whole folder of files that call each other, and temp downloads
  // ONE file only — the game would fail to start. Only the mapped
  // drive works for them.
  function cloudIsProgramFile(name) { return CLOUD_PROGRAM_EXTS.indexOf(cloudFileExt(name)) >= 0; }
  function cloudIsOfficeDoc(name) { return CLOUD_OFFICE_EXTS.indexOf(cloudFileExt(name)) >= 0; }
  // The mode indicator: how the last file actually opened.
  function cloudSetLastOpenMode(mode) {
    var el = $('cloudOpenModeStatus');
    if (!el) return;
    el.textContent = mode === 'direct' ? 'Last file: Direct' : mode === 'temp' ? 'Last file: temp' : 'Last file: —';
  }
  function renderCloudOpenMode() {
    var sel = $('cloudOpenModeSel');
    if (sel) sel.value = cloudOpenMode();
    var st = $('cloudOpenModeStatus');
    if (st && !st.textContent) st.textContent = 'Last file: —';
  }
  // Mapped-drive open (v1), shared by the program branch and direct
  // mode. Returns true when the file opened from the drive.
  async function cloudTryMappedOpen(entry) {
    try {
      var letter = await cloudMapLetterFor(cloudConn.serverId);
      if (letter && api && typeof api.cloudMapdriveOpenMapped === 'function') {
        var m = await api.cloudMapdriveOpenMapped(cloudConn.serverId, entry.rel);
        if (m && m.success) return true;
        // A stale cache (mapped, then unmapped outside the app) must
        // not block the file: drop it and fall through.
        cloudMapInvalidateCache();
      }
    } catch (e) {}
    return false;
  }

  // Open a file the way Windows would: music plays, pictures open.
  // Direct mode tries, in order: the mapped drive, then (for Office
  // documents) the Office app straight from the server, then temp +
  // save-back. Temp mode goes straight to temp + save-back. Any step
  // that fails falls through AUTOMATICALLY to the next one; only when
  // every method fails does the user see an error. Programs never go
  // through temp: without a mapped drive they get the Map prompt.
  // Folders are entered, as before.
  async function cloudOpenFile(entry) {
    if (!entry) return;
    if (entry.isDir) { cloudBrowse(entry.rel); return; }
    if (!cloudConn || cloudTransferBusy) return;
    if (!api || typeof api.cloudClientOpen !== 'function') return cloudMissing();
    // Programs / games: mapped drive or nothing.
    if (cloudIsProgramFile(entry.name)) {
      if (await cloudTryMappedOpen(entry)) { cloudSetLastOpenMode('direct'); return; }
      askConfirm('"' + entry.name + '" is a program — it needs a mapped drive to run correctly. Without a map it will not run (temp downloads a single file only, and a game is a whole folder).', function () { showCloudPanel('mapdrive'); }, { title: 'This file is a program', yesLabel: 'Create Map', noLabel: 'Cancel' });
      return;
    }
    if (cloudOpenMode() === 'direct') {
      // (a) Mapped drive.
      if (await cloudTryMappedOpen(entry)) { cloudSetLastOpenMode('direct'); return; }
      // (b) Office document: open straight from the server in
      // Word/Excel/PowerPoint — no temp copy, saves go back.
      if (cloudIsOfficeDoc(entry.name) && api && typeof api.cloudOfficeOpen === 'function') {
        try {
          var o = await api.cloudOfficeOpen(cloudConn.serverId, entry.rel);
          if (o && o.success) { cloudSetLastOpenMode('direct'); return; }
        } catch (e) {}
      }
    }
    // (c) Temp + save-back: download once, open, and edits upload
    // back to the server while the app is open.
    try {
      cloudTransferBusy = true;
      showCloudTransfer('Opening ' + entry.name + '…', 0);
      var r = await api.cloudClientOpen(cloudConn.serverId, entry.rel);
      hideCloudTransfer();
      // r.dest is present exactly when the download succeeded, even
      // when the OS open itself failed — the file still opened via
      // temp, so the indicator says temp either way.
      if (!r || (!r.success && !r.dest)) toast('Could not open', (r && r.error) || 'The file could not be opened.', 'error');
      else cloudSetLastOpenMode('temp');
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
  /* Next run of a scheduled job as a Date (null when unscheduled or
     unparseable). nextRunText() keeps its exact output for the Jobs
     page; the Dashboard reuses the Date to find the earliest run. */
  function nextRunDate(job) {
    var s = job.schedule || (job.raw && job.raw.schedule) || null;
    if (!s || !s.enabled) return null;
    var time = s.time || '02:00';
    var m = /^(\d{1,2}):(\d{2})$/.exec(time);
    if (!m) return null;
    var hh = parseInt(m[1], 10), mm = parseInt(m[2], 10);
    var now = new Date();
    if ((s.frequency || '').toLowerCase() === 'custom') {
      var days = Array.isArray(s.days) ? s.days : [];
      for (var i = 0; i < 8; i++) {
        var c = new Date(); c.setDate(c.getDate() + i);
        if (days.indexOf(c.getDay()) < 0) continue;
        c.setHours(hh, mm, 0, 0);
        if (c > now) return c;
        if (i === 0) return c; // due today
      }
      return null;
    }
    var next = new Date();
    next.setHours(hh, mm, 0, 0);
    if ((s.frequency || '').toLowerCase() === 'weekly') {
      if (next <= now) next.setDate(next.getDate() + 7);
    } else if ((s.frequency || '').toLowerCase() === 'monthly') {
      if (next <= now) next.setMonth(next.getMonth() + 1);
    } else if (next <= now) {
      next.setDate(next.getDate() + 1);
    }
    return next;
  }
  function nextRunText(job) {
    var s = job.schedule || (job.raw && job.raw.schedule) || null;
    if (!s || !s.enabled) return 'No schedule — manual only';
    var next = nextRunDate(job);
    if (!next) return scheduleLabel(s);
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
    /* Settings is a full page now: the four tabs switch sections. The
       old drawer view names still work: 'home' = General, 'email' = Email. */
    var tab = view === 'email' ? 'email' : view === 'backup' ? 'backup' : view === 'security' ? 'security' : 'general';
    var sections = { general: 'settingsGeneralSection', backup: 'settingsBackupSection', security: 'settingsSecuritySection', email: 'settingsEmailSection' };
    Object.keys(sections).forEach(function (k) { var s = $(sections[k]); if (s) s.style.display = k === tab ? '' : 'none'; });
    document.querySelectorAll('[data-settings-tab]').forEach(function (t) { t.classList.toggle('active', t.getAttribute('data-settings-tab') === tab); });
  }
  function refreshEmailMenuStatus() {
    var el = $('emailTabStatus'); if (!el) return;
    var enabled = $('settingEmailEnabled') ? $('settingEmailEnabled').checked : false;
    var to = $('settingEmailTo') ? $('settingEmailTo').value.trim() : '';
    el.textContent = enabled ? ('On' + (to ? ' — ' + to : '')) : 'Off';
  }
  function openSettings() {
    showSettingsView('home');
    showView('settings');
  }
  function closeSettings() {
    /* The settings page is a view now, not a drawer: closing it goes
       back to the view it was opened from. */
    showView(lastBackupView || 'dashboard');
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
    /* In-place restore: the pending job goes to main (the restore
       script reads it back with getJobConfig(null)), the view resets
       to a blank state, and it opens in the main area — no second
       window any more. */
    if (!api || typeof api.setRestorePending !== 'function') { toast('Restore unavailable', 'Restore API is not available.', 'error'); return; }
    try {
      await api.setRestorePending(job ? (job.raw || job) : null);
      wizardReturnView = lastBackupView || 'dashboard';
      if (window.__restoreWizard && typeof window.__restoreWizard.reset === 'function') window.__restoreWizard.reset();
      showView('restore');
    }
    catch (e) { toast('Restore failed', e && e.message ? e.message : 'Could not open Restore.', 'error'); }
  }
  async function openJobWizard(job) {
    /* In-place wizard: same pattern as openRestore — pending job to
       main, reset the wizard view, open it in the main area. */
    if (!api || typeof api.setWizardPending !== 'function') { toast('New Job unavailable', 'Job wizard API is not available.', 'error'); return; }
    try {
      await api.setWizardPending(job ? (job.raw || job) : null);
      wizardReturnView = lastBackupView || 'dashboard';
      if (window.__jobWizard && typeof window.__jobWizard.reset === 'function') window.__jobWizard.reset();
      showView('wizard');
    }
    catch (e) { toast('New Job failed', e && e.message ? e.message : 'Could not open the job wizard.', 'error'); }
  }

  /* ---------- load jobs ---------- */
  async function loadJobs() {
    if (!api || typeof api.getJobHistory !== 'function') {
      jobs = [];
      renderStats();
      refreshStorageCard();
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
    refreshStorageCard();
    renderJobsView();
  }
  if (api && typeof api.onJobsUpdated === 'function') {
    api.onJobsUpdated(function () { loadJobs(); });
  }
  // One visible spin on a refresh button the user pressed himself.
  // The background auto-refresh never calls this, so it stays silent.
  function spinOnce(el) {
    if (!el) return;
    el.classList.remove('spinning');
    void el.offsetWidth;
    el.classList.add('spinning');
    el.addEventListener('animationend', function h() { el.classList.remove('spinning'); el.removeEventListener('animationend', h); });
  }
  async function refreshJobs() {
    spinOnce($('backupTopRefreshBtn'));
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
    /* The hero tints with the state (06 look): green while connected,
       red on error, neutral otherwise — the dot and text say the same. */
    var hero = $('vpnHero');
    if (hero) hero.className = 'card vpn-hero ' + ((!st || !st.installed) ? 'vpn-hero-idle' : (st.error && !st.connected && !st.needsLogin) ? 'vpn-hero-bad' : st.connected ? 'vpn-hero-ok' : 'vpn-hero-idle');
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
      // The settings live in this card (API credentials, key expiry,
      // subnet sharing) — they must be reachable BEFORE connecting:
      // the key-expiry choice and the API token are exactly what make
      // the first connect stay connected, so hiding the card until
      // after Connect made them unreachable when they matter most.
      // Show it while disconnected; the live facts stay "—" until
      // the VPN is on, and the routes note stays hidden (it only
      // applies while advertising).
      if (dc) dc.style.display = '';
      var ket0 = $('vpnKeyExpiryToggle'); if (ket0) ket0.checked = vpnKeyExpiryWanted();
      var tok0 = $('vpnApiToken'); if (tok0) tok0.value = (settings.vpn && settings.vpn.apiToken) || '';
      var ocid0 = $('vpnOauthClientId'); if (ocid0) ocid0.value = (settings.vpn && settings.vpn.oauthClientId) || '';
      var osec0 = $('vpnOauthClientSecret'); if (osec0) osec0.value = (settings.vpn && settings.vpn.oauthClientSecret) || '';
      refreshVpnRoutesState();
      refreshVpnKeyExpiryState();
      refreshVpnApiCredsStatus(false);
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
      var h = document.createElement('h3'); h.className = 'vpn-peer-name'; h.textContent = p.name;
      var ip = document.createElement('span'); ip.className = 'vpn-peer-ip'; ip.textContent = p.ip || '—';
      var os = document.createElement('span'); os.className = 'vpn-peer-os'; os.textContent = p.os || '—';
      var st = document.createElement('span'); st.className = 'pill ' + (p.online ? 'pill-completed' : 'pill-pending'); st.textContent = p.online ? 'online' : 'offline';
      row.appendChild(d); row.appendChild(h); row.appendChild(ip); row.appendChild(os); row.appendChild(st);
      if (p.ip) {
        var open = document.createElement('button'); open.className = 'btn btn-primary btn-sm'; open.type = 'button'; open.textContent = 'Open in Cloud';
        open.addEventListener('click', function () { openCloudWithPeer(p); });
        row.appendChild(open);
      } else {
        var spacer = document.createElement('span'); row.appendChild(spacer);
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
    /* Same state tint as the Tailscale hero (06 look). */
    var wh = $('wgHero');
    if (wh) wh.className = 'card vpn-hero ' + (!st.installed ? 'vpn-hero-idle' : st.serverRunning ? 'vpn-hero-ok' : st.error ? 'vpn-hero-bad' : 'vpn-hero-idle');
    renderWgNat(st || {});
    var dot = $('wgStatusDot'); if (dot) dot.className = 'vpn-dot' + (st.serverRunning ? ' on' : '');
    var txt = $('wgStatusText'), sub = $('wgStatusSub');
    var ni = $('wgNotInstalled');
    var sc = $('wgServerCard');
    var tl = $('wgTransportLine');
    if (!st.installed) {
      if (txt) txt.textContent = 'Not installed';
      if (sub) sub.textContent = 'AmneziaWG is not installed on this computer.';
      if (tl) tl.style.display = 'none';
      if (ni) ni.style.display = '';
      if (sc) sc.style.display = 'none';
      // The early return below used to skip the button reset, so a
      // failed Start left the button stuck on "Working…" — reset
      // the button here too.
      var sb0 = $('wgServerBtn'); if (sb0) { sb0.textContent = 'Start server'; sb0.classList.add('btn-primary'); }
      renderWgPeers([]);
      return;
    }
    if (ni) ni.style.display = 'none';
    if (sc) sc.style.display = wgPanel === 'server' ? '' : 'none';
    if (tl) {
      if (st.transport === 'amneziawg') { tl.style.display = ''; tl.textContent = st.obfuscated ? 'Transport: AmneziaWG (obfuscated)' : 'Transport: AmneziaWG.'; }
      else { tl.style.display = ''; tl.textContent = 'Transport: stock WireGuard (no obfuscation).'; }
    }
    if (st.serverRunning) {
      if (txt) txt.textContent = 'Server running';
      if (sub) sub.textContent = 'This machine is the AmneziaWG hub — devices connect to it.';
    } else if (st.error) {
      if (txt) txt.textContent = 'Error';
      if (sub) sub.textContent = st.error;
    } else {
      if (txt) txt.textContent = 'Off';
      if (sub) sub.textContent = 'The server is stopped.';
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
    if (ph) ph.textContent = 'On your router, forward UDP ' + ((st.server && st.server.listenPort) || 51820) + ' to this machine — the only router step.';
    var ep = $('wgEndpoint');
    if (ep && document.activeElement !== ep) ep.value = (st.server && st.server.endpoint) || '';
    renderWgPeers(st.peers || []);
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
    ns.className = 't-sub vpn-note wg-nat-banner' + (n.running ? ' ok' : '');
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
      el.style.cssText = 'flex:1; min-width:100px;';
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
      empty.innerHTML = '<div class="big">🔐</div><h3>No devices yet</h3><p>Add a device above and it will show up here.</p>';
      list.appendChild(empty);
      return;
    }
    peers.forEach(function (p) {
      var row = document.createElement('div');
      row.className = 'vpn-peer wg-peer';
      var d = document.createElement('span'); d.className = 'vpn-peer-dot' + (p.online ? ' on' : '');
      var dev = document.createElement('div'); dev.className = 'wg-peer-dev';
      var h = document.createElement('h3'); h.className = 'vpn-peer-name'; h.textContent = p.name;
      var tip = document.createElement('div'); tip.className = 'vpn-peer-meta'; tip.textContent = (p.tunnelIp || '—') + (p.endpoint ? (' · endpoint ' + p.endpoint) : '');
      dev.appendChild(h); dev.appendChild(tip);
      var st = document.createElement('div'); st.className = 'wg-peer-status';
      var pill = document.createElement('span'); pill.className = 'pill ' + (p.online ? 'pill-completed' : 'pill-pending'); pill.textContent = p.online ? 'online' : 'offline';
      var hs = document.createElement('div'); hs.className = 'vpn-peer-meta'; hs.textContent = p.online ? ('last handshake ' + wgHandshakeText(p.latestHandshake)) : 'never connected';
      st.appendChild(pill); st.appendChild(hs);
      var tr = document.createElement('div'); tr.className = 'wg-peer-transfer';
      var dn = document.createElement('div'); dn.textContent = formatBytes(p.transferRx || 0) + ' down';
      var up = document.createElement('div'); up.className = 'vpn-peer-meta'; up.textContent = formatBytes(p.transferTx || 0) + ' up';
      tr.appendChild(dn); tr.appendChild(up);
      var key = document.createElement('span'); key.className = 'wg-peer-key'; key.textContent = String(p.publicKey || '').slice(0, 12) + '…';
      var ep = p.endpoint ? (' · ' + p.endpoint) : '';
      key.title = (p.publicKey || '') + ep;
      row.appendChild(d); row.appendChild(dev); row.appendChild(st); row.appendChild(tr); row.appendChild(key);
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

  /* ---------- wiring ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    var nnj = $('navNewJob'); if (nnj) nnj.addEventListener('click', function () { openJobWizard(null); });
    var jnb = $('jobsNewJobBtn'); if (jnb) jnb.addEventListener('click', function () { openJobWizard(null); });
    var jenb = $('jobsEmptyNewJobBtn'); if (jenb) jenb.addEventListener('click', function () { openJobWizard(null); });
    /* Jobs page 02 toolbar + details panel: everything acts on the
       selected row (first row when nothing is picked yet). */
    var jrb = $('jobsRunBtn'); if (jrb) jrb.addEventListener('click', function () { var j = selectedJob(); if (j) runBackup(j, false); });
    var jeb = $('jobsEditBtn'); if (jeb) jeb.addEventListener('click', function () { var j = selectedJob(); if (j) openJobWizard(j); });
    var jdb = $('jobsDeleteBtn'); if (jdb) jdb.addEventListener('click', deleteSelectedJob);
    var jrf = $('jobsRefreshBtn'); if (jrf) jrf.addEventListener('click', refreshJobs);
    var jch = $('jobsClearHistoryBtn'); if (jch) jch.addEventListener('click', function () {
      if (!api || typeof api.clearJobHistory !== 'function') return;
      askConfirm('Do you want to delete ALL backup history? This cannot be undone.', async function () {
        try { await api.clearJobHistory(); await loadJobs(); toast('History cleared', 'Backup history has been cleared.', 'success'); }
        catch (e) { toast('Clear failed', e && e.message ? e.message : 'History could not be cleared.', 'error'); }
      });
    });
    var jsi = $('jobsSearchInput'); if (jsi) jsi.addEventListener('input', renderJobsView);
    var jsf = $('jobsStatusFilter'); if (jsf) jsf.addEventListener('change', renderJobsView);
    var jss = $('jobsSortSelect'); if (jss) jss.addEventListener('change', renderJobsView);
    var jdr = $('jobsDetailsRun'); if (jdr) jdr.addEventListener('click', function () { var j = selectedJob(); if (j) runBackup(j, false); });
    var jdrs = $('jobsDetailsRestore'); if (jdrs) jdrs.addEventListener('click', function () { var j = selectedJob(); if (j) openRestore(j); });
    var jde = $('jobsDetailsEdit'); if (jde) jde.addEventListener('click', function () { var j = selectedJob(); if (j) openJobWizard(j); });
    /* Dashboard 01 quick actions. */
    var dnj = $('dashNewJob'); if (dnj) dnj.addEventListener('click', function () { openJobWizard(null); });
    var denj = $('dashEmptyNewJobBtn'); if (denj) denj.addEventListener('click', function () { openJobWizard(null); });
    var drs = $('dashRestore'); if (drs) drs.addEventListener('click', function () { openRestore(null); });
    var dvj = $('dashViewJobs'); if (dvj) dvj.addEventListener('click', function () { showView('jobs'); });
    var dval = $('dashViewAllJobs'); if (dval) dval.addEventListener('click', function () { showView('jobs'); });
    var dol = $('dashOpenLogs'); if (dol) dol.addEventListener('click', function () { showView('logs'); });
    var dst = $('dashSettings'); if (dst) dst.addEventListener('click', function () { openSettings(); refreshVaultStatus(); });
    var dcs = $('dashCheckStorage'); if (dcs) dcs.addEventListener('click', function () { refreshStorageCard(true); });
    var dopen = $('dashOpenLocation'); if (dopen) dopen.addEventListener('click', function () {
      if (storageDest && api && typeof api.openPath === 'function') api.openPath(storageDest).catch(function () {});
    });

    $('navRestore').addEventListener('click', function () { openRestore(null); });
    var brb = $('backupTopRefreshBtn');
    if (brb) brb.addEventListener('click', refreshJobs);
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
    document.querySelectorAll('[data-settings-tab]').forEach(function (tab) {
      tab.addEventListener('click', function () { showSettingsView(tab.getAttribute('data-settings-tab')); });
    });
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
    var cy = $('confirmYes'); if (cy) cy.addEventListener('click', function () { var cb = confirmCallback; closeConfirm(); if (cb) cb(); });
    var cn = $('confirmNo'); if (cn) cn.addEventListener('click', closeConfirm);
    var cb2 = $('confirmBackdrop'); if (cb2) cb2.addEventListener('click', closeConfirm);
    /* Collapsible nav groups: the arrow next to Backup / Cloud / VPN
       folds its items away. All groups start collapsed and open only
       when the user clicks the header — navigation never opens one. */
    document.querySelectorAll('.nav-group-head').forEach(function (head) {
      head.addEventListener('click', function () {
        var g = head.closest('.nav-group');
        if (g) g.classList.toggle('collapsed');
      });
    });
    document.querySelectorAll('[data-wg-tab]').forEach(function (tab) {
      tab.addEventListener('click', function () { showWgPanel(tab.getAttribute('data-wg-tab')); });
    });
    document.querySelectorAll('[data-cloud-tab]').forEach(function (tab) {
      tab.addEventListener('click', function () {
        var panel = tab.getAttribute('data-cloud-tab');
        showCloudPanel(panel); setModule('cloud');
      });
    });
    document.querySelectorAll('[data-nav]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var nav = btn.getAttribute('data-nav');
        document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
        btn.classList.add('active');
        if (nav === 'logs') toast('Logs', 'Open the Log Viewer from the Logs window.', '');
        if (nav === 'jobs') showView('jobs');
        if (nav === 'dashboard') showView('dashboard');
        if (nav === 'logs') showView('logs');
        if (nav === 'cloud') { showCloudPanel('home'); showView('cloud'); }
        if (nav === 'vpn') showView('vpn');
        if (nav === 'wireguard') { showView('wireguard'); showWgPanel('server'); }
        if (nav === 'wireguard-site') { showView('wireguard'); showWgPanel('nat'); }
        // (No 'wireguard-nat' item: it was a duplicate shortcut to the
        // same Site-to-Site panel — removed in round 2 #2.)
        if (nav === 'cloud-server') { showCloudPanel('server'); setModule('cloud'); }
        if (nav === 'cloud-client') { showCloudPanel('client'); setModule('cloud'); }
        if (nav === 'cloud-mapdrive') { showCloudPanel('mapdrive'); setModule('cloud'); }
      });
    });
    document.querySelectorAll('#cloudServerAccessSeg .seg-btn').forEach(function (b) {
      b.addEventListener('click', function () { setServerAccess(b.getAttribute('data-access')); saveCloudServerSettings(); });
    });
    document.querySelectorAll('#cloudClientAccessSeg .seg-btn').forEach(function (b) {
      b.addEventListener('click', function () { setClientAccess(b.getAttribute('data-access')); });
    });
    // Jump to the WireGuard module's Add a device form: the picker
    // above lists tunnel devices, and when it is empty the device
    // has to be added first — this button is the shortcut there.
    var wgApb = $('cloudClientWgAddPeerBtn');
    if (wgApb) wgApb.addEventListener('click', function () {
      showView('wireguard');
      showWgPanel('server'); // the Add-a-device form lives in the server card
      // Focus AFTER the status load finishes: it hides the server
      // card when the transport is not installed, and focusing
      // before that races it (the card hides under the focus).
      var focusKey = function () {
        var key = $('wgPeerKey');
        if (key) { try { key.scrollIntoView({ block: 'center' }); } catch (e) {} key.focus(); }
      };
      if (typeof loadWireGuard === 'function') {
        try { var p = loadWireGuard(); if (p && typeof p.then === 'function') { p.then(focusKey); return; } } catch (e) {}
      }
      focusKey();
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
    $('drawerEdit').addEventListener('click', function () { var j = currentJob; if (j) { closeDrawer(); openJobWizard(j); } });
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
    if (lrb) lrb.addEventListener('click', function () { spinOnce(lrb.querySelector('.refresh-glyph')); loadJobs().then(function () { renderLogs(currentLogTab); }); });
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
    var cmb2 = $('cloudMapBtn');
    if (cmb2) cmb2.addEventListener('click', function () { cloudMapDriveAction(); });
    var cmd = $('cloudMapDisconnectBtn');
    if (cmd) cmd.addEventListener('click', async function () {
      var sel = $('cloudMapServer');
      if (!sel || !sel.value) return;
      if (!api || typeof api.cloudMapdriveDisconnect !== 'function') return cloudMissing();
      try {
        var r = await api.cloudMapdriveDisconnect(sel.value);
        if (r && r.success) { toast('Drive disconnected', 'The mapped drive was removed.', 'success'); cloudMapInvalidateCache(); }
        else toast('Disconnect failed', (r && r.error) || 'Could not disconnect the drive.', 'error');
      } catch (e) { toast('Disconnect error', e && e.message ? e.message : 'Could not disconnect the drive.', 'error'); }
      await renderMapdrivePanel();
    });
    var cme = $('cloudMapExplorerBtn');
    if (cme) cme.addEventListener('click', async function () {
      if (!cloudMapCurrentLetter) return;
      if (!api || typeof api.cloudMapdriveOpenExplorer !== 'function') return cloudMissing();
      try {
        var r2 = await api.cloudMapdriveOpenExplorer(cloudMapCurrentLetter);
        if (!r2 || !r2.success) toast('Could not open Explorer', (r2 && r2.error) || 'The drive could not be opened.', 'error');
      } catch (e) { toast('Explorer error', e && e.message ? e.message : 'The drive could not be opened.', 'error'); }
    });
    var cms2 = $('cloudMapServer');
    if (cms2) cms2.addEventListener('change', function () { renderMapdrivePanel(); });
    var cub2 = $('cloudUploadBtn');
    if (cub2) cub2.addEventListener('click', function () { cloudUpload(); });
    var cmb = $('cloudMkdirBtn');
    if (cmb) cmb.addEventListener('click', function () { cloudNewFolder(cloudPath); });
    var cbr = $('cloudBrowserRefreshBtn');
    if (cbr) cbr.addEventListener('click', function () { cloudBrowse(cloudPath); });
    // Open mode (spec v2): which way a double-click opens a file.
    // The choice persists in cloud.json; no mode ever creates a
    // drive letter.
    var coms = $('cloudOpenModeSel');
    if (coms) coms.addEventListener('change', async function () {
      var next = coms.value === 'temp' ? 'temp' : 'direct';
      if (!api || typeof api.cloudSetOpenMode !== 'function') return cloudMissing();
      try {
        var r = await api.cloudSetOpenMode(next);
        if (r && r.success) { if (cloudCfg) cloudCfg.openMode = r.openMode; }
        else { toast('Could not save the open mode', (r && r.error) || 'The choice was not saved.', 'error'); renderCloudOpenMode(); }
      } catch (e) { toast('Could not save the open mode', e && e.message ? e.message : 'The choice was not saved.', 'error'); renderCloudOpenMode(); }
    });
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
    // Temp + save-back results: a successful save-back stays silent
    // (that is the point); a conflict or a failure warns the user.
    if (api && typeof api.onCloudSaveback === 'function') {
      api.onCloudSaveback(function (ev) {
        if (!ev) return;
        if (ev.kind === 'conflict') toast('Not saved back', '«' + (ev.name || '') + '» changed on the server since you opened it — your edits were NOT overwritten onto the server. They are still in the temp copy.', 'error');
        else if (ev.kind === 'error') toast('Save-back failed', '«' + (ev.name || '') + '» could not be saved back to the server: ' + (ev.error || ''), 'error');
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
    var tbb = $('topBackBtn');
    if (tbb) tbb.addEventListener('click', goBack);

    loadSettings().then(function () { loadJobs(); checkVaultOnStartup(); refreshVaultStatus(); });
    showView('dashboard');
  });
})();
