/* New Backup Job wizard — plain JavaScript, Electron renderer only.
   No require(). All native calls go through window.electronAPI.
   Browse buttons call showOpenDialog and fill the field WITHOUT
   closing this window — that was the old bug. */
(function () {
  'use strict';
  var api = window.electronAPI || null;
  var step = 1;
  var patterns = [];
  var editing = null;
  var hasSavedPassword = false; // vault already holds a password for this job

  function $(id) { return document.getElementById(id); }
  function driveLetterOf(p) {
    if (typeof p !== 'string') return null;
    var m = /^([A-Za-z]):[\\/]/.exec(p.trim());
    return m ? m[1].toUpperCase() : null;
  }
  // How this job finds its drive again: by name, by letter, or by
  // serial number. The three choices sit at the top of the Source and
  // Destination steps — the user picks one first, then Browses. The
  // values are read automatically from the drive that is picked; the
  // serial is never typed. On a path with no drive letter (a UNC path,
  // or Linux) the choice is hidden: there is nothing to remap.
  function matchMode(which) {
    var checked = document.querySelector('input[name="' + (which === 'source' ? 'sourceMatch' : 'destMatch') + '"]:checked');
    var v = checked ? checked.value : 'label';
    return (v === 'letter' || v === 'serial' || v === 'label') ? v : 'label';
  }
  function setMatchMode(which, mode) {
    var name = which === 'source' ? 'sourceMatch' : 'destMatch';
    var m = (mode === 'letter' || mode === 'serial' || mode === 'label') ? mode : 'label';
    var radio = document.querySelector('input[name="' + name + '"][value="' + m + '"]');
    if (radio && !radio.disabled) radio.checked = true;
  }
  function setText(id, text) { var el = $(id); if (el) el.textContent = text; }
  async function refreshDriveMatch(which) {
    var isSrc = which === 'source';
    var field = $(isSrc ? 'sourceMatchField' : 'destMatchField');
    var pathVal = $(isSrc ? 'sourceDir' : 'destDir').value.trim();
    var letter = driveLetterOf(pathVal);
    if (!field) return;
    if (!letter) { field.style.display = 'none'; return; }
    field.style.display = '';
    var drives = [];
    try { if (api && typeof api.getDrives === 'function') drives = await api.getDrives() || []; } catch (e) { drives = []; }
    var info = null;
    for (var i = 0; i < drives.length; i++) {
      if (drives[i] && String(drives[i].letter || '').toUpperCase() === letter) { info = drives[i]; break; }
    }
    var p = isSrc ? 'sourceMatch' : 'destMatch';
    setText(p + 'Label', info && info.label ? '— ' + info.label : '— unknown');
    setText(p + 'Letter', '— ' + letter + ':');
    setText(p + 'Serial', info && info.serial ? '— ' + info.serial : '— not readable');
    var serialRadio = document.querySelector('input[name="' + p + '"][value="serial"]');
    if (serialRadio) {
      serialRadio.disabled = !(info && info.serial);
      if (serialRadio.disabled && serialRadio.checked) setMatchMode(which, 'label');
    }
  }
  function matchSummary(which) {
    var mode = matchMode(which);
    var pathVal = $(which === 'source' ? 'sourceDir' : 'destDir').value.trim();
    var letter = driveLetterOf(pathVal);
    if (!letter) return '—';
    if (mode === 'letter') return 'By drive letter (' + letter + ':)';
    if (mode === 'serial') {
      var s = $(which === 'source' ? 'sourceMatchSerial' : 'destMatchSerial');
      var v = s ? s.textContent.replace(/^—\s*/, '') : '';
      return 'By serial number' + (v && v !== 'not readable' ? ' (' + v + ')' : '');
    }
    var l = $(which === 'source' ? 'sourceMatchLabel' : 'destMatchLabel');
    var lv = l ? l.textContent.replace(/^—\s*/, '') : '';
    return 'By name' + (lv && lv !== 'unknown' ? ' (' + lv + ')' : '');
  }
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
  function showStep(n) {
    step = n;
    document.querySelectorAll('.step').forEach(function (s) {
      var sn = Number(s.getAttribute('data-step'));
      s.classList.toggle('active', sn === n);
      s.classList.toggle('done', sn < n);
    });
    document.querySelectorAll('.step-panel').forEach(function (p) {
      p.classList.toggle('active', Number(p.getAttribute('data-panel')) === n);
    });
    $('backBtn').style.display = n > 1 ? '' : 'none';
    $('nextBtn').style.display = n < 5 ? '' : 'none';
    $('createBtn').style.display = n === 5 ? '' : 'none';
    if (n === 5) renderReview();
  }
  function validateStep(n) {
    if (n === 1) {
      var ok = true;
      var nameOk = $('jobName').value.trim().length > 0;
      $('jobNameError').classList.toggle('show', !nameOk);
      var srcOk = $('sourceDir').value.trim().length > 0;
      $('sourceError').classList.toggle('show', !srcOk);
      ok = nameOk && srcOk;
      if (!ok) {
        toast('Missing information', 'Please enter a job name and choose a source folder.', 'warning');
        if (!nameOk) $('jobName').focus(); else if (!srcOk) $('sourceDir').focus();
      }
      return ok;
    }
    if (n === 2) {
      var destOk = $('destDir').value.trim().length > 0;
      $('destError').classList.toggle('show', !destOk);
      if (!destOk) toast('Missing information', 'Please choose a destination folder.', 'warning');
      return destOk;
    }
    if (n === 4) {
      if (!$('optEncrypt').checked) return true;
      // A saved vault password counts: blank fields keep it.
      if (hasSavedPassword && !$('encPassword').value && !$('encPasswordConfirm').value) return true;
      var pw = $('encPassword').value;
      var pwOk = pw.length >= 8;
      $('encPasswordError').classList.toggle('show', !pwOk);
      var matchOk = pwOk && $('encPasswordConfirm').value === pw;
      $('encPasswordConfirmError').classList.toggle('show', pwOk && !matchOk);
      if (!pwOk) { toast('Password too short', 'The backup password must be at least 8 characters.', 'warning'); $('encPassword').focus(); return false; }
      if (!matchOk) { toast('Passwords do not match', 'Please repeat the same password.', 'warning'); $('encPasswordConfirm').focus(); return false; }
      return true;
    }
    return true;
  }
  function renderChips() {
    var box = $('patternChips');
    box.innerHTML = '';
    patterns.forEach(function (p, i) {
      var chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = p;
      var x = document.createElement('button');
      x.type = 'button'; x.textContent = '✕'; x.setAttribute('aria-label', 'Remove pattern ' + p);
      x.addEventListener('click', function () { patterns.splice(i, 1); renderChips(); });
      chip.appendChild(x);
      box.appendChild(chip);
    });
  }
  function addPattern() {
    var v = $('patternInput').value.trim();
    if (!v) return;
    if (patterns.indexOf(v) === -1) patterns.push(v);
    $('patternInput').value = '';
    renderChips();
  }
  function collectJob() {
    var freq = 'Daily';
    var checked = document.querySelector('input[name="frequency"]:checked');
    if (checked) freq = checked.value;
    return {
      // Every job gets a unique id. Two jobs may share a name, but they
      // must stay two separate tasks — the old code keyed everything by
      // name, so a second job with the same name overwrote the first.
      id: (editing && editing.id) || ('job-' + Date.now() + '-' + Math.random().toString(36).substr(2, 4)),
      name: $('jobName').value.trim(),
      source: $('sourceDir').value.trim(),
      sourceDirectory: $('sourceDir').value.trim(),
      sourceDriveMatch: { mode: matchMode('source') },
      destination: $('destDir').value.trim(),
      destinationDirectory: $('destDir').value.trim(),
      destinationDriveMatch: { mode: matchMode('dest') },
      includePatterns: patterns.slice(),
      allowIncremental: $('optIncremental').checked,
      compress: $('optCompress').checked,
      compression: $('optCompress').checked ? 'standard' : 'none',
      encryptionEnabled: $('optEncrypt').checked,
      verify: $('optVerify').checked,
      use_vss: false,
      schedule: $('optSchedule').checked ? { enabled: true, frequency: freq, time: $('scheduleTime').value || '02:00' } : { enabled: false, frequency: freq, time: $('scheduleTime').value || '02:00' },
      type: 'TEMPLATE',
      status: 'PENDING'
    };
  }
  function renderReview() {
    var j = collectJob();
    var rows = [
      ['Job name', j.name || '—'],
      ['Source', j.source || '—'],
      ['Find source drive', matchSummary('source')],
      ['Destination', j.destination || '—'],
      ['Find destination drive', matchSummary('dest')],
      ['Include patterns', j.includePatterns.length ? j.includePatterns.join(', ') : 'All files'],
      ['Incremental', j.allowIncremental ? 'Yes' : 'No'],
      ['Compress with ZIP', j.compress ? 'Yes' : 'No'],
      ['Encryption', j.encryptionEnabled ? 'AES-256' + (j.compress ? ' (compression + encryption)' : ' (encryption only, files stored uncompressed)') : 'Off'],
      ['Verify after backup', j.verify ? 'Yes' : 'No'],
      ['Schedule', j.schedule.enabled ? j.schedule.frequency + ' at ' + j.schedule.time : 'Manual only']
    ];
    $('reviewBox').innerHTML = rows.map(function (r) {
      var div = document.createElement('div');
      div.className = 'review-row';
      var k = document.createElement('div'); k.className = 'k'; k.textContent = r[0];
      var v = document.createElement('div'); v.className = 'v'; v.textContent = r[1];
      div.appendChild(k); div.appendChild(v);
      return div.outerHTML;
    }).join('');
  }
  async function pickFolder(targetId, allowFile) {
    if (!api || typeof api.showOpenDialog !== 'function') { toast('Browse unavailable', 'Folder picker API is not available.', 'error'); return; }
    try {
      // Source may be a folder OR a single file — whichever the user
      // picks. Destination stays folder-only.
      var props = allowFile ? ['openFile', 'openDirectory'] : ['openDirectory'];
      var result = await api.showOpenDialog({ properties: props });
      var path = null;
      if (typeof result === 'string') path = result;
      else if (result && Array.isArray(result.filePaths) && result.filePaths.length) path = result.filePaths[0];
      else if (result && result.filePath) path = result.filePath;
      else if (Array.isArray(result) && result.length) path = result[0];
      if (path) {
        $(targetId).value = path;
        refreshDriveMatch(targetId === 'destDir' ? 'dest' : 'source');
      }
      /* Cancelled dialog = do nothing, wizard stays open. */
    } catch (e) {
      toast('Browse failed', e && e.message ? e.message : 'Could not open the folder picker.', 'error');
    }
  }
  async function createJob() {
    var job = collectJob();
    if (!job.name || !job.source || !job.destination) { toast('Missing information', 'Job name, source and destination are all required.', 'error'); return; }
    if (!api || typeof api.saveJobConfig !== 'function') { toast('Save unavailable', 'Save API is not available.', 'error'); return; }
    $('createBtn').disabled = true;
    $('createBtn').textContent = 'Creating…';
    try {
      await api.saveJobConfig(job);
      if (job.encryptionEnabled) {
        var pw = $('encPassword').value;
        if (pw && typeof api.vaultStoreJobPassword === 'function') {
          try {
            var stored = await api.vaultStoreJobPassword(job.id, pw);
            if (!stored || stored.success === false) {
              toast('Vault is locked', 'Job saved, but the password was not stored: unlock or set up the master password in Settings so scheduled encrypted backups can run.', 'warning');
            }
          } catch (e) {}
        } else if (!pw && !hasSavedPassword) {
          toast('No password saved', 'Job saved, but no password was stored: unlock or set up the master password in Settings so scheduled encrypted backups can run.', 'warning');
        }
      }
      if (typeof api.refreshJobs === 'function') { try { await api.refreshJobs(); } catch (e) {} }
      toast('Job created', job.name + ' has been saved.', 'success');
      setTimeout(function () { closeWizard(); }, 500);
    } catch (e) {
      toast('Create failed', e && e.message ? e.message : 'Could not save the job.', 'error');
      $('createBtn').disabled = false;
      $('createBtn').textContent = 'Create Job';
    }
  }
  function closeWizard() {
    if (api && typeof api.closeJobWizard === 'function') { api.closeJobWizard(); }
  }
  async function loadExisting() {
    if (!api) return;
    try {
      if (typeof api.getSettings === 'function') {
        var s = await api.getSettings();
        if (s && typeof s === 'object') {
          applyTheme(s.theme || 'dark');
          if (s.compress === false) $('optCompress').checked = false;
          if (s.verify === false) $('optVerify').checked = false;
          if (s.allowIncremental === false) $('optIncremental').checked = false;
        }
      }
      if (typeof api.getJobConfig === 'function') {
        var cfg = await api.getJobConfig(editing && editing.id);
        if (cfg && typeof cfg === 'object' && (cfg.name || cfg.source)) {
          var keepId = editing && editing.id;
          editing = cfg;
          if (keepId) editing.id = keepId;
          $('wizardTitle').textContent = 'Edit Backup Job';
          $('jobName').value = cfg.name || cfg.jobName || '';
          $('sourceDir').value = cfg.source || cfg.sourceDirectory || '';
          $('destDir').value = cfg.destination || cfg.destinationDirectory || '';
          if (cfg.sourceDriveMatch && cfg.sourceDriveMatch.mode) setMatchMode('source', cfg.sourceDriveMatch.mode);
          if (cfg.destinationDriveMatch && cfg.destinationDriveMatch.mode) setMatchMode('dest', cfg.destinationDriveMatch.mode);
          refreshDriveMatch('source');
          refreshDriveMatch('dest');
          if (Array.isArray(cfg.includePatterns)) { patterns = cfg.includePatterns.slice(); renderChips(); }
          if (cfg.allowIncremental === false) $('optIncremental').checked = false;
          if (cfg.compress === false) $('optCompress').checked = false;
          if (cfg.verify === false) $('optVerify').checked = false;
          if (cfg.encryptionEnabled === true) {
            $('optEncrypt').checked = true;
            $('encFields').style.display = 'block';
            updateEncNote();
            if (typeof api.vaultHasJobPassword === 'function') {
              try {
                var hp = await api.vaultHasJobPassword(editing.id);
                if (hp && hp.has) { hasSavedPassword = true; $('encVaultNote').style.display = 'block'; }
              } catch (e) {}
            }
          }
        }
      }
    } catch (e) { /* start with a blank job */ }
  }

  // Wire the buttons as soon as this script runs: it sits at the end of
  // <body>, so all buttons already exist. Relying only on DOMContentLoaded
  // left the wizard dead when the event had already fired / was missed.
  function updateEncNote() {
    var note = $('encModeNote'); if (!note) return;
    note.innerHTML = '';
    var b = document.createElement('strong');
    b.textContent = $('optCompress').checked ? 'Compression + encryption: ' : 'Encryption only: ';
    var s = document.createElement('span');
    s.textContent = $('optCompress').checked
      ? 'files are compressed and then encrypted (AES-256).'
      : 'files are stored uncompressed inside the encrypted ZIP (AES-256) — same files, just protected.';
    note.appendChild(b); note.appendChild(s);
  }
  function wireWizard() {
    if (wireWizard.done) return; wireWizard.done = true;
    function on(id, ev, fn) { var el = $(id); if (el) el.addEventListener(ev, fn); }
    on('browseSource', 'click', function () { pickFolder('sourceDir', true); });
    on('browseDest', 'click', function () { pickFolder('destDir'); });
    on('sourceDir', 'change', function () { refreshDriveMatch('source'); });
    on('destDir', 'change', function () { refreshDriveMatch('dest'); });
    on('addPatternBtn', 'click', addPattern);
    on('patternInput', 'keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); addPattern(); } });
    on('optSchedule', 'change', function (ev) { $('scheduleFields').style.display = ev.target.checked ? 'block' : 'none'; });
    on('optEncrypt', 'change', function (ev) { $('encFields').style.display = ev.target.checked ? 'block' : 'none'; if (ev.target.checked) updateEncNote(); });
    on('optCompress', 'change', function () { if ($('optEncrypt').checked) updateEncNote(); });
    on('nextBtn', 'click', function () { if (validateStep(step)) showStep(Math.min(5, step + 1)); });
    on('backBtn', 'click', function () { showStep(Math.max(1, step - 1)); });
    on('createBtn', 'click', createJob);
    on('cancelBtn', 'click', closeWizard);
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') closeWizard(); });
    loadExisting().catch(function(e) { /* ignore async errors on initial load */ });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireWizard);
  else wireWizard();
})();
