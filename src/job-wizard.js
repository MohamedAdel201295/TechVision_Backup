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
    // Nothing picked yet: keep the three choices visible. Hiding the
    // field here used to be harmless (this only ran after a Browse),
    // but the match radios now call this too, and clicking one before
    // Browsing must not make the whole block vanish.
    if (!pathVal) return;
    if (!letter) { field.style.display = 'none'; return; }
    field.style.display = '';
    var p = isSrc ? 'sourceMatch' : 'destMatch';
    // The drive list comes from PowerShell and takes a moment: show
    // that the serial is being read instead of leaving the value blank
    // until the call returns.
    setText(p + 'Serial', '— reading…');
    var drives = [];
    try { if (api && typeof api.getDrives === 'function') drives = await api.getDrives() || []; } catch (e) { drives = []; }
    var info = null;
    for (var i = 0; i < drives.length; i++) {
      if (drives[i] && String(drives[i].letter || '').toUpperCase() === letter) { info = drives[i]; break; }
    }
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
    if (n === 3) {
      if ($('optSchedule').checked) {
        var f3 = document.querySelector('input[name="frequency"]:checked');
        if (f3 && f3.value === 'Custom' && !document.querySelector('input[name="customDay"]:checked')) {
          toast('Pick at least one day', 'A custom schedule needs at least one day selected.', 'warning');
          return false;
        }
      }
      return true;
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
  var DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  function scheduleSummary(s) {
    if (!s) return 'Manual only';
    var time = s.time || '02:00';
    if ((s.frequency || '') === 'Custom') {
      var days = Array.isArray(s.days) ? s.days : [];
      var names = days.map(function (d) { return DAY_NAMES[d] || ''; }).filter(Boolean);
      return 'Custom (' + (names.join(', ') || 'no days') + ') at ' + time;
    }
    return (s.frequency || 'Daily') + ' at ' + time;
  }
  function collectJob() {
    var freq = 'Daily';
    var checked = document.querySelector('input[name="frequency"]:checked');
    if (checked) freq = checked.value;
    var schedEnabled = $('optSchedule').checked;
    var sched = { enabled: schedEnabled, frequency: freq, time: $('scheduleTime').value || '02:00' };
    if (freq === 'Custom') {
      sched.days = Array.prototype.map.call(document.querySelectorAll('input[name="customDay"]:checked'), function (c) { return parseInt(c.value, 10); });
    }
    var levelRadio = document.querySelector('input[name="compressLevel"]:checked');
    var level = levelRadio && levelRadio.value === 'advanced' ? 'advanced' : 'standard';
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
      compression: $('optCompress').checked ? level : 'none',
      encryptionEnabled: $('optEncrypt').checked,
      verify: $('optVerify').checked,
      use_vss: false,
      schedule: sched,
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
      ['Compress with ZIP', j.compress ? (j.compression === 'advanced' ? 'Yes — Advanced (Deflate level 9)' : 'Yes — Standard (Deflate level 6)') : 'No'],
      ['Encryption', j.encryptionEnabled ? 'AES-256' + (j.compress ? ' (compression + encryption)' : ' (encryption only, files stored uncompressed)') : 'Off'],
      ['Verify after backup', j.verify ? 'Yes' : 'No'],
      ['Schedule', j.schedule.enabled ? scheduleSummary(j.schedule) : 'Manual only']
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
      // The main process returns { success:false } on a failed save
      // instead of throwing — the old code ignored the return value
      // and toasted "Job created" for a job that was never saved.
      var saved = await api.saveJobConfig(job);
      if (saved && saved.success === false) {
        toast('Save failed', saved.error ? ('Could not save the job: ' + saved.error) : 'Could not save the job.', 'error');
        $('createBtn').disabled = false;
        $('createBtn').textContent = createBtnLabel();
        return;
      }
      if (job.encryptionEnabled) {
        var pw = $('encPassword').value;
        if (pw && typeof api.vaultStoreJobPassword === 'function') {
          try {
            var stored = await api.vaultStoreJobPassword(job.id, pw);
            if (!stored || stored.success === false) {
              // No master key yet: offer to create one — the retry
              // stores the same password so scheduled encrypted
              // backups of this job can run. Skipping keeps the job
              // usable for manual runs, which ask for the password.
              var noVault = false;
              try { noVault = !(await window.__vaultExists()); } catch (e) {}
              if (noVault && typeof window.__askCreateMasterKey === 'function') {
                window.__askCreateMasterKey('the backup password', async function () {
                  try {
                    var retry = await api.vaultStoreJobPassword(job.id, pw);
                    if (retry && retry.success) toast('Password saved', 'The backup password is now saved in the vault.', 'success');
                    else toast('Password not saved', 'Job saved, but the password was not stored' + ((retry && retry.error) ? ': ' + retry.error : '.') + ' Manual runs will ask for the password.', 'warning');
                  } catch (e) {}
                }, function () {
                  toast('Password not saved', 'Job saved, but the password was not stored. Manual runs will ask for the password; create a master password later to save it for scheduled runs.', 'warning');
                });
              } else {
                // The vault exists but is locked (or the store failed
                // for another reason): offer the unlock modal on
                // demand — the old toast pointed at Settings →
                // Security, where no Unlock button ever existed.
                // Skipping keeps the job usable for manual runs.
                var offered = false;
                try {
                  if (typeof window.__offerVaultUnlockThen === 'function') {
                    offered = await window.__offerVaultUnlockThen(async function () {
                      try {
                        var retry2 = await api.vaultStoreJobPassword(job.id, pw);
                        if (retry2 && retry2.success) toast('Password saved', 'The backup password is now saved in the vault.', 'success');
                        else toast('Password not saved', 'Job saved, but the password was not stored. Manual runs will ask for the password.', 'warning');
                      } catch (e) {}
                    }, 'Unlock the vault to save the backup password for this job.');
                  }
                } catch (e) {}
                if (!offered) toast('Password not saved', 'Job saved, but the password was not stored. Manual runs will ask for the password.', 'warning');
              }
            }
          } catch (e) {}
        } else if (!pw && !hasSavedPassword) {
          toast('No password saved', 'Job saved, but no backup password was stored. Manual runs will ask for the password each time; scheduled runs need a saved password.', 'warning');
        }
      }
      if (typeof api.refreshJobs === 'function') { try { await api.refreshJobs(); } catch (e) {} }
      toast('Job created', job.name + ' has been saved.', 'success');
      setTimeout(function () { closeWizard(); }, 500);
    } catch (e) {
      toast('Create failed', e && e.message ? e.message : 'Could not save the job.', 'error');
      $('createBtn').disabled = false;
      $('createBtn').textContent = createBtnLabel();
    }
  }
  function closeWizard() {
    /* In-place wizard: closing means going back to the view it was
       opened from (Dashboard or Jobs) — there is no separate window
       any more. The old closeJobWizard IPC is kept as a fallback. */
    if (typeof window.__closeWizardView === 'function') { window.__closeWizardView(); return; }
    if (api && typeof api.closeJobWizard === 'function') { api.closeJobWizard(); }
  }
  /* The footer button (and the step-5 note) say "Save changes" when an
     existing job is being edited and "Create Job" for a new job
     (round 3). `editing` is set by loadExisting once the pending job
     loads, so the label is applied there and reset here. */
  function createBtnLabel() { return editing ? 'Save changes' : 'Create Job'; }
  function applyCreateLabel() {
    var btn = $('createBtn'); if (btn) btn.textContent = createBtnLabel();
    var note = $('reviewNote');
    if (note) note.innerHTML = editing
      ? '<strong>Ready?</strong> Click <strong>Save changes</strong> to save your changes to this job.'
      : '<strong>Ready?</strong> Click <strong>Create Job</strong> to save this job. You can run it right away from the Dashboard.';
  }
  /* Reset the wizard to a blank new job (or the pending edit job) and
     show step 1. Called every time the wizard view opens — the old
     separate window reloaded its page on every open, so this is the
     in-place equivalent of that fresh start. Exposed for renderer.js. */
  function resetWizard() {
    step = 1; patterns = []; editing = null; hasSavedPassword = false;
    $('wizardTitle').textContent = 'New Backup Job';
    $('jobName').value = 'My Backup';
    $('jobNameError').classList.remove('show');
    $('sourceDir').value = ''; $('sourceError').classList.remove('show');
    $('destDir').value = ''; $('destError').classList.remove('show');
    $('patternInput').value = ''; renderChips();
    setMatchMode('source', 'label'); setMatchMode('dest', 'label');
    setText('sourceMatchLabel', ''); setText('sourceMatchLetter', ''); setText('sourceMatchSerial', '');
    setText('destMatchLabel', ''); setText('destMatchLetter', ''); setText('destMatchSerial', '');
    var smf = $('sourceMatchField'); if (smf) smf.style.display = '';
    var dmf = $('destMatchField'); if (dmf) dmf.style.display = '';
    $('optIncremental').checked = true;
    $('optCompress').checked = true;
    var clf = $('compressLevelField'); if (clf) clf.style.display = '';
    var std = document.querySelector('input[name="compressLevel"][value="standard"]'); if (std) std.checked = true;
    $('optVerify').checked = true;
    $('optSchedule').checked = false;
    $('scheduleFields').style.display = 'none';
    var daily = document.querySelector('input[name="frequency"][value="Daily"]'); if (daily) daily.checked = true;
    $('customDaysField').style.display = 'none';
    document.querySelectorAll('input[name="customDay"]').forEach(function (c) { c.checked = false; });
    $('scheduleTime').value = '02:00';
    $('optEncrypt').checked = false;
    $('encFields').style.display = 'none';
    $('encPassword').value = ''; $('encPasswordConfirm').value = '';
    $('encPasswordError').classList.remove('show');
    $('encPasswordConfirmError').classList.remove('show');
    var evn = $('encVaultNote'); if (evn) evn.style.display = 'none';
    $('reviewBox').innerHTML = '';
    $('createBtn').disabled = false; applyCreateLabel();
    showStep(1);
    loadExisting().catch(function () { /* start blank */ });
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
          applyCreateLabel();
          $('jobName').value = cfg.name || cfg.jobName || '';
          $('sourceDir').value = cfg.source || cfg.sourceDirectory || '';
          $('destDir').value = cfg.destination || cfg.destinationDirectory || '';
          if (cfg.sourceDriveMatch && cfg.sourceDriveMatch.mode) setMatchMode('source', cfg.sourceDriveMatch.mode);
          if (cfg.destinationDriveMatch && cfg.destinationDriveMatch.mode) setMatchMode('dest', cfg.destinationDriveMatch.mode);
          refreshDriveMatch('source');
          refreshDriveMatch('dest');
          if (Array.isArray(cfg.includePatterns)) { patterns = cfg.includePatterns.slice(); renderChips(); }
          if (cfg.allowIncremental === false) $('optIncremental').checked = false;
          if (cfg.compress === false) { $('optCompress').checked = false; var clf = $('compressLevelField'); if (clf) clf.style.display = 'none'; }
          if (cfg.compression === 'advanced') { var adv = document.querySelector('input[name="compressLevel"][value="advanced"]'); if (adv) adv.checked = true; }
          if (cfg.schedule && cfg.schedule.enabled) {
            $('optSchedule').checked = true;
            $('scheduleFields').style.display = 'block';
            if (cfg.schedule.frequency) { var fr = document.querySelector('input[name="frequency"][value="' + cfg.schedule.frequency + '"]'); if (fr) fr.checked = true; }
            if (cfg.schedule.time) $('scheduleTime').value = cfg.schedule.time;
            if (cfg.schedule.frequency === 'Custom' && Array.isArray(cfg.schedule.days)) {
              $('customDaysField').style.display = 'block';
              cfg.schedule.days.forEach(function (d) { var cb = document.querySelector('input[name="customDay"][value="' + d + '"]'); if (cb) cb.checked = true; });
            }
          }
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
    // Picking a match radio re-reads the drive right away, so the
    // serial (or name/letter) shows the moment the user selects it —
    // the old code only refreshed on Browse/change, so the serial
    // stayed blank until the user left the step and came back.
    document.querySelectorAll('input[name="sourceMatch"]').forEach(function (r) { r.addEventListener('change', function () { refreshDriveMatch('source'); }); });
    document.querySelectorAll('input[name="destMatch"]').forEach(function (r) { r.addEventListener('change', function () { refreshDriveMatch('dest'); }); });
    document.querySelectorAll('input[name="frequency"]').forEach(function (r) { r.addEventListener('change', function () { $('customDaysField').style.display = r.value === 'Custom' ? 'block' : 'none'; }); });
    on('addPatternBtn', 'click', addPattern);
    on('patternInput', 'keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); addPattern(); } });
    on('optSchedule', 'change', function (ev) { $('scheduleFields').style.display = ev.target.checked ? 'block' : 'none'; });
    on('optEncrypt', 'change', function (ev) { $('encFields').style.display = ev.target.checked ? 'block' : 'none'; if (ev.target.checked) updateEncNote(); });
    on('optCompress', 'change', function () { var clf = $('compressLevelField'); if (clf) clf.style.display = $('optCompress').checked ? '' : 'none'; if ($('optEncrypt').checked) updateEncNote(); });
    on('nextBtn', 'click', function () { if (validateStep(step)) showStep(Math.min(5, step + 1)); });
    on('backBtn', 'click', function () { showStep(Math.max(1, step - 1)); });
    on('createBtn', 'click', createJob);
    on('cancelBtn', 'click', closeWizard);
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { var v = $('view-wizard'); if (v && v.style.display !== 'none') closeWizard(); } });
    loadExisting().catch(function(e) { /* ignore async errors on initial load */ });
  }
  /* In-place wizard: renderer.js opens this view and calls reset(). */
  window.__jobWizard = { reset: resetWizard };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireWizard);
  else wireWizard();
})();
