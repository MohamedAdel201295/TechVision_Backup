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
    $('nextBtn').style.display = n < 4 ? '' : 'none';
    $('createBtn').style.display = n === 4 ? '' : 'none';
    if (n === 4) renderReview();
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
      name: $('jobName').value.trim(),
      source: $('sourceDir').value.trim(),
      sourceDirectory: $('sourceDir').value.trim(),
      destination: $('destDir').value.trim(),
      destinationDirectory: $('destDir').value.trim(),
      includePatterns: patterns.slice(),
      allowIncremental: $('optIncremental').checked,
      compress: $('optCompress').checked,
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
      ['Destination', j.destination || '—'],
      ['Include patterns', j.includePatterns.length ? j.includePatterns.join(', ') : 'All files'],
      ['Incremental', j.allowIncremental ? 'Yes' : 'No'],
      ['Compress with ZIP', j.compress ? 'Yes' : 'No'],
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
  async function pickFolder(targetId) {
    if (!api || typeof api.showOpenDialog !== 'function') { toast('Browse unavailable', 'Folder picker API is not available.', 'error'); return; }
    try {
      var result = await api.showOpenDialog({ properties: ['openDirectory'] });
      var path = null;
      if (typeof result === 'string') path = result;
      else if (result && Array.isArray(result.filePaths) && result.filePaths.length) path = result.filePaths[0];
      else if (result && result.filePath) path = result.filePath;
      else if (Array.isArray(result) && result.length) path = result[0];
      if (path) { $(targetId).value = path; }
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
          editing = cfg;
          $('wizardTitle').textContent = 'Edit Backup Job';
          $('jobName').value = cfg.name || cfg.jobName || '';
          $('sourceDir').value = cfg.source || cfg.sourceDirectory || '';
          $('destDir').value = cfg.destination || cfg.destinationDirectory || '';
          if (Array.isArray(cfg.includePatterns)) { patterns = cfg.includePatterns.slice(); renderChips(); }
          if (cfg.allowIncremental === false) $('optIncremental').checked = false;
          if (cfg.compress === false) $('optCompress').checked = false;
          if (cfg.verify === false) $('optVerify').checked = false;
        }
      }
    } catch (e) { /* start with a blank job */ }
  }

  // Wire the buttons as soon as this script runs: it sits at the end of
  // <body>, so all buttons already exist. Relying only on DOMContentLoaded
  // left the wizard dead when the event had already fired / was missed.
  function wireWizard() {
    if (wireWizard.done) return; wireWizard.done = true;
    function on(id, ev, fn) { var el = $(id); if (el) el.addEventListener(ev, fn); }
    on('browseSource', 'click', function () { pickFolder('sourceDir'); });
    on('browseDest', 'click', function () { pickFolder('destDir'); });
    on('addPatternBtn', 'click', addPattern);
    on('patternInput', 'keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); addPattern(); } });
    on('optSchedule', 'change', function (ev) { $('scheduleFields').style.display = ev.target.checked ? 'block' : 'none'; });
    on('nextBtn', 'click', function () { if (validateStep(step)) showStep(Math.min(4, step + 1)); });
    on('backBtn', 'click', function () { showStep(Math.max(1, step - 1)); });
    on('createBtn', 'click', createJob);
    on('cancelBtn', 'click', closeWizard);
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') closeWizard(); });
    loadExisting().catch(function(e) { /* ignore async errors on initial load */ });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireWizard);
  else wireWizard();
})();
