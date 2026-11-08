/* VaultGuard front-end: charts, upload flow, small UI helpers. No browser storage is used. */
(function () {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  const fmtSize = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';

  /* ---------- sidebar, confirms, copy ---------- */
  const toggle = $('#sidebarToggle');
  if (toggle) toggle.addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  document.addEventListener('submit', (e) => {
    const msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) e.preventDefault();
  });
  document.querySelectorAll('[data-copy]').forEach((btn) => btn.addEventListener('click', () => {
    const text = $(btn.dataset.copy).textContent.trim();
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(
      () => { btn.innerHTML = '<i class="bi bi-check2"></i> Copied'; }, () => { btn.textContent = 'Select the code and copy it manually'; });
  }));
  document.querySelectorAll('.risk-meter').forEach((m) => {
    const score = Math.max(0, Math.min(100, Number(m.dataset.score) || 0));
    requestAnimationFrame(() => { m.querySelector('.marker').style.left = `calc(${score}% - 2px)`; });
  });

  /* ---------- charts ---------- */
  const dataEl = $('#chart-data');
  if (window.Chart && dataEl) {
    const D = JSON.parse(dataEl.textContent);
    Chart.defaults.color = '#8ea3c6';
    Chart.defaults.font.family = "'Sora', system-ui, sans-serif";
    Chart.defaults.borderColor = 'rgba(70,140,255,.12)';
    const C = { blue: '#2f6bff', cyan: '#19e3ff', green: '#2ee6a6', amber: '#ffb84d', red: '#ff4d6d', violet: '#8b7bff' };
    const palette = [C.blue, C.cyan, C.violet, C.amber, C.red, C.green, '#5ad1ff', '#ff8ad8'];
    const mk = (id, cfg) => { const el = document.getElementById(id); return el ? new Chart(el, cfg) : null; };
    const noLegendGrid = { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } };

    if (D.activity) {
      mk('activityChart', { type: 'bar', data: { labels: D.activity.labels, datasets: [
        { label: 'Normal events', data: D.activity.normal, backgroundColor: C.blue, borderRadius: 6, stack: 's' },
        { label: 'Alerts', data: D.activity.alerts, backgroundColor: C.red, borderRadius: 6, stack: 's' }] },
        options: { maintainAspectRatio: false, scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
          plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } } } });
    }
    if (D.risk && document.getElementById('riskChart')) {          // user dashboard
      if (!D.risk.values.length) { document.getElementById('riskChart').parentElement.hidden = true; $('#riskEmpty').hidden = false; }
      else mk('riskChart', { type: 'doughnut', data: { labels: D.risk.labels, datasets: [{ data: D.risk.values, backgroundColor: palette, borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: '68%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } } } });
    }
    if (D.storage) {
      if (!D.storage.values.length) { document.getElementById('storageChart').parentElement.hidden = true; $('#storageEmpty').hidden = false; }
      else mk('storageChart', { type: 'bar', data: { labels: D.storage.labels, datasets: [{ data: D.storage.values, backgroundColor: C.cyan, borderRadius: 8 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: noLegendGrid } });
    }
    if (typeof D.score === 'number') {                              // risk monitor gauge
      const col = D.score < 30 ? C.green : D.score < 60 ? C.amber : C.red;
      mk('riskGauge', { type: 'doughnut', data: { datasets: [{ data: [D.score, 100 - D.score], backgroundColor: [col, 'rgba(70,140,255,.12)'], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, rotation: -90, circumference: 180, cutout: '78%', plugins: { legend: { display: false }, tooltip: { enabled: false } } } });
    }
    if (D.levels) {                                                 // admin
      mk('adminRiskChart', { type: 'doughnut', data: { labels: Object.keys(D.levels), datasets: [{ data: Object.values(D.levels), backgroundColor: [C.green, C.amber, C.red], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: '66%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } } } });
      mk('adminEventChart', { type: 'bar', data: { labels: D.events.labels, datasets: [{ data: D.events.values, backgroundColor: C.blue, borderRadius: 6 }] },
        options: { indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } } } });
    }
  }

  /* ---------- upload ---------- */
  const zone = $('#dropzone');
  if (!zone) return;
  const input = $('#fileInput'), form = $('#uploadForm'), submit = $('#submitBtn'), errBox = $('#uploadError');
  const allowed = zone.dataset.allowed.split(','), maxBytes = Number(zone.dataset.maxMb) * 1048576;
  const showError = (m) => { errBox.innerHTML = '<i class="bi bi-shield-exclamation"></i><span></span>'; errBox.lastChild.textContent = m; errBox.hidden = false; };

  function setFile(file) {
    errBox.hidden = true;
    if (!file) { $('#fileChip').hidden = true; submit.disabled = true; return; }
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!allowed.includes(ext)) { input.value = ''; $('#fileChip').hidden = true; submit.disabled = true; return showError('.' + ext + ' files are not allowed. Allowed: ' + allowed.join(', ').toUpperCase()); }
    if (file.size > maxBytes) { input.value = ''; $('#fileChip').hidden = true; submit.disabled = true; return showError('File is larger than ' + zone.dataset.maxMb + ' MB.'); }
    if (file.size === 0) { input.value = ''; submit.disabled = true; return showError('The file is empty.'); }
    $('#fileName').textContent = file.name; $('#fileSize').textContent = fmtSize(file.size); $('#fileType').textContent = '.' + ext + ' · ' + (file.type || 'unknown type');
    $('#fileChip').hidden = false; submit.disabled = false;
  }
  $('#chooseBtn').addEventListener('click', (e) => { e.stopPropagation(); input.click(); });
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  input.addEventListener('click', (e) => e.stopPropagation());
  input.addEventListener('change', () => setFile(input.files[0]));
  $('#clearBtn').addEventListener('click', () => { input.value = ''; setFile(null); });
  ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('drag'); }));
  zone.addEventListener('drop', (e) => { if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; setFile(input.files[0]); } });

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!input.files.length) return showError('Choose a file first.');
    const bar = $('#progressBar'), wrap = $('#progressWrap'), label = $('#progressLabel');
    wrap.hidden = false; label.hidden = false; bar.style.width = '0%'; errBox.hidden = true; submit.disabled = true;
    submit.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Encrypting…';
    const xhr = new XMLHttpRequest();
    xhr.open('POST', form.action);
    xhr.setRequestHeader('X-CSRFToken', csrf());
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      const pct = Math.round(ev.loaded / ev.total * 100);
      bar.style.width = pct + '%';
      label.textContent = pct < 100 ? 'Uploading… ' + pct + '%' : 'Upload complete · encrypting with AES-256-GCM…';
    };
    xhr.onload = () => {
      let r = {}; try { r = JSON.parse(xhr.responseText); } catch (_) { }
      submit.innerHTML = '<i class="bi bi-shield-lock-fill"></i> Encrypt &amp; Upload';
      if (xhr.status === 200 && r.ok) {
        bar.style.width = '100%'; label.textContent = 'Encrypted and stored.';
        form.hidden = true; $('#successCard').hidden = false; $('#successMsg').textContent = r.message;
        $('#rFile').textContent = r.filename; $('#rVer').textContent = 'v' + r.version; $('#rSize').textContent = fmtSize(r.size) + ' → ' + fmtSize(r.encrypted_size) + ' encrypted';
        $('#rNonce').textContent = r.nonce; $('#rHash').textContent = r.sha256; $('#rInt').textContent = r.integrity === 'verified' ? 'Passed ✓' : 'FAILED';
      } else {
        wrap.hidden = true; label.hidden = true; submit.disabled = false;
        showError(r.error || (xhr.status === 413 ? 'File too large.' : 'Upload failed (HTTP ' + xhr.status + ').'));
      }
    };
    xhr.onerror = () => { submit.disabled = false; submit.innerHTML = '<i class="bi bi-shield-lock-fill"></i> Encrypt &amp; Upload'; showError('Network error. Please try again.'); };
    xhr.send(new FormData(form));
  });
})();
