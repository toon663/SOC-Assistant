const state = { incidents: [] };

function selectedSeverities() {
  return new Set([...document.querySelectorAll('#severity-filter input:checked')].map((box) => box.value));
}
const $ = (selector) => document.querySelector(selector);

function setApiStatus(online, text) {
  const pill = $('.connection-pill');
  pill.classList.toggle('online', online);
  pill.classList.toggle('offline', !online);
  $('#status-text').textContent = text;
}

function formatDate(value) {
  if (!value) return 'Unknown time';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function riskScore(incident) {
  return Number(incident.forecast?.forecast_score ?? incident.risk_analysis?.risk_score ?? 0);
}

function occurrenceCount(incident) {
  return Number(incident.alert?.occurrence_count ?? incident.events?.length ?? 1);
}

function renderMetrics() {
  const incidents = state.incidents;
  $('#incident-count').textContent = incidents.length;
  $('#high-risk-count').textContent = incidents.filter((item) => riskScore(item) >= 65 && item.action_result?.status !== 'resolved').length;
  $('#contained-count').textContent = incidents.filter((item) => ['executed', 'contained', 'resolved'].includes(item.action_result?.status)).length;
  $('#approval-count').textContent = incidents.filter((item) => item.action_result?.status === 'approval_required').length;
}

function renderIncidents() {
  const list = $('#incident-list');
  const search = $('#incident-search').value.trim().toLowerCase();
  const severities = selectedSeverities();
  const statusFilter = $('#status-filter').value;
  const incidents = state.incidents.filter((incident) => {
    const status = incident.action_result?.status || 'open';
    const event = incident.events?.[0] || {};
    const searchable = [incident.incident_id, incident.alert?.title, event.event_type, event.host, event.user].join(' ').toLowerCase();
    const statusMatch = statusFilter === 'active' ? status !== 'resolved' : (!statusFilter || status === statusFilter);
    return (!search || searchable.includes(search)) && severities.has(event.severity) && statusMatch;
  });
  if (!incidents.length) {
    list.innerHTML = '<div class="empty-state">No matching incidents found.</div>';
    return;
  }
  list.innerHTML = incidents.map((incident) => {
    const status = incident.action_result?.status || 'open';
    const title = incident.alert?.title || incident.events?.[0]?.event_type || 'Security incident';
    const event = incident.events?.[0] || {};
    const score = Math.round(riskScore(incident));
    const severity = event.severity || 'unknown';
    const count = occurrenceCount(incident);
    const countBadge = count > 1 ? `<span class="count-badge" title="${count} occurrences">×${count}</span>` : '';
    const lastSeen = count > 1 ? ` · last seen ${escapeHtml(formatDate(incident.alert?.last_seen))}` : '';
    return `<article class="incident-row" tabindex="0" role="button" data-incident-id="${escapeHtml(incident.incident_id)}"><div><div class="incident-title">${escapeHtml(title)}${countBadge}</div><div class="incident-meta">${escapeHtml(event.host || 'Unknown host')} · ${formatDate(incident.detected_at)}${lastSeen} · ${escapeHtml(incident.incident_id.slice(0, 10))}</div></div><div class="incident-right"><span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong class="risk-score">${score}<small>/100</small></strong><div class="risk-bar"><span style="width: ${Math.min(score, 100)}%"></span></div></div></article>`;
  }).join('');
  list.querySelectorAll('[data-incident-id]').forEach((row) => {
    row.addEventListener('click', () => openDrawer(row.dataset.incidentId));
    row.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') openDrawer(row.dataset.incidentId); });
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
}

async function checkHealth() {
  try {
    const response = await fetch('/health');
    if (!response.ok) throw new Error('Health check failed');
    setApiStatus(true, 'API connected');
  } catch (error) {
    setApiStatus(false, 'API unavailable');
  }
}

async function loadIncidents() {
  try {
    const response = await fetch('/incidents?limit=100');
    if (!response.ok) throw new Error(`Request failed: ${response.status}`);
    state.incidents = await response.json();
    renderMetrics();
    renderIncidents();
  } catch (error) {
    $('#incident-list').innerHTML = '<div class="empty-state">Could not load incidents. Start the API and try again.</div>';
  }
}

async function submitEvent(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const message = $('#form-message');
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  message.className = 'form-message';
  message.textContent = 'Running investigation…';
  try {
    const data = Object.fromEntries(new FormData(form).entries());
    const response = await fetch('/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ events: [{ event_id: `manual-${Date.now()}`, ...data }] }) });
    const raw = await response.text();
    let result;
    try { result = raw ? JSON.parse(raw) : {}; } catch { result = {}; }
    if (!response.ok) throw new Error(result.detail || `Server error (${response.status}). Check the API console.`);
    message.className = 'form-message success';
    message.textContent = `Incident created. Status: ${result.action_result?.status || 'open'}`;
    form.reset();
    await loadIncidents();
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
}

async function collectEvents(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const message = $('#collect-message');
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  message.className = 'form-message';
  message.textContent = 'Collecting events and training the detector…';
  try {
    const data = new FormData(form);
    const response = await fetch('/ingest/windows', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ hours: Number(data.get('hours')), max_events_per_log: Number(data.get('max_events_per_log')) }) });
    const raw = await response.text();
    let result;
    try { result = raw ? JSON.parse(raw) : {}; } catch { result = {}; }
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Server error (${response.status}). Check the API console.`);
    const merged = result.incidents.filter((item) => item.merged).length;
    const scan = result.malware_scan || {};
    const malware = scan.files_scanned ? ` Scanned ${scan.files_scanned} executables: ${result.malware_detected} flagged as malware.` : '';
    const summary = `Scanned ${result.events_scanned} events: ${result.anomalies_detected} anomalies, ${result.incidents.length - merged} new incidents, ${merged} updated with repeats, ${result.duplicates_skipped} events already seen${result.duplicates_in_resolved ? ` (${result.duplicates_in_resolved} already resolved)` : ''}.${malware}`;
    const skipped = result.errors.map((item) => `${item.logName}: ${item.message}`).join(' ');
    message.className = `form-message ${skipped ? 'warning' : 'success'}`;
    message.textContent = skipped ? `${summary} Not collected, ${skipped}` : summary;
    await loadIncidents();
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
}

const MAX_SCAN_BYTES = 128 * 1024 * 1024;

async function loadScanStatus() {
  try {
    const response = await fetch('/scan/status');
    const status = await response.json();
    $('#scan-badge').textContent = status.available ? `Sentinel → LightGBM · ${status.family_classes - 1} families` : 'Scanner unavailable';
    if (!status.available) {
      $('#scan-message').className = 'form-message warning';
      $('#scan-message').textContent = status.detail || 'Malware models are not installed.';
    }
  } catch {
    $('#scan-badge').textContent = 'Scanner unavailable';
  }
}

function percent(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function renderScanResult(result) {
  const scan = result.scan || {};
  const container = $('#scan-result');
  const verdict = scan.verdict || 'unknown';
  const candidates = (scan.family_candidates || []).map((item) => `${item.family} ${percent(item.probability)}`).join(', ');
  const cutoff = percent(scan.family_min_probability ?? 0.75);
  let family = 'Not classified (file is clean)';
  if (scan.family) family = `${scan.family} (${percent(scan.family_probability)})`;
  else if (candidates) family = `Uncertain: below ${cutoff} confidence`;
  const explanation = scan.explanation || {};
  const drivers = (items) => items.map((item) => item.feature_group).join(', ') || 'None';
  const tactics = scan.family_profile?.tactics?.join(', ');
  const techniques = (scan.family_profile?.techniques || []).map((item) => `${item.id} ${item.name}`).join(', ');
  const score = scan.score == null ? 'n/a' : Number(scan.score).toFixed(4);
  let incident = 'None opened (clean or unsupported file)';
  const incidentId = result.incident?.incident_id || result.incident_id;
  if (result.incident) incident = `${result.incident.title} · ${String(result.incident.status || '').replaceAll('_', ' ')}`;
  else if (result.already_reported) incident = 'Already reported for this host';
  const rows = [
    ['Verdict', `<span class="verdict ${escapeHtml(verdict)}">${escapeHtml(verdict)}</span>${scan.note ? ` · ${escapeHtml(scan.note)}` : ''}`],
    ['Malware score', `${escapeHtml(score)} <span class="incident-meta">(suspicious ≥ ${escapeHtml(scan.suspicious_threshold)}, malicious ≥ ${escapeHtml(scan.malicious_threshold)})</span>`],
    ['Family', escapeHtml(family)],
    ['Candidates', escapeHtml(candidates || '—')],
    ['Typical tactics', escapeHtml(tactics || '—')],
    ['Typical techniques', escapeHtml(techniques || '—')],
    ['Toward malicious', escapeHtml(drivers(explanation.toward_malicious || []))],
    ['Toward benign', escapeHtml(drivers(explanation.toward_benign || []))],
    ['File', escapeHtml(`${scan.file_name || 'unknown'} · ${Number(scan.size_bytes || 0).toLocaleString()} bytes`)],
    ['SHA-256', escapeHtml(scan.sha256 || '—')],
    ['Incident', escapeHtml(incident)],
  ];
  container.innerHTML = `<dl class="detail-grid">${rows.map(([label, value]) => `<dt>${label}</dt><dd>${value}</dd>`).join('')}</dl>${incidentId ? `<div class="scan-actions"><button class="text-button" type="button" data-open-incident="${escapeHtml(incidentId)}">Open incident →</button></div>` : ''}`;
  container.hidden = false;
  const open = container.querySelector('[data-open-incident]');
  if (open) open.addEventListener('click', () => openDrawer(open.dataset.openIncident));
}

async function scanFile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const message = $('#scan-message');
  const submitButton = form.querySelector('button[type="submit"]');
  const file = form.elements.file.files[0];
  if (!file) return;
  if (file.size > MAX_SCAN_BYTES) {
    message.className = 'form-message error';
    message.textContent = 'File is larger than 128 MB.';
    return;
  }
  submitButton.disabled = true;
  message.className = 'form-message';
  message.textContent = `Scanning ${file.name}…`;
  try {
    const params = new URLSearchParams({ filename: file.name, host: form.elements.host.value.trim() || 'uploaded-sample' });
    const response = await fetch(`/scan/upload?${params}`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file });
    const raw = await response.text();
    let result;
    try { result = raw ? JSON.parse(raw) : {}; } catch { result = {}; }
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Server error (${response.status}). Check the API console.`);
    message.className = 'form-message success';
    message.textContent = `Scanned ${file.name}.`;
    await loadIncidents();
    renderScanResult(result);
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
}

const live = { status: null, changes: null };

function timeOnly(value) {
  return value ? new Date(value).toLocaleTimeString() : '—';
}

function renderLive(status) {
  live.status = status;
  const button = $('#live-toggle');
  button.textContent = status.running ? 'Stop live detection' : 'Start live detection';
  button.classList.toggle('running', status.running);
  const t = status.totals || {};
  const totals = `${t.events || 0} events, ${t.anomalies || 0} anomalies, ${t.malware || 0} malware, ${t.incidents_opened || 0} new incidents, ${t.incidents_updated || 0} updated`;
  const problems = [
    ...(status.log_errors || []).map((item) => `${item.logName} not collected: ${item.message}`),
    ...(status.last_error ? [`Last poll failed: ${status.last_error}`] : []),
  ];
  const warning = problems.length ? `<br><span class="warn">${escapeHtml(problems.join(' · '))}</span>` : '';
  let text;
  if (status.running) {
    text = `<span class="live-dot"></span>Live since ${escapeHtml(timeOnly(status.started_at))} · checking every ${status.interval_seconds}s · last check ${escapeHtml(timeOnly(status.last_poll_at))} · ${status.polls} checks · ${escapeHtml(totals)}`;
  } else if (status.started_at) {
    text = `Live detection is off. Last run from ${escapeHtml(timeOnly(status.started_at))}: ${status.polls} checks, ${escapeHtml(totals)}.`;
  } else {
    text = 'Live detection is off. When on, this host is checked for new events every 30 seconds.';
  }
  $('#live-status').innerHTML = text + warning;
}

async function refreshLive() {
  try {
    const status = await (await fetch('/live/status')).json();
    const changes = (status.totals?.incidents_opened || 0) + (status.totals?.incidents_updated || 0);
    if (live.changes !== null && changes !== live.changes) await loadIncidents();
    live.changes = changes;
    renderLive(status);
  } catch {
    // The health pill already reports an unreachable API.
  }
}

async function toggleLive() {
  const button = $('#live-toggle');
  const starting = !live.status?.running;
  button.disabled = true;
  if (!starting) $('#live-status').textContent = 'Stopping after the current check…';
  try {
    const response = await fetch(starting ? '/live/start' : '/live/stop', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Server error (${response.status}).`);
    renderLive(result);
  } catch (error) {
    $('#live-status').innerHTML = `<span class="warn">${escapeHtml(error.message)}</span>`;
  } finally {
    button.disabled = false;
  }
}

async function devRequest(url, button, describe) {
  const message = $('#dev-message');
  button.disabled = true;
  message.className = 'form-message';
  message.textContent = 'Running…';
  try {
    const response = await fetch(url, { method: 'POST' });
    const raw = await response.text();
    let result;
    try { result = raw ? JSON.parse(raw) : {}; } catch { result = {}; }
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Server error (${response.status}).`);
    message.className = 'form-message success';
    message.textContent = describe(result);
    await loadIncidents();
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function loadDevStatus() {
  let status;
  try {
    status = await (await fetch('/dev/status')).json();
  } catch {
    return;
  }
  if (!status.enabled) return;
  $('#dev').hidden = false;
  $('#dev-nav').hidden = false;
  $('#dev-scenarios').innerHTML = status.scenarios.map((item) => `<button class="dev-button" type="button" data-scenario="${escapeHtml(item.name)}" title="${escapeHtml(item.description)}">${escapeHtml(item.title)}</button>`).join('');
  $('#dev-scenarios').querySelectorAll('[data-scenario]').forEach((button) => {
    button.addEventListener('click', () => devRequest(`/dev/scenarios/${encodeURIComponent(button.dataset.scenario)}`, button, (result) => {
      const opened = result.incidents.filter((item) => !item.merged).length;
      return `${button.textContent}: ${result.events_scanned} synthetic events, ${result.anomalies_detected} anomalies, ${opened} new incidents.`;
    }));
  });
  const samples = status.malware_samples || [];
  $('#dev-malware-sample').innerHTML = samples.length
    ? `<option value="">Random sample</option>${samples.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join('')}`
    : '<option value="">No demo vectors (run build_demo_vectors.py)</option>';
  $('#dev-malware-run').disabled = !samples.length;
  $('#dev-malware-run').addEventListener('click', (event) => {
    const sample = $('#dev-malware-sample').value;
    devRequest(`/dev/malware-demo?${new URLSearchParams({ sample })}`, event.currentTarget, (result) => {
      const scan = result.scan || {};
      const family = scan.family ? `${scan.family} (${percent(scan.family_probability)})` : 'family uncertain';
      return `Malware launch: ${scan.verdict}, ${family}, true family ${scan.true_family}. ${result.incident ? 'Incident opened.' : 'No incident.'}`;
    });
  });
  $('#dev-reset-events').addEventListener('click', (event) => {
    if (!confirm('Forget processed events? The next collection will re-report log records it has already seen.')) return;
    devRequest('/dev/reset?scope=events', event.currentTarget, (result) => `Forgot ${result.events_forgotten} processed events. Incidents were kept.`);
  });
  $('#dev-reset-all').addEventListener('click', (event) => {
    if (!confirm('Delete ALL incidents and audit records? This cannot be undone.')) return;
    devRequest('/dev/reset?scope=all', event.currentTarget, (result) => `Deleted ${result.incidents_deleted} incidents.`);
  });
}

function malwareDetails(incident) {
  const malware = incident.alert?.malware;
  if (!malware) return '';
  const family = malware.malware_family ? `${malware.malware_family} (${Math.round((malware.family_probability || 0) * 100)}%)` : 'Unknown family';
  const candidates = (malware.family_candidates || []).map((item) => `${item.family} ${Math.round(item.probability * 100)}%`).join(', ');
  return `<div class="detail-section"><span class="detail-label">Malware scan</span><dl class="detail-grid"><dt>Verdict</dt><dd>${escapeHtml(malware.verdict || 'Unknown')}</dd><dt>Family</dt><dd>${escapeHtml(family)}</dd><dt>Candidates</dt><dd>${escapeHtml(candidates || 'None')}</dd><dt>File</dt><dd>${escapeHtml(malware.file_path || malware.file_name || 'Unknown')}</dd><dt>SHA-256</dt><dd>${escapeHtml(malware.sha256 || '')}</dd><dt>Typical tactics</dt><dd>${escapeHtml((malware.attack_tactics || []).join(', ') || 'Not profiled')}</dd></dl></div>`;
}

function detectionDetails(incident) {
  const techniques = incident.alert?.mitre_techniques || [];
  const reasons = incident.alert?.detection_reasons || [];
  if (!techniques.length && !reasons.length) return '';
  return `${malwareDetails(incident)}<div class="detail-section"><span class="detail-label">MITRE ATT&amp;CK</span><p>${escapeHtml(techniques.join(', ') || 'No mapped techniques')}</p></div><div class="detail-section"><span class="detail-label">Detection reasons</span><p>${escapeHtml(reasons.join('; ') || 'Model score only')}</p></div>`;
}

function openDrawer(incidentId) {
  const incident = state.incidents.find((item) => item.incident_id === incidentId);
  if (!incident) return;
  const event = incident.events?.[0] || {};
  const status = incident.action_result?.status || 'open';
  const score = Math.round(riskScore(incident));
  const resolved = status === 'resolved';
  const resolveControl = resolved
    ? `<p class="resolved-note">Resolved ${escapeHtml(formatDate(incident.action_result?.resolved_at))}</p>`
    : `<button class="resolve-button" type="button" id="resolve-incident" data-incident-id="${escapeHtml(incident.incident_id)}">Mark as resolved ✓</button><div id="resolve-message" class="form-message" role="status"></div>`;
  $('#drawer-title').textContent = incident.alert?.title || event.event_type || 'Security incident';
  $('#drawer-content').innerHTML = `<div class="drawer-status"><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong>${score}/100 risk</strong></div><div class="drawer-actions">${resolveControl}</div><dl class="detail-grid"><dt>Incident ID</dt><dd>${escapeHtml(incident.incident_id)}</dd><dt>Detected</dt><dd>${escapeHtml(formatDate(incident.detected_at))}</dd><dt>Occurrences</dt><dd>${occurrenceCount(incident)}</dd><dt>First seen</dt><dd>${escapeHtml(formatDate(incident.alert?.first_seen))}</dd><dt>Last seen</dt><dd>${escapeHtml(formatDate(incident.alert?.last_seen))}</dd><dt>Event type</dt><dd>${escapeHtml(event.event_type || 'Unknown')}</dd><dt>Severity</dt><dd>${escapeHtml(event.severity || 'Unknown')}</dd><dt>User</dt><dd>${escapeHtml(event.user || 'Unknown')}</dd><dt>Host</dt><dd>${escapeHtml(event.host || 'Unknown')}</dd><dt>Source IP</dt><dd>${escapeHtml(event.source_ip || 'Unknown')}</dd></dl><div class="detail-section"><span class="detail-label">Analyst summary</span><p>${escapeHtml(incident.alert?.summary || event.message || 'No summary available.')}</p></div>${detectionDetails(incident)}<div class="detail-section"><span class="detail-label">Recommended playbook</span><p>${escapeHtml(incident.selected_playbook || 'Not assigned')}</p></div>`;
  const resolveButton = $('#resolve-incident');
  if (resolveButton) resolveButton.addEventListener('click', () => resolveIncident(resolveButton.dataset.incidentId, resolveButton));
  $('#incident-drawer').classList.add('open');
  $('#incident-drawer').setAttribute('aria-hidden', 'false');
}

async function resolveIncident(incidentId, button) {
  button.disabled = true;
  try {
    const response = await fetch(`/incidents/${encodeURIComponent(incidentId)}/resolve`, { method: 'POST' });
    if (!response.ok) throw new Error(`Could not resolve incident (${response.status}).`);
    closeDrawer();
    await loadIncidents();
  } catch (error) {
    $('#resolve-message').className = 'form-message error';
    $('#resolve-message').textContent = error.message;
    button.disabled = false;
  }
}

function closeDrawer() {
  $('#incident-drawer').classList.remove('open');
  $('#incident-drawer').setAttribute('aria-hidden', 'true');
}

// Manual event submission is disabled for now (see the commented-out panel in index.html).
// $('#event-form').addEventListener('submit', submitEvent);
$('#collect-form').addEventListener('submit', collectEvents);
$('#scan-form').addEventListener('submit', scanFile);
$('#refresh-button').addEventListener('click', async () => { await checkHealth(); await loadIncidents(); });
$('#refresh-incidents').addEventListener('click', loadIncidents);
$('#incident-search').addEventListener('input', renderIncidents);
function updateSeveritySummary() {
  const boxes = [...document.querySelectorAll('#severity-filter input')];
  const checked = boxes.filter((box) => box.checked).map((box) => box.parentElement.textContent.trim());
  $('#severity-summary').textContent = checked.length === boxes.length ? 'All severities' : (checked.join(', ') || 'No severities');
}

document.querySelectorAll('#severity-filter input').forEach((box) => box.addEventListener('change', () => { updateSeveritySummary(); renderIncidents(); }));
document.addEventListener('click', (event) => {
  const dropdown = $('#severity-dropdown');
  if (dropdown.open && !dropdown.contains(event.target)) dropdown.open = false;
});
$('#status-filter').addEventListener('change', renderIncidents);
$('#close-drawer').addEventListener('click', closeDrawer);
document.querySelector('[data-close-drawer]').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeDrawer(); });
checkHealth();
loadIncidents();
loadScanStatus();
loadDevStatus();
refreshLive();
$('#live-toggle').addEventListener('click', toggleLive);
// Live status is cheap; the incident list reloads only when a poll changed something.
setInterval(refreshLive, 5000);
setInterval(() => { checkHealth(); loadIncidents(); }, 30000);
