const state = { incidents: [], activeIncidentId: null };
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

function renderMetrics() {
  const incidents = state.incidents;
  $('#incident-count').textContent = incidents.length;
  $('#high-risk-count').textContent = incidents.filter((item) => riskScore(item) >= 65).length;
  $('#contained-count').textContent = incidents.filter((item) => ['executed', 'contained', 'resolved'].includes(item.action_result?.status)).length;
  $('#approval-count').textContent = incidents.filter((item) => item.action_result?.status === 'approval_required').length;
}

function renderIncidents() {
  const list = $('#incident-list');
  const search = $('#incident-search').value.trim().toLowerCase();
  const severity = $('#severity-filter').value;
  const statusFilter = $('#status-filter').value;
  const incidents = state.incidents.filter((incident) => {
    const status = incident.action_result?.status || 'open';
    const event = incident.events?.[0] || {};
    const searchable = [incident.incident_id, incident.alert?.title, event.event_type, event.host, event.user].join(' ').toLowerCase();
    return (!search || searchable.includes(search)) && (!severity || event.severity === severity) && (!statusFilter || status === statusFilter);
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
    return `<article class="incident-row" tabindex="0" role="button" data-incident-id="${escapeHtml(incident.incident_id)}"><div><div class="incident-title">${escapeHtml(title)}</div><div class="incident-meta">${escapeHtml(event.host || 'Unknown host')} · ${formatDate(incident.detected_at)} · ${escapeHtml(incident.incident_id.slice(0, 10))}</div></div><div class="incident-right"><span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong class="risk-score">${score}<small>/100</small></strong><div class="risk-bar"><span style="width: ${Math.min(score, 100)}%"></span></div></div></article>`;
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

async function scanComputer() {
  const button = $('#scan-button');
  const message = $('#scan-message');
  button.disabled = true;
  message.className = 'form-message';
  message.textContent = 'Reading Windows Logs > Security and checking Sentinel rules...';
  $('#scan-results').replaceChildren();
  try {
    const response = await fetch('/scan', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || `Security log scan failed (${response.status}).`);
    const { snapshot, anomalies, incident } = result;
    message.className = 'form-message success';
    message.textContent = `${snapshot.host}: read ${snapshot.events.length} Security records; ${anomalies.length} finding(s) for review. ${snapshot.truncated ? `Limited to the newest ${snapshot.limit} records; older events were not analyzed.` : ''}`;
    for (const anomaly of anomalies) {
      const finding = document.createElement('p');
      finding.textContent = anomaly.message;
      $('#scan-results').appendChild(finding);
    }
    const records = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = `Security records read (${snapshot.events.length})`;
    records.appendChild(summary);
    for (const record of snapshot.events) {
      const item = document.createElement('details');
      const title = document.createElement('summary');
      title.textContent = `Event ${record.event_id} | Record ${record.record_id} | ${formatDate(record.timestamp)} | ${record.host}`;
      const fields = document.createElement('pre');
      fields.style.whiteSpace = 'pre-wrap';
      fields.textContent = JSON.stringify(record.data, null, 2);
      item.append(title, fields);
      records.appendChild(item);
    }
    $('#scan-results').appendChild(records);
    if (incident) await loadIncidents();
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function openDrawer(incidentId) {
  const incident = state.incidents.find((item) => item.incident_id === incidentId);
  if (!incident) return;
  state.activeIncidentId = incidentId;
  const event = incident.events?.[0] || {};
  const status = incident.action_result?.status || 'open';
  const score = Math.round(riskScore(incident));
  $('#drawer-title').textContent = incident.alert?.title || event.event_type || 'Security incident';
  $('#drawer-content').innerHTML = `<div class="drawer-status"><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong>${score}/100 risk</strong></div><dl class="detail-grid"><dt>Incident ID</dt><dd>${escapeHtml(incident.incident_id)}</dd><dt>Detected</dt><dd>${escapeHtml(formatDate(incident.detected_at))}</dd><dt>Event type</dt><dd>${escapeHtml(event.event_type || 'Unknown')}</dd><dt>Severity</dt><dd>${escapeHtml(event.severity || 'Unknown')}</dd><dt>User</dt><dd>${escapeHtml(event.user || 'Unknown')}</dd><dt>Host</dt><dd>${escapeHtml(event.host || 'Unknown')}</dd><dt>Source IP</dt><dd>${escapeHtml(event.source_ip || 'Unknown')}</dd></dl><div class="detail-section"><span class="detail-label">Analyst summary</span><p>${escapeHtml(incident.alert?.summary || event.message || 'No summary available.')}</p></div><div class="detail-section"><span class="detail-label">Recommended playbook</span><p>${escapeHtml(incident.selected_playbook || 'Not assigned')}</p></div>`;
  renderReview(incident);
  $('#incident-drawer').classList.add('open');
  $('#incident-drawer').setAttribute('aria-hidden', 'false');
}

function describeResponse(incident) {
  const event = incident.events?.[0] || {};
  if (incident.selected_playbook === 'contain_and_disable_user') return `Isolate endpoint ${event.host || 'Unknown'} and disable user ${event.user || 'Unknown'}.`;
  if (incident.selected_playbook === 'contain_endpoint') return `Isolate endpoint ${event.host || 'Unknown'}.`;
  return 'Monitor and investigate. No endpoint isolation or account disabling is proposed.';
}

function renderReview(incident) {
  const section = document.createElement('section');
  section.className = 'detail-section review-section';
  const approval = incident.action_result?.approval;
  if (incident.action_result?.status === 'approval_required') {
    section.innerHTML = `<h3>Human review</h3><p>${escapeHtml(describeResponse(incident))}</p><p class="review-note">Response actions are simulated. Reviewer names are recorded as entered in this local demo.</p><form id="decision-form"><label>Reviewer name<input name="reviewer" autocomplete="name" maxlength="200" required /></label><label>Reason for decision<textarea name="reason" rows="3" maxlength="2000" required></textarea></label><div class="review-actions"><button class="primary-button" type="submit" name="decision" value="approve">Approve response</button><button class="deny-button" type="submit" name="decision" value="deny">Deny response</button></div><div class="form-message" id="decision-message" role="status"></div></form>`;
    section.querySelector('form').addEventListener('submit', (event) => submitDecision(event, incident.incident_id));
  } else if (approval) {
    section.innerHTML = `<h3>${approval.decision === 'approve' ? 'Response approved' : 'Response denied'}</h3><dl class="detail-grid"><dt>Reviewer</dt><dd>${escapeHtml(approval.reviewer)}</dd><dt>Decision time</dt><dd>${escapeHtml(formatDate(approval.decided_at))}</dd><dt>Reason</dt><dd>${escapeHtml(approval.reason)}</dd></dl><p>${approval.decision === 'deny' ? 'The proposed response was denied. No response actions were executed.' : 'The approved response completed using simulated adapters.'}</p>`;
  } else {
    return;
  }
  $('#drawer-content').appendChild(section);
}

async function submitDecision(event, incidentId) {
  event.preventDefault();
  const form = event.currentTarget;
  if (form.dataset.submitting === 'true') return;
  const decision = event.submitter?.value;
  const data = Object.fromEntries(new FormData(form).entries());
  const message = form.querySelector('#decision-message');
  if (!['approve', 'deny'].includes(decision) || !data.reviewer.trim() || !data.reason.trim()) {
    message.className = 'form-message error';
    message.textContent = 'Enter your name and reason, then choose Approve or Deny.';
    return;
  }
  form.dataset.submitting = 'true';
  form.querySelectorAll('button').forEach((button) => { button.disabled = true; });
  message.className = 'form-message';
  message.textContent = 'Recording your decision...';
  try {
    const response = await fetch(`/incidents/${encodeURIComponent(incidentId)}/decision`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reviewer: data.reviewer.trim(), reason: data.reason.trim() }),
    });
    const raw = await response.text();
    let result;
    try { result = JSON.parse(raw); } catch { throw new Error(`Could not record decision (${response.status}). Refresh the incident before retrying.`); }
    if (!response.ok) throw new Error(result.detail || `Decision failed (${response.status}).`);
    state.incidents = state.incidents.map((incident) => incident.incident_id === incidentId ? result : incident);
    renderMetrics();
    renderIncidents();
    if (state.activeIncidentId === incidentId) openDrawer(incidentId);
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  } finally {
    form.dataset.submitting = 'false';
    form.querySelectorAll('button').forEach((button) => { button.disabled = false; });
  }
}

function closeDrawer() {
  state.activeIncidentId = null;
  $('#incident-drawer').classList.remove('open');
  $('#incident-drawer').setAttribute('aria-hidden', 'true');
}

$('#event-form').addEventListener('submit', submitEvent);
$('#scan-button').addEventListener('click', scanComputer);
$('#refresh-button').addEventListener('click', async () => { await checkHealth(); await loadIncidents(); });
$('#refresh-incidents').addEventListener('click', loadIncidents);
$('#incident-search').addEventListener('input', renderIncidents);
$('#severity-filter').addEventListener('change', renderIncidents);
$('#status-filter').addEventListener('change', renderIncidents);
$('#close-drawer').addEventListener('click', closeDrawer);
document.querySelector('[data-close-drawer]').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeDrawer(); });
checkHealth();
loadIncidents();
setInterval(() => { checkHealth(); loadIncidents(); }, 30000);
