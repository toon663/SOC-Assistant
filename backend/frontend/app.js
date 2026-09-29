const state = { incidents: [] };

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
  if (!state.incidents.length) {
    list.innerHTML = '<div class="empty-state">No incidents have been submitted yet.</div>';
    return;
  }
  list.innerHTML = state.incidents.map((incident) => {
    const status = incident.action_result?.status || 'open';
    const title = incident.alert?.title || incident.events?.[0]?.event_type || 'Security incident';
    const host = incident.events?.[0]?.host || 'Unknown host';
    const score = Math.round(riskScore(incident));
    return `<article class="incident-row">
      <div><div class="incident-title">${escapeHtml(title)}</div>
      <div class="incident-meta">${escapeHtml(host)} · ${formatDate(incident.detected_at)} · ${incident.incident_id.slice(0, 10)}</div></div>
      <div class="incident-right"><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong class="risk-score">${score}<small>/100</small></strong></div>
    </article>`;
  }).join('');
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
    $('#incident-list').innerHTML = `<div class="empty-state">Could not load incidents. Start the API and try again.</div>`;
  }
}

async function submitEvent(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form).entries());
  const message = $('#form-message');
  message.className = 'form-message';
  message.textContent = 'Running Sentinel → Analyst → Prognostic → BI → Orchestrator…';
  const payload = {
    events: [{
      event_id: `manual-${Date.now()}`,
      ...data,
    }],
  };
  try {
    const response = await fetch('/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || 'Event submission failed');
    message.className = 'form-message success';
    message.textContent = `Incident created. Status: ${result.action_result?.status || 'open'}`;
    form.reset();
    await loadIncidents();
  } catch (error) {
    message.className = 'form-message error';
    message.textContent = error.message;
  }
}

$('#event-form').addEventListener('submit', submitEvent);
$('#refresh-button').addEventListener('click', async () => { await checkHealth(); await loadIncidents(); });
$('#refresh-incidents').addEventListener('click', loadIncidents);
checkHealth();
loadIncidents();
