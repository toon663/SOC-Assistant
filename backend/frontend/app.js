const state = { incidents: [], llm: {}, openIncidentId: null };

function hasPendingReview() {
  return state.incidents.some((item) => item.risk_analysis?.claude_review?.status === 'pending');
}

async function loadLlmStatus() {
  try {
    state.llm = await (await fetch('/llm/status')).json();
  } catch {
    state.llm = {};
  }
}

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
  const verdictFilter = $('#verdict-filter').value;
  const incidents = state.incidents.filter((incident) => {
    const status = incident.action_result?.status || 'open';
    const event = incident.events?.[0] || {};
    const verdict = incident.risk_analysis?.verdict;
    const searchable = [incident.incident_id, incident.explanations?.title, incident.alert?.title, event.event_type, event.host, event.user, verdict, incident.risk_analysis?.summary].join(' ').toLowerCase();
    const statusMatch = statusFilter === 'active' ? status !== 'resolved' : (!statusFilter || status === statusFilter);
    // Incidents triaged before the Analyst gave verdicts have none and stay visible.
    const verdictMatch = !verdictFilter || !verdict || (verdictFilter === 'actionable' ? verdict !== 'benign' : verdict === verdictFilter);
    return (!search || searchable.includes(search)) && severities.has(event.severity) && statusMatch && verdictMatch;
  });
  if (!incidents.length) {
    list.innerHTML = '<div class="empty-state">No matching incidents found.</div>';
    return;
  }
  list.innerHTML = incidents.map((incident) => {
    const status = incident.action_result?.status || 'open';
    const title = incident.explanations?.title || incident.alert?.title || incident.events?.[0]?.event_type || 'Security incident';
    const event = incident.events?.[0] || {};
    const score = Math.round(riskScore(incident));
    const severity = event.severity || 'unknown';
    const count = occurrenceCount(incident);
    const countBadge = count > 1 ? `<span class="count-badge" title="${count} occurrences">×${count}</span>` : '';
    const lastSeen = count > 1 ? ` · last seen ${escapeHtml(formatDate(incident.alert?.last_seen))}` : '';
    const triage = incident.risk_analysis || {};
    const verdictBadge = triage.verdict ? `<span class="verdict-badge ${escapeHtml(triage.verdict)}" title="Analyst verdict">${escapeHtml(triage.priority || '')} · ${escapeHtml(triage.verdict)}</span>` : '';
    const review = triage.claude_review?.status;
    const claudeTag = review === 'pending' ? ' · Claude reviewing…' : (review === 'done' ? ' · reviewed by Claude' : '');
    const humanTag = triage.needs_human_review ? ' · needs human decision' : '';
    const triageLine = triage.summary ? `<div class="incident-meta">${escapeHtml(triage.summary)}${escapeHtml(claudeTag)}${escapeHtml(humanTag)}</div>` : '';
    return `<article class="incident-row" tabindex="0" role="button" data-incident-id="${escapeHtml(incident.incident_id)}"><div><div class="incident-title">${escapeHtml(title)}${countBadge}</div>${triageLine}<div class="incident-meta">${escapeHtml(event.host || 'Unknown host')} · ${formatDate(incident.detected_at)}${lastSeen} · ${escapeHtml(incident.incident_id.slice(0, 10))}</div></div><div class="incident-right">${verdictBadge}<span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong class="risk-score">${score}<small>/100</small></strong><div class="risk-bar"><span style="width: ${Math.min(score, 100)}%"></span></div></div></article>`;
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
    const reviewStatus = () => state.incidents.find((item) => item.incident_id === state.openIncidentId)?.risk_analysis?.claude_review?.status;
    const before = reviewStatus();
    state.incidents = await response.json();
    renderMetrics();
    renderIncidents();
    // Refresh an open drawer when its Claude review finishes (not on every poll, to keep the scroll position).
    if (state.openIncidentId && $('#incident-drawer').classList.contains('open') && reviewStatus() !== before) openDrawer(state.openIncidentId);
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
    const benign = result.incidents.filter((item) => item.verdict === 'benign').length;
    const triaged = result.incidents.length ? ` Analyst: ${result.incidents.length - benign} need attention, ${benign} benign.` : '';
    const summary = `Scanned ${result.events_scanned} events: ${result.anomalies_detected} anomalies, ${result.incidents.length - merged} new incidents, ${merged} updated with repeats, ${result.duplicates_skipped} events already seen${result.duplicates_in_resolved ? ` (${result.duplicates_in_resolved} already resolved)` : ''}.${malware}${triaged}`;
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
    if ((live.changes !== null && changes !== live.changes) || hasPendingReview()) await loadIncidents();
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

// A technique as "Name (T1234)" with its tactic and one-line meaning underneath.
function techniqueItem(item) {
  const tactics = item.tactics?.length ? ` <span class="incident-meta">${escapeHtml(item.tactics.join(', '))}</span>` : '';
  const meaning = item.meaning ? `<br><span class="explain-text">${escapeHtml(item.meaning)}</span>` : '';
  return `<li><strong>${escapeHtml(item.name)}</strong> <span class="code-ref">${escapeHtml(item.id)}</span>${tactics}${meaning}</li>`;
}

function detectionDetails(incident) {
  const detection = incident.explanations?.detection;
  const techniques = incident.explanations?.techniques || {};
  if (!detection) return '';
  const reasons = (detection.reasons || []).map((item) => `<li>${escapeHtml(item.text)}${item.text !== item.code ? `<br><span class="code-ref">Sentinel code: ${escapeHtml(item.code)}</span>` : ''}</li>`).join('');
  const candidates = techniques.candidate_count
    ? `<details class="explain-details"><summary>${escapeHtml(techniques.candidate_count)} possible attacker techniques linked to this kind of event</summary><p class="incident-meta">MITRE ATT&amp;CK lists these techniques as ones that can produce this type of event. They are possibilities to keep in mind, not findings about this incident.</p><ul class="triage-list">${(techniques.candidates || []).map(techniqueItem).join('')}</ul>${techniques.candidate_count > (techniques.candidates || []).length ? `<p class="incident-meta">…and ${techniques.candidate_count - techniques.candidates.length} more.</p>` : ''}</details>`
    : '';
  return `${malwareDetails(incident)}<div class="detail-section"><span class="detail-label">Why the Sentinel flagged this</span><p>${escapeHtml(detection.summary)}</p>${reasons ? `<ul class="triage-list">${reasons}</ul>` : '<p>The model scored it as unusual without a specific reason.</p>'}${detection.model_note ? `<p class="incident-meta">${escapeHtml(detection.model_note)}</p>` : ''}${candidates}</div>`;
}

function playbookDetails(incident) {
  const playbook = incident.explanations?.playbook;
  if (!playbook?.name) return `<div class="detail-section"><span class="detail-label">Recommended response</span><p>Not assigned</p></div>`;
  return `<div class="detail-section"><span class="detail-label">Recommended response</span><p><strong>${escapeHtml(playbook.title)}</strong> <span class="code-ref">${escapeHtml(playbook.name)}</span></p><p>${escapeHtml(playbook.what)}</p><span class="detail-label">Why this response</span><p class="explain-text">${escapeHtml(playbook.why)}</p>${playbook.next ? `<p class="explain-text">${escapeHtml(playbook.next)}</p>` : ''}${playbook.status ? `<p class="incident-meta">Status: ${escapeHtml(playbook.status)}</p>` : ''}</div>`;
}

const CLAUDE_TOOLS = {
  get_incident_events: () => 'Read the raw events in this incident',
  search_host_activity: (input) => `Searched other activity on this computer${input.windows_event_ids?.length ? ` for event IDs ${input.windows_event_ids.join(', ')}` : ''}${input.user ? ` by ${input.user}` : ''}${input.source_ip ? ` from ${input.source_ip}` : ''}`,
  get_linked_incident: (input) => `Opened the linked incident ${String(input.incident_id || '').slice(0, 10)}`,
  decode_powershell_command: () => 'Decoded a hidden (encoded) PowerShell command',
  check_ip_reputation: (input) => `Checked the reputation of IP address ${input.ip}`,
};

const CLAUDE_OUTCOMES = {
  agreed: 'Agrees with the rules.',
  changed_verdict: 'Changed the verdict.',
  disagreed: 'Disagrees with the rules. Rules are never lowered automatically, so a person must decide.',
};

function claudeDetails(incident) {
  const review = incident.risk_analysis?.claude_review;
  const canAsk = state.llm.mode && state.llm.mode !== 'off' && review?.status !== 'pending';
  const ask = canAsk ? `<div class="scan-actions"><button class="text-button" type="button" id="ask-claude" data-incident-id="${escapeHtml(incident.incident_id)}">${review ? 'Ask Claude again' : 'Ask Claude to review'} →</button><div id="ask-claude-message" class="form-message" role="status"></div></div>` : '';
  if (!review) return ask ? `<div class="detail-section"><span class="detail-label">Claude review</span><p class="incident-meta">Not reviewed: the rules settled this incident.</p>${ask}</div>` : '';
  let body;
  if (review.status === 'pending') {
    body = `<p><span class="live-dot"></span>Claude is investigating this incident…</p>`;
  } else if (review.status === 'done') {
    const rule = incident.risk_analysis.rule_verdict;
    const outcome = review.outcome === 'changed_verdict' ? `Changed the verdict from ${rule} to ${review.verdict}.` : (CLAUDE_OUTCOMES[review.outcome] || '');
    const steps = (review.tool_calls || []).map((call) => {
      const label = CLAUDE_TOOLS[call.tool] ? CLAUDE_TOOLS[call.tool](call.input || {}) : call.tool;
      return `<li>${escapeHtml(label)} <span class="code-ref">${escapeHtml(call.tool)}</span></li>`;
    }).join('');
    const evidence = (review.evidence || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
    const tokens = review.usage ? ` · ${Number(review.usage.input_tokens || 0).toLocaleString()} in / ${Number(review.usage.output_tokens || 0).toLocaleString()} out tokens` : '';
    body = `<p><span class="verdict-badge ${escapeHtml(review.verdict)}">${escapeHtml(review.verdict)}</span> ${escapeHtml(review.confidence)} confidence${review.carried_over ? ' · reused from an earlier review of this incident' : ''}</p><p><strong>${escapeHtml(outcome)}</strong> ${escapeHtml(review.summary)}</p><p>${escapeHtml(review.reasoning)}</p>${evidence ? `<span class="detail-label">Evidence cited</span><ul class="triage-list">${evidence}</ul>` : ''}${steps ? `<span class="detail-label">Investigation steps</span><ol class="triage-list">${steps}</ol>` : '<p class="incident-meta">Decided without tool calls.</p>'}<p class="incident-meta">${escapeHtml(review.served_by || review.model || '')} · ${escapeHtml(review.seconds ?? '?')}s${escapeHtml(tokens)} · ${escapeHtml(formatDate(review.reviewed_at))}</p>`;
  } else {
    body = `<p class="warn">Review ${escapeHtml(review.status)}${review.detail ? `: ${escapeHtml(review.detail)}` : ''}. The rule verdict stands.</p>`;
  }
  return `<div class="detail-section"><span class="detail-label">Claude review</span>${body}${ask}</div>`;
}

async function askClaude(incidentId, button) {
  button.disabled = true;
  try {
    const response = await fetch(`/incidents/${encodeURIComponent(incidentId)}/review`, { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Request failed (${response.status}).`);
    await loadIncidents();
  } catch (error) {
    $('#ask-claude-message').className = 'form-message error';
    $('#ask-claude-message').textContent = error.message;
    button.disabled = false;
  }
}

function benignDetails(triage) {
  if (triage.verdict !== 'benign') return '';
  // Incidents triaged before explanations existed fall back to the summary.
  const why = triage.benign_explanation || `${triage.summary || ''} No finding in the score breakdown below points to attack activity.`;
  const verdictNote = triage.needs_human_review
    ? 'Claude disagrees with this verdict; read its review below before closing.'
    : 'Safe to resolve once you have read this. Add your own reasoning below before marking it resolved.';
  return `<div class="detail-section benign-callout"><span class="detail-label">Why this is benign</span><p>${escapeHtml(why)}</p><p class="incident-meta">${escapeHtml(verdictNote)}</p></div>`;
}

function riskCallout(incident) {
  const triage = incident.risk_analysis || {};
  if (!['suspicious', 'malicious'].includes(triage.verdict)) return '';
  const reasons = (incident.explanations?.risk_reasons || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  const confirmed = incident.explanations?.techniques?.confirmed || [];
  const attacker = confirmed.length
    ? `<span class="detail-label">What an attacker could be doing</span><ul class="triage-list">${confirmed.map(techniqueItem).join('')}</ul>`
    : '';
  const firstStep = (triage.recommended_actions || [])[0];
  return `<div class="detail-section risk-callout ${escapeHtml(triage.verdict)}"><span class="detail-label">Why this is ${triage.verdict === 'malicious' ? 'a threat' : 'a possible risk'}</span><p>${escapeHtml(triage.summary || '')}</p>${reasons ? `<ul class="triage-list">${reasons}</ul>` : ''}${attacker}${firstStep ? `<p class="explain-text"><strong>Start here:</strong> ${escapeHtml(firstStep)}</p>` : ''}</div>`;
}

function triageDetails(incident) {
  const triage = incident.risk_analysis || {};
  if (!triage.verdict) return '';
  const list = (items, render) => (items.length ? `<ul class="triage-list">${items.map(render).join('')}</ul>` : '<p>None</p>');
  const findings = list(triage.findings || [], (item) => {
    const points = Number(item.points || 0);
    const label = points ? `${points > 0 ? '+' : ''}${Math.round(points)}` : '·';
    return `<li><span class="finding-points ${points > 0 ? 'up' : ''}">${escapeHtml(label)}</span>${escapeHtml(item.text)}</li>`;
  }).replace('class="triage-list"', 'class="triage-list findings-list"');
  const links = list(triage.correlations || [], (item) => {
    const target = item.incident_id && state.incidents.some((other) => other.incident_id === item.incident_id)
      ? `<button class="link-button" type="button" data-open-incident="${escapeHtml(item.incident_id)}">${escapeHtml(item.title || item.incident_id.slice(0, 10))}</button>`
      : escapeHtml(item.title || item.event_type || 'Related activity');
    return `<li>${target}: ${escapeHtml(item.relation)} (${escapeHtml(item.event_count)} event${item.event_count === 1 ? '' : 's'})</li>`;
  });
  const meaning = incident.explanations?.triage || {};
  const confirmed = incident.explanations?.techniques?.confirmed || [];
  const techniques = confirmed.length
    ? confirmed.map((item) => `${escapeHtml(item.name)} <span class="code-ref">${escapeHtml(item.id)}</span>`).join('<br>')
    : 'None: the evidence does not show a specific attacker technique.';
  const humanReview = triage.needs_human_review ? '<p class="warn">Claude and the rules disagree: needs a human decision.</p>' : '';
  const explained = (plain, fallback) => escapeHtml(plain || fallback);
  return `${benignDetails(triage)}${riskCallout(incident)}<div class="detail-section"><span class="detail-label">Analyst triage</span><p><span class="verdict-badge ${escapeHtml(triage.verdict)}">${escapeHtml(triage.priority)} · ${escapeHtml(triage.verdict)}</span> ${escapeHtml(triage.summary || '')}</p>${humanReview}<dl class="detail-grid explain-grid"><dt>Verdict</dt><dd>${explained(meaning.verdict, triage.verdict)}</dd><dt>Priority</dt><dd>${explained(meaning.priority, triage.priority)}</dd><dt>Decision</dt><dd>${explained(meaning.decision, triage.triage)}</dd><dt>Category</dt><dd>${explained(meaning.category, (triage.category || '').replaceAll('_', ' '))}</dd><dt>Triage score</dt><dd>${explained(meaning.score, `${Math.round(triage.risk_score || 0)}/100`)}</dd><dt>Confidence</dt><dd>${explained(meaning.confidence, percent(triage.confidence))}</dd><dt>Attacker technique</dt><dd>${techniques}</dd></dl></div><div class="detail-section"><span class="detail-label">How the score was reached</span><p class="incident-meta">Each line adds (or explains) points toward the triage score.</p>${findings}</div><div class="detail-section"><span class="detail-label">Correlated activity</span>${links}</div><div class="detail-section"><span class="detail-label">Recommended next steps</span>${list(triage.recommended_actions || [], (item) => `<li>${escapeHtml(item)}</li>`)}</div>${claudeDetails(incident)}`;
}

function openDrawer(incidentId) {
  const incident = state.incidents.find((item) => item.incident_id === incidentId);
  if (!incident) return;
  const event = incident.events?.[0] || {};
  const status = incident.action_result?.status || 'open';
  const score = Math.round(riskScore(incident));
  const resolved = status === 'resolved';
  // Keep a half-typed note when the open drawer re-renders (e.g. a Claude review finishing).
  const draft = state.openIncidentId === incidentId ? ($('#resolve-note')?.value || '') : '';
  const note = incident.action_result?.resolution_note;
  const resolveControl = resolved
    ? `<p class="resolved-note">Resolved ${escapeHtml(formatDate(incident.action_result?.resolved_at))}</p>${note ? `<span class="detail-label">Analyst reasoning</span><p class="resolution-note">${escapeHtml(note)}</p>` : ''}`
    : `<label class="detail-label" for="resolve-note">Your reasoning</label><textarea id="resolve-note" rows="3" maxlength="4000" placeholder="Why is this safe to close? E.g. confirmed with the user, expected maintenance, known false positive…">${escapeHtml(draft)}</textarea><button class="resolve-button" type="button" id="resolve-incident" data-incident-id="${escapeHtml(incident.incident_id)}">Mark as resolved ✓</button><div id="resolve-message" class="form-message" role="status"></div>`;
  $('#drawer-title').textContent = incident.explanations?.title || incident.alert?.title || event.event_type || 'Security incident';
  $('#drawer-content').innerHTML = `<div class="drawer-status"><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replaceAll('_', ' '))}</span><strong>${score}/100 risk</strong></div><div class="drawer-actions">${resolveControl}</div>${incident.explanations?.detection?.event ? `<div class="detail-section"><span class="detail-label">What happened</span><p>${escapeHtml(incident.explanations.detection.event)}</p></div>` : ''}<dl class="detail-grid"><dt>Incident ID</dt><dd>${escapeHtml(incident.incident_id)}</dd><dt>Detected</dt><dd>${escapeHtml(formatDate(incident.detected_at))}</dd><dt>Occurrences</dt><dd>${occurrenceCount(incident)}</dd><dt>First seen</dt><dd>${escapeHtml(formatDate(incident.alert?.first_seen))}</dd><dt>Last seen</dt><dd>${escapeHtml(formatDate(incident.alert?.last_seen))}</dd><dt>Event type</dt><dd>${escapeHtml(incident.explanations?.event_type || event.event_type || 'Unknown')}</dd><dt>Severity</dt><dd>${escapeHtml(event.severity || 'Unknown')}</dd><dt>User</dt><dd>${escapeHtml(event.user || 'Unknown')}</dd><dt>Host</dt><dd>${escapeHtml(event.host || 'Unknown')}</dd><dt>Source IP</dt><dd>${escapeHtml(event.source_ip || 'Unknown')}</dd></dl>${triageDetails(incident)}${detectionDetails(incident) || `<div class="detail-section"><span class="detail-label">Sentinel detection</span><p>${escapeHtml(incident.alert?.summary || event.message || 'No summary available.')}</p></div>`}${playbookDetails(incident)}`;
  $('#drawer-content').querySelectorAll('[data-open-incident]').forEach((button) => button.addEventListener('click', () => openDrawer(button.dataset.openIncident)));
  const askButton = $('#ask-claude');
  if (askButton) askButton.addEventListener('click', () => askClaude(askButton.dataset.incidentId, askButton));
  state.openIncidentId = incident.incident_id;
  const resolveButton = $('#resolve-incident');
  if (resolveButton) resolveButton.addEventListener('click', () => resolveIncident(resolveButton.dataset.incidentId, resolveButton));
  $('#incident-drawer').classList.add('open');
  $('#incident-drawer').setAttribute('aria-hidden', 'false');
}

async function resolveIncident(incidentId, button) {
  button.disabled = true;
  try {
    const note = $('#resolve-note')?.value.trim() || '';
    const response = await fetch(`/incidents/${encodeURIComponent(incidentId)}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note }),
    });
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
  state.openIncidentId = null;
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
$('#verdict-filter').addEventListener('change', renderIncidents);
$('#close-drawer').addEventListener('click', closeDrawer);
document.querySelector('[data-close-drawer]').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeDrawer(); });
checkHealth();
loadLlmStatus().then(loadIncidents);
loadScanStatus();
loadDevStatus();
refreshLive();
$('#live-toggle').addEventListener('click', toggleLive);
// Live status is cheap; the incident list reloads only when a poll changed something.
setInterval(refreshLive, 5000);
setInterval(() => { checkHealth(); loadIncidents(); }, 30000);
