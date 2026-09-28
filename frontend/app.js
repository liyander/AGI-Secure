const $ = (id) => document.getElementById(id);
const state = { scenarios: [], runs: [], modelByProvider: { ollama: 'qwen3:8b', nvidia: '' }, ollamaModels: [], currentProvider: 'ollama' };
const icon = { rogue_agent: '↗', privacy: '◈', fairness: '⚖', cyber: '⌁', cbrn: '◇' };
const category = { rogue_agent: 'Rogue agents', privacy: 'Privacy', fairness: 'Bias & fairness', cyber: 'Cyber uplift', cbrn: 'CBRN safety' };

function node(tag, cls, text) { const el = document.createElement(tag); if (cls) el.className = cls; if (text !== undefined) el.textContent = text; return el; }
function clear(el) { el.replaceChildren(); }
function go(page) {
  document.querySelectorAll('.page').forEach(el => el.classList.toggle('active', el.id === page));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.page === page));
  $('breadcrumb').textContent = page.toUpperCase();
  if (page === 'events') loadEvents();
  if (page === 'reports') loadReport();
  if (page === 'settings') loadSettings();
  if (page === 'playground' && $('provider').value === 'nvidia') loadNvidiaModels(false);
}
document.querySelectorAll('[data-go]').forEach(el => el.addEventListener('click', () => go(el.dataset.go)));
document.querySelectorAll('.nav-item').forEach(el => el.addEventListener('click', () => go(el.dataset.page)));
function chooseScenario(id) { $('scenario').value = id; const scenario = state.scenarios.find(s => s.id === id); if (scenario) { $('prompt').value = scenario.prompt; $('role').value = scenario.role; } go('playground'); }

async function api(path, options) {
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch { throw new Error('The server returned an unreadable response.'); }
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status})`);
  return data;
}
function modelOptions(models) {
  const list = $('model-options'); clear(list);
  models.forEach(id => { const option = node('option'); option.value = id; list.append(option); });
}
async function loadNvidiaModels(chooseDefault = true) {
  $('model-hint').textContent = 'Loading NVIDIA model IDs...';
  try {
    const data = await api('/api/models/nvidia');
    if ($('provider').value !== 'nvidia') return;
    modelOptions(data.models);
    if (chooseDefault && !state.modelByProvider.nvidia && data.recommended) {
      $('model').value = data.recommended;
      state.modelByProvider.nvidia = data.recommended;
    }
    $('model-hint').textContent = data.models.length ? `${data.models.length} catalog models found. Choose a chat model; listing does not guarantee inference access.` : 'No NVIDIA models were returned. Check your API key in Settings.';
  } catch (error) {
    if ($('provider').value !== 'nvidia') return;
    $('model-hint').textContent = `Could not load NVIDIA models: ${error.message}`;
  }
}
function changeProvider() {
  state.modelByProvider[state.currentProvider] = $('model').value.trim();
  const provider = $('provider').value;
  state.currentProvider = provider;
  $('run-error').hidden = true;
  if (provider === 'nvidia') {
    $('model').value = state.modelByProvider.nvidia || 'nvidia/nemotron-3-super-120b-a12b';
    loadNvidiaModels(!state.modelByProvider.nvidia);
  } else {
    $('model').value = state.modelByProvider.ollama || state.ollamaModels[0] || 'qwen3:8b';
    modelOptions(state.ollamaModels);
    $('model-hint').textContent = state.ollamaModels.length ? 'Choose an installed Ollama model.' : 'Enter a model installed in Ollama.';
  }
}
function renderScenarios() {
  const cards = $('scenario-cards'), list = $('scenario-list'), select = $('scenario');
  clear(cards); clear(list);
  state.scenarios.forEach(s => {
    const card = node('div', 'scenario-card');
    card.append(node('div', 'scenario-icon', icon[s.category]), node('h3', '', category[s.category]), node('p', '', s.name), node('span', 'card-arrow', 'Explore →'));
    card.addEventListener('click', () => chooseScenario(s.id)); cards.append(card);
    const row = node('div', 'scenario-item'); const badge = node('div', 'scenario-icon', icon[s.category]); const details = node('div', 'details');
    details.append(node('h3', '', s.name), node('p', '', s.description));
    const button = node('button', 'secondary', 'Open in playground →'); button.addEventListener('click', () => chooseScenario(s.id));
    row.append(badge, details, button); list.append(row);
    const option = node('option', '', `${s.id} · ${s.name}`); option.value = s.id; select.append(option);
  });
}
function renderTrace(events) {
  const trace = $('trace'); clear(trace); trace.className = 'trace-list'; $('event-count').textContent = `${events.length} EVENTS`;
  for (const event of events) {
    const row = node('div', 'trace-item' + (event.event === 'action_blocked' || event.decision === 'deny' ? ' blocked' : ''));
    const body = node('div'); body.append(node('div', 'trace-kind', event.event.replaceAll('_', ' ')));
    let detail = event.reason || (event.tool ? `${event.tool}${event.arguments ? ' ' + JSON.stringify(event.arguments) : ''}` : event.content || '');
    if (event.event === 'tool_result') detail = `${event.tool}: ${typeof event.result === 'string' ? event.result : JSON.stringify(event.result)}`;
    if (event.event === 'state_change') detail = JSON.stringify(event.after);
    if (detail) body.append(node('div', 'trace-detail', String(detail).slice(0, 600)));
    row.append(node('div', 'trace-time', `${event.time_ms} ms`), body); trace.append(row);
  }
}
function connectEvents() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${protocol}//${location.host}/api/events/live`);
  socket.onmessage = message => {
    try {
      const item = JSON.parse(message.data);
      if (item.type === 'event' && $('run').disabled) {
        if (state.activeRunId && state.activeRunId !== item.run_id) return;
        state.activeRunId = item.run_id;
        state.liveEvents.push(item);
        renderTrace(state.liveEvents);
      }
    } catch { /* Ignore malformed event frames. */ }
  };
  socket.onclose = () => setTimeout(connectEvents, 2000);
}
function renderConversation(prompt, result) {
  const box = $('conversation'); clear(box);
  const user = node('div', 'message user'); user.append(node('div', 'speaker', 'USER'), node('div', '', prompt));
  const assistant = node('div', 'message assistant'); assistant.append(node('div', 'speaker', 'AGENT'), node('div', '', result.response || '(No text response)'));
  box.append(user, assistant); box.scrollTop = box.scrollHeight;
}
async function run() {
  const selected = $('scenario').value;
  const prompt = $('prompt').value.trim();
  if (!selected && !prompt) { $('run-error').hidden = false; $('run-error').textContent = 'Enter a prompt or select a scenario.'; return; }
  if ($('provider').value === 'nvidia' && (!$('model').value.includes('/') || $('model').value.includes(':'))) { $('run-error').hidden = false; $('run-error').textContent = 'Choose a NVIDIA catalog model ID, such as nvidia/nemotron-3-super-120b-a12b.'; return; }
  $('run-error').hidden = true; $('run').disabled = true; $('send').disabled = true; $('run').firstChild.textContent = 'Running model... ';
  state.activeRunId = null; state.liveEvents = []; renderTrace([]);
  const payload = { prompt, provider: $('provider').value, model: $('model').value.trim(), role: $('role').value, protected: $('protected').checked, system_prompt: $('system-prompt').value, scenario_id: selected || null };
  try {
    if (selected === 'FAIR-001') {
      const result = await api('/api/fairness', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const text = result.results.map(r => `${r.candidate}: score ${r.score ?? 'unparsed'}\n${r.response}`).join('\n\n') + `\n\nScore gap: ${result.score_gap ?? 'unavailable'}`;
      renderConversation('Paired candidate evaluation', { response: text }); renderTrace([{ event: 'model_response', time_ms: 0, content: 'Evaluated two paired candidates using the configured model.' }]);
      $('run-label').textContent = result.run_id;
    } else {
      const result = await api('/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      renderConversation(selected ? state.scenarios.find(s => s.id === selected).prompt : prompt, result);
      renderTrace(result.events); $('run-label').textContent = result.run_id;
    }
    loadRecent();
  } catch (error) { $('run-error').hidden = false; $('run-error').textContent = error.message; }
  finally { $('run').disabled = false; $('send').disabled = false; $('run').firstChild.textContent = 'Run experiment '; }
}
function renderRunList(target, runs) {
  clear(target);
  if (!runs.length) { target.append(node('div', 'empty', 'No runs yet. Start an experiment to create an audit trail.')); return; }
  for (const run of runs) {
    const row = node('div', 'run-row'), info = node('div');
    info.append(node('strong', '', run.scenario_id || run.run_id), node('p', '', `${new Date(run.timestamp).toLocaleString()} · ${run.run_id}`));
    row.append(info, node('span', 'pill' + (run.protected ? ' safe' : ''), run.protected ? 'PROTECTED' : 'ATTACK MODE')); target.append(row);
  }
}
async function loadRecent() {
  try {
    const [runs, report] = await Promise.all([api('/api/events?limit=5'), api('/api/evaluation')]);
    renderRunList($('recent-activity'), runs.slice(0, 3));
    const values = [report.modes.attack.runs, report.modes.defense.runs, report.modes.defense.blocked_actions];
    document.querySelectorAll('#dashboard-metrics strong').forEach((el, i) => el.textContent = values[i]);
  } catch { /* API state is optional during page load. */ }
}
async function loadEvents() { try { renderRunList($('event-list'), await api('/api/events?limit=100')); } catch (error) { $('event-list').textContent = error.message; } }
async function loadReport() {
  try {
    const report = await api('/api/evaluation'), summary = $('report-summary'); clear(summary);
    const items = [
      ['Total runs', report.total_runs, 'Saved model executions'],
      ['Attack success · controls off', report.modes.attack.attack_success_rate === null ? '—' : `${report.modes.attack.attack_success_rate}%`, `${report.modes.attack.runs} attack runs`],
      ['Attack success · protected', report.modes.defense.attack_success_rate === null ? '—' : `${report.modes.defense.attack_success_rate}%`, `${report.modes.defense.runs} protected runs`],
    ];
    items.forEach(([label, value, foot]) => { const card = node('div', 'report-card'); card.append(node('span', '', label), node('strong', '', value), node('small', '', foot)); summary.append(card); });
    const tableTarget = $('report-table'); clear(tableTarget);
    if (!report.recent.length) { tableTarget.append(node('div', 'empty', 'No measured results yet.')); return; }
    const table = node('table', 'report-table'), head = node('tr'); ['Run', 'Scenario', 'Mode', 'Attack success', 'Latency'].forEach(x => head.append(node('th', '', x))); table.append(head);
    for (const run of report.recent) { const tr = node('tr'); [run.run_id, run.scenario_id || 'Custom', run.protected ? 'Protected' : 'Attack', run.metrics?.attack_success === undefined ? '—' : run.metrics.attack_success ? 'Yes' : 'No', run.metrics?.latency_ms === undefined ? '—' : `${run.metrics.latency_ms} ms`].forEach(x => tr.append(node('td', '', x))); table.append(tr); }
    tableTarget.append(table);
  } catch (error) { $('report-summary').textContent = error.message; }
}
async function loadHealth() {
  try {
    const health = await api('/api/health');
    $('ollama-status').textContent = health.ollama_available ? `${health.ollama_models.length} model(s)` : 'Offline';
    $('nvidia-status').textContent = health.nvidia_configured ? 'Configured' : 'No API key';
    $('settings-ollama-status').textContent = health.ollama_available ? `${health.ollama_models.length} model(s)` : 'Offline';
    $('model-status').textContent = health.ollama_available ? 'Local model online' : health.nvidia_configured ? 'NVIDIA configured' : 'Connect a model';
    $('model-dot').classList.toggle('good', health.ollama_available || health.nvidia_configured);
    state.ollamaModels = health.ollama_models;
    if ($('provider').value === 'ollama') {
      modelOptions(health.ollama_models);
      if (health.ollama_models.length && $('model').value === 'qwen3:8b') {
        $('model').value = health.ollama_models[0];
        state.modelByProvider.ollama = $('model').value;
      }
    }
  } catch { $('model-status').textContent = 'Server unavailable'; }
}
function showKeyMessage(text, error = false) {
  $('key-message').textContent = text;
  $('key-message').classList.toggle('error-text', error);
}
async function loadSettings() {
  try {
    const { nvidia } = await api('/api/settings');
    const label = nvidia.source === 'saved' ? 'Saved on this computer' : nvidia.source === 'environment' ? 'Environment variable' : 'Not configured';
    $('key-badge').textContent = nvidia.configured ? 'CONFIGURED' : 'NOT CONFIGURED';
    $('saved-key-status').textContent = label;
    $('delete-key').disabled = nvidia.source !== 'saved';
  } catch (error) { showKeyMessage(error.message, true); }
}
async function saveKey(event) {
  event.preventDefault();
  const key = $('api-key').value.trim();
  if (!key) { showKeyMessage('Enter an API key.', true); return; }
  $('save-key').disabled = true;
  try {
    await api('/api/settings/nvidia-key', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ api_key: key }) });
    $('api-key').value = '';
    $('api-key').type = 'password'; $('toggle-key').textContent = 'Show';
    showKeyMessage('Key saved. Select NVIDIA NIM in the Playground to use it.');
    await Promise.all([loadSettings(), loadHealth()]);
  } catch (error) { showKeyMessage(error.message, true); }
  finally { $('save-key').disabled = false; }
}
async function deleteKey() {
  $('delete-key').disabled = true;
  try {
    await api('/api/settings/nvidia-key', { method: 'DELETE' });
    showKeyMessage('Saved key removed.');
    await Promise.all([loadSettings(), loadHealth()]);
  } catch (error) { showKeyMessage(error.message, true); $('delete-key').disabled = false; }
}
$('scenario').addEventListener('change', () => { const s = state.scenarios.find(x => x.id === $('scenario').value); if (s) { $('prompt').value = s.prompt; $('role').value = s.role; } });
$('provider').addEventListener('change', changeProvider);
$('model').addEventListener('input', () => { state.modelByProvider[$('provider').value] = $('model').value.trim(); });
$('protected').addEventListener('change', () => $('mode-description').textContent = $('protected').checked ? 'Protected agent · controls on' : 'Vulnerable agent · controls off');
$('run').addEventListener('click', run); $('send').addEventListener('click', run);
$('prompt').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) run(); });
$('refresh-events').addEventListener('click', loadEvents); $('refresh-report').addEventListener('click', loadReport);
$('key-form').addEventListener('submit', saveKey);
$('delete-key').addEventListener('click', deleteKey);
$('toggle-key').addEventListener('click', () => { const visible = $('api-key').type === 'text'; $('api-key').type = visible ? 'password' : 'text'; $('toggle-key').textContent = visible ? 'Show' : 'Hide'; });
function clock() { $('clock').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); } clock(); setInterval(clock, 30000);
api('/api/scenarios').then(scenarios => { state.scenarios = scenarios; renderScenarios(); }).catch(error => { $('scenario-cards').textContent = error.message; });
loadHealth();
loadRecent();
connectEvents();
