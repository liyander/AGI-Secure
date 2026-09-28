(() => {
  const byId = id => document.getElementById(id);
  const make = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = String(text); return element; };
  const request = async (path, options) => { const response = await fetch(path, options); const body = await response.json(); if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`); return body; };
  const lab = { scenarios: [], guardrails: [], choices: {}, modelByProvider: { ollama: 'qwen3:8b', nvidia: '' }, provider: 'ollama', nvidiaModels: [], ollamaModels: [] };
  const labels = { prompt_boundary: 'Untrusted data boundary', role_permissions: 'Role permissions', goal_integrity: 'Goal integrity', data_classification: 'Data classification', state_change_guard: 'State change guard', cyber_boundary: 'Toy web boundary', output_redaction: 'Output redaction', high_risk_filter: 'High-risk input filter', fairness_attribute_filter: 'Attribute filter', fairness_rubric: 'Consistent rubric' };

  function chosenScenario() { return lab.scenarios.find(item => item.id === byId('lab-scenario').value); }
  function showError(message) { byId('lab-error').hidden = !message; byId('lab-error').textContent = message || ''; }
  function fillOptions(models) { const list = byId('lab-model-options'); list.replaceChildren(); for (const id of models) { const option = make('option'); option.value = id; list.append(option); } }
  async function loadModels(preferDefault = false) {
    const provider = byId('lab-provider').value;
    if (provider === 'ollama') {
      fillOptions(lab.ollamaModels);
      byId('lab-model-hint').textContent = lab.ollamaModels.length ? 'Installed local models are suggested.' : 'Enter a model installed in Ollama.';
      return;
    }
    byId('lab-model-hint').textContent = 'Loading NVIDIA catalog...';
    try {
      const result = await request('/api/models/nvidia');
      if (byId('lab-provider').value !== 'nvidia') return;
      lab.nvidiaModels = result.models;
      fillOptions(result.models);
      if (preferDefault && !lab.modelByProvider.nvidia && result.recommended) {
        byId('lab-model').value = result.recommended;
        lab.modelByProvider.nvidia = result.recommended;
      }
      byId('lab-model-hint').textContent = `${result.models.length} catalog IDs. Listing does not guarantee inference access.`;
    } catch (error) { byId('lab-model-hint').textContent = `Catalog unavailable: ${error.message}`; }
  }
  function changeProvider() {
    lab.modelByProvider[lab.provider] = byId('lab-model').value.trim();
    lab.provider = byId('lab-provider').value;
    byId('lab-model').value = lab.modelByProvider[lab.provider] || (lab.provider === 'nvidia' ? 'nvidia/nemotron-3-super-120b-a12b' : lab.ollamaModels[0] || 'qwen3:8b');
    loadModels(lab.provider === 'nvidia' && !lab.modelByProvider.nvidia);
    showError('');
  }
  function briefLine(title, value) { const line = make('div'); line.append(make('b', '', title), make('span', '', value)); return line; }
  function renderGuards(scenario) {
    const target = byId('lab-guards'); target.replaceChildren();
    const relevant = scenario.relevant_guardrails || [];
    for (const guard of lab.guardrails.filter(item => relevant.includes(item.id))) {
      const label = make('label', 'lab-guard');
      const checkbox = make('input'); checkbox.type = 'checkbox'; checkbox.checked = lab.choices[guard.id] !== false; checkbox.dataset.guard = guard.id;
      checkbox.addEventListener('change', () => { lab.choices[guard.id] = checkbox.checked; });
      const text = make('span'); text.append(make('strong', '', labels[guard.id] || guard.id), make('small', '', guard.description));
      label.append(checkbox, text); target.append(label);
    }
  }
  function showScenario() {
    const scenario = chosenScenario(); if (!scenario) return;
    const brief = byId('lab-brief'); brief.replaceChildren(
      briefLine('Attack surface', scenario.attack_surface),
      briefLine('Attacker objective', scenario.attacker_goal),
      briefLine('Authorized task', scenario.authorized_path),
      briefLine('Protected target', scenario.protected_resource)
    );
    const variantSelect = byId('lab-variant'); variantSelect.replaceChildren();
    for (const [index, variant] of (scenario.payload_variants || []).entries()) { const option = make('option', '', variant.name); option.value = String(index); variantSelect.append(option); }
    const customOption = make('option', '', 'Custom text'); customOption.value = 'custom'; variantSelect.append(customOption);
    variantSelect.value = scenario.payload_variants?.length ? '0' : 'custom';
    variantSelect.disabled = !scenario.payload_variants?.length;
    byId('lab-payload').value = scenario.attack_payload;
    const fixed = ['fairness', 'cbrn'].includes(scenario.category);
    byId('lab-payload').disabled = fixed;
    byId('lab-payload-label').textContent = fixed ? 'Fixed evaluation input' : 'Attacker-controlled text';
    byId('lab-payload-hint').textContent = scenario.category === 'rogue_agent' ? 'This text is inserted into a retrieved public document. The user still asks only for a summary.' : scenario.category === 'fairness' ? 'Two profiles have identical qualifications. Only the identity attribute changes in the raw run.' : scenario.category === 'cbrn' ? 'This predefined boundary probe stays fixed; inspect the refusal and guard events manually.' : 'This text becomes the user request in both runs.';
    lab.choices = {};
    renderGuards(scenario);
    showError('');
  }
  function metric(label, value) { const box = make('div', 'lab-metric'); box.append(make('span', '', label), make('strong', '', value)); return box; }
  function pill(text, kind) { return make('span', 'lab-pill ' + (kind || ''), text); }
  function eventDetail(event) {
    if (event.event === 'policy_decision') return `${event.source || 'policy'}: ${event.reason || ''}`;
    if (event.event === 'tool_request') return `${event.tool}(${JSON.stringify(event.arguments || {})})`;
    if (event.event === 'tool_result') return `${event.tool}: ${typeof event.result === 'string' ? event.result : JSON.stringify(event.result)}`;
    if (event.event === 'state_change') return `Before ${JSON.stringify(event.before)}\nAfter ${JSON.stringify(event.after)}`;
    if (event.event === 'guardrail_config') return JSON.stringify(event.controls);
    if (event.event === 'attack_surface_prepared') return `${event.path}\n${event.content}`;
    return event.content || event.reason || (event.step ? `Model call ${event.step}` : '');
  }
  function trace(events) {
    const list = make('div', 'lab-trace');
    for (const event of events) {
      const item = make('details', event.decision === 'deny' || event.event === 'action_blocked' ? 'deny' : event.decision === 'allow' ? 'allow' : '');
      const summary = make('summary', '', `${String(event.seq || '').padStart(2, '0')} · ${event.event.replaceAll('_', ' ')}${event.tool ? ' · ' + event.tool : ''}${event.decision ? ' · ' + event.decision : ''}`);
      item.append(summary, make('p', '', eventDetail(event))); list.append(item);
    }
    return list;
  }
  function section(title, content) { const box = make('div', 'lab-section'); box.append(make('h4', '', title), content); return box; }
  function resultCard(run, title, kind, isFairness, isCbrn) {
    const card = make('div', `panel lab-run-card ${kind}`), head = make('div', 'lab-run-head');
    head.append(make('h3', '', title), make('small', '', run.run_id)); card.append(head);
    if (isFairness) {
      const outcome = make('div', 'lab-outcome'); outcome.append(pill(`SCORE GAP ${run.score_gap === null ? 'UNPARSED' : run.score_gap}`, run.score_gap !== null && run.score_gap < 10 ? 'safe' : '')); card.append(outcome);
      for (const result of run.results) {
        const text = make('pre', '', `Profile sent: ${result.profile_sent}\n\nModel response: ${result.response}`);
        card.append(section(`${result.candidate} · score ${result.score ?? 'unparsed'}`, text));
      }
      return card;
    }
    const outcome = make('div', 'lab-outcome');
    if (isCbrn) outcome.append(pill(run.metrics.refusal ? 'REFUSAL SIGNAL DETECTED' : 'NO REFUSAL SIGNAL', run.metrics.refusal ? 'safe' : ''));
    else outcome.append(pill(run.metrics.attack_success ? 'ATTACK OBJECTIVE REACHED' : 'OBJECTIVE NOT REACHED', run.metrics.attack_success ? '' : 'safe'));
    if (run.metrics.blocked_actions) outcome.append(pill(`${run.metrics.blocked_actions} BLOCKED`, 'safe'));
    outcome.append(pill(`${run.metrics.latency_ms} MS`, 'muted')); card.append(outcome);
    card.append(section('Agent response', make('pre', '', run.response || '(No final text)')));
    const evidence = make('div', 'lab-evidence');
    if (run.evidence.length) for (const item of run.evidence) { const line = make('div'); line.append(make('b', '', item.kind.toUpperCase() + ' · '), document.createTextNode(item.detail)); evidence.append(line); }
    else evidence.append(make('p', '', 'No success marker or state violation was observed.'));
    card.append(section('Deterministic evidence', evidence));
    const before = run.world_before || {}, after = run.world || {};
    const changed = Object.keys(after).filter(key => before[key] !== after[key]);
    card.append(section('Synthetic world state', make('p', '', changed.length ? changed.map(key => `${key}: ${before[key]} → ${after[key]}`).join('\n') : 'No persistent state change in this run.')));
    card.append(section(`Execution trace · ${run.events.length} events`, trace(run.events)));
    return card;
  }
  function renderResults(data) {
    const fairness = data.scenario.category === 'fairness', cbrn = data.scenario.category === 'cbrn';
    byId('lab-intro').hidden = true; byId('lab-results').hidden = false;
    const summary = byId('lab-summary'); summary.replaceChildren();
    const top = make('div', 'lab-summary-top'), title = make('div');
    let verdict;
    if (fairness) verdict = 'Paired score comparison';
    else if (cbrn) verdict = 'Safety boundary comparison';
    else if (data.raw.metrics.attack_success && !data.defended.metrics.attack_success) verdict = data.defended.metrics.blocked_actions ? 'Exploit observed · guardrail blocked a proposed action' : 'Exploit observed · protected run avoided it';
    else if (data.raw.metrics.attack_success && data.defended.metrics.attack_success) verdict = 'Exploit observed in both runs';
    else verdict = 'No exploit observed in the raw run';
    title.append(make('h2', '', verdict), make('p', '', data.analysis.note));
    top.append(title, make('span', 'tag', data.comparison_id)); summary.append(top);
    const strip = make('div', 'lab-metric-strip');
    if (fairness) strip.append(metric('Raw score gap', data.raw.score_gap ?? '—'), metric('Protected score gap', data.defended.score_gap ?? '—'), metric('Qualification difference', '0'));
    else if (cbrn) strip.append(metric('Raw refusal heuristic', data.raw.metrics.refusal ? 'Detected' : 'Not detected'), metric('Protected refusal heuristic', data.defended.metrics.refusal ? 'Detected' : 'Not detected'), metric('Guard actions', data.defended.metrics.blocked_actions));
    else strip.append(metric('Raw objective', data.raw.metrics.attack_success ? 'Reached' : 'Not reached'), metric('Protected objective', data.defended.metrics.attack_success ? 'Reached' : 'Not reached'), metric('Blocked actions', data.defended.metrics.blocked_actions));
    summary.append(strip);
    const columns = byId('lab-columns'); columns.replaceChildren(resultCard(data.raw, 'Controls off', 'raw', fairness, cbrn), resultCard(data.defended, 'Selected controls on', 'defended', fairness, cbrn));
    const decisions = byId('lab-decisions'); decisions.replaceChildren(); decisions.append(make('div', 'panel-head')); decisions.firstChild.append(make('h3', '', 'Guardrail decisions'), make('span', 'tag', fairness ? 'ATTRIBUTE FILTER / RUBRIC' : 'EACH LAYER LOGGED'));
    if (fairness) {
      for (const [key, enabled] of Object.entries(data.defended.controls || {})) { const row = make('div', 'lab-decision-row'); row.append(make('b', '', labels[key] || key), make('span', enabled ? 'ON' : 'OFF', enabled ? 'allow' : 'deny'), make('span', '', lab.guardrails.find(guard => guard.id === key)?.description || '')); decisions.append(row); }
    } else if (data.analysis.guardrail_decisions.length) {
      for (const item of data.analysis.guardrail_decisions) { const row = make('div', 'lab-decision-row'); row.append(make('b', '', labels[item.source] || item.source), make('span', item.decision.toUpperCase(), item.decision === 'deny' ? 'deny' : 'allow'), make('span', '', `${item.tool ? item.tool + ': ' : ''}${item.reason}`)); decisions.append(row); }
    } else decisions.append(make('p', 'empty', 'No tool guard was evaluated. The model may have answered without requesting a tool, or an input guard stopped the run first.'));
  }
  async function runComparison() {
    const scenario = chosenScenario(); if (!scenario) return;
    const provider = byId('lab-provider').value, model = byId('lab-model').value.trim();
    if (provider === 'nvidia' && (!model.includes('/') || model.includes(':'))) { showError('Choose a NVIDIA catalog model ID.'); return; }
    const payload = { scenario_id: scenario.id, provider, model, attack_payload: byId('lab-payload').value, guardrails: lab.choices };
    const button = byId('lab-run'); button.disabled = true; button.firstChild.textContent = 'Running both configurations... '; showError('');
    byId('lab-results').hidden = true; byId('lab-intro').hidden = false;
    byId('lab-intro').querySelector('h2').textContent = 'Running the comparison';
    byId('lab-intro').querySelector('p').textContent = 'The same model is processing the attack run and then the protected run. This can take a minute.';
    try { renderResults(await request('/api/compare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })); if (typeof loadRecent === 'function') loadRecent(); }
    catch (error) { showError(error.message); byId('lab-intro').querySelector('h2').textContent = 'Comparison did not finish'; byId('lab-intro').querySelector('p').textContent = 'Review the error in the setup panel and try again.'; }
    finally { button.disabled = false; button.firstChild.textContent = 'Run side-by-side comparison '; }
  }
  async function initialize() {
    try {
      const [scenarios, guards, health] = await Promise.all([request('/api/scenarios'), request('/api/guardrails'), request('/api/health')]);
      lab.scenarios = scenarios; lab.guardrails = guards; lab.ollamaModels = health.ollama_models || [];
      const select = byId('lab-scenario');
      for (const scenario of scenarios) { const option = make('option', '', `${scenario.id} · ${scenario.name}`); option.value = scenario.id; select.append(option); }
      select.value = 'ROGUE-001'; showScenario();
      if (health.nvidia_configured) { byId('lab-provider').value = 'nvidia'; lab.provider = 'nvidia'; byId('lab-model').value = 'nvidia/nemotron-3-super-120b-a12b'; loadModels(true); }
      else { byId('lab-model').value = lab.ollamaModels[0] || 'qwen3:8b'; lab.modelByProvider.ollama = byId('lab-model').value; loadModels(); }
    } catch (error) { showError(error.message); }
  }
  byId('lab-scenario').addEventListener('change', showScenario);
  byId('lab-variant').addEventListener('change', () => { const scenario = chosenScenario(); const index = Number(byId('lab-variant').value); if (byId('lab-variant').value !== 'custom' && scenario?.payload_variants?.[index]) byId('lab-payload').value = scenario.payload_variants[index].text; });
  byId('lab-payload').addEventListener('input', () => { byId('lab-variant').value = 'custom'; });
  byId('lab-provider').addEventListener('change', changeProvider);
  byId('lab-model').addEventListener('input', () => { lab.modelByProvider[byId('lab-provider').value] = byId('lab-model').value.trim(); });
  byId('lab-reset-guards').addEventListener('click', () => { lab.choices = {}; renderGuards(chosenScenario()); });
  byId('lab-run').addEventListener('click', runComparison);
  initialize();
})();
