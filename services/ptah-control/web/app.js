const state = { snapshot: null };
const status = document.querySelector('#status');
const selector = document.querySelector('#workspace-selector');

const el = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};

function row(title, stateText) {
  const node = el('article', undefined, 'row');
  const head = el('div', undefined, 'row-head');
  head.append(el('strong', title), el('span', stateText, 'state'));
  node.append(head);
  return node;
}

function list(node, className, label, items) {
  if (!items?.length) return;
  node.append(el('div', label, 'boundary'));
  const ul = el('ul', undefined, className);
  items.forEach((item) => ul.append(el('li', item)));
  node.append(ul);
}

function controls(node, specs) {
  const wrap = el('div', undefined, 'controls');
  for (const spec of specs) {
    const button = el('button', spec.label, spec.critical ? 'critical' : undefined);
    button.dataset.control = spec.kind;
    button.dataset.targetId = spec.target;
    if (spec.providerId) button.dataset.providerId = spec.providerId;
    if (spec.providerGeneration !== undefined) button.dataset.providerGeneration = String(spec.providerGeneration);
    wrap.append(button);
  }
  node.append(wrap);
}

function render() {
  const s = state.snapshot;
  const a = s.authority;
  document.querySelector('#authority').textContent = `${a.workspace_id}@${a.workspace_revision} · ${a.session_id}@${a.session_revision} · ${a.node_id}/gen-${a.node_generation} · fence ${a.fence}`;
  selector.replaceChildren(...s.workspaces.map((id) => {
    const option = el('option', id);
    option.value = id;
    option.selected = id === a.workspace_id;
    return option;
  }));
  document.querySelector('#home-content').replaceChildren(
    el('p', `Workspace ${a.workspace_id} is projected from canonical revision ${a.workspace_revision}.`),
    el('p', `Session ${a.session_id}; Node ${a.node_id} generation ${a.node_generation}.`, 'boundary'),
  );
  renderActivities(s.activities);
  renderObjects(s.objects);
  renderTerminals(s.terminals);
  renderTransfers(s.transfers);
  renderBrowsers(s.browsers);
  renderHealth(s.nodes, s.providers);
  renderAdvisories(s.advisories);
  renderWorkers(s.workers);
  renderRecovery(s.recovery);
  renderEvidence(s.evidence_links);
  reconcilePresentation(a);
}

function renderActivities(items) {
  const root = document.querySelector('[data-view="activities"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.title, item.runtime_state);
    node.append(el('div', `Worker completion: ${item.worker_completion ? 'complete' : 'not complete'}`));
    node.append(el('div', `Caller/reviewer acceptance: ${item.acceptance}`, item.acceptance));
    list(node, 'evidence', 'Evidence', item.evidence);
    if (item.limitation) list(node, 'limitations', 'Limitation', [item.limitation]);
    return node;
  }));
}

function renderObjects(items) {
  const root = document.querySelector('[data-view="objects"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.label, `${item.artifact ? 'artifact' : 'object'} · ${item.materialization_state}`);
    node.append(el('div', `ID ${item.id} · revision ${item.revision}`, 'boundary'));
    list(node, 'evidence', 'Evidence', item.evidence);
    return node;
  }));
}

function renderTerminals(items) {
  const root = document.querySelector('[data-view="terminals"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.id, item.attached ? 'attached' : 'detached');
    node.append(el('div', `Activity ${item.activity_id} · ${item.provider_id}/gen-${item.provider_generation}`, 'boundary'));
    if (item.limitation) list(node, 'limitations', 'Limitation', [item.limitation]);
    controls(node, [
      { label: 'Reconnect', kind: 'terminal_reconnect', target: item.id, providerId: item.provider_id, providerGeneration: item.provider_generation },
      { label: 'Send input', kind: 'terminal_input', target: item.id, providerId: item.provider_id, providerGeneration: item.provider_generation },
    ]);
    return node;
  }));
}

function renderTransfers(items) {
  const root = document.querySelector('[data-view="transfers"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.id, `${item.state} · ${item.progress_percent}%`);
    node.append(el('div', `Partial retained: ${item.partial_retained ? 'yes' : 'no'}`, 'boundary'));
    list(node, 'evidence', 'Evidence', item.evidence);
    controls(node, [
      { label: 'Pause', kind: 'transfer_pause', target: item.id },
      { label: 'Resume', kind: 'transfer_resume', target: item.id },
    ]);
    return node;
  }));
}

function renderBrowsers(items) {
  const root = document.querySelector('[data-view="browsers"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.page_id, item.attached ? 'attached' : 'detached');
    node.append(el('div', item.url));
    node.append(el('div', `${item.provider_id}/gen-${item.provider_generation} · profile ${item.profile_id}`, 'boundary'));
    if (item.limitation) list(node, 'limitations', 'Limitation', [item.limitation]);
    controls(node, [{ label: 'Navigate', kind: 'browser_navigate', target: item.page_id, providerId: item.provider_id, providerGeneration: item.provider_generation }]);
    return node;
  }));
}

function renderHealth(nodes, providers) {
  const root = document.querySelector('[data-view="health"]');
  const rows = [];
  for (const item of nodes) {
    const node = row(item.node_id, `${item.health} · gen-${item.generation}`);
    node.append(el('div', `ready=${item.ready} reachable=${item.reachable} pressure=${item.pressure}`, 'boundary'));
    list(node, 'evidence', 'Evidence', item.evidence);
    rows.push(node);
  }
  for (const item of providers) {
    const node = row(item.provider_id, `${item.health} · gen-${item.generation}`);
    list(node, 'limitations', 'Limitations', item.limitations);
    list(node, 'evidence', 'Evidence', item.evidence);
    rows.push(node);
  }
  root.replaceChildren(...rows);
}

function renderAdvisories(items) {
  const root = document.querySelector('[data-view="advisories"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.id, item.state);
    list(node, 'facts', 'Observed facts', item.observed_facts);
    list(node, 'evidence', 'Evidence', item.evidence);
    list(node, 'suggestions', 'Suggestions (non-authorizing)', item.suggestions);
    if (item.uncertainty) list(node, 'limitations', 'Uncertainty', [item.uncertainty]);
    controls(node, [
      { label: 'Dismiss', kind: 'advisory_dismiss', target: item.id },
      { label: 'Defer', kind: 'advisory_defer', target: item.id },
      { label: 'Choose alternative', kind: 'advisory_choose_alternative', target: item.id },
      { label: 'Submit approved upgrade', kind: 'submit_upgrade_activity', target: item.id, critical: true },
    ]);
    return node;
  }));
}

function renderWorkers(items) {
  const root = document.querySelector('[data-view="workers"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(`${item.worker_id} · ${item.role}`, item.completed ? 'worker complete' : 'worker active');
    node.append(el('div', `Caller/reviewer acceptance: ${item.acceptance}`, item.acceptance));
    if (item.checkpoint) node.append(el('div', `Checkpoint: ${item.checkpoint}`, 'boundary'));
    if (item.partial_result) list(node, 'evidence', 'Partial result', [item.partial_result]);
    if (item.conflict) list(node, 'limitations', 'Conflict', [item.conflict]);
    controls(node, [{ label: 'Accept result', kind: 'accept_worker_result', target: item.worker_id, critical: true }]);
    return node;
  }));
}

function renderRecovery(item) {
  const root = document.querySelector('[data-view="recovery"]');
  const node = row(item.checkpoint_id || 'No checkpoint', item.recovery_verification);
  node.append(el('div', `Integrity: ${item.checkpoint_integrity}`));
  node.append(el('div', `Restore compatibility: ${item.restore_compatibility}`));
  list(node, 'limitations', 'Limitations', item.limitations);
  controls(node, [
    { label: 'Checkpoint', kind: 'checkpoint_request', target: state.snapshot.authority.workspace_id, critical: true },
    { label: 'Reconnect', kind: 'workspace_reconnect', target: state.snapshot.authority.workspace_id, critical: true },
  ]);
  root.replaceChildren(node);
}

function renderEvidence(items) {
  const root = document.querySelector('[data-view="evidence"]');
  root.replaceChildren(...items.map((item) => {
    const node = row(item.label, 'evidence');
    node.append(el('code', item.reference));
    return node;
  }));
}

function reconcilePresentation(authority) {
  const cached = JSON.parse(localStorage.getItem('ptah.presentation') || 'null');
  const fresh = { workspace: authority.workspace_id, session: authority.session_id, panel: 'home' };
  if (cached?.workspace === fresh.workspace && cached?.session === fresh.session) fresh.panel = cached.panel || 'home';
  localStorage.setItem('ptah.presentation', JSON.stringify(fresh));
}

async function refresh() {
  const response = await fetch('/api/state', { cache: 'no-store' });
  if (!response.ok) throw new Error(`state request failed: ${response.status}`);
  state.snapshot = await response.json();
  render();
  status.textContent = `Fresh canonical projection loaded at ${new Date().toLocaleTimeString()}.`;
}

function requestPayload(kind) {
  if (kind === 'terminal_input') return { input: window.prompt('Terminal input') || '' };
  if (kind === 'browser_navigate') return { url: window.prompt('Navigate to URL') || '' };
  if (kind === 'advisory_choose_alternative') return { alternative: window.prompt('Chosen alternative') || '' };
  return {};
}

function approvalFor(kind) {
  if (!['submit_upgrade_activity', 'accept_worker_result'].includes(kind)) return null;
  const approval = window.prompt('Explicit caller approval reference');
  return approval?.trim() || null;
}

async function submit(button) {
  const snapshotAtClick = state.snapshot;
  const authority = snapshotAtClick.authority;
  const kind = button.dataset.control;
  const target = button.dataset.target === 'workspace' ? authority.workspace_id : button.dataset.targetId;
  const providerId = button.dataset.providerId || null;
  const providerGeneration = button.dataset.providerGeneration ? Number(button.dataset.providerGeneration) : null;
  const body = {
    request_id: crypto.randomUUID(),
    kind,
    target_id: target,
    expected: authority,
    provider_id: providerId,
    expected_provider_generation: providerGeneration,
    approval_id: approvalFor(kind),
    payload: requestPayload(kind),
  };
  const response = await fetch('/api/control', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.detail || result.error || `control rejected: ${response.status}`);
  status.textContent = `${kind} authorized for dispatch as ${result.request_id}; this is not completion.`;
  await refresh();
}

document.addEventListener('click', async (event) => {
  const button = event.target.closest('button');
  if (!button) return;
  try {
    if (button.id === 'refresh') await refresh();
    else if (button.dataset.control) await submit(button);
  } catch (error) {
    status.textContent = `Rejected: ${error.message}`;
  }
});

selector.addEventListener('change', () => {
  if (selector.value !== state.snapshot?.authority.workspace_id) {
    status.textContent = `Workspace ${selector.value} is listed, but no authority projection is loaded for it. Refresh/open through the runtime before control.`;
  }
});

refresh().catch((error) => { status.textContent = `State unavailable: ${error.message}`; });
