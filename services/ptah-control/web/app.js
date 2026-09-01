const state = { snapshot: null, shell: null };
const status = document.querySelector('#status');
const layoutRoot = document.querySelector('#workspace-shell');
const layoutMode = document.querySelector('#layout-mode');
const LAYOUT_KEY = 'ptah.layout.v2';
const DEFAULT_PANEL_ORDER = [...layoutRoot.querySelectorAll('.panel')].map((panel) => panel.id);

function readLayoutPresentation() {
  try {
    const parsed = JSON.parse(localStorage.getItem(LAYOUT_KEY) || 'null');
    if (!parsed || !Array.isArray(parsed.panel_order)) return null;
    if (!['grid', 'single'].includes(parsed.layout_mode)) return null;
    if (!parsed.panel_order.every((id) => typeof id === 'string' && id.length > 0)) return null;
    return parsed;
  } catch {
    localStorage.removeItem(LAYOUT_KEY);
    return null;
  }
}

function applyLayoutPresentation(layout) {
  const safe = layout || { panel_order: DEFAULT_PANEL_ORDER, layout_mode: 'grid' };
  const panels = new Map([...layoutRoot.querySelectorAll('.panel')].map((panel) => [panel.id, panel]));
  const seen = new Set();
  for (const id of safe.panel_order) {
    const panel = panels.get(id);
    if (!panel || seen.has(id)) continue;
    layoutRoot.append(panel);
    seen.add(id);
  }
  for (const id of DEFAULT_PANEL_ORDER) {
    if (!seen.has(id) && panels.has(id)) layoutRoot.append(panels.get(id));
  }
  layoutRoot.classList.toggle('layout-single', safe.layout_mode === 'single');
  layoutMode.value = safe.layout_mode;
}

function persistLayoutPresentation() {
  const presentation = {
    panel_order: [...layoutRoot.querySelectorAll('.panel')].map((panel) => panel.id),
    layout_mode: layoutMode.value === 'single' ? 'single' : 'grid',
  };
  localStorage.setItem(LAYOUT_KEY, JSON.stringify(presentation));
  applyLayoutPresentation(presentation);
}

function movePanel(panel, direction) {
  const panels = [...layoutRoot.querySelectorAll('.panel')];
  const index = panels.indexOf(panel);
  const targetIndex = index + direction;
  if (index < 0 || targetIndex < 0 || targetIndex >= panels.length) return;
  const target = panels[targetIndex];
  if (direction < 0) layoutRoot.insertBefore(panel, target);
  else layoutRoot.insertBefore(target, panel);
  persistLayoutPresentation();
  panel.focus();
}

function initializeLayoutPresentation() {
  for (const panel of layoutRoot.querySelectorAll('.panel')) {
    panel.draggable = true;
    panel.tabIndex = 0;
    panel.setAttribute('aria-label', `${panel.querySelector('h2')?.textContent || panel.id} panel; Alt+Arrow keys reorder`);
    panel.addEventListener('dragstart', (event) => {
      event.dataTransfer?.setData('text/plain', panel.id);
    });
    panel.addEventListener('dragover', (event) => event.preventDefault());
    panel.addEventListener('drop', (event) => {
      event.preventDefault();
      const sourceId = event.dataTransfer?.getData('text/plain');
      const source = sourceId ? document.getElementById(sourceId) : null;
      if (!source || source === panel || !source.classList.contains('panel')) return;
      layoutRoot.insertBefore(source, panel);
      persistLayoutPresentation();
      source.focus();
    });
    panel.addEventListener('keydown', (event) => {
      if (!event.altKey || !['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      movePanel(panel, ['ArrowUp', 'ArrowLeft'].includes(event.key) ? -1 : 1);
    });
  }
  applyLayoutPresentation(readLayoutPresentation());
}

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

function syncControlAvailability() {
  const authorityWorkspace = state.snapshot?.authority.workspace_id;
  const mismatch = Boolean(authorityWorkspace && selector.value !== authorityWorkspace);
  document.querySelectorAll('button[data-control]').forEach((button) => {
    button.disabled = mismatch;
  });
  return mismatch;
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
  renderOperations(state.shell);
  renderActivities(s.activities);
  renderObjects(s.objects);
  renderAvailability(state.shell);
  renderResults(state.shell);
  renderTerminals(s.terminals);
  renderTransfers(s.transfers);
  renderBrowsers(s.browsers);
  renderHealth(s.nodes, s.providers);
  renderAdvisories(s.advisories);
  renderWorkers(s.workers);
  renderSchedules(state.shell);
  renderConflicts(state.shell);
  renderMaturityPanels(state.shell);
  renderRecovery(s.recovery);
  renderViewsAndLimits(state.shell);
  renderEvidence(s.evidence_links);
  reconcilePresentation(a);
  syncControlAvailability();
}

function renderOperations(shell) {
  const root = document.querySelector('[data-view="operations"]');
  root.replaceChildren(...shell.operations.map((item) => {
    const node = row(item.label, item.effect);
    node.append(el('div', `Grant requirement: ${item.grant_requirement} · status ${item.grant_state}`));
    node.append(el('div', `Caller confirmation: ${item.confirmation_state}`));
    node.append(el('div', `Provider permission relation: ${item.provider_permission_relation} · status ${item.provider_access_state}`, 'boundary'));
    node.append(el('div', `Materialization requirement: ${item.materialization_requirement}`, 'boundary'));
    list(node, 'limitations', 'Limits', item.limits);
    return node;
  }));
}

function renderAvailability(shell) {
  const root = document.querySelector('[data-view="availability"]');
  root.replaceChildren(...shell.availability.map((item) => {
    const node = row(item.object_id, item.state);
    node.append(el('div', `Revision ${item.revision}`, 'boundary'));
    node.append(el('div', item.local_path ? `Local path: ${item.local_path}` : 'No canonical local path is asserted.', 'boundary'));
    list(node, 'evidence', 'Evidence', item.evidence);
    return node;
  }));
}

function renderResults(shell) {
  const root = document.querySelector('[data-view="results"]');
  root.replaceChildren(...shell.results.map((item) => {
    const node = row(item.handle, item.final_state || 'non-final');
    node.append(el('div', `Activity ${item.activity_id}`));
    node.append(el('div', `Caller/reviewer acceptance: ${item.acceptance}`, item.acceptance));
    const partial = item.partial_retained === null ? 'not exposed' : (item.partial_retained ? 'yes' : 'no');
    node.append(el('div', `Partial retained: ${partial} · pageable=${item.pageable} searchable=${item.searchable}`, 'boundary'));
    list(node, 'limitations', 'Limits', item.limitations);
    return node;
  }));
}

function renderSchedules(shell) {
  const root = document.querySelector('[data-view="schedules"]');
  if (!shell.schedules.length) {
    const node = row('No caller-defined schedules', 'none');
    node.append(el('div', `Supported timing modes: ${shell.supported_timing_modes.join(', ')}`, 'boundary'));
    node.append(el('div', 'Ptah does not manufacture schedule purpose, inputs, Provider choice or Grants.', 'boundary'));
    root.replaceChildren(node);
    return;
  }
  root.replaceChildren(...shell.schedules.map((item) => {
    const node = row(item.schedule_id, `${item.timing_mode} · ${item.state}`);
    node.append(el('div', `Input revision ${item.input_revision}`, 'boundary'));
    node.append(el('div', `Provider ${item.provider_id || 'caller not supplied'} · Grant ${item.grant_id || 'caller not supplied'}`, 'boundary'));
    return node;
  }));
}

function renderConflicts(shell) {
  const root = document.querySelector('[data-view="conflicts"]');
  if (!shell.conflicts.length) {
    root.replaceChildren(row('No unresolved projected conflicts', 'clear'));
    return;
  }
  root.replaceChildren(...shell.conflicts.map((item) => {
    const node = row(item.target_id, item.state);
    node.append(el('div', item.detail));
    node.append(el('div', `Caller/reviewer resolution required: ${item.caller_resolution_required ? 'yes' : 'no'}`, 'boundary'));
    return node;
  }));
}

function renderViewsAndLimits(shell) {
  const root = document.querySelector('[data-view="views-limits"]');
  const nodes = shell.views.map((item) => {
    const node = row(item.view_id, item.backing_kind);
    node.append(el('div', `Backing ${item.backing_id} · replaceable=${item.replaceable} authoritative=${item.authoritative}`, 'boundary'));
    return node;
  });
  const limits = row('Workspace limits', shell.profile_id);
  list(limits, 'limitations', 'Visible limits', shell.limits);
  nodes.push(limits);
  root.replaceChildren(...nodes);
}

function renderMaturityPanels(shell) {
  const editor = row('Editor integration', 'projection boundary');
  editor.append(el('div', 'No canonical editor session exists in the current A14 snapshot; D01 does not invent one.', 'boundary'));
  document.querySelector('[data-view="editor"]').replaceChildren(editor);

  const apps = row('Application / Device panels', 'runtime-backed only');
  apps.append(el('div', 'C10/C11 runtime state must be projected by its owning session before this shell can claim a live application or device panel.', 'boundary'));
  document.querySelector('[data-view="applications-devices"]').replaceChildren(apps);

  const media = row('Media / Document panels', 'object-backed only');
  media.append(el('div', 'Viewer chrome is available only when canonical typed Objects/Artifacts provide the backing record.', 'boundary'));
  document.querySelector('[data-view="media-documents"]').replaceChildren(media);

  const approval = row('Control authority', 'separated');
  approval.append(el('div', `Profile ${shell.profile_id}: approval authority=${shell.approval_authority}; context selection authority=${shell.context_selection_authority}; next-action authority=${shell.next_action_authority}.`, 'boundary'));
  const confirmationOps = shell.operations.filter((item) => item.confirmation_requirement === 'required').map((item) => item.label);
  list(approval, 'evidence', 'Explicit-confirmation operations', confirmationOps);
  document.querySelector('[data-view="control-transfer"]').replaceChildren(approval);
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
  const [stateResponse, shellResponse] = await Promise.all([
    fetch('/api/state', { cache: 'no-store' }),
    fetch('/api/shell-v2', { cache: 'no-store' }),
  ]);
  if (!stateResponse.ok) throw new Error(`state request failed: ${stateResponse.status}`);
  if (!shellResponse.ok) throw new Error(`shell-v2 request failed: ${shellResponse.status}`);
  const snapshot = await stateResponse.json();
  const shell = await shellResponse.json();
  if (JSON.stringify(shell.authority) !== JSON.stringify(snapshot.authority)) {
    throw new Error('shell-v2 projection and canonical state use different authority revisions; refresh required');
  }
  state.snapshot = snapshot;
  state.shell = shell;
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
  if (selector.value !== authority.workspace_id) {
    throw new Error(`workspace ${selector.value} has no loaded authority projection; refresh/open it before control`);
  }
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
  await refresh();
  status.textContent = `${kind} authorized for dispatch as ${result.request_id}; this is not completion.`;
}

document.addEventListener('click', async (event) => {
  const button = event.target.closest('button');
  if (!button) return;
  try {
    if (button.id === 'refresh') await refresh();
    else if (button.id === 'reset-layout') {
      localStorage.removeItem(LAYOUT_KEY);
      applyLayoutPresentation({ panel_order: DEFAULT_PANEL_ORDER, layout_mode: 'grid' });
      status.textContent = 'Workspace presentation layout reset; canonical runtime state was unchanged.';
    } else if (button.dataset.control) await submit(button);
  } catch (error) {
    status.textContent = `Rejected: ${error.message}`;
  }
});

layoutMode.addEventListener('change', () => {
  persistLayoutPresentation();
  status.textContent = `Workspace presentation switched to ${layoutMode.value} layout; canonical runtime state was unchanged.`;
});

selector.addEventListener('change', () => {
  if (syncControlAvailability()) {
    status.textContent = `Workspace ${selector.value} is listed, but no authority projection is loaded for it. Refresh/open through the runtime before control.`;
  } else {
    status.textContent = `Canonical workspace ${selector.value} is loaded; protected controls restored.`;
  }
});

initializeLayoutPresentation();
refresh().catch((error) => { status.textContent = `State unavailable: ${error.message}`; });
