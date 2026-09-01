try {
  const raw = localStorage.getItem('ptah.presentation');
  if (raw !== null) JSON.parse(raw);
} catch {
  localStorage.removeItem('ptah.presentation');
}

try {
  const raw = localStorage.getItem('ptah.layout.v2');
  if (raw !== null) {
    const layout = JSON.parse(raw);
    const validMode = layout && (layout.layout_mode === 'grid' || layout.layout_mode === 'single');
    const validOrder = layout && Array.isArray(layout.panel_order) && layout.panel_order.every((id) => typeof id === 'string' && id.length > 0);
    if (!validMode || !validOrder) localStorage.removeItem('ptah.layout.v2');
  }
} catch {
  localStorage.removeItem('ptah.layout.v2');
}
