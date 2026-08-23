try {
  const raw = localStorage.getItem('ptah.presentation');
  if (raw !== null) JSON.parse(raw);
} catch {
  localStorage.removeItem('ptah.presentation');
}
