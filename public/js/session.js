// The signed-in account, for the pages to know what to offer: a viewer
// account is read-only, so its pages leave out what would change anything
// (the server refuses it regardless - see src/auth.js).

let current = null;

// loadSession asks the server who is signed in; null when no one is.
export async function loadSession() {
  const res = await fetch('/api/auth/me');
  current = res.ok ? (await res.json()) || null : null;
  return current;
}

export function setSession(user) { current = user; }
export function sessionUser() { return current; }

// canEdit reports whether the signed-in account may change anything:
// triage, suppress, import, remove.
export function canEdit() { return Boolean(current && current.role !== 'viewer'); }

// isAdmin reports whether the signed-in account is an admin: the only role
// that changes the console's shared settings (VirusTotal, KEV and NVD) or
// deletes what only an admin may - the server refuses anyone else.
export function isAdmin() { return Boolean(current && current.role === 'admin'); }
