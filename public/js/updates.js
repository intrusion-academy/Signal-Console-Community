// The update banner under the top bar (src/updates.js, GET /api/updates):
// a restart about to apply an update, and a withdrawn running version, for
// every user; a new version available, an update rolled back and stale
// update information for admins; and once per browser, after an update,
// what changed.
import { h, fetchJSON, ts } from './dom.js';
import { pageLink } from './router.js';
import { sessionUser } from './session.js';

const SEEN = 'signal-console.updated-to';
let last = 0;

export async function drawUpdateBanner() {
  const box = document.getElementById('updateBanner');
  if (!box || Date.now() - last < 60000) return;
  last = Date.now();
  const u = await fetchJSON('/api/updates').catch(() => null);
  if (!u) { last = 0; return; }
  const admin = (sessionUser() || {}).role === 'admin';
  const settings = (text) => pageLink('settings', { group: 'updates' }, text);
  let line = null;
  if (u.pending) {
    line = ['warn', `Signal Console restarts at ${ts(u.pending.at)} (or when idle after it) to update to ${u.pending.version}${u.withdrawn ? ', because this version is withdrawn' : ''}. Pages reload when it is back.`];
  } else if (u.withdrawn) {
    line = ['bad', `This Signal Console version (${u.version}) is withdrawn: ${u.withdrawn.reason}. `,
      admin ? settings(u.mode === 'managed' ? 'Update it on Settings › Updates.' : 'Install the new version (Settings › Updates says how).') : 'An admin updates it on Settings › Updates.'];
  } else if (admin && u.rolled_back) {
    line = ['bad', `The update to ${u.rolled_back.version} did not start; Signal Console went back to ${u.version} and its data as it was before. `, settings('Settings › Updates')];
  } else if (admin && u.available) {
    line = ['info', `Signal Console ${u.latest} is available${u.mode === 'managed' && u.auto ? ' - it is applied when the console is idle' : ''}. `, settings('Settings › Updates')];
  } else if (admin && u.stale) {
    line = ['info', `The update information expired on ${ts(u.expires)}: a newer version may not be known. `, settings('Settings › Updates')];
  }
  let seen = null;
  try { seen = window.localStorage.getItem(SEEN); window.localStorage.setItem(SEEN, u.version); } catch { /* storage refused: no "updated" note */ }
  if (!line && seen && seen !== u.version) {
    line = ['info', `Signal Console was updated to ${u.version}. `, u.notes ? h('a', { href: u.notes, target: '_blank', rel: 'noopener' }, 'What changed') : ''];
  }
  box.hidden = !line;
  box.className = `update-banner${line ? ` update-${line[0]}` : ''}`;
  box.replaceChildren(...(line ? line.slice(1) : []));
}
