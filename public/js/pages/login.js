// The sign-in page: an account name and password, checked by the server
// (POST /api/auth/login). Accounts are created on the server's command line
// (npm run users), so this page offers no sign-up. After signing in, the
// page asked for before (?next=) opens.

import { h, fetchJSON } from '../dom.js';
import { urlParams } from '../router.js';
import { setSession } from '../session.js';

export async function renderLogin(container, onSignedIn) {
  const username = h('input', { type: 'text', name: 'username', autocomplete: 'username', required: 'required' });
  const password = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: 'required' });
  const status = h('div', { class: 'result-err', role: 'alert' });
  const button = h('button', { class: 'btn', type: 'submit' }, 'Sign in');
  const form = h('form', { class: 'card login-card', onsubmit: async (e) => {
    e.preventDefault();
    button.disabled = true;
    status.textContent = '';
    try {
      setSession(await fetchJSON('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: username.value, password: password.value }) }));
      onSignedIn(urlParams().get('next') || '/overview');
    } catch (err) {
      status.textContent = err.message;
      password.value = '';
      button.disabled = false;
    }
  } },
  h('div', { class: 'login-brand', role: 'img', 'aria-label': 'Signal' }, h('span', { class: 'brand-mark' }), h('span', { class: 'brand-word' })),
  h('h2', {}, 'Sign in to Signal Console'),
  h('label', {}, h('span', { class: 'mut' }, 'Account'), username),
  h('label', {}, h('span', { class: 'mut' }, 'Password'), password),
  button, status,
  h('div', { class: 'mut login-note' }, 'Accounts are created by an administrator - on the Settings page, or on the server (npm run users).'));
  container.replaceChildren(form);
  username.focus();
}
