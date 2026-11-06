// The section navigator: a small rail on the right edge listing the page's
// panels (every titled card that is not inside another card), so the
// analyst sees at once what the page holds and goes to any panel with one
// click. Its ticks follow the page's panels as they render; the panel in
// view is marked; hovering the rail shows the titles.

import { h } from './dom.js';

const rail = h('nav', { class: 'section-nav', 'aria-label': 'Panels on this page' });
let entries = [];

// panels lists the page's top-level titled cards, each with its title.
function panels(app) {
  return [...app.querySelectorAll('h2[data-title]')]
    .filter((head) => !head.parentElement.parentElement.closest('.card'))
    .map((head) => ({ head, card: head.parentElement, title: head.dataset.title }));
}

// stickyOffset is the height of the page's sticky filter bar, if any, so
// a panel scrolled to lands below it.
function stickyOffset() {
  const bar = document.querySelector('#app .sticky-bar');
  return (bar ? bar.getBoundingClientRect().height : 0) + 12;
}

// goTo opens the panel if it is collapsed, scrolls it smoothly into view
// and flashes its frame, so the eye finds it.
function goTo({ head, card }) {
  if (head.classList.contains('collapsible') && head.nextElementSibling?.style.display === 'none') head.click();
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  window.scrollTo({ top: card.getBoundingClientRect().top + window.scrollY - stickyOffset(), behavior: reduce ? 'auto' : 'smooth' });
  card.classList.remove('nav-flash');
  void card.offsetWidth; // restarts the animation on a second click
  card.classList.add('nav-flash');
}

// markCurrent marks the last panel whose top has passed a third of the window.
function markCurrent() {
  const line = window.innerHeight / 3;
  let current = 0;
  entries.forEach((e, i) => { if (e.card.getBoundingClientRect().top <= line) current = i; });
  if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) current = entries.length - 1;
  [...rail.children].forEach((b, i) => b.classList.toggle('on', i === current));
}

function rebuild(app) {
  const found = panels(app);
  const same = found.length === entries.length && found.every((e, i) => e.head === entries[i].head && e.title === entries[i].title);
  if (same) return markCurrent();
  entries = found;
  rail.replaceChildren(...entries.map((e) => h('button', { type: 'button', title: e.title, onclick: (ev) => { ev.currentTarget.blur(); goTo(e); } },
    h('span', { class: 'section-nav-label' }, e.title.split(' — ')[0]), h('i', { class: 'section-nav-tick' }))));
  rail.classList.toggle('shown', entries.length > 1);
  markCurrent();
}

// startSectionNav adds the rail and keeps it in step with #app's content.
export function startSectionNav(app) {
  document.body.append(rail);
  let pending = 0;
  const later = () => { if (!pending) pending = setTimeout(() => { pending = 0; rebuild(app); }, 120); };
  new window.MutationObserver(later).observe(app, { childList: true, subtree: true });
  let frame = 0;
  const onScroll = () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; markCurrent(); }); };
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
}
