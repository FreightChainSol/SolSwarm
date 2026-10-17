// Embedded with a nonce: reports remain usable offline, with no external assets.
const cards = [...document.querySelectorAll('.finding')];
const search = document.querySelector('#search-box');
const severityButtons = [...document.querySelectorAll('[data-filter]')];
const surfaceButtons = [...document.querySelectorAll('[data-surface-filter]')];
let severity = 'all';
let surface = 'all';

function filterCards() {
  const query = search.value.trim().toLowerCase();
  let shown = 0;
  for (const card of cards) {
    const level = card.dataset.severity;
    const matchesSeverity = severity === 'all' || level === severity || (severity === 'low' && level === 'info');
    card.hidden = !(matchesSeverity && (surface === 'all' || card.dataset.surface === surface) && (!query || card.textContent.toLowerCase().includes(query)));
    if (!card.hidden) shown++;
  }
  document.querySelector('#results-count').textContent = `${shown} / ${cards.length} findings${surface === 'all' ? '' : ` · ${surface}`}`;
  document.querySelector('#empty-results').hidden = shown !== 0;
  document.querySelector('#reset-filters').hidden = severity === 'all' && surface === 'all' && !query;
  updateExpandLabel();
}

function updateExpandLabel() {
  const visible = cards.filter(card => !card.hidden);
  document.querySelector('#expand-all').textContent = visible.length && visible.every(card => card.open) ? 'Collapse findings' : 'Expand findings';
}

severityButtons.forEach(button => button.addEventListener('click', () => {
  severity = button.dataset.filter;
  severityButtons.forEach(item => {
    const active = item === button;
    item.classList.toggle('active', active);
    item.setAttribute('aria-pressed', String(active));
  });
  filterCards();
}));

surfaceButtons.forEach(button => button.addEventListener('click', () => {
  surface = surface === button.dataset.surfaceFilter ? 'all' : button.dataset.surfaceFilter;
  surfaceButtons.forEach(item => item.setAttribute('aria-pressed', String(item.dataset.surfaceFilter === surface)));
  filterCards();
  document.querySelector('#findings').scrollIntoView({ block: 'start' });
}));

document.querySelector('#reset-filters').addEventListener('click', () => {
  severity = surface = 'all';
  search.value = '';
  severityButtons.forEach(item => {
    const active = item.dataset.filter === 'all';
    item.classList.toggle('active', active);
    item.setAttribute('aria-pressed', String(active));
  });
  surfaceButtons.forEach(item => item.setAttribute('aria-pressed', 'false'));
  filterCards();
});

document.querySelector('#expand-all').addEventListener('click', () => {
  const visible = cards.filter(card => !card.hidden);
  const open = !visible.every(card => card.open);
  visible.forEach(card => { card.open = open; });
  updateExpandLabel();
});

cards.forEach(card => card.addEventListener('toggle', updateExpandLabel));
search.addEventListener('input', filterCards);
filterCards();

function revealAnchor() {
  const target = document.getElementById(location.hash.slice(1));
  if (target?.tagName === 'DETAILS') target.open = true;
}
window.addEventListener('hashchange', revealAnchor);
revealAnchor();

// Opening native details makes all evidence available in a printed report.
let printState = [];
window.addEventListener('beforeprint', () => {
  printState = [...document.querySelectorAll('details')].map(item => [item, item.open]);
  printState.forEach(([item]) => { item.open = true; });
});
window.addEventListener('afterprint', () => {
  printState.forEach(([item, open]) => { item.open = open; });
  printState = [];
});
