/* Dashboard logic — talks to the local backend API. */
const LEVEL_STYLES = {
  low:      { color: 'var(--green)',  bg: 'rgba(46,204,143,.12)' },
  moderate: { color: 'var(--yellow)', bg: 'rgba(244,185,66,.12)' },
  high:     { color: 'var(--orange)', bg: 'rgba(244,123,63,.12)' },
  critical: { color: 'var(--red)',    bg: 'rgba(255,92,92,.14)' },
  invalid:  { color: 'var(--muted)',  bg: 'rgba(147,160,184,.12)' },
};

const $ = (id) => document.getElementById(id);
const form = $('form');
const input = $('email');
const btn = $('btn');
const errorBox = $('error');

document.querySelectorAll('.examples button').forEach((b) => {
  b.addEventListener('click', () => {
    input.value = b.dataset.email;
    form.requestSubmit();
  });
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = input.value.trim();
  if (!email) return;
  btn.disabled = true;
  btn.textContent = 'Analyzing…';
  errorBox.style.display = 'none';
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    render(data);
  } catch (err) {
    errorBox.textContent = `⚠️ ${err.message}`;
    errorBox.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Risk';
  }
});

function setPlaceholder(id, text) {
  const el = $(id);
  el.className = 'placeholder';
  el.textContent = text;
}

function render(data) {
  const p = data.prediction;
  const b = data.breach;

  // --- Gauge ---
  const gauge = $('gauge');
  gauge.className = '';
  gauge.id = 'gauge';
  const style = LEVEL_STYLES[p.riskLevel] || LEVEL_STYLES.low;
  gauge.innerHTML = '';
  const value = document.createElement('div');
  value.className = 'gauge-value';
  value.style.color = style.color;
  value.textContent = p.riskScore === null ? '—' : `${p.riskScore}`;
  const label = document.createElement('div');
  label.className = 'gauge-label';
  label.style.color = style.color;
  label.style.background = style.bg;
  label.textContent = p.riskLevel;
  const sub = document.createElement('div');
  sub.className = 'gauge-sub';
  const sourceLabel = data.meta.source === 'xposedornot'
    ? `live data: XposedOrNot${data.meta.cached ? ' (cached)' : ''}`
    : data.meta.source === 'mock-fallback'
      ? 'simulated demo data'
      : data.meta.source;
  sub.textContent = b.breached
    ? `${b.breachCount} breach record${b.breachCount === 1 ? '' : 's'} found · ${sourceLabel} · ${data.meta.processingMs} ms`
    : `No breach records found · ${sourceLabel} · ${data.meta.processingMs} ms`;
  gauge.append(value, label, sub);

  // Warn visibly when we had to fall back to simulated data
  if (data.meta.warning) {
    errorBox.textContent = `⚠️ ${data.meta.warning}`;
    errorBox.style.borderColor = 'var(--yellow)';
    errorBox.style.color = 'var(--yellow)';
    errorBox.style.background = 'rgba(244,185,66,.1)';
    errorBox.style.display = 'block';
  } else {
    errorBox.style.display = 'none';
    // restore default error styling for future errors
    errorBox.style.borderColor = '';
    errorBox.style.color = '';
    errorBox.style.background = '';
  }

  const chips = document.createElement('div');
  chips.className = 'chips';
  const exposure = p.breachExposure || {};
  const chipData = [
    exposure.credential ? '🔐 passwords leaked' : '🔑 no password leak',
    exposure.count ? `📥 ${exposure.count} breach(es)` : '📥 0 breaches',
    exposure.piiClasses && exposure.piiClasses.length ? `🗂 ${exposure.piiClasses.length} data types` : null,
  ].filter(Boolean);
  for (const text of chipData) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.textContent = text;
    chips.appendChild(chip);
  }
  gauge.appendChild(chips);

  // --- Summary & advice ---
  const summaryEl = $('summary');
  summaryEl.className = '';
  summaryEl.id = 'summary';
  summaryEl.innerHTML = '';
  const s = document.createElement('p');
  s.className = 'summary';
  s.textContent = p.summary;
  summaryEl.appendChild(s);
  const adviceWrap = document.createElement('div');
  adviceWrap.className = 'advice';
  for (const a of p.advice || []) {
    const item = document.createElement('div');
    item.className = 'advice-item';
    item.textContent = a;
    adviceWrap.appendChild(item);
  }
  summaryEl.appendChild(adviceWrap);

  // --- Factors ---
  const factorsEl = $('factors');
  if (!p.factors || !p.factors.length) {
    setPlaceholder('factors', 'No factors computed (invalid email).');
  } else {
    factorsEl.className = '';
    factorsEl.id = 'factors';
    factorsEl.innerHTML = '';
    const maxImpact = Math.max(...p.factors.map((f) => f.impact), 0.001);
    for (const f of p.factors) {
      const row = document.createElement('div');
      row.className = 'factor-row';
      const top = document.createElement('div');
      top.className = 'factor-top';
      const name = document.createElement('span');
      name.textContent = f.label;
      const impact = document.createElement('span');
      impact.className = 'factor-impact';
      impact.textContent = f.impact > 0 ? `+${f.impact.toFixed(2)} · ${f.impactPct}%` : '0';
      if (f.impact > maxImpact * 0.5) impact.style.color = style.color;
      top.append(name, impact);
      const bar = document.createElement('div');
      bar.className = 'factor-bar';
      const fill = document.createElement('div');
      fill.className = 'factor-fill';
      fill.style.width = `${Math.round((f.impact / maxImpact) * 100)}%`;
      fill.style.background = f.impact > 0 ? style.color : 'var(--muted)';
      bar.appendChild(fill);
      const detail = document.createElement('div');
      detail.className = 'factor-detail';
      detail.textContent = f.detail;
      row.append(top, bar, detail);
      factorsEl.appendChild(row);
    }
  }

  // --- Breaches ---
  const breachesEl = $('breaches');
  if (!b.breaches || !b.breaches.length) {
    setPlaceholder('breaches', '✅ No known breaches contain this address. New breaches surface daily — check back periodically.');
  } else {
    breachesEl.className = '';
    breachesEl.id = 'breaches';
    breachesEl.innerHTML = '';
    for (const br of b.breaches) {
      const item = document.createElement('div');
      item.className = 'breach-item';
      const head = document.createElement('div');
      head.className = 'breach-head';
      const name = document.createElement('span');
      name.className = 'breach-name';
      name.textContent = br.site;
      const date = document.createElement('span');
      date.className = 'breach-date';
      date.textContent = `breached ${br.breachDate} · severity ${br.severity}/10${br.verified ? '' : ' · unverified'}`;
      head.append(name, date);
      const desc = document.createElement('div');
      desc.className = 'breach-desc';
      desc.textContent = br.description;
      const chipRow = document.createElement('div');
      chipRow.className = 'breach-chips';
      for (const c of br.dataClasses) {
        const chip = document.createElement('span');
        chip.className = 'chip' + (/password/i.test(c) ? ' cred' : '');
        chip.textContent = c;
        chipRow.appendChild(chip);
      }
      item.append(head, desc, chipRow);
      breachesEl.appendChild(item);
    }
  }
}
