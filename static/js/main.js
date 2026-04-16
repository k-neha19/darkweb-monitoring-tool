/**
 * DarkWatch — Frontend Logic
 * Handles: form submission, animated progress log,
 *          results rendering, filtering, and modal detail view.
 */

// ── GLOBAL STATE ──────────────────────────────────
let allFindings = [];

// ── CLOCK ─────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toTimeString().split(' ')[0];
}
setInterval(updateClock, 1000);
updateClock();

// ── DEMO FILL ─────────────────────────────────────
function fillDemo() {
  document.getElementById('domain').value       = 'acmecorp.com';
  document.getElementById('company').value      = 'Acme Corporation';
  document.getElementById('email_domain').value = 'acmecorp.com';
  document.getElementById('keywords').value     = 'acme, acmecorp, acme-login, acme-support';
  document.getElementById('ip_address').value   = '203.0.113.42';
}

// ── SCAN PROGRESS MESSAGES ─────────────────────────
const SCAN_STEPS = [
  { msg: 'Initializing scan engine...', delay: 200, type: 'run' },
  { msg: 'Querying breach databases (HIBP, Collection #1)...', delay: 500, type: 'run' },
  { msg: 'Breach database scan complete', delay: 900, type: 'ok' },
  { msg: 'Scanning paste sites (Pastebin, Ghostbin)...', delay: 1100, type: 'run' },
  { msg: 'Paste site scan complete', delay: 1400, type: 'ok' },
  { msg: 'Probing dark web forum indices...', delay: 1550, type: 'run' },
  { msg: 'Forum scan complete', delay: 1800, type: 'ok' },
  { msg: 'Running brand impersonation checks...', delay: 1900, type: 'run' },
  { msg: 'Checking exposed email addresses...', delay: 2100, type: 'run' },
  { msg: 'Querying IP threat intelligence feeds...', delay: 2300, type: 'run' },
  { msg: 'Calculating risk score...', delay: 2600, type: 'run' },
  { msg: 'Aggregating findings...', delay: 2900, type: 'ok' },
];

function runProgressAnimation() {
  const log = document.getElementById('progressLog');
  log.innerHTML = '';
  SCAN_STEPS.forEach(({ msg, delay, type }) => {
    setTimeout(() => {
      const line = document.createElement('div');
      line.className = `log-line ${type}`;
      line.textContent = msg;
      line.style.animationDelay = '0s';
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }, delay);
  });
}

// ── MAIN SCAN FUNCTION ────────────────────────────
async function startScan() {
  const domain      = document.getElementById('domain').value.trim();
  const company     = document.getElementById('company').value.trim();
  const email_domain = document.getElementById('email_domain').value.trim();
  const keywords    = document.getElementById('keywords').value.trim();
  const ip_address  = document.getElementById('ip_address').value.trim();

  if (!domain && !company) {
    alert('Please enter at least a domain name or company name.');
    return;
  }

  // Show progress, hide old results
  document.getElementById('scanProgress').style.display = 'block';
  document.getElementById('resultsSection').style.display = 'none';
  document.getElementById('scanBtn').disabled = true;
  runProgressAnimation();

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, company, email_domain, keywords, ip_address })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Scan failed');
    }

    const data = await res.json();

    // Brief pause so last log lines finish rendering
    await sleep(400);

    document.getElementById('scanProgress').style.display = 'none';
    renderResults(data);
    document.getElementById('resultsSection').style.display = 'block';
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });

  } catch (err) {
    document.getElementById('scanProgress').style.display = 'none';
    alert('Error: ' + err.message);
  } finally {
    document.getElementById('scanBtn').disabled = false;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── RENDER RESULTS ────────────────────────────────
function renderResults(data) {
  allFindings = data.findings;

  // Risk banner
  const risk = data.risk;
  const scoreEl = document.getElementById('riskScore');
  scoreEl.textContent = risk.score;
  scoreEl.style.color = risk.color;
  const levelEl = document.getElementById('riskLevel');
  levelEl.textContent = risk.label;
  levelEl.style.color = risk.color;
  setTimeout(() => {
    document.getElementById('riskBarFill').style.width = risk.score + '%';
    document.getElementById('riskBarFill').style.background =
      `linear-gradient(90deg, ${risk.color}88, ${risk.color})`;
  }, 100);

  // Scan meta
  const assets = data.assets_scanned;
  document.getElementById('scanMeta').innerHTML = `
    <span><b>SCAN TIME</b>  ${data.scan_time}</span>
    <span><b>DOMAIN</b>     ${assets.domain || '—'}</span>
    <span><b>COMPANY</b>    ${assets.company || '—'}</span>
    <span><b>TOTAL HITS</b> ${data.summary.total}</span>
  `;

  // Summary counts
  document.getElementById('countHigh').textContent   = data.summary.high;
  document.getElementById('countMedium').textContent = data.summary.medium;
  document.getElementById('countLow').textContent    = data.summary.low;
  document.getElementById('countTotal').textContent  = data.summary.total;

  // Category bars
  const catContainer = document.getElementById('categoryBars');
  catContainer.innerHTML = '';
  const maxCount = Math.max(...Object.values(data.summary.categories));
  Object.entries(data.summary.categories).forEach(([name, count]) => {
    const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
    const row = document.createElement('div');
    row.className = 'cat-row';
    row.innerHTML = `
      <div class="cat-name">${name.toUpperCase()}</div>
      <div class="cat-track"><div class="cat-fill" style="width:0%" data-pct="${pct}"></div></div>
      <div class="cat-count">${count}</div>
    `;
    catContainer.appendChild(row);
  });
  // Animate bars after paint
  setTimeout(() => {
    document.querySelectorAll('.cat-fill').forEach(el => {
      el.style.width = el.dataset.pct + '%';
    });
  }, 100);

  // Reset filter + render table
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelector('[data-filter="all"]').classList.add('active');
  renderTable(allFindings);
}

// ── RENDER TABLE ──────────────────────────────────
function renderTable(findings) {
  const tbody = document.getElementById('findingsBody');
  tbody.innerHTML = '';

  document.getElementById('findingCount').textContent = `${findings.length} RESULTS`;

  if (findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:30px;font-family:var(--mono);color:var(--text-dim)">NO FINDINGS MATCH THIS FILTER</td></tr>`;
    return;
  }

  findings.forEach((f, idx) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="sev-badge sev-${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td><span class="cat-badge">${f.category}</span></td>
      <td class="td-source">${f.source}</td>
      <td class="td-detail">${escapeHtml(f.detail)}</td>
      <td class="td-time">${f.timestamp}</td>
      <td class="td-action"><button onclick="openModal(${allFindings.indexOf(f)})">DETAIL ▶</button></td>
    `;
    tbody.appendChild(tr);
  });
}

// ── FILTER ────────────────────────────────────────
function filterFindings(filter, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  let filtered;
  if (filter === 'all') {
    filtered = allFindings;
  } else if (['High', 'Medium', 'Low'].includes(filter)) {
    filtered = allFindings.filter(f => f.severity === filter);
  } else {
    filtered = allFindings.filter(f => f.category === filter);
  }
  renderTable(filtered);
}

// ── MODAL ─────────────────────────────────────────
function openModal(idx) {
  const f = allFindings[idx];
  document.getElementById('modalTitle').textContent = f.category.toUpperCase() + ' — DETAIL';

  let html = `
    <div class="detail-row">
      <div class="detail-key">SEVERITY</div>
      <div class="detail-val"><span class="sev-badge sev-${f.severity.toLowerCase()}">${f.severity}</span></div>
    </div>
    <div class="detail-row">
      <div class="detail-key">CATEGORY</div>
      <div class="detail-val bright">${f.category}</div>
    </div>
    <div class="detail-row">
      <div class="detail-key">SOURCE</div>
      <div class="detail-val">${f.source}</div>
    </div>
    <div class="detail-row">
      <div class="detail-key">TIMESTAMP</div>
      <div class="detail-val">${f.timestamp}</div>
    </div>
    <div class="detail-row">
      <div class="detail-key">FINDING</div>
      <div class="detail-val bright">${escapeHtml(f.detail)}</div>
    </div>
    <hr class="detail-divider"/>
    <div class="detail-row"><div class="detail-key" style="color:var(--accent);letter-spacing:2px">RAW DATA</div><div></div></div>
  `;

  // Render each data field
  Object.entries(f.data).forEach(([key, val]) => {
    const label = key.replace(/_/g, ' ').toUpperCase();
    let displayVal;
    if (Array.isArray(val)) {
      displayVal = `<div class="tag-list">${val.map(v => `<span class="tag">${escapeHtml(String(v))}</span>`).join('')}</div>`;
    } else if (val === null || val === undefined) {
      displayVal = `<span style="color:var(--text-dim)">—</span>`;
    } else {
      displayVal = `<span class="detail-val">${escapeHtml(String(val))}</span>`;
    }
    html += `<div class="detail-row"><div class="detail-key">${label}</div><div>${displayVal}</div></div>`;
  });

  document.getElementById('modalBody').innerHTML = html;
  document.getElementById('modalOverlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
}

// Close modal on Escape key
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

// ── HELPERS ───────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
