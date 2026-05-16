const form = document.querySelector("#scan-form");
const targetInput = document.querySelector("#target");
const authorizedInput = document.querySelector("#authorized");
const lightActiveInput = document.querySelector("#light-active");
const scanButton = document.querySelector("#scan-button");
const loadDemoButton = document.querySelector("#load-demo");
const exportButton = document.querySelector("#export-report");
const clearHistoryButton = document.querySelector("#clear-history");
const statusNode = document.querySelector("#status");
const scoreNode = document.querySelector("#score");
const scoreLabelNode = document.querySelector("#score-label");
const meterNode = document.querySelector("#meter");
const recommendationNode = document.querySelector("#recommendation");
const criticalCountNode = document.querySelector("#critical-count");
const highCountNode = document.querySelector("#high-count");
const mediumCountNode = document.querySelector("#medium-count");
const lowCountNode = document.querySelector("#low-count");
const infoCountNode = document.querySelector("#info-count");
const metaNode = document.querySelector("#scan-meta");
const findingsNode = document.querySelector("#findings");
const headersNode = document.querySelector("#headers");
const historyNode = document.querySelector("#history");
const filterButtons = document.querySelectorAll("[data-filter]");

const historyKey = "webVulnScannerHistory";
let currentReport = null;
let activeFilter = "all";

const demoReport = {
  target: "https://demo-authorized-app.test/",
  finalUrl: "https://demo-authorized-app.test/",
  scannedAt: new Date().toISOString(),
  mode: "Passive + safe light active",
  status: 200,
  score: 100,
  summary: { critical: 2, high: 5, medium: 2, low: 1, info: 1 },
  recommendation: "Critical risk. Treat this as urgent: remove exposure, rotate secrets, and verify impact immediately.",
  findings: [
    {
      title: "Environment file exposed",
      severity: "critical",
      category: "Exposure Checks",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/.env",
      evidence: "Matched sensitive content at /.env",
      remediation: "Remove public access to .env and rotate every exposed credential.",
    },
    {
      title: "Private key exposed in response",
      severity: "critical",
      category: "Secrets Exposure",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/",
      evidence: "Private key marker was found in the response body.",
      remediation: "Remove the key immediately and rotate impacted credentials.",
    },
    {
      title: "Sensitive cookie missing HttpOnly",
      severity: "high",
      category: "Cookie Security",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/",
      evidence: "sessionid",
      remediation: "Set HttpOnly on session/auth cookies.",
    },
    {
      title: "Weak Content-Security-Policy",
      severity: "high",
      category: "Security Headers",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/",
      evidence: "script-src * 'unsafe-inline'",
      remediation: "Remove unsafe-inline and broad wildcards where possible.",
    },
    {
      title: "Reflected XSS indicator",
      severity: "high",
      category: "XSS",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/search?q=%3Cctscan-xss-demo%3E",
      evidence: "Parameter q reflected an HTML-like canary without encoding.",
      remediation: "Contextually encode reflected input and validate untrusted parameters before rendering.",
    },
    {
      title: "SQL injection error indicator",
      severity: "high",
      category: "SQL Injection",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/products?id=ctscan'",
      evidence: "Database error appeared after a quote canary was sent to parameter id.",
      remediation: "Use parameterized queries, avoid string-built SQL, and hide database errors from users.",
    },
    {
      title: "Open redirect indicator",
      severity: "high",
      category: "Open Redirect",
      confidence: "Firm",
      affectedUrl: "https://demo-authorized-app.test/login?next=https://example.com/ctscan-open-redirect",
      evidence: "Parameter next redirected to https://example.com/ctscan-open-redirect.",
      remediation: "Allow only relative redirects or validate redirect destinations against a strict allowlist.",
    },
  ],
  observed: {
    headers: {
      server: "nginx/1.22.0",
      "x-powered-by": "Express",
      "content-security-policy": "script-src * 'unsafe-inline'",
      "set-cookie": "sessionid=demo",
    },
    cookies: ["sessionid=demo"],
    bodyBytesRead: 48211,
  },
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function riskLevel(score, summary = {}) {
  if ((summary.critical || 0) > 0 || score >= 90) return { label: "Critical risk", className: "critical", color: "var(--critical)" };
  if (score >= 70) return { label: "High risk", className: "high", color: "var(--danger)" };
  if (score >= 35) return { label: "Medium risk", className: "medium", color: "var(--warning)" };
  if (score > 0) return { label: "Low risk", className: "low", color: "var(--low)" };
  return { label: "No scan yet", className: "safe", color: "var(--safe)" };
}

function readHistory() {
  try {
    return JSON.parse(localStorage.getItem(historyKey) || "[]");
  } catch {
    return [];
  }
}

function writeHistory(history) {
  localStorage.setItem(historyKey, JSON.stringify(history.slice(0, 12)));
}

function saveHistory(report) {
  if (!report) return;
  const history = readHistory();
  const entry = {
    id: crypto.randomUUID(),
    target: report.finalUrl || report.target,
    scannedAt: report.scannedAt,
    score: report.score,
    summary: report.summary,
    report,
  };
  writeHistory([entry, ...history]);
  renderHistory();
}

function renderHistory() {
  const history = readHistory();
  historyNode.innerHTML = "";
  if (history.length === 0) {
    historyNode.innerHTML = '<p class="empty">No scan history yet.</p>';
    return;
  }

  history.forEach((entry) => {
    const level = riskLevel(entry.score, entry.summary);
    const item = document.createElement("article");
    item.className = "history-item";
    item.innerHTML = `
      <div>
        <strong>${escapeHtml(entry.target)}</strong>
        <small>${escapeHtml(new Date(entry.scannedAt).toLocaleString())} - ${entry.score}/100</small>
        <div>
          <span class="tag critical">${entry.summary.critical || 0} critical</span>
          <span class="tag high">${entry.summary.high || 0} high</span>
          <span class="tag medium">${entry.summary.medium || 0} medium</span>
        </div>
      </div>
      <button class="secondary compact" type="button" data-history-id="${escapeHtml(entry.id)}">${level.label}</button>
    `;
    historyNode.appendChild(item);
  });
}

function renderReport(report) {
  currentReport = report;
  const level = riskLevel(report.score, report.summary);
  scoreNode.textContent = report.score;
  scoreLabelNode.textContent = level.label;
  scoreLabelNode.style.backgroundColor = level.color;
  meterNode.style.width = `${report.score}%`;
  meterNode.style.backgroundColor = level.color;
  recommendationNode.textContent = report.recommendation;
  criticalCountNode.textContent = report.summary.critical || 0;
  highCountNode.textContent = report.summary.high || 0;
  mediumCountNode.textContent = report.summary.medium || 0;
  lowCountNode.textContent = report.summary.low || 0;
  infoCountNode.textContent = report.summary.info || 0;

  metaNode.innerHTML = `
    <div class="code-row"><strong>Target</strong><br><code>${escapeHtml(report.target)}</code></div>
    <div class="code-row"><strong>Final URL</strong><br><code>${escapeHtml(report.finalUrl)}</code></div>
    <div class="code-row"><strong>Mode</strong><br><code>${escapeHtml(report.mode)}</code></div>
    <div class="code-row"><strong>Status</strong><br><code>${escapeHtml(report.status)}</code></div>
  `;

  renderFindings();
  renderHeaders(report.observed?.headers || {});
}

function renderFindings() {
  const findings = currentReport?.findings || [];
  const visible = activeFilter === "all" ? findings : findings.filter((finding) => finding.severity === activeFilter);
  findingsNode.innerHTML = "";

  if (visible.length === 0) {
    findingsNode.innerHTML = '<p class="empty">No findings match this filter.</p>';
    return;
  }

  visible.forEach((finding) => {
    const item = document.createElement("article");
    item.className = `finding ${finding.severity}`;
    item.innerHTML = `
      <div class="finding-head">
        <div>
          <h3>${escapeHtml(finding.title)}</h3>
          <p>${escapeHtml(finding.category)} - ${escapeHtml(finding.confidence)}</p>
        </div>
        <span class="tag ${finding.severity}">${escapeHtml(finding.severity.toUpperCase())}</span>
      </div>
      <p><strong>Affected:</strong> <code>${escapeHtml(finding.affectedUrl)}</code></p>
      <p class="evidence"><strong>Evidence:</strong> ${escapeHtml(finding.evidence)}</p>
      <p><strong>Fix:</strong> ${escapeHtml(finding.remediation)}</p>
    `;
    findingsNode.appendChild(item);
  });
}

function renderHeaders(headers) {
  const entries = Object.entries(headers);
  headersNode.innerHTML = "";
  if (entries.length === 0) {
    headersNode.innerHTML = '<p class="empty">No headers captured yet.</p>';
    return;
  }

  entries.forEach(([name, value]) => {
    const item = document.createElement("div");
    item.className = "code-row";
    item.innerHTML = `<strong>${escapeHtml(name)}</strong><br><code>${escapeHtml(value)}</code>`;
    headersNode.appendChild(item);
  });
}

async function startScan() {
  scanButton.disabled = true;
  statusNode.textContent = "Scanning with safe critical/high checks...";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: targetInput.value,
        authorized: authorizedInput.checked,
        includeLightActive: lightActiveInput.checked,
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Scan failed.");
    renderReport(payload);
    saveHistory(payload);
    statusNode.textContent = "Scan complete.";
  } catch (error) {
    statusNode.textContent = error.message;
  } finally {
    scanButton.disabled = false;
  }
}

function exportReport() {
  if (!currentReport) {
    statusNode.textContent = "Run or load a report before exporting.";
    return;
  }
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `web-vulnerability-report-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  startScan();
});

loadDemoButton.addEventListener("click", () => {
  renderReport(demoReport);
  saveHistory(demoReport);
  statusNode.textContent = "Demo report loaded.";
});

exportButton.addEventListener("click", exportReport);

clearHistoryButton.addEventListener("click", () => {
  writeHistory([]);
  renderHistory();
});

historyNode.addEventListener("click", (event) => {
  const button = event.target.closest("[data-history-id]");
  if (!button) return;
  const entry = readHistory().find((item) => item.id === button.dataset.historyId);
  if (entry) renderReport(entry.report);
});

filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    activeFilter = button.dataset.filter;
    filterButtons.forEach((item) => item.classList.toggle("active", item === button));
    renderFindings();
  });
});

renderHistory();
