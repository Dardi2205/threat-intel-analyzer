const trustedBrands = [
  "amazon",
  "apple",
  "bankofamerica",
  "chase",
  "facebook",
  "google",
  "instagram",
  "microsoft",
  "netflix",
  "paypal",
  "wellsfargo",
];

const riskyTlds = new Set(["zip", "mov", "click", "top", "tk", "gq", "cf", "ml", "xyz", "work"]);

const urgencyWords = [
  "act now",
  "account suspended",
  "confirm immediately",
  "final notice",
  "limited time",
  "locked",
  "urgent",
  "verify within",
  "within 24 hours",
];

const credentialWords = [
  "confirm your password",
  "login to verify",
  "payment details",
  "security code",
  "social security",
  "update billing",
  "verify your account",
];

const attachmentWords = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", "macro enabled"];
const freeMailDomains = new Set(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me"]);

const sample = `From: PayPal Security <support@paypaI-secure-login.com>
Subject: URGENT: Your account will be suspended in 24 hours

We noticed unusual activity. Click here to verify your account immediately:
http://paypaI-secure-login.com/account/verify?session=8842

Please update billing and confirm your password to avoid account locked status.`;

const headerSample = `Return-Path: <billing@paypaI-alerts.com>
Received: from unknown (HELO mail.paypaI-alerts.com) (185.199.110.153)
  by mx.google.com with ESMTP id q7si1234567 for <victim@example.com>;
  Thu, 14 May 2026 09:15:22 +0200
Received-SPF: fail (google.com: domain of billing@paypaI-alerts.com does not designate 185.199.110.153 as permitted sender)
Authentication-Results: mx.google.com;
  spf=fail smtp.mailfrom=paypaI-alerts.com;
  dkim=none;
  dmarc=fail header.from=paypal.com
From: PayPal Support <support@paypal.com>
Reply-To: billing@paypaI-alerts.com
Subject: Urgent billing verification required
Message-ID: <8842@paypaI-alerts.com>
X-Mailer: PHP/8.1`;

let activeMode = "message";
let currentMessageReport = null;
let currentHeaderReport = null;
let currentVirusTotalResults = [];

const historyKey = "cyberThreatAnalyzerHistory";

const modeButtons = document.querySelectorAll("[data-mode]");
const modePanels = document.querySelectorAll(".mode-panel");
const modeDetails = document.querySelectorAll(".mode-detail");
const input = document.querySelector("#scan-input");
const form = document.querySelector("#scan-form");
const loadSampleButton = document.querySelector("#load-sample");
const clearButton = document.querySelector("#clear-scan");
const exportMessageButton = document.querySelector("#export-message-report");
const virusTotalButton = document.querySelector("#check-virustotal");
const virusTotalStatus = document.querySelector("#vt-status");
const scoreNode = document.querySelector("#risk-score");
const levelNode = document.querySelector("#risk-level");
const summaryNode = document.querySelector("#summary");
const meterNode = document.querySelector("#risk-meter");
const urlCountNode = document.querySelector("#url-count");
const signalCountNode = document.querySelector("#signal-count");
const domainCountNode = document.querySelector("#domain-count");
const findingsList = document.querySelector("#findings-list");
const urlList = document.querySelector("#url-list");
const virusTotalList = document.querySelector("#vt-list");
const headerForm = document.querySelector("#header-form");
const headerInput = document.querySelector("#header-input");
const loadHeaderSampleButton = document.querySelector("#load-header-sample");
const clearHeadersButton = document.querySelector("#clear-headers");
const exportHeaderButton = document.querySelector("#export-header-report");
const headerSummaryNode = document.querySelector("#header-summary");
const headerMeterNode = document.querySelector("#header-risk-meter");
const headerCountNode = document.querySelector("#header-count");
const headerSignalCountNode = document.querySelector("#header-signal-count");
const hopCountNode = document.querySelector("#hop-count");
const headerFindingsList = document.querySelector("#header-findings-list");
const headerDetailsList = document.querySelector("#header-details-list");
const iocList = document.querySelector("#ioc-list");
const historyList = document.querySelector("#history-list");
const clearHistoryButton = document.querySelector("#clear-history");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function extractUrls(text) {
  const matches = text.match(/https?:\/\/[^\s<>"')]+|www\.[^\s<>"')]+/gi) || [];
  return [...new Set(matches.map((url) => url.replace(/[.,;!?]+$/, "")))];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function extractIocs(text) {
  const urls = extractUrls(text);
  const emails = unique((text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []).map((value) => value.toLowerCase()));
  const ips = unique(text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []);
  const hashes = unique(text.match(/\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi) || []);
  const domainsFromUrls = urls
    .map(parseUrl)
    .filter(Boolean)
    .map((url) => url.hostname.toLowerCase().replace(/^www\./, ""));
  const domainsFromEmails = emails.map((email) => email.split("@").at(-1));
  const domains = unique([...domainsFromUrls, ...domainsFromEmails]);

  return { urls, domains, ips, emails, hashes };
}

function countSeverity(findings) {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] = (counts[finding.severity] || 0) + 1;
      return counts;
    },
    { high: 0, medium: 0, info: 0 },
  );
}

function analystRecommendation(score, findings) {
  if (score >= 65 || findings.some((finding) => finding.severity === "high")) {
    return "Do not click links or reply until the sender is verified through a trusted channel.";
  }

  if (score >= 32) {
    return "Verify the sender and inspect the suspicious indicators before taking action.";
  }

  return "No obvious high-risk signals were found, but still verify unexpected requests.";
}

function parseUrl(rawUrl) {
  try {
    const normalized = rawUrl.startsWith("www.") ? `https://${rawUrl}` : rawUrl;
    return new URL(normalized);
  } catch {
    return null;
  }
}

function hostnameParts(hostname) {
  const clean = hostname.toLowerCase().replace(/^www\./, "");
  const parts = clean.split(".");
  return {
    clean,
    tld: parts.at(-1) || "",
    root: parts.length >= 2 ? parts.at(-2) : clean,
    subdomains: parts.slice(0, -2),
  };
}

function levenshtein(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, row) => [row]);
  for (let col = 0; col <= a.length; col += 1) matrix[0][col] = col;

  for (let row = 1; row <= b.length; row += 1) {
    for (let col = 1; col <= a.length; col += 1) {
      matrix[row][col] = b[row - 1] === a[col - 1]
        ? matrix[row - 1][col - 1]
        : Math.min(matrix[row - 1][col - 1] + 1, matrix[row][col - 1] + 1, matrix[row - 1][col] + 1);
    }
  }

  return matrix[b.length][a.length];
}

function addFinding(findings, severity, title, detail, score) {
  findings.push({ severity, title, detail, score });
}

function emailAddress(value) {
  const match = String(value || "").match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0].toLowerCase() : "";
}

function domainFromEmail(value) {
  const address = emailAddress(value);
  return address.includes("@") ? address.split("@").at(-1) : "";
}

function rootDomain(domain) {
  const parts = String(domain || "").toLowerCase().split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : parts.join(".");
}

function parseHeaders(text) {
  const unfolded = [];
  text.replace(/\r\n/g, "\n").split("\n").forEach((line) => {
    if (/^\s/.test(line) && unfolded.length) {
      unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    } else if (line.trim()) {
      unfolded.push(line.trim());
    }
  });

  const headers = new Map();
  unfolded.forEach((line) => {
    const separator = line.indexOf(":");
    if (separator <= 0) return;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!headers.has(name)) headers.set(name, []);
    headers.get(name).push(value);
  });

  return { headers, unfolded };
}

function headerValues(headers, name) {
  return headers.get(name.toLowerCase()) || [];
}

function firstHeader(headers, name) {
  return headerValues(headers, name)[0] || "";
}

function analyzeHeaders(text) {
  const findings = [];
  const { headers, unfolded } = parseHeaders(text);
  const from = firstHeader(headers, "from");
  const replyTo = firstHeader(headers, "reply-to");
  const returnPath = firstHeader(headers, "return-path");
  const authResults = headerValues(headers, "authentication-results").join(" ");
  const receivedSpf = headerValues(headers, "received-spf").join(" ");
  const received = headerValues(headers, "received");
  const messageId = firstHeader(headers, "message-id");
  const xMailer = firstHeader(headers, "x-mailer");
  const fromDomain = domainFromEmail(from);
  const replyToDomain = domainFromEmail(replyTo);
  const returnPathDomain = domainFromEmail(returnPath);
  const messageIdDomain = domainFromEmail(messageId);
  const authText = `${authResults} ${receivedSpf}`.toLowerCase();

  if (!text.trim()) {
    return { score: 0, findings: [], headerCount: 0, hopCount: 0, details: [], iocs: extractIocs("") };
  }

  if (!from) {
    addFinding(findings, "high", "Missing From header", "A normal email should include a clear From header.", 18);
  }

  if (!authResults && !receivedSpf) {
    addFinding(findings, "medium", "No authentication results found", "SPF, DKIM, and DMARC results were not visible in the pasted headers.", 10);
  }

  if (/spf=(fail|softfail|neutral|none)|received-spf:\s*(fail|softfail|neutral|none)/i.test(authText)) {
    const severity = /spf=fail|received-spf:\s*fail/i.test(authText) ? "high" : "medium";
    addFinding(findings, severity, "SPF did not pass", "The sender IP may not be authorized to send for the claimed envelope domain.", severity === "high" ? 18 : 10);
  }

  if (/dkim=(fail|none|neutral|temperror|permerror)/i.test(authText) || !headers.has("dkim-signature")) {
    const missingOnly = !/dkim=(fail|none|neutral|temperror|permerror)/i.test(authText) && !headers.has("dkim-signature");
    addFinding(
      findings,
      missingOnly ? "medium" : "high",
      missingOnly ? "No DKIM signature visible" : "DKIM did not pass",
      missingOnly ? "A missing DKIM signature lowers confidence in the sender identity." : "The message was not cryptographically verified for the claimed domain.",
      missingOnly ? 8 : 18,
    );
  }

  if (/dmarc=(fail|none|temperror|permerror)/i.test(authText)) {
    addFinding(findings, "high", "DMARC did not pass", "The visible From domain did not pass DMARC alignment checks.", 20);
  }

  if (fromDomain && replyToDomain && rootDomain(fromDomain) !== rootDomain(replyToDomain)) {
    addFinding(findings, "high", "Reply-To domain mismatch", `Replies go to ${replyToDomain}, but the From domain is ${fromDomain}.`, 18);
  }

  if (fromDomain && returnPathDomain && rootDomain(fromDomain) !== rootDomain(returnPathDomain)) {
    addFinding(findings, "medium", "Return-Path domain mismatch", `Bounces route through ${returnPathDomain}, not ${fromDomain}.`, 10);
  }

  if (fromDomain && messageIdDomain && rootDomain(fromDomain) !== rootDomain(messageIdDomain)) {
    addFinding(findings, "medium", "Message-ID domain mismatch", `Message-ID references ${messageIdDomain}, which differs from ${fromDomain}.`, 8);
  }

  trustedBrands.forEach((brand) => {
    const displayMentionsBrand = from.toLowerCase().includes(brand);
    const domainRoot = fromDomain.split(".").at(-2) || "";
    if (displayMentionsBrand && fromDomain && domainRoot !== brand) {
      addFinding(findings, "high", "Brand display name mismatch", `The sender name mentions ${brand}, but the email domain is ${fromDomain}.`, 18);
    }
  });

  if (fromDomain && freeMailDomains.has(rootDomain(fromDomain)) && /(support|security|billing|admin|account)/i.test(from)) {
    addFinding(findings, "medium", "Official-sounding free email sender", "Support or billing messages from free email domains deserve extra caution.", 10);
  }

  if (/php|wordpress|massmail|bulk/i.test(xMailer)) {
    addFinding(findings, "info", "Bulk or script mailer", `X-Mailer shows "${xMailer}", which can appear in automated phishing campaigns.`, 4);
  }

  if (received.length === 0) {
    addFinding(findings, "medium", "No Received path", "Missing Received headers make delivery path verification harder.", 8);
  } else if (received.length > 6) {
    addFinding(findings, "info", "Long delivery path", `${received.length} Received hops were found. Long routes can be normal but are worth reviewing.`, 4);
  }

  const score = Math.min(100, findings.reduce((total, finding) => total + finding.score, 0));
  const details = [
    { title: "From", value: from || "Not found" },
    { title: "Reply-To", value: replyTo || "Not found" },
    { title: "Return-Path", value: returnPath || "Not found" },
    { title: "Authentication", value: authResults || receivedSpf || "Not found" },
    { title: "Received Hops", value: received.length ? received.join("\n\n") : "Not found" },
  ];

  return {
    score,
    findings,
    headerCount: unfolded.length,
    hopCount: received.length,
    details,
    iocs: extractIocs(text),
  };
}

function analyzeText(text) {
  const lower = text.toLowerCase();
  const urls = extractUrls(text);
  const findings = [];
  const domains = new Set();

  urgencyWords.forEach((word) => {
    if (lower.includes(word)) {
      addFinding(findings, "medium", "Urgent pressure language", `"${word}" appears in the message.`, 10);
    }
  });

  credentialWords.forEach((word) => {
    if (lower.includes(word)) {
      addFinding(findings, "high", "Sensitive information request", `"${word}" asks for credentials, billing, or identity data.`, 16);
    }
  });

  attachmentWords.forEach((word) => {
    if (lower.includes(word)) {
      addFinding(findings, "high", "Risky attachment pattern", `"${word}" is commonly abused in malware delivery.`, 14);
    }
  });

  if (/\bfrom:\s?.+<[^>]+>/i.test(text) && /reply-to:\s?.+/i.test(text)) {
    addFinding(findings, "medium", "Reply-To header present", "A separate Reply-To address can be used to redirect responses.", 8);
  }

  const urlDetails = urls.map((rawUrl) => {
    const parsed = parseUrl(rawUrl);
    if (!parsed) {
      addFinding(findings, "medium", "Malformed URL", `${rawUrl} could not be parsed cleanly.`, 8);
      return { rawUrl, host: "Invalid URL", tags: ["Malformed"] };
    }

    const { clean, root, tld, subdomains } = hostnameParts(parsed.hostname);
    domains.add(clean);
    const tags = [];

    if (parsed.protocol !== "https:") {
      tags.push("No HTTPS");
      addFinding(findings, "medium", "Insecure link", `${clean} uses ${parsed.protocol.replace(":", "").toUpperCase()} instead of HTTPS.`, 8);
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
      tags.push("IP address");
      addFinding(findings, "high", "Raw IP address URL", "Legitimate brands rarely ask users to sign in through a bare IP address.", 18);
    }

    if (clean.includes("@")) {
      tags.push("@ symbol");
      addFinding(findings, "high", "Deceptive @ symbol", "Text before @ can hide the real destination in some URLs.", 16);
    }

    if (clean.includes("-")) {
      tags.push("Hyphenated domain");
      addFinding(findings, "info", "Hyphenated domain", `${clean} uses hyphens, which are common in impersonation domains.`, 4);
    }

    if (subdomains.length >= 3) {
      tags.push("Many subdomains");
      addFinding(findings, "medium", "Long subdomain chain", `${clean} has several subdomains before the real domain.`, 8);
    }

    if (riskyTlds.has(tld)) {
      tags.push("Risky TLD");
      addFinding(findings, "medium", "Unusual top-level domain", `.${tld} is often seen in low-cost phishing campaigns.`, 9);
    }

    if (/[il1o0]/i.test(root)) {
      const normalizedRoot = root.replaceAll("1", "l").replaceAll("0", "o");
      trustedBrands.forEach((brand) => {
        const distance = levenshtein(normalizedRoot, brand);
        if (distance > 0 && distance <= 2) {
          tags.push("Lookalike");
          addFinding(findings, "high", "Possible lookalike domain", `${clean} resembles ${brand}.com but is not the same domain.`, 20);
        }
      });
    }

    trustedBrands.forEach((brand) => {
      if (clean.includes(brand) && root !== brand) {
        tags.push("Brand in domain");
        addFinding(findings, "high", "Brand name used outside root domain", `${clean} contains "${brand}" but the registered-looking root is "${root}".`, 18);
      }
    });

    if (parsed.search.length > 80) {
      tags.push("Long query");
      addFinding(findings, "info", "Long tracking query", "Very long query strings can hide redirects or tracking tokens.", 4);
    }

    return {
      rawUrl,
      host: clean,
      protocol: parsed.protocol.replace(":", "").toUpperCase(),
      tags: tags.length ? [...new Set(tags)] : ["No URL-specific flags"],
    };
  });

  if (urls.length === 0 && text.trim()) {
    addFinding(findings, "info", "No URLs found", "The text can still be suspicious, but there were no links to inspect.", 0);
  }

  const score = Math.min(100, findings.reduce((total, finding) => total + finding.score, 0));
  const iocs = extractIocs(text);
  return { score, findings, urls: urlDetails, domains: [...domains], iocs };
}

function riskLevel(score) {
  if (score >= 65) return { text: "High risk", className: "high" };
  if (score >= 32) return { text: "Medium risk", className: "medium" };
  return { text: "Low risk", className: "safe" };
}

function renderResults(result) {
  currentMessageReport = {
    type: "URL & Message",
    createdAt: new Date().toISOString(),
    input: input.value,
    ...result,
    severity: countSeverity(result.findings),
    recommendation: analystRecommendation(result.score, result.findings),
    virusTotal: currentVirusTotalResults,
  };

  const level = riskLevel(result.score);
  scoreNode.textContent = result.score;
  levelNode.textContent = level.text;
  levelNode.className = `risk-level ${level.className}`;
  meterNode.style.width = `${result.score}%`;
  meterNode.style.backgroundColor = result.score >= 65 ? "var(--danger)" : result.score >= 32 ? "var(--warning)" : "var(--safe)";
  urlCountNode.textContent = result.urls.length;
  signalCountNode.textContent = result.findings.length;
  domainCountNode.textContent = result.domains.length;
  summaryNode.textContent = result.findings.length
    ? `${result.findings.length} signal${result.findings.length === 1 ? "" : "s"} found. Review before clicking or replying.`
    : "No obvious threat signals found. Still verify the sender before trusting it.";

  findingsList.innerHTML = "";
  if (result.findings.length === 0) {
    findingsList.innerHTML = '<li class="empty-state">No suspicious signals detected.</li>';
  } else {
    result.findings.forEach((finding) => {
      const item = document.createElement("li");
      item.className = `finding ${finding.severity}`;
      item.innerHTML = `<strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.detail)}</small>`;
      findingsList.appendChild(item);
    });
  }

  urlList.innerHTML = "";
  if (result.urls.length === 0) {
    urlList.innerHTML = '<p class="empty-state">No URLs found.</p>';
  } else {
    result.urls.forEach((url) => {
      const item = document.createElement("article");
      item.className = "url-item";
      const tags = url.tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("");
      item.innerHTML = `
        <code>${escapeHtml(url.rawUrl)}</code>
        <small>${escapeHtml(url.host)}${url.protocol ? ` - ${escapeHtml(url.protocol)}` : ""}</small>
        <div class="url-meta">${tags}</div>
      `;
      urlList.appendChild(item);
    });
  }

  renderIocs(result.iocs);
}

function renderVirusTotalResults(results) {
  currentVirusTotalResults = results;
  if (currentMessageReport) currentMessageReport.virusTotal = results;
  virusTotalList.innerHTML = "";

  if (results.length === 0) {
    virusTotalList.innerHTML = '<p class="empty-state">No URLs found for VirusTotal lookup.</p>';
    return;
  }

  results.forEach((result) => {
    const item = document.createElement("article");
    const stats = result.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const level = malicious > 0 ? "high" : suspicious > 0 ? "medium" : "safe";
    const detectionText = `${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless, ${undetected} undetected`;

    item.className = `url-item ${level}`;
    item.innerHTML = `
      <code>${escapeHtml(result.url)}</code>
      <small>${escapeHtml(result.error ? result.error : detectionText)}</small>
      <div class="url-meta">
        <span class="tag ${level}">${result.found ? "Report found" : "No report"}</span>
        <span class="tag ${level}">${malicious + suspicious} detections</span>
        ${result.link ? `<a class="tag" href="${escapeHtml(result.link)}" target="_blank" rel="noreferrer">Open report</a>` : ""}
      </div>
    `;
    virusTotalList.appendChild(item);
  });
}

function renderHeaderResults(result) {
  currentHeaderReport = {
    type: "Email Headers",
    createdAt: new Date().toISOString(),
    input: headerInput.value,
    ...result,
    severity: countSeverity(result.findings),
    recommendation: analystRecommendation(result.score, result.findings),
  };

  const level = riskLevel(result.score);
  scoreNode.textContent = result.score;
  levelNode.textContent = level.text;
  levelNode.className = `risk-level ${level.className}`;
  headerMeterNode.style.width = `${result.score}%`;
  headerMeterNode.style.backgroundColor = result.score >= 65 ? "var(--danger)" : result.score >= 32 ? "var(--warning)" : "var(--safe)";
  headerCountNode.textContent = result.headerCount;
  headerSignalCountNode.textContent = result.findings.length;
  hopCountNode.textContent = result.hopCount;
  headerSummaryNode.textContent = result.findings.length
    ? `${result.findings.length} header signal${result.findings.length === 1 ? "" : "s"} found. Check sender identity before trusting it.`
    : "No obvious header risks found in the pasted data.";

  headerFindingsList.innerHTML = "";
  if (result.findings.length === 0) {
    headerFindingsList.innerHTML = '<li class="empty-state">No header signals detected.</li>';
  } else {
    result.findings.forEach((finding) => {
      const item = document.createElement("li");
      item.className = `finding ${finding.severity}`;
      item.innerHTML = `<strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.detail)}</small>`;
      headerFindingsList.appendChild(item);
    });
  }

  headerDetailsList.innerHTML = "";
  if (result.details.length === 0) {
    headerDetailsList.innerHTML = '<p class="empty-state">No header details parsed yet.</p>';
  } else {
    result.details.forEach((detail) => {
      const item = document.createElement("article");
      item.className = "url-item";
      item.innerHTML = `<strong>${escapeHtml(detail.title)}</strong><pre>${escapeHtml(detail.value)}</pre>`;
      headerDetailsList.appendChild(item);
    });
  }

  renderIocs(result.iocs);
}

function renderIocs(iocs) {
  const groups = [
    ["URLs", iocs?.urls || []],
    ["Domains", iocs?.domains || []],
    ["IPs", iocs?.ips || []],
    ["Emails", iocs?.emails || []],
    ["Hashes", iocs?.hashes || []],
  ];

  iocList.innerHTML = "";
  if (groups.every(([, values]) => values.length === 0)) {
    iocList.innerHTML = '<p class="empty-state">No indicators extracted from this scan.</p>';
    return;
  }

  groups.forEach(([title, values]) => {
    const item = document.createElement("article");
    item.className = "ioc-card url-item";
    item.innerHTML = `
      <strong>${title}</strong>
      <small>${values.length} found</small>
      ${values.length ? values.slice(0, 8).map((value) => `<code>${escapeHtml(value)}</code>`).join("") : "<small>None</small>"}
    `;
    iocList.appendChild(item);
  });
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
  if (!report || !report.input.trim()) return;

  const history = readHistory();
  const entry = {
    id: crypto.randomUUID(),
    type: report.type,
    createdAt: report.createdAt,
    score: report.score,
    severity: report.severity,
    recommendation: report.recommendation,
    input: report.input,
    findingTitles: report.findings.slice(0, 3).map((finding) => finding.title),
  };

  writeHistory([entry, ...history]);
  renderHistory();
}

function renderHistory() {
  const history = readHistory();
  historyList.innerHTML = "";

  if (history.length === 0) {
    historyList.innerHTML = '<p class="empty-state">No saved scans yet.</p>';
    return;
  }

  history.forEach((entry) => {
    const level = riskLevel(entry.score);
    const item = document.createElement("article");
    item.className = `history-item url-item ${level.className}`;
    item.innerHTML = `
      <div>
        <strong>${escapeHtml(entry.type)} - ${entry.score}/100</strong>
        <small>${escapeHtml(new Date(entry.createdAt).toLocaleString())}</small>
        <div class="url-meta">
          <span class="tag high">${entry.severity.high || 0} high</span>
          <span class="tag medium">${entry.severity.medium || 0} medium</span>
          <span class="tag">${entry.severity.info || 0} info</span>
        </div>
      </div>
      <button class="secondary compact" type="button" data-history-id="${escapeHtml(entry.id)}">Load</button>
    `;
    historyList.appendChild(item);
  });
}

function loadHistoryEntry(id) {
  const entry = readHistory().find((item) => item.id === id);
  if (!entry) return;

  if (entry.type === "Email Headers") {
    headerInput.value = entry.input;
    setMode("headers");
    renderHeaderResults(analyzeHeaders(headerInput.value));
  } else {
    input.value = entry.input;
    setMode("message");
    renderResults(analyzeText(input.value));
  }
}

function exportReport(report) {
  if (!report || !report.input.trim()) return;

  const filename = `${report.type.toLowerCase().replaceAll(" ", "-").replaceAll("&", "and")}-${new Date().toISOString().slice(0, 10)}.json`;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function setMode(mode) {
  activeMode = mode;
  modeButtons.forEach((button) => button.classList.toggle("active", button.dataset.mode === mode));
  modePanels.forEach((panel) => panel.classList.toggle("active", panel.id === `${mode}-panel`));
  modeDetails.forEach((detail) => detail.classList.toggle("active", detail.dataset.detail === mode));

  if (mode === "message") {
    renderResults(analyzeText(input.value));
  } else {
    renderHeaderResults(analyzeHeaders(headerInput.value));
  }
}

async function checkVirusTotal() {
  const urls = extractUrls(input.value);

  if (urls.length === 0) {
    virusTotalStatus.textContent = "Add at least one URL before checking VirusTotal.";
    renderVirusTotalResults([]);
    return;
  }

  virusTotalButton.disabled = true;
  virusTotalStatus.textContent = `Checking ${urls.length} URL${urls.length === 1 ? "" : "s"} with VirusTotal...`;

  try {
    const response = await fetch("/api/virustotal/urls", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "VirusTotal check failed.");
    }

    renderVirusTotalResults(payload.results || []);
    virusTotalStatus.textContent = "VirusTotal results loaded.";
  } catch (error) {
    virusTotalStatus.textContent = error.message;
  } finally {
    virusTotalButton.disabled = false;
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const result = analyzeText(input.value);
  renderResults(result);
  saveHistory(currentMessageReport);
});

loadSampleButton.addEventListener("click", () => {
  input.value = sample;
  renderResults(analyzeText(input.value));
});

clearButton.addEventListener("click", () => {
  input.value = "";
  currentMessageReport = null;
  currentVirusTotalResults = [];
  renderResults(analyzeText(""));
  renderVirusTotalResults([]);
  virusTotalStatus.textContent = "VirusTotal checks require a local API key.";
});

virusTotalButton.addEventListener("click", () => {
  renderResults(analyzeText(input.value));
  checkVirusTotal();
});

modeButtons.forEach((button) => {
  button.addEventListener("click", () => setMode(button.dataset.mode));
});

headerForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const result = analyzeHeaders(headerInput.value);
  renderHeaderResults(result);
  saveHistory(currentHeaderReport);
});

loadHeaderSampleButton.addEventListener("click", () => {
  headerInput.value = headerSample;
  renderHeaderResults(analyzeHeaders(headerInput.value));
});

clearHeadersButton.addEventListener("click", () => {
  headerInput.value = "";
  currentHeaderReport = null;
  renderHeaderResults(analyzeHeaders(""));
});

exportMessageButton.addEventListener("click", () => {
  if (!currentMessageReport) renderResults(analyzeText(input.value));
  exportReport(currentMessageReport);
});

exportHeaderButton.addEventListener("click", () => {
  if (!currentHeaderReport) renderHeaderResults(analyzeHeaders(headerInput.value));
  exportReport(currentHeaderReport);
});

historyList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-history-id]");
  if (button) loadHistoryEntry(button.dataset.historyId);
});

clearHistoryButton.addEventListener("click", () => {
  writeHistory([]);
  renderHistory();
});

renderHistory();
