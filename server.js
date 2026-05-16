import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import dns from "node:dns/promises";
import net from "node:net";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT || 3100);
const allowPrivateTargets = process.env.ALLOW_PRIVATE_TARGETS === "true";
const requestTimeoutMs = 8000;
const maxBodyBytes = 1_000_000;

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

const exposureChecks = [
  { path: "/.env", title: "Environment file exposed", severity: "critical", evidence: ["APP_KEY=", "DB_PASSWORD", "SECRET", "TOKEN="] },
  { path: "/.git/config", title: "Git repository metadata exposed", severity: "critical", evidence: ["[core]", "repositoryformatversion"] },
  { path: "/.aws/credentials", title: "AWS credentials file exposed", severity: "critical", evidence: ["aws_access_key_id", "aws_secret_access_key"] },
  { path: "/id_rsa", title: "Private SSH key exposed", severity: "critical", evidence: ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY"] },
  { path: "/backup.sql", title: "Database dump exposed", severity: "critical", evidence: ["CREATE TABLE", "INSERT INTO", "-- MySQL", "PostgreSQL database dump"] },
  { path: "/database.sql", title: "Database dump exposed", severity: "critical", evidence: ["CREATE TABLE", "INSERT INTO", "-- MySQL", "PostgreSQL database dump"] },
  { path: "/wp-config.php.bak", title: "WordPress config backup exposed", severity: "critical", evidence: ["DB_NAME", "DB_PASSWORD", "AUTH_KEY"] },
  { path: "/config.php.bak", title: "Application config backup exposed", severity: "critical", evidence: ["<?php", "DB_PASSWORD", "$db"] },
  { path: "/backup.zip", title: "Backup archive exposed", severity: "high", evidence: ["PK"] },
  { path: "/phpinfo.php", title: "Public phpinfo page", severity: "high", evidence: ["phpinfo()", "PHP Version"] },
  { path: "/server-status", title: "Server status page exposed", severity: "high", evidence: ["Apache Server Status", "Server uptime"] },
  { path: "/swagger", title: "Swagger UI exposed", severity: "medium", evidence: ["Swagger UI", "openapi"] },
  { path: "/api-docs", title: "API documentation exposed", severity: "medium", evidence: ["openapi", "swagger"] },
  { path: "/graphql", title: "GraphQL endpoint responds", severity: "medium", evidence: ["GraphQL", "Cannot query field", "must provide query"] },
  { path: "/robots.txt", title: "Robots.txt exposes paths", severity: "info", evidence: ["Disallow:", "Allow:"] },
];

const sqlErrorPattern = /SQL syntax|mysql_fetch|You have an error in your SQL syntax|ORA-\d+|PostgreSQL.*ERROR|SQLite\/JDBCDriver|ODBC SQL|Unclosed quotation mark|Microsoft SQL Server|MariaDB server version|PDOException|pg_query\(\)/i;

function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 60_000) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function normalizeTarget(rawTarget) {
  const value = String(rawTarget || "").trim();
  if (!value) throw new Error("Target URL is required.");
  const parsed = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only http and https targets are supported.");
  parsed.hash = "";
  return parsed;
}

function isPrivateIp(address) {
  if (net.isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
  }
  if (net.isIP(address) === 6) {
    const lower = address.toLowerCase();
    return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80");
  }
  return false;
}

async function validateTarget(target) {
  if (["localhost", "127.0.0.1", "::1"].includes(target.hostname.toLowerCase()) && !allowPrivateTargets) {
    throw new Error("Local/private targets are blocked by default. Set ALLOW_PRIVATE_TARGETS=true only for your own lab.");
  }
  const records = net.isIP(target.hostname) ? [{ address: target.hostname }] : await dns.lookup(target.hostname, { all: true });
  if (!allowPrivateTargets && records.some((record) => isPrivateIp(record.address))) {
    throw new Error("Private network targets are blocked by default. Scan only authorized public targets, or enable lab mode.");
  }
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
  try {
    return await fetch(url, {
      redirect: "follow",
      ...options,
      signal: controller.signal,
      headers: {
        "user-agent": "SafeWebVulnScanner/1.0 authorized-security-check",
        ...(options.headers || {}),
      },
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function safeText(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!/text|html|json|xml|javascript/i.test(contentType)) return "";
  const reader = response.body?.getReader();
  if (!reader) return "";
  let received = 0;
  const chunks = [];
  while (received < maxBodyBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.length;
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function headerObject(headers) {
  const result = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function cookieList(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const cookie = headers.get("set-cookie");
  return cookie ? [cookie] : [];
}

function add(findings, issue) {
  findings.push({
    confidence: "Firm",
    affectedUrl: "",
    evidence: "",
    remediation: "",
    ...issue,
  });
}

function checkHeaders(findings, headers, url) {
  const csp = headers["content-security-policy"] || "";
  const hsts = headers["strict-transport-security"] || "";
  const frame = headers["x-frame-options"] || "";
  const nosniff = headers["x-content-type-options"] || "";

  if (!csp) add(findings, {
    title: "Missing Content-Security-Policy",
    severity: "medium",
    category: "Security Headers",
    affectedUrl: url,
    evidence: "No CSP header was found.",
    remediation: "Add a restrictive Content-Security-Policy to reduce XSS impact.",
  });
  else if (/unsafe-inline|unsafe-eval|\*/i.test(csp)) add(findings, {
    title: "Weak Content-Security-Policy",
    severity: "high",
    category: "Security Headers",
    affectedUrl: url,
    evidence: csp,
    remediation: "Remove unsafe-inline, unsafe-eval, and broad wildcards where possible.",
  });

  if (url.startsWith("https://") && !hsts) add(findings, {
    title: "Missing Strict-Transport-Security",
    severity: "medium",
    category: "Security Headers",
    affectedUrl: url,
    evidence: "HTTPS response did not include HSTS.",
    remediation: "Add Strict-Transport-Security after confirming HTTPS works across the site.",
  });

  if (!frame && !/frame-ancestors/i.test(csp)) add(findings, {
    title: "Missing clickjacking protection",
    severity: "medium",
    category: "Security Headers",
    affectedUrl: url,
    evidence: "No X-Frame-Options or CSP frame-ancestors directive found.",
    remediation: "Use CSP frame-ancestors or X-Frame-Options.",
  });

  if (!/^nosniff$/i.test(nosniff)) add(findings, {
    title: "Missing X-Content-Type-Options nosniff",
    severity: "low",
    category: "Security Headers",
    affectedUrl: url,
    evidence: nosniff || "Header missing.",
    remediation: "Set X-Content-Type-Options: nosniff.",
  });

  if (!headers["referrer-policy"]) add(findings, {
    title: "Missing Referrer-Policy",
    severity: "low",
    category: "Security Headers",
    affectedUrl: url,
    evidence: "No Referrer-Policy header was found.",
    remediation: "Use strict-origin-when-cross-origin or stricter.",
  });

  if (!headers["permissions-policy"]) add(findings, {
    title: "Missing Permissions-Policy",
    severity: "info",
    category: "Security Headers",
    affectedUrl: url,
    evidence: "No Permissions-Policy header was found.",
    remediation: "Disable browser features the app does not need.",
  });
}

function checkCookies(findings, cookies, url) {
  cookies.forEach((cookie) => {
    const name = cookie.split("=")[0] || "cookie";
    const lower = cookie.toLowerCase();
    const sensitive = /(sess|auth|token|jwt|sid|login)/i.test(name);
    if (sensitive && !lower.includes("httponly")) add(findings, {
      title: "Sensitive cookie missing HttpOnly",
      severity: "high",
      category: "Cookie Security",
      affectedUrl: url,
      evidence: name,
      remediation: "Set HttpOnly on session/auth cookies.",
    });
    if (sensitive && url.startsWith("https://") && !lower.includes("secure")) add(findings, {
      title: "Sensitive cookie missing Secure",
      severity: "high",
      category: "Cookie Security",
      affectedUrl: url,
      evidence: name,
      remediation: "Set Secure on cookies used over HTTPS.",
    });
    if (sensitive && !lower.includes("samesite")) add(findings, {
      title: "Sensitive cookie missing SameSite",
      severity: "medium",
      category: "Cookie Security",
      affectedUrl: url,
      evidence: name,
      remediation: "Set SameSite=Lax or Strict where compatible.",
    });
  });
}

function checkHtml(findings, html, url) {
  if (!html) return;
  const final = new URL(url);

  if (final.protocol === "https:" && /(?:src|href|action)=["']http:\/\//i.test(html)) add(findings, {
    title: "Mixed content found",
    severity: "medium",
    category: "HTTPS",
    affectedUrl: url,
    evidence: "HTTPS page references http:// resources or form actions.",
    remediation: "Load all resources and form actions over HTTPS.",
  });

  if (sqlErrorPattern.test(html)) add(findings, {
    title: "Database error disclosure",
    severity: "critical",
    category: "Information Disclosure",
    affectedUrl: url,
    evidence: "Database error text was found in the response.",
    remediation: "Hide detailed DB errors and log them server-side.",
  });

  if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/i.test(html)) add(findings, {
    title: "Private key exposed in response",
    severity: "critical",
    category: "Secrets Exposure",
    affectedUrl: url,
    evidence: "Private key marker was found in the response body.",
    remediation: "Remove the key immediately and rotate impacted credentials.",
  });

  if (/AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}|xox[baprs]-[0-9A-Za-z-]+/i.test(html)) add(findings, {
    title: "Possible API token exposed",
    severity: "critical",
    category: "Secrets Exposure",
    affectedUrl: url,
    evidence: "The response body contains a pattern resembling a cloud/API token.",
    remediation: "Remove the secret and rotate it immediately.",
  });

  if (/<title>\s*index of\s*/i.test(html) || /Directory Listing For|Parent Directory/i.test(html)) add(findings, {
    title: "Directory listing enabled",
    severity: "high",
    category: "Misconfiguration",
    affectedUrl: url,
    evidence: "Common directory index markers were found.",
    remediation: "Disable directory listing.",
  });

  if (/\b(eval\s*\(|document\.write\s*\(|\.innerHTML\s*=)/i.test(html)) add(findings, {
    title: "Risky JavaScript sink detected",
    severity: "low",
    category: "XSS Indicators",
    affectedUrl: url,
    evidence: "Found eval(), document.write(), or innerHTML assignment.",
    remediation: "Avoid dangerous DOM sinks or sanitize untrusted data.",
  });

  [...html.matchAll(/<form\b[\s\S]*?<\/form>/gi)].forEach((match, index) => {
    const form = match[0];
    const method = (form.match(/\bmethod=["']?([^"'\s>]+)/i)?.[1] || "get").toLowerCase();
    const action = form.match(/\baction=["']?([^"'\s>]+)/i)?.[1] || url;
    const actionUrl = new URL(action, url);
    const hasPassword = /<input[^>]+type=["']?password/i.test(form);
    const hasCsrf = /csrf|xsrf|authenticity_token|__requestverificationtoken/i.test(form);

    if (hasPassword && actionUrl.protocol !== "https:") add(findings, {
      title: "Password form submits without HTTPS",
      severity: "critical",
      category: "Forms",
      affectedUrl: url,
      evidence: `Form ${index + 1} submits to ${actionUrl.href}`,
      remediation: "Submit credentials only over HTTPS.",
    });
    if (hasPassword && method === "get") add(findings, {
      title: "Password form uses GET",
      severity: "critical",
      category: "Forms",
      affectedUrl: url,
      evidence: `Form ${index + 1} uses GET.`,
      remediation: "Use POST and never put credentials in URLs.",
    });
    if (method === "post" && !hasCsrf) add(findings, {
      title: "POST form without visible CSRF token",
      severity: "medium",
      category: "Forms",
      affectedUrl: url,
      evidence: `Form ${index + 1} posts to ${actionUrl.href}`,
      remediation: "Add server-validated anti-CSRF tokens.",
    });
    if (actionUrl.hostname !== final.hostname) add(findings, {
      title: "Form submits to another domain",
      severity: "high",
      category: "Forms",
      affectedUrl: url,
      evidence: actionUrl.href,
      remediation: "Confirm cross-domain form actions are trusted and intentional.",
    });
  });
}

function htmlEscaped(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function checkCors(findings, headers, url) {
  const origin = headers["access-control-allow-origin"] || "";
  const credentials = headers["access-control-allow-credentials"] || "";
  if (origin === "*" && /true/i.test(credentials)) add(findings, {
    title: "Critical CORS misconfiguration",
    severity: "critical",
    category: "CORS",
    affectedUrl: url,
    evidence: "Access-Control-Allow-Origin: * with credentials enabled.",
    remediation: "Never combine wildcard origins with credentialed CORS.",
  });
  else if (origin === "*") add(findings, {
    title: "Wildcard CORS origin",
    severity: "low",
    category: "CORS",
    affectedUrl: url,
    evidence: "Access-Control-Allow-Origin: *",
    remediation: "Restrict CORS to trusted origins if responses contain sensitive data.",
  });
}

function checkFingerprint(findings, headers, html, url) {
  if (headers.server) add(findings, {
    title: "Server banner disclosed",
    severity: "info",
    category: "Fingerprinting",
    affectedUrl: url,
    evidence: headers.server,
    remediation: "Reduce detailed server banners where possible.",
  });
  if (headers["x-powered-by"]) add(findings, {
    title: "Technology header disclosed",
    severity: "info",
    category: "Fingerprinting",
    affectedUrl: url,
    evidence: headers["x-powered-by"],
    remediation: "Remove X-Powered-By or similar framework disclosure headers.",
  });

  [
    ["WordPress", /wp-content|wp-includes/i],
    ["Next.js", /__NEXT_DATA__|_next\/static/i],
    ["Laravel", /laravel_session|csrf-token/i],
    ["Django", /csrftoken|django/i],
  ].forEach(([name, pattern]) => {
    if (pattern.test(html)) add(findings, {
      title: `${name} fingerprint detected`,
      severity: "info",
      category: "Fingerprinting",
      affectedUrl: url,
      evidence: name,
      remediation: "Keep framework versions patched and avoid exposing exact versions.",
    });
  });
}

async function lightActive(findings, target, html) {
  const base = new URL(target.href);
  base.pathname = "/";
  base.search = "";

  const options = await fetchWithTimeout(base.href, {
    method: "OPTIONS",
    headers: {
      origin: "https://authorized-scanner.example",
      "access-control-request-method": "GET",
    },
  }).catch(() => null);
  if (options) {
    const headers = headerObject(options.headers);
    if (/\bTRACE\b/i.test(headers.allow || "")) add(findings, {
      title: "TRACE method appears enabled",
      severity: "high",
      category: "HTTP Methods",
      affectedUrl: base.href,
      evidence: `Allow: ${headers.allow}`,
      remediation: "Disable TRACE unless explicitly required.",
    });
    checkCors(findings, headers, base.href);
  }

  for (const item of exposureChecks) {
    const url = new URL(item.path, base);
    const response = await fetchWithTimeout(url.href).catch(() => null);
    if (!response || response.status !== 200) continue;
    const text = await safeText(response);
    const matched = item.evidence.some((needle) => text.includes(needle));
    if (!matched && item.path !== "/robots.txt") continue;
    add(findings, {
      title: item.title,
      severity: item.severity,
      category: "Exposure Checks",
      confidence: matched ? "Firm" : "Tentative",
      affectedUrl: url.href,
      evidence: matched ? `Matched sensitive content at ${item.path}` : `HTTP 200 at ${item.path}`,
      remediation: "Remove public access to sensitive files and rotate any exposed credentials.",
    });
  }

  await activeApplicationChecks(findings, collectApplicationTargets(target, html));
}

function collectApplicationTargets(target, html) {
  const targets = new Map([[target.href, new URL(target.href)]]);
  const sameOrigin = (candidate) => candidate.origin === target.origin;

  if (html) {
    [...html.matchAll(/\bhref=["']([^"']+)["']/gi)].forEach((match) => {
      try {
        const candidate = new URL(match[1], target.href);
        if (sameOrigin(candidate) && candidate.search) targets.set(candidate.href, candidate);
      } catch {
        // Ignore invalid or non-URL hrefs.
      }
    });

    [...html.matchAll(/<form\b[\s\S]*?<\/form>/gi)].forEach((match) => {
      const form = match[0];
      const method = (form.match(/\bmethod=["']?([^"'\s>]+)/i)?.[1] || "get").toLowerCase();
      if (method !== "get") return;

      try {
        const action = form.match(/\baction=["']?([^"'\s>]+)/i)?.[1] || target.href;
        const candidate = new URL(action, target.href);
        if (!sameOrigin(candidate)) return;

        [...form.matchAll(/\bname=["']([^"']+)["']/gi)].slice(0, 6).forEach((nameMatch) => {
          candidate.searchParams.set(nameMatch[1], "ctscan");
        });
        targets.set(candidate.href, candidate);
      } catch {
        // Ignore invalid form actions.
      }
    });
  }

  return [...targets.values()].slice(0, 10);
}

function parameterProbeUrls(target, payload, fallbackName = "ct_scan_probe") {
  const names = [...target.searchParams.keys()].slice(0, 5);
  if (names.length === 0) names.push(fallbackName);

  return names.map((name) => {
    const probe = new URL(target.href);
    probe.searchParams.set(name, payload);
    return { name, url: probe };
  });
}

function hasFinding(findings, title) {
  return findings.some((finding) => finding.title === title);
}

async function activeApplicationChecks(findings, targets) {
  const xssCanary = `ctscan-xss-${Date.now()}`;
  const xssPayload = `<${xssCanary}>`;
  for (const target of targets) {
    const xssProbes = parameterProbeUrls(target, xssPayload, "ct_scan_xss");

    for (const probe of xssProbes) {
      const response = await fetchWithTimeout(probe.url.href).catch(() => null);
      if (!response) continue;
      const text = await safeText(response);

      if (text.includes(xssPayload) && !hasFinding(findings, "Reflected XSS indicator")) {
        add(findings, {
          title: "Reflected XSS indicator",
          severity: "high",
          category: "XSS",
          confidence: "Firm",
          affectedUrl: probe.url.href,
          evidence: `Parameter "${probe.name}" reflected an HTML-like canary without encoding.`,
          remediation: "Contextually encode reflected input and validate untrusted parameters before rendering.",
        });
        break;
      }

      if (text.includes(htmlEscaped(xssPayload)) && !hasFinding(findings, "Reflected parameter observed")) {
        add(findings, {
          title: "Reflected parameter observed",
          severity: "info",
          category: "XSS",
          confidence: "Tentative",
          affectedUrl: probe.url.href,
          evidence: `Parameter "${probe.name}" was reflected with HTML encoding.`,
          remediation: "Keep output encoding in place and verify all contexts are encoded correctly.",
        });
        break;
      }
    }
  }

  for (const target of targets) {
    const sqlProbes = parameterProbeUrls(target, "ctscan'", "ct_scan_sqli");
    for (const probe of sqlProbes) {
      const response = await fetchWithTimeout(probe.url.href).catch(() => null);
      if (!response) continue;
      const text = await safeText(response);

      if (sqlErrorPattern.test(text) && !hasFinding(findings, "SQL injection error indicator")) {
        add(findings, {
          title: "SQL injection error indicator",
          severity: "high",
          category: "SQL Injection",
          confidence: "Firm",
          affectedUrl: probe.url.href,
          evidence: `Database error appeared after a quote canary was sent to parameter "${probe.name}".`,
          remediation: "Use parameterized queries, avoid string-built SQL, and hide database errors from users.",
        });
        break;
      }
    }
  }

  const redirectTarget = "https://example.com/ctscan-open-redirect";
  const redirectNames = ["next", "url", "redirect", "redirect_uri", "return", "continue"];
  for (const target of targets) {
    const namesToTry = [...new Set([...target.searchParams.keys()].filter((name) => redirectNames.includes(name.toLowerCase())).concat(redirectNames))].slice(0, 6);

    for (const name of namesToTry) {
      const probe = new URL(target.href);
      probe.searchParams.set(name, redirectTarget);
      const response = await fetchWithTimeout(probe.href, { redirect: "manual" }).catch(() => null);
      if (!response) continue;
      const location = response.headers.get("location") || "";

      if (response.status >= 300 && response.status < 400 && location.startsWith(redirectTarget) && !hasFinding(findings, "Open redirect indicator")) {
        add(findings, {
          title: "Open redirect indicator",
          severity: "high",
          category: "Open Redirect",
          confidence: "Firm",
          affectedUrl: probe.href,
          evidence: `Parameter "${name}" redirected to ${redirectTarget}.`,
          remediation: "Allow only relative redirects or validate redirect destinations against a strict allowlist.",
        });
        break;
      }
    }
  }
}

function summary(findings) {
  return findings.reduce((acc, item) => {
    acc[item.severity] = (acc[item.severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function score(findings) {
  const weights = { critical: 40, high: 25, medium: 12, low: 5, info: 1 };
  return Math.min(100, findings.reduce((total, item) => total + weights[item.severity], 0));
}

function recommendation(resultScore, counts) {
  if (counts.critical > 0) return "Critical risk. Treat this as urgent: remove exposure, rotate secrets, and verify impact immediately.";
  if (counts.high > 0 || resultScore >= 70) return "High risk. Fix high severity findings before production exposure.";
  if (counts.medium > 0 || resultScore >= 35) return "Medium risk. Review configuration and exposed surfaces before launch.";
  return "Low visible risk from safe checks. Continue with authenticated testing and code review.";
}

async function runScan({ target, includeLightActive }) {
  const parsed = normalizeTarget(target);
  await validateTarget(parsed);
  const response = await fetchWithTimeout(parsed.href);
  const finalUrl = response.url || parsed.href;
  const headers = headerObject(response.headers);
  const cookies = cookieList(response.headers);
  const html = await safeText(response);
  const findings = [];

  if (!finalUrl.startsWith("https://")) add(findings, {
    title: "Target not served over HTTPS",
    severity: "high",
    category: "HTTPS",
    affectedUrl: finalUrl,
    evidence: finalUrl,
    remediation: "Redirect HTTP to HTTPS and serve the application over TLS.",
  });

  checkHeaders(findings, headers, finalUrl);
  checkCookies(findings, cookies, finalUrl);
  checkHtml(findings, html, finalUrl);
  checkCors(findings, headers, finalUrl);
  checkFingerprint(findings, headers, html, finalUrl);
  if (includeLightActive) await lightActive(findings, new URL(finalUrl), html);

  const counts = summary(findings);
  const resultScore = score(findings);
  return {
    target: parsed.href,
    finalUrl,
    scannedAt: new Date().toISOString(),
    mode: includeLightActive ? "Passive + safe light active" : "Passive only",
    status: response.status,
    score: resultScore,
    summary: counts,
    recommendation: recommendation(resultScore, counts),
    findings,
    observed: {
      headers,
      cookies: cookies.map((cookie) => cookie.split(";")[0]),
      bodyBytesRead: Buffer.byteLength(html),
    },
  };
}

async function handleScan(request, response) {
  if (request.method !== "POST") return sendJson(response, 405, { error: "Use POST for scans." });
  try {
    const payload = JSON.parse((await readBody(request)) || "{}");
    if (payload.authorized !== true) {
      return sendJson(response, 400, { error: "Confirm that you are authorized to scan this target." });
    }
    sendJson(response, 200, await runScan({
      target: payload.target,
      includeLightActive: payload.includeLightActive === true,
    }));
  } catch (error) {
    sendJson(response, 400, { error: error.message || "Scan failed." });
  }
}

async function serveStatic(request, response) {
  const pathname = decodeURIComponent(new URL(request.url, `http://${request.headers.host}`).pathname);
  const filePath = pathname === "/" ? "index.html" : pathname.slice(1);
  const normalizedPath = normalize(filePath);
  if (normalizedPath.startsWith("..")) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }
  try {
    const absolutePath = join(__dirname, normalizedPath);
    const file = await readFile(absolutePath);
    response.writeHead(200, { "Content-Type": contentTypes[extname(absolutePath)] || "application/octet-stream" });
    response.end(file);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}

createServer(async (request, response) => {
  if (request.url?.startsWith("/api/scan")) return handleScan(request, response);
  return serveStatic(request, response);
}).listen(port, () => {
  console.log(`Web Vulnerability Scanner running at http://localhost:${port}`);
  if (!allowPrivateTargets) console.log("Private targets blocked. Set ALLOW_PRIVATE_TARGETS=true only for your own lab.");
});
