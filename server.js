import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const publicRoot = __dirname;
const port = Number(process.env.PORT || 3000);
const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 50_000) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function normalizeUrl(rawUrl) {
  const value = String(rawUrl || "").trim();
  if (!value) return null;
  const withProtocol = value.startsWith("www.") ? `https://${value}` : value;
  const parsed = new URL(withProtocol);
  if (!["http:", "https:"].includes(parsed.protocol)) return null;
  return parsed.toString();
}

function virusTotalUrlId(url) {
  return Buffer.from(url, "utf8").toString("base64url");
}

function virusTotalGuiUrl(urlId) {
  return `https://www.virustotal.com/gui/url/${urlId}/detection`;
}

async function lookupVirusTotalUrl(url) {
  const id = virusTotalUrlId(url);
  const vtResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: {
      accept: "application/json",
      "x-apikey": virusTotalApiKey,
    },
  });

  if (vtResponse.status === 404) {
    return {
      url,
      id,
      found: false,
      stats: null,
      link: virusTotalGuiUrl(id),
      error: "VirusTotal has no existing report for this URL.",
    };
  }

  const payload = await vtResponse.json().catch(() => ({}));

  if (!vtResponse.ok) {
    const message = payload?.error?.message || `VirusTotal returned HTTP ${vtResponse.status}.`;
    return { url, id, found: false, stats: null, link: virusTotalGuiUrl(id), error: message };
  }

  const attributes = payload?.data?.attributes || {};
  return {
    url,
    id,
    found: true,
    stats: attributes.last_analysis_stats || null,
    reputation: attributes.reputation || 0,
    link: virusTotalGuiUrl(id),
  };
}

async function handleVirusTotalUrls(request, response) {
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "Use POST for VirusTotal URL checks." });
    return;
  }

  if (!virusTotalApiKey) {
    sendJson(response, 500, {
      error: "Missing VIRUSTOTAL_API_KEY. Set it in your terminal before running npm start.",
    });
    return;
  }

  try {
    const body = await readRequestBody(request);
    const payload = JSON.parse(body || "{}");
    const urls = Array.isArray(payload.urls) ? payload.urls : [];
    const normalizedUrls = [...new Set(urls.map(normalizeUrl).filter(Boolean))].slice(0, 5);

    if (normalizedUrls.length === 0) {
      sendJson(response, 400, { error: "Provide at least one http or https URL." });
      return;
    }

    const results = [];
    for (const url of normalizedUrls) {
      results.push(await lookupVirusTotalUrl(url));
    }

    sendJson(response, 200, { results });
  } catch (error) {
    sendJson(response, 400, { error: error.message || "Could not process VirusTotal request." });
  }
}

async function serveStatic(request, response) {
  const requestedPath = decodeURIComponent(new URL(request.url, `http://${request.headers.host}`).pathname);
  const filePath = requestedPath === "/" ? "index.html" : requestedPath.slice(1);
  const normalizedPath = normalize(filePath);

  if (normalizedPath.startsWith("..")) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  try {
    const absolutePath = join(publicRoot, normalizedPath);
    const file = await readFile(absolutePath);
    response.writeHead(200, { "Content-Type": contentTypes[extname(absolutePath)] || "application/octet-stream" });
    response.end(file);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}

const server = createServer(async (request, response) => {
  if (request.url?.startsWith("/api/virustotal/urls")) {
    await handleVirusTotalUrls(request, response);
    return;
  }

  await serveStatic(request, response);
});

server.listen(port, () => {
  console.log(`Email & URL Threat Analyzer running at http://localhost:${port}`);
});
