# Cyber Threat Analyzer

A beginner-friendly cyber security project inspired by the screenshot prompt. It scans pasted emails, messages, URLs, and raw email headers for common phishing indicators, and can optionally enrich URLs with VirusTotal reputation results.

## Features

- Extracts URLs from pasted text
- Scores the message from 0 to 100
- Flags urgent language and credential or payment requests
- Detects insecure HTTP links, raw IP URLs, risky top-level domains, long subdomain chains, and brand impersonation patterns
- Shows a readable findings list and detected URL breakdown
- Checks existing VirusTotal URL reports through a local server endpoint
- Analyzes raw email headers for SPF, DKIM, DMARC, Reply-To, Return-Path, Message-ID, sender branding, and delivery hop signals
- Extracts indicators of compromise: URLs, domains, IP addresses, email addresses, and common hash formats
- Saves recent scan history locally in the browser
- Exports scan reports as JSON for portfolio demos or analyst notes

## Run It

Use Node.js 18 or newer.

```bash
npm start
```

Then open:

```text
http://localhost:3000
```

## VirusTotal API

Get a VirusTotal API key from your VirusTotal account, then set it before starting the app.

PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
npm start
```

Command Prompt:

```bat
set VIRUSTOTAL_API_KEY=your_api_key_here
npm start
```

The API key is used only by `server.js`; it is not placed in browser JavaScript.

## Project Files

- `index.html` - app structure
- `styles.css` - responsive interface styling
- `app.js` - threat analysis logic and UI rendering
- `server.js` - static file server and VirusTotal proxy endpoint
- `package.json` - `npm start` script

## Notes

This is a heuristic learning tool, not a replacement for a professional email security gateway. Treat the output as a guide for what to inspect more carefully. VirusTotal public API usage may be rate limited.
