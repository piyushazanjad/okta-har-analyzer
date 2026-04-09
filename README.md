# Okta HAR Analyzer

A developer support tool for analyzing Okta authentication flows captured in HAR files. Drop in a HAR file and get a visual swimlane breakdown of the auth flow, inline JWT/SAML decoding, and an AI-powered verdict explaining what happened and how to fix it.

![Dark mode](https://img.shields.io/badge/theme-dark%20%2F%20light-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)
![Claude](https://img.shields.io/badge/powered%20by-Claude%20AI-purple)

---

## What it does

**1. Auth Flow Visualization**
Parses the HAR and filters it down to the Okta-relevant requests, then renders an SVG swimlane showing the full authentication sequence across Browser → Okta → Application. Each step is color-coded by phase (auth, token, SAML) with status code badges.

**2. Protocol Detection**
Automatically identifies the flow type:
- OIDC Authorization Code + PKCE
- OIDC Authorization Code
- SAML (SP-Initiated / IdP-Initiated)
- OAuth 2.0 Client Credentials
- OAuth 2.0 Device Authorization
- Okta Identity Engine (IDX)

**3. Inline Artifact Decoding**
Click any step to open a detail drawer with:
- **JWT decoder** — Claims, Header, and Payload JSON tabs. Flags expired tokens.
- **SAML decoder** — Issuer, NameID, Status, Destination, Attributes, raw XML. Handles both SAMLRequest (deflated) and SAMLResponse.
- **Request/Response** — Filtered headers, formatted body (JSON, form-encoded, or raw), Location header highlighted, rate-limit headers surfaced.
- **Timing** — DNS / Connect / TLS / Send / Wait / Receive broken out as a bar chart.

**4. AI Verdict (Claude-powered)**
Sends the structured flow to Claude and streams back:
- Plain-English summary of what happened
- Flow health: Healthy / Warning / Broken
- Exact failure point with error codes
- Root cause analysis
- Step-by-step fix with Okta Admin Console locations

---

## Getting started

**Prerequisites:** Node.js 18+, an Anthropic API key

```bash
git clone https://github.com/piyushazanjad/okta-har-analyzer.git
cd okta-har-analyzer
npm install
```

Copy the env file and add your key:
```bash
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY=your_key_here
```

Start the server:
```bash
npm start
# → http://localhost:3001
```

---

## Capturing a HAR file

| Browser | Steps |
|---------|-------|
| Chrome / Edge | DevTools → Network tab → right-click any request → **Save all as HAR** |
| Firefox | DevTools → Network → ⚙️ gear icon → **Save all as HAR** |
| Safari | Web Inspector → Network → Export → **Export HAR** |

Reproduce the auth flow you want to debug while the network tab is open, then export.

---

## Stack

- **Backend** — Node.js + Express
- **AI** — Anthropic Claude API (`claude-4-6-opus`) with SSE streaming
- **Frontend** — Vanilla HTML/CSS/JS, SVG swimlane, Inter + JetBrains Mono fonts
- **HAR parsing** — Custom parser (`harParser.js`) with zlib inflate for SAMLRequest decoding

---

## Project structure

```
okta-har-analyzer/
├── server.js          # Express server — /api/analyze and /api/verdict
├── harParser.js       # HAR parsing, artifact extraction, Claude prompt builder
├── public/
│   └── index.html     # Full frontend (styles + JS inline)
├── .env.example
└── package.json
```
