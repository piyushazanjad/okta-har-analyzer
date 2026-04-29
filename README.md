# HARlens

Bring your auth flows into focus. Drop in a HAR file and get a visual swimlane breakdown of the authentication flow, inline JWT/SAML decoding, AI-powered diagnosis, side-by-side HAR comparison, and a Claude chat for follow-up questions.

![Dark mode](https://img.shields.io/badge/theme-dark%20%2F%20light-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)
![Claude](https://img.shields.io/badge/powered%20by-Claude%20AI-purple)

---

## What it does

**1. Auth Flow Visualization**
Parses the HAR and filters it down to the Okta-relevant requests, then renders an SVG swimlane showing the full authentication sequence across Browser → Okta → Application. Each step is color-coded by phase (auth, token, SAML) with status code badges. Falls back to all requests for non-Okta HAR files.

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
- **Network errors** — Browser-level failures (e.g. `ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`) are detected and shown with a human-readable label, cause summary, and a targeted fix hint.

**4. AI Verdict (Claude-powered)**
Sends the structured flow to Claude and streams back:
- Plain-English summary of what happened
- Flow health: Healthy / Warning / Broken
- Exact failure point with error codes
- Root cause analysis
- Step-by-step fix with Okta Admin Console locations

**5. HAR Comparison**
Upload two HAR files side-by-side to diff them:
- Matched, only-in-A, and only-in-B steps highlighted
- Timing deltas shown per matched step (faster / slower vs baseline)
- Each row is expandable to reveal the full URL, request/response headers, and body

**6. Security Audit**
Runs a set of automated checks against the parsed flow and surfaces findings by severity (high / medium / low):
- Missing or weak PKCE (`code_challenge`)
- Implicit flow usage
- Tokens in URL fragments or query strings
- Insecure redirect URIs
- Missing state parameter (CSRF risk)
- Short-lived or already-expired tokens
- Custom-to-default Okta domain switches that break SSO sessions
- Browser-level network blocks (e.g. Private Network Access CORS rejections)

**7. Chat with Claude**
After loading a HAR, ask follow-up questions about the flow in a streaming chat panel — scoped to the parsed flow context.

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
- **AI** — Anthropic Claude API (`claude-opus-4-6`) with SSE streaming
- **Frontend** — Vanilla HTML/CSS/JS, SVG swimlane, Inter + JetBrains Mono fonts
- **HAR parsing** — Custom parser (`harParser.js`) with zlib inflate for SAMLRequest decoding

---

## Project structure

```
okta-har-analyzer/
├── server.js          # Express server — /api/analyze, /api/verdict, /api/chat
├── harParser.js       # HAR parsing, artifact extraction, Claude prompt builder
├── public/
│   └── index.html     # Full frontend (styles + JS inline)
├── .env.example
└── package.json
```
