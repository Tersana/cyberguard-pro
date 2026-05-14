# CyberGuard Pro

A web-based cybersecurity analysis platform. Vanilla JavaScript frontend deployed on Vercel, backed by a Laravel 12 REST API.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Available Scripts](#available-scripts)
- [Usage](#usage)
- [API Integration](#api-integration)
- [Testing](#testing)
- [Deployment](#deployment)

---

## Overview

CyberGuard Pro lets authenticated users run real-time security scans against targets (domains, IPs, URLs). Scan results are streamed live to the dashboard via Laravel Echo (Pusher WebSockets). The frontend is a no-build-step, vanilla JS SPA served as static files.

**Core workflow:**

1. User logs in → JWT stored in `localStorage`
2. User creates a project and adds scan targets
3. User selects tools and clicks **Execute Scan**
4. Backend queues the scan; real-time progress arrives over WebSockets
5. Results render in the scan terminal + risk gauge; findings persist to the project

---

## Features

### Security Tools (Dashboard Tabs)

| Tab | Tools |
|---|---|
| **Network** | Port scanner, TCP connectivity test, WHOIS lookup, IP geolocation, DNS analysis |
| **Web Security** | OWASP ZAP XSS scanner, SSL/TLS certificate check |
| **Hash Tools** | MD5/SHA-1/SHA-256/SHA-512 generation, hash identifier, password strength analyzer |
| **Threat Intel** | VirusTotal, AbuseIPDB, URLScan.io — unified threat intelligence hub |
| **AI Assistant** | In-dashboard AI chat (local fallback model) |
| **Projects** | Project CRUD, collaborator management, findings per target |

### Platform Features

- **Real-time scan terminal** — live log lines streamed over Pusher WebSockets via Laravel Echo
- **Risk gauge** — SVG score visualization updated per scan result
- **Project management** — multi-target projects with collaborator invitations
- **Billing & subscriptions** — Paymob payment integration, plan-gated features
- **Auth flows** — Login, signup, 2FA, email verification, password reset
- **Export** — Download scan results as CSV/PDF
- **Session history** — Persisted in `localStorage`
- **API key vault** — Third-party keys encrypted with XOR cipher in `localStorage`

---

## Tech Stack

### Frontend

| Technology | Role |
|---|---|
| HTML5 / CSS3 / ES6+ JS | Core — no bundler, no transpilation |
| `theme-tokens.css` | Design token system (`--cg-*` CSS custom properties) |
| `cyber-theme.css` | Component styles (`cyber-*` classes) |
| Tailwind CSS (CDN) | Utility classes on `dashboard.html` |
| Laravel Echo + Pusher JS | Real-time WebSocket events |
| Vitest + happy-dom | Unit & integration testing |

### Backend (separate repo)

| Technology | Role |
|---|---|
| Laravel 12 | REST API, auth, scan queue |
| MySQL | Persistence |
| Redis | Queue driver |
| Pusher | WebSocket broadcasting |

### Supporting Services

| Service | Role |
|---|---|
| OWASP ZAP (Docker) | Active web vulnerability scanner |
| `zap-proxy.js` (Node/Express) | Local CORS proxy for ZAP API on port 3001 |
| VirusTotal API | Malware / URL reputation |
| AbuseIPDB API | IP reputation |
| URLScan.io API | URL analysis |
| Paymob | Payment processing |

---

## Project Structure

```
CyberGuardWeb/
│
├── index.html                  # Marketing landing page
├── dashboard.html              # Main app (tabbed security dashboard)
├── login.html / signup.html    # Authentication pages
├── email-verification.html     # Email confirm page
├── forgot-password.html        # Password reset request
├── reset-password.html         # Password reset form
├── invite.html                 # Team invitation acceptance
├── pricing.html                # Subscription plans
├── paymob-redirect.html        # Payment redirect handler
├── billing-paymob-redirect.html
├── project-detail.html         # Per-project findings & targets view
│
├── api-client.js               # Centralized HTTP client (APIClient class)
├── auth.js                     # Auth flows — AuthManager class
├── main.js                     # Core security tools (large, monolithic)
├── scan-manager.js             # Scan lifecycle & terminal output
├── project-manager.js          # Project CRUD & collaborators
├── threat-intel.js             # Threat intel hub (VT, AbuseIPDB, URLScan)
├── billing-api.js              # Subscription & billing API calls
├── billing-utils.js            # Billing formatting helpers
├── data-normalizer.js          # camelCase ↔ snake_case conversion
├── error-handler.js            # Centralized error display
├── cyber-notify.js             # Toast notification system
├── state-manager.js            # Dashboard state (empty/scanning/result)
├── dashboard-tab-manager.js    # Tab switching
├── dashboard-integration.js    # Dashboard initialization glue
├── risk-gauge.js               # SVG risk score gauge
├── target-validator.js         # Input validation for scan targets
├── result-item-structure.js    # Normalized scan result schema
├── performance-audit.js        # APM utilities (tracker, batcher, cache)
├── echo-config.js              # Laravel Echo / Pusher bootstrap
├── landing.js                  # Landing page animations
├── zap-proxy.js                # Node.js/Express CORS proxy for ZAP
│
├── theme-tokens.css            # CSS custom properties (design tokens)
├── cyber-theme.css             # Component-level styles
├── auth.css                    # Auth page styles
├── landing.css                 # Landing page styles
├── Style.css                   # Dashboard / global styles
│
├── lib/                        # Vendored libraries (echo.iife.js, pusher.min.js)
├── tests/
│   ├── unit/                   # 39 Vitest unit test files
│   └── integration/            # 6 Vitest integration test files
│
├── vercel.json                 # Vercel routing rules
├── vitest.config.js            # Vitest + happy-dom config
├── package.json                # npm scripts & dependencies
└── .gitignore
```

---

## Installation

### Prerequisites

- **Node.js** v18+
- **npm** v9+
- **Docker** — only needed if running OWASP ZAP locally
- A modern browser (Chrome, Firefox, Edge)

### Steps

```bash
# 1. Clone the repo
git clone <repository-url>
cd CyberGuardWeb

# 2. Install dependencies
npm install

# 3. Open the app
#    No build step needed — open index.html or dashboard.html directly in your browser,
#    or serve them with any static file server:
npx serve .
```

> The app communicates with the Laravel backend via the `APIClient` base URL configured in `api-client.js`.  
> During local development, the backend is typically exposed via **ngrok**. Update the base URL constant in `api-client.js` to your ngrok tunnel URL.

---

## Environment Variables

This is a static frontend — there is no `.env` file loaded at runtime. Configuration is done in two places:

### 1. `api-client.js` — Backend URL

```js
// api-client.js
const BASE_URL = 'https://<your-ngrok-or-production-url>/api';
```

### 2. In-App API Key Vault (runtime, stored in localStorage)

Users configure third-party API keys inside the dashboard under **Settings → API Keys**. Keys are encrypted with a simple XOR cipher before being stored in `localStorage`.

| Key | Service | Where to get it |
|---|---|---|
| `virusTotalApiKey` | VirusTotal | [virustotal.com](https://www.virustotal.com/) |
| `abuseApiKey` | AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/) |
| `urlScanApiKey` | URLScan.io | [urlscan.io](https://urlscan.io/) |
| `whoisApiKey` | WhoisXML | [whoisxmlapi.com](https://www.whoisxmlapi.com/) |

### 3. localStorage Auth Keys

| Key | Contents |
|---|---|
| `cyberguard_jwt` | JWT Bearer token |
| `cyberguard_user` | Serialized user object |
| `cyberguard_session` | Current scan session |

---

## Available Scripts

```bash
# Run the test suite (single pass)
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage report
npm test -- --coverage

# Run a single test file
npx vitest run tests/unit/scan-lifecycle-events.test.js

# Start the OWASP ZAP CORS proxy (port 3001)
npm start

# Start the proxy with auto-reload (development)
npm run dev
```

---

## Usage

### Running OWASP ZAP (for XSS scanning)

```bash
# Pull and start ZAP as a daemon
docker run -d -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true

# Start the CORS proxy (bridges browser → ZAP)
npm start
```

The ZAP proxy listens on **port 3001** and forwards requests to ZAP on port 8080.

### Dashboard Navigation

| Tab | What to do |
|---|---|
| **Network** | Enter an IP or hostname → select tools → Execute Scan |
| **Web Security** | Enter a URL → run XSS or SSL checks (ZAP must be running) |
| **Hash Tools** | Type text or drop a file → choose algorithm → Generate |
| **Threat Intel** | Enter an IP, domain, or URL → run intelligence checks |
| **Projects** | Create project → add targets → run scans → view findings |
| **AI Assistant** | Chat with the in-dashboard assistant |

### Authentication Flow

1. Navigate to `login.html` (redirected automatically if unauthenticated)
2. Log in — JWT is stored and attached to all subsequent API requests
3. All dashboard pages call `AuthManager.runAuthGuard()` on load; unauthenticated users are redirected to login

---

## API Integration

All backend communication goes through `APIClient` in `api-client.js`.

```
browser → APIClient → ngrok tunnel → Laravel 12 API
                                   ↳ Pusher broadcast → Laravel Echo → browser
```

Key patterns:

- **JWT auth**: `Authorization: Bearer <token>` header on every request
- **ngrok header**: `ngrok-skip-browser-warning: true` (required for ngrok tunnels)
- **snake_case ↔ camelCase**: `data-normalizer.js` converts outgoing and incoming payloads automatically
- **Error handling**: `error-handler.js` renders inline form errors and toast notifications
- **Interceptors**: `APIClient` supports request/response interceptors for cross-cutting concerns

### Scan Real-Time Events (Pusher/Echo)

Scans run as Laravel queue jobs. Results broadcast over Pusher. `echo-config.js` bootstraps Laravel Echo with vendored `lib/echo.iife.js` and `lib/pusher.min.js`. `scan-manager.js` binds the channel listeners.

### Vercel Routing

`vercel.json` maps clean URLs to HTML pages:

| URL pattern | Page |
|---|---|
| `/invitations/:token` | `invite.html` |
| `/invite/:token` | `invite.html` |
| `/billing/paymob/redirect` | `paymob-redirect.html` |
| `/api/billing/paymob/redirect` | `paymob-redirect.html` |

---

## Testing

Tests use **Vitest** with the **happy-dom** environment (no real browser required).

```
tests/
├── unit/           # 39 test files — individual module behaviour
└── integration/    # 6 test files — cross-module interactions
```

Property-based tests use **fast-check** for input-space exploration (e.g., hash tools, password analysis, data mapping).

```bash
npm test                    # run all tests once
npm run test:watch          # re-run on file save
npm test -- --coverage      # generate HTML coverage report in ./coverage/
```

---

## Deployment

### Frontend → Vercel

Push to the main branch. Vercel picks up `vercel.json` and serves all static files. No build step.

### ZAP Proxy

The `zap-proxy.js` Node.js process is **not** deployed to Vercel. It must run locally (or on a separate server) whenever ZAP-based scanning is needed.

### Backend → Laravel

See the backend repository for deployment instructions (Laravel Forge / Envoyer recommended). Required services: MySQL, Redis, Pusher.

---

## Contributing

1. Fork and create a feature branch
2. Follow existing conventions:
   - CSS classes: `cyber-*` prefix
   - JS classes: `PascalCase`
   - JS functions: `camelCase`
   - Constants: `UPPER_SNAKE_CASE`
   - DOM IDs: `kebab-case`
   - Design tokens only from `theme-tokens.css` — no hardcoded colors or spacing
3. Add or update tests in `tests/unit/` or `tests/integration/`
4. Run `npm test` before opening a PR

---

*CyberGuard Pro — web-based security analysis platform*
