# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CyberGuard Pro is a web-based cybersecurity analysis platform. It's a **vanilla JavaScript frontend** (no build step, no bundler) that communicates with a Laravel 12 backend via REST API. The frontend is deployed as static files on Vercel.

## Project Structure

```
CyberGuardWeb/
├── public/               # Static site root (served by Vercel)
│   ├── *.html            # All HTML pages
│   ├── css/              # Stylesheets (theme-tokens, cyber-theme, etc.)
│   ├── js/               # JavaScript modules (api-client, auth, main, etc.)
│   └── lib/              # Vendor libraries (pusher, echo)
├── data/                 # Static data files (CSV, JSON)
├── docs/                 # Project documentation
├── scripts/              # Build/utility scripts (Python)
├── tests/                # Test suites (unit/, integration/, manual/)
├── graphify-out/         # Knowledge graph output
├── vercel.json           # Vercel deployment config
├── package.json          # Node.js manifest
└── vitest.config.js      # Test runner config
```

## Commands

```bash
# Run all tests (single execution)
npm test

# Run tests in watch mode
npm run test:watch

# Run a single test file
npx vitest run path/to/file.test.js

# Run tests with coverage
npm test -- --coverage

# Start the OWASP ZAP CORS proxy server (port 3001)
npm start

# Dev mode with auto-reload (proxy server)
npm run dev
```

## Architecture

### No Build Step
This is a vanilla JS project served as static HTML/CSS/JS files. Pages load scripts via `<script>` tags. There is no module bundler, no transpilation, no import/export between browser files — modules communicate through globals on `window`.

### Key Modules (loaded order matters in dashboard.html)
All JS modules live in `public/js/`:
- `api-client.js` — Centralized HTTP client (`APIClient` class). Handles JWT auth, request interceptors, loading indicators. Base URL points to an ngrok-tunneled Laravel backend.
- `auth.js` — Authentication flows (login, signup, 2FA, session management). Exposes `AuthManager`.
- `main.js` — Core security tools (port scanning, XSS via ZAP, SSL checks, hash tools, WHOIS, DNS). Initializes `apiClient` and `projectManager` globals.
- `project-manager.js` — Project CRUD and collaborator management (`ProjectManager` class).
- `threat-intel.js` — Threat intelligence hub orchestrating VirusTotal, AbuseIPDB, URLScan.io APIs.
- `data-normalizer.js` — Converts between camelCase (frontend) and snake_case (backend API).
- `error-handler.js` — Centralized error display utility.
- `cyber-notify.js` — Toast notification system.
- `state-manager.js` — Dashboard state transitions (empty/scanning/result).
- `dashboard-tab-manager.js` — Tab switching logic.
- `risk-gauge.js` — SVG risk score visualization.

### Pages
All HTML pages live in `public/`:
- `index.html` — Marketing landing page
- `dashboard.html` — Main app (tabbed: Network, Web Security, Hash Tools, AI Assistant, Threat Intel, Projects)
- `login.html` / `signup.html` / `forgot-password.html` / `reset-password.html` / `email-verification.html` — Auth pages
- `pricing.html` — Subscription plans
- `invite.html` — Team invitation acceptance
- `paymob-redirect.html` — Payment redirect handler

### Styling
All CSS files live in `public/css/`:
- `theme-tokens.css` — Design token system (CSS custom properties prefixed `--cg-*`). Single source of truth for colors, spacing, radii, shadows, transitions.
- `cyber-theme.css` — Component styles using those tokens. Classes prefixed `cyber-*`.
- `landing.css` / `auth.css` / `Style.css` — Page-specific styles.
- Dashboard also loads Tailwind CSS via CDN for utility classes.

### Backend API
- Base URL: hardcoded in `public/js/api-client.js` (ngrok URL)
- Auth: JWT Bearer token stored in localStorage (`cyberguard_jwt`)
- All requests include `ngrok-skip-browser-warning: true` header
- API uses snake_case field names; `data-normalizer.js` handles conversion

### State & Storage
- JWT token: `localStorage.cyberguard_jwt`
- User data: `localStorage.cyberguard_user`
- Session: `localStorage.cyberguard_session`
- API keys: encrypted with XOR cipher in localStorage
- Threat intel search history: localStorage

## Testing

- **Framework**: Vitest with happy-dom environment
- **Property-based testing**: fast-check library for correctness validation
- **Test files**: `tests/` directory (unit/, integration/, manual/)
- **Coverage**: v8 provider
- Tests mock the DOM (happy-dom) — no real browser needed for unit/integration tests
- Source files are read from `public/js/` and `public/` in tests

## Conventions

- CSS classes: `cyber-*` prefix for themed components
- JS classes: PascalCase (`APIClient`, `ProjectManager`)
- JS functions: camelCase
- Constants: UPPER_SNAKE_CASE
- DOM IDs: kebab-case
- File names: lowercase with hyphens
- Design tokens must come from `theme-tokens.css` — no hardcoded colors/spacing
- HTML pages reference CSS via `css/` prefix, JS via `js/` prefix (relative to public/)

## Deployment

- Frontend: Vercel (static files from `public/`, routing configured in `vercel.json`)
- Backend: Laravel 12 with MySQL, Redis queues, Pusher WebSockets
- ZAP proxy: separate Node.js process (not deployed to Vercel)

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
