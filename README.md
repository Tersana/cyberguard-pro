# CyberGuard Pro

A web-based cybersecurity analysis platform built with vanilla JavaScript. Communicates with a Laravel 12 backend via REST API and deploys as static files on Vercel.

---

## Project Structure

```
CyberGuardWeb/
├── public/                              # Static site root (served by Vercel)
│   ├── index.html                       # Marketing landing page
│   ├── dashboard.html                   # Main app dashboard
│   ├── login.html                       # Authentication: login
│   ├── signup.html                      # Authentication: registration
│   ├── forgot-password.html             # Authentication: password recovery
│   ├── reset-password.html              # Authentication: password reset
│   ├── email-verification.html          # Authentication: email verification prompt
│   ├── verify-email.html                # Authentication: email verify action
│   ├── invite.html                      # Team invitation acceptance
│   ├── pricing.html                     # Subscription plans
│   ├── paymob-redirect.html             # Payment redirect handler
│   ├── billing-paymob-redirect.html     # Alternate billing redirect
│   ├── project-detail.html              # Project detail view
│   ├── reset-password/                  # Reset password redirect shim
│   │   └── index.html
│   ├── css/                             # Stylesheets
│   │   ├── theme-tokens.css             # Design token system (--cg-* custom properties)
│   │   ├── cyber-theme.css              # Component styles (cyber-* classes)
│   │   ├── Style.css                    # Dashboard component styles
│   │   ├── landing.css                  # Landing page styles
│   │   └── auth.css                     # Authentication page styles
│   ├── js/                              # JavaScript modules
│   │   ├── api-client.js                # HTTP client with JWT auth
│   │   ├── auth.js                      # Authentication flows & session management
│   │   ├── main.js                      # Core security tools
│   │   ├── main-original.js             # Legacy version (archive)
│   │   ├── project-manager.js           # Project CRUD & collaborator management
│   │   ├── threat-intel.js              # Threat intelligence hub
│   │   ├── data-normalizer.js           # camelCase/snake_case conversion
│   │   ├── error-handler.js             # Centralized error display
│   │   ├── error-handler-example.js     # Error handler usage example
│   │   ├── cyber-notify.js              # Toast notification system
│   │   ├── state-manager.js             # Dashboard state transitions
│   │   ├── dashboard-tab-manager.js     # Tab switching logic
│   │   ├── dashboard-integration.js     # Dashboard integration layer
│   │   ├── risk-gauge.js                # SVG risk score visualization
│   │   ├── scan-manager.js              # Scan engine
│   │   ├── billing-api.js               # Billing service layer
│   │   ├── billing-utils.js             # Billing utility functions
│   │   ├── forgot-password.js           # Forgot password flow
│   │   ├── reset-password.js            # Reset password flow
│   │   ├── landing.js                   # Landing page animations
│   │   ├── target-validator.js          # Target input validation
│   │   ├── result-item-structure.js     # Result item schema
│   │   ├── echo-config.js              # Laravel Echo/WebSocket config
│   │   └── performance-audit.js         # Performance tracking
│   └── lib/                             # Vendor libraries
│       ├── echo.iife.js                 # Laravel Echo
│       └── pusher.min.js                # Pusher.js
├── data/                                # Static data files
│   ├── phishing_dataset.csv             # ML training data
│   └── test-results.json                # Test results data
├── docs/                                # Documentation
│   ├── CYBERGUARD_PRO_DOCUMENTATION.md  # Full project documentation
│   ├── CyberGuard API Reference.md      # API reference
│   ├── BACKEND_ARCHITECTURE_QUICK_REFERENCE.md
│   ├── SECURITY_TESTING_GUIDE.md
│   ├── SECURITY_TEST_DATA.md
│   ├── email verify workflow.md
│   ├── frontend_scanning_implementation_guide.md
│   ├── Billing and Subscription in Cygaurd prompt.md
│   ├── CyberGuard Pro — Design Token System & UI Refactor implementation plan.md
│   └── pricing-page-subscription-fix.md
├── scripts/                             # Build & utility scripts
│   ├── build_html_slides.py             # Presentation builder
│   └── generate_presentation.py         # Presentation generator
├── tests/                               # Test suites
│   ├── unit/                            # Unit tests (39 files)
│   ├── integration/                     # Integration tests (6 files)
│   ├── manual/                          # Manual test scripts
│   └── *.test.js                        # Root-level test files
├── graphify-out/                        # Knowledge graph output
├── vercel.json                          # Vercel deployment config
├── package.json                         # Node.js package manifest
├── package-lock.json                    # Dependency lock file
├── vitest.config.js                     # Vitest test runner config
├── CLAUDE.md                            # AI assistant guide
├── .gitignore                           # Git ignore rules
└── .graphifyignore                      # Graphify ignore rules
```

## Folder Descriptions

| Folder | Contents |
|--------|----------|
| `public/` | Static site root deployed to Vercel — all HTML, CSS, JS, and vendor libs |
| `public/css/` | Stylesheets: design tokens, component themes, page-specific styles |
| `public/js/` | JavaScript modules loaded via `<script>` tags (no bundler) |
| `public/lib/` | Third-party vendor libraries (Pusher, Laravel Echo) |
| `data/` | Static data files (datasets, test results) not served to browsers |
| `docs/` | Project documentation, API references, implementation guides |
| `scripts/` | Python build/utility scripts for presentations |
| `tests/` | Vitest test suites organized by type (unit, integration, manual) |
| `graphify-out/` | Auto-generated knowledge graph for codebase navigation |

## Getting Started

### Prerequisites
- Node.js 18+
- npm

### Setup
```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch
```

### Development
This is a static HTML/CSS/JS project — no build step required. Open any HTML file in `public/` directly in a browser, or use a local static server.

For the OWASP ZAP CORS proxy:
```bash
npm start        # Start proxy on port 3001
npm run dev      # Dev mode with auto-reload
```

### Deployment
The project deploys to Vercel as static files. Vercel serves from the `public/` directory with clean URLs enabled.

```bash
# Deploy via Vercel CLI
vercel
```

Configuration is in `vercel.json`:
- `outputDirectory: "public"` — serves the public/ folder
- `cleanUrls: true` — extension-free URLs
- Rewrites for invitation and payment redirect routes
- 301 redirects from `.html` extensions to clean URLs

## Architecture Notes

- **No bundler/transpiler**: Modules communicate through `window` globals
- **Script load order matters**: `dashboard.html` loads scripts in dependency order
- **Design tokens**: All colors, spacing, and visual properties come from `public/css/theme-tokens.css`
- **API communication**: JWT-based auth via `public/js/api-client.js` pointing to a Laravel backend
- **Real-time updates**: Pusher/Laravel Echo for WebSocket communication
