/**
 * CyberGuard Pro — Local Development Server
 *
 * Mirrors vercel.json cleanUrls + rewrites so that clean URLs (e.g. /dashboard)
 * work identically in local dev as they do on Vercel production.
 *
 * Usage:  npm run dev
 * URL:    http://127.0.0.1:5512
 */

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = process.env.PORT || 5513;

const app = express();

// ─── 1. Clean-URL rewrites (mirrors vercel.json "cleanUrls": true) ───────────
// Map every clean URL → its .html file, exactly as Vercel resolves them.
const CLEAN_URL_MAP = {
  '/':                          'index.html',
  '/index':                     'index.html',
  '/login':                     'login.html',
  '/signup':                    'signup.html',
  '/dashboard':                 'dashboard.html',
  '/forgot-password':           'forgot-password.html',
  '/reset-password':            'reset-password.html',
  '/email-verification':        'email-verification.html',
  '/verify-email':              'verify-email.html',
  '/invite':                    'invite.html',
  '/pricing':                   'pricing.html',
  '/project-detail':            'project-detail.html',
  '/paymob-redirect':           'paymob-redirect.html',
  '/billing-paymob-redirect':   'billing-paymob-redirect.html',
  '/scan-progress':             'scan-progress.html',
};

// ─── 2. Dynamic rewrites (mirrors vercel.json "rewrites" array) ───────────────
// These are checked in order, just like Vercel processes them.
const DYNAMIC_REWRITES = [
  // /invitations/:token*  → /invite
  { pattern: /^\/invitations(\/.*)?$/, target: 'invite.html' },
  // /invite/:token*       → /invite  (token present = parameterised invite link)
  { pattern: /^\/invite\/.+/, target: 'invite.html' },
  // /billing/paymob/redirect → /paymob-redirect
  { pattern: /^\/billing\/paymob\/redirect$/, target: 'paymob-redirect.html' },
  // /api/billing/paymob/redirect → /paymob-redirect
  { pattern: /^\/api\/billing\/paymob\/redirect$/, target: 'paymob-redirect.html' },
  // /scan/:scanJobId → /scan-progress
  { pattern: /^\/scan\/[^/]+$/, target: 'scan-progress.html' },
];

// ─── 3. Redirect .html → clean URL (mirrors vercel.json "redirects") ─────────
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    const clean = req.path.slice(0, -5); // strip .html
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    return res.redirect(301, clean + qs);
  }
  next();
});

// ─── 4. Apply clean-URL map ───────────────────────────────────────────────────
app.use((req, res, next) => {
  const pathname = req.path.split('?')[0].replace(/\/$/, '') || '/';

  if (CLEAN_URL_MAP[pathname]) {
    req.url = '/' + CLEAN_URL_MAP[pathname];
    return next();
  }

  // Check dynamic rewrites
  for (const { pattern, target } of DYNAMIC_REWRITES) {
    if (pattern.test(pathname)) {
      req.url = '/' + target;
      return next();
    }
  }

  next();
});

// ─── 5. Serve static files from /public ──────────────────────────────────────
app.use(express.static(PUBLIC_DIR));

// ─── 6. 404 fallback ─────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <body style="font-family:monospace;padding:2rem;background:#0d1117;color:#f85149">
        <h2>404 — Not Found</h2>
        <p>No route matched: <code>${req.originalUrl}</code></p>
        <p>Available routes: ${Object.keys(CLEAN_URL_MAP).join(', ')}</p>
      </body>
    </html>
  `);
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
  console.log('\n🛡️  CyberGuard Pro — Local Dev Server');
  console.log(`   http://127.0.0.1:${PORT}`);
  console.log('\n   Clean URLs active (mirrors Vercel production):');
  Object.entries(CLEAN_URL_MAP).forEach(([url]) =>
    console.log(`   http://127.0.0.1:${PORT}${url}`)
  );
  console.log('\n   Press Ctrl+C to stop.\n');
});
