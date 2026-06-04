/**
 * patch_email_auditor.js
 * Renames all remaining 'tech' → 'email' references in WebAuditing,
 * plus adds the Email Security Auditor function and renderer.
 */

const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'public', 'js', 'main.js');
let c = fs.readFileSync(file, 'utf8');

// ─────────────────────────────────────────────────────────────
// 1. ToolRegistry: tech-btn → email-btn
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `"tech-btn":    () => window.WebAuditing?.runTechFingerprint(),`,
  `"email-btn":   () => window.WebAuditing?.runEmailSecurityAnalysis(),`
);

// ─────────────────────────────────────────────────────────────
// 2. Button-to-toolId map
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `'headers-btn': 'headers', 'links-btn': 'links', 'tech-btn': 'tech',`,
  `'headers-btn': 'headers', 'links-btn': 'links', 'email-btn': 'email',`
);

// ─────────────────────────────────────────────────────────────
// 3. updateAuditorFilterControls: tech filters → email filters
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `        tech: [\r\n          { label: 'High Risk (CVE)', status: 'high', type: 'danger' },\r\n          { label: 'Medium Risk (CVE)', status: 'medium', type: 'warning' },\r\n          { label: 'Safe Components', status: 'none', type: 'success' }\r\n        ],`,
  `        email: [\r\n          { label: 'Missing Defenses', status: 'missing', type: 'danger' },\r\n          { label: 'Weak Policies', status: 'warning', type: 'warning' },\r\n          { label: 'Secure Policies', status: 'passed', type: 'success' }\r\n        ],`
);

// ─────────────────────────────────────────────────────────────
// 4. applyAuditorFilters: replace tech pill branch with email legacy branch
// ─────────────────────────────────────────────────────────────
const techFilterBlock = `      } else if (toolId === 'tech') {\r\n        const pills = bodyEl.querySelectorAll('.wa-tech-item-pill');\r\n        pills.forEach(el => {\r\n          if (!filtersActive) {\r\n            el.style.display = 'inline-flex';\r\n          } else {\r\n            const risk = el.dataset.risk || 'none';\r\n            let show = false;\r\n            if (this.activeFilters.has('high') && risk === 'high') show = true;\r\n            if (this.activeFilters.has('medium') && risk === 'medium') show = true;\r\n            if (this.activeFilters.has('none') && (risk === 'none' || risk === 'low')) show = true;\r\n            el.style.display = show ? 'inline-flex' : 'none';\r\n          }\r\n        });\r\n\r\n        const cards = bodyEl.querySelectorAll('.wa-tech-category-card');\r\n        cards.forEach(card => {\r\n          const visiblePills = Array.from(card.querySelectorAll('.wa-tech-item-pill')).filter(p => p.style.display !== 'none');\r\n          card.style.display = (visiblePills.length > 0) ? '' : 'none';\r\n        });\r\n      } else if (['ssl', 'phishing', 'dns-spoof'].includes(toolId)) {`;

const emailFilterBlock = `      } else if (['email', 'ssl', 'phishing', 'dns-spoof'].includes(toolId)) {`;

c = c.replace(techFilterBlock, emailFilterBlock);

// ─────────────────────────────────────────────────────────────
// 5. clearActiveToolResults: techResults → emailResults, update tools array
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `this.headersResults = null;\r\n      this.linksResults = null;\r\n      this.techResults = null;\r\n      const tools = ['headers', 'links', 'tech', 'ssl', 'phishing', 'dns-spoof'];`,
  `this.headersResults = null;\r\n      this.linksResults = null;\r\n      this.emailResults = null;\r\n      const tools = ['headers', 'links', 'email', 'ssl', 'phishing', 'dns-spoof'];`
);

// ─────────────────────────────────────────────────────────────
// 6. switchTool: tabs array
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `      const tabs = ['headers', 'links', 'tech', 'ssl', 'phishing', 'dns-spoof'];`,
  `      const tabs = ['headers', 'links', 'email', 'ssl', 'phishing', 'dns-spoof'];`
);

// ─────────────────────────────────────────────────────────────
// 7. switchTool: toolNames
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `        tech: 'Technology Fingerprinting',`,
  `        email: 'Email Security Policy Audit',`
);

// ─────────────────────────────────────────────────────────────
// 8. switchTool: toolDescs
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `        tech: 'Fingerprint technologies, frameworks, servers, and vulnerability CVE risk levels',`,
  `        email: 'Audit SPF and DMARC DNS records to detect email spoofing vulnerabilities',`
);

// ─────────────────────────────────────────────────────────────
// 9. renderCurrentToolView: tech branch → email branch
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `      } else if (this.activeToolId === 'tech' && this.techResults) {\r\n        this.renderTechResults(this.techResults.detected, this.techResults.target);\r\n      } else if (['ssl', 'phishing', 'dns-spoof'].includes(this.activeToolId)) {`,
  `      } else if (this.activeToolId === 'email' && this.emailResults) {\r\n        this.renderEmailResults(this.emailResults);\r\n      } else if (['ssl', 'phishing', 'dns-spoof', 'email'].includes(this.activeToolId)) {`
);

// ─────────────────────────────────────────────────────────────
// 10. updateCountBadges: tools array
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `      const tools = ['headers', 'links', 'tech', 'ssl', 'phishing', 'dns-spoof'];`,
  `      const tools = ['headers', 'links', 'email', 'ssl', 'phishing', 'dns-spoof'];`
);

// ─────────────────────────────────────────────────────────────
// 11. updateCountBadges: tech count logic → email count logic
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `        } else if (t === 'tech' && this.techResults) {\r\n          count = this.techResults.detected.filter(tech => tech.cveRisk === 'high').length;`,
  `        } else if (t === 'email' && this.emailResults) {\r\n          count = (this.emailResults.checks || []).filter(ch => ch.status === 'missing').length;`
);

// ─────────────────────────────────────────────────────────────
// 12. logResult: add 'email' to featureToToolId
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `      const featureToToolId = {\r\n        "SSL/TLS Check": "ssl",\r\n        "URL Phishing Analyzer": "phishing",\r\n        "DNS Spoof Check": "dns-spoof"\r\n      };`,
  `      const featureToToolId = {\r\n        "SSL/TLS Check": "ssl",\r\n        "URL Phishing Analyzer": "phishing",\r\n        "DNS Spoof Check": "dns-spoof",\r\n        "Email Security": "email"\r\n      };`
);

// ─────────────────────────────────────────────────────────────
// 13. renderLegacyResults: add email to featureMap
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `      const featureMap = {\r\n        'ssl': 'SSL/TLS Check',\r\n        'phishing': 'URL Phishing Analyzer',\r\n        'dns-spoof': 'DNS Spoof Check'\r\n      };`,
  `      const featureMap = {\r\n        'ssl': 'SSL/TLS Check',\r\n        'phishing': 'URL Phishing Analyzer',\r\n        'dns-spoof': 'DNS Spoof Check',\r\n        'email': 'Email Security'\r\n      };`
);

// ─────────────────────────────────────────────────────────────
// 14. Replace runTechFingerprint + _renderTechToElement + renderTechResults
//     with the new Email Security Auditor implementation
// ─────────────────────────────────────────────────────────────

// Find and remove the old tech functions block
const techFnStart = `    async runTechFingerprint() {`;
const techFnEndMarker = `    // ── SHARED UTILITIES ──────────────────────────────────────`;

const techFnStartIdx = c.indexOf(techFnStart);
const techFnEndIdx = c.indexOf(techFnEndMarker, techFnStartIdx);

if (techFnStartIdx === -1) {
  console.error('runTechFingerprint start not found!');
  process.exit(1);
}
if (techFnEndIdx === -1) {
  console.error('Tool 4 marker not found!');
  process.exit(1);
}

const newEmailFunctions = `    // ── TOOL 3: EMAIL SECURITY POLICY AUDITOR (SPF & DMARC) ──────────────
    async runEmailSecurityAnalysis() {
      const target = this.getTarget();
      if (!target) return;

      this.setToolStatus('email', 'running');
      this.switchTool('email');

      try {
        // Extract root domain from URL
        let domain = target.trim().replace(/^https?:\\/\\//i, '').replace(/\\/.*$/, '').toLowerCase();

        logResult(new Date(), 'Email Security', \`Starting email security audit for \${domain}\`, 'info');

        // ── Query SPF (TXT records on root domain) ──
        let spfRecord = null;
        let spfRaw = '';
        try {
          const spfResp = await fetch(\`https://cloudflare-dns.com/dns-query?name=\${encodeURIComponent(domain)}&type=TXT\`, {
            headers: { accept: 'application/dns-json' }
          });
          const spfData = await spfResp.json();
          const txtAnswers = (spfData.Answer || []).map(a => (a.data || '').replace(/"/g, '').trim());
          spfRecord = txtAnswers.find(t => t.startsWith('v=spf1')) || null;
          spfRaw = spfRecord || '(none)';
          logResult(new Date(), 'Email Security', \`SPF TXT lookup complete: \${spfRecord ? 'record found' : 'no SPF record'}\`, 'info');
        } catch (spfErr) {
          logResult(new Date(), 'Email Security', \`SPF lookup error: \${spfErr.message}\`, 'warning');
        }

        // ── Query DMARC (TXT records on _dmarc.domain) ──
        let dmarcRecord = null;
        let dmarcRaw = '';
        try {
          const dmarcDomain = \`_dmarc.\${domain}\`;
          const dmarcResp = await fetch(\`https://cloudflare-dns.com/dns-query?name=\${encodeURIComponent(dmarcDomain)}&type=TXT\`, {
            headers: { accept: 'application/dns-json' }
          });
          const dmarcData = await dmarcResp.json();
          const dmarcAnswers = (dmarcData.Answer || []).map(a => (a.data || '').replace(/"/g, '').trim());
          dmarcRecord = dmarcAnswers.find(t => t.startsWith('v=DMARC1')) || null;
          dmarcRaw = dmarcRecord || '(none)';
          logResult(new Date(), 'Email Security', \`DMARC TXT lookup complete: \${dmarcRecord ? 'record found' : 'no DMARC record'}\`, 'info');
        } catch (dmarcErr) {
          logResult(new Date(), 'Email Security', \`DMARC lookup error: \${dmarcErr.message}\`, 'warning');
        }

        // ── Evaluate SPF ──────────────────────────────────
        let spfStatus, spfDetail, spfRec;
        if (!spfRecord) {
          spfStatus = 'missing';
          spfDetail = 'No SPF record found. Unauthenticated senders can spoof your domain in email From headers.';
          spfRec = 'Publish a TXT record on your root domain: v=spf1 include:your-mail-provider.com -all';
        } else if (spfRecord.includes('-all')) {
          spfStatus = 'passed';
          spfDetail = 'SPF record exists with hard fail (-all). Unauthorized senders are rejected.';
          spfRec = 'Maintain your current SPF record. Periodically audit include: mechanisms for unused services.';
        } else if (spfRecord.includes('~all')) {
          spfStatus = 'warning';
          spfDetail = 'SPF record uses soft fail (~all). Unauthorized senders are marked but not rejected.';
          spfRec = 'Upgrade from ~all to -all once all legitimate sending sources are included in your SPF record.';
        } else if (spfRecord.includes('?all') || spfRecord.includes('+all')) {
          spfStatus = 'missing';
          spfDetail = 'SPF record uses neutral/pass-all (?all or +all). This provides no spoofing protection.';
          spfRec = 'Replace ?all or +all with -all to enforce a strict SPF policy.';
        } else {
          spfStatus = 'warning';
          spfDetail = 'SPF record exists but does not include a recognized all mechanism.';
          spfRec = 'Ensure your SPF record ends with -all for strict enforcement.';
        }

        // ── Evaluate DMARC ────────────────────────────────
        let dmarcStatus, dmarcDetail, dmarcRec;
        const dmarcPolicy = dmarcRecord ? (dmarcRecord.match(/p=([^;\\s]+)/i)?.[1] || '').toLowerCase() : '';
        if (!dmarcRecord) {
          dmarcStatus = 'missing';
          dmarcDetail = 'No DMARC record found at _dmarc.' + domain + '. Email spoofing cannot be reported or blocked.';
          dmarcRec = 'Publish: _dmarc.' + domain + ' TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@' + domain + '"';
        } else if (dmarcPolicy === 'reject') {
          dmarcStatus = 'passed';
          dmarcDetail = 'DMARC policy is p=reject. Spoofed emails are blocked by receiving mail servers.';
          dmarcRec = 'Maintain the reject policy and ensure rua/ruf reporting addresses are monitored.';
        } else if (dmarcPolicy === 'quarantine') {
          dmarcStatus = 'warning';
          dmarcDetail = 'DMARC policy is p=quarantine. Spoofed emails are sent to spam, but not rejected outright.';
          dmarcRec = 'Escalate from p=quarantine to p=reject once DMARC reporting confirms all legitimate mail passes.';
        } else if (dmarcPolicy === 'none') {
          dmarcStatus = 'warning';
          dmarcDetail = 'DMARC policy is p=none (monitor only). No enforcement action is taken on spoofed emails.';
          dmarcRec = 'Review DMARC aggregate reports (rua), then escalate to p=quarantine and then p=reject.';
        } else {
          dmarcStatus = 'warning';
          dmarcDetail = 'DMARC record found but policy could not be determined.';
          dmarcRec = 'Verify the p= tag in your DMARC record and set it to quarantine or reject.';
        }

        const checks = [
          {
            name: 'SPF Record Presence',
            status: spfRecord ? (spfStatus === 'passed' ? 'passed' : spfStatus) : 'missing',
            value: spfRaw,
            detail: spfDetail,
            recommendation: spfRec
          },
          {
            name: 'SPF Policy Enforcement',
            status: spfStatus,
            value: spfRecord ? (spfRecord.match(/[~?+-]all/i)?.[0] || 'unknown') : 'N/A',
            detail: spfDetail,
            recommendation: spfRec
          },
          {
            name: 'DMARC Record Presence',
            status: dmarcRecord ? (dmarcStatus === 'passed' ? 'passed' : dmarcStatus) : 'missing',
            value: dmarcRaw,
            detail: dmarcDetail,
            recommendation: dmarcRec
          },
          {
            name: 'DMARC Policy Enforcement',
            status: dmarcStatus,
            value: dmarcRecord ? ('p=' + (dmarcPolicy || 'unknown')) : 'N/A',
            detail: dmarcDetail,
            recommendation: dmarcRec
          }
        ];

        const missingCount = checks.filter(ch => ch.status === 'missing').length;
        const warnCount    = checks.filter(ch => ch.status === 'warning').length;
        const safeCount    = checks.filter(ch => ch.status === 'passed').length;

        const overallStatus = missingCount > 0 ? 'threat' : warnCount > 0 ? 'warning' : 'safe';
        const summaryMsg = [
          spfRecord ? \`SPF: \${spfStatus.toUpperCase()}\` : 'SPF: MISSING',
          dmarcRecord ? \`DMARC: \${dmarcStatus.toUpperCase()}\` : 'DMARC: MISSING'
        ].join(' | ');

        this.emailResults = { checks, domain, spfRaw, dmarcRaw };
        this.renderEmailResults(this.emailResults);
        this.setToolStatus('email', 'done', \`\${missingCount + warnCount} issue\${(missingCount + warnCount) !== 1 ? 's' : ''}\`);

        logResult(
          new Date(),
          'Email Security',
          \`Email security audit for \${domain} — \${summaryMsg}. Missing: \${missingCount}, Weak: \${warnCount}, Secure: \${safeCount}\`,
          overallStatus === 'threat' ? 'danger' : overallStatus === 'warning' ? 'warning' : 'success',
          {
            evidence: JSON.stringify({ domain, spfRaw, dmarcRaw, checks }),
            remediation: checks.filter(ch => ch.status !== 'passed').map(ch => ch.recommendation)
          }
        );

      } catch(e) {
        this.setToolStatus('email', 'error');
        this.showError('email', e.message);
      }
    },

    // ── EMAIL SECURITY RESULTS RENDERER ──────────────────────────────────
    renderEmailResults(results) {
      const bodyEl = document.getElementById('wa-results-body');
      if (!bodyEl || !results) return;

      const { checks = [], domain = '', spfRaw = '', dmarcRaw = '' } = results;
      const missingCount = checks.filter(ch => ch.status === 'missing').length;
      const warnCount    = checks.filter(ch => ch.status === 'warning').length;
      const safeCount    = checks.filter(ch => ch.status === 'passed').length;

      const threatColor  = missingCount > 0 ? 'var(--cg-danger)'  : 'var(--cg-text-3)';
      const warningColor = warnCount    > 0 ? 'var(--cg-warning)' : 'var(--cg-text-3)';
      const safeColor    = safeCount    > 0 ? 'var(--cg-success)' : 'var(--cg-text-3)';

      const findingsHtml = checks.map((ch, idx) => {
        const statusClass = ch.status === 'passed' ? 'wa-present' : ch.status === 'warning' ? 'wa-misconfigured' : 'wa-missing';
        const statusText  = ch.status === 'passed' ? 'passed'     : ch.status === 'warning' ? 'warning'          : 'missing';
        return \`
          <div class="wa-legacy-item" data-status="\${statusText}">
            <div class="wa-header-row" onclick="window.WebAuditing.toggleLegacyDetail('email', \${idx})">
              <span class="wa-header-name" style="font-weight:600;">\${escapeHtml(ch.name)}</span>
              <span class="wa-header-status \${statusClass}">\${statusText}</span>
              <span style="font-size:12px;color:var(--cg-text-2);font-family:var(--cg-font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                \${escapeHtml(ch.value)}
              </span>
            </div>
            <div class="wa-header-detail" id="wa-legacy-detail-email-\${idx}" style="display:none;padding:16px;background:rgba(0,0,0,0.3);border-bottom:1px solid var(--cg-border);font-size:12px;color:var(--cg-text-2);line-height:1.5;">
              <div style="font-weight:600;color:var(--cg-text-1);margin-bottom:6px;">Check: \${escapeHtml(ch.name)}</div>
              <div style="margin-bottom:8px;">Status: <span class="font-bold" style="color:\${ch.status === 'passed' ? 'var(--cg-success)' : ch.status === 'warning' ? 'var(--cg-warning)' : 'var(--cg-danger)'}">\${statusText.toUpperCase()}</span></div>
              <div style="margin-bottom:8px;font-family:var(--cg-font-mono);">\${escapeHtml(ch.detail)}</div>
              \${ch.recommendation ? \`
                <div style="margin-top:8px;padding:10px;background:rgba(0,0,0,0.4);border:1px solid var(--cg-border);border-radius:6px;font-family:var(--cg-font-mono);font-size:11px;color:var(--cg-success)">
                  Recommended Action: \${escapeHtml(ch.recommendation)}
                </div>\` : ''}
            </div>
          </div>\`;
      }).join('');

      const additionalInfoHtml = \`
        <div style="margin-top:16px;padding:16px;background:rgba(255,255,255,0.02);border:1px solid var(--cg-border);border-radius:8px;">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--cg-text-3);margin-bottom:10px">
            DNS Record Snapshot
          </div>
          <div style="overflow-x:auto;">
            <table style="width:100%;font-size:11px;font-family:var(--cg-font-mono);border-collapse:collapse;color:var(--cg-text-2);">
              <thead>
                <tr style="border-bottom:1px solid var(--cg-border);text-align:left;">
                  <th style="padding:6px 8px;color:var(--cg-text-3)">RECORD TYPE</th>
                  <th style="padding:6px 8px;color:var(--cg-text-3)">QUERY</th>
                  <th style="padding:6px 8px;color:var(--cg-text-3)">RAW VALUE</th>
                </tr>
              </thead>
              <tbody>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.03);">
                  <td style="padding:6px 8px;color:var(--cg-text-1);font-weight:600;">SPF</td>
                  <td style="padding:6px 8px;">\${escapeHtml(domain)}</td>
                  <td style="padding:6px 8px;word-break:break-all;">\${escapeHtml(spfRaw)}</td>
                </tr>
                <tr>
                  <td style="padding:6px 8px;color:var(--cg-text-1);font-weight:600;">DMARC</td>
                  <td style="padding:6px 8px;">_dmarc.\${escapeHtml(domain)}</td>
                  <td style="padding:6px 8px;word-break:break-all;">\${escapeHtml(dmarcRaw)}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>\`;

      bodyEl.innerHTML = \`
        <div class="wa-grade-display" style="padding:16px;margin-bottom:16px;">
          <div>
            <div style="font-size:14px;font-weight:700;color:var(--cg-text-1);margin-bottom:4px;">
              Target Audited: <span style="font-family:var(--cg-font-mono);">\${escapeHtml(domain)}</span>
            </div>
            <div style="display:flex;gap:16px;font-size:12px;margin-top:4px;">
              <span style="color:\${threatColor};font-weight:600;">\${missingCount} missing defense\${missingCount !== 1 ? 's' : ''}</span>
              <span style="color:\${warningColor};font-weight:600;">\${warnCount} weak polic\${warnCount !== 1 ? 'ies' : 'y'}</span>
              <span style="color:\${safeColor};font-weight:600;">\${safeCount} secure polic\${safeCount !== 1 ? 'ies' : 'y'}</span>
            </div>
          </div>
        </div>

        <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.1em;color:var(--cg-text-3);margin-bottom:12px;">
          Audit Findings Breakdown
        </div>

        <div>\${findingsHtml}</div>

        \${additionalInfoHtml}
      \`;

      this.applyAuditorFilters();

      if (document.getElementById('wa-auditor-modal') && !document.getElementById('wa-auditor-modal').classList.contains('hidden')) {
        this.renderModalResults(this.activeToolId);
      }
    },

    `;

c = c.slice(0, techFnStartIdx) + newEmailFunctions + c.slice(techFnEndIdx);

// ─────────────────────────────────────────────────────────────
// 15. renderModalResults: replace tech section with email section
// ─────────────────────────────────────────────────────────────
c = c.replace(
  `      // 3. Tech Fingerprint — delegate to the shared Wappalyzer-grade renderer\r\n      else if (toolId === 'tech') {\r\n        if (!this.techResults) {\r\n          resultsPane.innerHTML = \`\r\n            <div style="padding:40px;text-align:center;color:var(--cg-text-3);font-size:12px">\r\n              No Tech Fingerprint data available yet. Enter a target URL and click Fingerprint Stack.\r\n            </div>\`;\r\n          return;\r\n        }\r\n        // Temporarily point the renderer at the modal pane, then restore\r\n        this._renderTechToElement(this.techResults.detected, this.techResults.target, resultsPane);\r\n      }`,
  `      // 3. Email Security Policy Audit\r\n      else if (toolId === 'email') {\r\n        if (!this.emailResults) {\r\n          resultsPane.innerHTML = \`\r\n            <div style="padding:40px;text-align:center;color:var(--cg-text-3);font-size:12px">\r\n              No Email Security data available yet. Enter a target URL and click Run Analysis.\r\n            </div>\`;\r\n          return;\r\n        }\r\n        this.renderEmailResults(this.emailResults);\r\n      }`
);

// ─────────────────────────────────────────────────────────────
// 16. renderLegacyResults: add email branch (before the final bodyEl.innerHTML block)
// ─────────────────────────────────────────────────────────────
// The email data is stored in emailResults not in resultsData, so renderEmailResults
// already handles it. We just need to make sure it's triggered for the 'email' tool.
// The renderCurrentToolView already calls renderEmailResults. For renderLegacyResults,
// 'email' will fall through (no feature match in featureMap produces null result)
// and will be handled gracefully showing "No scan data available".
// However the email tool stores data in this.emailResults, not resultsData.
// We should add a guard in renderLegacyResults to redirect email to renderEmailResults:
const legacyStartStr = `    renderLegacyResults() {\r\n      const bodyEl = document.getElementById('wa-results-body');\r\n      if (!bodyEl) return;`;
c = c.replace(
  legacyStartStr,
  `    renderLegacyResults() {\r\n      const bodyEl = document.getElementById('wa-results-body');\r\n      if (!bodyEl) return;\r\n\r\n      // Email tool uses its own dedicated renderer\r\n      if (this.activeToolId === 'email') {\r\n        return this.renderEmailResults(this.emailResults);\r\n      }`
);

fs.writeFileSync(file, c, 'utf8');
console.log('All patches applied. Final line count:', c.split('\n').length);
