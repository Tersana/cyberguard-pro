const fs = require('fs');
const f = 'd:/Code/CyberGuardWeb/public/js/main.js';
let c = fs.readFileSync(f, 'utf8');

// The orphaned code left behind by the bad patch — 
// these lines exist in the file without the proper else-if guard around them
const bad = [
  '\n        const modalPane = document.getElementById(\'wa-modal-results-pane\');',
  '\n        if (modalPane) this.renderEmailResults(this.emailResults, modalPane);',
  '\n      }',
  '\r\n',
  '\r\n'
].join('');

const good = [
  '\r\n      // 3. Email Security Policy Audit',
  '\r\n      else if (toolId === \'email\') {',
  '\r\n        if (!this.emailResults) {',
  '\r\n          resultsPane.innerHTML = `',
  '\r\n            <div style="padding:40px;text-align:center;color:var(--cg-text-3);font-size:12px">',
  '\r\n              No Email Security data available yet. Enter a target URL and click Run Analysis.',
  '\r\n            </div>`;',
  '\r\n          return;',
  '\r\n        }',
  '\r\n        this.renderEmailResults(this.emailResults, resultsPane);',
  '\r\n      }',
  '\r\n',
  '\r\n'
].join('');

const idx = c.indexOf(bad);
if (idx === -1) {
  // Try to locate what's actually there for debugging
  const searchStr = 'wa-modal-results-pane';
  const positions = [];
  let pos = 0;
  while ((pos = c.indexOf(searchStr, pos)) !== -1) {
    positions.push(pos);
    pos++;
  }
  console.log('wa-modal-results-pane found at positions:', positions);
  // Show context around first occurrence
  if (positions.length > 0) {
    console.log('Context:', JSON.stringify(c.substring(positions[0] - 50, positions[0] + 200)));
  }
  process.exit(1);
}

c = c.slice(0, idx) + good + c.slice(idx + bad.length);
fs.writeFileSync(f, c, 'utf8');
console.log('Fixed. Lines:', c.split('\n').length);
