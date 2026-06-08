import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PUBLIC_DIR = path.resolve(__dirname, '../public');

const EXCLUDE_FILES = [
  'pusher.min.js',
  'echo.iife.js'
];

const EXCLUDE_DIRS = [
  'lib',
  'node_modules'
];

// Regex for raw secrets/passwords/API keys: checks if there's a variable assignment of a token/key that has a static value >= 8 chars
const CREDENTIAL_LEAK_REGEX = /\b(api[-_]?key|secret|password|private[-_]?key|token|jwt|auth[-_]?token)\b\s*=\s*['"]([a-zA-Z0-9_\-\/\.+=:]{8,})['"]/gi;

// Unsafe HTTP endpoints (excludes localhost, dev loopbacks, or namespaces like w3.org)
const INSECURE_HTTP_REGEX = /\bhttp:\/\/(?!localhost|127\.0\.0\.1|www\.w3\.org)[a-zA-Z0-9_\-\.]+\b/gi;

function shouldIgnorePath(filePath) {
  const relative = path.relative(PUBLIC_DIR, filePath);
  const parts = relative.split(path.sep);
  
  if (EXCLUDE_FILES.includes(parts[parts.length - 1])) {
    return true;
  }
  
  return parts.some(part => EXCLUDE_DIRS.includes(part));
}

function walkDir(dir, callback) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      walkDir(fullPath, callback);
    } else {
      callback(fullPath);
    }
  }
}

function cleanCodeString(str) {
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBacktick = false;
  let inLineComment = false;
  let inBlockComment = false;
  let result = '';
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const nextChar = i < str.length - 1 ? str[i + 1] : '';
    const prevChar = i > 0 ? str[i - 1] : '';
    
    if (inLineComment) {
      if (char === '\n' || char === '\r') {
        inLineComment = false;
        result += char;
      }
      continue;
    }
    
    if (inBlockComment) {
      if (char === '*' && nextChar === '/') {
        inBlockComment = false;
        i++; // skip '/'
      }
      continue;
    }
    
    if (inSingleQuote) {
      result += char;
      if (char === "'" && prevChar !== '\\') {
        inSingleQuote = false;
      }
      continue;
    }
    
    if (inDoubleQuote) {
      result += char;
      if (char === '"' && prevChar !== '\\') {
        inDoubleQuote = false;
      }
      continue;
    }
    
    if (inBacktick) {
      result += char;
      if (char === '`' && prevChar !== '\\') {
        inBacktick = false;
      }
      continue;
    }
    
    // Check for comments
    if (char === '/' && nextChar === '/') {
      inLineComment = true;
      i++; // skip second '/'
      continue;
    }
    if (char === '/' && nextChar === '*') {
      inBlockComment = true;
      i++; // skip '*'
      continue;
    }
    
    // Check for quotes
    if (char === "'") inSingleQuote = true;
    else if (char === '"') inDoubleQuote = true;
    else if (char === '`') inBacktick = true;
    
    result += char;
  }
  
  return result;
}

function isBalanced(str) {
  const clean = cleanCodeString(str);
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBacktick = false;
  let parens = 0;
  let brackets = 0;
  let braces = 0;
  
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    const prev = i > 0 ? clean[i - 1] : '';
    
    if (prev === '\\') continue;
    
    if (inSingleQuote) {
      if (char === "'") inSingleQuote = false;
    } else if (inDoubleQuote) {
      if (char === '"') inDoubleQuote = false;
    } else if (inBacktick) {
      if (char === '`') inBacktick = false;
    } else {
      if (char === "'") inSingleQuote = true;
      else if (char === '"') inDoubleQuote = true;
      else if (char === '`') inBacktick = true;
      else if (char === '(') parens++;
      else if (char === ')') parens--;
      else if (char === '[') brackets++;
      else if (char === ']') brackets--;
      else if (char === '{') braces++;
      else if (char === '}') braces--;
    }
  }
  
  return !inSingleQuote && !inDoubleQuote && !inBacktick && parens <= 0 && brackets <= 0 && braces <= 0;
}

function auditFile(filePath) {
  const violations = [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);
  const ext = path.extname(filePath);
  const skippedLines = new Set();

  for (let idx = 0; idx < lines.length; idx++) {
    if (skippedLines.has(idx)) continue;
    
    const line = lines[idx];
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip inline comment flags
    if (trimmed.includes('security-audit-ignore') || trimmed.startsWith('//') || trimmed.startsWith('*')) {
      continue;
    }

    // 1. Check for Script Injections & Eval Wrappers
    if (trimmed.includes('eval(')) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Vulnerable Method (eval)',
        value: 'eval()',
        suggestion: 'Avoid eval() due to high risk of code injection. Use JSON.parse or standard function calls'
      });
    }

    if (trimmed.includes('new Function(')) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Vulnerable Constructor (new Function)',
        value: 'new Function()',
        suggestion: 'Avoid dynamic function instantiation which mimics eval()'
      });
    }

    // Check for setTimeout or setInterval with string parameters (eval wrappers)
    const timeoutStringMatch = trimmed.match(/set(Timeout|Interval)\s*\(\s*['"`]/);
    if (timeoutStringMatch) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Vulnerable Timer Invocation',
        value: timeoutStringMatch[0],
        suggestion: 'Pass a callback function to setTimeout/setInterval instead of a code string'
      });
    }

    // 2. Check for XSS & Unsafe DOM updates
    // Flags assignments to innerHTML or outerHTML
    const innerHtmlMatch = trimmed.match(/\.(innerHTML|outerHTML)\s*=\s*(.*)/);
    if (innerHtmlMatch) {
      let rightSide = innerHtmlMatch[2];
      let currentIdx = idx;
      
      while (currentIdx < lines.length - 1) {
        let cleanRightSide = cleanCodeString(rightSide).trim();
        const nextLine = lines[currentIdx + 1].trim();
        const nextLineClean = cleanCodeString(nextLine).trim();
        
        const isCurrentlyBalanced = isBalanced(rightSide);
        const endsWithSemicolon = cleanRightSide.endsWith(';');
        const nextLineContinues = nextLineClean.startsWith('.') || nextLineClean.startsWith('+') || nextLineClean.startsWith('?');
        
        if (isCurrentlyBalanced && (endsWithSemicolon || (!nextLineContinues && !cleanRightSide.endsWith('+')))) {
          break;
        }
        
        currentIdx++;
        skippedLines.add(currentIdx);
        rightSide += '\n' + lines[currentIdx];
      }

      if (rightSide.includes('security-audit-ignore')) {
        continue;
      }
      
      // Clean trailing comments and semicolon from rightSide to accurately verify if it is static
      let cleanRightSide = cleanCodeString(rightSide).trim();
      if (cleanRightSide.endsWith(';')) {
        cleanRightSide = cleanRightSide.slice(0, -1).trim();
      }

      // Safe if it is a plain static string without dynamic content (no backticks with dollars, no addition vars, etc.)
      const isStaticString = (cleanRightSide.startsWith("'") && cleanRightSide.endsWith("'") && !cleanRightSide.includes('+')) ||
                             (cleanRightSide.startsWith('"') && cleanRightSide.endsWith('"') && !cleanRightSide.includes('+')) ||
                             (cleanRightSide.startsWith('`') && cleanRightSide.endsWith('`') && !cleanRightSide.includes('$') && !cleanRightSide.includes('+'));
      
      // Check if it passes through an escaping function
      const isEscaped = rightSide.includes('escapeHtml(') || 
                        rightSide.includes('escHtml(') || 
                        rightSide.includes('esc(') || 
                        rightSide.includes('_escapeHtml(') || 
                        rightSide.includes('DOMPurify.sanitize(') || 
                        rightSide.includes('cleanTarget') || 
                        rightSide.includes('encodeURIComponent(') ||
                        // Safe rendering functions
                        rightSide.includes('formatIPGeolocationHtml(') ||
                        rightSide.includes('formatReverseDNSHtml(') ||
                        rightSide.includes('formatWhoisHtml(') ||
                        rightSide.includes('getModalMarkup(') ||
                        rightSide.includes('buildPanelHTML(') ||
                        rightSide.includes('renderFindingCard(') ||
                        rightSide.includes('renderFindingsEmptyState(') ||
                        rightSide.includes('renderScanRow(') ||
                        rightSide.includes('renderTargetRow(') ||
                        rightSide.includes('renderInvitationRow(') ||
                        rightSide.includes('renderProjectCard(') ||
                        rightSide.includes('renderBillingRow(') ||
                        rightSide.includes('formatMessage(') ||
                        rightSide.includes('errMsg(') ||
                        // Original element restoration / safe DOM variables
                        /\b(originalHTML|originalText|origHTML|orig|originalContent|_orig|originalIcon|defaultLabel|originalLabel)\b/.test(rightSide) ||
                        rightSide.includes('dataset.originalContent');
      
      if (!isStaticString && !isEscaped) {
        violations.push({
          line: lineNum,
          snippet: trimmed,
          type: 'Unsafe DOM Modification (Potential XSS)',
          value: innerHtmlMatch[1],
          suggestion: 'Ensure variables are escaped using escapeHtml() or DOMPurify, or use textContent / element.setAttribute instead'
        });
      }
    }

    if (trimmed.includes('document.write(') || trimmed.includes('document.writeln(')) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Vulnerable Method (document.write)',
        value: 'document.write()',
        suggestion: 'Avoid document.write() as it causes security issues and blocks rendering'
      });
    }

    // 3. Check for Insecure Transport (HTTP links)
    let httpMatch;
    INSECURE_HTTP_REGEX.lastIndex = 0;
    while ((httpMatch = INSECURE_HTTP_REGEX.exec(trimmed)) !== null) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Insecure Transport Protocol',
        value: httpMatch[0],
        suggestion: 'Use secure HTTPS instead of unencrypted HTTP'
      });
    }

    // 4. Check for Credential Leakage
    let credMatch;
    CREDENTIAL_LEAK_REGEX.lastIndex = 0;
    while ((credMatch = CREDENTIAL_LEAK_REGEX.exec(trimmed)) !== null) {
      // Allow placeholder keys or example texts
      const keyVal = credMatch[2];
      const skipValues = ['placeholder', 'example', 'your-key', 'mock-token', 'myKey', 'api_key_here', 'default_key'];
      if (!skipValues.some(val => keyVal.toLowerCase().includes(val))) {
        violations.push({
          line: lineNum,
          snippet: trimmed,
          type: 'Hardcoded Credentials / API Token',
          value: `${credMatch[1]} = "${keyVal.substring(0, 4)}..."`,
          suggestion: 'Store credentials in environment variables or configuration files, never hardcode them in frontend script files'
        });
      }
    }

    // 5. Check for Weak Cryptography (XOR cycles in production files)
    if (ext === '.js' && (trimmed.includes('^') || trimmed.includes('charCodeAt')) && (trimmed.includes('cipher') || trimmed.includes('encrypt') || trimmed.includes('xor'))) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Weak Cryptographic Pattern (XOR)',
        value: 'XOR logic ^',
        suggestion: 'Avoid using XOR cipher for security configurations. Use Web Cryptography API (SubtleCrypto) or AES via CryptoJS'
      });
    }
  }

  return violations;
}

function run() {
  console.log('Auditing public/ codebase for security vulnerabilities...');
  let totalIssues = 0;
  let totalFilesScanned = 0;

  walkDir(PUBLIC_DIR, (filePath) => {
    if (shouldIgnorePath(filePath)) return;
    
    const ext = path.extname(filePath);
    if (ext !== '.js' && ext !== '.html') return; // only check script and document pages

    totalFilesScanned++;
    const fileIssues = auditFile(filePath);

    if (fileIssues.length > 0) {
      const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
      console.log(`\n\x1b[31mCRITICAL/WARN\x1b[0m: ${relPath} - ${fileIssues.length} issues found:`);
      
      fileIssues.forEach(v => {
        console.log(`  [Line ${v.line}] \x1b[31m${v.type}\x1b[0m: ${v.value}`);
        console.log(`    Code: ${v.snippet}`);
        console.log(`    Fix:  ${v.suggestion}`);
      });
      
      totalIssues += fileIssues.length;
    }
  });

  console.log('\n----------------------------------------');
  console.log(`Audit complete. Scanned ${totalFilesScanned} files.`);
  if (totalIssues > 0) {
    console.log(`\x1b[31mStatus: FAILED. Found ${totalIssues} security considerations.\x1b[0m`);
    console.log('Resolve the vulnerability risks above to align with secure coding practices.');
    process.exit(1);
  } else {
    console.log('\x1b[32mStatus: SECURE. No critical security violations detected!\x1b[0m');
    process.exit(0);
  }
}

run();
