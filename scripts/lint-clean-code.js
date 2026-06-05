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

// Check filename conventions (lowercase with hyphens, e.g., api-client.js)
function checkFilename(filePath) {
  const baseName = path.basename(filePath);
  const ext = path.extname(filePath);
  const nameWithoutExt = path.basename(filePath, ext);

  // Exclude files like index.html or package.json
  if (nameWithoutExt === 'index' || nameWithoutExt === 'landing' || nameWithoutExt === 'Style') return null;

  // Regex matches lowercase letters, digits, and hyphens
  const isValid = /^[a-z0-9-]+$/.test(nameWithoutExt);
  if (!isValid) {
    return {
      type: 'Filename Convention',
      value: baseName,
      suggestion: 'Rename file using lowercase letters and hyphens (e.g. user-profile.js)'
    };
  }
  return null;
}

// Check DOM IDs in HTML (kebab-case, e.g., id="pane-api-keys")
function lintHtmlDomIds(filePath) {
  const violations = [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    if (line.includes('clean-code-ignore')) return;

    // Match id="someValue" or id='someValue'
    const idRegex = /\bid\s*=\s*["']([^"']+)["']/gi;
    let match;
    while ((match = idRegex.exec(line)) !== null) {
      const idVal = match[1];
      // Skip template engine placeholders or simple dynamic lookups if they contain brackets or dollars
      if (idVal.includes('{') || idVal.includes('}') || idVal.includes('$')) continue;

      const isValidKebab = /^[a-z0-9-]+$/.test(idVal);
      if (!isValidKebab) {
        violations.push({
          line: lineNum,
          snippet: line.trim(),
          type: 'DOM ID Casing',
          value: `id="${idVal}"`,
          suggestion: 'Change ID to kebab-case (e.g., id="submit-button")'
        });
      }
    }
  });

  return violations;
}

function parseBlockLengthsAndCasing(filePath) {
  const violations = [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  let insideDoubleQuote = false;
  let insideSingleQuote = false;
  let insideTemplateLiteral = false;
  let insideLineComment = false;
  let insideBlockComment = false;
  let escape = false;

  let braceCount = 0;
  let currentFunction = null;
  let functionStartLine = -1;

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    if (trimmed.includes('clean-code-ignore')) return;

    // Check for raw console.logs (clutters codebase)
    if (trimmed.includes('console.log(') && !trimmed.startsWith('//') && !trimmed.startsWith('*')) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Leftover Debug Logger',
        value: 'console.log()',
        suggestion: 'Remove debug console.log or replace with window.showToast or error-handler alert'
      });
    }

    // Inspect JS casing declarations (Class names, Function names, Constant names)
    // We only inspect if we are not inside comments or strings
    if (!insideBlockComment && !insideLineComment) {
      // 1. Class PascalCase Check
      const classMatch = trimmed.match(/^class\s+(\w+)/);
      if (classMatch) {
        const className = classMatch[1];
        if (!/^[A-Z][a-zA-Z0-9]*$/.test(className)) {
          violations.push({
            line: lineNum,
            snippet: trimmed,
            type: 'Class Casing',
            value: className,
            suggestion: 'Use PascalCase for class names (e.g., class ProjectManager)'
          });
        }
      }

      // 2. Function camelCase Check (e.g. function mapStatusToSeverity)
      // Capture both function declarations and object methods
      const funcMatch = trimmed.match(/^(?:function\s+(\w+)\(|(\w+)\s*\([^)]*\)\s*\{)/);
      if (funcMatch) {
        const funcName = funcMatch[1] || funcMatch[2];
        // Skip reserved or lifecycle methods
        const reserved = ['init', 'connect', 'save', 'delete', 'show', 'hide', 'get', 'post', 'put', 'open', 'close'];
        if (funcName && !reserved.includes(funcName) && !/^[a-z][a-zA-Z0-9]*$/.test(funcName)) {
          // Allow PascalCase constructors or IIFE
          if (!/^[A-Z]/.test(funcName)) {
            violations.push({
              line: lineNum,
              snippet: trimmed,
              type: 'Function Casing',
              value: funcName,
              suggestion: 'Use camelCase for function names (e.g., mapStatusToSeverity)'
            });
          }
        }
      }
      
      // 3. Constants UPPER_SNAKE_CASE Check
      // Matches const NGROK_URL = ...
      const constMatch = trimmed.match(/^const\s+([a-zA-Z0-9_]+)\s*=\s*(['"`0-9]|true|false|\[|\{)/);
      if (constMatch) {
        const constName = constMatch[1];
        // If it starts with an uppercase letter, it should be UPPER_SNAKE_CASE
        if (/^[A-Z]/.test(constName) && !/^[A-Z0-9_]+$/.test(constName)) {
          violations.push({
            line: lineNum,
            snippet: trimmed,
            type: 'Constant Casing',
            value: constName,
            suggestion: 'Use UPPER_SNAKE_CASE for constant declarations (e.g., const NGROK_HEADER)'
          });
        }
      }
    }

    // Dynamic brace counting to track function sizes and block nesting depth
    let lineBraceCount = 0;
    
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      const nextChar = line[i + 1] || '';

      if (escape) {
        escape = false;
        continue;
      }
      if (char === '\\') {
        escape = true;
        continue;
      }

      // Handle comments
      if (insideLineComment) {
        break; // skip rest of line
      }
      if (insideBlockComment) {
        if (char === '*' && nextChar === '/') {
          insideBlockComment = false;
          i++;
        }
        continue;
      }

      if (char === '/' && nextChar === '/') {
        insideLineComment = true;
        break;
      }
      if (char === '/' && nextChar === '*') {
        insideBlockComment = true;
        i++;
        continue;
      }

      // Handle strings
      if (insideDoubleQuote) {
        if (char === '"') insideDoubleQuote = false;
        continue;
      }
      if (insideSingleQuote) {
        if (char === "'") insideSingleQuote = false;
        continue;
      }
      if (insideTemplateLiteral) {
        if (char === '`') insideTemplateLiteral = false;
        continue;
      }

      if (char === '"') { insideDoubleQuote = true; continue; }
      if (char === "'") { insideSingleQuote = true; continue; }
      if (char === '`') { insideTemplateLiteral = true; continue; }

      // count braces
      if (char === '{') {
        braceCount++;
        lineBraceCount++;
        // If function starts
        if (trimmed.includes('function') || trimmed.includes(') {') || trimmed.endsWith('{')) {
          if (currentFunction === null) {
            currentFunction = trimmed.substring(0, 40);
            functionStartLine = lineNum;
          }
        }
      } else if (char === '}') {
        braceCount--;
        lineBraceCount--;
        if (braceCount === 0 && currentFunction !== null) {
          const linesSpent = lineNum - functionStartLine + 1;
          if (linesSpent > 150) {
            violations.push({
              line: functionStartLine,
              snippet: currentFunction,
              type: 'Function Complexity',
              value: `Function body takes ${linesSpent} lines`,
              suggestion: 'Break down into smaller helper functions or classes (< 150 lines)'
            });
          }
          currentFunction = null;
          functionStartLine = -1;
        }
      }
    }

    // Nesting depth warning
    // If braceCount is > 4 inside a function block, it usually indicates deeply nested conditions
    if (braceCount > 4 && lineBraceCount > 0 && (trimmed.startsWith('if') || trimmed.startsWith('for') || trimmed.startsWith('while') || trimmed.startsWith('switch'))) {
      violations.push({
        line: lineNum,
        snippet: trimmed,
        type: 'Deep Nesting Level',
        value: `Nesting depth is ${braceCount}`,
        suggestion: 'Reduce nesting levels by using early return statements or splitting logic'
      });
    }

    insideLineComment = false; // resets at newline
  });

  return violations;
}

function run() {
  console.log('Scanning public/ directory for Clean Code compliance...');
  let totalViolations = 0;
  let totalFilesScanned = 0;

  walkDir(PUBLIC_DIR, (filePath) => {
    if (shouldIgnorePath(filePath)) return;
    
    totalFilesScanned++;
    const fileViolations = [];

    // Check filename
    const filenameViolation = checkFilename(filePath);
    if (filenameViolation) {
      fileViolations.push({
        line: 0,
        snippet: path.basename(filePath),
        ...filenameViolation
      });
    }

    const ext = path.extname(filePath);
    if (ext === '.css') {
      // styles checked by theme tokens, skip clean code JS check
    } else if (ext === '.html') {
      fileViolations.push(...lintHtmlDomIds(filePath));
    } else if (ext === '.js') {
      fileViolations.push(...parseBlockLengthsAndCasing(filePath));
    }

    if (fileViolations.length > 0) {
      const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
      console.log(`\n\x1b[33mWARN\x1b[0m: ${relPath} - ${fileViolations.length} issues found:`);
      
      fileViolations.forEach(v => {
        const lineStr = v.line > 0 ? `Line ${v.line}` : 'File';
        console.log(`  [${lineStr}] \x1b[31m${v.type}\x1b[0m: ${v.value}`);
        console.log(`    Code: ${v.snippet}`);
        console.log(`    Fix:  ${v.suggestion}`);
      });
      
      totalViolations += fileViolations.length;
    }
  });

  console.log('\n----------------------------------------');
  console.log(`Scan complete. Scanned ${totalFilesScanned} files.`);
  if (totalViolations > 0) {
    console.log(`\x1b[33mStatus: PASSED WITH WARNINGS. Found ${totalViolations} Clean Code suggestions.\x1b[0m`);
    console.log('Refactor these elements to maintain optimal clean code structure.');
  } else {
    console.log('\x1b[32mStatus: PASSED. All code meets clean conventions!\x1b[0m');
  }
}

run();
