import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PUBLIC_DIR = path.resolve(__dirname, '../public');

// Exclude vendor libraries or theme files
const EXCLUDE_FILES = [
  'theme-tokens.css',
  'pusher.min.js',
  'echo.iife.js'
];

const EXCLUDE_DIRS = [
  'lib',
  'node_modules'
];

// Hex color regex (matches 3, 4, 6, or 8 char hex values)
const HEX_COLOR_REGEX = /#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/g;
// functional color regex (rgb, rgba, hsl, hsla)
const FUNC_COLOR_REGEX = /\b(rgb|rgba|hsl|hsla)\(.*?\)/g;
// raw px values in css properties that could use space/radius tokens
const RAW_PX_REGEX = /\b([0-9]+)px\b/g;

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

function lintCssFile(filePath) {
  const violations = [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;

    // Skip comments or lines explicitly marked to ignore
    if (line.includes('cg-ignore') || line.trim().startsWith('/*') || line.trim().startsWith('*')) {
      return;
    }

    // Check if line contains a CSS property declaration
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) return;

    // Only inspect the value part (after the first colon)
    const valuePart = line.substring(colonIdx + 1);

    // Look for hardcoded hex colors
    let match;
    HEX_COLOR_REGEX.lastIndex = 0;
    while ((match = HEX_COLOR_REGEX.exec(valuePart)) !== null) {
      violations.push({
        line: lineNum,
        snippet: line.trim(),
        type: 'Hardcoded Hex Color',
        value: match[0],
        suggestion: 'Replace with var(--cg-*) token'
      });
    }

    // Look for functional colors
    FUNC_COLOR_REGEX.lastIndex = 0;
    while ((match = FUNC_COLOR_REGEX.exec(valuePart)) !== null) {
      // Allow if it contains var(--cg-
      if (!match[0].includes('var(--cg-')) {
        violations.push({
          line: lineNum,
          snippet: line.trim(),
          type: 'Hardcoded RGB/HSL Color',
          value: match[0],
          suggestion: 'Replace with var(--cg-*) token'
        });
      }
    }
    
    // Look for raw px sizes (only flag if they are > 4px to avoid small border/pixel adjustments)
    RAW_PX_REGEX.lastIndex = 0;
    while ((match = RAW_PX_REGEX.exec(valuePart)) !== null) {
      const pixels = parseInt(match[1], 10);
      if (pixels > 4) {
        // Exclude box-shadow sizes, gradients, or border widths if <= 2px (often raw styling)
        // Check property name
        const propName = line.substring(0, colonIdx).trim().toLowerCase();
        const skipProps = ['box-shadow', 'text-shadow', 'border-width', 'stroke-width'];
        if (!skipProps.includes(propName)) {
          violations.push({
            line: lineNum,
            snippet: line.trim(),
            type: 'Hardcoded Pixel Value',
            value: `${pixels}px`,
            suggestion: 'Use --cg-space-* or --cg-radius-* tokens instead'
          });
        }
      }
    }
  });

  return violations;
}

function lintHtmlFile(filePath) {
  const violations = [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  // Look for inline styles
  lines.forEach((line, idx) => {
    const lineNum = idx + 1;

    if (line.includes('cg-ignore')) return;

    // Match style="..." attributes
    const styleAttrRegex = /style\s*=\s*["']([\s\S]*?)["']/gi;
    let styleMatch;
    
    while ((styleMatch = styleAttrRegex.exec(line)) !== null) {
      const styleContent = styleMatch[1];

      // Check style content for hex colors
      let colorMatch = styleContent.match(/#([0-9a-fA-F]{3,8})\b/g);
      if (colorMatch) {
        colorMatch.forEach(color => {
          violations.push({
            line: lineNum,
            snippet: line.trim(),
            type: 'Inline Style Hex Color',
            value: color,
            suggestion: 'Use CSS class or Tailwind color utility class matching theme-tokens'
          });
        });
      }

      // Check style content for rgb/hsl functions
      let funcMatch = styleContent.match(/\b(rgb|rgba|hsl|hsla)\(.*?\)/g);
      if (funcMatch) {
        funcMatch.forEach(func => {
          if (!func.includes('var(--cg-')) {
            violations.push({
              line: lineNum,
              snippet: line.trim(),
              type: 'Inline Style RGB/HSL Color',
              value: func,
              suggestion: 'Use Tailwind class or var(--cg-*) custom property'
            });
          }
        });
      }
      
      // Check style content for raw px layouts
      let pxMatch = styleContent.match(/\b([0-9]+)px\b/g);
      if (pxMatch) {
        pxMatch.forEach(px => {
          const val = parseInt(px, 10);
          if (val > 4) {
            violations.push({
              line: lineNum,
              snippet: line.trim(),
              type: 'Inline Style Pixel Spacing',
              value: px,
              suggestion: 'Use Tailwind margin/padding utilities (e.g., p-4, m-2)'
            });
          }
        });
      }
    }
  });

  return violations;
}

function run() {
  console.log('Scanning public/ directory for design token compliance...');
  let totalViolations = 0;
  let totalFilesScanned = 0;

  walkDir(PUBLIC_DIR, (filePath) => {
    if (shouldIgnorePath(filePath)) return;
    
    const ext = path.extname(filePath);
    let fileViolations = [];

    if (ext === '.css') {
      totalFilesScanned++;
      fileViolations = lintCssFile(filePath);
    } else if (ext === '.html') {
      totalFilesScanned++;
      fileViolations = lintHtmlFile(filePath);
    }

    if (fileViolations.length > 0) {
      const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
      console.log(`\n\x1b[33mWARN\x1b[0m: ${relPath} - ${fileViolations.length} issues found:`);
      
      fileViolations.forEach(v => {
        console.log(`  [Line ${v.line}] \x1b[31m${v.type}\x1b[0m: ${v.value}`);
        console.log(`    Code: ${v.snippet}`);
        console.log(`    Fix:  ${v.suggestion}`);
      });
      
      totalViolations += fileViolations.length;
    }
  });

  console.log('\n----------------------------------------');
  console.log(`Scan complete. Scanned ${totalFilesScanned} CSS/HTML files.`);
  if (totalViolations > 0) {
    console.log(`\x1b[31mStatus: FAILED. Found ${totalViolations} design system violations.\x1b[0m`);
    console.log('Fix the issues above or add "/* cg-ignore */" to bypass verification checks.');
    process.exit(1);
  } else {
    console.log('\x1b[32mStatus: PASSED. All files conform to the design system tokens!\x1b[0m');
    process.exit(0);
  }
}

run();
