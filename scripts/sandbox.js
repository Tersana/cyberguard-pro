import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure scratch directory exists
const SCRATCH_DIR = path.resolve(__dirname, '../.agents/scratch');
if (!fs.existsSync(SCRATCH_DIR)) {
  fs.mkdirSync(SCRATCH_DIR, { recursive: true });
}

function showHelp() {
  console.log(`
CyberGuard Monolith Sandbox Tool
--------------------------------
Usage:
  node scripts/sandbox.js extract <file-path> <search-string>
  node scripts/sandbox.js merge <file-path>

Examples:
  node scripts/sandbox.js extract public/js/main.js "const CyberGuardHashTools = {"
  node scripts/sandbox.js merge public/js/main.js
`);
}

function sanitizeFilename(str) {
  return str.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
}

function findClosingBrace(content, startFrom) {
  let braceCount = 0;
  let startIdx = -1;
  let endIdx = -1;
  let insideDoubleQuote = false;
  let insideSingleQuote = false;
  let insideTemplateLiteral = false;
  let insideLineComment = false;
  let insideBlockComment = false;
  let escape = false;

  for (let i = startFrom; i < content.length; i++) {
    const char = content[i];
    const nextChar = content[i + 1] || '';

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
      if (char === '\n') {
        insideLineComment = false;
      }
      continue;
    }
    if (insideBlockComment) {
      if (char === '*' && nextChar === '/') {
        insideBlockComment = false;
        i++; // skip /
      }
      continue;
    }

    // Check for starting comment
    if (char === '/' && nextChar === '/') {
      insideLineComment = true;
      i++;
      continue;
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

    if (char === '"') {
      insideDoubleQuote = true;
      continue;
    }
    if (char === "'") {
      insideSingleQuote = true;
      continue;
    }
    if (char === '`') {
      insideTemplateLiteral = true;
      continue;
    }

    // Handle braces
    if (char === '{') {
      if (startIdx === -1) {
        startIdx = i;
      }
      braceCount++;
    } else if (char === '}') {
      braceCount--;
      if (braceCount === 0 && startIdx !== -1) {
        endIdx = i;
        break;
      }
    }
  }

  return { startIdx, endIdx };
}

function extract(filePath, searchString) {
  const absolutePath = path.resolve(filePath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`Error: File not found at ${filePath}`);
    process.exit(1);
  }

  let content = fs.readFileSync(absolutePath, 'utf8');
  const matchIndex = content.indexOf(searchString);

  if (matchIndex === -1) {
    console.error(`Error: Search string "${searchString}" not found in ${filePath}`);
    process.exit(1);
  }

  // Find block coordinates starting from the search string index
  const { startIdx, endIdx } = findClosingBrace(content, matchIndex);

  if (startIdx === -1 || endIdx === -1) {
    console.error('Error: Could not locate matching curly braces for the target block.');
    process.exit(1);
  }

  // Determine if block ends with a semicolon
  let endPos = endIdx + 1;
  if (content[endPos] === ';') {
    endPos++;
  }

  const blockContent = content.substring(matchIndex, endPos);
  
  // Create scratch file path
  const baseName = path.basename(filePath);
  const sanitizedSearch = sanitizeFilename(searchString);
  const scratchFileName = `sandbox_${baseName}_${sanitizedSearch}.js`;
  const scratchFilePath = path.join(SCRATCH_DIR, scratchFileName);
  const relativeScratchPath = path.relative(process.cwd(), scratchFilePath).replace(/\\/g, '/');

  // Write sandboxed content to scratch file
  fs.writeFileSync(scratchFilePath, blockContent, 'utf8');

  // Replace block in original file with placeholders
  const placeholder = `/* SANDBOX_START:${relativeScratchPath} */\n/* CODE EXTRACED TO SANDBOX FILE - EDIT THERE */\n/* SANDBOX_END */`;
  const newContent = content.substring(0, matchIndex) + placeholder + content.substring(endPos);
  
  fs.writeFileSync(absolutePath, newContent, 'utf8');

  console.log(`\n[SUCCESS] Extracted block successfully!`);
  console.log(`- Source: ${filePath}`);
  console.log(`- Sandbox File: ${relativeScratchPath}`);
  console.log(`- Original file modified with placeholder headers.\n`);
  console.log(`>>> Go ahead and edit ${relativeScratchPath}. When done, run:`);
  console.log(`    npm run sandbox:merge -- ${filePath}\n`);
}

function merge(filePath) {
  const absolutePath = path.resolve(filePath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`Error: File not found at ${filePath}`);
    process.exit(1);
  }

  let content = fs.readFileSync(absolutePath, 'utf8');
  
  // Regex to match our sandbox placeholders
  const regex = /\/\* SANDBOX_START:(.*?) \*\/\r?\n[\s\S]*?\r?\n\/\* SANDBOX_END \*\//g;
  
  let match;
  let modifiedCount = 0;
  let newContent = content;

  // We need to resolve replacements carefully.
  // Because replacements change the index offsets, we can gather all matches first
  // and replace them, or do it iteratively if we use replace with function.
  
  newContent = content.replace(regex, (fullMatch, scratchPath) => {
    const absoluteScratchPath = path.resolve(scratchPath);
    if (!fs.existsSync(absoluteScratchPath)) {
      console.warn(`Warning: Sandbox file not found at ${scratchPath}. Skipping replacement.`);
      return fullMatch;
    }

    const updatedBlock = fs.readFileSync(absoluteScratchPath, 'utf8');
    modifiedCount++;
    
    // Clean up sandbox file after merge
    try {
      fs.unlinkSync(absoluteScratchPath);
      console.log(`- Cleaned up sandbox file: ${scratchPath}`);
    } catch (e) {
      console.warn(`Warning: Could not delete ${scratchPath}:`, e.message);
    }

    return updatedBlock;
  });

  if (modifiedCount === 0) {
    console.log(`No active sandbox sessions found in ${filePath}.`);
    return;
  }

  fs.writeFileSync(absolutePath, newContent, 'utf8');
  console.log(`\n[SUCCESS] Merged ${modifiedCount} sandboxed block(s) back into ${filePath}.\n`);
}

// CLI router
const [,, command, file, arg] = process.argv;

if (command === 'extract' && file && arg) {
  extract(file, arg);
} else if (command === 'merge' && file) {
  merge(file);
} else {
  showHelp();
}
