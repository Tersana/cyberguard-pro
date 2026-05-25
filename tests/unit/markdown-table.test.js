import { describe, it, expect } from 'vitest';

describe('Markdown Table Parser & HTML Whitelist System', () => {
  // Ported formatMessage and highlightCode logic from main.js for testing
  function highlightCode(code, lang) {
    let safe = code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
      
    const keywords = /\b(const|let|var|function|return|import|export|from|class|extends|new|if|else|for|while|await|async|try|catch|finally|nmap|curl|get|post|yes|no|bind|exposed|true|false)\b/gi;
    safe = safe.replace(keywords, '<span class="ai-code-keyword">$1</span>');
    safe = safe.replace(/(["'])(.*?)\1/g, '<span class="ai-code-string">$1$2$1</span>');
    safe = safe.replace(/(\/\/.*|\/\*[\s\S]*?\*\/|#.*)/g, '<span class="ai-code-comment">$1</span>');
    safe = safe.replace(/\b(\d+)\b/g, '<span class="ai-code-number">$1</span>');
    safe = safe.replace(/([=\-+*/%&|^!~<>:?]+)/g, '<span class="ai-code-operator">$1</span>');
    
    return safe;
  }

  function formatMessage(text) {
    // 1. Escape all raw HTML tokens from user to prevent injection/XSS first
    let escaped = text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
      
    let formatted = escaped;
    
    // 2. Process markdown tables
    const tableRegex = /((?:^\s*\|[^\n]*\|\s*(?:\n|$))+)/gm;
    formatted = formatted.replace(tableRegex, (match) => {
      const lines = match.trim().split("\n");
      if (lines.length < 2) return match; // Not a valid table

      const parseRow = (rowStr) => {
        const clean = rowStr.trim().replace(/^\||\|$/g, "");
        return clean.split("|").map(s => s.trim());
      };

      const headers = parseRow(lines[0]);
      
      // Check if second line is a separator line
      const hasSeparator = /^[\s|:-]+$/.test(lines[1].trim());
      const startIndex = hasSeparator ? 2 : 1;
      
      let html = '<div class="cyber-table-container"><table class="cyber-markdown-table">';
      
      // Header
      html += '<thead><tr>';
      headers.forEach(h => {
        html += `<th>${h}</th>`;
      });
      html += '</tr></thead><tbody>';
      
      // Body
      for (let i = startIndex; i < lines.length; i++) {
        const cells = parseRow(lines[i]);
        html += '<tr>';
        for (let j = 0; j < headers.length; j++) {
          const val = cells[j] || "";
          html += `<td>${val}</td>`;
        }
        html += '</tr>';
      }
      
      html += '</tbody></table></div>';
      return `\n${html}\n`;
    });

    // 3. Process markdown code blocks
    const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/g;
    formatted = formatted.replace(codeBlockRegex, (match, lang, code) => {
      const displayLang = lang || "CODE";
      // Unescape HTML tokens inside the code block for highlighting
      const unescapedCode = code
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&");
      const highlighted = highlightCode(unescapedCode.trim(), lang);
      const escapedRawCode = btoa(unescape(encodeURIComponent(unescapedCode.trim())));
      
      return `
        <div class="ai-code-block">
          <div class="ai-code-header">
            <span>${displayLang}</span>
            <button class="ai-code-copy" onclick="window.CyberGuardAIChat.copyCode('${escapedRawCode}', this)">
              <span class="material-symbols-outlined text-[12px]">content_copy</span>
              Copy
            </button>
          </div>
          <pre class="ai-code-pre"><code>${highlighted}</code></pre>
        </div>
      `;
    });
    
    // 4. Casing bold and italics
    let safe = formatted;
    safe = safe.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    safe = safe.replace(/\*(.+?)\*/g, "<em>$1</em>");
    safe = safe.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    
    const lines = safe.split("\n");
    let inList = false;
    const out = [];
    for (let line of lines) {
      if (/^\s*[-•]\s/.test(line)) {
        if (!inList) {
          out.push('<ul class="list-disc pl-5 my-1.5">');
          inList = true;
        }
        out.push(`<li>${line.replace(/^\s*[-•]\s/, "")}</li>`);
      } else {
        if (inList) {
          out.push("</ul>");
          inList = false;
        }
        if (line.trim() === "") {
          out.push("<br>");
        } else {
          // Keep HTML elements intact
          const trimmed = line.trim();
          if (trimmed.startsWith("<div") || trimmed.startsWith("</div") || trimmed.startsWith("<table") || trimmed.startsWith("</table") || trimmed.startsWith("<button") || trimmed.startsWith("</button") || trimmed.startsWith("<h4") || trimmed.startsWith("<pre") || trimmed.startsWith("<svg") || trimmed.startsWith("</svg") || trimmed.startsWith("<span") || trimmed.startsWith("</span")) {
            out.push(line);
          } else {
            out.push(`<p class="mb-1.5">${line}</p>`);
          }
        }
      }
    }
    if (inList) out.push("</ul>");
    
    return out.join("");
  }

  it('should parse standard markdown tables successfully without escaping HTML', () => {
    const rawTable = `
| Tab | What You Can Do |
|-----|------------------|
| **Network Analysis** | Perform real-time DNS scanning |
| **Web Security** | Run Phishing URL Analyzer |
`;
    const formatted = formatMessage(rawTable);
    
    // Expect generated table structure
    expect(formatted).toContain('<div class="cyber-table-container">');
    expect(formatted).toContain('<table class="cyber-markdown-table">');
    expect(formatted).toContain('<th>Tab</th>');
    expect(formatted).toContain('<th>What You Can Do</th>');
    expect(formatted).toContain('<td><strong>Network Analysis</strong></td>');
    expect(formatted).toContain('<td>Perform real-time DNS scanning</td>');
    expect(formatted).toContain('<td><strong>Web Security</strong></td>');
    expect(formatted).toContain('<td>Run Phishing URL Analyzer</td>');
    
    // Make sure HTML tags are NOT escaped in the final output
    expect(formatted).not.toContain('&lt;table');
    expect(formatted).not.toContain('&lt;div class="cyber-table-container"');
    expect(formatted).not.toContain('&lt;thead&gt;');
  });

  it('should handle tables without explicit separators gracefully', () => {
    const rawTable = `
| Column A | Column B |
| Value A | Value B |
`;
    const formatted = formatMessage(rawTable);
    expect(formatted).toContain('<th>Column A</th>');
    expect(formatted).toContain('<td>Value A</td>');
  });

  it('should format normal paragraph elements alongside tables correctly', () => {
    const inputText = `
Here is a list of features:

| Feature | Active |
|---|---|
| Autopilot | Yes |

Make sure to utilize these tools carefully.
`;
    const formatted = formatMessage(inputText);
    
    expect(formatted).toContain('<p class="mb-1.5">Here is a list of features:</p>');
    expect(formatted).toContain('<div class="cyber-table-container">');
    expect(formatted).toContain('<p class="mb-1.5">Make sure to utilize these tools carefully.</p>');
  });
});
