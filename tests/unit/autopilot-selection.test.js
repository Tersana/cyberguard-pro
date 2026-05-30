import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Autopilot Selection Actions & Offline Parsing', () => {
  let dom;
  let document;
  let SelectionManagerMock;
  let SelectAllToggleMock;

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div class="tab-pane active" id="network-tools">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="port-scan-btn">
              <div class="selection-indicator hidden"></div>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="whois-btn">
              <div class="selection-indicator"></div>
            </div>
            <div class="cyber-tool-card" data-selected="false" data-tool-id="tcp-scan-btn">
              <div class="selection-indicator hidden"></div>
            </div>
          </div>
          <div class="tab-pane" id="web-security">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="xss-btn">
              <div class="selection-indicator hidden"></div>
            </div>
            <div class="cyber-tool-card" data-selected="false" data-tool-id="ssl-btn">
              <div class="selection-indicator hidden"></div>
            </div>
          </div>
          <span id="selection-count-display"></span>
          <span id="selection-count-display-web"></span>
        </body>
      </html>
    `);
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Define mock global variables to avoid undefined errors
    SelectionManagerMock = {
      updateVisuals: vi.fn((card) => {
        const indicator = card.querySelector('.selection-indicator');
        if (card.dataset.selected === 'true') {
          indicator?.classList.remove('hidden');
        } else {
          indicator?.classList.add('hidden');
        }
      }),
      saveToLocalStorage: vi.fn(),
      updateSelectionCount: vi.fn()
    };
    global.SelectionManager = SelectionManagerMock;

    SelectAllToggleMock = {
      updateButtonLabel: vi.fn()
    };
    global.SelectAllToggle = SelectAllToggleMock;
  });

  // Helper to simulate executeAutopilotAction
  function executeAutopilotAction(actionName, argsStr) {
    const args = argsStr.split(",").map(arg => {
      let s = arg.trim();
      if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
        s = s.slice(1, -1);
      }
      return s;
    });

    switch (actionName) {
      case "select_tool": {
        const toolId = args[0];
        const isSelected = args[1] === "true" || args[1] === true || args[1] === "1";
        const card = document.querySelector(`.cyber-tool-card[data-tool-id="${toolId}"]`);
        if (card) {
          card.dataset.selected = isSelected.toString();
          if (typeof SelectionManager !== "undefined") {
            SelectionManager.updateVisuals(card);
            SelectionManager.saveToLocalStorage();
            SelectionManager.updateSelectionCount();
          }
          if (typeof SelectAllToggle !== "undefined" && typeof SelectAllToggle.updateButtonLabel === "function") {
            SelectAllToggle.updateButtonLabel();
          }
        }
        break;
      }
      case "select_only_tool": {
        const toolId = args[0];
        const card = document.querySelector(`.cyber-tool-card[data-tool-id="${toolId}"]`);
        if (card) {
          const tabPane = card.closest(".tab-pane");
          if (tabPane) {
            const toolCards = tabPane.querySelectorAll(".cyber-tool-card");
            toolCards.forEach(c => {
              c.dataset.selected = "false";
              if (typeof SelectionManager !== "undefined") {
                SelectionManager.updateVisuals(c);
              }
            });
          }
          card.dataset.selected = "true";
          if (typeof SelectionManager !== "undefined") {
            SelectionManager.updateVisuals(card);
            SelectionManager.saveToLocalStorage();
            SelectionManager.updateSelectionCount();
          }
          if (typeof SelectAllToggle !== "undefined" && typeof SelectAllToggle.updateButtonLabel === "function") {
            SelectAllToggle.updateButtonLabel();
          }
        }
        break;
      }
    }
  }

  // Helper to simulate processOfflineMessage scan/run logic
  function processOfflineMessage(query) {
    const q = query.toLowerCase();
    let target = null;
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/;
    const ipMatch = q.match(ipRegex);
    const domainMatch = q.match(domainRegex);
    const localhostMatch = q.match(/\blocalhost\b/);

    if (ipMatch) {
      target = ipMatch[0];
    } else if (domainMatch) {
      target = domainMatch[0];
    } else if (localhostMatch) {
      target = "localhost";
    } else {
      const legacyMatch = /\b(scan|run|analyze|test)\s+(\S+)\b/.exec(q);
      if (legacyMatch) {
        target = legacyMatch[2].replace(/["']/g, "");
      }
    }

    if (target && /\b(scan|run|analyze|test|trigger)\b/.test(q)) {
      let targetTool = null;
      let tabId = "network-tools";
      let scanType = "network";

      if (q.includes("xss")) {
        return "XSS vulnerability scanning has been removed from Web Auditing. However, I can perform other web auditing scans like SSL, Phishing, or DNS Spoofing analysis for you.";
      } else if (q.includes("ssl") || q.includes("tls")) {
        targetTool = "ssl-btn";
        tabId = "web-security";
        scanType = "web";
      } else if (q.includes("phish")) {
        targetTool = "phishing-btn";
        tabId = "web-security";
        scanType = "web";
      } else if (q.includes("spoof")) {
        targetTool = "dns-spoof-btn";
        tabId = "web-security";
        scanType = "web";
      } else if (q.includes("whois")) {
        targetTool = "whois-btn";
        tabId = "network-tools";
        scanType = "network";
      } else if (q.includes("geo") || q.includes("location")) {
        targetTool = "ip-geo-btn";
        tabId = "network-tools";
        scanType = "network";
      } else if (q.includes("dns") || q.includes("reverse")) {
        targetTool = "reverse-dns-btn";
        tabId = "network-tools";
        scanType = "network";
      } else if (q.includes("tcp")) {
        targetTool = "tcp-scan-btn";
        tabId = "network-tools";
        scanType = "network";
      } else if (q.includes("udp")) {
        targetTool = "udp-scan-btn";
        tabId = "network-tools";
        scanType = "network";
      } else if (q.includes("threat") || q.includes("intel") || q.includes("virus") || q.includes("vt") || q.includes("abuse")) {
        targetTool = "threat-intel-btn";
        tabId = "network-tools";
        scanType = "network";
      } else if (q.includes("port")) {
        targetTool = "port-scan-btn";
        tabId = "network-tools";
        scanType = "network";
      } else {
        if (target.includes("://") || target.includes("www.") || (isNaN(target.split(".")[0]) && target.includes("."))) {
          tabId = "web-security";
          scanType = "web";
        } else {
          tabId = "network-tools";
          scanType = "network";
        }
      }

      if (targetTool) {
        return `I will switch to the ${scanType === "web" ? "Web Security" : "Network Scanner"} tab, select only the requested tool, and analyze ${target} for you. [[ACTION: switch_tab("${tabId}")]] [[ACTION: select_only_tool("${targetTool}")]] [[ACTION: run_scan("${scanType}", "${target}")]]`;
      } else {
        return `I will execute a ${scanType === "web" ? "Web Security" : "Network Port"} scan on the target ${target} now. [[ACTION: switch_tab("${tabId}")]] [[ACTION: run_scan("${scanType}", "${target}")]]`;
      }
    }
    return "";
  }

  describe('executeAutopilotAction', () => {
    it('should select a tool card with select_tool', () => {
      const portCard = document.querySelector('[data-tool-id="port-scan-btn"]');
      expect(portCard.dataset.selected).toBe('false');

      executeAutopilotAction('select_tool', '"port-scan-btn", "true"');

      expect(portCard.dataset.selected).toBe('true');
      expect(SelectionManagerMock.updateVisuals).toHaveBeenCalled();
      expect(SelectionManagerMock.saveToLocalStorage).toHaveBeenCalled();
      expect(SelectionManagerMock.updateSelectionCount).toHaveBeenCalled();
      expect(SelectAllToggleMock.updateButtonLabel).toHaveBeenCalled();
    });

    it('should deselect a tool card with select_tool', () => {
      const whoisCard = document.querySelector('[data-tool-id="whois-btn"]');
      expect(whoisCard.dataset.selected).toBe('true');

      executeAutopilotAction('select_tool', '"whois-btn", "false"');

      expect(whoisCard.dataset.selected).toBe('false');
      expect(SelectionManagerMock.updateVisuals).toHaveBeenCalled();
    });

    it('should select ONLY the target card and deselect all others with select_only_tool', () => {
      const tcpCard = document.querySelector('[data-tool-id="tcp-scan-btn"]');
      const whoisCard = document.querySelector('[data-tool-id="whois-btn"]');

      expect(whoisCard.dataset.selected).toBe('true');
      expect(tcpCard.dataset.selected).toBe('false');

      executeAutopilotAction('select_only_tool', '"tcp-scan-btn"');

      expect(tcpCard.dataset.selected).toBe('true');
      expect(whoisCard.dataset.selected).toBe('false');
      expect(SelectionManagerMock.updateVisuals).toHaveBeenCalled();
      expect(SelectionManagerMock.saveToLocalStorage).toHaveBeenCalled();
      expect(SelectionManagerMock.updateSelectionCount).toHaveBeenCalled();
      expect(SelectAllToggleMock.updateButtonLabel).toHaveBeenCalled();
    });
  });

  describe('processOfflineMessage parsing', () => {
    it('should extract target and tool keywords to output action sequences', () => {
      const result = processOfflineMessage('run whois scan on 8.8.8.8');
      expect(result).toContain('[[ACTION: switch_tab("network-tools")]]');
      expect(result).toContain('[[ACTION: select_only_tool("whois-btn")]]');
      expect(result).toContain('[[ACTION: run_scan("network", "8.8.8.8")]]');
    });

    it('should support web target and tool parsing', () => {
      const result = processOfflineMessage('test ssl on google.com');
      expect(result).toContain('[[ACTION: switch_tab("web-security")]]');
      expect(result).toContain('[[ACTION: select_only_tool("ssl-btn")]]');
      expect(result).toContain('[[ACTION: run_scan("web", "google.com")]]');
    });

    it('should fallback to default scan if no tool is mentioned', () => {
      const result = processOfflineMessage('scan 192.168.1.10');
      expect(result).toContain('[[ACTION: switch_tab("network-tools")]]');
      expect(result).not.toContain('select_only_tool');
      expect(result).toContain('[[ACTION: run_scan("network", "192.168.1.10")]]');
    });
  });
});
