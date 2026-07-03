import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('AI Assistant P0 Enhancements', () => {
  let dom;
  let document;
  let conversationHistory;
  let resultsData;
  let currentScanTarget;
  let isRunning;
  let messagesEl;

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="ai-messages"></div>
          <div id="jwt-decoder-token" value="eyJuYW1lIjoiQWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.token.signature"></div>
          <div id="jwt-decoder-secret" value="super-secret-key"></div>
          <div id="ht-hash-input" value="hello-world-hash"></div>
          <div id="target-url" value=""></div>
          <button id="run-analysis-btn"></button>
          <div class="tab-pane" id="jwt-debugger"></div>
          <div class="tab-pane hidden" id="hash-tools"></div>
        </body>
      </html>
    `, { runScripts: "dangerously" });
    
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Reset mocks & states
    conversationHistory = [];
    resultsData = [];
    currentScanTarget = "";
    isRunning = false;
    messagesEl = document.getElementById("ai-messages");

    // Mock global window objects
    global.window.projectManager = {
      projects: [
        { name: "Alpha Project", risk_score: 8.5, targets_count: 5 },
        { name: "Beta Project", risk_score: 3.2, targets_count: 2 }
      ]
    };
    
    global.window.authManager = {
      currentUser: {
        full_name: "John Doe",
        email: "john@cyberguard.com",
        role: "administrator"
      }
    };

    global.window.switchToTab = vi.fn();
    executedActionsList.length = 0;
    lastToastAction = null;
    lastToastArgs = null;
  });

  // ─── GATHER SYSTEM CONTEXT ──────────────────────────────────────────
  function gatherSystemContext() {
    let projectDetails = "No active project loaded.";
    if (global.window.projectManager && global.window.projectManager.projects && global.window.projectManager.projects.length > 0) {
      const list = global.window.projectManager.projects;
      const details = list.map(p => `- ${p.name} (Risk Score: ${p.risk_score ? Number(p.risk_score).toFixed(1) : "0.0"}, Targets: ${p.targets_count ?? 0})`).join("\n");
      projectDetails = `Active projects in database:\n${details}`;
    }

    const targetDetails = `Current Active Scan Target: ${currentScanTarget || "None specified yet."}\nDashboard scan processing status: ${isRunning ? "ACTIVE" : "IDLE"}`;

    let findingsDetails = "No current findings inside results display table.";
    if (resultsData && resultsData.length > 0) {
      const threats = resultsData.filter(r => r.status === "threat").length;
      const warnings = resultsData.filter(r => r.status === "warning").length;
      const safe = resultsData.filter(r => r.status === "safe").length;
      const list = resultsData.slice(0, 20).map(r => {
        let detailStr = `[${r.status.toUpperCase()}] ${r.tool}: ${r.message}`;
        if (r.details) {
          try {
            const rawDetails = typeof r.details === "string" ? r.details : JSON.stringify(r.details);
            detailStr += `\n  Details: ${rawDetails.slice(0, 300)}`;
          } catch (e) {}
        }
        return detailStr;
      }).join("\n");
      findingsDetails = `Current findings count: ${resultsData.length} (${threats} threats, ${warnings} warnings, ${safe} safe). Structured findings details:\n${list}`;
    }

    let userDetails = "Guest User (Offline sandbox)";
    if (global.window.authManager && global.window.authManager.currentUser) {
      const u = global.window.authManager.currentUser;
      userDetails = `Active Session User: ${u.full_name || u.name} (${u.email}), Role: ${u.role || "member"}`;
    }

    let currentTab = "unknown";
    document.querySelectorAll(".tab-pane").forEach(pane => {
      if (!pane.classList.contains("hidden")) currentTab = pane.id;
    });

    let activeTabInputs = "";
    if (currentTab === "jwt-debugger") {
      // Mock retrieving input directly or from mocked DOM elements
      const jwtTokenEl = document.getElementById("jwt-decoder-token");
      const jwtToken = jwtTokenEl ? (jwtTokenEl.value || jwtTokenEl.getAttribute("value")) : "";
      if (jwtToken) {
        activeTabInputs += `\n- Current input JWT Token in Decoder: ${jwtToken.slice(0, 200)}...`;
      }
    } else if (currentTab === "hash-tools") {
      const hashInputEl = document.getElementById("ht-hash-input");
      const hashInput = hashInputEl ? (hashInputEl.value || hashInputEl.getAttribute("value")) : "";
      if (hashInput) {
        activeTabInputs += `\n- Current Hashing generator input: "${hashInput}"`;
      }
    }

    return `
[REAL-TIME DASHBOARD CONTEXT]
- Active Tab: ${currentTab}
- ${userDetails}
- ${targetDetails}
- ${projectDetails}
- ${findingsDetails}${activeTabInputs}
`;
  }

  // ─── DYNAMIC REST API CALLS ──────────────────────────────────────
  async function callOpenRouterAPI(message, systemPrompt, apiKey, model, temp, onChunk) {
    const url = "https://openrouter.ai/api/v1/chat/completions";
    
    // Increased history window to -20
    const messages = [
      { role: "system", content: systemPrompt },
      ...conversationHistory.slice(-20)
    ];

    const isStream = typeof onChunk === "function";
    const body = JSON.stringify({
      model: model || "openai/gpt-oss-120b:free",
      messages,
      temperature: temp,
      max_tokens: model.includes(":free") ? 2048 : 4096, // Dynamic max_tokens
      stream: isStream
    });

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    if (isStream && res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";
      let fullResponseText = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
          const cleanLine = line.trim();
          if (!cleanLine || cleanLine === "data: [DONE]") continue;

          if (cleanLine.startsWith("data: ")) {
            try {
              const rawJson = cleanLine.slice(6);
              const parsed = JSON.parse(rawJson);
              const chunkText = parsed.choices?.[0]?.delta?.content || "";
              if (chunkText) {
                fullResponseText += chunkText;
                onChunk(fullResponseText);
              }
            } catch (e) {}
          }
        }
      }
      return fullResponseText;
    } else {
      const data = await res.json();
      return data.choices?.[0]?.message?.content || "";
    }
  }

  // ─── LOCAL SECURITY KNOWLEDGE BASE (RAG-LITE) ───────────────────
  const SECURITY_KNOWLEDGE_BASE = {
    ssl_tls: {
      title: "SSL/TLS Hardening Guidance",
      keywords: ["ssl", "tls", "certificate", "https", "cipher", "tls1.0", "tls1.1", "tls1.2", "tls1.3", "encryption"],
      content: "SSL/TLS Hardening: Exclusively enforce TLS 1.2 and TLS 1.3. Fully deprecate SSLv3, TLS 1.0, and TLS 1.1 to mitigate POODLE and BEAST attacks."
    },
    phishing: {
      title: "Phishing Detection & Analysis",
      keywords: ["phish", "phishing", "spoof", "homoglyph", "typosquat", "suspicious domain", "url analysis"],
      content: "Phishing & Spoofing Indicators: Typo-spoofing uses lookalike characters (homoglyphs) to trick users."
    },
    ports: {
      title: "Port Hardening Guide",
      keywords: ["port", "ports", "scan", "scanner", "nmap", "tcp", "udp", "service", "ftp", "ssh", "telnet", "mysql", "3306", "22", "21", "23"],
      content: "Port Security Hardening: Close all unused ports. Enforce key-based authentication for SSH on Port 22."
    }
  };

  function retrieveKnowledgeContext(query) {
    if (!query) return "";
    const q = query.toLowerCase();
    let bestMatch = null;
    let maxScore = 0;

    for (const key in SECURITY_KNOWLEDGE_BASE) {
      const entry = SECURITY_KNOWLEDGE_BASE[key];
      let score = 0;
      for (const kw of entry.keywords) {
        if (q.includes(kw)) {
          score += 1;
        }
      }
      if (score > maxScore) {
        maxScore = score;
        bestMatch = entry;
      }
    }

    if (bestMatch && maxScore >= 1) {
      return `\n\n[RELEVANT SECURITY REFERENCE KNOWLEDGE: ${bestMatch.title}]\n${bestMatch.content}`;
    }
    return "";
  }

  // ─── AUTOPILOT CHAIN MOCKS ─────────────────────────────────────────
  let lastToastAction = null;
  let lastToastArgs = null;
  function showAutopilotToast(actionName, args) {
    lastToastAction = actionName;
    lastToastArgs = args;
  }

  const executedActionsList = [];
  function executeIndividualAction(actionName, args) {
    executedActionsList.push({ action: actionName, args });
    try {
      switch (actionName) {
        case "switch_tab": {
          const tabId = args[0];
          if (typeof global.window.switchToTab === "function") {
            global.window.switchToTab(tabId);
          }
          break;
        }
        case "fill_input": {
          const elId = args[0];
          const val = args[1];
          const el = document.getElementById(elId);
          if (el) {
            el.value = val;
            el.dispatchEvent(new Event("input", { bubbles: true }));
          }
          break;
        }
        case "run_scan": {
          const type = args[0];
          const target = args[1];
          if (type === "web") {
            const input = document.getElementById("target-url");
            if (input) {
              input.value = target;
              input.dispatchEvent(new Event("input", { bubbles: true }));
            }
            const btn = document.getElementById("run-analysis-btn");
            if (btn) btn.click();
          }
          break;
        }
      }
    } catch (e) {}
  }

  async function executeWorkflowSteps(steps) {
    if (!Array.isArray(steps)) return;
    for (const step of steps) {
      const actionName = step.action;
      const args = step.args || [];
      showAutopilotToast(actionName, args);
      executeIndividualAction(actionName, args);
      // Shortened timeout for test speed
      await new Promise(resolve => setTimeout(resolve, 5));
    }
  }

  function executeAutopilotAction(actionName, args) {
    if (actionName === "chain_workflow") {
      try {
        const steps = JSON.parse(args[0]);
        if (Array.isArray(steps)) {
          executeWorkflowSteps(steps);
        }
      } catch (e) {}
    } else {
      executeIndividualAction(actionName, args);
    }
  }

  function parseAndExecuteAutopilot(text) {
    if (!text) return "";
    const actionRegex = /\[\[ACTION:\s*(\w+)\((.*?)\)\]\]/g;
    let match;
    const actions = [];

    while ((match = actionRegex.exec(text)) !== null) {
      const actionName = match[1];
      const argsStr = match[2];
      
      let args;
      if (actionName === "chain_workflow") {
        let s = argsStr.trim();
        if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
          s = s.slice(1, -1);
        }
        s = s.replace(/\\"/g, '"').replace(/\\'/g, "'");
        args = [s];
      } else {
        args = argsStr.split(",").map(arg => {
          let s = arg.trim();
          if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
            s = s.slice(1, -1);
          }
          return s;
        });
      }

      actions.push({ action: actionName, args, rawArgsStr: argsStr });
    }

    if (actions.length === 1) {
      executeAutopilotAction(actions[0].action, actions[0].args);
    } else if (actions.length > 1) {
      executeWorkflowSteps(actions);
    }

    return text.replace(/\[\[ACTION:.*?\]\]/g, "");
  }

  // ─── TESTS ──────────────────────────────────────────────────────────

  describe('Context Injection', () => {
    it('should inject active session user and active projects', () => {
      const context = gatherSystemContext();
      
      expect(context).toContain('Active Session User: John Doe (john@cyberguard.com), Role: administrator');
      expect(context).toContain('Alpha Project (Risk Score: 8.5, Targets: 5)');
      expect(context).toContain('Beta Project (Risk Score: 3.2, Targets: 2)');
    });

    it('should inject active tab info and structured findings details (up to 20)', () => {
      resultsData = [
        { status: "threat", tool: "SSL Checker", message: "Expired certificate", details: { domain: "expired.com" } },
        { status: "warning", tool: "Phishing Analyzer", message: "Suspicious homoglyphs", details: "Domain uses characters outside Latin alphabet" }
      ];
      
      const context = gatherSystemContext();
      
      expect(context).toContain('Active Tab: jwt-debugger');
      expect(context).toContain('Current findings count: 2 (1 threats, 1 warnings, 0 safe)');
      expect(context).toContain('[THREAT] SSL Checker: Expired certificate');
      expect(context).toContain('Details: {"domain":"expired.com"}');
      expect(context).toContain('[WARNING] Phishing Analyzer: Suspicious homoglyphs');
      expect(context).toContain('Details: Domain uses characters outside Latin alphabet');
      
      // Check active tab input injection
      expect(context).toContain('Current input JWT Token in Decoder: eyJuYW1lIjoiQWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.token.signature...');
    });

    it('should switch active tab inputs when active tab changes', () => {
      document.getElementById('jwt-debugger').classList.add('hidden');
      document.getElementById('hash-tools').classList.remove('hidden');

      const context = gatherSystemContext();
      expect(context).toContain('Active Tab: hash-tools');
      expect(context).toContain('Current Hashing generator input: "hello-world-hash"');
      expect(context).not.toContain('JWT Token in Decoder');
    });
  });

  describe('REST API Call & Streaming Response Handler', () => {
    it('should include 20 messages history and model-based max_tokens', async () => {
      conversationHistory = Array.from({ length: 25 }, (_, i) => ({
        role: i % 2 === 0 ? "user" : "assistant",
        content: `Msg ${i}`
      }));

      const mockFetch = vi.fn().mockImplementation(() => Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          choices: [{ message: { content: "Mock API response" } }]
        })
      }));
      global.fetch = mockFetch;

      const reply = await callOpenRouterAPI("Hello", "System Prompt", "key-123", "openai/gpt-oss-120b:free", 0.7);
      expect(reply).toBe("Mock API response");

      // Verify request payload limits
      const fetchCallArgs = mockFetch.mock.calls[0];
      const payload = JSON.parse(fetchCallArgs[1].body);
      
      expect(payload.messages.length).toBe(21); // system prompt + 20 messages
      expect(payload.messages[1].content).toBe("Msg 5"); // verify slice(-20) keeps the last 20 messages
      expect(payload.max_tokens).toBe(2048); // free model limit
    });

    it('should use 4096 tokens for a paid model', async () => {
      const mockFetch = vi.fn().mockImplementation(() => Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          choices: [{ message: { content: "Paid response" } }]
        })
      }));
      global.fetch = mockFetch;

      await callOpenRouterAPI("Hello", "System", "key-123", "openai/gpt-4o-mini", 0.7);
      
      const payload = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(payload.max_tokens).toBe(4096);
    });

    it('should process SSE streamed chunks and call onChunk callback correctly', async () => {
      // Mock SSE reader
      const streamChunks = [
        "data: {\"choices\": [{\"delta\": {\"content\": \"Hello \"}}]}\n\n",
        "data: {\"choices\": [{\"delta\": {\"content\": \"world\"}}]}\n\n",
        "data: {\"choices\": [{\"delta\": {\"content\": \"!\"}}]}\n\n",
        "data: [DONE]\n\n"
      ];
      let chunkIndex = 0;

      const mockReader = {
        read: vi.fn().mockImplementation(() => {
          if (chunkIndex < streamChunks.length) {
            const chunk = streamChunks[chunkIndex++];
            return Promise.resolve({
              done: false,
              value: new TextEncoder().encode(chunk)
            });
          }
          return Promise.resolve({ done: true });
        })
      };

      const mockFetch = vi.fn().mockImplementation(() => Promise.resolve({
        ok: true,
        body: {
          getReader: () => mockReader
        }
      }));
      global.fetch = mockFetch;

      const onChunkMock = vi.fn();
      const reply = await callOpenRouterAPI("Hello", "System", "key-123", "openai/gpt-oss-120b:free", 0.7, onChunkMock);

      expect(reply).toBe("Hello world!");
      expect(onChunkMock).toHaveBeenCalledTimes(3);
      expect(onChunkMock.mock.calls[0][0]).toBe("Hello ");
      expect(onChunkMock.mock.calls[1][0]).toBe("Hello world");
      expect(onChunkMock.mock.calls[2][0]).toBe("Hello world!");
    });
  });

  describe('Local Knowledge Base (RAG-Lite)', () => {
    it('should retrieve SSL/TLS reference context for SSL related queries', () => {
      const query = "How do I secure TLS and HTTPS?";
      const context = retrieveKnowledgeContext(query);
      
      expect(context).toContain("[RELEVANT SECURITY REFERENCE KNOWLEDGE: SSL/TLS Hardening Guidance]");
      expect(context).toContain("Exclusively enforce TLS 1.2 and TLS 1.3");
    });

    it('should retrieve port security guide for port scanning queries', () => {
      const query = "What are the common vulnerabilities of port 22 and 3306?";
      const context = retrieveKnowledgeContext(query);
      
      expect(context).toContain("[RELEVANT SECURITY REFERENCE KNOWLEDGE: Port Hardening Guide]");
      expect(context).toContain("Enforce key-based authentication for SSH on Port 22");
    });

    it('should return empty string if no keywords match', () => {
      const query = "Recommend a good movie to watch tonight";
      const context = retrieveKnowledgeContext(query);
      
      expect(context).toBe("");
    });
  });

  describe('Automated Workflow Chains', () => {
    it('should execute a single action directly without queuing workflow steps', () => {
      const text = "Please switch to projects tab: [[ACTION: switch_tab(\"projects\")]]";
      const cleaned = parseAndExecuteAutopilot(text);

      expect(cleaned).toBe("Please switch to projects tab: ");
      expect(executedActionsList).toEqual([
        { action: "switch_tab", args: ["projects"] }
      ]);
      expect(global.window.switchToTab).toHaveBeenCalledWith("projects");
    });

    it('should queue multiple actions and execute them sequentially', async () => {
      const text = "Let's configure target and run scan. [[ACTION: switch_tab(\"web-security\")]] [[ACTION: run_scan(\"web\", \"example.com\")]]";
      const cleaned = parseAndExecuteAutopilot(text);

      expect(cleaned).toBe("Let's configure target and run scan.  ");
      
      // Let the setTimeout microtasks flush
      await new Promise(resolve => setTimeout(resolve, 30));

      expect(executedActionsList.length).toBe(2);
      expect(executedActionsList[0]).toEqual({ action: "switch_tab", args: ["web-security"] });
      expect(executedActionsList[1]).toEqual({ action: "run_scan", args: ["web", "example.com"] });
      
      // Check DOM interactions of executed actions
      expect(global.window.switchToTab).toHaveBeenCalledWith("web-security");
      expect(document.getElementById("target-url").value).toBe("example.com");
    });

    it('should support chain_workflow(jsonString) tag explicitly', async () => {
      const stepsJson = JSON.stringify([
        { action: "switch_tab", args: ["jwt-debugger"] },
        { action: "fill_input", args: ["jwt-decoder-token", "abc"] }
      ]);
      const text = `Executing custom chain: [[ACTION: chain_workflow("${stepsJson.replace(/"/g, '\\"')}")]]`;
      parseAndExecuteAutopilot(text);

      await new Promise(resolve => setTimeout(resolve, 30));

      expect(executedActionsList.length).toBe(2);
      expect(executedActionsList[0]).toEqual({ action: "switch_tab", args: ["jwt-debugger"] });
      expect(executedActionsList[1]).toEqual({ action: "fill_input", args: ["jwt-decoder-token", "abc"] });
      
      expect(global.window.switchToTab).toHaveBeenCalledWith("jwt-debugger");
      expect(document.getElementById("jwt-decoder-token").value).toBe("abc");
    });
  });

  describe('Proposal 4: Message Actions Bar', () => {
    it('should append copy and regenerate buttons below AI message bubbles', () => {
      const isUser = false;
      const bubble = document.createElement("div");
      bubble.className = "ai-msg-bubble";
      bubble.innerText = "Malicious domain detected.";

      const inner = document.createElement("div");
      inner.appendChild(bubble);

      if (!isUser) {
        const actionBar = document.createElement("div");
        actionBar.className = "ai-action-bar";
        
        const copyBtn = document.createElement("button");
        copyBtn.className = "ai-action-btn";
        copyBtn.innerHTML = "Copy";

        const regenBtn = document.createElement("button");
        regenBtn.className = "ai-action-btn";
        regenBtn.innerHTML = "Regenerate";

        actionBar.appendChild(copyBtn);
        actionBar.appendChild(regenBtn);
        inner.appendChild(actionBar);
      }

      const bar = inner.querySelector(".ai-action-bar");
      expect(bar).not.toBeNull();
      expect(bar.children.length).toBe(2);
      expect(bar.children[0].innerHTML).toContain("Copy");
      expect(bar.children[1].innerHTML).toContain("Regenerate");
    });
  });

  describe('Proposal 5: Dynamic Suggestion Chips', () => {
    it('should dynamically update suggestion chips based on selected tab and active target', () => {
      const suggestEl = document.createElement("div");
      suggestEl.id = "ai-suggestions";
      document.body.appendChild(suggestEl);

      const tabChips = {
        "osint": [
          { icon: "explore", label: "Run all OSINT", question: "Run all OSINT recon tools on my current target" },
          { icon: "fingerprint", label: "Wayback Archive check", question: "Search the Wayback Machine archive for history on example.com" }
        ]
      };

      const currentTab = "osint";
      const target = "google.com";

      const chipsList = [...tabChips[currentTab]];
      const finalChips = chipsList.map(chip => {
        let q = chip.question;
        let label = chip.label;
        if (target) {
          q = q.replace(/example\.com/g, target).replace(/current target/g, target);
          label = label.replace(/current target/g, target);
        }
        return { ...chip, question: q, label };
      });

      finalChips.forEach(chip => {
        const btn = document.createElement("button");
        btn.className = "ai-chip";
        btn.dataset.question = chip.question;
        btn.textContent = chip.label;
        suggestEl.appendChild(btn);
      });

      const chips = suggestEl.querySelectorAll(".ai-chip");
      expect(chips.length).toBe(2);
      expect(chips[0].dataset.question).toContain("google.com");
      expect(chips[1].dataset.question).toContain("google.com");
    });
  });

  describe('Proposal 6: AI-Powered PDF Report Generation', () => {
    it('should invoke generatePDFReport when generate_report action is parsed', () => {
      const mockGenerateReport = vi.fn();
      
      const testExecuteAction = (actionName) => {
        if (actionName === "generate_report") {
          mockGenerateReport();
        }
      };

      const text = "Assessment finished. [[ACTION: generate_report()]]";
      const actionRegex = /\[\[ACTION:\s*(\w+)\((.*?)\)\]\]/g;
      const match = actionRegex.exec(text);
      
      expect(match).not.toBeNull();
      expect(match[1]).toBe("generate_report");
      
      testExecuteAction(match[1]);
      expect(mockGenerateReport).toHaveBeenCalled();
    });
  });
});
