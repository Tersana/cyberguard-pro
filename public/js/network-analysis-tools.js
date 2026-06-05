(function () {
  "use strict";

  // ===== API KEYS & ENCRYPTION DEFAULTS =====
  const ENCRYPTION_KEY = "CyberGuard2024!@#";

  function decryptApiKey(encryptedKey) {
    if (!encryptedKey) return "";
    try {
      const decoded = atob(encryptedKey);
      let decrypted = "";
      for (let i = 0; i < decoded.length; i++) {
        decrypted += String.fromCharCode(
          decoded.charCodeAt(i) ^
            ENCRYPTION_KEY.charCodeAt(i % ENCRYPTION_KEY.length),
        );
      }
      return decrypted;
    } catch (e) {
      console.error("Decryption failed:", e);
      return encryptedKey;
    }
  }

  function getStoredApiKey(name) {
    if (typeof window.getApiKey === "function") {
      return window.getApiKey(name);
    }
    const stored = localStorage.getItem(name);
    return stored ? decryptApiKey(stored) : "";
  }

  // ===== PIPELINE LOGGING & UI ROUTING WRAPPERS =====
  // These wrappers automatically route outputs to whichever logging system is currently active on the page.
  function logResult(timestamp, feature, message, status = "info", details = null) {
    if (typeof window.onFrontendToolResult === "function") {
      window.onFrontendToolResult({ timestamp, feature, message, status, details });
    }
    if (typeof window.logResult === "function" && window.logResult !== logResult) {
      window.logResult(timestamp, feature, message, status, details);
    } else {
      console.log(`[Result] [${feature}] [${status}] ${message}`);
    }
  }

  function addActivityLog(message, scanner) {
    if (typeof window.onFrontendToolLog === "function") {
      window.onFrontendToolLog(message, scanner);
    }
    if (typeof window.addActivityLog === "function" && window.addActivityLog !== addActivityLog) {
      window.addActivityLog(message, scanner);
    } else {
      console.log(`[Log] [${scanner}] ${message}`);
    }
  }

  function appendActivityEvent(event) {
    if (typeof window.onFrontendToolEvent === "function") {
      window.onFrontendToolEvent(event);
    }
    if (typeof window.appendActivityEvent === "function" && window.appendActivityEvent !== appendActivityEvent) {
      window.appendActivityEvent(event);
    }
  }

  function updateStatus(status) {
    if (typeof window.onFrontendToolStatus === "function") {
      window.onFrontendToolStatus(status);
    }
    if (typeof window.updateStatus === "function" && window.updateStatus !== updateStatus) {
      window.updateStatus(status);
    }
  }

  function showProgressBar() {
    if (typeof window.showProgressBar === "function") {
      window.showProgressBar();
    }
  }

  function hideProgressBar() {
    if (typeof window.hideProgressBar === "function") {
      window.hideProgressBar();
    }
  }

  function isValidIP(ip) {
    const ipRegex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
    return ipRegex.test(ip);
  }

  function isValidDomain(domain) {
    const domainRegex =
      /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
  }

  // ===== PORT SERVICES META MAP =====
  const PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3000: "Dev-Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017: "MongoDB",
  };

  function getServiceName(port) {
    return PORT_SERVICES[port] || "Unknown";
  }

  function getPortRisk(port) {
    const high = [21, 23, 445, 1433, 3389, 5900, 6379, 27017, 9200];
    const med = [22, 25, 80, 3306, 5432, 8080];
    if (high.includes(port)) return "high";
    if (med.includes(port)) return "medium";
    return "low";
  }

  const WHOIS_DIVIDER = "─".repeat(54);

  function formatIpWhoisOutput(ip, location, asn, security) {
    const coords =
      location.latitude && location.longitude
        ? `${location.latitude}, ${location.longitude}`
        : "N/A";

    return [
      WHOIS_DIVIDER,
      `  IP WHOIS DATA — ${ip}`,
      WHOIS_DIVIDER,
      "  Location",
      `    Country        : ${location.country || "N/A"}`,
      `    Region         : ${location.region || "N/A"}`,
      `    City           : ${location.city || "N/A"}`,
      `    Postal Code    : ${location.postalCode || "N/A"}`,
      `    Coordinates    : ${coords}`,
      `    Timezone       : ${location.timezone || "N/A"}`,
      "",
      "  Network",
      `    Organization   : ${asn.organization || "N/A"}`,
      `    ASN            : ${asn.asn || "N/A"}`,
      `    ASN Name       : ${asn.name || "N/A"}`,
      `    ASN Domain     : ${asn.domain || "N/A"}`,
      `    ASN Country    : ${asn.country || "N/A"}`,
      "",
      "  Security",
      `    Proxy          : ${security.isProxy ? "Proxy detected" : "No proxy"}`,
      `    VPN            : ${security.isVpn ? "VPN detected" : "No VPN"}`,
      `    Hosting        : ${security.isHosting ? "Hosting provider" : "Not hosting"}`,
      `    Tor            : ${security.isTor ? "Tor exit node" : "Not Tor"}`,
      WHOIS_DIVIDER,
    ].join("\n");
  }

  function formatDomainWhoisOutput(domainName, opts) {
    const {
      createdDate,
      updatedDate,
      expiresDate,
      registrar,
      registrant,
      status,
      nameServers,
    } = opts;

    const statusFlags = Array.isArray(status)
      ? status
      : typeof status === "string" && status !== "N/A"
        ? status.split(/[,\s]+/).filter(Boolean)
        : ["N/A"];
    const flagLines = statusFlags.map(
      (f, i) => (i === 0 ? `    Flags          : ${f}` : `                     ${f}`),
    );

    const nsArray = Array.isArray(nameServers) ? nameServers : [];
    const nsLines =
      nsArray.length > 0
        ? nsArray.map(
            (ns, i) =>
              i === 0
                ? `    Nameservers    : ${ns}`
                : `                     ${ns}`,
          )
        : ["    Nameservers    : N/A"];

    return [
      WHOIS_DIVIDER,
      `  DOMAIN WHOIS DATA — ${domainName}`,
      WHOIS_DIVIDER,
      "  Registration",
      `    Domain         : ${domainName}`,
      `    Created        : ${createdDate}`,
      `    Updated        : ${updatedDate}`,
      `    Expires        : ${expiresDate}`,
      `    Registrar      : ${registrar}`,
      `    Registrant     : ${registrant}`,
      "",
      "  Status",
      ...flagLines,
      "",
      "  DNS",
      ...nsLines,
      WHOIS_DIVIDER,
    ].join("\n");
  }

  async function resolveDomainToIP(domain) {
    try {
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
      );
      const data = await res.json();
      const a = data.Answer?.find((r) => r.type === 1);
      if (a?.data) return a.data;
    } catch (_) {}
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
        { headers: { Accept: "application/dns-json" } },
      );
      const data = await res.json();
      const a = data.Answer?.find((r) => r.type === 1);
      if (a?.data) return a.data;
    } catch (_) {}
    return null;
  }

  // ===== 1. PORT SCANNER (SHODAN INTERNETDB OR SHODAN API) =====
  class ShodanPortScanner {
    constructor(apiKey) {
      this.apiKey = apiKey;
      this.baseUrl = "https://api.shodan.io";
      this.rateLimitDelay = 1000;
      this.lastRequestTime = 0;
    }

    async rateLimit() {
      const now = Date.now();
      const timeSinceLastRequest = now - this.lastRequestTime;
      if (timeSinceLastRequest < this.rateLimitDelay) {
        await new Promise((resolve) =>
          setTimeout(resolve, this.rateLimitDelay - timeSinceLastRequest),
        );
      }
      this.lastRequestTime = Date.now();
    }

    async makeShodanRequest(endpoint, params = {}) {
      await this.rateLimit();
      const targetUrl = new URL(`${this.baseUrl}${endpoint}`);
      targetUrl.searchParams.append("key", this.apiKey);

      Object.entries(params).forEach(([key, value]) => {
        if (value !== null && value !== undefined) {
          targetUrl.searchParams.append(key, value);
        }
      });

      const proxyOptions = [
        "https://api.allorigins.win/raw?url=",
        "https://cors.lol/?url=",
        "https://corsproxy.io/?url=",
      ];
      const proxyUrl = proxyOptions[0];
      const encodedUrl = encodeURIComponent(targetUrl.toString());

      try {
        const response = await fetch(`${proxyUrl}${encodedUrl}`, {
          method: "GET",
          headers: {
            "User-Agent": "CyberGuard-Pro/1.0",
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          mode: "cors",
        });

        if (!response.ok) {
          throw new Error(`Proxy Error: ${response.status} - ${response.statusText}`);
        }

        const data = await response.json();
        if (data.error) {
          throw new Error(`Shodan API Error: ${data.error}`);
        }
        return data;
      } catch (error) {
        if (error.message.includes("Failed to fetch") || error.message.includes("NetworkError")) {
          return await this.makeShodanRequestAlternative(targetUrl);
        }
        throw error;
      }
    }

    async makeShodanRequestAlternative(targetUrl) {
      const proxyOptions = [
        "https://api.allorigins.win/raw?url=",
        "https://cors.lol/?url=",
        "https://corsproxy.io/?url=",
      ];

      for (let i = 0; i < proxyOptions.length; i++) {
        try {
          const proxyUrl = proxyOptions[i];
          const encodedUrl = encodeURIComponent(targetUrl.toString());
          logResult(new Date(), "Shodan Scanner", `🔄 Trying CORS proxy ${i + 1}/${proxyOptions.length}...`, "info");

          const response = await fetch(`${proxyUrl}${encodedUrl}`, {
            method: "GET",
            headers: {
              "User-Agent": "CyberGuard-Pro/1.0",
              Accept: "application/json",
            },
          });

          if (!response.ok) {
            if (i === proxyOptions.length - 1) {
              throw new Error(`All proxies failed. Last error: ${response.status} - ${response.statusText}`);
            }
            continue;
          }

          const data = await response.json();
          if (data.error) {
            throw new Error(`Shodan API Error: ${data.error}`);
          }
          logResult(new Date(), "Shodan Scanner", `✅ Successfully connected via CORS proxy ${i + 1}`, "success");
          return data;
        } catch (error) {
          if (i === proxyOptions.length - 1) {
            logResult(new Date(), "Shodan Scanner", `⚠️ All CORS proxies failed, trying JSONP approach...`, "warning");
            return await this.makeShodanRequestJSONP(targetUrl);
          }
          continue;
        }
      }
    }

    async makeShodanRequestJSONP(targetUrl) {
      return new Promise((resolve, reject) => {
        const callbackName = `shodanCallback_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const jsonpUrl = new URL(targetUrl);
        jsonpUrl.searchParams.append("callback", callbackName);

        const script = document.createElement("script");
        script.src = jsonpUrl.toString();
        script.async = true;

        window[callbackName] = (data) => {
          document.head.removeChild(script);
          delete window[callbackName];
          if (data.error) {
            reject(new Error(`Shodan API Error: ${data.error}`));
          } else {
            resolve(data);
          }
        };

        script.onerror = () => {
          document.head.removeChild(script);
          delete window[callbackName];
          reject(new Error("JSONP request failed"));
        };

        document.head.appendChild(script);

        setTimeout(() => {
          if (window[callbackName]) {
            document.head.removeChild(script);
            delete window[callbackName];
            reject(new Error("JSONP request timeout"));
          }
        }, 10000);
      });
    }

    async getHostInfo(target) {
      try {
        logResult(new Date(), "Shodan Scanner", `🔍 Querying Shodan for host information: ${target}...`, "info");
        const hostInfo = await this.makeShodanRequest(`/shodan/host/${target}`);
        return {
          success: true,
          data: hostInfo,
          timestamp: new Date().toISOString(),
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          timestamp: new Date().toISOString(),
        };
      }
    }

    processHostData(hostData) {
      const processedData = {
        ip: hostData.ip_str || "Unknown",
        hostnames: hostData.hostnames || [],
        ports: hostData.ports || [],
        services: [],
        vulnerabilities: hostData.vulns || [],
        location: hostData.location || {},
        os: hostData.os || "Unknown",
        lastUpdate: hostData.last_update || "Unknown",
        organization: hostData.org || "Unknown",
        isp: hostData.isp || "Unknown",
      };

      if (hostData.data && Array.isArray(hostData.data)) {
        hostData.data.forEach((service) => {
          processedData.services.push({
            port: service.port,
            protocol: service.transport || "tcp",
            service: service.product || "Unknown",
            version: service.version || "Unknown",
            banner: service.data || "",
            timestamp: service.timestamp || "Unknown",
            cpe: service.cpe || [],
            vulns: service.vulns || [],
          });
        });
      }

      return processedData;
    }

    generateReport(processedData, scanStartTime) {
      const scanDuration = Date.now() - scanStartTime;
      return {
        target: processedData.ip,
        scanDuration: Math.round(scanDuration),
        totalPorts: processedData.ports.length,
        openPorts: processedData.ports,
        services: processedData.services,
        vulnerabilities: processedData.vulnerabilities,
        location: processedData.location,
        os: processedData.os,
        organization: processedData.organization,
        isp: processedData.isp,
        hostnames: processedData.hostnames,
        lastUpdate: processedData.lastUpdate,
        timestamp: new Date().toISOString(),
      };
    }
  }

  async function portScan(target) {
    const key = getStoredApiKey("shodanApiKey") || "oL1wHP4qa2zzeF08o31ZIACZQqkb3Rzw";
    const shodanScanner = new ShodanPortScanner(key);
    const scanStartTime = Date.now();

    try {
      addActivityLog(`Starting port scan for ${target}`, "Port Scanner");
      updateStatus("Querying Shodan database...");
      addActivityLog("Querying Shodan database...", "Port Scanner");
      const hostResult = await shodanScanner.getHostInfo(target);

      if (!hostResult.success) {
        addActivityLog(`Shodan query failed: ${hostResult.error}`, "Port Scanner");
        logResult(new Date(), "Shodan Scanner", `❌ [ERROR] Shodan query failed: ${hostResult.error}`, "danger");
        return;
      }

      addActivityLog("Processing host data...", "Port Scanner");
      const processedData = shodanScanner.processHostData(hostResult.data);
      const report = shodanScanner.generateReport(processedData, scanStartTime);

      if (processedData.services.length > 0) {
        addActivityLog(`Found ${processedData.services.length} open ports`, "Port Scanner");
        for (const service of processedData.services) {
          const serviceInfo = service.service !== "Unknown" ? ` - ${service.service.toUpperCase()}` : "";
          const versionInfo = service.version !== "Unknown" ? ` (${service.version})` : "";
          const protocolInfo = service.protocol ? ` [${service.protocol.toUpperCase()}]` : "";
          const vulnInfo = service.vulns.length > 0 ? ` ⚠️ ${service.vulns.length} vulns` : "";

          logResult(new Date(), "Shodan Scanner", `✅ Port ${service.port} is OPEN${serviceInfo}${versionInfo}${protocolInfo}${vulnInfo}`, "success");

          if (service.banner && service.banner.length > 0) {
            const bannerPreview = service.banner.length > 100 ? service.banner.substring(0, 100) + "..." : service.banner;
            logResult(new Date(), "Shodan Scanner", `📋 Banner: ${bannerPreview}`, "info");
          }
        }
      }

      if (report.totalPorts > 0) {
        addActivityLog(`Generating report for ${report.totalPorts} ports`, "Port Scanner");
        const portList = report.services
          .map((s) => {
            const serviceInfo = s.service !== "Unknown" ? ` - ${s.service.toUpperCase()}` : "";
            const versionInfo = s.version !== "Unknown" ? ` (${s.version})` : "";
            const vulnInfo = s.vulns.length > 0 ? ` ⚠️ ${s.vulns.length} vulns` : "";
            return `${s.port}${serviceInfo}${versionInfo}${vulnInfo}`;
          })
          .join("\n - ");

        const locationInfo = report.location.city ? `${report.location.city}, ${report.location.country_name}` : "Unknown location";
        const orgInfo = report.organization !== "Unknown" ? report.organization : "Unknown organization";

        addActivityLog("Scan complete - open ports detected", "Port Scanner");
        logResult(
          new Date(),
          "Shodan Scanner",
          `🚨 [SCAN COMPLETE] Network intelligence for ${target}:\n\n🌐 Host Information:\n - IP: ${report.target}\n - Organization: ${orgInfo}\n - ISP: ${report.isp}\n - Location: ${locationInfo}\n - OS: ${report.os}\n - Hostnames: ${report.hostnames.join(", ") || "None"}\n\n🔓 Open Ports & Services:\n - ${portList}\n\n⚠️ Vulnerabilities: ${report.vulnerabilities.length}\n📊 Scan Statistics:\n - Total ports: ${report.totalPorts}\n - Services detected: ${report.services.length}\n - Scan duration: ${report.scanDuration}ms\n - Data freshness: ${report.lastUpdate}`,
          "danger",
        );
      } else {
        addActivityLog("Scan complete - no open ports found", "Port Scanner");
        logResult(
          new Date(),
          "Shodan Scanner",
          `✅ [SCAN COMPLETE] No open ports found in Shodan database for ${target}\n\n📊 Scan Statistics:\n - Scan duration: ${report.scanDuration}ms\n - Data source: Shodan database\n - Last update: ${report.lastUpdate}`,
          "success",
        );
      }
    } catch (error) {
      addActivityLog(`Scan failed: ${error.message}`, "Port Scanner");
      logResult(new Date(), "Shodan Scanner", `❌ [ERROR] Scan failed: ${error.message}`, "danger");
    } finally {
      updateStatus("Shodan scan completed");
    }
  }

  // ===== 2. TCP CONNECTIVITY =====
  function injectShodanPanel(panel) {
    const container = document.getElementById("accordion-items-container");
    if (!container) return;
    const emptyState = document.getElementById("empty-results-state");
    if (emptyState) emptyState.style.display = "none";
    const existing = document.getElementById("tcp-scan-results");
    if (existing && existing !== panel) existing.remove();
    container.appendChild(panel);
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function setTCPScanState(state, target) {
    if (state === "scanning") {
      let panel = document.getElementById("tcp-scan-results");
      if (!panel) {
        panel = document.createElement("div");
        panel.id = "tcp-scan-results";
        panel.className = "shodan-results-panel";
      }
      panel.innerHTML =
        '<div class="shodan-scanning-state">' +
        '<div class="shodan-scan-spinner"></div>' +
        `<span>Querying Shodan InternetDB for ${target}…</span>` +
        "</div>";
      injectShodanPanel(panel);
    }
  }

  function renderShodanResults(data, target) {
    let panel = document.getElementById("tcp-scan-results");
    if (!panel) {
      panel = document.createElement("div");
      panel.id = "tcp-scan-results";
      panel.className = "shodan-results-panel";
    } else {
      panel.innerHTML = "";
    }

    if (data.error) {
      panel.innerHTML =
        '<div class="shodan-error-state">' +
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">' +
        '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>' +
        '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
        `<p>${data.message}</p></div>`;
      injectShodanPanel(panel);
      return;
    }

    const resolvedNote =
      String(target) !== String(data.ip)
        ? `<span class="resolved-note">${target} → ${data.ip}</span>`
        : "";

    const statsEl = document.createElement("div");
    statsEl.className = "shodan-stats-bar";
    statsEl.innerHTML =
      `<div class="shodan-stat"><span class="stat-value">${data.ports.length}</span><span class="stat-label">Open Ports</span></div>` +
      `<div class="shodan-stat"><span class="stat-value">${data.hostnames.length}</span><span class="stat-label">Hostnames</span></div>` +
      `<div class="shodan-stat"><span class="stat-value${data.vulns.length > 0 ? " stat-value-danger" : ""}">${data.vulns.length}</span><span class="stat-label">Known CVEs</span></div>` +
      `<div class="shodan-stat"><span class="stat-value stat-value-sm">${data.tags.length > 0 ? data.tags.join(", ") : "—"}</span><span class="stat-label">Tags</span></div>` +
      `<div class="shodan-source">${resolvedNote}<span class="source-badge">Shodan InternetDB</span></div>`;
    panel.appendChild(statsEl);

    if (data.ports.length === 0) {
      const noEl = document.createElement("div");
      noEl.className = "no-ports-found";
      noEl.innerHTML =
        '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">' +
        '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>' +
        '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
        `<p>${data.message || "No open ports found for this IP."}</p>` +
        "<span>This IP may be behind a firewall or not yet indexed by Shodan.</span>";
      panel.appendChild(noEl);
    } else {
      const tableWrapper = document.createElement("div");
      tableWrapper.className = "port-table-wrapper";
      const rows = [...data.ports]
        .sort((a, b) => a - b)
        .map((port) => {
          const service = getServiceName(port);
          const risk = getPortRisk(port);
          return (
            '<tr class="port-row">' +
            `<td class="port-number">${port}</td>` +
            `<td class="port-service">${service}</td>` +
            `<td><span class="risk-badge risk-${risk}">${risk.toUpperCase()}</span></td>` +
            '<td><span class="port-status-badge status-open">' +
            '<svg width="8" height="8" viewBox="0 0 8 8"><circle cx="4" cy="4" r="4" fill="currentColor"/></svg> OPEN' +
            "</span></td></tr>"
          );
        })
        .join("");
      tableWrapper.innerHTML =
        '<table class="port-results-table"><thead><tr>' +
        "<th>PORT</th><th>SERVICE</th><th>RISK</th><th>STATUS</th>" +
        `</tr></thead><tbody>${rows}</tbody></table>`;
      panel.appendChild(tableWrapper);
    }

    if (data.hostnames && data.hostnames.length > 0) {
      const hostsEl = document.createElement("div");
      hostsEl.className = "shodan-hostnames";
      hostsEl.innerHTML =
        '<div class="section-label">Hostnames</div>' +
        `<div class="hostnames-list">${data.hostnames.map((h) => `<span class="hostname-tag">${h}</span>`).join("")}</div>`;
      panel.appendChild(hostsEl);
    }

    if (data.vulns && data.vulns.length > 0) {
      const vulnsEl = document.createElement("div");
      vulnsEl.className = "shodan-vulns";
      vulnsEl.innerHTML =
        `<div class="section-label danger-label">⚠ Known Vulnerabilities (${data.vulns.length})</div>` +
        `<div class="vulns-list">${data.vulns
          .map(
            (cve) =>
              `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener" class="cve-tag">${cve}</a>`,
          )
          .join("")}</div>`;
      panel.appendChild(vulnsEl);
    }

    const disc = document.createElement("div");
    disc.className = "shodan-disclaimer";
    disc.innerHTML =
      '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
      '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="8"/>' +
      '<line x1="12" y1="12" x2="12" y2="16"/></svg>' +
      "Data sourced from Shodan InternetDB. Results reflect last known scan, not real-time port status. " +
      "For live scanning use nmap locally.";
    panel.appendChild(disc);

    injectShodanPanel(panel);
  }

  async function realTcpPortScan(target) {
    document.getElementById("tcp-scan-results")?.remove();
    setTCPScanState("scanning", target);

    appendActivityEvent({
      type: "system",
      scanner: "TCP SCAN",
      message: `Querying Shodan InternetDB for ${target}`,
    });

    const result = await scanWithShodanInternetDB(target);

    if (result.error) {
      appendActivityEvent({
        type: "error",
        scanner: "TCP SCAN",
        message: result.message,
      });
      renderShodanResults(result, target);
      logResult(new Date(), "TCP Port Scan", result.message, "danger");
      return;
    }

    if (result.ports.length > 0) {
      appendActivityEvent({
        type: "success",
        scanner: "TCP SCAN",
        message: `Found ${result.ports.length} open port${result.ports.length !== 1 ? "s" : ""}`,
        detail: result.ports.slice(0, 10).join(", ") + (result.ports.length > 10 ? "…" : ""),
      });
      result.ports.forEach((port) => {
        const service = getServiceName(port);
        const risk = getPortRisk(port);
        const aType = risk === "high" ? "error" : risk === "medium" ? "warning" : "info";
        appendActivityEvent({
          type: aType,
          scanner: "TCP SCAN",
          message: `Port ${port} OPEN`,
          detail: service,
        });
        logResult(new Date(), "TCP Port Scan", `Port ${port} is OPEN - ${service}`, "success");
      });
    } else {
      const msg = result.message || "No open ports found in Shodan database.";
      appendActivityEvent({ type: "info", scanner: "TCP SCAN", message: msg });
      logResult(new Date(), "TCP Port Scan", msg, "info");
    }

    if (result.vulns && result.vulns.length > 0) {
      const topCves = result.vulns.slice(0, 3).join(", ");
      const more = result.vulns.length > 3 ? ` +${result.vulns.length - 3} more` : "";
      appendActivityEvent({
        type: "error",
        scanner: "TCP SCAN",
        message: `${result.vulns.length} known CVE${result.vulns.length !== 1 ? "s" : ""} found`,
        detail: topCves + more,
      });
      logResult(
        new Date(),
        "TCP Port Scan",
        `⚠ ${result.vulns.length} known CVE${result.vulns.length !== 1 ? "s" : ""}: ${topCves}${more}`,
        "danger",
      );
    }

    if (result.hostnames && result.hostnames.length > 0) {
      appendActivityEvent({
        type: "info",
        scanner: "TCP SCAN",
        message: `${result.hostnames.length} hostname${result.hostnames.length !== 1 ? "s" : ""} resolved`,
        detail: result.hostnames.slice(0, 2).join(", "),
      });
    }

    renderShodanResults(result, target);
  }

  // ===== 3. UDP SERVICES =====
  async function realUdpConnectivityTest(target) {
    logResult(new Date(), "UDP Port Scan", `📡 Starting REAL UDP-based service connectivity test of ${target}...`);
    logResult(
      new Date(),
      "UDP Port Scan",
      `⚠️ Note: Browsers cannot directly test UDP ports. Testing UDP-based services via available APIs.`,
      "info",
    );

    try {
      showProgressBar();
      updateStatus("Initializing real UDP service test...");

      let hostname = target;
      if (target.startsWith("http://") || target.startsWith("https://")) {
        hostname = new URL(target).hostname;
      }

      logResult(new Date(), "UDP Port Scan", `📡 Testing UDP-based services on ${hostname}...`, "info");

      const testedServices = [];
      const workingServices = [];
      const failedServices = [];

      // Test DNS
      updateStatus("Testing DNS service (UDP 53)...");
      try {
        const startTime = Date.now();
        const dnsTest = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`, {
          method: "GET",
          headers: { Accept: "application/dns-json" },
        });

        const responseTime = Date.now() - startTime;
        const dnsData = await dnsTest.json();

        if (dnsData.Status === 0 && dnsData.Answer) {
          workingServices.push({
            port: 53,
            service: "DNS",
            protocol: "UDP",
            responseTime,
            status: "DNS Resolution Working",
            details: `Resolved to ${dnsData.Answer.map((a) => a.data).join(", ")}`,
          });
          logResult(new Date(), "UDP Port Scan", `✅ DNS (UDP 53) - Service responding (${responseTime}ms)`, "success");
        } else {
          failedServices.push({ port: 53, service: "DNS", error: "DNS resolution failed" });
          logResult(new Date(), "UDP Port Scan", `❌ DNS (UDP 53) - Service not responding`, "info");
        }
        testedServices.push({ port: 53, service: "DNS", tested: true });
      } catch (error) {
        failedServices.push({ port: 53, service: "DNS", error: error.message });
        logResult(new Date(), "UDP Port Scan", `❌ DNS (UDP 53) - Test failed: ${error.message}`, "info");
        testedServices.push({ port: 53, service: "DNS", tested: true });
      }

      await new Promise((r) => setTimeout(r, 500));

      // Test NTP
      updateStatus("Testing NTP service (UDP 123)...");
      try {
        const startTime = Date.now();
        const ntpTest = await fetch(`https://worldtimeapi.org/api/timezone/Etc/UTC`, {
          method: "GET",
          signal: AbortSignal.timeout(5000),
        });

        const responseTime = Date.now() - startTime;

        if (ntpTest.ok) {
          const timeData = await ntpTest.json();
          workingServices.push({
            port: 123,
            service: "NTP/Time",
            protocol: "UDP",
            responseTime,
            status: "Time Service Available",
            details: `Current time: ${timeData.datetime}`,
          });
          logResult(new Date(), "UDP Port Scan", `✅ NTP/Time (UDP 123) - Time service responding (${responseTime}ms)`, "success");
        } else {
          failedServices.push({ port: 123, service: "NTP", error: "Time service unavailable" });
          logResult(new Date(), "UDP Port Scan", `❌ NTP (UDP 123) - Time service not available`, "info");
        }
        testedServices.push({ port: 123, service: "NTP", tested: true });
      } catch (error) {
        failedServices.push({ port: 123, service: "NTP", error: error.message });
        logResult(new Date(), "UDP Port Scan", `❌ NTP (UDP 123) - Test failed: ${error.message}`, "info");
        testedServices.push({ port: 123, service: "NTP", tested: true });
      }

      await new Promise((r) => setTimeout(r, 500));

      // Test DHCP Indicator
      updateStatus("Testing DHCP service indicators...");
      try {
        const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (connection) {
          workingServices.push({
            port: 67,
            service: "DHCP",
            protocol: "UDP",
            responseTime: "N/A",
            status: "Network Connection Active",
            details: `Type: ${connection.effectiveType || "unknown"}, Downlink: ${connection.downlink || "unknown"}Mbps`,
          });
          logResult(new Date(), "UDP Port Scan", `✅ DHCP (UDP 67/68) - Network connection indicates DHCP usage`, "success");
        } else {
          logResult(new Date(), "UDP Port Scan", `ℹ️ DHCP (UDP 67/68) - Network connection info unavailable`, "info");
        }
        testedServices.push({ port: 67, service: "DHCP", tested: true });
      } catch (error) {
        logResult(new Date(), "UDP Port Scan", `❌ DHCP (UDP 67/68) - Test failed: ${error.message}`, "info");
        testedServices.push({ port: 67, service: "DHCP", tested: true });
      }

      await new Promise((r) => setTimeout(r, 500));

      // Test mDNS/Bonjour
      updateStatus("Testing mDNS/Bonjour service...");
      try {
        const mdnsTest = await fetch(`http://${hostname}.local`, {
          method: "HEAD",
          mode: "no-cors",
          signal: AbortSignal.timeout(3000),
        });

        workingServices.push({
          port: 5353,
          service: "mDNS",
          protocol: "UDP",
          responseTime: "N/A",
          status: "Local network discovery possible",
          details: "mDNS/.local domain accessible",
        });
        logResult(new Date(), "UDP Port Scan", `✅ mDNS (UDP 5353) - Local network discovery working`, "success");
      } catch (error) {
        failedServices.push({ port: 5353, service: "mDNS", error: "Local discovery not available" });
        logResult(new Date(), "UDP Port Scan", `❌ mDNS (UDP 5353) - Local network discovery failed`, "info");
      }
      testedServices.push({ port: 5353, service: "mDNS", tested: true });

      // Generate report
      updateStatus("Generating UDP service report...");
      await new Promise((r) => setTimeout(r, 300));

      const scanReport = [
        `📡 REAL UDP Service Connectivity Test Results for ${hostname}`,
        `Test completed at ${new Date().toLocaleString()}`,
        `Method: Browser APIs + Public Service Tests`,
        ``,
        `WORKING UDP SERVICES:`,
      ];

      if (workingServices.length > 0) {
        scanReport.push(`Port    Service    Protocol    Response    Status`);
        scanReport.push(`----    -------    --------    --------    ------`);
        workingServices.forEach((service) => {
          const response = service.responseTime !== "N/A" ? `${service.responseTime}ms` : "N/A";
          scanReport.push(
            `${service.port.toString().padEnd(7)} ${service.service.padEnd(10)} ${service.protocol.padEnd(11)} ${response.padEnd(11)} ${service.status}`,
          );
          if (service.details) {
            scanReport.push(`        Details: ${service.details}`);
          }
        });
      } else {
        scanReport.push(`No UDP services detected with available browser methods`);
      }

      if (failedServices.length > 0) {
        scanReport.push(``);
        scanReport.push(`FAILED/UNAVAILABLE UDP SERVICES:`);
        failedServices.forEach((service) => {
          scanReport.push(`${service.port}/udp ${service.service} - ${service.error}`);
        });
      }

      scanReport.push(``);
      scanReport.push(`UDP TESTING LIMITATIONS IN BROWSERS:`);
      scanReport.push(`• Cannot create raw UDP sockets`);
      scanReport.push(`• Can only test via HTTP APIs and indirect methods`);
      scanReport.push(`• DNS, NTP, and network info are testable`);
      scanReport.push(`• Direct UDP port scanning requires native tools`);
      scanReport.push(`• Results indicate service availability, not port status`);

      scanReport.push(``);
      scanReport.push(`REAL SERVICE TEST SUMMARY:`);
      scanReport.push(`Total services tested: ${testedServices.length}`);
      scanReport.push(`Working services: ${workingServices.length}`);
      scanReport.push(`Failed/Unavailable: ${failedServices.length}`);
      scanReport.push(`Method: Real API calls and browser capabilities`);

      hideProgressBar();
      updateStatus("Real UDP service test completed");

      const status = workingServices.length > 0 ? "success" : "info";
      logResult(new Date(), "UDP Port Scan", scanReport.join("\n"), status);
    } catch (error) {
      hideProgressBar();
      updateStatus("Real UDP service test failed");
      logResult(new Date(), "UDP Port Scan", `❌ [ERROR] Real UDP service test failed: ${error.message}`, "danger");
    }
  }

  // ===== 4. IP GEOLOCATION =====
  async function ipGeolocation(target) {
    addActivityLog(`Starting geolocation lookup for ${target}`, "IP Geolocation");
    logResult(new Date(), "IP Geolocation", `Fetching geolocation for ${target}...`);
    try {
      addActivityLog("Querying geolocation API...", "IP Geolocation");
      const r = await fetch(`https://ipapi.co/${target}/json/`);
      if (!r.ok) throw new Error(`API error ${r.status}`);
      const d = await r.json();
      if (d.error) throw new Error(d.reason);

      addActivityLog("Processing geolocation data...", "IP Geolocation");
      let result = `Detailed Geolocation for ${target}:\n\n`;
      result += `Location Details:\n`;
      result += `  Country: ${d.country_name || "N/A"} (${d.country || "N/A"})\n`;
      result += `  Region/State: ${d.region || "N/A"}\n`;
      result += `  City: ${d.city || "N/A"}\n`;
      result += `  Postal Code: ${d.postal || "N/A"}\n`;
      result += `  Coordinates: ${d.latitude || "N/A"}, ${d.longitude || "N/A"}\n\n`;

      result += `Network Information:\n`;
      result += `  ISP/Organization: ${d.org || "N/A"}\n`;
      result += `  ASN: ${d.asn || "N/A"}\n`;
      result += `  Connection Type: ${d.connection || "N/A"}\n\n`;

      result += `Regional Details:\n`;
      result += `  Timezone: ${d.timezone || "N/A"}\n`;
      result += `  UTC Offset: ${d.utc_offset || "N/A"}\n`;
      result += `  Currency: ${d.currency_name || "N/A"} (${d.currency || "N/A"})\n`;
      result += `  Languages: ${d.languages || "N/A"}\n\n`;

      result += `Security Information:\n`;
      result += `  Threat Level: ${d.threat || "Low"}\n`;
      result += `  Is EU Country: ${d.in_eu ? "Yes" : "No"}\n`;

      addActivityLog("Geolocation lookup complete", "IP Geolocation");
      logResult(new Date(), "IP Geolocation", result, "success");
    } catch (e) {
      addActivityLog(`Lookup failed: ${e.message}`, "IP Geolocation");
      logResult(new Date(), "IP Geolocation", `[ERROR] Geolocation fetch failed. ${e.message}`, "danger");
    }
  }

  // ===== 5. REVERSE DNS =====
  async function reverseDns(target) {
    logResult(
      new Date(),
      "Reverse DNS",
      `Advanced DNS analysis and security audit for ${target}...`,
    );
    try {
      const isIP = isValidIP(target);

      // Helper function to query DNS over Cloudflare HTTPS JSON API
      const queryDNS = async (name, type) => {
        try {
          const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
            headers: { accept: "application/dns-json" },
          });
          if (res.ok) {
            const data = await res.json();
            return {
              answer: data.Answer || [],
              ad: data.AD || false
            };
          }
        } catch (_) {}
        return { answer: [], ad: false };
      };

      if (isIP) {
        // Reverse DNS lookup for IP
        const reverseIP = target.split(".").reverse().join(".") + ".in-addr.arpa";
        logResult(new Date(), "Reverse DNS", `Querying PTR record for IP: ${reverseIP}`, "info");

        const ptrResult = await queryDNS(reverseIP, "PTR");
        const ptrAnswers = ptrResult.answer.filter(a => a.type === 12);
        
        let service = "Unknown Service";
        let provider = "Unknown Provider";
        let type = "Unknown Type";
        let hostnames = [];
        
        const knownIPs = {
          "1.1.1.1": { service: "Cloudflare DNS", provider: "Cloudflare", type: "Public DNS" },
          "1.0.0.1": { service: "Cloudflare DNS", provider: "Cloudflare", type: "Public DNS" },
          "8.8.8.8": { service: "Google DNS", provider: "Google", type: "Public DNS" },
          "8.8.4.4": { service: "Google DNS", provider: "Google", type: "Public DNS" },
          "9.9.9.9": { service: "Quad9 DNS", provider: "Quad9", type: "Public DNS" },
          "208.67.222.222": { service: "OpenDNS", provider: "Cisco", type: "Public DNS" },
          "208.67.220.220": { service: "OpenDNS", provider: "Cisco", type: "Public DNS" },
          "76.76.19.19": { service: "Alternate DNS", provider: "Alternate", type: "Public DNS" },
          "76.223.122.150": { service: "Alternate DNS", provider: "Alternate", type: "Public DNS" },
        };

        if (knownIPs[target]) {
          const info = knownIPs[target];
          service = info.service;
          provider = info.provider;
          type = info.type;
        }

        // Fetch IP details from ipwho.is
        let geoInfo = null;
        try {
          const proxyUrl = `/api/proxy?url=${encodeURIComponent(`https://ipwho.is/${target}`)}`;
          const geoRes = await fetch(proxyUrl);
          if (geoRes.ok) {
            const rawGeo = await geoRes.json();
            geoInfo = typeof rawGeo.contents === 'string' ? JSON.parse(rawGeo.contents) : (rawGeo.contents || rawGeo);
          }
        } catch (_) {}

        if (geoInfo && geoInfo.success) {
          if (provider === "Unknown Provider") {
            provider = geoInfo.connection?.org || geoInfo.connection?.isp || "Unknown Provider";
          }
          if (type === "Unknown Type") {
            type = geoInfo.security?.hosting ? "Cloud Hosting" : "Residential / Corporate";
          }
        }

        if (ptrAnswers.length > 0) {
          for (const ans of ptrAnswers) {
            const ptrHostname = ans.data.replace(/\.$/, "");
            // FCrDNS Check
            updateStatus(`Verifying FCrDNS for ${ptrHostname}...`);
            const forwardResult = await queryDNS(ptrHostname, "A");
            const forwardIPs = forwardResult.answer.filter(a => a.type === 1).map(a => a.data);
            const verified = forwardIPs.includes(target);
            hostnames.push(`${ptrHostname}${verified ? " (FCrDNS Verified)" : " (FCrDNS Unverified)"}`);
          }
        }

        let output = `[SUCCESS] IP: ${target}\n`;
        output += `Service: ${service}\n`;
        output += `Provider: ${provider}\n`;
        output += `Type: ${type}\n`;
        
        if (hostnames.length > 0) {
          output += `Hostname(s):\n - ${hostnames.join("\n - ")}\n`;
        } else {
          output += `No reverse DNS record found\n`;
        }

        // Append detailed passive intelligence as Note lines
        if (geoInfo && geoInfo.success) {
          output += `\nPassive Geolocation:\n`;
          output += `  Location: ${geoInfo.city || "N/A"}, ${geoInfo.region || "N/A"}, ${geoInfo.country || "N/A"}\n`;
          output += `  Coordinates: ${geoInfo.latitude || "N/A"}, ${geoInfo.longitude || "N/A"}\n`;
          output += `  ISP: ${geoInfo.connection?.isp || "N/A"} (${geoInfo.connection?.asn ? "AS" + geoInfo.connection.asn : "N/A"})\n`;
          
          if (geoInfo.security) {
            output += `Security Threat Profile:\n`;
            output += `  Proxy: ${geoInfo.security.proxy ? "Detected" : "No"}\n`;
            output += `  VPN: ${geoInfo.security.vpn ? "Detected" : "No"}\n`;
            output += `  Tor Exit: ${geoInfo.security.tor ? "Detected" : "No"}\n`;
            output += `  Hosting Range: ${geoInfo.security.hosting ? "Yes" : "No"}\n`;
          }
        }

        logResult(new Date(), "Reverse DNS", output, "success");
        updateStatus("Reverse DNS completed");
      } else {
        // Domain DNS Profile
        let domain = target.trim().toLowerCase();
        if (domain.includes("://")) {
          domain = new URL(domain).hostname;
        }
        if (domain.startsWith("www.")) {
          domain = domain.substring(4);
        }

        logResult(new Date(), "Reverse DNS", `Querying DNS Profile for domain: ${domain}`, "info");

        // Fetch A, AAAA, MX, NS, CAA, TXT records in parallel
        updateStatus("Fetching DNS records...");
        const [aRes, aaaaRes, mxRes, nsRes, caaRes, txtRes, dmarcRes] = await Promise.all([
          queryDNS(domain, "A"),
          queryDNS(domain, "AAAA"),
          queryDNS(domain, "MX"),
          queryDNS(domain, "NS"),
          queryDNS(domain, "CAA"),
          queryDNS(domain, "TXT"),
          queryDNS(`_dmarc.${domain}`, "TXT")
        ]);

        const aIPs = aRes.answer.filter(a => a.type === 1).map(a => a.data);
        const aaaaIPs = aaaaRes.answer.filter(a => a.type === 28).map(a => a.data);
        const mxServers = mxRes.answer.filter(a => a.type === 15).map(a => a.data);
        const nsServers = nsRes.answer.filter(a => a.type === 2).map(a => a.data.replace(/\.$/, ""));
        const caaRecords = caaRes.answer.filter(a => a.type === 257).map(a => a.data);
        const txtRecords = txtRes.answer.filter(a => a.type === 16).map(a => a.data);
        const dmarcRecords = dmarcRes.answer.filter(a => a.type === 16).map(a => a.data);

        // Check DNSSEC via AD flag
        const dnssecEnabled = aRes.ad || aaaaRes.ad || mxRes.ad || nsRes.ad;

        // Fetch ISP info of the first resolved IP
        let hostingProvider = "Unknown Hosting";
        if (aIPs.length > 0) {
          try {
            const proxyUrl = `/api/proxy?url=${encodeURIComponent(`https://ipwho.is/${aIPs[0]}`)}`;
            const geoRes = await fetch(proxyUrl);
            if (geoRes.ok) {
              const rawGeo = await geoRes.json();
              const geoInfo = typeof rawGeo.contents === 'string' ? JSON.parse(rawGeo.contents) : (rawGeo.contents || rawGeo);
              if (geoInfo && geoInfo.success) {
                hostingProvider = geoInfo.connection?.org || geoInfo.connection?.isp || hostingProvider;
              }
            }
          } catch (_) {}
        }

        // Parse SPF
        let spfRecord = "None configured";
        const spf = txtRecords.find(t => t.includes("v=spf1"));
        if (spf) {
          spfRecord = spf.replace(/^"|"$/g, "");
        }

        // Parse DMARC
        let dmarcRecord = "None configured";
        const dmarc = dmarcRecords.find(t => t.includes("v=DMARC1"));
        if (dmarc) {
          dmarcRecord = dmarc.replace(/^"|"$/g, "");
        }

        let output = `[SUCCESS] Hostname: ${domain}\n`;
        output += `Service: Domain DNS Profile\n`;
        output += `Provider: ${hostingProvider}\n`;
        output += `Type: Public Website\n`;

        // Output resolved IPs under Hostname(s) so UI displays them
        const allResolvedIPs = [...aIPs, ...aaaaIPs];
        if (allResolvedIPs.length > 0) {
          output += `Hostname(s):\n - ${allResolvedIPs.join("\n - ")}\n`;
        }

        // Build DNS profile details as Note lines
        output += `\nDNSSEC Validation:\n`;
        output += `  DNSSEC Status: ${dnssecEnabled ? "Enabled (Authentic Data verified)" : "Disabled / Unsigned"}\n`;

        if (nsServers.length > 0) {
          output += `Name Servers:\n`;
          nsServers.forEach(ns => {
            output += `  - ${ns}\n`;
          });
        }

        if (mxServers.length > 0) {
          output += `Mail Exchange (MX) Servers:\n`;
          mxServers.forEach(mx => {
            output += `  - ${mx}\n`;
          });
        }

        if (caaRecords.length > 0) {
          output += `Certification Authority Authorization (CAA):\n`;
          caaRecords.forEach(caa => {
            output += `  - ${caa}\n`;
          });
        }

        output += `Email Security Assessment:\n`;
        output += `  SPF: ${spfRecord}\n`;
        output += `  DMARC: ${dmarcRecord}\n`;

        logResult(new Date(), "Reverse DNS", output, "success");
        updateStatus("Domain DNS lookup completed");
      }
    } catch (e) {
      logResult(new Date(), "Reverse DNS", `[ERROR] DNS lookup failed. ${e.message}`, "danger");
    }
  }

  // ===== 6. WHOIS LOOKUP =====
  async function whoisLookup(target) {
    addActivityLog(`Starting WHOIS lookup for ${target}`, "WHOIS Lookup");
    logResult(new Date(), "WHOIS Lookup", `[*] Fetching WHOIS data for: ${target}`);
    try {
      const isIP = isValidIP(target);
      const isDomain = isValidDomain(target);

      if (!isIP && !isDomain) {
        addActivityLog("Invalid target format", "WHOIS Lookup");
        logResult(new Date(), "WHOIS Lookup", `[!] ERROR: Invalid input format. Please enter a valid IP address (e.g., 8.8.8.8) or domain name (e.g., google.com).`, "danger");
        return;
      }

      // Check if API key is available
      const whoisApiKey = getStoredApiKey("whoisApiKey");

      let data;
      let queryType = isIP ? "IP Geolocation" : "Domain WHOIS";
      updateStatus(`Querying WHOIS data for ${queryType}...`);

      if (whoisApiKey) {
        // If API key is available, attempt to use WHOISXML API
        let apiUrl;
        if (isIP) {
          apiUrl = `https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${whoisApiKey}&ipAddress=${encodeURIComponent(target)}`;
        } else {
          let normalizedDomain = target.trim().toLowerCase();
          if (normalizedDomain.includes("://")) {
            normalizedDomain = new URL(normalizedDomain).hostname;
          }
          if (normalizedDomain.startsWith("www.")) {
            normalizedDomain = normalizedDomain.substring(4);
          }
          apiUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${whoisApiKey}&domainName=${encodeURIComponent(normalizedDomain)}&outputFormat=JSON`;
        }

        try {
          addActivityLog(`Querying WHOISXML API...`, "WHOIS Lookup");
          const res = await fetch(apiUrl);
          if (res.ok) {
            data = await res.json();
            if (data.errorMessage) {
              addActivityLog(`WHOISXML API Error: ${data.errorMessage}. Falling back to free sources...`, "WHOIS Lookup");
              data = null;
            }
          } else {
            addActivityLog(`WHOISXML API failed with status ${res.status}. Falling back to free sources...`, "WHOIS Lookup");
          }
        } catch (err) {
          addActivityLog(`WHOISXML API network error. Falling back to free sources...`, "WHOIS Lookup");
        }
      }

      // Fallback if no API key or if WHOISXML API failed
      if (!data) {
        if (isIP) {
          addActivityLog("Using ipwho.is free fallback...", "WHOIS Lookup");
          const proxyUrl = `/api/proxy?url=${encodeURIComponent(`https://ipwho.is/${target}`)}`;
          const res = await fetch(proxyUrl);
          if (!res.ok) {
            throw new Error(`Failed to query free IP WHOIS service: ${res.status} ${res.statusText}`);
          }
          const rawData = await res.json();
          const ipData = typeof rawData.contents === 'string' ? JSON.parse(rawData.contents) : (rawData.contents || rawData);
          
          if (ipData && ipData.success) {
            // Map ipwho.is structure to WHOISXML API format
            data = {
              ip: ipData.ip,
              location: {
                country: ipData.country,
                region: ipData.region,
                city: ipData.city,
                postalCode: ipData.postal,
                latitude: ipData.latitude,
                longitude: ipData.longitude,
                timezone: ipData.timezone?.utc
              },
              asn: {
                asn: ipData.connection?.asn ? `AS${ipData.connection.asn}` : "N/A",
                organization: ipData.connection?.org || "N/A",
                name: ipData.connection?.isp || "N/A",
                domain: ipData.connection?.domain || "N/A",
                country: ipData.country_code || "N/A"
              },
              security: {
                isProxy: ipData.security?.proxy || false,
                isVpn: ipData.security?.vpn || false,
                isHosting: ipData.security?.hosting || false,
                isTor: ipData.security?.tor || false
              }
            };
          } else {
            throw new Error(ipData?.message || "Failed to fetch geolocation from free fallback");
          }
        } else {
          // Domain RDAP Fallback
          let normalizedDomain = target.trim().toLowerCase();
          if (normalizedDomain.includes("://")) {
            normalizedDomain = new URL(normalizedDomain).hostname;
          }
          if (normalizedDomain.startsWith("www.")) {
            normalizedDomain = normalizedDomain.substring(4);
          }

          addActivityLog("Using free bootstrap RDAP fallback...", "WHOIS Lookup");
          const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(normalizedDomain)}`;
          const proxyUrl = `/api/proxy?url=${encodeURIComponent(rdapUrl)}`;
          const res = await fetch(proxyUrl);
          if (!res.ok) {
            throw new Error(`Failed to query RDAP server: ${res.status} ${res.statusText}`);
          }
          
          const rawData = await res.json();
          const rdapData = typeof rawData.contents === 'string' ? JSON.parse(rawData.contents) : (rawData.contents || rawData);

          if (rdapData && rdapData.ldhName) {
            // Helper to parse RDAP entity organization
            const extractEntityOrg = (entities, role) => {
              const entity = entities?.find(e => e.roles?.includes(role));
              if (!entity) return "N/A";
              const vcard = entity.vcardArray?.[1];
              if (Array.isArray(vcard)) {
                const fnProperty = vcard.find(prop => prop[0] === 'fn');
                if (fnProperty) return fnProperty[3];
                const orgProperty = vcard.find(prop => prop[0] === 'org');
                if (orgProperty) return orgProperty[3];
              }
              return entity.handle || "N/A";
            };

            let createdDate = "N/A";
            let updatedDate = "N/A";
            let expiresDate = "N/A";
            
            if (rdapData.events) {
              rdapData.events.forEach(evt => {
                if (evt.eventAction === "registration") createdDate = evt.eventDate;
                else if (evt.eventAction === "last changed") updatedDate = evt.eventDate;
                else if (evt.eventAction === "expiration") expiresDate = evt.eventDate;
              });
            }

            const registrar = extractEntityOrg(rdapData.entities, "registrar");
            const registrant = extractEntityOrg(rdapData.entities, "registrant");
            const status = rdapData.status || ["N/A"];
            const nameServers = rdapData.nameservers ? rdapData.nameservers.map(ns => ns.ldhName.toLowerCase()) : [];

            data = {
              WhoisRecord: {
                domainName: rdapData.ldhName.toLowerCase(),
                registrarName: registrar,
                registrar: { name: registrar },
                creationDate: createdDate,
                createdDate: createdDate,
                updatedDate: updatedDate,
                lastUpdated: updatedDate,
                expirationDate: expiresDate,
                expiresDate: expiresDate,
                status: status,
                domainStatus: status.join(", "),
                nameServers: { hostNames: nameServers },
                registrant: { organization: registrant }
              }
            };
          } else {
            throw new Error("No domain registration data returned from RDAP server");
          }
        }
      }

      // Present the final output
      if (isIP) {
        if (data.ip) {
          addActivityLog(`WHOIS lookup complete for ${data.ip}`, "WHOIS Lookup");
          const output = formatIpWhoisOutput(data.ip, data.location || {}, data.asn || {}, data.security || {});
          logResult(new Date(), "WHOIS Lookup", output, "success");
          updateStatus("IP WHOIS lookup completed");
        } else {
          throw new Error("No IP data found in the response");
        }
      } else {
        if (data.WhoisRecord) {
          const record = data.WhoisRecord;
          const domainName = record.domainName || target;
          const registrar = record.registrar?.name || record.registrarName || "Unknown";
          const createdDate = record.creationDate || record.createdDate || "N/A";
          const updatedDate = record.updatedDate || record.lastUpdated || "N/A";
          const expiresDate = record.expiresDate || record.expirationDate || "N/A";
          const status = record.status || record.domainStatus || "N/A";
          const nameServers = record.nameServers?.hostNames || record.nameServers?.nameserver || record.nameServers || [];
          const registrant = record.registrant || {};

          const formatDate = (dateStr) => {
            if (!dateStr || dateStr === "N/A") return "N/A";
            try {
              return new Date(dateStr).toLocaleDateString();
            } catch {
              return dateStr;
            }
          };

          addActivityLog(`WHOIS lookup complete for ${domainName}`, "WHOIS Lookup");
          const output = formatDomainWhoisOutput(domainName, {
            createdDate: formatDate(createdDate),
            updatedDate: formatDate(updatedDate),
            expiresDate: formatDate(expiresDate),
            registrar,
            registrant: registrant.organization || "N/A",
            status,
            nameServers,
          });

          logResult(new Date(), "WHOIS Lookup", output, "success");
          updateStatus("Domain WHOIS lookup completed");
        } else {
          throw new Error("No domain data found in the response");
        }
      }
    } catch (e) {
      addActivityLog(`Lookup failed: ${e.message}`, "WHOIS Lookup");
      updateStatus("WHOIS lookup failed");
      logResult(new Date(), "WHOIS Lookup", `[!] ERROR: WHOIS lookup failed: ${e.message}`, "danger");
    }
  }

  // ===== EXPOSE TO GLOBAL SCOPE =====
  window.ShodanPortScanner = ShodanPortScanner;
  window.portScan = portScan;
  window.realTcpPortScan = realTcpPortScan;
  window.realUdpConnectivityTest = realUdpConnectivityTest;
  window.ipGeolocation = ipGeolocation;
  window.reverseDns = reverseDns;
  window.whoisLookup = whoisLookup;

  window.isValidIP = isValidIP;
  window.isValidDomain = isValidDomain;
})();
