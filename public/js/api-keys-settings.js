/**
 * API Keys Settings Tab Module
 * Handles displaying service states, entering new keys, bulk saving, and deletion.
 */

// Global escapeHtml helper to sanitize input and prevent injection
if (typeof window.escapeHtml !== "function") {
    window.escapeHtml = function(str) {
        if (!str) return "";
        return str.toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };
}
const escapeHtml = window.escapeHtml;

class ApiKeysSettings {
    constructor() {
        this.services = ['virustotal', 'abuseipdb', 'whoisxml', 'shodan', 'urlscan', 'ai_assistant'];
        this.initialState = {};
        this.currentState = {};
        this.keysData = {};
        this.isDirty = false;
        
        // Metadata for rendering each service card beautifully
        this.serviceMeta = {
            virustotal: {
                name: "VirusTotal",
                category: "Threat Intelligence",
                icon: "security",
                providerUrl: "https://www.virustotal.com/gui/my-apikey"
            },
            abuseipdb: {
                name: "AbuseIPDB",
                category: "IP Reputation",
                icon: "gpp_bad",
                providerUrl: "https://www.abuseipdb.com/api"
            },
            whoisxml: {
                name: "WhoisXML",
                category: "Domain Intelligence",
                icon: "dns",
                providerUrl: "https://whoisxmlapi.com/api"
            },
            shodan: {
                name: "Shodan",
                category: "Network Intelligence",
                icon: "router",
                providerUrl: "https://account.shodan.io/"
            },
            urlscan: {
                name: "URLScan.io",
                category: "URL Analysis",
                icon: "language",
                providerUrl: "https://urlscan.io/user/profile/"
            },
            ai_assistant: {
                name: "AI Assistant",
                category: "AI Copilot Scans",
                icon: "smart_toy",
                providerUrl: null
            }
        };
    }

    async init() {
        if (typeof showContainerLoading === "function") {
            showContainerLoading("#pane-api-keys", "Fetching API Key configurations...");
        }

        try {
            // Load keys from backend
            const data = await window.fetchUserApiKeys();
            this.keysData = data || {};

            // Initialize form states
            this.initialState = {};
            this.services.forEach(service => {
                this.initialState[service] = "";
            });
            this.currentState = { ...this.initialState };
            this.isDirty = false;

            this.renderForm();
            this.setupEventListeners();
            this.checkDirtyState();
        } catch (error) {
            console.error("[ApiKeysSettings] Failed to initialize API keys settings:", error);
            const pane = document.getElementById("pane-api-keys");
            if (pane) {
                pane.innerHTML = `
                    <div class="text-center py-16">
                        <span class="material-symbols-outlined text-red-500 text-4xl mb-4">error</span>
                        <h5 class="text-lg font-bold text-white mb-2">Failed to Load API Keys</h5>
                        <p class="text-xs text-slate-400 mb-6">An error occurred while loading your key configurations.</p>
                        <button type="button" id="api-keys-retry-btn" class="cyber-btn-primary px-6 py-2.5 rounded-lg text-sm font-semibold inline-flex items-center gap-2">
                            <span class="material-symbols-outlined" style="font-size: 1.1rem;">refresh</span>
                            Retry
                        </button>
                    </div>
                `;
                const retryBtn = document.getElementById("api-keys-retry-btn");
                if (retryBtn) {
                    retryBtn.addEventListener("click", () => this.init());
                }
            }
        }
    }

    renderForm() {
        const pane = document.getElementById("pane-api-keys");
        if (!pane) return;

        let cardsHTML = "";
        this.services.forEach(service => {
            const meta = this.serviceMeta[service];
            const keyInfo = this.keysData[service] || {};
            const hasKey = !!keyInfo.has_key;
            const masked = keyInfo.masked || "";
            const keyId = keyInfo.id || null;
            const isSystemDefault = (service === "ai_assistant" && hasKey && !keyId);

            // Determine badge HTML
            let badgeHTML = "";
            if (isSystemDefault) {
                badgeHTML = `<span class="bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10px] px-2 py-0.5 rounded-full font-medium ml-auto">System Default</span>`;
            } else if (hasKey) {
                badgeHTML = `<span class="bg-green-500/10 text-green-400 border border-green-500/20 text-[10px] px-2 py-0.5 rounded-full font-medium ml-auto">Configured</span>`;
            } else {
                badgeHTML = `<span class="bg-slate-500/10 text-slate-400 border border-slate-500/20 text-[10px] px-2 py-0.5 rounded-full font-medium ml-auto">Not Configured</span>`;
            }

            cardsHTML += `
                <div class="settings-section-card p-5 flex flex-col justify-between" style="margin-bottom: 0;">
                    <div>
                        <div class="flex items-center justify-between mb-4">
                            <div class="flex items-center gap-3">
                                <div class="w-8 h-8 rounded-lg bg-slate-800/80 border border-white/5 flex items-center justify-center text-blue-400">
                                    <span class="material-symbols-outlined text-lg">${meta.icon}</span>
                                </div>
                                <div>
                                    <h5 class="text-sm font-bold text-white">${meta.name}</h5>
                                    <p class="text-[11px] text-slate-400">${meta.category}</p>
                                </div>
                            </div>
                            ${badgeHTML}
                        </div>
                        
                        <!-- Masked Value & Actions -->
                        ${hasKey ? `
                        <div class="flex items-center justify-between bg-black/20 border border-white/5 rounded-lg p-2 mb-3">
                            <code class="text-xs font-mono text-slate-300 select-all">${escapeHtml(masked)}</code>
                            ${(!isSystemDefault && keyId) ? `
                            <button type="button" class="text-slate-400 hover:text-red-400 transition-colors p-1" data-delete="${service}" data-id="${keyId}" title="Delete API Key">
                                <span class="material-symbols-outlined text-base">delete</span>
                            </button>
                            ` : ""}
                        </div>
                        ` : ""}
                    </div>

                    <div class="mt-auto">
                        <!-- Input field -->
                        <div class="settings-form-group mb-0">
                            <div class="input-wrapper">
                                <input type="password" id="api-input-${service}" class="cyber-input p-2.5 rounded-lg text-xs" 
                                    placeholder="${hasKey ? 'Enter new key to update...' : 'Enter API key...'}" 
                                    value="${this.currentState[service]}">
                                <button type="button" class="toggle-pwd-btn" data-input="api-input-${service}">
                                    <span class="material-symbols-outlined text-sm">visibility</span>
                                </button>
                            </div>
                        </div>
                        
                        ${meta.providerUrl ? `
                        <div class="mt-2 text-right">
                            <a href="${meta.providerUrl}" target="_blank" class="text-[10px] text-blue-400 hover:text-blue-300 inline-flex items-center gap-0.5">
                                Get Key <span class="material-symbols-outlined" style="font-size: 0.75rem;">open_in_new</span>
                            </a>
                        </div>
                        ` : ""}
                    </div>
                </div>
            `;
        });

        pane.innerHTML = ` // security-audit-ignore
            <div class="space-y-6">
                <div>
                    <p class="text-sm text-slate-400 mb-4">
                        Configure third-party service keys for scans and threat intelligence integrations.
                    </p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    ${cardsHTML}
                </div>
            </div>
        `;
    }

    setupEventListeners() {
        const pane = document.getElementById("pane-api-keys");
        if (!pane) return;

        // 1. Password visibility toggle buttons
        const pwdToggles = pane.querySelectorAll(".toggle-pwd-btn");
        pwdToggles.forEach(btn => {
            btn.addEventListener("click", () => {
                const targetId = btn.getAttribute("data-input");
                const input = document.getElementById(targetId);
                if (input) {
                    const isPwd = input.type === "password";
                    input.type = isPwd ? "text" : "password";
                    btn.querySelector("span").textContent = isPwd ? "visibility_off" : "visibility";
                }
            });
        });

        // 2. Input change listeners
        this.services.forEach(service => {
            const input = document.getElementById(`api-input-${service}`);
            if (input) {
                input.addEventListener("input", () => {
                    this.currentState[service] = input.value;
                    this.checkDirtyState();
                });
            }
        });

        // 3. Delete button click handlers
        const deleteBtns = pane.querySelectorAll("[data-delete]");
        deleteBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                const service = btn.getAttribute("data-delete");
                const keyId = btn.getAttribute("data-id");
                if (keyId) {
                    if (window.CyberNotify && typeof window.CyberNotify.confirm === "function") {
                        window.CyberNotify.confirm(
                            `Are you sure you want to delete the ${this.serviceMeta[service].name} API key?`,
                            (confirmed) => {
                                if (confirmed) {
                                    this.deleteKey(keyId, service);
                                }
                            },
                            { type: "warning" }
                        );
                    } else {
                        if (confirm(`Are you sure you want to delete the ${this.serviceMeta[service].name} API key?`)) {
                            this.deleteKey(keyId, service);
                        }
                    }
                }
            });
        });
    }

    async deleteKey(keyId, service) {
        try {
            if (typeof showLoading === "function") {
                showLoading("Deleting API Key...");
            }

            const response = await window.apiClient.delete(`apiKeys/${keyId}`);

            if (window.CyberNotify) {
                window.CyberNotify.alert(response.message || "API Key deleted successfully", { type: "success" });
            } else {
                alert(response.message || "API Key deleted successfully");
            }

            // Reload memory cache and form
            await window.fetchUserApiKeys();
            await this.init();
        } catch (error) {
            console.error("[ApiKeysSettings] Delete key error:", error);
        } finally {
            if (typeof hideLoading === "function") {
                hideLoading();
            }
        }
    }

    checkDirtyState() {
        const dirty = this.services.some(service => this.currentState[service] !== this.initialState[service]);
        this.isDirty = dirty;

        document.dispatchEvent(new CustomEvent("settingsTabDirtyChange", {
            detail: { tabId: "api-keys", isDirty: dirty }
        }));
    }

    async save() {
        const keysToSubmit = {};
        let hasChanges = false;

        this.services.forEach(service => {
            if (this.currentState[service] !== this.initialState[service]) {
                keysToSubmit[service] = this.currentState[service];
                hasChanges = true;
            }
        });

        if (!hasChanges) return true;

        try {
            if (typeof showLoading === "function") {
                showLoading("Saving API Keys...");
            }

            const response = await window.apiClient.post("apiKeys", { keys: keysToSubmit });

            if (window.CyberNotify) {
                window.CyberNotify.alert(response.message || "API Keys Saved Or Updated Successfuly.", { type: "success" });
            } else {
                alert(response.message || "API Keys Saved Or Updated Successfuly.");
            }

            // Fetch and update cache, then re-initialize
            await window.fetchUserApiKeys();
            await this.init();
            return true;
        } catch (error) {
            console.error("[ApiKeysSettings] Save keys error:", error);
            return false;
        } finally {
            if (typeof hideLoading === "function") {
                hideLoading();
            }
        }
    }

    reset() {
        this.currentState = { ...this.initialState };
        this.renderForm();
        this.setupEventListeners();
        this.checkDirtyState();
    }
}

// Bind to window
window.ApiKeysSettings = new ApiKeysSettings();
