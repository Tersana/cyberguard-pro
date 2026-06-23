/**
 * Appearance Settings Tab Module
 * Handles application theme, sidebar options, and accent color selection
 */

class AppearanceSettings {
    constructor() {
        this.initialState = {
            theme: "dark",
            sidebarDefaultCollapsed: false,
            accentColor: "blue"
        };
        this.currentState = { ...this.initialState };
        this.isDirty = false;
        
        this.accents = {
            blue: { name: "Blue", primary: "#3b82f6", hover: "#60a5fa", muted: "rgba(59, 130, 246, 0.15)", dark: "#1d4ed8" },
            cyan: { name: "Cyan", primary: "#22d3ee", hover: "#06b6d4", muted: "rgba(34, 211, 238, 0.15)", dark: "#0891b2" },
            green: { name: "Green", primary: "#34d399", hover: "#059669", muted: "rgba(52, 211, 153, 0.15)", dark: "#047857" },
            crimson: { name: "Crimson", primary: "#fb7185", hover: "#f43f5e", muted: "rgba(251, 113, 133, 0.15)", dark: "#be123c" }
        };
    }

    init() {
        this.loadInitialData();
        this.renderForm();
        this.setupEventListeners();
        this.checkDirtyState();
    }

    loadInitialData() {
        const theme = localStorage.getItem("cyberguard_theme") || "dark";
        
        // Load sidebar default state
        const storedSidebar = localStorage.getItem("sidebarCollapsed");
        let sidebarCollapsed = false;
        if (storedSidebar !== null) {
            try { sidebarCollapsed = JSON.parse(storedSidebar); } catch(e) {}
        }
        
        const accentColor = localStorage.getItem("cyberguard_accent") || "blue";

        this.initialState = {
            theme: theme,
            sidebarDefaultCollapsed: !!sidebarCollapsed,
            accentColor: accentColor
        };
        this.currentState = { ...this.initialState };
        
        // Ensure initial accent is applied on startup
        this.applyAccent(this.currentState.accentColor);
    }

    renderForm() {
        const pane = document.getElementById("pane-appearance");
        if (!pane) return;

        // security-audit-ignore
        pane.innerHTML = `
            <form id="appearance-settings-form" class="space-y-6" onsubmit="return false;">
                <p class="text-sm text-slate-400 mb-6">
                    Customize the interface theme, colors, and layout configurations.
                </p>

                <!-- Theme Selection -->
                <div class="settings-form-group">
                    <label>Interface Theme</label>
                    <div class="grid grid-cols-3 gap-4 mt-2">
                        <!-- Dark theme -->
                        <label class="cyber-card p-4 flex flex-col items-center gap-3 cursor-pointer border border-white/5 bg-slate-900/20 hover:bg-slate-900/40 relative">
                            <input type="radio" name="theme-option" value="dark" class="absolute top-3 left-3 accent-blue-400" ${this.currentState.theme === "dark" ? "checked" : ""}>
                            <span class="material-symbols-outlined text-3xl text-blue-400 mt-2">dark_mode</span>
                            <span class="text-sm font-semibold text-white">Dark Theme</span>
                            <span class="text-[10px] text-slate-500">Default & Optimized</span>
                        </label>

                        <!-- Light theme -->
                        <label class="cyber-card p-4 flex flex-col items-center gap-3 cursor-pointer border border-white/5 bg-slate-900/20 hover:bg-slate-900/40 relative" style="opacity: 0.85;">
                            <input type="radio" name="theme-option" value="light" class="absolute top-3 left-3 accent-blue-400" ${this.currentState.theme === "light" ? "checked" : ""}>
                            <span class="material-symbols-outlined text-3xl text-amber-400 mt-2">light_mode</span>
                            <span class="text-sm font-semibold text-white">Light Theme</span>
                            <span class="text-[10px] text-slate-500">Experimental</span>
                        </label>

                        <!-- System theme -->
                        <label class="cyber-card p-4 flex flex-col items-center gap-3 cursor-pointer border border-white/5 bg-slate-900/20 hover:bg-slate-900/40 relative">
                            <input type="radio" name="theme-option" value="system" class="absolute top-3 left-3 accent-blue-400" ${this.currentState.theme === "system" ? "checked" : ""}>
                            <span class="material-symbols-outlined text-3xl text-sky-400 mt-2">desktop_windows</span>
                            <span class="text-sm font-semibold text-white">System Default</span>
                            <span class="text-[10px] text-slate-500">Syncs with OS</span>
                        </label>
                    </div>
                </div>

                <div class="settings-divider my-6" style="height: 1px; background-color: var(--cg-border);"></div>

                <!-- Accent Color Picker -->
                <div class="settings-form-group">
                    <label>Accent Color</label>
                    <p class="text-xs text-slate-400 mb-3">Choose the accent highlight color used for links, buttons, and badges.</p>
                    
                    <div class="theme-accent-picker">
                        ${Object.entries(this.accents).map(([key, item]) => `
                            <label class="theme-accent-option" title="${item.name}">
                                <input type="radio" name="accent-option" value="${key}" ${this.currentState.accentColor === key ? "checked" : ""}>
                                <span class="theme-accent-color-dot" style="background-color: ${item.primary}; display: block;"></span>
                            </label>
                        `).join('')}
                    </div>
                </div>

                <div class="settings-divider my-6" style="height: 1px; background-color: var(--cg-border);"></div>

                <!-- Sidebar Settings -->
                <div class="flex items-center justify-between p-4 rounded-xl border border-white/5 bg-slate-900/20">
                    <div class="space-y-1">
                        <h5 class="text-sm font-semibold text-white">Collapse Sidebar by Default</h5>
                        <p class="text-xs text-slate-400">Keep the navigation sidebar collapsed for a wider workspace on load.</p>
                    </div>
                    <label class="settings-switch">
                        <input type="checkbox" id="sidebar-collapse-opt" ${this.currentState.sidebarDefaultCollapsed ? "checked" : ""}>
                        <span class="settings-switch-slider"></span>
                    </label>
                </div>
            </form>
        `;
    }

    setupEventListeners() {
        const form = document.getElementById("appearance-settings-form");
        if (!form) return;

        const themeOptions = form.querySelectorAll('input[name="theme-option"]');
        const accentOptions = form.querySelectorAll('input[name="accent-option"]');
        const sidebarCollapseOpt = document.getElementById("sidebar-collapse-opt");

        // Theme choices
        themeOptions.forEach(opt => {
            opt.addEventListener("change", () => {
                this.currentState.theme = opt.value;
                this.checkDirtyState();
            });
        });

        // Accent choice
        accentOptions.forEach(opt => {
            opt.addEventListener("change", () => {
                this.currentState.accentColor = opt.value;
                this.checkDirtyState();
            });
        });

        // Sidebar defaults
        if (sidebarCollapseOpt) {
            sidebarCollapseOpt.addEventListener("change", () => {
                this.currentState.sidebarDefaultCollapsed = sidebarCollapseOpt.checked;
                this.checkDirtyState();
            });
        }
    }

    checkDirtyState() {
        const dirty = 
            this.currentState.theme !== this.initialState.theme ||
            this.currentState.accentColor !== this.initialState.accentColor ||
            this.currentState.sidebarDefaultCollapsed !== this.initialState.sidebarDefaultCollapsed;
            
        this.isDirty = dirty;
        
        document.dispatchEvent(new CustomEvent("settingsTabDirtyChange", {
            detail: { tabId: "appearance", isDirty: dirty }
        }));
    }

    applyAccent(accentKey) {
        const color = this.accents[accentKey];
        if (!color) return;

        const root = document.documentElement;
        
        // Dynamically override tokens variables in real-time
        root.style.setProperty("--cg-accent", color.primary);
        root.style.setProperty("--cg-accent-hover", color.hover);
        root.style.setProperty("--cg-accent-muted", color.muted);
        root.style.setProperty("--cg-accent-dark", color.dark);
        
        // Also update standard legacy variables if any elements use them
        root.style.setProperty("--purple-400", color.primary);
        root.style.setProperty("--purple-500", color.hover);
        root.style.setProperty("--purple-600", color.dark);
    }

    save() {
        try {
            // Persist preferences in localstorage
            localStorage.setItem("cyberguard_theme", this.currentState.theme);
            localStorage.setItem("cyberguard_accent", this.currentState.accentColor);
            localStorage.setItem("sidebarCollapsed", JSON.stringify(this.currentState.sidebarDefaultCollapsed));

            // Apply theme changes instantly
            if (this.currentState.theme === "light") {
                // mock Light theme overlay alert
                CyberNotify.alert("Light theme is experimental. Defaulting to cyber dark styles with new accents.", { type: "warning" });
            }

            this.applyAccent(this.currentState.accentColor);

            // Sync sidebar collapsed state immediately
            if (typeof window.setSidebarState === "function") {
                window.setSidebarState(this.currentState.sidebarDefaultCollapsed);
            } else {
                const sidebar = document.getElementById("sidebar");
                if (sidebar) {
                    if (this.currentState.sidebarDefaultCollapsed) {
                        sidebar.classList.add("sidebar-collapsed");
                    } else {
                        sidebar.classList.remove("sidebar-collapsed");
                    }
                }
            }

            // Reset initial state to current state
            this.initialState = { ...this.currentState };
            this.checkDirtyState();

            CyberNotify.alert("Appearance settings saved.", { type: "success" });
            return true;
        } catch (e) {
            console.error("Failed to save appearance settings:", e);
            CyberNotify.alert("Failed to save appearance configuration.", { type: "error" });
            return false;
        }
    }

    reset() {
        this.currentState = { ...this.initialState };
        this.renderForm();
        this.setupEventListeners();
        this.checkDirtyState();
        
        // Re-apply original active accent
        this.applyAccent(this.initialState.accentColor);
    }
}

// Bind to window
window.AppearanceSettings = new AppearanceSettings();
