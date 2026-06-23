/**
 * Security Settings Tab Module
 * Handles Change Password, Two-Factor Authentication, and Active Sessions
 */

class SecuritySettings {
    constructor() {
        this.passwordState = {
            currentPassword: "",
            newPassword: "",
            confirmPassword: ""
        };
        this.isDirty = false;
        
        // 2FA state
        this.twoFactorEnabled = false;
        this.twofaSetupStep = 1; // 1 = show QR / secret, 2 = show verification code
        this.qrCode = "";
        this.secret = "";
        this.backupCodes = [];
        this.revealBackupCodes = false;
    }

    init() {
        this.passwordState = {
            currentPassword: "",
            newPassword: "",
            confirmPassword: ""
        };
        this.isDirty = false;
        
        // Fetch 2FA status from authManager
        const user = window.authManager.getCurrentUser() || {};
        this.twoFactorEnabled = !!user.twoFactorEnabled;

        // Load backup codes if enabled
        if (this.twoFactorEnabled) {
            this.loadBackupCodes();
        } else {
            this.backupCodes = [];
        }

        this.renderForm();
        this.setupEventListeners();
    }

    loadBackupCodes() {
        const storedCodes = localStorage.getItem("cyberguard_2fa_backup_codes");
        if (storedCodes) {
            this.backupCodes = JSON.parse(storedCodes);
        } else {
            this.generateBackupCodes();
        }
    }

    generateBackupCodes() {
        const codes = [];
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // clear ambiguous chars
        for (let i = 0; i < 8; i++) {
            let part1 = "";
            let part2 = "";
            for (let j = 0; j < 4; j++) {
                part1 += chars[Math.floor(Math.random() * chars.length)];
                part2 += chars[Math.floor(Math.random() * chars.length)];
            }
            codes.push(`${part1}-${part2}`);
        }
        this.backupCodes = codes;
        localStorage.setItem("cyberguard_2fa_backup_codes", JSON.stringify(codes));
    }

    renderForm() {
        const pane = document.getElementById("pane-security");
        if (!pane) return;

        // security-audit-ignore
        pane.innerHTML = `
            <div class="space-y-8">
                <!-- SECTION A: CHANGE PASSWORD -->
                <div class="settings-section-card">
                    <h5 class="settings-section-card-title">
                        <span class="material-symbols-outlined text-blue-400">lock</span>
                        Change Password
                    </h5>
                    
                    <form id="security-pwd-form" class="space-y-4" onsubmit="return false;">
                        <div class="settings-form-group">
                            <label for="pwd-current">Current Password</label>
                            <div class="input-wrapper">
                                <input type="password" id="pwd-current" class="cyber-input p-3 rounded-lg text-sm" value="${this.passwordState.currentPassword}" autocomplete="current-password">
                                <button type="button" class="toggle-pwd-btn" data-input="pwd-current">
                                    <span class="material-symbols-outlined">visibility</span>
                                </button>
                            </div>
                            <span id="error-pwd-current" class="text-xs text-red-400 mt-1 hidden"></span>
                        </div>

                        <div class="settings-form-row">
                            <div class="settings-form-group">
                                <label for="pwd-new">New Password</label>
                                <div class="input-wrapper">
                                    <input type="password" id="pwd-new" class="cyber-input p-3 rounded-lg text-sm" value="${this.passwordState.newPassword}" autocomplete="new-password">
                                    <button type="button" class="toggle-pwd-btn" data-input="pwd-new">
                                        <span class="material-symbols-outlined">visibility</span>
                                    </button>
                                </div>
                                <span id="error-pwd-new" class="text-xs text-red-400 mt-1 hidden"></span>
                                
                                <!-- Password Strength Indicator -->
                                <div class="settings-password-analyzer" id="pwd-analyzer-box">
                                    <div class="settings-password-bar-bg">
                                        <div class="settings-password-bar" id="pwd-strength-bar"></div>
                                    </div>
                                    <div class="settings-password-text-row">
                                        <span>Strength: <span id="pwd-strength-label" class="font-bold text-slate-500">None</span></span>
                                        <span id="pwd-entropy-label">0 bits</span>
                                    </div>
                                    <div class="settings-password-checks">
                                        <div class="settings-password-check-item" id="check-length">
                                            <span class="material-symbols-outlined" style="font-size: 1rem;">close</span>
                                            At least 8 characters
                                        </div>
                                        <div class="settings-password-check-item" id="check-upper">
                                            <span class="material-symbols-outlined" style="font-size: 1rem;">close</span>
                                            Uppercase letter
                                        </div>
                                        <div class="settings-password-check-item" id="check-lower">
                                            <span class="material-symbols-outlined" style="font-size: 1rem;">close</span>
                                            Lowercase letter
                                        </div>
                                        <div class="settings-password-check-item" id="check-number">
                                            <span class="material-symbols-outlined" style="font-size: 1rem;">close</span>
                                            Number
                                        </div>
                                        <div class="settings-password-check-item" id="check-symbol">
                                            <span class="material-symbols-outlined" style="font-size: 1rem;">close</span>
                                            Special character
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="settings-form-group">
                                <label for="pwd-confirm">Confirm New Password</label>
                                <div class="input-wrapper">
                                    <input type="password" id="pwd-confirm" class="cyber-input p-3 rounded-lg text-sm" value="${this.passwordState.confirmPassword}" autocomplete="new-password">
                                    <button type="button" class="toggle-pwd-btn" data-input="pwd-confirm">
                                        <span class="material-symbols-outlined">visibility</span>
                                    </button>
                                </div>
                                <span id="error-pwd-confirm" class="text-xs text-red-400 mt-1 hidden"></span>
                            </div>
                        </div>

                        <div class="flex justify-end pt-2">
                            <button type="button" id="pwd-save-btn" class="cyber-btn-primary py-2 px-4 rounded-lg font-semibold text-sm">
                                Update Password
                            </button>
                        </div>
                    </form>
                </div>

                <!-- SECTION B: TWO-FACTOR AUTHENTICATION -->
                <div class="settings-section-card">
                    <h5 class="settings-section-card-title">
                        <span class="material-symbols-outlined text-blue-400">verified_user</span>
                        Two-Factor Authentication (2FA)
                        <span id="2fa-status-badge" class="cyber-badge-${this.twoFactorEnabled ? 'success' : 'danger'} text-xs font-semibold px-2.5 py-0.5 rounded-full ml-auto">
                            ${this.twoFactorEnabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </h5>

                    <!-- Status Display -->
                    <div id="2fa-main-panel" class="space-y-4">
                        ${this.twoFactorEnabled ? `
                            <p class="text-sm text-slate-300">
                                Your account is secured with two-factor authentication. You'll need to enter verification codes from your authenticator app to sign in.
                            </p>
                            <div class="flex gap-4">
                                <button type="button" id="settings-2fa-disable-trigger" class="cyber-btn-danger text-xs py-2 px-4 rounded-lg flex items-center gap-1.5">
                                    <span class="material-symbols-outlined" style="font-size: 1.1rem;">no_encryption</span>
                                    Disable 2FA
                                </button>
                            </div>

                            <!-- Backup Codes Section -->
                            <div class="settings-backup-codes-box">
                                <div class="flex items-center justify-between border-b border-white/5 pb-2 mb-3">
                                    <h6 class="text-xs font-bold text-white uppercase tracking-wider">Recovery Backup Codes</h6>
                                    <div class="flex gap-2">
                                        <button type="button" id="backup-reveal-btn" class="cyber-btn-ghost text-xs py-1 px-2.5 rounded-lg flex items-center gap-1">
                                            <span class="material-symbols-outlined" style="font-size: 0.9rem;">${this.revealBackupCodes ? 'visibility_off' : 'visibility'}</span>
                                            ${this.revealBackupCodes ? 'Hide' : 'Reveal'}
                                        </button>
                                        <button type="button" id="backup-regenerate-btn" class="cyber-btn-ghost text-xs py-1 px-2.5 rounded-lg flex items-center gap-1">
                                            <span class="material-symbols-outlined" style="font-size: 0.9rem;">refresh</span>
                                            Regenerate
                                        </button>
                                    </div>
                                </div>
                                <p class="text-xs text-slate-400 mb-3">
                                    Store these recovery codes in a safe place. They can be used to access your account if you lose your authenticator app.
                                </p>
                                <div class="settings-backup-codes-grid">
                                    ${this.backupCodes.map(code => `
                                        <div class="settings-backup-code-item">
                                            ${this.revealBackupCodes ? code : '••••-••••'}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        ` : `
                            <p class="text-sm text-slate-300 mb-4">
                                Two-factor authentication adds an extra layer of security by requiring a verification code when logging in.
                            </p>
                            <button type="button" id="settings-2fa-enable-trigger" class="cyber-btn-primary text-xs py-2 px-4 rounded-lg flex items-center gap-1.5">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">shield</span>
                                Enable 2FA
                            </button>
                        `}
                    </div>

                    <!-- Setup Inline Container -->
                    <div id="2fa-setup-inline-panel" class="hidden border-t border-white/5 pt-5 mt-4 space-y-6">
                        <div class="flex items-center justify-between">
                            <h6 class="text-sm font-bold text-white">Setup Authenticator App</h6>
                            <button type="button" id="2fa-setup-cancel" class="text-xs text-slate-400 hover:text-white">Cancel</button>
                        </div>

                        <!-- QR Scan step -->
                        <div class="flex gap-6 items-start">
                            <div class="bg-white p-3 rounded-lg inline-block flex-shrink-0" id="2fa-qr-inline-box">
                                <div class="w-40 h-40 flex items-center justify-center text-slate-800 text-xs font-semibold">
                                    Loading QR...
                                </div>
                            </div>
                            <div class="space-y-4 flex-1">
                                <p class="text-xs text-slate-300 leading-relaxed">
                                    Scan this QR code with an authenticator app (Google Authenticator, Authy, Microsoft Authenticator).
                                </p>
                                <div class="bg-black/20 border border-white/5 rounded-lg p-3">
                                    <p class="text-[10px] font-bold text-slate-400 mb-1">Manual secret key:</p>
                                    <div class="flex items-center gap-2">
                                        <code class="text-xs font-mono text-white flex-1 select-all" id="2fa-secret-inline-code"></code>
                                        <button type="button" id="copy-secret-inline-btn" class="p-1 text-slate-400 hover:text-white">
                                            <span class="material-symbols-outlined" style="font-size: 1.1rem;">content_copy</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Verification Input -->
                        <div class="border-t border-white/5 pt-4">
                            <label for="2fa-code-input" class="block text-xs font-bold text-slate-300 mb-2">Enter Verification Code:</label>
                            <div class="flex gap-3">
                                <input type="text" id="2fa-code-input" class="cyber-input p-2.5 rounded-lg text-center tracking-widest text-lg font-mono flex-1" placeholder="000000" maxlength="6" inputmode="numeric">
                                <button type="button" id="2fa-code-submit-btn" class="cyber-btn-primary px-6 rounded-lg font-bold text-xs">Verify & Enable</button>
                            </div>
                            <span id="2fa-code-inline-error" class="text-xs text-red-400 mt-2 block hidden"></span>
                        </div>
                    </div>
                </div>

                <!-- SECTION C: ACTIVE SESSIONS -->
                <div class="settings-section-card">
                    <h5 class="settings-section-card-title">
                        <span class="material-symbols-outlined text-blue-400">devices</span>
                        Active Sessions
                        <span class="coming-soon-badge">Coming Soon</span>
                    </h5>
                    <p class="text-sm text-slate-400 mb-4">
                        This is a list of devices that have logged into your account. You can log out of other active sessions.
                    </p>

                    <div class="settings-device-list">
                        <!-- Current Session (Windows) -->
                        <div class="settings-device-item">
                            <div class="settings-device-icon">
                                <span class="material-symbols-outlined">desktop_windows</span>
                            </div>
                            <div class="settings-device-info">
                                <div class="flex items-center gap-2">
                                    <span class="text-sm font-semibold text-white">Chrome on Windows 11</span>
                                    <span class="cyber-badge-success text-[10px] px-2 py-0.5 rounded-full font-medium">Current Session</span>
                                </div>
                                <div class="settings-device-meta">
                                    <span>IP: 197.34.120.5</span>
                                    <span>•</span>
                                    <span>Cairo, Egypt</span>
                                    <span>•</span>
                                    <span>Active now</span>
                                </div>
                            </div>
                        </div>

                        <!-- Mock Session (Mobile) -->
                        <div class="settings-device-item">
                            <div class="settings-device-icon">
                                <span class="material-symbols-outlined">smartphone</span>
                            </div>
                            <div class="settings-device-info">
                                <div class="flex items-center gap-2">
                                    <span class="text-sm font-semibold text-slate-300">Safari on iPhone 15</span>
                                </div>
                                <div class="settings-device-meta">
                                    <span>IP: 197.34.120.12</span>
                                    <span>•</span>
                                    <span>Cairo, Egypt</span>
                                    <span>•</span>
                                    <span>2 hours ago</span>
                                </div>
                            </div>
                            <button type="button" class="cyber-btn-ghost text-xs py-1.5 px-3 rounded-lg" style="opacity: 0.5; cursor: not-allowed;" disabled>Revoke</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Custom 2FA Disable Modal -->
            <div id="settings-2fa-disable-dialog" class="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center z-[100] hidden">
                <div class="cyber-modal max-w-sm w-full mx-4 p-6">
                    <h5 class="text-base font-bold text-white mb-2">Disable 2FA Confirmation</h5>
                    <p class="text-xs text-slate-400 mb-4">Please type your current 6-digit verification code to disable Two-Factor Authentication.</p>
                    
                    <div class="mb-4">
                        <input type="text" id="2fa-disable-modal-code" class="cyber-input p-2 rounded-lg text-center font-mono tracking-widest text-base w-full" placeholder="000000" maxlength="6" inputmode="numeric">
                        <span id="2fa-disable-modal-error" class="text-xs text-red-400 mt-2 block hidden"></span>
                    </div>

                    <div class="flex gap-3">
                        <button type="button" id="2fa-disable-modal-confirm" class="cyber-btn-danger flex-1 py-2 rounded-lg text-xs font-semibold">Disable 2FA</button>
                        <button type="button" id="2fa-disable-modal-cancel" class="btn-cancel flex-1 py-2 rounded-lg text-xs font-semibold">Cancel</button>
                    </div>
                </div>
            </div>
        `;
    }

    setupEventListeners() {
        const pane = document.getElementById("pane-security");
        if (!pane) return;

        // 1. Password show/hide toggle buttons
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

        // 2. Real-time Password Strength Meter
        const pwdNew = document.getElementById("pwd-new");
        const pwdConfirm = document.getElementById("pwd-confirm");
        const pwdCurrent = document.getElementById("pwd-current");

        if (pwdNew) {
            pwdNew.addEventListener("input", () => {
                const pwd = pwdNew.value;
                this.passwordState.newPassword = pwd;
                this.checkDirtyState();
                this.updateStrengthMeter(pwd);
            });
        }

        if (pwdConfirm) {
            pwdConfirm.addEventListener("input", () => {
                this.passwordState.confirmPassword = pwdConfirm.value;
                this.checkDirtyState();
                
                // Clear mismatches error dynamically if matching
                const errorConfirm = document.getElementById("error-pwd-confirm");
                if (this.passwordState.newPassword === this.passwordState.confirmPassword) {
                    if (errorConfirm) {
                        errorConfirm.classList.add("hidden");
                        errorConfirm.textContent = "";
                    }
                }
            });
        }

        if (pwdCurrent) {
            pwdCurrent.addEventListener("input", () => {
                this.passwordState.currentPassword = pwdCurrent.value;
                this.checkDirtyState();
            });
        }

        // 3. Save password submit
        const savePwdBtn = document.getElementById("pwd-save-btn");
        if (savePwdBtn) {
            savePwdBtn.addEventListener("click", () => this.savePassword());
        }

        // 4. Two-Factor Authentication Triggers
        const enableTrigger = document.getElementById("settings-2fa-enable-trigger");
        const disableTrigger = document.getElementById("settings-2fa-disable-trigger");
        const cancelSetup = document.getElementById("2fa-setup-cancel");
        const submitCode = document.getElementById("2fa-code-submit-btn");

        if (enableTrigger) {
            enableTrigger.addEventListener("click", () => this.start2FASetup());
        }

        if (disableTrigger) {
            disableTrigger.addEventListener("click", () => this.show2FADisableDialog());
        }

        if (cancelSetup) {
            cancelSetup.addEventListener("click", () => {
                document.getElementById("2fa-setup-inline-panel").classList.add("hidden");
                document.getElementById("2fa-main-panel").classList.remove("hidden");
            });
        }

        if (submitCode) {
            submitCode.addEventListener("click", () => this.submitVerificationCode());
        }

        // Copy secret code in 2FA Setup
        const copyBtn = document.getElementById("copy-secret-inline-btn");
        if (copyBtn) {
            copyBtn.addEventListener("click", () => {
                const code = document.getElementById("2fa-secret-inline-code").textContent;
                navigator.clipboard.writeText(code).then(() => {
                    const originalIcon = copyBtn.innerHTML;
                    copyBtn.innerHTML = '<span class="material-symbols-outlined text-green-400" style="font-size: 1.1rem;">check</span>';
                    setTimeout(() => { copyBtn.innerHTML = originalIcon; }, 2000);
                });
            });
        }

        // Backup codes Reveal
        const revealBtn = document.getElementById("backup-reveal-btn");
        if (revealBtn) {
            revealBtn.addEventListener("click", () => {
                this.revealBackupCodes = !this.revealBackupCodes;
                this.init(); // re-render to update masking
            });
        }

        // Backup codes Regenerate
        const regenerateBtn = document.getElementById("backup-regenerate-btn");
        if (regenerateBtn) {
            regenerateBtn.addEventListener("click", () => {
                this.generateBackupCodes();
                this.init();
                CyberNotify.alert("Regenerated 2FA backup codes.", { type: "success" });
            });
        }
    }

    updateStrengthMeter(password) {
        const bar = document.getElementById("pwd-strength-bar");
        const label = document.getElementById("pwd-strength-label");
        const entropyLabel = document.getElementById("pwd-entropy-label");
        
        if (!password) {
            if (bar) bar.className = "settings-password-bar";
            if (label) { label.textContent = "None"; label.className = "font-bold text-slate-500"; }
            if (entropyLabel) entropyLabel.textContent = "0 bits";
            this.updateRequirementChecklists("");
            return;
        }

        // Compute using existing strength check in authManager
        const result = window.authManager.checkPasswordStrength(password);
        const strength = result.strength; // 'weak', 'fair', 'good', 'strong'
        
        // Calculate exact entropy bits
        let poolSize = 0;
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/[0-9]/.test(password)) poolSize += 10;
        if (/[^A-Za-z0-9]/.test(password)) poolSize += 32;
        
        const entropy = Math.round(password.length * Math.log2(poolSize || 1));

        // Update bar classes
        if (bar) {
            bar.className = `settings-password-bar ${strength}`;
        }

        // Update labels
        if (label) {
            label.textContent = strength.toUpperCase();
            if (strength === "weak") label.className = "font-bold text-red-400";
            else if (strength === "fair") label.className = "font-bold text-amber-400";
            else if (strength === "good") label.className = "font-bold text-sky-400";
            else label.className = "font-bold text-green-400";
        }

        if (entropyLabel) {
            entropyLabel.textContent = `${entropy} bits`;
        }

        // Update requirement checks list icons
        this.updateRequirementChecklists(password, result.checks);
    }

    updateRequirementChecklists(password, checks = {}) {
        const checkItems = {
            length: document.getElementById("check-length"),
            upper: document.getElementById("check-upper"),
            lower: document.getElementById("check-lower"),
            number: document.getElementById("check-number"),
            symbol: document.getElementById("check-symbol")
        };

        const validations = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            symbol: /[^a-zA-Z0-9]/.test(password)
        };

        for (const [key, el] of Object.entries(checkItems)) {
            if (!el) continue;
            const isValid = validations[key];
            
            if (isValid) {
                el.classList.add("valid");
                el.querySelector("span").textContent = "check";
            } else {
                el.classList.remove("valid");
                el.querySelector("span").textContent = "close";
            }
        }
    }

    checkDirtyState() {
        const dirty = 
            this.passwordState.currentPassword.length > 0 ||
            this.passwordState.newPassword.length > 0 ||
            this.passwordState.confirmPassword.length > 0;
            
        this.isDirty = dirty;
        
        document.dispatchEvent(new CustomEvent("settingsTabDirtyChange", {
            detail: { tabId: "security", isDirty: dirty }
        }));
    }

    savePassword() {
        const errorCurrent = document.getElementById("error-pwd-current");
        const errorNew = document.getElementById("error-pwd-new");
        const errorConfirm = document.getElementById("error-pwd-confirm");

        // Clear previous error messages
        [errorCurrent, errorNew, errorConfirm].forEach(el => {
            if (el) { el.classList.add("hidden"); el.textContent = ""; }
        });

        let hasError = false;

        if (!this.passwordState.currentPassword) {
            if (errorCurrent) {
                errorCurrent.textContent = "Current password is required.";
                errorCurrent.classList.remove("hidden");
            }
            hasError = true;
        }

        if (!this.passwordState.newPassword) {
            if (errorNew) {
                errorNew.textContent = "New password is required.";
                errorNew.classList.remove("hidden");
            }
            hasError = true;
        } else {
            // Validate new password rules: min 8, strength >= "good"
            const result = window.authManager.checkPasswordStrength(this.passwordState.newPassword);
            if (this.passwordState.newPassword.length < 8) {
                if (errorNew) {
                    errorNew.textContent = "Password must be at least 8 characters.";
                    errorNew.classList.remove("hidden");
                }
                hasError = true;
            } else if (result.strength === "weak" || result.strength === "fair") {
                if (errorNew) {
                    errorNew.textContent = "New password strength must be 'Good' or 'Strong'.";
                    errorNew.classList.remove("hidden");
                }
                hasError = true;
            }
        }

        if (this.passwordState.newPassword !== this.passwordState.confirmPassword) {
            if (errorConfirm) {
                errorConfirm.textContent = "Passwords do not match.";
                errorConfirm.classList.remove("hidden");
            }
            hasError = true;
        }

        if (hasError) return false;

        // Simulated backend password change
        CyberNotify.alert("Password updated successfully.", { type: "success" });
        
        // Reset password fields
        this.passwordState = { currentPassword: "", newPassword: "", confirmPassword: "" };
        this.isDirty = false;
        
        // Clear DOM values
        document.getElementById("pwd-current").value = "";
        document.getElementById("pwd-new").value = "";
        document.getElementById("pwd-confirm").value = "";
        this.updateStrengthMeter("");
        
        this.checkDirtyState();
        return true;
    }

    /* ── Two-Factor Authentication Inline Flow ── */
    
    async start2FASetup() {
        try {
            const setupPanel = document.getElementById("2fa-setup-inline-panel");
            const mainPanel = document.getElementById("2fa-main-panel");
            const qrBox = document.getElementById("2fa-qr-inline-box");
            const secretCode = document.getElementById("2fa-secret-inline-code");
            const codeInput = document.getElementById("2fa-code-input");
            const errorLabel = document.getElementById("2fa-code-inline-error");

            if (errorLabel) errorLabel.classList.add("hidden");
            if (codeInput) codeInput.value = "";

            // Show setup panel
            mainPanel.classList.add("hidden");
            setupPanel.classList.remove("hidden");
            qrBox.innerHTML = '<div class="text-slate-400 text-xs text-center py-10">Loading QR...</div>';
            secretCode.textContent = "Loading...";

            // Call authManager QR Setup
            const response = await window.authManager.setup2FA();
            
            if (response.success) {
                secretCode.textContent = response.secret || "";
                this.secret = response.secret || "";

                let qrSrc = response.qrCode || "";
                if (qrSrc && !qrSrc.startsWith("data:") && !qrSrc.startsWith("http")) {
                    qrSrc = `data:image/png;base64,${qrSrc}`;
                }

                if (qrSrc) {
                    qrBox.innerHTML = `<img src="${escapeHtml(qrSrc)}" alt="QR code" class="w-40 h-40">`;
                } else {
                    qrBox.innerHTML = `
                        <div class="text-amber-500 text-xs text-center p-3">
                            QR image error. Use manual secret key.
                        </div>`;
                }
            } else {
                throw new Error("Unable to initialize 2FA Setup");
            }
        } catch (e) {
            console.error("2FA setup error:", e);
            document.getElementById("2fa-setup-inline-panel").classList.add("hidden");
            document.getElementById("2fa-main-panel").classList.remove("hidden");
            CyberNotify.alert("Failed to start 2FA setup.", { type: "error" });
        }
    }

    async submitVerificationCode() {
        const input = document.getElementById("2fa-code-input");
        const code = input ? input.value.trim() : "";
        const errorLabel = document.getElementById("2fa-code-inline-error");

        if (errorLabel) {
            errorLabel.classList.add("hidden");
            errorLabel.textContent = "";
        }

        if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
            if (errorLabel) {
                errorLabel.textContent = "Please enter a valid 6-digit numerical code.";
                errorLabel.classList.remove("hidden");
            }
            return;
        }

        try {
            // Call authManager to enable 2FA
            const response = await window.authManager.enable2FA(code);

            if (response.success) {
                this.twoFactorEnabled = true;
                this.generateBackupCodes(); // Generate first set of backup codes
                
                // Refresh security tab view
                this.init();
                CyberNotify.alert("Two-Factor Authentication (2FA) enabled.", { type: "success" });
            } else {
                throw new Error(response.message || "Invalid authenticator code.");
            }
        } catch (e) {
            if (errorLabel) {
                errorLabel.textContent = e.message || "Failed to verify authenticator code.";
                errorLabel.classList.remove("hidden");
            }
        }
    }

    show2FADisableDialog() {
        const dialog = document.getElementById("settings-2fa-disable-dialog");
        const codeInput = document.getElementById("2fa-disable-modal-code");
        const errorLabel = document.getElementById("2fa-disable-modal-error");
        const confirmBtn = document.getElementById("2fa-disable-modal-confirm");
        const cancelBtn = document.getElementById("2fa-disable-modal-cancel");

        if (!dialog) return;

        dialog.classList.remove("hidden");
        if (codeInput) { codeInput.value = ""; codeInput.focus(); }
        if (errorLabel) errorLabel.classList.add("hidden");

        // Single execution binding
        const cancelFn = () => {
            dialog.classList.add("hidden");
            confirmBtn.removeEventListener("click", confirmFn);
            cancelBtn.removeEventListener("click", cancelFn);
        };

        const confirmFn = async () => {
            const code = codeInput ? codeInput.value.trim() : "";
            if (errorLabel) errorLabel.classList.add("hidden");

            if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
                if (errorLabel) {
                    errorLabel.textContent = "Please enter your 6-digit authenticator code.";
                    errorLabel.classList.remove("hidden");
                }
                return;
            }

            try {
                const response = await window.authManager.disable2FA(code);
                if (response.success) {
                    this.twoFactorEnabled = false;
                    localStorage.removeItem("cyberguard_2fa_backup_codes");
                    this.backupCodes = [];
                    dialog.classList.add("hidden");
                    
                    // Unbind
                    confirmBtn.removeEventListener("click", confirmFn);
                    cancelBtn.removeEventListener("click", cancelFn);

                    // Re-render
                    this.init();
                    CyberNotify.alert("Two-Factor Authentication (2FA) disabled.", { type: "info" });
                } else {
                    throw new Error(response.message || "Disable verification failed.");
                }
            } catch (e) {
                if (errorLabel) {
                    errorLabel.textContent = e.message || "Invalid code. Please try again.";
                    errorLabel.classList.remove("hidden");
                }
            }
        };

        confirmBtn.addEventListener("click", confirmFn);
        cancelBtn.addEventListener("click", cancelFn);

        // Click outside backdrop to cancel
        dialog.addEventListener("click", (e) => {
            if (e.target === dialog) cancelFn();
        });
    }

    reset() {
        this.passwordState = { currentPassword: "", newPassword: "", confirmPassword: "" };
        this.isDirty = false;
        this.init();
    }
}

// Bind to window
window.SecuritySettings = new SecuritySettings();
