/**
 * Account Settings Tab Module
 * Handles account summary information and Danger Zone actions
 */

class AccountSettings {
    constructor() {
        this.isDirty = false;
    }

    init() {
        this.renderForm();
        this.setupEventListeners();
    }

    renderForm() {
        const pane = document.getElementById("pane-account");
        if (!pane) return;

        const user = window.authManager.getCurrentUser() || {};
        
        // Expose date info
        let creationDate = "May 12, 2026";
        if (user.createdAt) {
            try {
                creationDate = new Date(user.createdAt).toLocaleDateString("en-US", { year: 'numeric', month: 'long', day: 'numeric' });
            } catch(e) {
                creationDate = user.createdAt;
            }
        }

        // security-audit-ignore
        pane.innerHTML = `
            <div class="space-y-8">
                <!-- Account Summary Card -->
                <div class="settings-section-card">
                    <h5 class="settings-section-card-title">
                        <span class="material-symbols-outlined text-blue-400">info</span>
                        Account Information Summary
                    </h5>
                    
                    <div class="grid grid-cols-2 gap-y-6 gap-x-4 pt-2 text-sm">
                        <div class="settings-form-group mb-0">
                            <label class="flex items-center gap-1.5 mb-1.5">
                                Email Address
                                <span class="material-symbols-outlined text-slate-500 cursor-help" style="font-size: 1rem;" title="Your email address is managed centrally and cannot be changed here. Contact support if you need to update it.">info</span>
                            </label>
                            <input type="email" class="cyber-input p-3 rounded-lg text-sm bg-slate-900/40 text-slate-400 cursor-not-allowed" value="${escapeHtml(user.email || 'user@cyberguard.com')}" disabled>
                        </div>
                        
                        <div class="settings-form-group mb-0">
                            <label class="mb-1.5">Member Since</label>
                            <input type="text" class="cyber-input p-3 rounded-lg text-sm bg-slate-900/40 text-slate-400 cursor-not-allowed" value="${escapeHtml(creationDate)}" disabled>
                        </div>

                        <div class="settings-form-group mb-0">
                            <label class="mb-1.5">Current Plan</label>
                            <div class="flex items-center gap-3">
                                <input type="text" class="cyber-input p-3 rounded-lg text-sm bg-slate-900/40 text-slate-400 cursor-not-allowed flex-1" value="${escapeHtml(user.role === 'admin' ? 'Enterprise / Admin' : 'Pro Subscription')}" disabled>
                                <button type="button" class="cyber-btn-ghost text-xs py-2.5 px-4 rounded-lg flex items-center gap-1" onclick="document.getElementById('tab-billing').click();">
                                    View Billing details
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Danger Zone Card -->
                <div class="settings-danger-card">
                    <h5 class="settings-danger-card-title">
                        <span class="material-symbols-outlined" style="font-size: 1.25rem;">warning</span>
                        Danger Zone
                    </h5>
                    <p class="desc">Irreversible account actions. Please exercise caution when performing these actions.</p>


                    <!-- Delete Account -->
                    <div class="settings-danger-action-row">
                        <div class="settings-danger-action-info">
                            <h5>Delete Account</h5>
                            <p>Permanently purge your user account, project data, credentials, and delete all logs. This cannot be undone.</p>
                        </div>
                        <button type="button" id="delete-account-trigger" class="cyber-btn-danger text-xs py-2 px-4 rounded-lg flex items-center gap-1.5">
                            Delete Account
                            <span class="coming-soon-badge" style="background-color: rgba(248, 113, 113, 0.2); border-color: rgba(248, 113, 113, 0.4); color: var(--cg-danger);">Coming Soon</span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Delete Account Confirmation Dialog -->
            <div id="delete-account-confirm-modal" class="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center z-[100] hidden">
                <div class="cyber-modal max-w-md w-full mx-4 p-6 border border-red-500/30 bg-slate-950">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="w-10 h-10 rounded-lg bg-red-500/10 border border-red-500/25 flex items-center justify-center text-red-400">
                            <span class="material-symbols-outlined">warning</span>
                        </div>
                        <div>
                            <h4 class="text-sm font-bold text-red-400">Permanently Delete Account?</h4>
                            <p class="text-[11px] text-slate-400">All data including scan histories will be deleted forever.</p>
                        </div>
                    </div>
                    
                    <p class="text-xs text-slate-300 mb-4">
                        This action is irreversible. To confirm deletion, type <strong class="text-white font-mono select-none">DELETE</strong> in the box below:
                    </p>

                    <div class="mb-4">
                        <input type="text" id="delete-account-phrase-input" class="cyber-input p-2 rounded-lg text-center font-mono w-full" placeholder="Type DELETE" autocomplete="off">
                        <span id="delete-account-phrase-error" class="text-xs text-red-400 mt-2 block hidden">Validation phrase does not match.</span>
                    </div>

                    <div class="flex gap-3">
                        <button type="button" id="delete-account-btn" class="cyber-btn-danger flex-1 py-2.5 rounded-lg text-xs font-bold" style="opacity: 0.6; cursor: not-allowed;" disabled>
                            Delete Account
                        </button>
                        <button type="button" id="delete-account-cancel-btn" class="btn-cancel flex-1 py-2.5 rounded-lg text-xs font-bold">
                            Cancel
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    setupEventListeners() {
        const trigger = document.getElementById("delete-account-trigger");
        const modal = document.getElementById("delete-account-confirm-modal");
        const phraseInput = document.getElementById("delete-account-phrase-input");
        const deleteBtn = document.getElementById("delete-account-btn");
        const cancelBtn = document.getElementById("delete-account-cancel-btn");
        const errorLabel = document.getElementById("delete-account-phrase-error");

        if (!trigger || !modal) return;

        // Open confirm modal
        trigger.addEventListener("click", () => {
            modal.classList.remove("hidden");
            if (phraseInput) {
                phraseInput.value = "";
                phraseInput.focus();
            }
            if (deleteBtn) {
                deleteBtn.disabled = true;
                deleteBtn.style.opacity = "0.6";
                deleteBtn.style.cursor = "not-allowed";
            }
            if (errorLabel) errorLabel.classList.add("hidden");
        });

        // Phrase input validation listener
        if (phraseInput && deleteBtn) {
            phraseInput.addEventListener("input", () => {
                const phrase = phraseInput.value.trim();
                const isMatch = phrase === "DELETE";
                deleteBtn.disabled = !isMatch;
                deleteBtn.style.opacity = isMatch ? "1" : "0.6";
                deleteBtn.style.cursor = isMatch ? "pointer" : "not-allowed";
                
                if (errorLabel && isMatch) {
                    errorLabel.classList.add("hidden");
                }
            });
        }

        // Cancel deletion click
        if (cancelBtn) {
            cancelBtn.addEventListener("click", () => {
                modal.classList.add("hidden");
            });
        }

        // Trigger delete confirm (mock action since delete API is not ready)
        if (deleteBtn) {
            deleteBtn.addEventListener("click", () => {
                const phrase = phraseInput.value.trim();
                if (phrase !== "DELETE") {
                    if (errorLabel) errorLabel.classList.remove("hidden");
                    return;
                }

                // Delete account is not supported by backend yet - mock session logout
                modal.classList.add("hidden");
                CyberNotify.alert("Account deletion initiated (Draft simulator). Purging session...", { type: "warning" });
                
                setTimeout(() => {
                    window.authManager.logout();
                }, 1500);
            });
        }

        // Close when clicking backdrop
        modal.addEventListener("click", (e) => {
            if (e.target === modal) {
                modal.classList.add("hidden");
            }
        });
    }

    reset() {
        // Read-only settings tab
    }
}

// Bind to window
window.AccountSettings = new AccountSettings();
