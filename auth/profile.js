// Profile Management
class ProfileManager {
  constructor() {
    this.user = null;
    this.init();
  }

  async init() {
    // Check authentication
    const token = localStorage.getItem("accessToken");
    if (!token) {
      window.location.href = "login.html";
      return;
    }

    try {
      await this.loadUserProfile();
      this.setupEventListeners();
      this.loadUserData();
    } catch (error) {
      console.error("Profile initialization error:", error);
      AuthUtils.showToast("Failed to load profile", "error");
    }
  }

  async loadUserProfile() {
    try {
      const response = await fetch("http://localhost:3002/api/me", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem("accessToken");
          localStorage.removeItem("user");
          window.location.href = "login.html";
          return;
        }
        throw new Error("Failed to load profile");
      }

      const data = await response.json();
      this.user = data.user;
      return data.user;
    } catch (error) {
      console.error("Load profile error:", error);
      throw error;
    }
  }

  loadUserData() {
    if (!this.user) return;

    // Update header information
    document.getElementById("userName").textContent = this.user.fullName;
    document.getElementById("userEmail").textContent = this.user.email;
    document.getElementById("userInitials").textContent =
      this.user.firstName.charAt(0).toUpperCase() +
      this.user.lastName.charAt(0).toUpperCase();

    // Update email verification status
    const emailVerified = document.getElementById("emailVerified");
    if (this.user.isEmailVerified) {
      emailVerified.classList.remove("hidden");
    } else {
      emailVerified.classList.add("hidden");
    }

    // Update 2FA status
    const twoFactorStatus = document.getElementById("twoFactorStatus");
    const twoFactorStatusText = document.getElementById("twoFactorStatusText");
    const toggleTwoFactorBtn = document.getElementById("toggleTwoFactorBtn");

    if (this.user.twoFactorEnabled) {
      twoFactorStatus.classList.remove("hidden");
      twoFactorStatusText.textContent = "Currently enabled";
      toggleTwoFactorBtn.textContent = "Disable 2FA";
      toggleTwoFactorBtn.className =
        "bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors";
    } else {
      twoFactorStatus.classList.add("hidden");
      twoFactorStatusText.textContent = "Not enabled";
      toggleTwoFactorBtn.textContent = "Enable 2FA";
      toggleTwoFactorBtn.className =
        "bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-colors";
    }

    // Populate profile form
    document.getElementById("firstName").value = this.user.firstName || "";
    document.getElementById("lastName").value = this.user.lastName || "";
    document.getElementById("bio").value = this.user.profile?.bio || "";
    document.getElementById("company").value = this.user.profile?.company || "";
    document.getElementById("website").value = this.user.profile?.website || "";
    document.getElementById("location").value =
      this.user.profile?.location || "";

    // Populate preferences
    document.getElementById("theme").value =
      this.user.preferences?.theme || "auto";
    document.getElementById("language").value =
      this.user.preferences?.language || "en";
    document.getElementById("emailNotifications").checked =
      this.user.preferences?.notifications?.email !== false;
    document.getElementById("securityNotifications").checked =
      this.user.preferences?.notifications?.security !== false;
    document.getElementById("updateNotifications").checked =
      this.user.preferences?.notifications?.updates !== false;

    // Load active sessions
    this.loadActiveSessions();
  }

  async loadActiveSessions() {
    try {
      const response = await fetch("http://localhost:3002/api/devices", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      });

      if (response.ok) {
        const data = await response.json();
        this.displaySessions(data.devices);
      }
    } catch (error) {
      console.error("Load sessions error:", error);
    }
  }

  displaySessions(sessions) {
    const sessionsList = document.getElementById("sessionsList");
    if (!sessionsList) return;

    if (sessions.length === 0) {
      sessionsList.innerHTML =
        '<p class="text-slate-300">No active sessions</p>';
      return;
    }

    sessionsList.innerHTML = sessions
      .map(
        (session) => `
            <div class="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                <div class="flex items-center space-x-3">
                    <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                        <svg class="w-4 h-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />
                        </svg>
                    </div>
                    <div>
                        <p class="text-white font-medium">${
                          session.deviceName
                        }</p>
                        <p class="text-slate-300 text-sm">${
                          session.browser
                        } on ${session.os}</p>
                        <p class="text-slate-400 text-xs">Last used: ${new Date(
                          session.lastUsed
                        ).toLocaleString()}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    ${
                      session.isCurrent
                        ? '<span class="text-green-400 text-sm font-medium">Current</span>'
                        : `<button onclick="profileManager.revokeSession('${session.id}')" class="text-red-400 hover:text-red-300 text-sm transition-colors">Revoke</button>`
                    }
                </div>
            </div>
        `
      )
      .join("");
  }

  async revokeSession(deviceId) {
    try {
      const response = await fetch(
        `http://localhost:3002/api/devices/${deviceId}`,
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            "Content-Type": "application/json",
          },
          credentials: "include",
        }
      );

      if (response.ok) {
        AuthUtils.showToast("Session revoked successfully", "success");
        this.loadActiveSessions();
      } else {
        throw new Error("Failed to revoke session");
      }
    } catch (error) {
      console.error("Revoke session error:", error);
      AuthUtils.showToast("Failed to revoke session", "error");
    }
  }

  setupEventListeners() {
    // Profile form submission
    const profileForm = document.getElementById("profileForm");
    if (profileForm) {
      profileForm.addEventListener(
        "submit",
        this.handleProfileUpdate.bind(this)
      );
    }

    // Change password form submission
    const changePasswordForm = document.getElementById("changePasswordForm");
    if (changePasswordForm) {
      changePasswordForm.addEventListener(
        "submit",
        this.handlePasswordChange.bind(this)
      );
    }

    // Preferences form submission
    const preferencesForm = document.getElementById("preferencesForm");
    if (preferencesForm) {
      preferencesForm.addEventListener(
        "submit",
        this.handlePreferencesUpdate.bind(this)
      );
    }

    // Two-factor authentication toggle
    const toggleTwoFactorBtn = document.getElementById("toggleTwoFactorBtn");
    if (toggleTwoFactorBtn) {
      toggleTwoFactorBtn.addEventListener(
        "click",
        this.handleTwoFactorToggle.bind(this)
      );
    }

    // Revoke all sessions
    const revokeAllSessionsBtn = document.getElementById(
      "revokeAllSessionsBtn"
    );
    if (revokeAllSessionsBtn) {
      revokeAllSessionsBtn.addEventListener(
        "click",
        this.handleRevokeAllSessions.bind(this)
      );
    }

    // Logout button
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", this.handleLogout.bind(this));
    }
  }

  async handleProfileUpdate(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const profileData = {
      firstName: formData.get("firstName"),
      lastName: formData.get("lastName"),
      profile: {
        bio: formData.get("bio"),
        company: formData.get("company"),
        website: formData.get("website"),
        location: formData.get("location"),
      },
    };

    AuthUtils.showLoading(
      "saveProfileBtn",
      "saveProfileSpinner",
      "saveProfileBtnText",
      "Saving..."
    );

    try {
      const response = await fetch("http://localhost:3002/api/me", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify(profileData),
      });

      if (response.ok) {
        AuthUtils.showToast("Profile updated successfully", "success");
        await this.loadUserProfile();
        this.loadUserData();
      } else {
        throw new Error("Failed to update profile");
      }
    } catch (error) {
      console.error("Profile update error:", error);
      AuthUtils.showToast("Failed to update profile", "error");
    } finally {
      AuthUtils.hideLoading(
        "saveProfileBtn",
        "saveProfileSpinner",
        "saveProfileBtnText",
        "Save Changes"
      );
    }
  }

  async handlePasswordChange(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const passwordData = {
      currentPassword: formData.get("currentPassword"),
      newPassword: formData.get("newPassword"),
      confirmNewPassword: formData.get("confirmNewPassword"),
    };

    // Validate passwords match
    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      AuthUtils.showToast("Passwords do not match", "error");
      return;
    }

    // Validate password strength
    const passwordValidation = AuthUtils.validatePassword(
      passwordData.newPassword
    );
    if (!passwordValidation.isValid) {
      AuthUtils.showToast(
        "Password must be at least 8 characters with uppercase, lowercase, number, and special character",
        "error"
      );
      return;
    }

    AuthUtils.showLoading(
      "changePasswordBtn",
      "changePasswordSpinner",
      "changePasswordBtnText",
      "Changing..."
    );

    try {
      const response = await fetch(
        "http://localhost:3002/api/auth/change-password",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify(passwordData),
        }
      );

      if (response.ok) {
        AuthUtils.showToast("Password changed successfully", "success");
        e.target.reset();
      } else {
        const data = await response.json();
        throw new Error(data.message || "Failed to change password");
      }
    } catch (error) {
      console.error("Password change error:", error);
      AuthUtils.showToast(
        error.message || "Failed to change password",
        "error"
      );
    } finally {
      AuthUtils.hideLoading(
        "changePasswordBtn",
        "changePasswordSpinner",
        "changePasswordBtnText",
        "Change Password"
      );
    }
  }

  async handlePreferencesUpdate(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const preferencesData = {
      preferences: {
        theme: formData.get("theme"),
        language: formData.get("language"),
        notifications: {
          email: formData.get("emailNotifications") === "on",
          security: formData.get("securityNotifications") === "on",
          updates: formData.get("updateNotifications") === "on",
        },
      },
    };

    AuthUtils.showLoading(
      "savePreferencesBtn",
      "savePreferencesSpinner",
      "savePreferencesBtnText",
      "Saving..."
    );

    try {
      const response = await fetch("http://localhost:3002/api/me", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify(preferencesData),
      });

      if (response.ok) {
        AuthUtils.showToast("Preferences updated successfully", "success");
        await this.loadUserProfile();
        this.loadUserData();
      } else {
        throw new Error("Failed to update preferences");
      }
    } catch (error) {
      console.error("Preferences update error:", error);
      AuthUtils.showToast("Failed to update preferences", "error");
    } finally {
      AuthUtils.hideLoading(
        "savePreferencesBtn",
        "savePreferencesSpinner",
        "savePreferencesBtnText",
        "Save Preferences"
      );
    }
  }

  async handleTwoFactorToggle() {
    if (this.user.twoFactorEnabled) {
      // Disable 2FA
      const token = prompt(
        "Enter your 2FA code to disable two-factor authentication:"
      );
      if (!token) return;

      const password = prompt("Enter your password for security verification:");
      if (!password) return;

      try {
        const response = await fetch("http://localhost:3002/api/2fa/disable", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({ token, password }),
        });

        if (response.ok) {
          AuthUtils.showToast("Two-factor authentication disabled", "success");
          await this.loadUserProfile();
          this.loadUserData();
        } else {
          const data = await response.json();
          throw new Error(data.message || "Failed to disable 2FA");
        }
      } catch (error) {
        console.error("Disable 2FA error:", error);
        AuthUtils.showToast(error.message || "Failed to disable 2FA", "error");
      }
    } else {
      // Enable 2FA - redirect to setup page
      window.location.href = "2fa-setup.html";
    }
  }

  async handleRevokeAllSessions() {
    if (
      !confirm(
        "Are you sure you want to revoke all other sessions? You will need to log in again on other devices."
      )
    ) {
      return;
    }

    try {
      const response = await fetch(
        "http://localhost:3002/api/devices/revoke-all",
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            "Content-Type": "application/json",
          },
          credentials: "include",
        }
      );

      if (response.ok) {
        AuthUtils.showToast(
          "All other sessions revoked successfully",
          "success"
        );
        this.loadActiveSessions();
      } else {
        throw new Error("Failed to revoke sessions");
      }
    } catch (error) {
      console.error("Revoke all sessions error:", error);
      AuthUtils.showToast("Failed to revoke sessions", "error");
    }
  }

  async handleLogout() {
    try {
      await fetch("http://localhost:3002/api/auth/logout", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      });
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      localStorage.removeItem("accessToken");
      localStorage.removeItem("user");
      window.location.href = "login.html";
    }
  }
}

// Initialize profile manager when DOM is loaded
let profileManager;
document.addEventListener("DOMContentLoaded", () => {
  profileManager = new ProfileManager();
});


