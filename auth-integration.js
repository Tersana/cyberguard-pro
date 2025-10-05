// Authentication Integration for CyberGuard Pro
class AuthIntegration {
  constructor() {
    this.user = null;
    this.isAuthenticated = false;
    this.init();
  }

  async init() {
    // Check for existing authentication
    const token = localStorage.getItem("accessToken");
    const userData = localStorage.getItem("user");

    if (token && userData) {
      try {
        this.user = JSON.parse(userData);
        this.isAuthenticated = true;
        this.updateUI();
        this.setupEventListeners();

        // Verify token is still valid
        await this.verifyToken();
      } catch (error) {
        console.error("Auth initialization error:", error);
        this.logout();
      }
    } else {
      this.showLoginSection();
      this.setupEventListeners();
    }
  }

  async verifyToken() {
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
          this.logout();
          return false;
        }
        throw new Error("Token verification failed");
      }

      const data = await response.json();
      this.user = data.user;
      localStorage.setItem("user", JSON.stringify(this.user));
      this.updateUI();
      return true;
    } catch (error) {
      console.error("Token verification error:", error);
      this.logout();
      return false;
    }
  }

  updateUI() {
    const userProfileSection = document.getElementById("userProfileSection");
    const loginSection = document.getElementById("loginSection");
    const userName = document.getElementById("userName");
    const userEmail = document.getElementById("userEmail");
    const userInitials = document.getElementById("userInitials");

    if (this.isAuthenticated && this.user) {
      // Show user profile section
      if (userProfileSection) userProfileSection.classList.remove("hidden");
      if (loginSection) loginSection.classList.add("hidden");

      // Update user info
      if (userName)
        userName.textContent =
          this.user.fullName || `${this.user.firstName} ${this.user.lastName}`;
      if (userEmail) userEmail.textContent = this.user.email;
      if (userInitials) {
        const initials =
          (this.user.firstName?.charAt(0) || "") +
          (this.user.lastName?.charAt(0) || "");
        userInitials.textContent = initials.toUpperCase();
      }
    } else {
      // Show login section
      if (userProfileSection) userProfileSection.classList.add("hidden");
      if (loginSection) loginSection.classList.remove("hidden");
    }
  }

  showLoginSection() {
    this.isAuthenticated = false;
    this.user = null;
    this.updateUI();
  }

  setupEventListeners() {
    // Profile button
    const profileBtn = document.getElementById("profileBtn");
    if (profileBtn) {
      profileBtn.addEventListener("click", () => {
        window.location.href = "auth/profile.html";
      });
    }

    // Logout button
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", this.handleLogout.bind(this));
    }
  }

  async handleLogout() {
    try {
      // Call logout API
      await fetch("http://localhost:3002/api/auth/logout", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      });
    } catch (error) {
      console.error("Logout API error:", error);
    } finally {
      // Clear local storage and update UI
      localStorage.removeItem("accessToken");
      localStorage.removeItem("user");
      this.showLoginSection();

      // Show logout confirmation
      this.showToast("Logged out successfully", "success");
    }
  }

  showToast(message, type = "info", duration = 3000) {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById("toastContainer");
    if (!toastContainer) {
      toastContainer = document.createElement("div");
      toastContainer.id = "toastContainer";
      toastContainer.className = "fixed top-4 right-4 z-50 space-y-2";
      document.body.appendChild(toastContainer);
    }

    const toast = document.createElement("div");
    toast.className = `bg-white/10 backdrop-blur-lg border border-white/20 rounded-lg p-4 text-white shadow-lg transform transition-all duration-300 translate-x-full`;

    const iconMap = {
      success: "✅",
      error: "❌",
      warning: "⚠️",
      info: "ℹ️",
    };

    toast.innerHTML = `
            <div class="flex items-center space-x-3">
                <span class="text-lg">${iconMap[type] || iconMap.info}</span>
                <span class="flex-1">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="text-slate-300 hover:text-white transition-colors">
                    <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>
        `;

    toastContainer.appendChild(toast);

    // Animate in
    setTimeout(() => {
      toast.classList.remove("translate-x-full");
    }, 100);

    // Auto remove
    setTimeout(() => {
      toast.classList.add("translate-x-full");
      setTimeout(() => {
        if (toast.parentElement) {
          toast.remove();
        }
      }, 300);
    }, duration);
  }

  // Method to check if user is authenticated
  isUserAuthenticated() {
    return this.isAuthenticated && this.user !== null;
  }

  // Method to get current user
  getCurrentUser() {
    return this.user;
  }

  // Method to get access token
  getAccessToken() {
    return localStorage.getItem("accessToken");
  }

  // Method to make authenticated API requests
  async makeAuthenticatedRequest(url, options = {}) {
    const token = this.getAccessToken();
    if (!token) {
      throw new Error("No access token available");
    }

    const config = {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...options.headers,
      },
      credentials: "include",
    };

    const response = await fetch(url, config);

    if (response.status === 401) {
      // Token expired, logout user
      this.logout();
      throw new Error("Authentication required");
    }

    return response;
  }

  // Method to refresh access token
  async refreshAccessToken() {
    try {
      const response = await fetch("http://localhost:3002/api/auth/refresh", {
        method: "POST",
        credentials: "include",
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem("accessToken", data.accessToken);
        return data.accessToken;
      } else {
        throw new Error("Token refresh failed");
      }
    } catch (error) {
      console.error("Token refresh error:", error);
      this.logout();
      throw error;
    }
  }
}

// Initialize authentication integration
let authIntegration;
document.addEventListener("DOMContentLoaded", () => {
  authIntegration = new AuthIntegration();
});

// Export for use in other scripts
window.authIntegration = authIntegration;


