const express = require("express");
const router = express.Router();
const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const LoginAttempt = require("../models/LoginAttempt");
const emailService = require("../services/emailService");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const {
  authenticateToken,
  authenticateRefreshToken,
  generateTokens,
  generateRefreshToken,
  revokeAllUserTokens,
  revokeToken,
} = require("../middleware/auth");
const {
  authLimiter,
  passwordResetLimiter,
  emailVerificationLimiter,
  bruteForce,
  sanitizeInput,
} = require("../middleware/security");
const {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  changePasswordSchema,
  updateProfileSchema,
  enableTwoFactorSchema,
  verifyTwoFactorSchema,
  disableTwoFactorSchema,
  revokeDeviceSchema,
  validate,
} = require("../validators/authValidation");

// Helper function to get device info
const getDeviceInfo = (req) => {
  const userAgent = req.get("User-Agent") || "Unknown";
  const ipAddress = req.ip || req.connection.remoteAddress || "Unknown";

  // Simple device detection
  const isMobile = /Mobile|Android|iPhone|iPad/i.test(userAgent);
  const browser = userAgent.includes("Chrome")
    ? "Chrome"
    : userAgent.includes("Firefox")
    ? "Firefox"
    : userAgent.includes("Safari")
    ? "Safari"
    : "Unknown";
  const os = userAgent.includes("Windows")
    ? "Windows"
    : userAgent.includes("Mac")
    ? "macOS"
    : userAgent.includes("Linux")
    ? "Linux"
    : "Unknown";

  return {
    userAgent,
    ipAddress,
    deviceName: `${os} - ${browser}`,
    browser,
    os,
    isMobile,
  };
};

// POST /api/auth/register
router.post(
  "/register",
  authLimiter,
  sanitizeInput,
  validate(registerSchema),
  async (req, res) => {
    try {
      const { email, password, firstName, lastName } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: "User with this email already exists",
        });
      }

      // Create new user
      const user = new User({
        email,
        password,
        firstName,
        lastName,
      });

      // Generate email verification token
      const verificationToken = user.generateEmailVerificationToken();
      await user.save();

      // Send verification email
      try {
        await emailService.sendEmailVerification(user, verificationToken);
      } catch (emailError) {
        console.error("Failed to send verification email:", emailError);
        // Don't fail registration if email fails
      }

      res.status(201).json({
        success: true,
        message:
          "User registered successfully. Please check your email to verify your account.",
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: user.isEmailVerified,
        },
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({
        success: false,
        message: "Registration failed",
      });
    }
  }
);

// GET /api/auth/verify
router.get(
  "/verify",
  emailVerificationLimiter,
  validate(verifyEmailSchema),
  async (req, res) => {
    try {
      const { token } = req.query;

      const user = await User.findByEmailVerificationToken(token);
      if (!user) {
        return res.status(400).json({
          success: false,
          message: "Invalid or expired verification token",
        });
      }

      // Mark email as verified
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      // Send welcome email
      try {
        await emailService.sendWelcomeEmail(user);
      } catch (emailError) {
        console.error("Failed to send welcome email:", emailError);
      }

      res.json({
        success: true,
        message: "Email verified successfully",
      });
    } catch (error) {
      console.error("Email verification error:", error);
      res.status(500).json({
        success: false,
        message: "Email verification failed",
      });
    }
  }
);

// POST /api/auth/login
router.post(
  "/login",
  authLimiter,
  bruteForce.prevent,
  sanitizeInput,
  validate(loginSchema),
  async (req, res) => {
    try {
      const { email, password, rememberMe } = req.body;
      const deviceInfo = getDeviceInfo(req);

      // Find user with password
      const user = await User.findByEmailWithPassword(email);

      if (!user) {
        await LoginAttempt.logFailure(
          email,
          deviceInfo.ipAddress,
          deviceInfo.userAgent,
          "invalid_credentials"
        );
        return res.status(401).json({
          success: false,
          message: "Invalid email or password",
        });
      }

      // Check if account is locked
      if (user.isLocked()) {
        await LoginAttempt.logFailure(
          email,
          deviceInfo.ipAddress,
          deviceInfo.userAgent,
          "account_locked"
        );
        return res.status(423).json({
          success: false,
          message:
            "Account is temporarily locked due to too many failed login attempts",
        });
      }

      // Check if email is verified
      if (!user.isEmailVerified) {
        await LoginAttempt.logFailure(
          email,
          deviceInfo.ipAddress,
          deviceInfo.userAgent,
          "email_not_verified"
        );
        return res.status(403).json({
          success: false,
          message: "Please verify your email address before logging in",
          code: "EMAIL_NOT_VERIFIED",
        });
      }

      // Check password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        await user.incLoginAttempts();
        await LoginAttempt.logFailure(
          email,
          deviceInfo.ipAddress,
          deviceInfo.userAgent,
          "invalid_credentials"
        );
        return res.status(401).json({
          success: false,
          message: "Invalid email or password",
        });
      }

      // Reset login attempts on successful login
      await user.resetLoginAttempts();

      // Update last login info
      user.lastLogin = new Date();
      user.lastLoginIP = deviceInfo.ipAddress;
      await user.save();

      // Log successful login
      await LoginAttempt.logSuccess(
        email,
        deviceInfo.ipAddress,
        deviceInfo.userAgent
      );

      // Generate tokens
      const { accessToken } = generateTokens(user);
      const refreshTokenDoc = await generateRefreshToken(
        user._id,
        deviceInfo,
        rememberMe
      );

      // Set refresh token as HTTP-only cookie
      res.cookie("refreshToken", refreshTokenDoc.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000, // 30 days or 7 days
      });

      // Check if 2FA is required
      if (user.twoFactorEnabled) {
        return res.json({
          success: true,
          message: "Two-factor authentication required",
          requiresTwoFactor: true,
          tempToken: accessToken, // Temporary token for 2FA verification
        });
      }

      res.json({
        success: true,
        message: "Login successful",
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: user.isEmailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
          role: user.role,
        },
        accessToken,
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({
        success: false,
        message: "Login failed",
      });
    }
  }
);

// POST /api/auth/refresh
router.post("/refresh", authenticateRefreshToken, async (req, res) => {
  try {
    const { user, refreshToken } = req;

    // Generate new access token
    const { accessToken } = generateTokens(user);

    res.json({
      success: true,
      accessToken,
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(500).json({
      success: false,
      message: "Token refresh failed",
    });
  }
});

// POST /api/auth/logout
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (refreshToken) {
      await revokeToken(refreshToken);
    }

    res.clearCookie("refreshToken");
    res.json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({
      success: false,
      message: "Logout failed",
    });
  }
});

// POST /api/auth/logout-all
router.post("/logout-all", authenticateToken, async (req, res) => {
  try {
    await revokeAllUserTokens(req.user._id);

    res.clearCookie("refreshToken");
    res.json({
      success: true,
      message: "All sessions terminated successfully",
    });
  } catch (error) {
    console.error("Logout all error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to terminate all sessions",
    });
  }
});

// POST /api/auth/forgot-password
router.post(
  "/forgot-password",
  passwordResetLimiter,
  sanitizeInput,
  validate(forgotPasswordSchema),
  async (req, res) => {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        // Don't reveal if email exists or not
        return res.json({
          success: true,
          message:
            "If an account with that email exists, a password reset link has been sent",
        });
      }

      // Generate password reset token
      const resetToken = user.generatePasswordResetToken();
      await user.save();

      // Send password reset email
      try {
        await emailService.sendPasswordReset(user, resetToken);
      } catch (emailError) {
        console.error("Failed to send password reset email:", emailError);
        return res.status(500).json({
          success: false,
          message: "Failed to send password reset email",
        });
      }

      res.json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent",
      });
    } catch (error) {
      console.error("Forgot password error:", error);
      res.status(500).json({
        success: false,
        message: "Password reset request failed",
      });
    }
  }
);

// POST /api/auth/reset-password
router.post(
  "/reset-password",
  passwordResetLimiter,
  sanitizeInput,
  validate(resetPasswordSchema),
  async (req, res) => {
    try {
      const { token, password } = req.body;

      const user = await User.findByPasswordResetToken(token);
      if (!user) {
        return res.status(400).json({
          success: false,
          message: "Invalid or expired reset token",
        });
      }

      // Update password
      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      // Revoke all refresh tokens for security
      await revokeAllUserTokens(user._id);

      // Send security alert
      try {
        await emailService.sendSecurityAlert(
          user,
          "password_changed",
          "Your password has been changed"
        );
      } catch (emailError) {
        console.error("Failed to send security alert:", emailError);
      }

      res.json({
        success: true,
        message: "Password reset successful",
      });
    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).json({
        success: false,
        message: "Password reset failed",
      });
    }
  }
);

// GET /api/me
router.get("/me", authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        fullName: req.user.fullName,
        isEmailVerified: req.user.isEmailVerified,
        twoFactorEnabled: req.user.twoFactorEnabled,
        role: req.user.role,
        profile: req.user.profile,
        preferences: req.user.preferences,
        lastLogin: req.user.lastLogin,
        createdAt: req.user.createdAt,
      },
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get user profile",
    });
  }
});

// PUT /api/me
router.put(
  "/me",
  authenticateToken,
  sanitizeInput,
  validate(updateProfileSchema),
  async (req, res) => {
    try {
      const updates = req.body;

      // Update user
      Object.keys(updates).forEach((key) => {
        if (updates[key] !== undefined) {
          req.user[key] = updates[key];
        }
      });

      await req.user.save();

      res.json({
        success: true,
        message: "Profile updated successfully",
        user: {
          id: req.user._id,
          email: req.user.email,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          fullName: req.user.fullName,
          profile: req.user.profile,
          preferences: req.user.preferences,
        },
      });
    } catch (error) {
      console.error("Update profile error:", error);
      res.status(500).json({
        success: false,
        message: "Profile update failed",
      });
    }
  }
);

module.exports = router;


