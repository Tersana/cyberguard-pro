const express = require("express");
const router = express.Router();
const User = require("../models/User");
const emailService = require("../services/emailService");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { authenticateToken, generateTokens } = require("../middleware/auth");
const { authLimiter, sanitizeInput } = require("../middleware/security");
const {
  enableTwoFactorSchema,
  verifyTwoFactorSchema,
  disableTwoFactorSchema,
  validate,
} = require("../validators/authValidation");

// GET /api/2fa/setup
router.get("/setup", authenticateToken, async (req, res) => {
  try {
    if (req.user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: "Two-factor authentication is already enabled",
      });
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `CyberGuard Pro (${req.user.email})`,
      issuer: "CyberGuard Pro",
      length: 32,
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
    });
  } catch (error) {
    console.error("2FA setup error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to setup two-factor authentication",
    });
  }
});

// POST /api/2fa/enable
router.post(
  "/enable",
  authenticateToken,
  authLimiter,
  sanitizeInput,
  validate(enableTwoFactorSchema),
  async (req, res) => {
    try {
      if (req.user.twoFactorEnabled) {
        return res.status(400).json({
          success: false,
          message: "Two-factor authentication is already enabled",
        });
      }

      const { secret, token } = req.body;

      // Verify the token
      const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: "base32",
        token: token,
        window: 2, // Allow 2 time steps (60 seconds) of tolerance
      });

      if (!verified) {
        return res.status(400).json({
          success: false,
          message: "Invalid verification code",
        });
      }

      // Enable 2FA
      req.user.twoFactorSecret = secret;
      req.user.twoFactorEnabled = true;

      // Generate backup codes
      const backupCodes = req.user.generateBackupCodes();
      await req.user.save();

      // Send backup codes via email
      try {
        await emailService.sendTwoFactorBackupCodes(req.user, backupCodes);
      } catch (emailError) {
        console.error("Failed to send backup codes email:", emailError);
        // Don't fail the 2FA setup if email fails
      }

      res.json({
        success: true,
        message: "Two-factor authentication enabled successfully",
        backupCodes: backupCodes, // Only show once
      });
    } catch (error) {
      console.error("2FA enable error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to enable two-factor authentication",
      });
    }
  }
);

// POST /api/2fa/verify
router.post(
  "/verify",
  authLimiter,
  sanitizeInput,
  validate(verifyTwoFactorSchema),
  async (req, res) => {
    try {
      const { token, tempToken } = req.body;

      if (!tempToken) {
        return res.status(400).json({
          success: false,
          message: "Temporary token required",
        });
      }

      // Verify temp token to get user
      const jwt = require("jsonwebtoken");
      const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);

      if (!user || !user.twoFactorEnabled) {
        return res.status(400).json({
          success: false,
          message: "Two-factor authentication not enabled for this user",
        });
      }

      // Verify the 2FA token
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: token,
        window: 2,
      });

      if (!verified) {
        return res.status(400).json({
          success: false,
          message: "Invalid verification code",
        });
      }

      // Generate final tokens
      const { accessToken } = generateTokens(user);

      res.json({
        success: true,
        message: "Two-factor authentication verified successfully",
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
      console.error("2FA verify error:", error);
      res.status(500).json({
        success: false,
        message: "Two-factor authentication verification failed",
      });
    }
  }
);

// POST /api/2fa/disable
router.post(
  "/disable",
  authenticateToken,
  authLimiter,
  sanitizeInput,
  validate(disableTwoFactorSchema),
  async (req, res) => {
    try {
      const { token, password } = req.body;

      // Verify password
      const isPasswordValid = await req.user.comparePassword(password);
      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: "Invalid password",
        });
      }

      // Verify 2FA token
      const verified = speakeasy.totp.verify({
        secret: req.user.twoFactorSecret,
        encoding: "base32",
        token: token,
        window: 2,
      });

      if (!verified) {
        return res.status(400).json({
          success: false,
          message: "Invalid verification code",
        });
      }

      // Disable 2FA
      req.user.twoFactorSecret = undefined;
      req.user.twoFactorEnabled = false;
      req.user.twoFactorBackupCodes = undefined;
      await req.user.save();

      // Send security alert
      try {
        await emailService.sendSecurityAlert(
          req.user,
          "two_factor_disabled",
          "Two-factor authentication has been disabled"
        );
      } catch (emailError) {
        console.error("Failed to send security alert:", emailError);
      }

      res.json({
        success: true,
        message: "Two-factor authentication disabled successfully",
      });
    } catch (error) {
      console.error("2FA disable error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to disable two-factor authentication",
      });
    }
  }
);

// GET /api/2fa/backup-codes
router.get("/backup-codes", authenticateToken, async (req, res) => {
  try {
    if (!req.user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: "Two-factor authentication is not enabled",
      });
    }

    // Generate new backup codes
    const backupCodes = req.user.generateBackupCodes();
    await req.user.save();

    // Send backup codes via email
    try {
      await emailService.sendTwoFactorBackupCodes(req.user, backupCodes);
    } catch (emailError) {
      console.error("Failed to send backup codes email:", emailError);
    }

    res.json({
      success: true,
      message: "New backup codes generated and sent to your email",
      backupCodes: backupCodes,
    });
  } catch (error) {
    console.error("Backup codes error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate backup codes",
    });
  }
});

// POST /api/2fa/verify-backup
router.post("/verify-backup", authLimiter, sanitizeInput, async (req, res) => {
  try {
    const { backupCode, tempToken } = req.body;

    if (!tempToken) {
      return res.status(400).json({
        success: false,
        message: "Temporary token required",
      });
    }

    // Verify temp token to get user
    const jwt = require("jsonwebtoken");
    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select(
      "+twoFactorBackupCodes"
    );

    if (!user || !user.twoFactorEnabled) {
      return res.status(400).json({
        success: false,
        message: "Two-factor authentication not enabled for this user",
      });
    }

    // Check backup code
    const codeIndex = user.twoFactorBackupCodes.indexOf(
      backupCode.toUpperCase()
    );
    if (codeIndex === -1) {
      return res.status(400).json({
        success: false,
        message: "Invalid backup code",
      });
    }

    // Remove used backup code
    user.twoFactorBackupCodes.splice(codeIndex, 1);
    await user.save();

    // Generate final tokens
    const { accessToken } = generateTokens(user);

    res.json({
      success: true,
      message: "Backup code verified successfully",
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
    console.error("Backup code verification error:", error);
    res.status(500).json({
      success: false,
      message: "Backup code verification failed",
    });
  }
});

module.exports = router;


