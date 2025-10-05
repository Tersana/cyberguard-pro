const express = require("express");
const router = express.Router();
const RefreshToken = require("../models/RefreshToken");
const { authenticateToken } = require("../middleware/auth");
const { authLimiter, sanitizeInput } = require("../middleware/security");
const {
  revokeDeviceSchema,
  validate,
} = require("../validators/authValidation");

// GET /api/devices
router.get("/", authenticateToken, async (req, res) => {
  try {
    const devices = await RefreshToken.find({
      user: req.user._id,
      isActive: true,
      expiresAt: { $gt: new Date() },
    })
      .select("-token")
      .sort({ lastUsed: -1 });

    const deviceList = devices.map((device) => ({
      id: device._id,
      deviceName: device.deviceInfo.deviceName,
      browser: device.deviceInfo.browser,
      os: device.deviceInfo.os,
      isMobile: device.deviceInfo.isMobile,
      ipAddress: device.deviceInfo.ipAddress,
      lastUsed: device.lastUsed,
      createdAt: device.createdAt,
      rememberMe: device.rememberMe,
      isCurrent: device.token === req.cookies.refreshToken,
    }));

    res.json({
      success: true,
      devices: deviceList,
    });
  } catch (error) {
    console.error("Get devices error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get devices",
    });
  }
});

// DELETE /api/devices/:deviceId
router.delete(
  "/:deviceId",
  authenticateToken,
  authLimiter,
  sanitizeInput,
  validate(revokeDeviceSchema),
  async (req, res) => {
    try {
      const { deviceId } = req.params;

      const device = await RefreshToken.findOne({
        _id: deviceId,
        user: req.user._id,
        isActive: true,
      });

      if (!device) {
        return res.status(404).json({
          success: false,
          message: "Device not found",
        });
      }

      // Don't allow revoking current device
      if (device.token === req.cookies.refreshToken) {
        return res.status(400).json({
          success: false,
          message: "Cannot revoke current device",
        });
      }

      await device.revoke();

      res.json({
        success: true,
        message: "Device revoked successfully",
      });
    } catch (error) {
      console.error("Revoke device error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to revoke device",
      });
    }
  }
);

// DELETE /api/devices/revoke-all
router.delete(
  "/revoke-all",
  authenticateToken,
  authLimiter,
  async (req, res) => {
    try {
      const currentToken = req.cookies.refreshToken;

      if (currentToken) {
        // Revoke all devices except current
        await RefreshToken.revokeAllUserTokensExcept(
          req.user._id,
          currentToken
        );
      } else {
        // Revoke all devices
        await RefreshToken.revokeAllUserTokens(req.user._id);
      }

      res.json({
        success: true,
        message: "All other devices have been revoked",
      });
    } catch (error) {
      console.error("Revoke all devices error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to revoke devices",
      });
    }
  }
);

// GET /api/devices/cleanup
router.get("/cleanup", authenticateToken, async (req, res) => {
  try {
    // Cleanup expired tokens
    const result = await RefreshToken.cleanupExpiredTokens();

    res.json({
      success: true,
      message: "Expired tokens cleaned up",
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error("Cleanup devices error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to cleanup expired tokens",
    });
  }
});

module.exports = router;


