const jwt = require("jsonwebtoken");
const RefreshToken = require("../models/RefreshToken");
const User = require("../models/User");

// Middleware to verify JWT access token
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access token required",
      });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists and is active
    const user = await User.findById(decoded.userId).select(
      "-password -twoFactorSecret -twoFactorBackupCodes"
    );

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: "User not found or inactive",
      });
    }

    // Add user to request object
    req.user = user;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Token expired",
        code: "TOKEN_EXPIRED",
      });
    }

    console.error("Auth middleware error:", error);
    return res.status(500).json({
      success: false,
      message: "Authentication error",
    });
  }
};

// Middleware to verify refresh token
const authenticateRefreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Refresh token required",
      });
    }

    // Find the refresh token in database
    const tokenDoc = await RefreshToken.findActiveToken(refreshToken);

    if (!tokenDoc) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired refresh token",
      });
    }

    // Check if user is still active
    if (!tokenDoc.user.isActive) {
      // Revoke the token
      await tokenDoc.revoke();
      return res.status(401).json({
        success: false,
        message: "User account is inactive",
      });
    }

    // Update last used timestamp
    await tokenDoc.updateLastUsed();

    req.user = tokenDoc.user;
    req.refreshToken = tokenDoc;
    next();
  } catch (error) {
    console.error("Refresh token middleware error:", error);
    return res.status(500).json({
      success: false,
      message: "Refresh token verification error",
    });
  }
};

// Middleware to check if user has specific role
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const userRole = req.user.role;
    const allowedRoles = Array.isArray(roles) ? roles : [roles];

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message: "Insufficient permissions",
      });
    }

    next();
  };
};

// Middleware to check if email is verified
const requireEmailVerification = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required",
    });
  }

  if (!req.user.isEmailVerified) {
    return res.status(403).json({
      success: false,
      message: "Email verification required",
      code: "EMAIL_NOT_VERIFIED",
    });
  }

  next();
};

// Middleware to check if 2FA is enabled and verified
const requireTwoFactor = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required",
    });
  }

  if (req.user.twoFactorEnabled) {
    // Check if 2FA has been verified in this session
    if (!req.session.twoFactorVerified) {
      return res.status(403).json({
        success: false,
        message: "Two-factor authentication required",
        code: "TWO_FACTOR_REQUIRED",
      });
    }
  }

  next();
};

// Optional authentication - doesn't fail if no token
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId).select(
        "-password -twoFactorSecret -twoFactorBackupCodes"
      );

      if (user && user.isActive) {
        req.user = user;
      }
    }

    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

// Generate JWT tokens
const generateTokens = (user) => {
  const payload = {
    userId: user._id,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
  });

  return { accessToken };
};

// Generate refresh token
const generateRefreshToken = async (user, deviceInfo, rememberMe = false) => {
  return await RefreshToken.createToken(user._id, deviceInfo, rememberMe);
};

// Revoke all user tokens
const revokeAllUserTokens = async (userId) => {
  return await RefreshToken.revokeAllUserTokens(userId);
};

// Revoke specific token
const revokeToken = async (token) => {
  return await RefreshToken.revokeToken(token);
};

module.exports = {
  authenticateToken,
  authenticateRefreshToken,
  requireRole,
  requireEmailVerification,
  requireTwoFactor,
  optionalAuth,
  generateTokens,
  generateRefreshToken,
  revokeAllUserTokens,
  revokeToken,
};


