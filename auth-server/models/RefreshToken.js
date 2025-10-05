const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    token: {
      type: String,
      required: true,
      unique: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 }, // TTL index
    },
    deviceInfo: {
      userAgent: {
        type: String,
        required: true,
      },
      ipAddress: {
        type: String,
        required: true,
      },
      deviceName: {
        type: String,
        default: "Unknown Device",
      },
      browser: {
        type: String,
        default: "Unknown Browser",
      },
      os: {
        type: String,
        default: "Unknown OS",
      },
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastUsed: {
      type: Date,
      default: Date.now,
    },
    rememberMe: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Index for performance
refreshTokenSchema.index({ user: 1 });
refreshTokenSchema.index({ token: 1 });
refreshTokenSchema.index({ expiresAt: 1 });
refreshTokenSchema.index({ isActive: 1 });

// Static method to create refresh token
refreshTokenSchema.statics.createToken = function (
  userId,
  deviceInfo,
  rememberMe = false
) {
  const expiresAt = new Date();
  const expirationDays = rememberMe ? 30 : 7; // 30 days if remember me, 7 days otherwise
  expiresAt.setDate(expiresAt.getDate() + expirationDays);

  return this.create({
    user: userId,
    token: require("crypto").randomBytes(64).toString("hex"),
    expiresAt,
    deviceInfo,
    rememberMe,
  });
};

// Static method to find active token
refreshTokenSchema.statics.findActiveToken = function (token) {
  return this.findOne({
    token,
    isActive: true,
    expiresAt: { $gt: new Date() },
  }).populate("user", "-password -twoFactorSecret -twoFactorBackupCodes");
};

// Static method to revoke token
refreshTokenSchema.statics.revokeToken = function (token) {
  return this.updateOne({ token }, { isActive: false });
};

// Static method to revoke all user tokens
refreshTokenSchema.statics.revokeAllUserTokens = function (userId) {
  return this.updateMany({ user: userId }, { isActive: false });
};

// Static method to revoke all user tokens except current
refreshTokenSchema.statics.revokeAllUserTokensExcept = function (
  userId,
  currentToken
) {
  return this.updateMany(
    { user: userId, token: { $ne: currentToken } },
    { isActive: false }
  );
};

// Static method to cleanup expired tokens
refreshTokenSchema.statics.cleanupExpiredTokens = function () {
  return this.deleteMany({
    $or: [{ expiresAt: { $lt: new Date() } }, { isActive: false }],
  });
};

// Instance method to update last used
refreshTokenSchema.methods.updateLastUsed = function () {
  this.lastUsed = new Date();
  return this.save();
};

// Instance method to revoke
refreshTokenSchema.methods.revoke = function () {
  this.isActive = false;
  return this.save();
};

module.exports = mongoose.model("RefreshToken", refreshTokenSchema);


