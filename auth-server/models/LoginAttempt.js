const mongoose = require("mongoose");

const loginAttemptSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    ipAddress: {
      type: String,
      required: true,
    },
    userAgent: {
      type: String,
      required: true,
    },
    success: {
      type: Boolean,
      required: true,
    },
    failureReason: {
      type: String,
      enum: [
        "invalid_credentials",
        "account_locked",
        "email_not_verified",
        "two_factor_required",
        "two_factor_invalid",
      ],
      default: null,
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: { expireAfterSeconds: 86400 * 30 }, // Auto-delete after 30 days
    },
    location: {
      country: String,
      region: String,
      city: String,
      coordinates: {
        lat: Number,
        lng: Number,
      },
    },
    deviceInfo: {
      browser: String,
      os: String,
      device: String,
      isMobile: Boolean,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for performance and security
loginAttemptSchema.index({ email: 1, timestamp: -1 });
loginAttemptSchema.index({ ipAddress: 1, timestamp: -1 });
loginAttemptSchema.index({ success: 1, timestamp: -1 });
loginAttemptSchema.index({ timestamp: 1 });

// Static method to log successful login
loginAttemptSchema.statics.logSuccess = function (
  email,
  ipAddress,
  userAgent,
  location = null,
  deviceInfo = null
) {
  return this.create({
    email,
    ipAddress,
    userAgent,
    success: true,
    location,
    deviceInfo,
  });
};

// Static method to log failed login
loginAttemptSchema.statics.logFailure = function (
  email,
  ipAddress,
  userAgent,
  failureReason,
  location = null,
  deviceInfo = null
) {
  return this.create({
    email,
    ipAddress,
    userAgent,
    success: false,
    failureReason,
    location,
    deviceInfo,
  });
};

// Static method to get recent failed attempts for email
loginAttemptSchema.statics.getRecentFailedAttempts = function (
  email,
  timeWindow = 15 * 60 * 1000
) {
  // 15 minutes
  const since = new Date(Date.now() - timeWindow);
  return this.countDocuments({
    email,
    success: false,
    timestamp: { $gte: since },
  });
};

// Static method to get recent failed attempts for IP
loginAttemptSchema.statics.getRecentFailedAttemptsByIP = function (
  ipAddress,
  timeWindow = 15 * 60 * 1000
) {
  // 15 minutes
  const since = new Date(Date.now() - timeWindow);
  return this.countDocuments({
    ipAddress,
    success: false,
    timestamp: { $gte: since },
  });
};

// Static method to get login history for user
loginAttemptSchema.statics.getUserLoginHistory = function (email, limit = 50) {
  return this.find({ email })
    .sort({ timestamp: -1 })
    .limit(limit)
    .select("-__v");
};

// Static method to detect suspicious activity
loginAttemptSchema.statics.detectSuspiciousActivity = function (
  ipAddress,
  timeWindow = 60 * 60 * 1000
) {
  // 1 hour
  const since = new Date(Date.now() - timeWindow);
  return this.aggregate([
    {
      $match: {
        ipAddress,
        timestamp: { $gte: since },
        success: false,
      },
    },
    {
      $group: {
        _id: "$email",
        attempts: { $sum: 1 },
        uniqueEmails: { $addToSet: "$email" },
      },
    },
    {
      $match: {
        attempts: { $gte: 5 }, // 5 or more failed attempts
      },
    },
  ]);
};

// Static method to cleanup old records
loginAttemptSchema.statics.cleanupOldRecords = function (daysToKeep = 30) {
  const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
  return this.deleteMany({
    timestamp: { $lt: cutoffDate },
  });
};

module.exports = mongoose.model("LoginAttempt", loginAttemptSchema);


