const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");
const ExpressBrute = require("express-brute");
const RedisStore = require("express-brute-redis");
const Redis = require("redis");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss");

// Redis client for brute force protection
let redisClient;
if (process.env.REDIS_URL) {
  redisClient = Redis.createClient({ url: process.env.REDIS_URL });
  redisClient.connect().catch(console.error);
}

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: "Too many requests from this IP, please try again later",
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: "Too many requests from this IP, please try again later",
      retryAfter: Math.round(req.rateLimit.resetTime / 1000),
    });
  },
});

// Strict rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    success: false,
    message: "Too many authentication attempts, please try again later",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: "Too many authentication attempts, please try again later",
      retryAfter: Math.round(req.rateLimit.resetTime / 1000),
    });
  },
});

// Password reset rate limiting
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 password reset requests per hour
  message: {
    success: false,
    message: "Too many password reset attempts, please try again later",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Email verification rate limiting
const emailVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each IP to 5 email verification requests per hour
  message: {
    success: false,
    message: "Too many email verification attempts, please try again later",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Speed limiter for additional protection
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // allow 50 requests per 15 minutes, then...
  delayMs: 500, // add 500ms delay per request above 50
});

// Brute force protection for login
let bruteForceStore;
let bruteForce;

if (redisClient) {
  bruteForceStore = new RedisStore({
    client: redisClient,
  });

  bruteForce = new ExpressBrute(bruteForceStore, {
    freeRetries: 5, // Number of attempts before rate limiting kicks in
    minWait: 5 * 60 * 1000, // 5 minutes
    maxWait: 15 * 60 * 1000, // 15 minutes
    lifetime: 24 * 60 * 60 * 1000, // 24 hours
    skipSuccessfulRequests: true,
    skipFailedRequests: false,
    refreshTimeoutOnRequest: false,
    handleStoreError: (error) => {
      console.error("Brute force store error:", error);
    },
  });
} else {
  // Fallback to memory store if Redis is not available
  bruteForce = new ExpressBrute({
    freeRetries: 5,
    minWait: 5 * 60 * 1000,
    maxWait: 15 * 60 * 1000,
    lifetime: 24 * 60 * 60 * 1000,
    skipSuccessfulRequests: true,
    skipFailedRequests: false,
    refreshTimeoutOnRequest: false,
  });
}

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  // Sanitize request body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }

  // Sanitize query parameters
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }

  // Sanitize URL parameters
  if (req.params) {
    req.params = sanitizeObject(req.params);
  }

  next();
};

// Recursively sanitize objects
const sanitizeObject = (obj) => {
  if (typeof obj === "string") {
    return xss(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }

  if (obj && typeof obj === "object") {
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        sanitized[key] = sanitizeObject(obj[key]);
      }
    }
    return sanitized;
  }

  return obj;
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  // Remove X-Powered-By header
  res.removeHeader("X-Powered-By");

  // Set security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );

  // Content Security Policy
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https:; " +
      "font-src 'self' https:; " +
      "connect-src 'self' https:; " +
      "frame-ancestors 'none';"
  );

  next();
};

// IP whitelist middleware (for admin endpoints)
const ipWhitelist = (allowedIPs) => {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;

    if (allowedIPs.includes(clientIP)) {
      next();
    } else {
      res.status(403).json({
        success: false,
        message: "Access denied from this IP address",
      });
    }
  };
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      timestamp: new Date().toISOString(),
    };

    // Log only errors in production
    if (process.env.NODE_ENV === "production" && res.statusCode >= 400) {
      console.error("Request error:", logData);
    } else if (process.env.NODE_ENV !== "production") {
      console.log("Request:", logData);
    }
  });

  next();
};

module.exports = {
  generalLimiter,
  authLimiter,
  passwordResetLimiter,
  emailVerificationLimiter,
  speedLimiter,
  bruteForce,
  sanitizeInput,
  securityHeaders,
  ipWhitelist,
  requestLogger,
  mongoSanitize,
};


