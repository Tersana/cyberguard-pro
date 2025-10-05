const Joi = require("joi");

// User registration validation
const registerSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      "string.min": "Password must be at least 8 characters long",
      "string.max": "Password cannot exceed 128 characters",
      "string.pattern.base":
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      "any.required": "Password is required",
    }),
  firstName: Joi.string().min(1).max(50).trim().required().messages({
    "string.min": "First name is required",
    "string.max": "First name cannot exceed 50 characters",
    "any.required": "First name is required",
  }),
  lastName: Joi.string().min(1).max(50).trim().required().messages({
    "string.min": "Last name is required",
    "string.max": "Last name cannot exceed 50 characters",
    "any.required": "Last name is required",
  }),
  confirmPassword: Joi.string().valid(Joi.ref("password")).required().messages({
    "any.only": "Passwords do not match",
    "any.required": "Password confirmation is required",
  }),
  acceptTerms: Joi.boolean().valid(true).required().messages({
    "any.only": "You must accept the terms and conditions",
    "any.required": "You must accept the terms and conditions",
  }),
});

// User login validation
const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().messages({
    "any.required": "Password is required",
  }),
  rememberMe: Joi.boolean().default(false),
});

// Password reset request validation
const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),
});

// Password reset validation
const resetPasswordSchema = Joi.object({
  token: Joi.string().required().messages({
    "any.required": "Reset token is required",
  }),
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      "string.min": "Password must be at least 8 characters long",
      "string.max": "Password cannot exceed 128 characters",
      "string.pattern.base":
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      "any.required": "Password is required",
    }),
  confirmPassword: Joi.string().valid(Joi.ref("password")).required().messages({
    "any.only": "Passwords do not match",
    "any.required": "Password confirmation is required",
  }),
});

// Email verification validation
const verifyEmailSchema = Joi.object({
  token: Joi.string().required().messages({
    "any.required": "Verification token is required",
  }),
});

// Change password validation
const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required().messages({
    "any.required": "Current password is required",
  }),
  newPassword: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      "string.min": "Password must be at least 8 characters long",
      "string.max": "Password cannot exceed 128 characters",
      "string.pattern.base":
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      "any.required": "New password is required",
    }),
  confirmNewPassword: Joi.string()
    .valid(Joi.ref("newPassword"))
    .required()
    .messages({
      "any.only": "Passwords do not match",
      "any.required": "Password confirmation is required",
    }),
});

// Profile update validation
const updateProfileSchema = Joi.object({
  firstName: Joi.string().min(1).max(50).trim().messages({
    "string.min": "First name cannot be empty",
    "string.max": "First name cannot exceed 50 characters",
  }),
  lastName: Joi.string().min(1).max(50).trim().messages({
    "string.min": "Last name cannot be empty",
    "string.max": "Last name cannot exceed 50 characters",
  }),
  profile: Joi.object({
    bio: Joi.string().max(500).allow("").messages({
      "string.max": "Bio cannot exceed 500 characters",
    }),
    company: Joi.string().max(100).allow("").messages({
      "string.max": "Company name cannot exceed 100 characters",
    }),
    website: Joi.string().uri().allow("").messages({
      "string.uri": "Please provide a valid website URL",
    }),
    location: Joi.string().max(100).allow("").messages({
      "string.max": "Location cannot exceed 100 characters",
    }),
  }),
  preferences: Joi.object({
    theme: Joi.string().valid("light", "dark", "auto").messages({
      "any.only": "Theme must be light, dark, or auto",
    }),
    notifications: Joi.object({
      email: Joi.boolean(),
      security: Joi.boolean(),
      updates: Joi.boolean(),
    }),
    language: Joi.string().length(2).messages({
      "string.length": "Language code must be 2 characters",
    }),
  }),
});

// Two-factor authentication validation
const enableTwoFactorSchema = Joi.object({
  secret: Joi.string().required().messages({
    "any.required": "Two-factor secret is required",
  }),
  token: Joi.string()
    .length(6)
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      "string.length": "Token must be 6 digits",
      "string.pattern.base": "Token must contain only numbers",
      "any.required": "Verification token is required",
    }),
});

const verifyTwoFactorSchema = Joi.object({
  token: Joi.string()
    .length(6)
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      "string.length": "Token must be 6 digits",
      "string.pattern.base": "Token must contain only numbers",
      "any.required": "Token is required",
    }),
});

const disableTwoFactorSchema = Joi.object({
  token: Joi.string()
    .length(6)
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      "string.length": "Token must be 6 digits",
      "string.pattern.base": "Token must contain only numbers",
      "any.required": "Token is required",
    }),
  password: Joi.string().required().messages({
    "any.required": "Password is required for security verification",
  }),
});

// Device management validation
const revokeDeviceSchema = Joi.object({
  deviceId: Joi.string().required().messages({
    "any.required": "Device ID is required",
  }),
});

// Validation middleware
const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join("."),
        message: detail.message,
      }));

      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors,
      });
    }

    req.body = value;
    next();
  };
};

// Query parameter validation
const validateQuery = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.query, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join("."),
        message: detail.message,
      }));

      return res.status(400).json({
        success: false,
        message: "Query validation failed",
        errors,
      });
    }

    req.query = value;
    next();
  };
};

module.exports = {
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
  validateQuery,
};


