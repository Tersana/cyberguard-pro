# 🔐 CyberGuard Pro Authentication System Setup Guide

## Overview

This guide will help you set up the complete authentication system for CyberGuard Pro, including user registration, login, two-factor authentication, and security features.

## 🏗️ Architecture

The authentication system consists of:

- **Backend Server** (Node.js + Express) - Handles authentication logic
- **Database** (MongoDB) - Stores user data and sessions
- **Frontend Pages** - Login, registration, profile management
- **Security Features** - Rate limiting, account lockout, CSRF protection

## 📋 Prerequisites

Before starting, ensure you have:

- **Node.js** (v14 or higher)
- **MongoDB** (local or cloud instance)
- **Redis** (optional, for advanced rate limiting)
- **Email Service** (Gmail, SendGrid, etc.)

## 🚀 Quick Start

### 1. Database Setup

#### MongoDB Setup

```bash
# Install MongoDB (if not already installed)
# Windows: Download from https://www.mongodb.com/try/download/community
# macOS: brew install mongodb-community
# Linux: sudo apt-get install mongodb

# Start MongoDB service
# Windows: net start MongoDB
# macOS: brew services start mongodb-community
# Linux: sudo systemctl start mongod
```

#### Redis Setup (Optional)

```bash
# Install Redis (optional, for advanced features)
# Windows: Download from https://github.com/microsoftarchive/redis/releases
# macOS: brew install redis
# Linux: sudo apt-get install redis-server

# Start Redis
# Windows: redis-server
# macOS: brew services start redis
# Linux: sudo systemctl start redis
```

### 2. Authentication Server Setup

1. **Navigate to the auth server directory:**

   ```bash
   cd auth-server
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Configure environment variables:**

   ```bash
   # Copy the example environment file
   cp env.example .env

   # Edit .env with your configuration
   notepad .env  # Windows
   nano .env     # Linux/macOS
   ```

4. **Configure your .env file:**

   ```env
   # Database Configuration
   MONGODB_URI=mongodb://localhost:27017/cyberguard_auth
   REDIS_URL=redis://localhost:6379

   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-this-in-production
   JWT_ACCESS_EXPIRES_IN=15m
   JWT_REFRESH_EXPIRES_IN=30d

   # Email Configuration
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   EMAIL_FROM=CyberGuard Pro <noreply@cyberguard.com>

   # Server Configuration
   PORT=3002
   NODE_ENV=development
   FRONTEND_URL=http://localhost:3000
   BACKEND_URL=http://localhost:3002
   ```

5. **Start the authentication server:**

   ```bash
   npm start
   ```

   Or use the provided batch file:

   ```bash
   # Windows
   start-auth-server.bat
   ```

### 3. Frontend Integration

The authentication system is already integrated into the main CyberGuard Pro application. The frontend includes:

- **Login Page** (`auth/login.html`)
- **Registration Page** (`auth/register.html`)
- **Profile Management** (`auth/profile.html`)
- **Password Reset** (`auth/forgot-password.html`, `auth/reset-password.html`)

## 🔧 Configuration

### Email Service Setup

#### Gmail Setup

1. Enable 2-factor authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate a password for "Mail"
3. Use the app password in your `.env` file

#### SendGrid Setup

1. Create a SendGrid account
2. Generate an API key
3. Update your `.env` file:
   ```env
   EMAIL_HOST=smtp.sendgrid.net
   EMAIL_PORT=587
   EMAIL_USER=apikey
   EMAIL_PASS=your-sendgrid-api-key
   ```

### Security Configuration

#### Rate Limiting

- **General API**: 100 requests per 15 minutes
- **Authentication**: 5 requests per 15 minutes
- **Password Reset**: 3 requests per hour
- **Email Verification**: 5 requests per hour

#### Account Security

- **Password Requirements**: 8+ characters, uppercase, lowercase, number, special character
- **Account Lockout**: 5 failed attempts = 15-minute lockout
- **Session Management**: 7 days (30 days with "Remember Me")
- **Two-Factor Authentication**: TOTP with backup codes

## 🛡️ Security Features

### Implemented Security Measures

1. **Password Security**

   - bcrypt hashing (cost factor 12)
   - Strong password requirements
   - Password strength indicator

2. **Account Protection**

   - Account lockout after failed attempts
   - Email verification required
   - Suspicious activity detection

3. **Session Security**

   - JWT access tokens (15 minutes)
   - HTTP-only refresh tokens
   - Device management
   - Session revocation

4. **Two-Factor Authentication**

   - TOTP (Time-based One-Time Password)
   - QR code setup
   - Backup codes
   - Multiple device support

5. **Rate Limiting**

   - API endpoint protection
   - Brute force prevention
   - IP-based limiting

6. **Input Validation**
   - Joi schema validation
   - XSS protection
   - SQL injection prevention
   - Input sanitization

## 📱 API Endpoints

### Authentication Endpoints

| Method | Endpoint                    | Description            |
| ------ | --------------------------- | ---------------------- |
| POST   | `/api/auth/register`        | User registration      |
| GET    | `/api/auth/verify`          | Email verification     |
| POST   | `/api/auth/login`           | User login             |
| POST   | `/api/auth/refresh`         | Token refresh          |
| POST   | `/api/auth/logout`          | User logout            |
| POST   | `/api/auth/forgot-password` | Password reset request |
| POST   | `/api/auth/reset-password`  | Password reset         |
| GET    | `/api/me`                   | Get user profile       |
| PUT    | `/api/me`                   | Update user profile    |

### Two-Factor Authentication

| Method | Endpoint                | Description        |
| ------ | ----------------------- | ------------------ |
| GET    | `/api/2fa/setup`        | Get 2FA setup info |
| POST   | `/api/2fa/enable`       | Enable 2FA         |
| POST   | `/api/2fa/verify`       | Verify 2FA code    |
| POST   | `/api/2fa/disable`      | Disable 2FA        |
| GET    | `/api/2fa/backup-codes` | Get backup codes   |

### Device Management

| Method | Endpoint                  | Description               |
| ------ | ------------------------- | ------------------------- |
| GET    | `/api/devices`            | List active sessions      |
| DELETE | `/api/devices/:id`        | Revoke specific session   |
| DELETE | `/api/devices/revoke-all` | Revoke all other sessions |

## 🔍 Testing

### Health Check

```bash
curl http://localhost:3002/health
```

### Test Registration

```bash
curl -X POST http://localhost:3002/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "confirmPassword": "SecurePass123!",
    "acceptTerms": true
  }'
```

### Test Login

```bash
curl -X POST http://localhost:3002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Database Connection Error

```
Error: connect ECONNREFUSED 127.0.0.1:27017
```

**Solution**: Ensure MongoDB is running

```bash
# Windows
net start MongoDB

# macOS/Linux
sudo systemctl start mongod
```

#### 2. Email Service Error

```
Error: Invalid login: 535-5.7.8 Username and Password not accepted
```

**Solution**:

- Check email credentials in `.env`
- For Gmail, use App Password instead of regular password
- Ensure 2FA is enabled on Gmail account

#### 3. CORS Error

```
Access to fetch at 'http://localhost:3002' from origin 'http://localhost:3000' has been blocked by CORS policy
```

**Solution**: Check `FRONTEND_URL` in `.env` file matches your frontend URL

#### 4. Token Expired Error

```
Error: Token expired
```

**Solution**: The system automatically refreshes tokens. If persistent, clear localStorage and login again.

### Debug Mode

Enable debug logging by setting:

```env
NODE_ENV=development
```

Check server logs for detailed error information.

## 🔒 Production Deployment

### Security Checklist

- [ ] Change all default secrets in `.env`
- [ ] Use HTTPS in production
- [ ] Set secure cookie options
- [ ] Configure proper CORS origins
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy
- [ ] Set up SSL certificates
- [ ] Configure firewall rules

### Environment Variables for Production

```env
NODE_ENV=production
MONGODB_URI=mongodb://your-production-db
REDIS_URL=redis://your-production-redis
JWT_SECRET=your-production-jwt-secret
JWT_REFRESH_SECRET=your-production-refresh-secret
EMAIL_HOST=your-production-smtp
EMAIL_USER=your-production-email
EMAIL_PASS=your-production-password
FRONTEND_URL=https://your-domain.com
BACKEND_URL=https://api.your-domain.com
```

## 📚 Additional Resources

- [JWT.io](https://jwt.io/) - JWT token debugging
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Express.js Security](https://expressjs.com/en/advanced/best-practice-security.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## 🆘 Support

If you encounter issues:

1. Check the server logs for error messages
2. Verify all environment variables are set correctly
3. Ensure all services (MongoDB, Redis) are running
4. Check network connectivity between services
5. Review the troubleshooting section above

For additional help, check the main CyberGuard Pro documentation or create an issue in the project repository.

---

**CyberGuard Pro Authentication System** - Secure, scalable, and production-ready authentication for your cybersecurity platform! 🛡️


