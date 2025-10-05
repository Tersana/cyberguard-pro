const nodemailer = require("nodemailer");
const path = require("path");

class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  initializeTransporter() {
    try {
      this.transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT) || 587,
        secure: process.env.EMAIL_PORT === "465", // true for 465, false for other ports
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
        tls: {
          rejectUnauthorized: false,
        },
      });

      // Verify connection configuration
      this.transporter.verify((error, success) => {
        if (error) {
          console.error("Email service configuration error:", error);
        } else {
          console.log("Email service is ready to send messages");
        }
      });
    } catch (error) {
      console.error("Failed to initialize email service:", error);
    }
  }

  async sendEmail(to, subject, html, text = null) {
    if (!this.transporter) {
      throw new Error("Email service not initialized");
    }

    try {
      const mailOptions = {
        from:
          process.env.EMAIL_FROM || "CyberGuard Pro <noreply@cyberguard.com>",
        to,
        subject,
        html,
        text: text || this.stripHtml(html),
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log("Email sent successfully:", result.messageId);
      return result;
    } catch (error) {
      console.error("Failed to send email:", error);
      throw error;
    }
  }

  async sendEmailVerification(user, verificationToken) {
    const verificationUrl = `${process.env.BACKEND_URL}/api/auth/verify?token=${verificationToken}`;

    const html = this.getEmailVerificationTemplate(user, verificationUrl);

    return await this.sendEmail(
      user.email,
      "Verify Your Email - CyberGuard Pro",
      html
    );
  }

  async sendPasswordReset(user, resetToken) {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    const html = this.getPasswordResetTemplate(user, resetUrl);

    return await this.sendEmail(
      user.email,
      "Reset Your Password - CyberGuard Pro",
      html
    );
  }

  async sendWelcomeEmail(user) {
    const html = this.getWelcomeTemplate(user);

    return await this.sendEmail(user.email, "Welcome to CyberGuard Pro!", html);
  }

  async sendSecurityAlert(user, alertType, details) {
    const html = this.getSecurityAlertTemplate(user, alertType, details);

    return await this.sendEmail(
      user.email,
      "Security Alert - CyberGuard Pro",
      html
    );
  }

  async sendTwoFactorBackupCodes(user, backupCodes) {
    const html = this.getTwoFactorBackupCodesTemplate(user, backupCodes);

    return await this.sendEmail(
      user.email,
      "Your Two-Factor Authentication Backup Codes",
      html
    );
  }

  getEmailVerificationTemplate(user, verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛡️ CyberGuard Pro</h1>
            <p>Verify Your Email Address</p>
          </div>
          <div class="content">
            <h2>Hello ${user.firstName}!</h2>
            <p>Thank you for signing up for CyberGuard Pro. To complete your registration, please verify your email address by clicking the button below:</p>
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </div>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #007bff;">${verificationUrl}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account with CyberGuard Pro, you can safely ignore this email.</p>
          </div>
          <div class="footer">
            <p>© 2024 CyberGuard Pro. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getPasswordResetTemplate(user, resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛡️ CyberGuard Pro</h1>
            <p>Password Reset Request</p>
          </div>
          <div class="content">
            <h2>Hello ${user.firstName}!</h2>
            <p>We received a request to reset your password for your CyberGuard Pro account.</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #dc3545;">${resetUrl}</p>
            <div class="warning">
              <p><strong>⚠️ Security Notice:</strong></p>
              <ul>
                <li>This link will expire in 10 minutes</li>
                <li>If you didn't request this reset, please ignore this email</li>
                <li>Your password will remain unchanged until you click the link above</li>
              </ul>
            </div>
          </div>
          <div class="footer">
            <p>© 2024 CyberGuard Pro. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getWelcomeTemplate(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to CyberGuard Pro</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
          .feature { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #007bff; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛡️ Welcome to CyberGuard Pro!</h1>
            <p>Your cybersecurity toolkit is ready</p>
          </div>
          <div class="content">
            <h2>Hello ${user.firstName}!</h2>
            <p>Welcome to CyberGuard Pro! Your account has been successfully created and verified. You now have access to our comprehensive cybersecurity analysis platform.</p>
            
            <h3>🚀 What you can do with CyberGuard Pro:</h3>
            
            <div class="feature">
              <h4>🔍 Network Security Analysis</h4>
              <p>Advanced port scanning, service detection, and network vulnerability assessment</p>
            </div>
            
            <div class="feature">
              <h4>🌐 Web Application Security</h4>
              <p>XSS testing, SSL/TLS analysis, and comprehensive web security scanning</p>
            </div>
            
            <div class="feature">
              <h4>🔐 Cryptographic Tools</h4>
              <p>Hash analysis, password strength testing, and cryptographic operations</p>
            </div>
            
            <div class="feature">
              <h4>🦠 Threat Intelligence</h4>
              <p>VirusTotal integration, WHOIS lookups, and real-time threat detection</p>
            </div>
            
            <p style="text-align: center; margin-top: 30px;">
              <a href="${process.env.FRONTEND_URL}" style="display: inline-block; background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px;">Start Using CyberGuard Pro</a>
            </p>
          </div>
          <div class="footer">
            <p>© 2024 CyberGuard Pro. All rights reserved.</p>
            <p>Need help? Contact our support team at support@cyberguard.com</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getSecurityAlertTemplate(user, alertType, details) {
    const alertMessages = {
      login_from_new_device: "New device login detected",
      password_changed: "Your password has been changed",
      two_factor_enabled: "Two-factor authentication has been enabled",
      two_factor_disabled: "Two-factor authentication has been disabled",
      suspicious_activity: "Suspicious activity detected",
    };

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Alert</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
          .alert { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🚨 Security Alert</h1>
            <p>CyberGuard Pro</p>
          </div>
          <div class="content">
            <h2>Hello ${user.firstName}!</h2>
            <div class="alert">
              <h3>${alertMessages[alertType] || "Security Alert"}</h3>
              <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
              <p><strong>Details:</strong> ${details}</p>
            </div>
            <p>If this activity was not authorized by you, please:</p>
            <ul>
              <li>Change your password immediately</li>
              <li>Review your account security settings</li>
              <li>Contact our support team if needed</li>
            </ul>
            <p>If you recognize this activity, no further action is required.</p>
          </div>
          <div class="footer">
            <p>© 2024 CyberGuard Pro. All rights reserved.</p>
            <p>This is an automated security alert, please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getTwoFactorBackupCodesTemplate(user, backupCodes) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Two-Factor Authentication Backup Codes</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
          .codes { background: white; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 16px; text-align: center; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Two-Factor Authentication</h1>
            <p>Your Backup Codes</p>
          </div>
          <div class="content">
            <h2>Hello ${user.firstName}!</h2>
            <p>Here are your two-factor authentication backup codes. Store these codes in a safe place - you'll need them if you lose access to your authenticator app.</p>
            
            <div class="codes">
              ${backupCodes
                .map(
                  (code) =>
                    `<div style="margin: 5px 0; font-weight: bold;">${code}</div>`
                )
                .join("")}
            </div>
            
            <div class="warning">
              <p><strong>⚠️ Important Security Information:</strong></p>
              <ul>
                <li>Each code can only be used once</li>
                <li>Store these codes in a secure location</li>
                <li>Don't share these codes with anyone</li>
                <li>Generate new codes if you suspect they've been compromised</li>
              </ul>
            </div>
          </div>
          <div class="footer">
            <p>© 2024 CyberGuard Pro. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  stripHtml(html) {
    return html
      .replace(/<[^>]*>/g, "")
      .replace(/\s+/g, " ")
      .trim();
  }
}

module.exports = new EmailService();


