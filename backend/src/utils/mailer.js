const nodemailer = require('nodemailer');

/**
 * Sends password-reset emails through a real Gmail account via SMTP.
 *
 * Setup (see backend/.env.example):
 *   1. Turn on 2-Step Verification on the Gmail account that will send
 *      these emails: https://myaccount.google.com/security
 *   2. Create an App Password: https://myaccount.google.com/apppasswords
 *      (Gmail no longer accepts the normal account password for SMTP.)
 *   3. Set GMAIL_USER to the full gmail address and GMAIL_APP_PASSWORD to
 *      the 16-character app password in backend/.env.
 *
 * The transporter is created lazily (on first send) rather than at
 * module-load time, so a missing/incomplete config doesn't crash the
 * whole server at startup — only the forgot-password request that
 * actually needs it fails, with a clear error for the admin in the logs.
 */

let cachedTransporter = null;

function getTransporter() {
  if (cachedTransporter) return cachedTransporter;

  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;

  if (!user || !pass) {
    throw new Error(
      'GMAIL_USER / GMAIL_APP_PASSWORD are not set in backend/.env. ' +
      'Password-reset emails cannot be sent until these are configured — see backend/.env.example.'
    );
  }

  cachedTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass }
  });
  return cachedTransporter;
}

/**
 * Sends the "reset your password" email. resetUrl should already contain
 * the token and email as query params (built by the caller in auth.js)
 * so the recipient just has to click the button/link.
 */
async function sendPasswordResetEmail({ to, name, resetUrl }) {
  const transporter = getTransporter();
  const fromUser = process.env.GMAIL_USER;
  const displayName = name ? name.split(' ')[0] : 'there';

  const text =
    `Hi ${displayName},\n\n` +
    `We received a request to reset the password for your Talisay City College ` +
    `Management System account.\n\n` +
    `Reset your password: ${resetUrl}\n\n` +
    `This link expires in 1 hour. If you didn't request this, you can safely ` +
    `ignore this email — your password won't be changed.\n\n` +
    `— Talisay City College Management System`;

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1a1a1a;">
      <h2 style="margin:0 0 16px;color:#0f5132;">Reset your password</h2>
      <p>Hi ${escapeHtml(displayName)},</p>
      <p>We received a request to reset the password for your <strong>Talisay City College Management System</strong> account.</p>
      <p style="margin:28px 0;">
        <a href="${resetUrl}" style="background:#1c8a4b;color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;display:inline-block;">
          Reset Password
        </a>
      </p>
      <p style="color:#555;font-size:14px;">Or copy and paste this link into your browser:<br />
        <a href="${resetUrl}" style="color:#1c8a4b;word-break:break-all;">${resetUrl}</a>
      </p>
      <p style="color:#555;font-size:14px;">This link expires in <strong>1 hour</strong>. If you didn't request this, you can safely ignore this email — your password won't be changed.</p>
      <hr style="border:none;border-top:1px solid #e5e5e5;margin:24px 0;" />
      <p style="color:#999;font-size:12px;">Talisay City College Management System</p>
    </div>
  `;

  await transporter.sendMail({
    from: `"Talisay City College" <${fromUser}>`,
    to,
    subject: 'Reset your Talisay City College password',
    text,
    html
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { sendPasswordResetEmail };
