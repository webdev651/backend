const nodemailer = require('nodemailer');

/**
 * Centralized email service — the ONLY place in the backend that talks to
 * SMTP. Routes call the send*Email() helpers below; none of them build a
 * transporter or touch credentials themselves.
 *
 * Configuration (Render environment variables — never hard-code these):
 *   SMTP_HOST        default smtp.gmail.com
 *   SMTP_PORT        default 465
 *   SMTP_SECURE      default true  (true = implicit TLS, use with 465;
 *                    false = STARTTLS, use with 587)
 *   SMTP_USER        Gmail address that sends the mail
 *   SMTP_PASS        Gmail *App Password* (16 chars) — not the account password
 *   SMTP_FROM_NAME   default "Talisay City College"
 *   SMTP_FROM_EMAIL  default SMTP_USER
 *   FRONTEND_URL     public Netlify URL used to build links inside emails
 *
 * EmailJS (HTTPS) — works on Render's FREE tier, where SMTP is blocked:
 *   EMAILJS_SERVICE_ID   your EmailJS email service (connected to the Gmail account)
 *   EMAILJS_TEMPLATE_ID  ONE generic template (see README notes below)
 *   EMAILJS_PUBLIC_KEY   Account > General > Public Key
 *   EMAILJS_PRIVATE_KEY  Account > General > Private Key (server-side only!)
 * When all four are set, EmailJS is used; otherwise SMTP (above) is used.
 * The generic template must have: To Email = {{to_email}}, Subject =
 * {{subject}}, and the body = {{{html_body}}} (THREE braces so the HTML is
 * not escaped). Free EmailJS allows only 2 templates, so every message type
 * (verify, reset, welcome, ...) reuses this one.
 *
 * Backward compatible: the project previously used GMAIL_USER and
 * GMAIL_APP_PASSWORD. They are still honoured as fallbacks so an existing
 * Render setup keeps working; SMTP_* wins when both are set.
 *
 * The transporter is created lazily so a missing/incomplete config never
 * crashes the server at startup — only the email that needs it fails.
 */

const DEFAULT_FRONTEND_URL = 'https://tccsystem.netlify.app';

function readConfig() {
  const user = process.env.SMTP_USER || process.env.GMAIL_USER || '';
  const pass = process.env.SMTP_PASS || process.env.GMAIL_APP_PASSWORD || '';
  const port = Number(process.env.SMTP_PORT) || 465;
  const secureEnv = process.env.SMTP_SECURE;
  // 465 is implicit TLS; anything else defaults to STARTTLS unless told otherwise.
  const secure = secureEnv === undefined || secureEnv === ''
    ? port === 465
    : String(secureEnv).toLowerCase() === 'true';

  return {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port,
    secure,
    user,
    // Gmail displays App Passwords in groups of four ("abcd efgh ijkl mnop");
    // the spaces are not part of the password.
    pass: pass.replace(/\s+/g, ''),
    fromName: process.env.SMTP_FROM_NAME || 'Talisay City College',
    fromEmail: process.env.SMTP_FROM_EMAIL || user
  };
}

function readEmailJsConfig() {
  const c = {
    serviceId: process.env.EMAILJS_SERVICE_ID || '',
    templateId: process.env.EMAILJS_TEMPLATE_ID || '',
    publicKey: process.env.EMAILJS_PUBLIC_KEY || '',
    privateKey: process.env.EMAILJS_PRIVATE_KEY || ''
  };
  c.enabled = !!(c.serviceId && c.templateId && c.publicKey && c.privateKey);
  return c;
}

function usingEmailJs() { return readEmailJsConfig().enabled; }

async function sendViaEmailJs({ to, subject, text, html }) {
  const c = readEmailJsConfig();
  const cfg = readConfig();
  let res;
  try {
    res = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_id: c.serviceId,
        template_id: c.templateId,
        user_id: c.publicKey,
        accessToken: c.privateKey,
        template_params: {
          to_email: to,
          subject,
          html_body: html,
          text_body: text,
          from_name: cfg.fromName
        }
      }),
      signal: AbortSignal.timeout(15000)
    });
  } catch (err) {
    const e = new Error('EmailJS request failed.');
    e.code = (err && err.name === 'TimeoutError') ? 'ETIMEDOUT' : 'ECONNECTION';
    throw e;
  }
  if (!res.ok) {
    // EmailJS replies with a short plain-text reason; it never echoes our keys.
    let reason = '';
    try { reason = (await res.text()).slice(0, 200); } catch (e) { /* ignore */ }
    const e = new Error('EmailJS rejected the request.');
    e.code = 'EMAILJS_' + res.status;
    e.responseCode = res.status;
    e.command = reason;
    throw e;
  }
}

let cachedTransporter = null;
let cachedKey = '';

function getTransporter() {
  const cfg = readConfig();
  if (!cfg.user || !cfg.pass) {
    const err = new Error('Email is not configured (SMTP_USER / SMTP_PASS missing).');
    err.code = 'EMAIL_NOT_CONFIGURED';
    throw err;
  }
  // Rebuild only if the config changed (never keeps the password anywhere but memory).
  const key = [cfg.host, cfg.port, cfg.secure, cfg.user, cfg.pass.length].join('|');
  if (cachedTransporter && key === cachedKey) return { transporter: cachedTransporter, cfg };

  cachedTransporter = nodemailer.createTransport({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth: { user: cfg.user, pass: cfg.pass },
    // Fail fast instead of hanging a request when the network blocks SMTP.
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });
  cachedKey = key;
  return { transporter: cachedTransporter, cfg };
}

/** Public base URL of the Netlify frontend, no trailing slash. */
function getFrontendUrl() {
  return String(process.env.FRONTEND_URL || DEFAULT_FRONTEND_URL).trim().replace(/\/+$/, '');
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Keeps a failure's technical detail server-side; never includes secrets/tokens. */
function describeError(err) {
  const bits = [];
  if (err && err.code) bits.push(err.code);
  if (err && err.responseCode) bits.push('smtp ' + err.responseCode);
  if (err && err.command) bits.push('during ' + err.command);
  return bits.join(' / ') || 'unknown error';
}

/**
 * Low-level send. Throws an Error with .code = 'EMAIL_SEND_FAILED' (or
 * 'EMAIL_NOT_CONFIGURED') on failure. Callers decide whether a failure is
 * fatal for their request — none of them should let it crash the server.
 */
async function sendEmail({ to, subject, text, html }) {
  if (usingEmailJs()) {
    try {
      await sendViaEmailJs({ to, subject, text, html });
      return;
    } catch (err) {
      console.error('Email send failed via EmailJS (' + describeError(err) + ')');
      const wrapped = new Error('Email could not be sent.');
      wrapped.code = 'EMAIL_SEND_FAILED';
      wrapped.detail = describeError(err);
      throw wrapped;
    }
  }
  const { transporter, cfg } = getTransporter();
  try {
    await transporter.sendMail({
      from: `"${cfg.fromName.replace(/"/g, '')}" <${cfg.fromEmail}>`,
      to,
      subject,
      text,
      html
    });
  } catch (err) {
    console.error('Email send failed (' + describeError(err) + ')');
    const wrapped = new Error('Email could not be sent.');
    wrapped.code = 'EMAIL_SEND_FAILED';
    wrapped.detail = describeError(err);
    throw wrapped;
  }
}

/* ------------------------------ Templates ------------------------------ */

function layout({ heading, bodyHtml, buttonLabel, buttonUrl, footnoteHtml }) {
  const button = buttonUrl
    ? `<p style="margin:28px 0;text-align:center;">
         <a href="${escapeHtml(buttonUrl)}" style="background:#1c8a4b;color:#ffffff;text-decoration:none;padding:13px 28px;border-radius:8px;font-weight:700;display:inline-block;letter-spacing:.3px;">${escapeHtml(buttonLabel)}</a>
       </p>
       <p style="color:#555;font-size:13px;">If the button doesn't work, copy and paste this link into your browser:<br />
         <a href="${escapeHtml(buttonUrl)}" style="color:#1c8a4b;word-break:break-all;">${escapeHtml(buttonUrl)}</a></p>`
    : '';
  return `<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f3f5f4;">
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:0 auto;padding:24px;">
    <div style="background:#ffffff;border-radius:12px;padding:32px;color:#1a1a1a;border:1px solid #e5e7e6;">
      <p style="margin:0 0 4px;font-size:13px;font-weight:700;letter-spacing:2px;color:#0f5132;text-align:center;">TALISAY CITY COLLEGE</p>
      <h2 style="margin:0 0 20px;color:#0f5132;text-align:center;font-size:20px;">${escapeHtml(heading)}</h2>
      ${bodyHtml}
      ${button}
      ${footnoteHtml ? `<p style="color:#555;font-size:14px;">${footnoteHtml}</p>` : ''}
      <hr style="border:none;border-top:1px solid #e5e5e5;margin:24px 0;" />
      <p style="color:#999;font-size:12px;margin:0;text-align:center;">Talisay City College<br />College Management Information System</p>
    </div>
  </div>
</body></html>`;
}

function firstName(name) {
  return String(name || '').trim().split(/\s+/)[0] || 'there';
}

/* ----------------------------- Public senders ---------------------------- */

async function sendVerificationEmail({ to, name, verifyUrl, expiresInHours = 24 }) {
  const n = firstName(name);
  const text =
    `TALISAY CITY COLLEGE\n\nHello, ${n}\n\n` +
    `Thank you for registering for the Talisay City College Management Information System.\n\n` +
    `Please verify your email address by opening this link:\n${verifyUrl}\n\n` +
    `This verification link will expire in ${expiresInHours} hours.\n\n` +
    `If you did not create this account, you may safely ignore this email.\n\n` +
    `Talisay City College\nCollege Management Information System`;
  const html = layout({
    heading: 'Verify your email address',
    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>Thank you for registering for the <strong>Talisay City College Management Information System</strong>.</p>` +
      `<p>Please verify your email address by clicking the button below.</p>`,
    buttonLabel: 'VERIFY EMAIL',
    buttonUrl: verifyUrl,
    footnoteHtml:
      `This verification link will expire in ${expiresInHours} hours.<br />` +
      `If you did not create this account, you may safely ignore this email.`
  });
  return sendEmail({ to, subject: 'Verify Your Talisay City College Account', text, html });
}

async function sendPasswordResetEmail({ to, name, resetUrl, expiresInMinutes = 60 }) {
  const n = firstName(name);
  const text =
    `TALISAY CITY COLLEGE\n\nHello, ${n}\n\n` +
    `We received a request to reset your password.\n\n` +
    `Reset your password: ${resetUrl}\n\n` +
    `This link will expire in ${expiresInMinutes} minutes and can only be used once.\n\n` +
    `If you did not request a password reset, you may safely ignore this email.\n\n` +
    `Talisay City College\nCollege Management Information System`;
  const html = layout({
    heading: 'Reset your password',
    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>We received a request to reset your password.</p>`,
    buttonLabel: 'RESET PASSWORD',
    buttonUrl: resetUrl,
    footnoteHtml:
      `This link will expire in ${expiresInMinutes} minutes and can only be used once.<br />` +
      `If you did not request a password reset, you may safely ignore this email.`
  });
  return sendEmail({ to, subject: 'Reset Your Talisay City College Password', text, html });
}

async function sendWelcomeEmail({ to, name, role }) {
  const n = firstName(name);
  const accountType = role === 'teacher' ? 'Teacher' : role === 'admin' ? 'Administrator' : 'Student';
  const loginUrl = `${getFrontendUrl()}/login/login.html`;
  const text =
    `TALISAY CITY COLLEGE\n\nHello, ${n}\n\n` +
    `Welcome to Talisay City College! Your ${accountType} account is ready.\n\n` +
    `Sign in here: ${loginUrl}\n\n` +
    `Use the email address and password you registered with.\n\n` +
    `Talisay City College\nCollege Management Information System`;
  const html = layout({
    heading: 'Welcome to Talisay City College',
    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>Your <strong>${escapeHtml(accountType)}</strong> account is ready.</p>` +
      `<p>Use the email address and password you registered with to sign in.</p>`,
    buttonLabel: 'LOG IN',
    buttonUrl: loginUrl
  });
  return sendEmail({ to, subject: 'Welcome to Talisay City College', text, html });
}

async function sendRegistrationApprovedEmail({ to, name, role, emailVerified }) {
  const n = firstName(name);
  const accountType = role === 'teacher' ? 'Teacher' : 'Student';
  const loginUrl = `${getFrontendUrl()}/login/login.html`;
  const verifyNote = emailVerified
    ? ''
    : 'Before you can sign in, please verify your email address using the verification link we sent you. ' +
      'If you cannot find it, request a new one from the sign-in page.';
  const text =
    `TALISAY CITY COLLEGE\n\nHello, ${n}\n\n` +
    `Good news — your ${accountType} registration has been approved.\n\n` +
    `Sign in with the email address and password you registered with:\n${loginUrl}\n\n` +
    (verifyNote ? verifyNote + '\n\n' : '') +
    `Talisay City College\nCollege Management Information System`;
  const html = layout({
    heading: 'Registration approved',
    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>Good news — your <strong>${escapeHtml(accountType)}</strong> registration has been approved.</p>` +
      `<p>Sign in with the email address and password you registered with.</p>`,
    buttonLabel: 'LOG IN',
    buttonUrl: loginUrl,
    footnoteHtml: escapeHtml(verifyNote)
  });
  return sendEmail({ to, subject: 'Talisay City College Registration Approved', text, html });
}

async function sendRegistrationRejectedEmail({ to, name, reason }) {
  const n = firstName(name);
  const cleanReason = String(reason || '').trim().slice(0, 500);
  const text =
    `TALISAY CITY COLLEGE\n\nHello, ${n}\n\n` +
    `Thank you for your interest in the Talisay City College Management Information System. ` +
    `Unfortunately, your registration was not approved.\n\n` +
    (cleanReason ? `Note from the registrar: ${cleanReason}\n\n` : '') +
    `If you believe this is a mistake, please contact the registrar's office.\n\n` +
    `Talisay City College\nCollege Management Information System`;
  const html = layout({
    heading: 'Registration update',
    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>Thank you for your interest in the Talisay City College Management Information System. ` +
      `Unfortunately, your registration was <strong>not approved</strong>.</p>` +
      (cleanReason ? `<p><strong>Note from the registrar:</strong> ${escapeHtml(cleanReason)}</p>` : '') +
      `<p>If you believe this is a mistake, please contact the registrar's office.</p>`
  });
  return sendEmail({ to, subject: 'Talisay City College Registration Update', text, html });
}

/**
 * Checks the SMTP login without sending anything. Returns a safe summary —
 * never the credentials. Used by the admin-only test route.
 */
async function verifyConnection() {
  if (usingEmailJs()) {
    // EmailJS has no "login check" endpoint; the admin test route's real
    // test send is the check. Reports only that it is configured.
    const cfg0 = readConfig();
    return { ok: true, provider: 'emailjs', sender: cfg0.fromEmail || null };
  }
  const cfg = readConfig();
  const summary = { host: cfg.host, port: cfg.port, secure: cfg.secure, sender: cfg.fromEmail || null };
  try {
    const { transporter } = getTransporter();
    await transporter.verify();
    return { ok: true, ...summary };
  } catch (err) {
    console.error('SMTP verify failed (' + describeError(err) + ')');
    let hint = 'Could not log in to the SMTP server. Check SMTP_USER / SMTP_PASS (use a Google App Password).';
    if (err && err.code === 'EMAIL_NOT_CONFIGURED') hint = 'SMTP_USER / SMTP_PASS are not set on this server.';
    else if (err && (err.code === 'ETIMEDOUT' || err.code === 'ESOCKET' || err.code === 'ECONNECTION' || err.code === 'ECONNREFUSED')) {
      hint = 'Could not reach the SMTP server. Render free web services block outbound SMTP ports (465/587); ' +
        'a paid Render instance is required for Gmail SMTP.';
    } else if (err && err.code === 'EAUTH') hint = 'Gmail rejected the login. Create a new Google App Password and update SMTP_PASS.';
    return { ok: false, ...summary, code: (err && err.code) || 'UNKNOWN', hint };
  }
}

module.exports = {
  sendEmail,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendRegistrationApprovedEmail,
  sendRegistrationRejectedEmail,
  verifyConnection,
  getFrontendUrl
};
