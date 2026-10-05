// emailService.js

const nodemailer = require('nodemailer');

/* =========================================================
   CONFIGURATION
========================================================= */

const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE =
  String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';

const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';

const FROM_EMAIL =
  process.env.FROM_EMAIL ||
  SMTP_USER ||
  'noreply@talisaycitycollege.edu.ph';

const FROM_NAME =
  process.env.FROM_NAME ||
  'Talisay City College';

/* =========================================================
   EMAILJS CONFIGURATION
========================================================= */

const EMAILJS_SERVICE_ID =
  process.env.EMAILJS_SERVICE_ID || '';

const EMAILJS_TEMPLATE_ID =
  process.env.EMAILJS_TEMPLATE_ID || '';

const EMAILJS_PUBLIC_KEY =
  process.env.EMAILJS_PUBLIC_KEY || '';

/*
   Private key (EmailJS -> Account -> General). Required when
   Account -> Security has "Use Private Key (recommended)" enabled
   (strict mode), otherwise EmailJS returns 403.
*/
const EMAILJS_PRIVATE_KEY =
  process.env.EMAILJS_PRIVATE_KEY || '';

/*
   EmailJS endpoint
*/
const EMAILJS_API_URL =
  'https://api.emailjs.com/api/v1.0/email/send';

/* =========================================================
   HELPERS
========================================================= */

/*
   Base URL of the deployed frontend, used to build links inside emails.
   Reads FRONTEND_URL, falls back to the Netlify site, strips trailing slashes.
*/
function getFrontendUrl() {
  return String(process.env.FRONTEND_URL || 'https://tccsystem.netlify.app')
    .trim()
    .replace(/\/+$/, '');
}

function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function firstName(name = '') {
  const value = String(name || '').trim();

  if (!value) {
    return 'Student';
  }

  return value.split(/\s+/)[0];
}

/* =========================================================
   EMAIL TRANSPORTER
========================================================= */

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS
  }
});

/* =========================================================
   EMAILJS REQUEST
========================================================= */

async function emailJsRequest({
  to,
  subject,
  html,
  text,
  plain = ''
}) {
  if (
    !EMAILJS_SERVICE_ID ||
    !EMAILJS_TEMPLATE_ID ||
    !EMAILJS_PUBLIC_KEY
  ) {
    throw new Error(
      'EmailJS configuration is missing. Check EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, and EMAILJS_PUBLIC_KEY.'
    );
  }

  const response = await fetch(EMAILJS_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      service_id: EMAILJS_SERVICE_ID,
      template_id: EMAILJS_TEMPLATE_ID,
      user_id: EMAILJS_PUBLIC_KEY,
      ...(EMAILJS_PRIVATE_KEY ? { accessToken: EMAILJS_PRIVATE_KEY } : {}),

      template_params: {
        to_email: to,
        email: to,
        to: to,
        recipient: to,
        user_email: to,
        reply_to: to,

        subject,

        /*
          IMPORTANT:
          This sends the dynamic reset URL
          to your EmailJS template.

          In EmailJS use:

          {{reset_url}}
        */
        reset_url: plain || '',

        /*
          Other template variables
        */
        html_body: html,
        message: text,
        text_body: text,

        from_name: FROM_NAME
      }
    })
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(
      `EmailJS error ${response.status}: ${responseText}`
    );
  }

  return {
    success: true,
    provider: 'emailjs',
    response: responseText
  };
}

/* =========================================================
   GENERIC SEND EMAIL
========================================================= */

async function sendEmail({
  to,
  subject,
  text,
  html,
  plain = ''
}) {
  /*
    Try EmailJS first if configured.
  */

  if (
    EMAILJS_SERVICE_ID &&
    EMAILJS_TEMPLATE_ID &&
    EMAILJS_PUBLIC_KEY
  ) {
    try {
      return await emailJsRequest({
        to,
        subject,
        html,
        text,
        plain
      });
    } catch (error) {
      console.error(
        'EmailJS failed:',
        error.message
      );

      /*
        Continue to SMTP fallback.
      */
    }
  }

  /*
    SMTP fallback
  */

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error(
      'No working email provider is configured. Configure EmailJS or SMTP.'
    );
  }

  const info = await transporter.sendMail({
    from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
    to,
    subject,
    text,
    html
  });

  return {
    success: true,
    provider: 'smtp',
    messageId: info.messageId
  };
}

/* =========================================================
   HTML EMAIL LAYOUT
========================================================= */

function layout({
  heading,
  bodyHtml,
  buttonLabel,
  buttonUrl,
  footnoteHtml = ''
}) {
  const button = buttonUrl
    ? `
      <div style="text-align:center;margin:30px 0;">
        <a
          href="${escapeHtml(buttonUrl)}"
          target="_blank"
          style="
            display:inline-block;
            background:#2f4a9e;
            color:#ffffff;
            text-decoration:none;
            font-weight:bold;
            padding:14px 30px;
            border-radius:6px;
            font-family:Arial,sans-serif;
          "
        >
          ${escapeHtml(buttonLabel || 'OPEN')}
        </a>
      </div>
    `
    : '';

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>${escapeHtml(heading)}</title>
</head>

<body
  style="
    margin:0;
    padding:0;
    background:#f4f6f8;
    font-family:Arial,Helvetica,sans-serif;
  "
>

  <div
    style="
      width:100%;
      padding:40px 0;
      background:#f4f6f8;
    "
  >

    <div
      style="
        max-width:600px;
        margin:0 auto;
        background:#ffffff;
        border-radius:10px;
        overflow:hidden;
        box-shadow:0 2px 10px rgba(0,0,0,0.08);
      "
    >

      <!-- HEADER -->

      <div
        style="
          background:#2f4a9e;
          padding:25px;
          text-align:center;
        "
      >

        <h1
          style="
            margin:0;
            color:#ffffff;
            font-size:24px;
          "
        >
          Talisay City College
        </h1>

        <p
          style="
            margin:8px 0 0;
            color:#ffffff;
            font-size:14px;
          "
        >
          College Management Information System
        </p>

      </div>

      <!-- CONTENT -->

      <div
        style="
          padding:35px;
          color:#333333;
          line-height:1.6;
        "
      >

        <h2
          style="
            margin-top:0;
            color:#2f4a9e;
          "
        >
          ${escapeHtml(heading)}
        </h2>

        ${bodyHtml}

        ${button}

        ${
          footnoteHtml
            ? `
              <div
                style="
                  margin-top:25px;
                  padding:15px;
                  background:#f5f5f5;
                  border-radius:6px;
                  font-size:13px;
                  color:#666666;
                "
              >
                ${footnoteHtml}
              </div>
            `
            : ''
        }

      </div>

      <!-- FOOTER -->

      <div
        style="
          padding:20px;
          text-align:center;
          background:#f4f6f8;
          color:#777777;
          font-size:12px;
        "
      >
        Talisay City College<br>
        College Management Information System
      </div>

    </div>

  </div>

</body>
</html>
`;
}

/* =========================================================
   VERIFICATION EMAIL
========================================================= */

async function sendVerificationEmail({
  to,
  name,
  verifyUrl,
  expiresInHours,
  expiresInMinutes = 15
}) {
  const n = firstName(name);
  const expiryLabel = expiresInHours
    ? `${expiresInHours} hour${Number(expiresInHours) === 1 ? '' : 's'}`
    : `${expiresInMinutes} minutes`;

  const text =
    `TALISAY CITY COLLEGE\n\n` +
    `Hello, ${n}\n\n` +
    `Please verify your email address by opening the following link:\n\n` +
    `${verifyUrl}\n\n` +
    `This link will expire in ${expiryLabel}.\n\n` +
    `If you did not request this verification, you may safely ignore this email.\n\n` +
    `Talisay City College\n` +
    `College Management Information System`;

  const html = layout({
    heading: 'Verify your email address',

    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>Please verify your email address by clicking the button below.</p>`,

    buttonLabel: 'VERIFY EMAIL',

    buttonUrl: verifyUrl,

    footnoteHtml:
      `This verification link will expire in ` +
      `<strong>${expiryLabel}</strong>.`
  });

  return sendEmail({
    to,
    subject: 'Verify Your Talisay City College Account',
    text,
    html,
    plain: verifyUrl
  });
}

/* =========================================================
   PASSWORD RESET EMAIL
========================================================= */

async function sendPasswordResetEmail({
  to,
  name,
  resetUrl,
  expiresInMinutes = 15
}) {
  const n = firstName(name);

  /*
    Plain-text email
  */

  const text =
    `TALISAY CITY COLLEGE\n\n` +
    `Hello, ${n}\n\n` +
    `We received a request to reset your password.\n\n` +
    `Reset your password:\n` +
    `${resetUrl}\n\n` +
    `This link will expire in ${expiresInMinutes} minutes ` +
    `and can only be used once.\n\n` +
    `If you did not request a password reset, ` +
    `you may safely ignore this email.\n\n` +
    `Talisay City College\n` +
    `College Management Information System`;

  /*
    HTML email
  */

  const html = layout({
    heading: 'Reset your password',

    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>` +
      `We received a request to reset your Talisay City College ` +
      `account password.` +
      `</p>` +

      `<p>` +
      `Click the button below to create a new password.` +
      `</p>`,

    buttonLabel: 'RESET PASSWORD',

    /*
      IMPORTANT:
      This MUST be the dynamic reset URL.
      Do NOT hardcode the token here.
    */
    buttonUrl: resetUrl,

    footnoteHtml:
      `This password reset link will expire in ` +
      `<strong>${expiresInMinutes} minutes</strong> ` +
      `and can only be used once.<br><br>` +

      `If you did not request a password reset, ` +
      `you may safely ignore this email.`
  });

  /*
    Send resetUrl as "plain".

    emailJsRequest() converts this into:

    reset_url: resetUrl

    Therefore your EmailJS template MUST use:

    {{reset_url}}
  */

  return sendEmail({
    to,
    subject: 'Reset Your Talisay City College Password',
    text,
    html,
    plain: resetUrl
  });
}

/* =========================================================
   WELCOME EMAIL
========================================================= */

async function sendWelcomeEmail({
  to,
  name,
  loginUrl = ''
}) {
  const n = firstName(name);

  const text =
    `TALISAY CITY COLLEGE\n\n` +
    `Hello, ${n}\n\n` +
    `Welcome to the Talisay City College ` +
    `College Management Information System.\n\n` +
    `Your account has been successfully created.\n\n` +
    (
      loginUrl
        ? `Login here:\n${loginUrl}\n\n`
        : ''
    ) +
    `Talisay City College\n` +
    `College Management Information System`;

  const html = layout({
    heading: 'Welcome to Talisay City College',

    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>` +
      `Welcome to the Talisay City College ` +
      `College Management Information System.` +
      `</p>` +
      `<p>Your account has been successfully created.</p>`,

    buttonLabel: loginUrl
      ? 'LOGIN TO SYSTEM'
      : '',

    buttonUrl: loginUrl,

    footnoteHtml:
      `Please keep your account credentials secure.`
  });

  return sendEmail({
    to,
    subject: 'Welcome to Talisay City College',
    text,
    html,
    plain: loginUrl
  });
}

/* =========================================================
   APPROVED EMAIL
========================================================= */

async function sendApprovedEmail({
  to,
  name,
  loginUrl = ''
}) {
  const n = firstName(name);

  const text =
    `TALISAY CITY COLLEGE\n\n` +
    `Hello, ${n}\n\n` +
    `Your account has been approved.\n\n` +
    (
      loginUrl
        ? `You can now log in here:\n${loginUrl}\n\n`
        : ''
    ) +
    `Talisay City College\n` +
    `College Management Information System`;

  const html = layout({
    heading: 'Account Approved',

    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>` +
      `Your Talisay City College account has been ` +
      `<strong>approved</strong>.` +
      `</p>` +
      `<p>You can now access the system using your account.</p>`,

    buttonLabel: loginUrl
      ? 'LOGIN TO SYSTEM'
      : '',

    buttonUrl: loginUrl,

    footnoteHtml:
      `Thank you for using the Talisay City College ` +
      `College Management Information System.`
  });

  return sendEmail({
    to,
    subject: 'Your Talisay City College Account Has Been Approved',
    text,
    html,
    plain: loginUrl
  });
}

/* =========================================================
   REJECTED EMAIL
========================================================= */

async function sendRejectedEmail({
  to,
  name,
  reason = ''
}) {
  const n = firstName(name);

  const text =
    `TALISAY CITY COLLEGE\n\n` +
    `Hello, ${n}\n\n` +
    `We regret to inform you that your account registration ` +
    `has not been approved.\n\n` +
    (
      reason
        ? `Reason:\n${reason}\n\n`
        : ''
    ) +
    `If you believe this was an error, please contact ` +
    `the appropriate Talisay City College administrator.\n\n` +
    `Talisay City College\n` +
    `College Management Information System`;

  const html = layout({
    heading: 'Account Registration Update',

    bodyHtml:
      `<p>Hello, ${escapeHtml(n)}</p>` +
      `<p>` +
      `We regret to inform you that your account registration ` +
      `has not been approved.` +
      `</p>` +

      (
        reason
          ? `
            <p>
              <strong>Reason:</strong><br>
              ${escapeHtml(reason)}
            </p>
          `
          : ''
      ),

    buttonLabel: '',

    buttonUrl: '',

    footnoteHtml:
      `If you believe this was an error, please contact ` +
      `the appropriate Talisay City College administrator.`
  });

  return sendEmail({
    to,
    subject: 'Talisay City College Account Registration Update',
    text,
    html,
    plain: ''
  });
}

/* =========================================================
   VERIFY EMAIL CONNECTION
========================================================= */

async function verifyConnection() {
  /*
    Verify SMTP if SMTP configuration exists.
  */

  if (
    SMTP_HOST &&
    SMTP_USER &&
    SMTP_PASS
  ) {
    await transporter.verify();

    return {
      success: true,
      provider: 'smtp'
    };
  }

  /*
    If SMTP is not configured but EmailJS is,
    consider EmailJS configured.
  */

  if (
    EMAILJS_SERVICE_ID &&
    EMAILJS_TEMPLATE_ID &&
    EMAILJS_PUBLIC_KEY
  ) {
    return {
      success: true,
      provider: 'emailjs'
    };
  }

  throw new Error(
    'No email provider is configured.'
  );
}

/* =========================================================
   EXPORTS
========================================================= */

module.exports = {
  sendEmail,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendApprovedEmail,
  sendRejectedEmail,
  verifyConnection,
  getFrontendUrl
};
