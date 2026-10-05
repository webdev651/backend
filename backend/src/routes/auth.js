const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const pool = require('../db');
const { signToken } = require('../utils/token');
const { requireAuth } = require('../middleware/auth');
const { checkPasswordStrength } = require('../utils/passwordPolicy');
const {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
  getFrontendUrl
} = require('../services/emailService');

const router = express.Router();
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

// Basic brute-force guard on login: 10 attempts per IP per 15 minutes.
// Counts every request that reaches this route (success or failure) —
// deliberately simple rather than only-count-failures, since the goal is
// capping guess volume, not building a full account-lockout system.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts. Please wait a few minutes and try again.' }
});

// Basic anti-spam guard on signup: 5 account requests per IP per hour.
// Prevents a script from flooding the pending-approvals queue with junk
// accounts; generous enough that a real student retrying a typo'd form
// won't get blocked.
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many signup attempts from this network. Please try again later.' }
});

// Forgot-password requests are capped separately from login attempts:
// generous enough for someone genuinely locked out to retry, but tight
// enough that a script can't use this endpoint to spam an inbox or probe
// which emails have accounts.
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many password reset requests. Please wait a while and try again.' }
});

// Per-email limiter (in addition to the per-IP one above) so a single
// inbox can't be flooded even from many IPs. Falls back to the IP when no
// email was sent. Keyed on the normalised email, which is never logged.
function perEmailLimiter(max, message) {
  return rateLimit({
    windowMs: 60 * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      const email = String((req.body && req.body.email) || '').trim().toLowerCase();
      return email ? 'email:' + email : ipKeyGenerator(req.ip);
    },
    message: { message }
  });
}
const forgotPasswordEmailLimiter = perEmailLimiter(3, 'Too many password reset requests. Please wait a while and try again.');

// Resend-verification: capped per IP and per email. The 60-second spacing
// between emails is enforced separately in the route (from the DB).
const resendVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many verification requests. Please wait a while and try again.' }
});
const resendVerificationEmailLimiter = perEmailLimiter(5, 'Too many verification requests. Please wait a while and try again.');

// Verify / validate endpoints take a secret token: cap guessing per IP.
const tokenCheckLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please wait a few minutes and try again.' }
});

const RESET_TOKEN_BYTES = 32;
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
const VERIFY_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const VERIFY_TOKEN_HOURS = VERIFY_TOKEN_TTL_MS / 3600000;
const EMAIL_COOLDOWN_MS = 60 * 1000; // minimum gap between emails to the same account

function hashResetToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

/**
 * Creates a fresh single-use verification token for the user (invalidating
 * any older unused ones) and emails the link. Only the SHA-256 hash is
 * stored. Throws if the email can't be sent; the token row is left in
 * place either way (it simply expires if never used).
 */
async function issueAndSendVerification(user) {
  const rawToken = crypto.randomBytes(RESET_TOKEN_BYTES).toString('hex');
  const now = new Date();
  await pool.query(
    `UPDATE email_verification_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`,
    [now, user.id]
  );
  await pool.query(
    `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`,
    [user.id, hashResetToken(rawToken), new Date(now.getTime() + VERIFY_TOKEN_TTL_MS), now]
  );
  const verifyUrl = `${getFrontendUrl()}/verify-email.html?token=${rawToken}`;
  await sendVerificationEmail({ to: user.email, name: user.name, verifyUrl, expiresInHours: VERIFY_TOKEN_HOURS });
}

/** Looks up the reset token's owner; returns the user row only if the token matches and hasn't expired. */
async function findUserForResetToken(email, token) {
  if (!email || !/^[a-f0-9]{64}$/.test(token)) return null;
  const [rows] = await pool.query(
    `SELECT id, reset_token_hash, reset_token_expires FROM users WHERE email = ? LIMIT 1`,
    [email]
  );
  const user = rows[0];
  const ok = user
    && user.reset_token_hash
    && user.reset_token_hash === hashResetToken(token)
    && user.reset_token_expires
    && new Date(user.reset_token_expires).getTime() > Date.now();
  return ok ? user : null;
}

// Student ID Numbers are normalized to a single canonical form (trimmed,
// upper-cased) before validation/storage/comparison so e.g. "tcc-2024-101"
// and "TCC-2024-101" are treated as the same ID and can't slip past the
// uniqueness check as "different" values.
function normalizeStudentId(studentId) {
  return String(studentId || '').trim().toUpperCase();
}

// Letters, digits, and hyphens only, 4–20 characters — adjust this pattern
// if the registrar's real ID format differs (e.g. a fixed "YYYY-NNNNN"
// shape); the important properties (required, unique) stay the same either way.
const STUDENT_ID_PATTERN = /^[A-Z0-9-]{4,20}$/;

function serializeRequest(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    detail: row.detail || '',
    studentId: row.student_id || '',
    status: row.status,
    requestedAt: row.requested_at,
    decidedAt: row.decided_at
  };
}

/**
 * POST /api/auth/signup
 * Creates a pending student/teacher account request. Mirrors the original
 * accounts.js `createRequest` validation exactly. Admin accounts are never
 * created through this endpoint (see seed/create-admin.js).
 */
router.post('/signup', signupLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const role = req.body.role === 'teacher' ? 'teacher' : 'student';
    const detail = String(req.body.detail || '').trim();
    // Only students carry a Student ID Number; teachers/admins never do.
    const studentId = role === 'student' ? normalizeStudentId(req.body.studentId) : null;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Fill in every field.' });
    }
    const strength = checkPasswordStrength(password);
    if (!strength.valid) {
      return res.status(400).json({ message: strength.message });
    }
    if (role === 'student') {
      if (!studentId) {
        return res.status(400).json({ message: 'Student ID Number is required.' });
      }
      if (!STUDENT_ID_PATTERN.test(studentId)) {
        return res.status(400).json({
          message: 'Student ID Number must be 4–20 characters, using only letters, numbers, and hyphens.'
        });
      }
    }

    const [existingRows] = await pool.query(
      `SELECT id, status FROM users
       WHERE email = ? AND status <> 'rejected'
       ORDER BY id DESC LIMIT 1`,
      [email]
    );
    if (existingRows.length) {
      const existing = existingRows[0];
      return res.status(409).json({
        message: existing.status === 'pending'
          ? 'There is already a pending request for this email.'
          : 'An account already exists for this email — try signing in.'
      });
    }

    // A Student ID Number identifies one real student, so — unlike email —
    // it is never recycled: it stays reserved even if a past request tied
    // to it was rejected. Checked up front for a clear error message; the
    // UNIQUE index on users.student_id (see schema.sql / migrate.js) is
    // the authoritative guard against a race between two simultaneous
    // signups, caught via ER_DUP_ENTRY below.
    if (role === 'student') {
      const [dupRows] = await pool.query(
        `SELECT id FROM users WHERE student_id = ? LIMIT 1`,
        [studentId]
      );
      if (dupRows.length) {
        return res.status(409).json({ message: 'This Student ID Number is already registered.' });
      }
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let result;
    try {
      [result] = await pool.query(
        `INSERT INTO users (name, email, password_hash, role, detail, student_id, status, requested_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', NOW())`,
        [name, email, passwordHash, role, detail, studentId]
      );
    } catch (err) {
      if (err && err.code === 'ER_DUP_ENTRY' && String(err.sqlMessage).includes('student_id')) {
        return res.status(409).json({ message: 'This Student ID Number is already registered.' });
      }
      throw err;
    }

    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [result.insertId]);

    // Email verification. A mail failure must never fail the signup itself
    // (the request is already saved) — the person can use "Resend" instead.
    let verificationEmailSent = true;
    try {
      await issueAndSendVerification(rows[0]);
    } catch (mailErr) {
      verificationEmailSent = false;
      console.error('POST /api/auth/signup — verification email failed:', mailErr.code || mailErr.message);
    }

    return res.status(201).json({ request: serializeRequest(rows[0]), verificationEmailSent });
  } catch (err) {
    console.error('POST /api/auth/signup failed:', err);
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * POST /api/auth/login
 * Real credential check against the users table (bcrypt-compared password,
 * status gate for pending/rejected accounts). Issues a JWT on success.
 * Unlike the old frontend-only demo, there is no "any unknown email with a
 * 6+ char password succeeds" fallback — every login is checked for real.
 */
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const [rows] = await pool.query(
      `SELECT * FROM users WHERE email = ? ORDER BY id DESC LIMIT 1`,
      [email]
    );
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid login credentials.' });
    }
    if (user.status === 'pending') {
      return res.status(403).json({ message: 'Your account is awaiting admin approval. Please check back later.' });
    }
    if (user.status === 'rejected') {
      return res.status(403).json({ message: 'This account request was declined. Contact the registrar.' });
    }

    const passwordOk = await bcrypt.compare(password, user.password_hash);
    if (!passwordOk) {
      return res.status(401).json({ message: 'Invalid login credentials.' });
    }

    // Email must be verified before first sign-in. Accounts that existed
    // before verification was introduced are stamped verified by the
    // migration, and admins (seeded, not self-registered) are exempt.
    if (user.role !== 'admin' && !user.email_verified_at) {
      return res.status(403).json({
        code: 'EMAIL_NOT_VERIFIED',
        message: 'Please verify your email address before signing in. Check your inbox for the verification link.'
      });
    }

    const token = signToken({ id: user.id, email: user.email, role: user.role, name: user.name });
    return res.json({
      token,
      role: user.role,
      name: user.name,
      detail: user.detail || ''
    });
  } catch (err) {
    console.error('POST /api/auth/login failed:', err);
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * GET /api/auth/me
 * Verifies the bearer token and returns who it belongs to. Used by the
 * frontend's page guards (js/core/auth-guard.js) so that navigating
 * straight to admin/dashboard.html, teacher-dashboard.html, or
 * student-dashboard.html without a real, still-valid session for that
 * role bounces you back to login instead of rendering the page —
 * a stale/expired/forged token fails here the same way it would on any
 * other protected route.
 */
router.get('/me', requireAuth, (req, res) => {
  return res.json({
    id: req.user.id,
    email: req.user.email,
    role: req.user.role,
    name: req.user.name
  });
});

/**
 * POST /api/auth/verify-email
 * body: { token }
 *
 * Consumes a verification link. POST (not GET) on purpose: mail scanners
 * and link previewers fetch GET URLs automatically and would burn the
 * single-use token before the person clicks. The frontend page
 * (verify-email.html) calls this when it loads.
 */
router.post('/verify-email', tokenCheckLimiter, async (req, res) => {
  try {
    const token = String(req.body.token || '');
    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(400).json({ code: 'TOKEN_INVALID', message: 'This verification link is invalid. Please request a new one.' });
    }

    const [rows] = await pool.query(
      `SELECT t.id AS token_id, t.user_id, t.expires_at, t.used_at,
              u.name, u.email, u.role, u.status, u.email_verified_at
       FROM email_verification_tokens t
       JOIN users u ON u.id = t.user_id
       WHERE t.token_hash = ? LIMIT 1`,
      [hashResetToken(token)]
    );
    const row = rows[0];
    if (!row) {
      return res.status(400).json({ code: 'TOKEN_INVALID', message: 'This verification link is invalid. Please request a new one.' });
    }
    if (row.used_at) {
      return res.status(400).json({ code: 'TOKEN_USED', message: 'This verification link has already been used or replaced by a newer one.' });
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return res.status(400).json({ code: 'TOKEN_EXPIRED', message: 'This verification link has expired. Please request a new one.' });
    }

    // Claim the token atomically so two simultaneous clicks can't both succeed.
    const now = new Date();
    const [claim] = await pool.query(
      `UPDATE email_verification_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
      [now, row.token_id]
    );
    if (!claim.affectedRows) {
      return res.status(400).json({ code: 'TOKEN_USED', message: 'This verification link has already been used or replaced by a newer one.' });
    }

    const wasUnverified = !row.email_verified_at;
    await pool.query(
      `UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?`,
      [now, row.user_id]
    );

    // Welcome email only when the account is actually ready (already
    // approved). Pending accounts get the "registration approved" email
    // from the admin approval step instead.
    if (wasUnverified && row.status === 'approved') {
      sendWelcomeEmail({ to: row.email, name: row.name, role: row.role })
        .catch((e) => console.error('Welcome email failed:', e.code || e.message));
    }

    return res.json({
      message: 'Your email address has been verified.',
      status: row.status
    });
  } catch (err) {
    console.error('POST /api/auth/verify-email failed:', (err && (err.code || err.name)) || 'error'); // no err object: DB errors can embed SQL values
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * POST /api/auth/resend-verification
 * body: { email }
 *
 * Sends a fresh verification link to an unverified, non-rejected account.
 * Same generic response whether or not the email exists / is already
 * verified / is inside the 60-second cooldown, so it can't be used to
 * probe accounts. The email is sent in the background so response time
 * doesn't reveal anything either.
 */
router.post('/resend-verification', resendVerificationLimiter, resendVerificationEmailLimiter, async (req, res) => {
  const GENERIC_OK = { message: 'If this account still needs verification, a new verification email has been sent.' };
  try {
    const email = normalizeEmail(req.body.email);
    if (!email) return res.status(400).json({ message: 'Enter your email first.' });

    const [rows] = await pool.query(
      `SELECT id, name, email FROM users
       WHERE email = ? AND status <> 'rejected' AND role <> 'admin' AND email_verified_at IS NULL
       ORDER BY id DESC LIMIT 1`,
      [email]
    );
    const user = rows[0];
    if (!user) return res.json(GENERIC_OK);

    const [last] = await pool.query(
      `SELECT created_at FROM email_verification_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1`,
      [user.id]
    );
    if (last.length && Date.now() - new Date(last[0].created_at).getTime() < EMAIL_COOLDOWN_MS) {
      return res.json(GENERIC_OK); // cooldown: don't send, don't reveal
    }

    issueAndSendVerification(user)
      .catch((e) => console.error('Resend verification email failed:', e.code || e.message));
    return res.json(GENERIC_OK);
  } catch (err) {
    console.error('POST /api/auth/resend-verification failed:', (err && (err.code || err.name)) || 'error'); // no err object: DB errors can embed SQL values
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * POST /api/auth/forgot-password
 * body: { email }
 *
 * If an approved account exists for that email, generates a one-time reset
 * token, stores only its SHA-256 hash + a 1-hour expiry on the user row
 * (the raw token is never persisted — it only ever lives in the emailed
 * link), and emails the reset link (services/emailService.js).
 *
 * Always responds with the same generic message whether or not the email
 * is registered, whether the mail send succeeds, and whether the request
 * landed in the 60-second cooldown. The email is sent in the background
 * so neither the status code nor the response time reveals whether an
 * account exists. Send failures are logged server-side (no tokens, no
 * credentials); check the logs or the admin SMTP test if mail isn't arriving.
 */
router.post('/forgot-password', forgotPasswordLimiter, forgotPasswordEmailLimiter, async (req, res) => {
  const GENERIC_OK = { message: 'If an account exists for this email, a password reset link has been sent.' };
  try {
    const email = normalizeEmail(req.body.email);
    if (!email) {
      return res.status(400).json({ message: 'Enter your email first.' });
    }

    const [rows] = await pool.query(
      `SELECT id, name, email, reset_token_expires FROM users WHERE email = ? AND status = 'approved' ORDER BY id DESC LIMIT 1`,
      [email]
    );
    const user = rows[0];
    if (!user) return res.json(GENERIC_OK);

    // Cooldown: the previous link was issued at (expires - TTL).
    if (user.reset_token_expires) {
      const issuedAt = new Date(user.reset_token_expires).getTime() - RESET_TOKEN_TTL_MS;
      if (Date.now() - issuedAt < EMAIL_COOLDOWN_MS) return res.json(GENERIC_OK);
    }

    const rawToken = crypto.randomBytes(RESET_TOKEN_BYTES).toString('hex');
    await pool.query(
      `UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?`,
      [hashResetToken(rawToken), new Date(Date.now() + RESET_TOKEN_TTL_MS), user.id]
    );

    const resetUrl = `${getFrontendUrl()}/reset-password.html?token=${rawToken}&email=${encodeURIComponent(user.email)}`;
    sendPasswordResetEmail({ to: user.email, name: user.name, resetUrl, expiresInMinutes: RESET_TOKEN_TTL_MS / 60000 })
      .catch((e) => console.error('POST /api/auth/forgot-password — email send failed:', e.code || e.message));

    return res.json(GENERIC_OK);
  } catch (err) {
    console.error('POST /api/auth/forgot-password failed:', (err && (err.code || err.name)) || 'error'); // no err object: DB errors can embed SQL values
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * POST /api/auth/reset-password/validate
 * body: { email, token }
 * Lets reset-password.html tell the person up front that a link is
 * invalid/expired instead of after they've typed a new password.
 * Does not consume the token.
 */
router.post('/reset-password/validate', tokenCheckLimiter, async (req, res) => {
  try {
    const user = await findUserForResetToken(normalizeEmail(req.body.email), String(req.body.token || ''));
    if (!user) {
      return res.status(400).json({ message: 'This reset link is invalid or has expired. Please request a new one.' });
    }
    return res.json({ valid: true });
  } catch (err) {
    console.error('POST /api/auth/reset-password/validate failed:', (err && (err.code || err.name)) || 'error'); // no err object: DB errors can embed SQL values
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * POST /api/auth/reset-password
 * body: { email, token, password }
 *
 * Verifies the raw token against the stored hash and expiry, then replaces
 * password_hash (bcrypt, same as signup) and clears the token in the SAME
 * UPDATE, conditioned on the hash still matching — so a link works exactly
 * once even if clicked twice at the same moment. Receiving the link at
 * the account's email also proves ownership, so email_verified_at is set
 * if it was empty.
 */
router.post('/reset-password', tokenCheckLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const token = String(req.body.token || '');
    const password = String(req.body.password || '');

    if (!email || !token || !password) {
      return res.status(400).json({ message: 'This reset link is missing information. Please request a new one.' });
    }

    const strength = checkPasswordStrength(password);
    if (!strength.valid) {
      return res.status(400).json({ message: strength.message });
    }

    const user = await findUserForResetToken(email, token);
    if (!user) {
      return res.status(400).json({ message: 'This reset link is invalid or has expired. Please request a new one.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const [result] = await pool.query(
      `UPDATE users
       SET password_hash = ?, reset_token_hash = NULL, reset_token_expires = NULL,
           email_verified_at = COALESCE(email_verified_at, NOW())
       WHERE id = ? AND reset_token_hash = ?`,
      [passwordHash, user.id, hashResetToken(token)]
    );
    if (!result.affectedRows) {
      return res.status(400).json({ message: 'This reset link is invalid or has expired. Please request a new one.' });
    }

    return res.json({ message: 'Password reset successfully.' });
  } catch (err) {
    console.error('POST /api/auth/reset-password failed:', (err && (err.code || err.name)) || 'error'); // no err object: DB errors can embed SQL values
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

module.exports = router;
