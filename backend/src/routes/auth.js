const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const pool = require('../db');
const { signToken } = require('../utils/token');
const { requireAuth } = require('../middleware/auth');
const { checkPasswordStrength } = require('../utils/passwordPolicy');
const { sendPasswordResetEmail } = require('../utils/mailer');

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

const RESET_TOKEN_BYTES = 32;
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

function hashResetToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
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
    return res.status(201).json({ request: serializeRequest(rows[0]) });
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
 * POST /api/auth/forgot-password
 * body: { email }
 *
 * If an approved (active) account exists for that email, generates a one-time reset
 * token, stores only its SHA-256 hash + a 1-hour expiry on the user row
 * (the raw token is never persisted — it only ever lives in the emailed
 * link), and emails a reset link via Gmail SMTP (see utils/mailer.js).
 *
 * Always responds with the same generic success message whether or not
 * the email is registered, so this endpoint can't be used to check which
 * emails have accounts. A real send failure (bad mail config, Gmail
 * rejecting the request, etc.) is logged server-side and surfaced as a
 * distinct 500 — that's an operator problem, not a "this email doesn't
 * exist" leak, so it's fine to say so explicitly.
 */
router.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const GENERIC_OK = { message: 'If an account exists for that email, a reset link is on its way.' };
  try {
    const email = normalizeEmail(req.body.email);
    if (!email) {
      return res.status(400).json({ message: 'Enter your email first.' });
    }

    const [rows] = await pool.query(
      `SELECT id, name, email FROM users WHERE email = ? AND status = 'approved' ORDER BY id DESC LIMIT 1`,
      [email]
    );
    const user = rows[0];

    // No matching approved account — respond exactly as if we'd sent one.
    if (!user) {
      return res.json(GENERIC_OK);
    }

    const rawToken = crypto.randomBytes(RESET_TOKEN_BYTES).toString('hex');
    const tokenHash = hashResetToken(rawToken);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    await pool.query(
      `UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?`,
      [tokenHash, expiresAt, user.id]
    );

    const frontendUrl = (process.env.FRONTEND_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
    const resetUrl = `${frontendUrl}/reset-password.html?token=${rawToken}&email=${encodeURIComponent(user.email)}`;

    try {
      await sendPasswordResetEmail({ to: user.email, name: user.name, resetUrl });
    } catch (mailErr) {
      console.error('POST /api/auth/forgot-password — email send failed:', mailErr.message);
      return res.status(500).json({
        message: 'Could not send the reset email right now. Please try again in a few minutes, or contact the registrar.'
      });
    }

    return res.json(GENERIC_OK);
  } catch (err) {
    console.error('POST /api/auth/forgot-password failed:', err);
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

/**
 * POST /api/auth/reset-password
 * body: { email, token, password }
 *
 * Verifies the raw token from the emailed link against the stored hash
 * (and that it hasn't expired), then overwrites password_hash the same
 * way signup/admin-reset do. The token is cleared on both success and a
 * couple of failure paths aren't relevant here — it's simply never
 * reused: a fresh request always issues a fresh token/hash.
 */
router.post('/reset-password', async (req, res) => {
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

    const [rows] = await pool.query(
      `SELECT id, reset_token_hash, reset_token_expires FROM users WHERE email = ? LIMIT 1`,
      [email]
    );
    const user = rows[0];
    const tokenHash = hashResetToken(token);

    const valid = user
      && user.reset_token_hash
      && user.reset_token_hash === tokenHash
      && user.reset_token_expires
      && new Date(user.reset_token_expires).getTime() > Date.now();

    if (!valid) {
      return res.status(400).json({ message: 'This reset link is invalid or has expired. Please request a new one.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await pool.query(
      `UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_token_expires = NULL WHERE id = ?`,
      [passwordHash, user.id]
    );

    return res.json({ message: 'Password updated — you can now sign in.' });
  } catch (err) {
    console.error('POST /api/auth/reset-password failed:', err);
    return res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
});

module.exports = router;
