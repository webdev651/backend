const { verifyToken } = require('../utils/token');

/**
 * requireAuth
 * Reads the Bearer JWT issued by POST /api/auth/login, verifies it, and
 * attaches the decoded payload ({ id, email, role, name }) to req.user.
 * Every Phase 2 module route (grades, attendance, announcements, ...)
 * needs this to know who's asking and what role they have.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const parts = header.split(' ');
  const token = parts.length === 2 && /^Bearer$/i.test(parts[0]) ? parts[1] : null;

  if (!token) {
    return res.status(401).json({ message: 'Sign in required.' });
  }

  try {
    const payload = verifyToken(token);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Your session has expired. Please sign in again.' });
  }
}

/** requireAdmin — must follow requireAuth. */
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admins only.' });
  }
  return next();
}

/** requireTeacher — must follow requireAuth. */
function requireTeacher(req, res, next) {
  if (!req.user || req.user.role !== 'teacher') {
    return res.status(403).json({ message: 'Teachers only.' });
  }
  return next();
}

/** requireRole(...roles) — must follow requireAuth. */
function requireRole(...roles) {
  return function (req, res, next) {
    if (!req.user || roles.indexOf(req.user.role) === -1) {
      return res.status(403).json({ message: 'You are not allowed to do that.' });
    }
    return next();
  };
}

module.exports = { requireAuth, requireAdmin, requireTeacher, requireRole };
