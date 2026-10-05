const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');

/**
 * Rate limit for the sensitive-data reveal endpoint (decrypting student
 * DOB / address / mobile / guardian contact). Deliberately tight — this
 * gate exists to slow down passkey brute-forcing and to bound how much
 * PII a single compromised admin session can pull in a short window.
 * Keyed by admin user id (falls back to IP, via express-rate-limit's own
 * IPv6-safe helper) so it limits per-admin, not per-IP-shared-by-a-whole-office.
 */
const sensitiveDataLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.user && req.user.id ? `admin:${req.user.id}` : ipKeyGenerator(req.ip)),
  message: { message: 'Too many sensitive-data requests. Please try again later.' }
});

module.exports = { sensitiveDataLimiter };
